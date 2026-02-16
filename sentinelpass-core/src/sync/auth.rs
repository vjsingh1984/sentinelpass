//! Request signing and auth header formatting for sync API.

use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Format the canonical string-to-sign for a request.
///
/// ```text
/// {METHOD}\n{PATH}\n{TIMESTAMP}\n{NONCE}\n{SHA256(BODY)}
/// ```
pub fn canonical_string(
    method: &str,
    path: &str,
    timestamp: i64,
    nonce: &str,
    body: &[u8],
) -> String {
    let body_hash = hex::encode(Sha256::digest(body));
    format!(
        "{}\n{}\n{}\n{}\n{}",
        method, path, timestamp, nonce, body_hash
    )
}

/// Sign a request with the device's Ed25519 signing key.
///
/// Returns the signature bytes.
pub fn sign_request(
    signing_key: &SigningKey,
    method: &str,
    path: &str,
    timestamp: i64,
    nonce: &str,
    body: &[u8],
) -> Vec<u8> {
    let message = canonical_string(method, path, timestamp, nonce, body);
    let signature = signing_key.sign(message.as_bytes());
    signature.to_bytes().to_vec()
}

/// Format the Authorization header value.
///
/// ```text
/// SentinelPass-Ed25519 <device_id>:<timestamp>:<nonce>:<base64(signature)>
/// ```
pub fn format_auth_header(
    device_id: &Uuid,
    timestamp: i64,
    nonce: &str,
    signature: &[u8],
) -> String {
    use base64::{engine::general_purpose::STANDARD, Engine};
    format!(
        "SentinelPass-Ed25519 {}:{}:{}:{}",
        device_id,
        timestamp,
        nonce,
        STANDARD.encode(signature)
    )
}

/// Parse an Authorization header and verify the signature.
///
/// Returns `(device_id, timestamp, nonce)` if valid.
pub fn verify_auth_header(
    header: &str,
    method: &str,
    path: &str,
    body: &[u8],
    lookup_key: &dyn Fn(&Uuid) -> Option<VerifyingKey>,
    max_age_secs: i64,
) -> Result<(Uuid, i64, String), AuthError> {
    let stripped = header
        .strip_prefix("SentinelPass-Ed25519 ")
        .ok_or(AuthError::InvalidFormat)?;

    let parts: Vec<&str> = stripped.splitn(4, ':').collect();
    if parts.len() != 4 {
        return Err(AuthError::InvalidFormat);
    }

    let device_id = Uuid::parse_str(parts[0]).map_err(|_| AuthError::InvalidFormat)?;
    let timestamp: i64 = parts[1].parse().map_err(|_| AuthError::InvalidFormat)?;
    let nonce = parts[2].to_string();
    let sig_bytes = base64::engine::general_purpose::STANDARD
        .decode(parts[3])
        .map_err(|_| AuthError::InvalidFormat)?;

    // Check timestamp freshness
    let now = chrono::Utc::now().timestamp();
    if (now - timestamp).abs() > max_age_secs {
        return Err(AuthError::Expired);
    }

    // Look up the device's public key
    let verifying_key = lookup_key(&device_id).ok_or(AuthError::UnknownDevice)?;

    // Verify signature
    let message = canonical_string(method, path, timestamp, &nonce, body);
    let signature = Signature::from_bytes(
        &sig_bytes
            .try_into()
            .map_err(|_| AuthError::InvalidSignature)?,
    );
    verifying_key
        .verify(message.as_bytes(), &signature)
        .map_err(|_| AuthError::InvalidSignature)?;

    Ok((device_id, timestamp, nonce))
}

/// Authentication errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthError {
    InvalidFormat,
    Expired,
    UnknownDevice,
    InvalidSignature,
    DeviceRevoked,
    NonceReused,
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidFormat => write!(f, "Invalid authorization header format"),
            Self::Expired => write!(f, "Request timestamp expired"),
            Self::UnknownDevice => write!(f, "Unknown device"),
            Self::InvalidSignature => write!(f, "Invalid signature"),
            Self::DeviceRevoked => write!(f, "Device has been revoked"),
            Self::NonceReused => write!(f, "Nonce has been reused"),
        }
    }
}

impl std::error::Error for AuthError {}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::RngCore;

    #[test]
    fn sign_and_verify_roundtrip() {
        let signing_key = {
            let mut secret = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut secret);
            SigningKey::from_bytes(&secret)
        };
        let verifying_key = signing_key.verifying_key();
        let device_id = Uuid::new_v4();
        let timestamp = chrono::Utc::now().timestamp();
        let nonce = Uuid::new_v4().to_string();
        let body = b"request body";

        let signature = sign_request(
            &signing_key,
            "POST",
            "/api/v1/sync/push",
            timestamp,
            &nonce,
            body,
        );

        let header = format_auth_header(&device_id, timestamp, &nonce, &signature);

        let lookup = |id: &Uuid| -> Option<VerifyingKey> {
            if *id == device_id {
                Some(verifying_key)
            } else {
                None
            }
        };

        let result = verify_auth_header(&header, "POST", "/api/v1/sync/push", body, &lookup, 300);

        assert!(result.is_ok());
        let (parsed_id, parsed_ts, parsed_nonce) = result.unwrap();
        assert_eq!(parsed_id, device_id);
        assert_eq!(parsed_ts, timestamp);
        assert_eq!(parsed_nonce, nonce);
    }

    #[test]
    fn wrong_key_fails_verification() {
        let signing_key = {
            let mut secret = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut secret);
            SigningKey::from_bytes(&secret)
        };
        let wrong_key = {
            let mut secret = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut secret);
            SigningKey::from_bytes(&secret)
        };
        let device_id = Uuid::new_v4();
        let timestamp = chrono::Utc::now().timestamp();
        let nonce = Uuid::new_v4().to_string();
        let body = b"request body";

        let signature = sign_request(
            &signing_key,
            "POST",
            "/api/v1/sync/push",
            timestamp,
            &nonce,
            body,
        );

        let header = format_auth_header(&device_id, timestamp, &nonce, &signature);

        let lookup = |id: &Uuid| -> Option<VerifyingKey> {
            if *id == device_id {
                Some(wrong_key.verifying_key())
            } else {
                None
            }
        };

        let result = verify_auth_header(&header, "POST", "/api/v1/sync/push", body, &lookup, 300);

        assert_eq!(result.unwrap_err(), AuthError::InvalidSignature);
    }

    #[test]
    fn expired_timestamp_fails() {
        let signing_key = {
            let mut secret = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut secret);
            SigningKey::from_bytes(&secret)
        };
        let verifying_key = signing_key.verifying_key();
        let device_id = Uuid::new_v4();
        let timestamp = chrono::Utc::now().timestamp() - 600; // 10 min ago
        let nonce = Uuid::new_v4().to_string();
        let body = b"";

        let signature = sign_request(
            &signing_key,
            "GET",
            "/api/v1/status",
            timestamp,
            &nonce,
            body,
        );
        let header = format_auth_header(&device_id, timestamp, &nonce, &signature);

        let lookup = |id: &Uuid| -> Option<VerifyingKey> {
            if *id == device_id {
                Some(verifying_key)
            } else {
                None
            }
        };

        let result = verify_auth_header(&header, "GET", "/api/v1/status", body, &lookup, 300);
        assert_eq!(result.unwrap_err(), AuthError::Expired);
    }

    #[test]
    fn unknown_device_fails() {
        let signing_key = {
            let mut secret = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut secret);
            SigningKey::from_bytes(&secret)
        };
        let device_id = Uuid::new_v4();
        let timestamp = chrono::Utc::now().timestamp();
        let nonce = Uuid::new_v4().to_string();
        let body = b"data";

        let signature = sign_request(
            &signing_key,
            "POST",
            "/api/v1/sync/push",
            timestamp,
            &nonce,
            body,
        );
        let header = format_auth_header(&device_id, timestamp, &nonce, &signature);

        // Lookup always returns None (device not registered)
        let lookup = |_id: &Uuid| -> Option<VerifyingKey> { None };

        let result = verify_auth_header(&header, "POST", "/api/v1/sync/push", body, &lookup, 300);
        assert_eq!(result.unwrap_err(), AuthError::UnknownDevice);
    }

    #[test]
    fn tampered_method_fails() {
        let signing_key = {
            let mut secret = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut secret);
            SigningKey::from_bytes(&secret)
        };
        let verifying_key = signing_key.verifying_key();
        let device_id = Uuid::new_v4();
        let timestamp = chrono::Utc::now().timestamp();
        let nonce = Uuid::new_v4().to_string();
        let body = b"data";

        // Sign as POST
        let signature = sign_request(
            &signing_key,
            "POST",
            "/api/v1/sync/push",
            timestamp,
            &nonce,
            body,
        );
        let header = format_auth_header(&device_id, timestamp, &nonce, &signature);

        let lookup = |id: &Uuid| -> Option<VerifyingKey> {
            if *id == device_id {
                Some(verifying_key)
            } else {
                None
            }
        };

        // Verify as GET (method mismatch)
        let result = verify_auth_header(&header, "GET", "/api/v1/sync/push", body, &lookup, 300);
        assert_eq!(result.unwrap_err(), AuthError::InvalidSignature);
    }

    #[test]
    fn tampered_path_fails() {
        let signing_key = {
            let mut secret = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut secret);
            SigningKey::from_bytes(&secret)
        };
        let verifying_key = signing_key.verifying_key();
        let device_id = Uuid::new_v4();
        let timestamp = chrono::Utc::now().timestamp();
        let nonce = Uuid::new_v4().to_string();
        let body = b"data";

        let signature = sign_request(
            &signing_key,
            "POST",
            "/api/v1/sync/push",
            timestamp,
            &nonce,
            body,
        );
        let header = format_auth_header(&device_id, timestamp, &nonce, &signature);

        let lookup = |id: &Uuid| -> Option<VerifyingKey> {
            if *id == device_id {
                Some(verifying_key)
            } else {
                None
            }
        };

        // Verify with different path
        let result = verify_auth_header(
            &header,
            "POST",
            "/api/v1/sync/full-pull",
            body,
            &lookup,
            300,
        );
        assert_eq!(result.unwrap_err(), AuthError::InvalidSignature);
    }

    #[test]
    fn invalid_auth_scheme_rejected() {
        let lookup = |_id: &Uuid| -> Option<VerifyingKey> { None };
        let result = verify_auth_header(
            "Bearer token123",
            "GET",
            "/api/v1/status",
            b"",
            &lookup,
            300,
        );
        assert_eq!(result.unwrap_err(), AuthError::InvalidFormat);
    }

    #[test]
    fn malformed_header_rejected() {
        let lookup = |_id: &Uuid| -> Option<VerifyingKey> { None };
        // Missing fields
        let result = verify_auth_header(
            "SentinelPass-Ed25519 abc:123",
            "GET",
            "/api/v1/status",
            b"",
            &lookup,
            300,
        );
        assert_eq!(result.unwrap_err(), AuthError::InvalidFormat);
    }

    #[test]
    fn tampered_body_fails() {
        let signing_key = {
            let mut secret = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut secret);
            SigningKey::from_bytes(&secret)
        };
        let verifying_key = signing_key.verifying_key();
        let device_id = Uuid::new_v4();
        let timestamp = chrono::Utc::now().timestamp();
        let nonce = Uuid::new_v4().to_string();

        let signature = sign_request(
            &signing_key,
            "POST",
            "/api/v1/sync/push",
            timestamp,
            &nonce,
            b"original body",
        );
        let header = format_auth_header(&device_id, timestamp, &nonce, &signature);

        let lookup = |id: &Uuid| -> Option<VerifyingKey> {
            if *id == device_id {
                Some(verifying_key)
            } else {
                None
            }
        };

        let result = verify_auth_header(
            &header,
            "POST",
            "/api/v1/sync/push",
            b"tampered body",
            &lookup,
            300,
        );
        assert_eq!(result.unwrap_err(), AuthError::InvalidSignature);
    }
}
