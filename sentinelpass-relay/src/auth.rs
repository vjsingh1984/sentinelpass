//! Ed25519 auth middleware for the relay server.

use crate::error::RelayError;
use crate::storage::RelayStorage;
use axum::body::Body;
use axum::extract::State;
use axum::http::Request;
use axum::middleware::Next;
use axum::response::Response;
use chrono::Utc;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Auth middleware: verifies Ed25519 signature on every authenticated request.
pub async fn auth_middleware(
    State(storage): State<RelayStorage>,
    request: Request<Body>,
    next: Next,
) -> Result<Response, RelayError> {
    let auth_header = request
        .headers()
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| RelayError::Auth("Missing Authorization header".to_string()))?
        .to_string();

    let method = request.method().as_str().to_string();
    let path = request.uri().path().to_string();

    // Read body for signature verification
    let (parts, body) = request.into_parts();
    let body_bytes = axum::body::to_bytes(body, 1024 * 1024)
        .await
        .map_err(|e| RelayError::BadRequest(format!("Failed to read body: {}", e)))?;

    let (device_id, _timestamp, nonce) =
        verify_auth(&auth_header, &method, &path, &body_bytes, &storage)?;

    // Check nonce dedup
    {
        let conn = storage.conn()?;
        let now = Utc::now().timestamp();

        let seen: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM seen_nonces WHERE nonce = ?1)",
                [&nonce],
                |row| row.get(0),
            )
            .map_err(|e| RelayError::Database(e.to_string()))?;

        if seen {
            return Err(RelayError::Auth("Nonce reused".to_string()));
        }

        conn.execute(
            "INSERT INTO seen_nonces (nonce, device_id, seen_at) VALUES (?1, ?2, ?3)",
            rusqlite::params![nonce, device_id.to_string(), now],
        )
        .map_err(|e| RelayError::Database(e.to_string()))?;
    }

    // Reconstruct request with device_id in extensions and original body
    let mut request = Request::from_parts(parts, Body::from(body_bytes));
    request.extensions_mut().insert(device_id);

    Ok(next.run(request).await)
}

fn verify_auth(
    header: &str,
    method: &str,
    path: &str,
    body: &[u8],
    storage: &RelayStorage,
) -> Result<(Uuid, i64, String), RelayError> {
    let stripped = header
        .strip_prefix("SentinelPass-Ed25519 ")
        .ok_or_else(|| RelayError::Auth("Invalid auth scheme".to_string()))?;

    let parts: Vec<&str> = stripped.splitn(4, ':').collect();
    if parts.len() != 4 {
        return Err(RelayError::Auth("Invalid auth format".to_string()));
    }

    let device_id =
        Uuid::parse_str(parts[0]).map_err(|_| RelayError::Auth("Invalid device ID".to_string()))?;
    let timestamp: i64 = parts[1]
        .parse()
        .map_err(|_| RelayError::Auth("Invalid timestamp".to_string()))?;
    let nonce = parts[2].to_string();
    let sig_bytes = base64::engine::general_purpose::STANDARD
        .decode(parts[3])
        .map_err(|_| RelayError::Auth("Invalid signature encoding".to_string()))?;

    // Check timestamp freshness (5 min window)
    let now = Utc::now().timestamp();
    if (now - timestamp).abs() > 300 {
        return Err(RelayError::Auth("Request expired".to_string()));
    }

    // Look up device public key
    let conn = storage.conn()?;
    let (public_key_bytes, revoked): (Vec<u8>, bool) = conn
        .query_row(
            "SELECT public_key, revoked FROM devices WHERE device_id = ?1",
            [device_id.to_string()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|_| RelayError::Auth("Unknown device".to_string()))?;

    if revoked {
        return Err(RelayError::Auth("Device revoked".to_string()));
    }

    // Verify signature
    let body_hash = hex::encode(Sha256::digest(body));
    let message = format!(
        "{}\n{}\n{}\n{}\n{}",
        method, path, timestamp, nonce, body_hash
    );

    let key_array: [u8; 32] = public_key_bytes
        .try_into()
        .map_err(|_| RelayError::Auth("Invalid public key".to_string()))?;
    let verifying_key = VerifyingKey::from_bytes(&key_array)
        .map_err(|_| RelayError::Auth("Invalid public key".to_string()))?;

    let sig_array: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| RelayError::Auth("Invalid signature length".to_string()))?;
    let signature = Signature::from_bytes(&sig_array);

    verifying_key
        .verify(message.as_bytes(), &signature)
        .map_err(|_| RelayError::Auth("Signature verification failed".to_string()))?;

    Ok((device_id, timestamp, nonce))
}

use base64::Engine;
