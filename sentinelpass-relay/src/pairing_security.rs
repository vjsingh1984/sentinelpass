//! Pairing token/proof helpers for relay-side verification and at-rest hashing.

use crate::error::RelayError;
use base64::Engine;
use sha2::{Digest, Sha256};

const MAX_PAIRING_TOKEN_LEN: usize = 256;
const REGISTRATION_PROOF_LEN: usize = 32;

pub(crate) fn hash_pairing_token(token: &str) -> Result<String, RelayError> {
    if token.is_empty() || token.len() > MAX_PAIRING_TOKEN_LEN {
        return Err(RelayError::BadRequest(
            "Invalid pairing token length".to_string(),
        ));
    }

    Ok(hash_bytes_hex(token.as_bytes()))
}

pub(crate) fn hash_registration_proof_b64(proof_b64: &str) -> Result<String, RelayError> {
    let proof = base64::engine::general_purpose::STANDARD
        .decode(proof_b64)
        .map_err(|e| RelayError::BadRequest(format!("Invalid registration proof: {}", e)))?;

    if proof.len() != REGISTRATION_PROOF_LEN {
        return Err(RelayError::BadRequest(
            "Registration proof must be 32 bytes".to_string(),
        ));
    }

    Ok(hash_bytes_hex(&proof))
}

pub(crate) fn hash_bytes_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes_pairing_token_without_leaking_raw_value() {
        let token = "123456";
        let hashed = hash_pairing_token(token).unwrap();
        assert_ne!(hashed, token);
        assert_eq!(hashed.len(), 64);
    }

    #[test]
    fn registration_proof_requires_32_bytes() {
        let short = base64::engine::general_purpose::STANDARD.encode([1u8; 8]);
        let err = hash_registration_proof_b64(&short).expect_err("short proof rejected");
        match err {
            RelayError::BadRequest(msg) => assert!(msg.contains("32 bytes")),
            other => panic!("unexpected error: {}", other),
        }
    }
}
