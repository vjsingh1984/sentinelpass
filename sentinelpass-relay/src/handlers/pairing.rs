//! Pairing bootstrap handlers.

use crate::error::RelayError;
use crate::storage::RelayStorage;
use axum::extract::{Path, State};
use axum::Json;
use base64::Engine;
use chrono::Utc;
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct UploadBootstrapRequest {
    pub pairing_token: String,
    pub encrypted_bootstrap: String, // base64
    pub pairing_salt: String,        // base64
}

#[derive(Serialize)]
pub struct BootstrapResponse {
    pub encrypted_bootstrap: String, // base64
    pub pairing_salt: String,        // base64
}

pub async fn upload_bootstrap(
    State(storage): State<RelayStorage>,
    Json(req): Json<UploadBootstrapRequest>,
) -> Result<Json<serde_json::Value>, RelayError> {
    let encrypted = base64::engine::general_purpose::STANDARD
        .decode(&req.encrypted_bootstrap)
        .map_err(|e| RelayError::BadRequest(format!("Invalid bootstrap: {}", e)))?;

    let salt = base64::engine::general_purpose::STANDARD
        .decode(&req.pairing_salt)
        .map_err(|e| RelayError::BadRequest(format!("Invalid salt: {}", e)))?;

    let conn = storage.conn()?;
    let now = Utc::now().timestamp();
    let expires_at = now + 300; // 5 minute TTL

    // Check active pairing count
    let active_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM pairing_bootstraps WHERE expires_at > ?1 AND consumed = 0",
            [now],
            |row| row.get(0),
        )
        .map_err(|e| RelayError::Database(e.to_string()))?;

    if active_count >= 5 {
        return Err(RelayError::Conflict("Too many active pairings".to_string()));
    }

    conn.execute(
        "INSERT INTO pairing_bootstraps (pairing_token, vault_id, encrypted_bootstrap, pairing_salt, expires_at)
         VALUES (?1, '', ?2, ?3, ?4)",
        rusqlite::params![req.pairing_token, encrypted, salt, expires_at],
    )
    .map_err(|e| RelayError::Database(e.to_string()))?;

    Ok(Json(
        serde_json::json!({"status": "uploaded", "expires_at": expires_at}),
    ))
}

pub async fn fetch_bootstrap(
    State(storage): State<RelayStorage>,
    Path(token): Path<String>,
) -> Result<Json<BootstrapResponse>, RelayError> {
    let conn = storage.conn()?;
    let now = Utc::now().timestamp();

    let (encrypted, salt): (Vec<u8>, Vec<u8>) = conn
        .query_row(
            "SELECT encrypted_bootstrap, pairing_salt FROM pairing_bootstraps
             WHERE pairing_token = ?1 AND expires_at > ?2 AND consumed = 0",
            rusqlite::params![token, now],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|_| RelayError::NotFound("Pairing token not found or expired".to_string()))?;

    // Mark as consumed
    conn.execute(
        "UPDATE pairing_bootstraps SET consumed = 1 WHERE pairing_token = ?1",
        [&token],
    )
    .map_err(|e| RelayError::Database(e.to_string()))?;

    Ok(Json(BootstrapResponse {
        encrypted_bootstrap: base64::engine::general_purpose::STANDARD.encode(&encrypted),
        pairing_salt: base64::engine::general_purpose::STANDARD.encode(&salt),
    }))
}
