//! Device registration and management handlers.

use crate::error::RelayError;
use crate::storage::RelayStorage;
use axum::extract::State;
use axum::http::Extensions;
use axum::Json;
use base64::Engine;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Deserialize)]
pub struct RegisterDeviceRequest {
    pub device_id: Uuid,
    pub device_name: String,
    pub device_type: String,
    pub public_key: String, // base64
    pub vault_id: Uuid,
}

#[derive(Serialize)]
pub struct DeviceInfo {
    pub device_id: String,
    pub device_name: String,
    pub device_type: String,
    pub registered_at: i64,
    pub revoked: bool,
}

pub async fn register_device(
    State(storage): State<RelayStorage>,
    Json(req): Json<RegisterDeviceRequest>,
) -> Result<Json<serde_json::Value>, RelayError> {
    let public_key = base64::engine::general_purpose::STANDARD
        .decode(&req.public_key)
        .map_err(|e| RelayError::BadRequest(format!("Invalid public key: {}", e)))?;

    if public_key.len() != 32 {
        return Err(RelayError::BadRequest(
            "Public key must be 32 bytes".to_string(),
        ));
    }

    let conn = storage.conn()?;
    let now = Utc::now().timestamp();
    let vault_id_str = req.vault_id.to_string();
    let device_id_str = req.device_id.to_string();

    // Ensure vault exists
    conn.execute(
        "INSERT OR IGNORE INTO vaults (vault_id, created_at) VALUES (?1, ?2)",
        rusqlite::params![vault_id_str, now],
    )
    .map_err(|e| RelayError::Database(e.to_string()))?;

    // Ensure sequence counter exists
    conn.execute(
        "INSERT OR IGNORE INTO sequence_counters (vault_id, current_sequence) VALUES (?1, 0)",
        [&vault_id_str],
    )
    .map_err(|e| RelayError::Database(e.to_string()))?;

    // Register device
    conn.execute(
        "INSERT INTO devices (device_id, vault_id, device_name, device_type, public_key, registered_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)
         ON CONFLICT(device_id) DO UPDATE SET
            device_name = excluded.device_name,
            public_key = excluded.public_key",
        rusqlite::params![
            device_id_str,
            vault_id_str,
            req.device_name,
            req.device_type,
            public_key,
            now,
        ],
    )
    .map_err(|e| RelayError::Database(e.to_string()))?;

    // Init device sequence
    conn.execute(
        "INSERT OR IGNORE INTO device_sequences (device_id, last_sequence) VALUES (?1, 0)",
        [&device_id_str],
    )
    .map_err(|e| RelayError::Database(e.to_string()))?;

    Ok(Json(serde_json::json!({"status": "registered"})))
}

pub async fn list_devices(
    State(storage): State<RelayStorage>,
    extensions: Extensions,
) -> Result<Json<Vec<DeviceInfo>>, RelayError> {
    let device_id = extensions
        .get::<Uuid>()
        .ok_or_else(|| RelayError::Auth("No device ID".to_string()))?;

    let conn = storage.conn()?;

    // Find vault for this device
    let vault_id: String = conn
        .query_row(
            "SELECT vault_id FROM devices WHERE device_id = ?1",
            [device_id.to_string()],
            |row| row.get(0),
        )
        .map_err(|_| RelayError::NotFound("Device not found".to_string()))?;

    let mut stmt = conn
        .prepare(
            "SELECT device_id, device_name, device_type, registered_at, revoked
             FROM devices WHERE vault_id = ?1",
        )
        .map_err(|e| RelayError::Database(e.to_string()))?;

    let devices: Vec<DeviceInfo> = stmt
        .query_map([&vault_id], |row| {
            Ok(DeviceInfo {
                device_id: row.get(0)?,
                device_name: row.get(1)?,
                device_type: row.get(2)?,
                registered_at: row.get(3)?,
                revoked: row.get(4)?,
            })
        })
        .map_err(|e| RelayError::Database(e.to_string()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| RelayError::Database(e.to_string()))?;

    Ok(Json(devices))
}

pub async fn revoke_device(
    State(storage): State<RelayStorage>,
    axum::extract::Path(target_id): axum::extract::Path<String>,
    extensions: Extensions,
) -> Result<Json<serde_json::Value>, RelayError> {
    let requester_id = extensions
        .get::<Uuid>()
        .ok_or_else(|| RelayError::Auth("No device ID".to_string()))?;

    let conn = storage.conn()?;

    // Verify both devices belong to the same vault
    let requester_vault: String = conn
        .query_row(
            "SELECT vault_id FROM devices WHERE device_id = ?1",
            [requester_id.to_string()],
            |row| row.get(0),
        )
        .map_err(|_| RelayError::NotFound("Requester device not found".to_string()))?;

    let target_vault: String = conn
        .query_row(
            "SELECT vault_id FROM devices WHERE device_id = ?1",
            [&target_id],
            |row| row.get(0),
        )
        .map_err(|_| RelayError::NotFound("Target device not found".to_string()))?;

    if requester_vault != target_vault {
        return Err(RelayError::Auth(
            "Cannot revoke device from different vault".to_string(),
        ));
    }

    let now = Utc::now().timestamp();
    conn.execute(
        "UPDATE devices SET revoked = 1, revoked_at = ?1 WHERE device_id = ?2",
        rusqlite::params![now, target_id],
    )
    .map_err(|e| RelayError::Database(e.to_string()))?;

    Ok(Json(serde_json::json!({"status": "revoked"})))
}
