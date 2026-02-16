//! Sync push/pull handlers.

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
pub struct SyncEntryBlob {
    pub sync_id: Uuid,
    pub entry_type: String,
    pub sync_version: u64,
    pub modified_at: i64,
    pub encrypted_payload: String, // base64
    pub is_tombstone: bool,
    pub origin_device_id: Uuid,
}

#[derive(Deserialize)]
pub struct PushRequest {
    pub device_sequence: u64,
    pub entries: Vec<SyncEntryBlob>,
}

#[derive(Serialize)]
pub struct PushResponse {
    pub accepted: u64,
    pub rejected: u64,
    pub server_sequence: u64,
}

#[derive(Deserialize)]
pub struct PullRequest {
    pub since_sequence: u64,
    pub limit: Option<u64>,
}

#[derive(Serialize)]
pub struct PullEntry {
    pub sync_id: String,
    pub entry_type: String,
    pub sync_version: u64,
    pub modified_at: i64,
    pub encrypted_payload: String, // base64
    pub is_tombstone: bool,
    pub origin_device_id: String,
}

#[derive(Serialize)]
pub struct PullResponse {
    pub entries: Vec<PullEntry>,
    pub server_sequence: u64,
    pub has_more: bool,
}

pub async fn push(
    State(storage): State<RelayStorage>,
    extensions: Extensions,
    Json(req): Json<PushRequest>,
) -> Result<Json<PushResponse>, RelayError> {
    let device_id = extensions
        .get::<Uuid>()
        .ok_or_else(|| RelayError::Auth("No device ID".to_string()))?;

    let conn = storage.conn()?;

    // Get vault_id for this device
    let vault_id: String = conn
        .query_row(
            "SELECT vault_id FROM devices WHERE device_id = ?1",
            [device_id.to_string()],
            |row| row.get(0),
        )
        .map_err(|_| RelayError::NotFound("Device not found".to_string()))?;

    // Check device sequence (monotonic)
    let last_seq: i64 = conn
        .query_row(
            "SELECT last_sequence FROM device_sequences WHERE device_id = ?1",
            [device_id.to_string()],
            |row| row.get(0),
        )
        .unwrap_or(0);

    if (req.device_sequence as i64) <= last_seq {
        return Err(RelayError::Conflict(
            "Device sequence not increasing".to_string(),
        ));
    }

    let now = Utc::now().timestamp();
    let mut accepted = 0u64;
    let mut rejected = 0u64;

    for entry in &req.entries {
        let payload = base64::engine::general_purpose::STANDARD
            .decode(&entry.encrypted_payload)
            .map_err(|e| RelayError::BadRequest(format!("Invalid payload: {}", e)))?;

        let sync_id_str = entry.sync_id.to_string();

        // Check if we already have this sync_id with a higher version
        let existing_version: Option<i64> = conn
            .query_row(
                "SELECT sync_version FROM sync_entries WHERE sync_id = ?1 AND vault_id = ?2",
                rusqlite::params![sync_id_str, vault_id],
                |row| row.get(0),
            )
            .ok();

        if let Some(existing) = existing_version {
            if entry.sync_version as i64 <= existing {
                // Same or lower version, check modified_at for tie-break
                let existing_modified: i64 = conn
                    .query_row(
                        "SELECT modified_at FROM sync_entries WHERE sync_id = ?1 AND vault_id = ?2",
                        rusqlite::params![sync_id_str, vault_id],
                        |row| row.get(0),
                    )
                    .unwrap_or(0);

                if entry.sync_version as i64 == existing && entry.modified_at <= existing_modified {
                    rejected += 1;
                    continue;
                }
                if (entry.sync_version as i64) < existing {
                    rejected += 1;
                    continue;
                }
            }
        }

        // Increment server sequence
        conn.execute(
            "UPDATE sequence_counters SET current_sequence = current_sequence + 1 WHERE vault_id = ?1",
            [&vault_id],
        )
        .map_err(|e| RelayError::Database(e.to_string()))?;

        let server_seq: i64 = conn
            .query_row(
                "SELECT current_sequence FROM sequence_counters WHERE vault_id = ?1",
                [&vault_id],
                |row| row.get(0),
            )
            .map_err(|e| RelayError::Database(e.to_string()))?;

        // Upsert the entry
        conn.execute(
            "INSERT INTO sync_entries (sync_id, vault_id, entry_type, sync_version, modified_at,
                                       encrypted_payload, is_tombstone, origin_device_id,
                                       server_sequence, received_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
             ON CONFLICT(sync_id, vault_id) DO UPDATE SET
                entry_type = excluded.entry_type,
                sync_version = excluded.sync_version,
                modified_at = excluded.modified_at,
                encrypted_payload = excluded.encrypted_payload,
                is_tombstone = excluded.is_tombstone,
                origin_device_id = excluded.origin_device_id,
                server_sequence = excluded.server_sequence,
                received_at = excluded.received_at",
            rusqlite::params![
                sync_id_str,
                vault_id,
                entry.entry_type,
                entry.sync_version as i64,
                entry.modified_at,
                payload,
                entry.is_tombstone,
                entry.origin_device_id.to_string(),
                server_seq,
                now,
            ],
        )
        .map_err(|e| RelayError::Database(e.to_string()))?;

        accepted += 1;
    }

    // Update device sequence
    conn.execute(
        "UPDATE device_sequences SET last_sequence = ?1 WHERE device_id = ?2",
        rusqlite::params![req.device_sequence as i64, device_id.to_string()],
    )
    .map_err(|e| RelayError::Database(e.to_string()))?;

    let server_seq: i64 = conn
        .query_row(
            "SELECT current_sequence FROM sequence_counters WHERE vault_id = ?1",
            [&vault_id],
            |row| row.get(0),
        )
        .map_err(|e| RelayError::Database(e.to_string()))?;

    Ok(Json(PushResponse {
        accepted,
        rejected,
        server_sequence: server_seq as u64,
    }))
}

pub async fn pull(
    State(storage): State<RelayStorage>,
    extensions: Extensions,
    Json(req): Json<PullRequest>,
) -> Result<Json<PullResponse>, RelayError> {
    let device_id = extensions
        .get::<Uuid>()
        .ok_or_else(|| RelayError::Auth("No device ID".to_string()))?;

    let conn = storage.conn()?;

    let vault_id: String = conn
        .query_row(
            "SELECT vault_id FROM devices WHERE device_id = ?1",
            [device_id.to_string()],
            |row| row.get(0),
        )
        .map_err(|_| RelayError::NotFound("Device not found".to_string()))?;

    let limit = req.limit.unwrap_or(1000).min(10_000) as i64;

    let mut stmt = conn
        .prepare(
            "SELECT sync_id, entry_type, sync_version, modified_at,
                    encrypted_payload, is_tombstone, origin_device_id, server_sequence
             FROM sync_entries
             WHERE vault_id = ?1 AND server_sequence > ?2
             ORDER BY server_sequence ASC
             LIMIT ?3",
        )
        .map_err(|e| RelayError::Database(e.to_string()))?;

    let entries: Vec<PullEntry> = stmt
        .query_map(
            rusqlite::params![vault_id, req.since_sequence as i64, limit + 1],
            |row| {
                let payload: Vec<u8> = row.get(4)?;
                Ok(PullEntry {
                    sync_id: row.get(0)?,
                    entry_type: row.get(1)?,
                    sync_version: row.get::<_, i64>(2)? as u64,
                    modified_at: row.get(3)?,
                    encrypted_payload: base64::engine::general_purpose::STANDARD.encode(&payload),
                    is_tombstone: row.get(5)?,
                    origin_device_id: row.get(6)?,
                })
            },
        )
        .map_err(|e| RelayError::Database(e.to_string()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| RelayError::Database(e.to_string()))?;

    let has_more = entries.len() > limit as usize;
    let entries: Vec<PullEntry> = entries.into_iter().take(limit as usize).collect();

    let server_seq: i64 = conn
        .query_row(
            "SELECT current_sequence FROM sequence_counters WHERE vault_id = ?1",
            [&vault_id],
            |row| row.get(0),
        )
        .map_err(|e| RelayError::Database(e.to_string()))?;

    Ok(Json(PullResponse {
        entries,
        server_sequence: server_seq as u64,
        has_more,
    }))
}

pub async fn full_push(
    State(storage): State<RelayStorage>,
    extensions: Extensions,
    Json(entries): Json<Vec<SyncEntryBlob>>,
) -> Result<Json<PushResponse>, RelayError> {
    // Delegate to regular push with sequence 1
    let req = PushRequest {
        device_sequence: 1,
        entries,
    };
    push(State(storage), extensions, Json(req)).await
}

pub async fn full_pull(
    State(storage): State<RelayStorage>,
    extensions: Extensions,
) -> Result<Json<Vec<PullEntry>>, RelayError> {
    let req = PullRequest {
        since_sequence: 0,
        limit: Some(100_000),
    };
    let response = pull(State(storage), extensions, Json(req)).await?;
    Ok(Json(response.0.entries))
}

pub async fn status(
    State(storage): State<RelayStorage>,
    extensions: Extensions,
) -> Result<Json<serde_json::Value>, RelayError> {
    let device_id = extensions
        .get::<Uuid>()
        .ok_or_else(|| RelayError::Auth("No device ID".to_string()))?;

    let conn = storage.conn()?;

    let vault_id: String = conn
        .query_row(
            "SELECT vault_id FROM devices WHERE device_id = ?1",
            [device_id.to_string()],
            |row| row.get(0),
        )
        .map_err(|_| RelayError::NotFound("Device not found".to_string()))?;

    let entry_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sync_entries WHERE vault_id = ?1 AND is_tombstone = 0",
            [&vault_id],
            |row| row.get(0),
        )
        .map_err(|e| RelayError::Database(e.to_string()))?;

    let current_seq: i64 = conn
        .query_row(
            "SELECT current_sequence FROM sequence_counters WHERE vault_id = ?1",
            [&vault_id],
            |row| row.get(0),
        )
        .unwrap_or(0);

    Ok(Json(serde_json::json!({
        "vault_id": vault_id,
        "entry_count": entry_count,
        "server_sequence": current_seq,
    })))
}
