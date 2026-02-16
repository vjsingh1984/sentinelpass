//! Relay storage model types.

use serde::{Deserialize, Serialize};

#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredDevice {
    pub device_id: String,
    pub vault_id: String,
    pub device_name: String,
    pub device_type: String,
    pub public_key: Vec<u8>,
    pub registered_at: i64,
    pub revoked: bool,
    pub revoked_at: Option<i64>,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredSyncEntry {
    pub sync_id: String,
    pub vault_id: String,
    pub entry_type: String,
    pub sync_version: i64,
    pub modified_at: i64,
    pub encrypted_payload: Vec<u8>,
    pub is_tombstone: bool,
    pub origin_device_id: String,
    pub server_sequence: i64,
    pub received_at: i64,
}
