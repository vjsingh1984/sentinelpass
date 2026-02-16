//! Sync configuration stored in the local database.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{DatabaseError, Result};

/// Sync configuration for this device.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SyncConfig {
    pub sync_enabled: bool,
    pub vault_id: Option<Uuid>,
    pub device_id: Option<Uuid>,
    pub device_name: Option<String>,
    pub relay_url: Option<String>,
    pub last_push_sequence: u64,
    pub last_pull_sequence: u64,
    pub last_sync_at: Option<i64>,
}

impl SyncConfig {
    /// Load sync config from the database. Returns default if no row exists.
    pub fn load(conn: &rusqlite::Connection) -> Result<Self> {
        let exists: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='sync_metadata')",
                [],
                |row| row.get(0),
            )
            .map_err(DatabaseError::Sqlite)?;

        if !exists {
            return Ok(Self::default());
        }

        let result = conn.query_row(
            "SELECT vault_id, device_id, device_name, relay_url,
                    last_push_sequence, last_pull_sequence, last_sync_at, sync_enabled
             FROM sync_metadata WHERE id = 1",
            [],
            |row| {
                let vault_id: Option<String> = row.get(0)?;
                let device_id: Option<String> = row.get(1)?;
                let device_name: Option<String> = row.get(2)?;
                let relay_url: Option<String> = row.get(3)?;
                let last_push_sequence: i64 = row.get(4)?;
                let last_pull_sequence: i64 = row.get(5)?;
                let last_sync_at: Option<i64> = row.get(6)?;
                let sync_enabled: bool = row.get(7)?;

                Ok(SyncConfig {
                    sync_enabled,
                    vault_id: vault_id.and_then(|s| Uuid::parse_str(&s).ok()),
                    device_id: device_id.and_then(|s| Uuid::parse_str(&s).ok()),
                    device_name,
                    relay_url,
                    last_push_sequence: last_push_sequence as u64,
                    last_pull_sequence: last_pull_sequence as u64,
                    last_sync_at,
                })
            },
        );

        match result {
            Ok(config) => Ok(config),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(Self::default()),
            Err(e) => Err(DatabaseError::Sqlite(e).into()),
        }
    }

    /// Save sync config to the database (upsert).
    pub fn save(&self, conn: &rusqlite::Connection) -> Result<()> {
        conn.execute(
            "INSERT INTO sync_metadata (id, vault_id, device_id, device_name, relay_url,
                                        last_push_sequence, last_pull_sequence, last_sync_at, sync_enabled)
             VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(id) DO UPDATE SET
                vault_id = excluded.vault_id,
                device_id = excluded.device_id,
                device_name = excluded.device_name,
                relay_url = excluded.relay_url,
                last_push_sequence = excluded.last_push_sequence,
                last_pull_sequence = excluded.last_pull_sequence,
                last_sync_at = excluded.last_sync_at,
                sync_enabled = excluded.sync_enabled",
            rusqlite::params![
                self.vault_id.map(|u| u.to_string()),
                self.device_id.map(|u| u.to_string()),
                self.device_name,
                self.relay_url,
                self.last_push_sequence as i64,
                self.last_pull_sequence as i64,
                self.last_sync_at,
                self.sync_enabled,
            ],
        )
        .map_err(DatabaseError::Sqlite)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config() {
        let config = SyncConfig::default();
        assert!(!config.sync_enabled);
        assert!(config.vault_id.is_none());
        assert!(config.device_id.is_none());
        assert_eq!(config.last_push_sequence, 0);
    }
}
