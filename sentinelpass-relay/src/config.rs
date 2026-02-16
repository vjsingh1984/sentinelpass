//! Relay server configuration.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayConfig {
    pub listen_addr: String,
    pub storage_path: PathBuf,
    pub max_entries_per_vault: usize,
    pub max_payload_size: usize,
    pub rate_limit_per_minute: u32,
    pub pairing_ttl_secs: u64,
    pub max_active_pairings: usize,
    pub tombstone_retention_days: u64,
    pub nonce_window_secs: i64,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            listen_addr: "127.0.0.1:8743".to_string(),
            storage_path: PathBuf::from("relay.db"),
            max_entries_per_vault: 10_000,
            max_payload_size: 65_536,
            rate_limit_per_minute: 60,
            pairing_ttl_secs: 300,
            max_active_pairings: 5,
            tombstone_retention_days: 90,
            nonce_window_secs: 300,
        }
    }
}

impl RelayConfig {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: Self = toml_dep::from_str(&content)?;
        Ok(config)
    }
}
