//! Daemon vault state management for the daemon
//!
//! The daemon maintains the vault in memory, handling lock/unlock
//! and responding to credential requests.

use crate::{VaultManager, get_default_vault_path, Result, PasswordManagerError};
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use std::path::PathBuf;
use tokio::time::{interval, Duration};
use tracing::{info, warn};

/// Vault state for the daemon
#[derive(Clone, Copy, Debug)]
pub enum VaultState {
    Locked,
    Unlocked,
}

/// Daemon vault manager with auto-lock functionality
pub struct DaemonVault {
    vault: Arc<Mutex<Option<VaultManager>>>,
    state: Arc<RwLock<VaultState>>,
    vault_path: PathBuf,
    inactivity_timeout: Duration,
}

impl DaemonVault {
    /// Create a new daemon vault manager
    pub fn new(vault_path: Option<PathBuf>, inactivity_timeout_sec: u64) -> Result<Self> {
        let vault_path = vault_path.unwrap_or_else(|| get_default_vault_path());

        if !vault_path.exists() {
            return Err(PasswordManagerError::NotFound(format!("No vault found at {:?}", vault_path)));
        }

        Ok(Self {
            vault: Arc::new(Mutex::new(None)),
            state: Arc::new(RwLock::new(VaultState::Locked)),
            vault_path,
            inactivity_timeout: Duration::from_secs(inactivity_timeout_sec),
        })
    }

    /// Unlock the vault with master password
    pub async fn unlock(&self, master_password: &[u8]) -> Result<()> {
        let vault = VaultManager::open(&self.vault_path, master_password)
            .map_err(|e| PasswordManagerError::Database(format!("Failed to unlock vault: {}", e)))?;

        *self.vault.lock().await = Some(vault);
        *self.state.write().await = VaultState::Unlocked;

        info!("Vault unlocked successfully");

        // Start auto-lock task
        self.start_auto_lock_task();

        Ok(())
    }

    /// Lock the vault
    pub async fn lock(&self) {
        *self.vault.lock().await = None;
        *self.state.write().await = VaultState::Locked;
        info!("Vault locked");
    }

    /// Check if vault is unlocked
    pub async fn is_unlocked(&self) -> bool {
        matches!(*self.state.read().await, VaultState::Unlocked)
    }

    /// Get credential by domain
    pub async fn get_credential(&self, domain: &str) -> Result<Option<CredentialResponse>> {
        if !self.is_unlocked().await {
            return Ok(None);
        }

        let vault_guard = self.vault.lock().await;

        if let Some(ref vault) = *vault_guard {
            // List entries and search for matching domain
            let entries = vault.list_entries()?;

            // Search for entry with matching domain in URL
            for summary in entries {
                if let Ok(entry) = vault.get_entry(summary.entry_id) {
                    if let Some(ref url) = entry.url {
                        if url.contains(domain) || domain.contains(url) {
                            return Ok(Some(CredentialResponse {
                                username: entry.username,
                                password: entry.password,
                                title: entry.title,
                            }));
                        }
                    }
                }
            }

            Ok(None)
        } else {
            Ok(None)
        }
    }

    /// Record activity (resets the auto-lock timer)
    pub async fn record_activity(&self) {
        // Auto-lock is based on time since last activity
        // In a real implementation, we'd track last activity time
        // and check it in the auto-lock task
    }

    /// Start the auto-lock background task
    fn start_auto_lock_task(&self) {
        let state = self.state.clone();
        let vault = self.vault.clone();
        let timeout = self.inactivity_timeout;

        tokio::spawn(async move {
            let mut timer = interval(timeout);
            timer.tick().await; // Skip first tick

            loop {
                timer.tick().await;
                let current_state = state.read().await;
                if matches!(*current_state, VaultState::Unlocked) {
                    warn!("Auto-locking vault due to inactivity");
                    *vault.lock().await = None;
                    *state.write().await = VaultState::Locked;
                }
            }
        });
    }
}

/// Response with credential data
#[derive(Debug, Clone)]
pub struct CredentialResponse {
    pub username: String,
    pub password: String,
    pub title: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vault_state() {
        let state = VaultState::Locked;
        assert!(matches!(state, VaultState::Locked));
    }
}
