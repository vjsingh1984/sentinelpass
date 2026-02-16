//! Daemon vault state management for the daemon
//!
//! The daemon maintains the vault in memory, handling lock/unlock
//! and responding to credential requests.

use crate::{get_default_vault_path, DatabaseError, PasswordManagerError, Result, VaultManager};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::{Mutex, RwLock};
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
    last_activity: Arc<RwLock<Instant>>,
    vault_path: PathBuf,
    inactivity_timeout: Duration,
}

fn normalize_host(value: &str) -> Option<String> {
    let normalized = value.trim().trim_matches('.').to_ascii_lowercase();
    if normalized.is_empty() {
        return None;
    }

    let mut host = normalized.as_str();

    if let Some(scheme_pos) = host.find("://") {
        host = &host[(scheme_pos + 3)..];
    }

    if let Some(at_pos) = host.rfind('@') {
        host = &host[(at_pos + 1)..];
    }

    let host_end = host.find(['/', '?', '#']).unwrap_or(host.len());
    host = &host[..host_end];
    host = host.trim_end_matches('.');

    // Bracketed IPv6 URL host: [::1]:443
    if host.starts_with('[') {
        if let Some(end) = host.find(']') {
            let ipv6 = &host[1..end];
            if !ipv6.is_empty() {
                return Some(ipv6.to_string());
            }
        }
        return None;
    }

    // Strip port for host:port. Skip for non-bracketed IPv6.
    if let Some(colon_pos) = host.rfind(':') {
        if !host[..colon_pos].contains(':') {
            host = &host[..colon_pos];
        }
    }

    let host = host.trim().trim_matches('.');
    if host.is_empty() {
        None
    } else {
        Some(host.to_string())
    }
}

fn domains_match(request_domain: &str, entry_url_or_domain: &str) -> bool {
    let Some(request_host) = normalize_host(request_domain) else {
        return false;
    };
    let Some(entry_host) = normalize_host(entry_url_or_domain) else {
        return false;
    };

    if request_host == entry_host {
        return true;
    }

    let request_suffix = format!(".{}", request_host);
    let entry_suffix = format!(".{}", entry_host);
    request_host.ends_with(&entry_suffix) || entry_host.ends_with(&request_suffix)
}

fn usernames_match(lhs: &str, rhs: &str) -> bool {
    lhs.trim().eq_ignore_ascii_case(rhs.trim())
}

impl DaemonVault {
    /// Create a new daemon vault manager
    pub fn new(vault_path: Option<PathBuf>, inactivity_timeout_sec: u64) -> Result<Self> {
        let vault_path = vault_path.unwrap_or_else(get_default_vault_path);

        if !vault_path.exists() {
            return Err(PasswordManagerError::NotFound(format!(
                "No vault found at {:?}",
                vault_path
            )));
        }

        Ok(Self {
            vault: Arc::new(Mutex::new(None)),
            state: Arc::new(RwLock::new(VaultState::Locked)),
            last_activity: Arc::new(RwLock::new(Instant::now())),
            vault_path,
            inactivity_timeout: Duration::from_secs(inactivity_timeout_sec),
        })
    }

    /// Unlock the vault with master password
    pub async fn unlock(&self, master_password: &[u8]) -> Result<()> {
        let vault = VaultManager::open(&self.vault_path, master_password).map_err(|e| {
            PasswordManagerError::from(DatabaseError::Other(format!(
                "Failed to unlock vault: {}",
                e
            )))
        })?;

        self.unlock_with_manager(vault).await;
        Ok(())
    }

    /// Unlock the daemon with an already opened vault manager.
    pub async fn unlock_with_manager(&self, vault: VaultManager) {
        *self.vault.lock().await = Some(vault);
        *self.state.write().await = VaultState::Unlocked;
        *self.last_activity.write().await = Instant::now();

        info!("Vault unlocked successfully");

        // Start auto-lock task
        self.start_auto_lock_task();
    }

    /// Unlock the vault with biometric authentication.
    pub async fn unlock_with_biometric(&self, prompt_reason: &str) -> Result<()> {
        let vault =
            VaultManager::open_with_biometric(&self.vault_path, prompt_reason).map_err(|e| {
                PasswordManagerError::from(DatabaseError::Other(format!(
                    "Failed biometric unlock: {}",
                    e
                )))
            })?;

        self.unlock_with_manager(vault).await;
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

        self.record_activity().await;

        let vault_guard = self.vault.lock().await;

        if let Some(ref vault) = *vault_guard {
            // List entries and search for matching domain
            let entries = vault.list_entries()?;

            // Search for entry with matching domain in URL
            for summary in entries {
                if let Ok(entry) = vault.get_entry(summary.entry_id) {
                    if let Some(ref url) = entry.url {
                        if domains_match(domain, url) {
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

    /// Get TOTP code by domain.
    pub async fn get_totp_code(&self, domain: &str) -> Result<Option<TotpCodeResponse>> {
        if !self.is_unlocked().await {
            return Ok(None);
        }

        self.record_activity().await;

        let vault_guard = self.vault.lock().await;

        if let Some(ref vault) = *vault_guard {
            let entries = vault.list_entries()?;

            for summary in entries {
                if let Ok(entry) = vault.get_entry(summary.entry_id) {
                    if let Some(ref url) = entry.url {
                        if domains_match(domain, url) {
                            match vault.generate_totp_code(summary.entry_id) {
                                Ok(code) => {
                                    return Ok(Some(TotpCodeResponse {
                                        code: code.code,
                                        seconds_remaining: code.seconds_remaining,
                                    }));
                                }
                                Err(PasswordManagerError::NotFound(_)) => {
                                    // Matching entry without TOTP configured; keep scanning.
                                    continue;
                                }
                                Err(e) => {
                                    warn!("Failed to generate TOTP for domain '{}': {}", domain, e);
                                    return Err(e);
                                }
                            }
                        }
                    }
                }
            }

            Ok(None)
        } else {
            Ok(None)
        }
    }

    /// Save credential to vault
    pub async fn save_credential(
        &self,
        domain: &str,
        username: &str,
        password: &str,
        url: Option<&str>,
    ) -> Result<()> {
        if !self.is_unlocked().await {
            return Err(PasswordManagerError::VaultLocked);
        }

        self.record_activity().await;

        let vault_guard = self.vault.lock().await;

        if let Some(ref vault) = *vault_guard {
            use crate::vault::Entry;
            use chrono::Utc;

            let now = Utc::now();

            let mut existing_entry_id: Option<i64> = None;
            if !username.trim().is_empty() {
                let entries = vault.list_entries()?;
                for summary in entries {
                    if let Ok(existing_entry) = vault.get_entry(summary.entry_id) {
                        let url_matches = existing_entry
                            .url
                            .as_ref()
                            .map(|entry_url| domains_match(domain, entry_url))
                            .unwrap_or(false);
                        if url_matches && usernames_match(&existing_entry.username, username) {
                            existing_entry_id = Some(summary.entry_id);
                            break;
                        }
                    }
                }
            }

            if let Some(entry_id) = existing_entry_id {
                let mut existing_entry = vault.get_entry(entry_id)?;
                existing_entry.password = password.to_string();
                if let Some(incoming_url) = url {
                    existing_entry.url = Some(incoming_url.to_string());
                }
                existing_entry.modified_at = now;
                vault.update_entry(entry_id, &existing_entry)?;
                info!(
                    "Credential updated for domain: {} (entry_id={})",
                    domain, entry_id
                );
                return Ok(());
            }

            let entry = Entry {
                entry_id: None, // Auto-assigned by database
                title: format!("Credential for {}", domain),
                username: username.to_string(),
                password: password.to_string(),
                url: url.map(|u| u.to_string()),
                notes: None,
                created_at: now,
                modified_at: now,
                favorite: false,
            };

            vault.add_entry(&entry)?;
            info!("Credential saved for domain: {}", domain);
            Ok(())
        } else {
            Err(PasswordManagerError::VaultLocked)
        }
    }

    /// Record activity (resets the auto-lock timer)
    pub async fn record_activity(&self) {
        *self.last_activity.write().await = Instant::now();
    }

    /// Start the auto-lock background task
    fn start_auto_lock_task(&self) {
        let state = self.state.clone();
        let vault = self.vault.clone();
        let last_activity = self.last_activity.clone();
        let timeout = self.inactivity_timeout;

        tokio::spawn(async move {
            let check_interval = if timeout.is_zero() {
                Duration::from_secs(1)
            } else {
                timeout.min(Duration::from_secs(5))
            };
            let mut timer = interval(check_interval);
            timer.tick().await; // Skip first tick

            loop {
                timer.tick().await;
                let unlocked = matches!(*state.read().await, VaultState::Unlocked);
                if unlocked && last_activity.read().await.elapsed() >= timeout {
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

/// Response with TOTP code data.
#[derive(Debug, Clone)]
pub struct TotpCodeResponse {
    pub code: String,
    pub seconds_remaining: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vault_state() {
        let state = VaultState::Locked;
        assert!(matches!(state, VaultState::Locked));
    }

    #[test]
    fn test_normalize_host_handles_urls_and_ports() {
        assert_eq!(
            normalize_host("https://Login.Example.com:443/path"),
            Some("login.example.com".to_string())
        );
        assert_eq!(
            normalize_host("example.com"),
            Some("example.com".to_string())
        );
        assert_eq!(
            normalize_host("example.com:8443"),
            Some("example.com".to_string())
        );
        assert_eq!(normalize_host(""), None);
    }

    #[test]
    fn test_domains_match_exact_and_subdomains_only() {
        assert!(domains_match("example.com", "https://example.com/login"));
        assert!(domains_match(
            "accounts.example.com",
            "https://example.com/login"
        ));
        assert!(domains_match(
            "example.com",
            "https://accounts.example.com/login"
        ));
        assert!(!domains_match(
            "evil-example.com",
            "https://example.com/login"
        ));
        assert!(!domains_match(
            "notexample.com",
            "https://example.com/login"
        ));
    }

    #[test]
    fn test_usernames_match_case_insensitive_and_trimmed() {
        assert!(usernames_match(" User@Example.com ", "user@example.com"));
        assert!(!usernames_match("alice@example.com", "bob@example.com"));
    }
}
