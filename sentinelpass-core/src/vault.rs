//! Vault management - coordinates crypto and database layers

use crate::{
    audit::{get_audit_log_dir, AuditEventType, AuditLogger},
    crypto::cipher::{decrypt_to_string, encrypt_string},
    crypto::{EncryptedEntry, KdfParams, KeyHierarchy, WrappedKey},
    database::Database,
    lockout::DEFAULT_MAX_ATTEMPTS,
    platform::{ensure_data_dir, get_default_vault_path},
    PasswordManagerError, Result,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use zeroize::Zeroize;

/// Vault manager handles all vault operations
pub struct VaultManager {
    key_hierarchy: KeyHierarchy,
    db: Arc<Mutex<Database>>,
    vault_path: PathBuf,
    audit_logger: Option<Arc<AuditLogger>>,
}

impl VaultManager {
    /// Create a new vault with a master password
    pub fn create<P: AsRef<Path>>(path: P, master_password: &[u8]) -> Result<Self> {
        let vault_path = path.as_ref().to_path_buf();

        // Ensure data directory exists
        ensure_data_dir()?;

        // Create and initialize database
        let db = Database::open(&vault_path)?;
        db.initialize_schema()?;

        // Initialize key hierarchy
        let mut key_hierarchy = KeyHierarchy::new();
        let (kdf_params, wrapped_dek) = key_hierarchy.initialize_vault(master_password)?;

        // Store vault metadata
        Self::store_vault_metadata(&db, &kdf_params, &wrapped_dek)?;

        // Initialize audit logger
        let audit_logger = AuditLogger::new(get_audit_log_dir()).map(Arc::new).ok();

        let vault_manager = Self {
            key_hierarchy,
            db: Arc::new(Mutex::new(db)),
            vault_path,
            audit_logger,
        };

        // Log vault creation
        if let Some(ref logger) = vault_manager.audit_logger {
            let _ = logger.log(AuditEventType::VaultCreated, "Vault created successfully");
        }

        Ok(vault_manager)
    }

    /// Open an existing vault
    pub fn open<P: AsRef<Path>>(path: P, master_password: &[u8]) -> Result<Self> {
        let vault_path = path.as_ref().to_path_buf();
        let db = Database::open(&vault_path)?;
        db.initialize_schema()?;

        if let Some(remaining) = Self::get_remaining_lockout_seconds(&db)? {
            return Err(PasswordManagerError::LockedOut(remaining));
        }

        // Load vault metadata
        let (kdf_params, wrapped_dek) = Self::load_vault_metadata(&db)?;

        // Unlock vault
        let mut key_hierarchy = KeyHierarchy::new();
        if let Err(e) = key_hierarchy.unlock_vault(master_password, &kdf_params, &wrapped_dek) {
            let _ = Self::record_failed_attempt(&db);

            if let Some(remaining) = Self::get_remaining_lockout_seconds(&db)? {
                return Err(PasswordManagerError::LockedOut(remaining));
            }

            return Err(PasswordManagerError::Crypto(e));
        }

        Self::clear_failed_attempts(&db)?;

        // Initialize audit logger
        let audit_logger = AuditLogger::new(get_audit_log_dir()).map(Arc::new).ok();

        let vault_manager = Self {
            key_hierarchy,
            db: Arc::new(Mutex::new(db)),
            vault_path,
            audit_logger,
        };

        // Log vault unlock
        if let Some(ref logger) = vault_manager.audit_logger {
            let _ = logger.log(
                AuditEventType::VaultUnlocked { success: true },
                "Vault unlocked successfully",
            );
        }

        Ok(vault_manager)
    }

    /// Create a new vault at the default path
    pub fn create_default(master_password: &[u8]) -> Result<Self> {
        Self::create(get_default_vault_path(), master_password)
    }

    /// Open the vault at the default path
    pub fn open_default(master_password: &[u8]) -> Result<Self> {
        Self::open(get_default_vault_path(), master_password)
    }

    /// Open an existing vault using biometric authentication and OS key storage.
    pub fn open_with_biometric<P: AsRef<Path>>(path: P, reason: &str) -> Result<Self> {
        let vault_path = path.as_ref().to_path_buf();
        let db = Database::open(&vault_path)?;
        db.initialize_schema()?;

        let (kdf_params, wrapped_dek) = Self::load_vault_metadata(&db)?;
        let biometric_ref = Self::load_biometric_ref(&db)?.ok_or_else(|| {
            PasswordManagerError::NotFound("Biometric unlock configuration".to_string())
        })?;

        match crate::biometric::BiometricManager::authenticate(reason) {
            crate::biometric::BiometricResult::Success => {}
            crate::biometric::BiometricResult::Cancelled => {
                return Err(PasswordManagerError::InvalidInput(
                    "Biometric authentication was cancelled".to_string(),
                ));
            }
            crate::biometric::BiometricResult::NotAvailable => {
                return Err(PasswordManagerError::NotFound(format!(
                    "{} is not available on this system",
                    crate::biometric::BiometricManager::get_method_name()
                )));
            }
            crate::biometric::BiometricResult::NotEnrolled => {
                return Err(PasswordManagerError::NotFound(format!(
                    "{} is not enrolled on this system",
                    crate::biometric::BiometricManager::get_method_name()
                )));
            }
            crate::biometric::BiometricResult::Failed(err) => {
                return Err(PasswordManagerError::Database(format!(
                    "Biometric authentication failed: {}",
                    err
                )));
            }
        }

        let mut master_password =
            crate::biometric::BiometricManager::load_master_password(&biometric_ref)?;

        let mut key_hierarchy = KeyHierarchy::new();
        let unlock_result = key_hierarchy.unlock_vault(&master_password, &kdf_params, &wrapped_dek);
        master_password.zeroize();
        unlock_result.map_err(PasswordManagerError::Crypto)?;

        Self::clear_failed_attempts(&db)?;

        let audit_logger = AuditLogger::new(get_audit_log_dir()).map(Arc::new).ok();

        let vault_manager = Self {
            key_hierarchy,
            db: Arc::new(Mutex::new(db)),
            vault_path,
            audit_logger,
        };

        if let Some(ref logger) = vault_manager.audit_logger {
            let _ = logger.log(
                AuditEventType::VaultUnlocked { success: true },
                "Vault unlocked via biometric authentication",
            );
        }

        Ok(vault_manager)
    }

    /// Check whether biometric unlock is configured for a vault path.
    pub fn is_biometric_unlock_enabled<P: AsRef<Path>>(path: P) -> Result<bool> {
        let db = Database::open(path)?;
        db.initialize_schema()?;
        Ok(Self::load_biometric_ref(&db)?.is_some())
    }

    /// Enable biometric unlock for this vault.
    ///
    /// This stores the provided master password in the OS key storage and
    /// links it via `biometric_ref` metadata.
    pub fn enable_biometric_unlock(&self, master_password: &[u8]) -> Result<()> {
        if master_password.is_empty() {
            return Err(PasswordManagerError::InvalidInput(
                "Master password cannot be empty".to_string(),
            ));
        }

        if !crate::biometric::BiometricManager::is_available() {
            return Err(PasswordManagerError::NotFound(format!(
                "{} is not available on this system",
                crate::biometric::BiometricManager::get_method_name()
            )));
        }

        if !crate::biometric::BiometricManager::is_enrolled() {
            return Err(PasswordManagerError::NotFound(format!(
                "{} is not enrolled on this system",
                crate::biometric::BiometricManager::get_method_name()
            )));
        }

        let db = self
            .db
            .lock()
            .map_err(|_| PasswordManagerError::Database("Failed to lock database".to_string()))?;

        // Validate that the provided master password can actually unlock this vault.
        let (kdf_params, wrapped_dek) = Self::load_vault_metadata(&db)?;
        let mut verifier = KeyHierarchy::new();
        verifier
            .unlock_vault(master_password, &kdf_params, &wrapped_dek)
            .map_err(PasswordManagerError::Crypto)?;
        verifier.lock_vault();

        let biometric_ref = crate::biometric::BiometricManager::store_master_password(
            &self.vault_path,
            master_password,
        )?;
        Self::set_biometric_ref(&db, Some(&biometric_ref))?;
        Ok(())
    }

    /// Disable biometric unlock and clear keychain stored secret.
    pub fn disable_biometric_unlock(&self) -> Result<()> {
        let db = self
            .db
            .lock()
            .map_err(|_| PasswordManagerError::Database("Failed to lock database".to_string()))?;

        if let Some(biometric_ref) = Self::load_biometric_ref(&db)? {
            let _ = crate::biometric::BiometricManager::clear_master_password(&biometric_ref);
        }

        Self::set_biometric_ref(&db, None)?;
        Ok(())
    }

    /// Check whether biometric unlock is enabled for this vault instance.
    pub fn biometric_unlock_enabled(&self) -> Result<bool> {
        let db = self
            .db
            .lock()
            .map_err(|_| PasswordManagerError::Database("Failed to lock database".to_string()))?;
        Ok(Self::load_biometric_ref(&db)?.is_some())
    }

    /// Get the filesystem path for this vault instance.
    pub fn vault_path(&self) -> &Path {
        &self.vault_path
    }

    /// Lock the vault (clear keys from memory)
    pub fn lock(&mut self) {
        self.key_hierarchy.lock_vault();

        // Log vault lock event
        if let Some(ref logger) = self.audit_logger {
            let _ = logger.log(AuditEventType::VaultLocked, "Vault locked");
        }
    }

    /// Check if vault is unlocked
    pub fn is_unlocked(&self) -> bool {
        self.key_hierarchy.is_unlocked()
    }

    /// Add a new entry to the vault
    pub fn add_entry(&self, entry: &Entry) -> Result<i64> {
        if !self.is_unlocked() {
            return Err(PasswordManagerError::VaultLocked);
        }

        let dek = self.key_hierarchy.dek()?;

        // Encrypt sensitive fields
        let title_encrypted = encrypt_string(dek, &entry.title)?;
        let username_encrypted = encrypt_string(dek, &entry.username)?;
        let password_encrypted = encrypt_string(dek, &entry.password)?;

        let url_encrypted = entry
            .url
            .as_ref()
            .map(|u| encrypt_string(dek, u))
            .transpose()?;

        let notes_encrypted = entry
            .notes
            .as_ref()
            .map(|n| encrypt_string(dek, n))
            .transpose()?;

        // Serialize encrypted entries
        let title_blob = bincode::serialize(&title_encrypted)
            .map_err(|e| PasswordManagerError::Database(e.to_string()))?;
        let username_blob = bincode::serialize(&username_encrypted)
            .map_err(|e| PasswordManagerError::Database(e.to_string()))?;
        let password_blob = bincode::serialize(&password_encrypted)
            .map_err(|e| PasswordManagerError::Database(e.to_string()))?;
        let url_blob = url_encrypted
            .as_ref()
            .map(|e| {
                bincode::serialize(e).map_err(|e| PasswordManagerError::Database(e.to_string()))
            })
            .transpose()?;
        let notes_blob = notes_encrypted
            .as_ref()
            .map(|e| {
                bincode::serialize(e).map_err(|e| PasswordManagerError::Database(e.to_string()))
            })
            .transpose()?;

        let nonce_blob = bincode::serialize(&title_encrypted.nonce)
            .map_err(|e| PasswordManagerError::Database(e.to_string()))?;
        let auth_tag_blob = bincode::serialize(&title_encrypted.auth_tag)
            .map_err(|e| PasswordManagerError::Database(e.to_string()))?;

        // For now, use a simple vault_id of 1
        let vault_id: i64 = 1;
        let now = Utc::now().timestamp();
        let favorite: i64 = if entry.favorite { 1 } else { 0 };

        // Open database and insert entry
        let db = self
            .db
            .lock()
            .map_err(|_| PasswordManagerError::Database("Failed to lock database".to_string()))?;

        db.conn()
            .execute(
                "INSERT INTO entries (
                vault_id, title, username, password, url, notes,
                entry_nonce, auth_tag, created_at, modified_at, favorite
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                (
                    vault_id,
                    &title_blob,
                    &username_blob,
                    &password_blob,
                    url_blob.as_deref().unwrap_or(&[]),
                    notes_blob.as_deref().unwrap_or(&[]),
                    &nonce_blob,
                    &auth_tag_blob,
                    now,
                    now,
                    favorite,
                ),
            )
            .map_err(|e| PasswordManagerError::Database(e.to_string()))?;

        let entry_id = db.conn().last_insert_rowid();

        // Log credential creation
        if let Some(ref logger) = self.audit_logger {
            let _ = logger.log(
                AuditEventType::CredentialCreated { entry_id },
                &format!("Created credential: {}", entry.title),
            );
        }

        Ok(entry_id)
    }

    /// Get an entry by ID
    pub fn get_entry(&self, entry_id: i64) -> Result<Entry> {
        if !self.is_unlocked() {
            return Err(PasswordManagerError::VaultLocked);
        }

        let dek = self.key_hierarchy.dek()?;
        let db = self
            .db
            .lock()
            .map_err(|_| PasswordManagerError::Database("Failed to lock database".to_string()))?;

        // Query the database
        let mut stmt = db
            .conn()
            .prepare(
                "SELECT title, username, password, url, notes, created_at, modified_at, favorite
             FROM entries WHERE entry_id = ?1",
            )
            .map_err(|e| PasswordManagerError::Database(e.to_string()))?;

        let result = stmt.query_row([entry_id], |row| {
            let title_blob: Vec<u8> = row.get(0)?;
            let username_blob: Vec<u8> = row.get(1)?;
            let password_blob: Vec<u8> = row.get(2)?;
            let url_blob: Option<Vec<u8>> = row.get(3)?;
            let notes_blob: Option<Vec<u8>> = row.get(4)?;
            let created_at_i64: i64 = row.get(5)?;
            let modified_at_i64: i64 = row.get(6)?;
            let favorite_i32: i32 = row.get(7)?;

            Ok((
                title_blob,
                username_blob,
                password_blob,
                url_blob,
                notes_blob,
                created_at_i64,
                modified_at_i64,
                favorite_i32,
            ))
        });

        match result {
            Ok((
                title_blob,
                username_blob,
                password_blob,
                url_blob,
                notes_blob,
                created_at,
                modified_at,
                favorite,
            )) => {
                // Deserialize and decrypt fields
                let title_encrypted: EncryptedEntry = bincode::deserialize(&title_blob)
                    .map_err(|e| PasswordManagerError::Database(e.to_string()))?;
                let username_encrypted: EncryptedEntry = bincode::deserialize(&username_blob)
                    .map_err(|e| PasswordManagerError::Database(e.to_string()))?;
                let password_encrypted: EncryptedEntry = bincode::deserialize(&password_blob)
                    .map_err(|e| PasswordManagerError::Database(e.to_string()))?;

                let title = decrypt_to_string(dek, &title_encrypted)?;
                let username = decrypt_to_string(dek, &username_encrypted)?;
                let password = decrypt_to_string(dek, &password_encrypted)?;

                let url = if let Some(ub) = url_blob {
                    if ub.is_empty() {
                        None
                    } else {
                        let url_encrypted: EncryptedEntry = bincode::deserialize(&ub)
                            .map_err(|e| PasswordManagerError::Database(e.to_string()))?;
                        Some(decrypt_to_string(dek, &url_encrypted)?)
                    }
                } else {
                    None
                };

                let notes = if let Some(nb) = notes_blob {
                    if nb.is_empty() {
                        None
                    } else {
                        let notes_encrypted: EncryptedEntry = bincode::deserialize(&nb)
                            .map_err(|e| PasswordManagerError::Database(e.to_string()))?;
                        Some(decrypt_to_string(dek, &notes_encrypted)?)
                    }
                } else {
                    None
                };

                // Log credential viewing
                if let Some(ref logger) = self.audit_logger {
                    let _ = logger.log(
                        AuditEventType::CredentialViewed { entry_id },
                        &format!("Viewed credential: {}", title),
                    );
                }

                Ok(Entry {
                    entry_id: Some(entry_id),
                    title,
                    username,
                    password,
                    url,
                    notes,
                    created_at: DateTime::from_timestamp(created_at, 0).unwrap_or_default(),
                    modified_at: DateTime::from_timestamp(modified_at, 0).unwrap_or_default(),
                    favorite: favorite != 0,
                })
            }
            Err(_) => Err(PasswordManagerError::NotFound(format!(
                "Entry {}",
                entry_id
            ))),
        }
    }

    /// List all entries
    pub fn list_entries(&self) -> Result<Vec<EntrySummary>> {
        if !self.is_unlocked() {
            return Err(PasswordManagerError::VaultLocked);
        }

        let dek = self.key_hierarchy.dek()?;
        let db = self
            .db
            .lock()
            .map_err(|_| PasswordManagerError::Database("Failed to lock database".to_string()))?;

        let mut stmt = db
            .conn()
            .prepare("SELECT entry_id, title, username, favorite FROM entries")
            .map_err(|e| PasswordManagerError::Database(e.to_string()))?;

        let mut entries = stmt
            .query_map([], |row| {
                let entry_id: i64 = row.get(0)?;
                let title_blob: Vec<u8> = row.get(1)?;
                let username_blob: Vec<u8> = row.get(2)?;
                let favorite: i32 = row.get(3)?;

                Ok((entry_id, title_blob, username_blob, favorite))
            })
            .map_err(|e| PasswordManagerError::Database(e.to_string()))?
            .map(|row| -> Result<EntrySummary> {
                let (entry_id, title_blob, username_blob, favorite) =
                    row.map_err(|e| PasswordManagerError::Database(e.to_string()))?;

                let title_encrypted: EncryptedEntry = bincode::deserialize(&title_blob)
                    .map_err(|e| PasswordManagerError::Database(e.to_string()))?;
                let username_encrypted: EncryptedEntry = bincode::deserialize(&username_blob)
                    .map_err(|e| PasswordManagerError::Database(e.to_string()))?;

                let title = decrypt_to_string(dek, &title_encrypted)?;
                let username = decrypt_to_string(dek, &username_encrypted)?;

                Ok(EntrySummary {
                    entry_id,
                    title,
                    username,
                    favorite: favorite != 0,
                })
            })
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| PasswordManagerError::Database(e.to_string()))?;

        // Sort entries alphabetically by title
        entries.sort_by(|a, b| a.title.cmp(&b.title));

        // Log credentials list operation
        if let Some(ref logger) = self.audit_logger {
            let _ = logger.log(
                AuditEventType::CredentialsListed {
                    count: entries.len(),
                },
                &format!("Listed {} credentials", entries.len()),
            );
        }

        Ok(entries)
    }

    /// Delete an entry
    pub fn delete_entry(&self, entry_id: i64) -> Result<()> {
        if !self.is_unlocked() {
            return Err(PasswordManagerError::VaultLocked);
        }

        let db = self
            .db
            .lock()
            .map_err(|_| PasswordManagerError::Database("Failed to lock database".to_string()))?;

        // First, delete associated domain mappings
        db.conn()
            .execute(
                "DELETE FROM domain_mappings WHERE entry_id = ?1",
                [entry_id],
            )
            .map_err(|e| PasswordManagerError::Database(e.to_string()))?;

        // Then delete the entry
        let rows_affected = db
            .conn()
            .execute("DELETE FROM entries WHERE entry_id = ?1", [entry_id])
            .map_err(|e| PasswordManagerError::Database(e.to_string()))?;

        if rows_affected == 0 {
            return Err(PasswordManagerError::NotFound(format!(
                "Entry {}",
                entry_id
            )));
        }

        // Log credential deletion
        if let Some(ref logger) = self.audit_logger {
            let _ = logger.log(
                AuditEventType::CredentialDeleted { entry_id },
                &format!("Deleted credential: {}", entry_id),
            );
        }

        Ok(())
    }

    /// Update an existing entry
    pub fn update_entry(&self, entry_id: i64, entry: &Entry) -> Result<()> {
        if !self.is_unlocked() {
            return Err(PasswordManagerError::VaultLocked);
        }

        let dek = self.key_hierarchy.dek()?;
        let db = self
            .db
            .lock()
            .map_err(|_| PasswordManagerError::Database("Failed to lock database".to_string()))?;

        // Encrypt the entry data
        let title_encrypted = encrypt_string(dek, &entry.title)?;
        let username_encrypted = encrypt_string(dek, &entry.username)?;
        let password_encrypted = encrypt_string(dek, &entry.password)?;

        let url_encrypted = entry
            .url
            .as_ref()
            .map(|u| encrypt_string(dek, u))
            .transpose()?;

        let notes_encrypted = entry
            .notes
            .as_ref()
            .map(|n| encrypt_string(dek, n))
            .transpose()?;

        // Serialize encrypted entries
        let title_blob = bincode::serialize(&title_encrypted)
            .map_err(|e| PasswordManagerError::Database(e.to_string()))?;
        let username_blob = bincode::serialize(&username_encrypted)
            .map_err(|e| PasswordManagerError::Database(e.to_string()))?;
        let password_blob = bincode::serialize(&password_encrypted)
            .map_err(|e| PasswordManagerError::Database(e.to_string()))?;
        let url_blob = url_encrypted
            .as_ref()
            .map(|e| {
                bincode::serialize(e).map_err(|e| PasswordManagerError::Database(e.to_string()))
            })
            .transpose()?;
        let notes_blob = notes_encrypted
            .as_ref()
            .map(|e| {
                bincode::serialize(e).map_err(|e| PasswordManagerError::Database(e.to_string()))
            })
            .transpose()?;

        let nonce_blob = bincode::serialize(&title_encrypted.nonce)
            .map_err(|e| PasswordManagerError::Database(e.to_string()))?;
        let auth_tag_blob = bincode::serialize(&title_encrypted.auth_tag)
            .map_err(|e| PasswordManagerError::Database(e.to_string()))?;

        let now = Utc::now().timestamp();

        // Update the entry
        let rows_affected = db
            .conn()
            .execute(
                "UPDATE entries
             SET title = ?1, username = ?2, password = ?3, url = ?4, notes = ?5,
                 entry_nonce = ?6, auth_tag = ?7, modified_at = ?8, favorite = ?9
             WHERE entry_id = ?10",
                (
                    &title_blob,
                    &username_blob,
                    &password_blob,
                    url_blob.as_deref(),
                    notes_blob.as_deref(),
                    &nonce_blob,
                    &auth_tag_blob,
                    now,
                    entry.favorite as i32,
                    entry_id,
                ),
            )
            .map_err(|e| PasswordManagerError::Database(e.to_string()))?;

        if rows_affected == 0 {
            return Err(PasswordManagerError::NotFound(format!(
                "Entry {}",
                entry_id
            )));
        }

        // Log credential modification
        if let Some(ref logger) = self.audit_logger {
            let _ = logger.log(
                AuditEventType::CredentialModified { entry_id },
                &format!("Modified credential: {}", entry.title),
            );
        }

        Ok(())
    }

    /// Store vault metadata in database
    fn store_vault_metadata(
        db: &Database,
        kdf_params: &KdfParams,
        wrapped_dek: &WrappedKey,
    ) -> Result<()> {
        let kdf_params_blob = bincode::serialize(kdf_params)
            .map_err(|e| PasswordManagerError::Database(e.to_string()))?;
        let wrapped_dek_blob = bincode::serialize(wrapped_dek)
            .map_err(|e| PasswordManagerError::Database(e.to_string()))?;
        let nonce_blob = bincode::serialize(&wrapped_dek.nonce)
            .map_err(|e| PasswordManagerError::Database(e.to_string()))?;

        let now = Utc::now().timestamp();

        db.conn().execute(
            "INSERT INTO db_metadata (id, version, kdf_params, wrapped_dek, dek_nonce, created_at, last_modified)
             VALUES (1, 1, ?1, ?2, ?3, ?4, ?5)",
            (&kdf_params_blob, &wrapped_dek_blob, &nonce_blob, now, now),
        ).map_err(|e| PasswordManagerError::Database(e.to_string()))?;

        Ok(())
    }

    fn record_failed_attempt(db: &Database) -> Result<()> {
        let now = Utc::now().timestamp();
        db.conn()
            .execute(
                "INSERT INTO failed_attempts (attempt_time, ip_address) VALUES (?1, NULL)",
                [now],
            )
            .map_err(|e| PasswordManagerError::Database(e.to_string()))?;
        Ok(())
    }

    fn clear_failed_attempts(db: &Database) -> Result<()> {
        db.conn()
            .execute("DELETE FROM failed_attempts", [])
            .map_err(|e| PasswordManagerError::Database(e.to_string()))?;
        Ok(())
    }

    fn lockout_duration_seconds(total_failed_attempts: u32) -> Option<i64> {
        if total_failed_attempts < DEFAULT_MAX_ATTEMPTS {
            return None;
        }

        // Exponential backoff, capped to avoid extreme values.
        let excess_attempts = total_failed_attempts - DEFAULT_MAX_ATTEMPTS;
        let multiplier = 2_i64.pow(excess_attempts.min(10));
        Some(60 * multiplier)
    }

    fn get_remaining_lockout_seconds(db: &Database) -> Result<Option<i64>> {
        let total_failed_attempts: u32 = db
            .conn()
            .query_row("SELECT COUNT(*) FROM failed_attempts", [], |row| row.get(0))
            .map_err(|e| PasswordManagerError::Database(e.to_string()))?;

        let Some(lockout_duration_seconds) = Self::lockout_duration_seconds(total_failed_attempts)
        else {
            return Ok(None);
        };

        let last_failed_attempt: Option<i64> = db
            .conn()
            .query_row("SELECT MAX(attempt_time) FROM failed_attempts", [], |row| {
                row.get(0)
            })
            .map_err(|e| PasswordManagerError::Database(e.to_string()))?;

        let Some(last_failed_attempt) = last_failed_attempt else {
            return Ok(None);
        };

        let elapsed = Utc::now().timestamp() - last_failed_attempt;
        let remaining = lockout_duration_seconds - elapsed;

        if remaining > 0 {
            Ok(Some(remaining))
        } else {
            Ok(None)
        }
    }

    /// Load vault metadata from database
    fn load_vault_metadata(db: &crate::database::Database) -> Result<(KdfParams, WrappedKey)> {
        let mut stmt = db
            .conn()
            .prepare("SELECT kdf_params, wrapped_dek FROM db_metadata WHERE id = 1")
            .map_err(|e| PasswordManagerError::Database(e.to_string()))?;

        let result = stmt.query_row([], |row| {
            let kdf_params_blob: Vec<u8> = row.get(0)?;
            let wrapped_dek_blob: Vec<u8> = row.get(1)?;
            Ok((kdf_params_blob, wrapped_dek_blob))
        });

        match result {
            Ok((kdf_params_blob, wrapped_dek_blob)) => {
                let kdf_params: KdfParams = bincode::deserialize(&kdf_params_blob)
                    .map_err(|e| PasswordManagerError::Database(e.to_string()))?;
                let wrapped_dek: WrappedKey = bincode::deserialize(&wrapped_dek_blob)
                    .map_err(|e| PasswordManagerError::Database(e.to_string()))?;
                Ok((kdf_params, wrapped_dek))
            }
            Err(_) => Err(PasswordManagerError::NotFound("Vault metadata".to_string())),
        }
    }

    /// Load biometric key reference from database metadata.
    fn load_biometric_ref(db: &crate::database::Database) -> Result<Option<String>> {
        db.conn()
            .query_row(
                "SELECT biometric_ref FROM db_metadata WHERE id = 1",
                [],
                |row| row.get(0),
            )
            .map_err(|e| PasswordManagerError::Database(e.to_string()))
    }

    /// Update biometric key reference in database metadata.
    fn set_biometric_ref(
        db: &crate::database::Database,
        biometric_ref: Option<&str>,
    ) -> Result<()> {
        db.conn()
            .execute(
                "UPDATE db_metadata SET biometric_ref = ?1 WHERE id = 1",
                [biometric_ref],
            )
            .map_err(|e| PasswordManagerError::Database(e.to_string()))?;
        Ok(())
    }

    // TOTP Secret Management

    /// Add or update a TOTP secret for an entry.
    pub fn add_totp_secret(
        &self,
        entry_id: i64,
        secret_base32: &str,
        algorithm: crate::totp::TotpAlgorithm,
        digits: u8,
        period: u32,
        issuer: Option<&str>,
        account_name: Option<&str>,
    ) -> Result<i64> {
        if !self.is_unlocked() {
            return Err(PasswordManagerError::VaultLocked);
        }

        let dek = self.key_hierarchy.dek()?;
        let (secret_encrypted, nonce, auth_tag) =
            crate::totp::encrypt_totp_secret(dek, secret_base32)?;

        let db = self
            .db
            .lock()
            .map_err(|_| PasswordManagerError::Database("Failed to lock database".to_string()))?;

        let entry_exists: i64 = db
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM entries WHERE entry_id = ?1",
                [entry_id],
                |row| row.get(0),
            )
            .map_err(|e| PasswordManagerError::Database(e.to_string()))?;

        if entry_exists == 0 {
            return Err(PasswordManagerError::NotFound(format!(
                "Entry {}",
                entry_id
            )));
        }

        let now = Utc::now().timestamp();

        db.conn()
            .execute(
                "INSERT INTO totp_secrets (
                    entry_id, secret_encrypted, nonce, auth_tag, algorithm,
                    digits, period, issuer, account_name, created_at
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
                ON CONFLICT(entry_id) DO UPDATE SET
                    secret_encrypted = excluded.secret_encrypted,
                    nonce = excluded.nonce,
                    auth_tag = excluded.auth_tag,
                    algorithm = excluded.algorithm,
                    digits = excluded.digits,
                    period = excluded.period,
                    issuer = excluded.issuer,
                    account_name = excluded.account_name,
                    created_at = excluded.created_at",
                (
                    entry_id,
                    &secret_encrypted,
                    &nonce,
                    &auth_tag,
                    algorithm.as_db_value(),
                    digits,
                    period,
                    issuer,
                    account_name,
                    now,
                ),
            )
            .map_err(|e| PasswordManagerError::Database(e.to_string()))?;

        let totp_id: i64 = db
            .conn()
            .query_row(
                "SELECT totp_id FROM totp_secrets WHERE entry_id = ?1",
                [entry_id],
                |row| row.get(0),
            )
            .map_err(|e| PasswordManagerError::Database(e.to_string()))?;

        Ok(totp_id)
    }

    /// Get TOTP metadata for an entry.
    pub fn get_totp_metadata(&self, entry_id: i64) -> Result<crate::totp::TotpSecretMetadata> {
        if !self.is_unlocked() {
            return Err(PasswordManagerError::VaultLocked);
        }

        let db = self
            .db
            .lock()
            .map_err(|_| PasswordManagerError::Database("Failed to lock database".to_string()))?;

        let mut stmt = db
            .conn()
            .prepare(
                "SELECT totp_id, entry_id, algorithm, digits, period, issuer, account_name
                 FROM totp_secrets WHERE entry_id = ?1",
            )
            .map_err(|e| PasswordManagerError::Database(e.to_string()))?;

        let row = stmt.query_row([entry_id], |row| {
            let totp_id: i64 = row.get(0)?;
            let entry_id: i64 = row.get(1)?;
            let algorithm: String = row.get(2)?;
            let digits: u8 = row.get(3)?;
            let period: u32 = row.get(4)?;
            let issuer: Option<String> = row.get(5)?;
            let account_name: Option<String> = row.get(6)?;
            Ok((
                totp_id,
                entry_id,
                algorithm,
                digits,
                period,
                issuer,
                account_name,
            ))
        });

        match row {
            Ok((totp_id, entry_id, algorithm_raw, digits, period, issuer, account_name)) => {
                let algorithm = algorithm_raw
                    .parse::<crate::totp::TotpAlgorithm>()
                    .map_err(|_| {
                        PasswordManagerError::Database(format!(
                            "Invalid TOTP algorithm in database: {}",
                            algorithm_raw
                        ))
                    })?;

                Ok(crate::totp::TotpSecretMetadata {
                    totp_id,
                    entry_id,
                    algorithm,
                    digits,
                    period,
                    issuer,
                    account_name,
                })
            }
            Err(_) => Err(PasswordManagerError::NotFound(format!(
                "TOTP secret for entry {}",
                entry_id
            ))),
        }
    }

    /// Generate the current TOTP code for an entry.
    pub fn generate_totp_code(&self, entry_id: i64) -> Result<crate::totp::TotpCode> {
        if !self.is_unlocked() {
            return Err(PasswordManagerError::VaultLocked);
        }

        let dek = self.key_hierarchy.dek()?;
        let db = self
            .db
            .lock()
            .map_err(|_| PasswordManagerError::Database("Failed to lock database".to_string()))?;

        let mut stmt = db
            .conn()
            .prepare(
                "SELECT secret_encrypted, nonce, auth_tag, algorithm, digits, period
                 FROM totp_secrets WHERE entry_id = ?1",
            )
            .map_err(|e| PasswordManagerError::Database(e.to_string()))?;

        let row = stmt.query_row([entry_id], |row| {
            let secret_encrypted: Vec<u8> = row.get(0)?;
            let nonce: Vec<u8> = row.get(1)?;
            let auth_tag: Vec<u8> = row.get(2)?;
            let algorithm: String = row.get(3)?;
            let digits: u8 = row.get(4)?;
            let period: u32 = row.get(5)?;
            Ok((secret_encrypted, nonce, auth_tag, algorithm, digits, period))
        });

        let (secret_encrypted, nonce, auth_tag, algorithm_raw, digits, period) = match row {
            Ok(value) => value,
            Err(_) => {
                return Err(PasswordManagerError::NotFound(format!(
                    "TOTP secret for entry {}",
                    entry_id
                )));
            }
        };

        let algorithm = algorithm_raw
            .parse::<crate::totp::TotpAlgorithm>()
            .map_err(|_| {
                PasswordManagerError::Database(format!(
                    "Invalid TOTP algorithm in database: {}",
                    algorithm_raw
                ))
            })?;

        let secret = crate::totp::decrypt_totp_secret(dek, &secret_encrypted, &nonce, &auth_tag)?;
        let now = Utc::now().timestamp();
        let code = crate::totp::generate_totp_code(&secret, algorithm, digits, period, now)?;
        let seconds_remaining = crate::totp::seconds_remaining(period, now);

        Ok(crate::totp::TotpCode {
            code,
            seconds_remaining,
        })
    }

    /// Remove TOTP secret for an entry.
    pub fn remove_totp_secret(&self, entry_id: i64) -> Result<()> {
        if !self.is_unlocked() {
            return Err(PasswordManagerError::VaultLocked);
        }

        let db = self
            .db
            .lock()
            .map_err(|_| PasswordManagerError::Database("Failed to lock database".to_string()))?;

        let deleted = db
            .conn()
            .execute("DELETE FROM totp_secrets WHERE entry_id = ?1", [entry_id])
            .map_err(|e| PasswordManagerError::Database(e.to_string()))?;

        if deleted == 0 {
            return Err(PasswordManagerError::NotFound(format!(
                "TOTP secret for entry {}",
                entry_id
            )));
        }

        Ok(())
    }

    // SSH Key Management

    /// Add an SSH key to the vault from plaintext key material.
    pub fn add_ssh_key_plaintext(
        &self,
        name: String,
        comment: Option<String>,
        key_type: crate::ssh::SshKeyType,
        key_size: Option<u32>,
        public_key: String,
        private_key: String,
        fingerprint: String,
    ) -> Result<i64> {
        if !self.is_unlocked() {
            return Err(PasswordManagerError::VaultLocked);
        }

        let dek = self.key_hierarchy.dek()?;
        let ssh_key = crate::ssh::SshKey::create_encrypted(
            &dek,
            name,
            comment,
            key_type,
            key_size,
            public_key,
            private_key,
            fingerprint,
        )?;

        self.add_ssh_key(&ssh_key)
    }

    /// Add an SSH key to the vault
    pub fn add_ssh_key(&self, key: &crate::ssh::SshKey) -> Result<i64> {
        if !self.is_unlocked() {
            return Err(PasswordManagerError::VaultLocked);
        }

        let _dek = self.key_hierarchy.dek()?;
        let db = self
            .db
            .lock()
            .map_err(|_| PasswordManagerError::Database("Failed to lock database".to_string()))?;

        let now = Utc::now().timestamp();

        db.conn()
            .execute(
                "INSERT INTO ssh_keys (
                name, comment, key_type, key_size, public_key,
                private_key_encrypted, nonce, auth_tag, fingerprint,
                created_at, modified_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                (
                    &key.name,
                    key.comment.as_deref(),
                    key.key_type.to_string(),
                    key.key_size,
                    &key.public_key,
                    &key.private_key_encrypted,
                    &key.nonce,
                    &key.auth_tag,
                    &key.fingerprint,
                    now,
                    now,
                ),
            )
            .map_err(|e| PasswordManagerError::Database(e.to_string()))?;

        Ok(db.conn().last_insert_rowid())
    }

    /// Get an SSH key by ID
    pub fn get_ssh_key(&self, key_id: i64) -> Result<crate::ssh::SshKey> {
        if !self.is_unlocked() {
            return Err(PasswordManagerError::VaultLocked);
        }

        let db = self
            .db
            .lock()
            .map_err(|_| PasswordManagerError::Database("Failed to lock database".to_string()))?;

        let mut stmt = db
            .conn()
            .prepare(
                "SELECT name, comment, key_type, key_size, public_key, private_key_encrypted,
                     nonce, auth_tag, fingerprint, created_at, modified_at
             FROM ssh_keys WHERE key_id = ?1",
            )
            .map_err(|e| PasswordManagerError::Database(e.to_string()))?;

        let result = stmt.query_row([key_id], |row| {
            let name: String = row.get(0)?;
            let comment: Option<String> = row.get(1)?;
            let key_type_str: String = row.get(2)?;
            let key_size: Option<u32> = row.get(3)?;
            let public_key: String = row.get(4)?;
            let private_key_encrypted: Vec<u8> = row.get(5)?;
            let nonce: Vec<u8> = row.get(6)?;
            let auth_tag: Vec<u8> = row.get(7)?;
            let fingerprint: String = row.get(8)?;
            let created_at: i64 = row.get(9)?;
            let modified_at: i64 = row.get(10)?;

            Ok((
                name,
                comment,
                key_type_str,
                key_size,
                public_key,
                private_key_encrypted,
                nonce,
                auth_tag,
                fingerprint,
                created_at,
                modified_at,
            ))
        });

        match result {
            Ok((
                name,
                comment,
                key_type_str,
                key_size,
                public_key,
                private_key_encrypted,
                nonce,
                auth_tag,
                fingerprint,
                created_at,
                modified_at,
            )) => {
                let key_type = match key_type_str.as_str() {
                    "RSA" => crate::ssh::SshKeyType::Rsa,
                    "ED25519" => crate::ssh::SshKeyType::Ed25519,
                    "ECDSA" => crate::ssh::SshKeyType::Ecdsa,
                    "ECDSA-SHA2-NISTP256" => crate::ssh::SshKeyType::EcdsaSha256,
                    "ECDSA-SHA2-NISTP384" => crate::ssh::SshKeyType::EcdsaSha384,
                    "ECDSA-SHA2-NISTP521" => crate::ssh::SshKeyType::EcdsaSha521,
                    _ => {
                        return Err(PasswordManagerError::InvalidInput(format!(
                            "Unknown key type: {}",
                            key_type_str
                        )))
                    }
                };

                Ok(crate::ssh::SshKey {
                    key_id: Some(key_id),
                    name,
                    comment,
                    key_type,
                    key_size,
                    public_key,
                    private_key_encrypted,
                    nonce,
                    auth_tag,
                    fingerprint,
                    created_at: DateTime::from_timestamp(created_at, 0).unwrap_or_default(),
                    modified_at: DateTime::from_timestamp(modified_at, 0).unwrap_or_default(),
                })
            }
            Err(_) => Err(PasswordManagerError::NotFound(format!(
                "SSH key {}",
                key_id
            ))),
        }
    }

    /// List all SSH key summaries (without private keys)
    pub fn list_ssh_keys(&self) -> Result<Vec<crate::ssh::SshKeySummary>> {
        if !self.is_unlocked() {
            return Err(PasswordManagerError::VaultLocked);
        }

        let db = self
            .db
            .lock()
            .map_err(|_| PasswordManagerError::Database("Failed to lock database".to_string()))?;

        let mut stmt = db
            .conn()
            .prepare("SELECT key_id, name, comment, key_type, fingerprint FROM ssh_keys")
            .map_err(|e| PasswordManagerError::Database(e.to_string()))?;

        let keys = stmt
            .query_map([], |row| {
                let key_id: i64 = row.get(0)?;
                let name: String = row.get(1)?;
                let comment: Option<String> = row.get(2)?;
                let key_type_str: String = row.get(3)?;
                let fingerprint: String = row.get(4)?;

                let key_type = match key_type_str.as_str() {
                    "RSA" => crate::ssh::SshKeyType::Rsa,
                    "ED25519" => crate::ssh::SshKeyType::Ed25519,
                    "ECDSA" => crate::ssh::SshKeyType::Ecdsa,
                    "ECDSA-SHA2-NISTP256" => crate::ssh::SshKeyType::EcdsaSha256,
                    "ECDSA-SHA2-NISTP384" => crate::ssh::SshKeyType::EcdsaSha384,
                    "ECDSA-SHA2-NISTP521" => crate::ssh::SshKeyType::EcdsaSha521,
                    _ => crate::ssh::SshKeyType::Rsa, // Default fallback
                };

                Ok(crate::ssh::SshKeySummary {
                    key_id,
                    name,
                    comment,
                    key_type,
                    fingerprint,
                })
            })
            .map_err(|e| PasswordManagerError::Database(e.to_string()))?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| PasswordManagerError::Database(e.to_string()))?;

        Ok(keys)
    }

    /// Delete an SSH key
    pub fn delete_ssh_key(&self, key_id: i64) -> Result<()> {
        if !self.is_unlocked() {
            return Err(PasswordManagerError::VaultLocked);
        }

        let db = self
            .db
            .lock()
            .map_err(|_| PasswordManagerError::Database("Failed to lock database".to_string()))?;

        let rows_affected = db
            .conn()
            .execute("DELETE FROM ssh_keys WHERE key_id = ?1", [key_id])
            .map_err(|e| PasswordManagerError::Database(e.to_string()))?;

        if rows_affected == 0 {
            return Err(PasswordManagerError::NotFound(format!(
                "SSH key {}",
                key_id
            )));
        }

        Ok(())
    }

    /// Export the decrypted private key for an SSH key
    pub fn export_ssh_private_key(&self, key_id: i64) -> Result<String> {
        if !self.is_unlocked() {
            return Err(PasswordManagerError::VaultLocked);
        }

        let dek = self.key_hierarchy.dek()?;
        let db = self
            .db
            .lock()
            .map_err(|_| PasswordManagerError::Database("Failed to lock database".to_string()))?;

        let mut stmt = db
            .conn()
            .prepare(
                "SELECT private_key_encrypted, nonce, auth_tag FROM ssh_keys WHERE key_id = ?1",
            )
            .map_err(|e| PasswordManagerError::Database(e.to_string()))?;

        let result = stmt.query_row([key_id], |row| {
            let private_key_encrypted: Vec<u8> = row.get(0)?;
            let nonce: Vec<u8> = row.get(1)?;
            let auth_tag: Vec<u8> = row.get(2)?;
            Ok((private_key_encrypted, nonce, auth_tag))
        });

        match result {
            Ok((private_key_encrypted, nonce, auth_tag)) => {
                crate::ssh::SshKey::decrypt_private_key(
                    &dek,
                    &private_key_encrypted,
                    &nonce,
                    &auth_tag,
                )
            }
            Err(_) => Err(PasswordManagerError::NotFound(format!(
                "SSH key {}",
                key_id
            ))),
        }
    }
}

/// A password entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    pub entry_id: Option<i64>,
    pub title: String,
    pub username: String,
    pub password: String,
    pub url: Option<String>,
    pub notes: Option<String>,
    pub created_at: DateTime<Utc>,
    pub modified_at: DateTime<Utc>,
    pub favorite: bool,
}

/// Summary of an entry (without password)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntrySummary {
    pub entry_id: i64,
    pub title: String,
    pub username: String,
    pub favorite: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::Database;

    #[test]
    fn test_vault_create_and_open() {
        let temp_path = ":memory:"; // Use in-memory database for testing

        // Create vault
        let password = b"test_password_123!";
        let vault = VaultManager::create(temp_path, password);
        assert!(vault.is_ok());
        assert!(vault.unwrap().is_unlocked());

        // Opening with :memory: creates a new database each time, so we can't test reopening
        // In a real test, we'd use a temp file
    }

    #[test]
    fn test_vault_add_and_get_entry() {
        let temp_path = ":memory:";
        let password = b"test_password";

        let vault = VaultManager::create(temp_path, password).unwrap();

        let entry = Entry {
            entry_id: None,
            title: "Test Entry".to_string(),
            username: "user@example.com".to_string(),
            password: "secret123".to_string(),
            url: Some("https://example.com".to_string()),
            notes: Some("Test notes".to_string()),
            created_at: Utc::now(),
            modified_at: Utc::now(),
            favorite: false,
        };

        let entry_id = vault.add_entry(&entry).unwrap();
        assert!(entry_id > 0);

        let retrieved = vault.get_entry(entry_id).unwrap();
        assert_eq!(retrieved.title, "Test Entry");
        assert_eq!(retrieved.username, "user@example.com");
        assert_eq!(retrieved.password, "secret123");
        assert_eq!(retrieved.url, Some("https://example.com".to_string()));
        assert_eq!(retrieved.notes, Some("Test notes".to_string()));
    }

    #[test]
    fn test_vault_list_entries() {
        let temp_path = ":memory:";
        let password = b"test_password";

        let vault = VaultManager::create(temp_path, password).unwrap();

        let entry1 = Entry {
            entry_id: None,
            title: "Alpha Entry".to_string(),
            username: "user1@example.com".to_string(),
            password: "pass1".to_string(),
            url: None,
            notes: None,
            created_at: Utc::now(),
            modified_at: Utc::now(),
            favorite: false,
        };

        let entry2 = Entry {
            entry_id: None,
            title: "Zeta Entry".to_string(),
            username: "user2@example.com".to_string(),
            password: "pass2".to_string(),
            url: None,
            notes: None,
            created_at: Utc::now(),
            modified_at: Utc::now(),
            favorite: true,
        };

        vault.add_entry(&entry1).unwrap();
        vault.add_entry(&entry2).unwrap();

        let entries = vault.list_entries().unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].title, "Alpha Entry");
        assert_eq!(entries[1].title, "Zeta Entry");
    }

    #[test]
    fn test_vault_lock() {
        let temp_path = ":memory:";
        let password = b"test_password";

        let mut vault = VaultManager::create(temp_path, password).unwrap();
        assert!(vault.is_unlocked());

        vault.lock();
        assert!(!vault.is_unlocked());
    }

    #[test]
    fn test_vault_locked_operations_fail() {
        let temp_path = ":memory:";
        let password = b"test_password";

        let mut vault = VaultManager::create(temp_path, password).unwrap();
        vault.lock();

        assert!(vault
            .add_entry(&Entry {
                entry_id: None,
                title: "Test".to_string(),
                username: "test".to_string(),
                password: "test".to_string(),
                url: None,
                notes: None,
                created_at: Utc::now(),
                modified_at: Utc::now(),
                favorite: false,
            })
            .is_err());

        assert!(vault.get_entry(1).is_err());
        assert!(vault.list_entries().is_err());
    }

    #[test]
    fn test_vault_lockout_after_repeated_failed_unlocks() {
        let temp_path =
            std::env::temp_dir().join(format!("sentinelpass_lockout_{}.db", uuid::Uuid::new_v4()));
        let password = b"test_password";

        let vault = VaultManager::create(&temp_path, password).unwrap();
        drop(vault);

        for _ in 0..(DEFAULT_MAX_ATTEMPTS - 1) {
            let result = VaultManager::open(&temp_path, b"wrong_password");
            assert!(matches!(result, Err(PasswordManagerError::Crypto(_))));
        }

        let lockout_trigger = VaultManager::open(&temp_path, b"wrong_password");
        assert!(matches!(
            lockout_trigger,
            Err(PasswordManagerError::LockedOut(_))
        ));

        let still_locked_with_correct_password = VaultManager::open(&temp_path, password);
        assert!(matches!(
            still_locked_with_correct_password,
            Err(PasswordManagerError::LockedOut(_))
        ));

        let _ = std::fs::remove_file(&temp_path);
    }

    #[test]
    fn test_totp_add_generate_remove() {
        let temp_path = ":memory:";
        let password = b"test_password";

        let vault = VaultManager::create(temp_path, password).unwrap();

        let entry = Entry {
            entry_id: None,
            title: "TOTP Entry".to_string(),
            username: "user@example.com".to_string(),
            password: "secret123".to_string(),
            url: Some("https://example.com".to_string()),
            notes: None,
            created_at: Utc::now(),
            modified_at: Utc::now(),
            favorite: false,
        };

        let entry_id = vault.add_entry(&entry).unwrap();

        let totp_id = vault
            .add_totp_secret(
                entry_id,
                "JBSWY3DPEHPK3PXP",
                crate::totp::TotpAlgorithm::Sha1,
                6,
                30,
                Some("SentinelPass"),
                Some("user@example.com"),
            )
            .unwrap();
        assert!(totp_id > 0);

        let metadata = vault.get_totp_metadata(entry_id).unwrap();
        assert_eq!(metadata.entry_id, entry_id);
        assert_eq!(metadata.algorithm, crate::totp::TotpAlgorithm::Sha1);
        assert_eq!(metadata.digits, 6);
        assert_eq!(metadata.period, 30);

        let code = vault.generate_totp_code(entry_id).unwrap();
        assert_eq!(code.code.len(), 6);
        assert!(code.seconds_remaining >= 1 && code.seconds_remaining <= 30);

        vault.remove_totp_secret(entry_id).unwrap();
        assert!(vault.generate_totp_code(entry_id).is_err());
    }

    #[test]
    fn test_ssh_key_encrypt_decrypt_roundtrip() {
        use crate::crypto::DataEncryptionKey;

        let dek = DataEncryptionKey::new().unwrap();
        let private_key = "-----BEGIN OPENSSH PRIVATE KEY-----\ntest private key content\n-----END OPENSSH PRIVATE KEY-----";

        // Test encryption
        let (encrypted, nonce, auth_tag) =
            crate::ssh::SshKey::encrypt_private_key(&dek, private_key).unwrap();

        assert!(!encrypted.is_empty());
        assert_eq!(nonce.len(), 12);
        assert_eq!(auth_tag.len(), 16);

        // Test decryption
        let decrypted =
            crate::ssh::SshKey::decrypt_private_key(&dek, &encrypted, &nonce, &auth_tag).unwrap();

        assert_eq!(decrypted, private_key);
    }

    #[test]
    fn test_vault_add_and_list_ssh_keys() {
        let temp_path = ":memory:";
        let password = b"test_password";

        let vault = VaultManager::create(temp_path, password).unwrap();

        // Create an encrypted SSH key
        let dek = vault.key_hierarchy.dek().unwrap();
        let ssh_key = crate::ssh::SshKey::create_encrypted(
            &dek,
            "test-key".to_string(),
            Some("test comment".to_string()),
            crate::ssh::SshKeyType::Ed25519,
            Some(256),
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINCertainlyNotARealKeyButValidFormat test@example.com".to_string(),
            "-----BEGIN OPENSSH PRIVATE KEY-----\ntest content\n-----END OPENSSH PRIVATE KEY-----".to_string(),
            "SHA256:abcdefghijklmnopqrstuvwxyz123456=".to_string(),
        ).unwrap();

        // Add the key
        let key_id = vault.add_ssh_key(&ssh_key).unwrap();
        assert!(key_id > 0);

        // List keys
        let summaries = vault.list_ssh_keys().unwrap();
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].name, "test-key");
        assert_eq!(summaries[0].key_type, crate::ssh::SshKeyType::Ed25519);
    }

    #[test]
    fn test_vault_get_and_export_ssh_key() {
        let temp_path = ":memory:";
        let password = b"test_password";

        let vault = VaultManager::create(temp_path, password).unwrap();

        // Create and add an SSH key
        let dek = vault.key_hierarchy.dek().unwrap();
        let original_private_key =
            "-----BEGIN OPENSSH PRIVATE KEY-----\ntest content\n-----END OPENSSH PRIVATE KEY-----";

        let ssh_key = crate::ssh::SshKey::create_encrypted(
            &dek,
            "export-test".to_string(),
            None,
            crate::ssh::SshKeyType::Rsa,
            Some(4096),
            "ssh-rsa AAAAB3NzaC1yc2E... test@example.com".to_string(),
            original_private_key.to_string(),
            "SHA256:abcdef123456=".to_string(),
        )
        .unwrap();

        let key_id = vault.add_ssh_key(&ssh_key).unwrap();

        // Get the full key
        let retrieved_key = vault.get_ssh_key(key_id).unwrap();
        assert_eq!(retrieved_key.name, "export-test");
        assert_eq!(retrieved_key.key_type, crate::ssh::SshKeyType::Rsa);

        // Export and verify private key matches
        let exported_private_key = vault.export_ssh_private_key(key_id).unwrap();
        assert_eq!(exported_private_key, original_private_key);
    }

    #[test]
    fn test_vault_delete_ssh_key() {
        let temp_path = ":memory:";
        let password = b"test_password";

        let vault = VaultManager::create(temp_path, password).unwrap();

        // Create and add an SSH key
        let dek = vault.key_hierarchy.dek().unwrap();
        let ssh_key = crate::ssh::SshKey::create_encrypted(
            &dek,
            "to-delete".to_string(),
            None,
            crate::ssh::SshKeyType::Ed25519,
            Some(256),
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINCertainlyNotARealKey test@example.com"
                .to_string(),
            "-----BEGIN OPENSSH PRIVATE KEY-----\ntest\n-----END OPENSSH PRIVATE KEY-----"
                .to_string(),
            "SHA256:deleted=".to_string(),
        )
        .unwrap();

        let key_id = vault.add_ssh_key(&ssh_key).unwrap();

        // Verify it exists
        let keys = vault.list_ssh_keys().unwrap();
        assert_eq!(keys.len(), 1);

        // Delete the key
        vault.delete_ssh_key(key_id).unwrap();

        // Verify it's gone
        let keys = vault.list_ssh_keys().unwrap();
        assert_eq!(keys.len(), 0);

        // Trying to get it should fail
        assert!(vault.get_ssh_key(key_id).is_err());
    }

    #[test]
    fn test_ssh_key_wrong_password_fails() {
        use crate::crypto::DataEncryptionKey;

        let dek1 = DataEncryptionKey::new().unwrap();
        let dek2 = DataEncryptionKey::new().unwrap();

        let private_key =
            "-----BEGIN OPENSSH PRIVATE KEY-----\ntest content\n-----END OPENSSH PRIVATE KEY-----";

        // Encrypt with dek1
        let (encrypted, nonce, auth_tag) =
            crate::ssh::SshKey::encrypt_private_key(&dek1, private_key).unwrap();

        // Try to decrypt with dek2 (should fail)
        let result = crate::ssh::SshKey::decrypt_private_key(&dek2, &encrypted, &nonce, &auth_tag);
        assert!(result.is_err());
    }

    #[test]
    fn test_biometric_ref_metadata_roundtrip() {
        let db = Database::in_memory().unwrap();
        db.initialize_schema().unwrap();

        let mut key_hierarchy = KeyHierarchy::new();
        let (kdf_params, wrapped_dek) = key_hierarchy.initialize_vault(b"test_password").unwrap();
        VaultManager::store_vault_metadata(&db, &kdf_params, &wrapped_dek).unwrap();

        assert_eq!(VaultManager::load_biometric_ref(&db).unwrap(), None);

        VaultManager::set_biometric_ref(&db, Some("vault-biometric-ref")).unwrap();
        assert_eq!(
            VaultManager::load_biometric_ref(&db).unwrap().as_deref(),
            Some("vault-biometric-ref")
        );

        VaultManager::set_biometric_ref(&db, None).unwrap();
        assert_eq!(VaultManager::load_biometric_ref(&db).unwrap(), None);
    }
}
