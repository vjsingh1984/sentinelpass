//! Vault management - coordinates crypto and database layers

mod biometric_ops;
mod ssh_ops;
#[cfg(test)]
mod tests;
mod totp_ops;

use crate::{
    audit::{get_audit_log_dir, AuditEventType, AuditLogger},
    crypto::cipher::{decrypt_to_string, encrypt_string},
    crypto::{EncryptedEntry, KdfParams, KeyHierarchy, WrappedKey},
    database::{schema::CURRENT_SCHEMA_VERSION, Database},
    lockout::DEFAULT_MAX_ATTEMPTS,
    platform::{ensure_data_dir, get_default_vault_path},
    DatabaseError, PasswordManagerError, Result,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// Vault manager handles all vault operations
pub struct VaultManager {
    pub(super) key_hierarchy: KeyHierarchy,
    pub(super) db: Arc<Mutex<Database>>,
    pub(super) vault_path: PathBuf,
    pub(super) audit_logger: Option<Arc<AuditLogger>>,
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
        db.validate_schema_version()?;

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
            .map_err(|e| DatabaseError::Serialization(e.to_string()))?;
        let username_blob = bincode::serialize(&username_encrypted)
            .map_err(|e| DatabaseError::Serialization(e.to_string()))?;
        let password_blob = bincode::serialize(&password_encrypted)
            .map_err(|e| DatabaseError::Serialization(e.to_string()))?;
        let url_blob = url_encrypted
            .as_ref()
            .map(|e| bincode::serialize(e).map_err(|e| DatabaseError::Serialization(e.to_string())))
            .transpose()?;
        let notes_blob = notes_encrypted
            .as_ref()
            .map(|e| bincode::serialize(e).map_err(|e| DatabaseError::Serialization(e.to_string())))
            .transpose()?;

        let nonce_blob = bincode::serialize(&title_encrypted.nonce)
            .map_err(|e| DatabaseError::Serialization(e.to_string()))?;
        let auth_tag_blob = bincode::serialize(&title_encrypted.auth_tag)
            .map_err(|e| DatabaseError::Serialization(e.to_string()))?;

        // For now, use a simple vault_id of 1
        let vault_id: i64 = 1;
        let now = Utc::now().timestamp();
        let favorite: i64 = if entry.favorite { 1 } else { 0 };

        // Open database and insert entry
        let db = self
            .db
            .lock()
            .map_err(|_| DatabaseError::LockPoisoned("Failed to lock database".to_string()))?;

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
            .map_err(DatabaseError::Sqlite)?;

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
            .map_err(|_| DatabaseError::LockPoisoned("Failed to lock database".to_string()))?;

        // Query the database
        let mut stmt = db
            .conn()
            .prepare(
                "SELECT title, username, password, url, notes, created_at, modified_at, favorite
             FROM entries WHERE entry_id = ?1",
            )
            .map_err(DatabaseError::Sqlite)?;

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
                    .map_err(|e| DatabaseError::Serialization(e.to_string()))?;
                let username_encrypted: EncryptedEntry = bincode::deserialize(&username_blob)
                    .map_err(|e| DatabaseError::Serialization(e.to_string()))?;
                let password_encrypted: EncryptedEntry = bincode::deserialize(&password_blob)
                    .map_err(|e| DatabaseError::Serialization(e.to_string()))?;

                let title = decrypt_to_string(dek, &title_encrypted)?;
                let username = decrypt_to_string(dek, &username_encrypted)?;
                let password = decrypt_to_string(dek, &password_encrypted)?;

                let url = if let Some(ub) = url_blob {
                    if ub.is_empty() {
                        None
                    } else {
                        let url_encrypted: EncryptedEntry = bincode::deserialize(&ub)
                            .map_err(|e| DatabaseError::Serialization(e.to_string()))?;
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
                            .map_err(|e| DatabaseError::Serialization(e.to_string()))?;
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
            .map_err(|_| DatabaseError::LockPoisoned("Failed to lock database".to_string()))?;

        let mut stmt = db
            .conn()
            .prepare("SELECT entry_id, title, username, favorite FROM entries")
            .map_err(DatabaseError::Sqlite)?;

        let mut entries = stmt
            .query_map([], |row| {
                let entry_id: i64 = row.get(0)?;
                let title_blob: Vec<u8> = row.get(1)?;
                let username_blob: Vec<u8> = row.get(2)?;
                let favorite: i32 = row.get(3)?;

                Ok((entry_id, title_blob, username_blob, favorite))
            })
            .map_err(DatabaseError::Sqlite)?
            .map(|row| -> Result<EntrySummary> {
                let (entry_id, title_blob, username_blob, favorite) =
                    row.map_err(|e| PasswordManagerError::from(DatabaseError::Sqlite(e)))?;

                let title_encrypted: EncryptedEntry = bincode::deserialize(&title_blob)
                    .map_err(|e| DatabaseError::Serialization(e.to_string()))?;
                let username_encrypted: EncryptedEntry = bincode::deserialize(&username_blob)
                    .map_err(|e| DatabaseError::Serialization(e.to_string()))?;

                let title = decrypt_to_string(dek, &title_encrypted)?;
                let username = decrypt_to_string(dek, &username_encrypted)?;

                Ok(EntrySummary {
                    entry_id,
                    title,
                    username,
                    favorite: favorite != 0,
                })
            })
            .collect::<std::result::Result<Vec<_>, _>>()?;

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
            .map_err(|_| DatabaseError::LockPoisoned("Failed to lock database".to_string()))?;

        // First, delete associated domain mappings
        db.conn()
            .execute(
                "DELETE FROM domain_mappings WHERE entry_id = ?1",
                [entry_id],
            )
            .map_err(DatabaseError::Sqlite)?;

        // Then delete the entry
        let rows_affected = db
            .conn()
            .execute("DELETE FROM entries WHERE entry_id = ?1", [entry_id])
            .map_err(DatabaseError::Sqlite)?;

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
            .map_err(|_| DatabaseError::LockPoisoned("Failed to lock database".to_string()))?;

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
            .map_err(|e| DatabaseError::Serialization(e.to_string()))?;
        let username_blob = bincode::serialize(&username_encrypted)
            .map_err(|e| DatabaseError::Serialization(e.to_string()))?;
        let password_blob = bincode::serialize(&password_encrypted)
            .map_err(|e| DatabaseError::Serialization(e.to_string()))?;
        let url_blob = url_encrypted
            .as_ref()
            .map(|e| bincode::serialize(e).map_err(|e| DatabaseError::Serialization(e.to_string())))
            .transpose()?;
        let notes_blob = notes_encrypted
            .as_ref()
            .map(|e| bincode::serialize(e).map_err(|e| DatabaseError::Serialization(e.to_string())))
            .transpose()?;

        let nonce_blob = bincode::serialize(&title_encrypted.nonce)
            .map_err(|e| DatabaseError::Serialization(e.to_string()))?;
        let auth_tag_blob = bincode::serialize(&title_encrypted.auth_tag)
            .map_err(|e| DatabaseError::Serialization(e.to_string()))?;

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
            .map_err(DatabaseError::Sqlite)?;

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
    pub(super) fn store_vault_metadata(
        db: &Database,
        kdf_params: &KdfParams,
        wrapped_dek: &WrappedKey,
    ) -> Result<()> {
        let kdf_params_blob = bincode::serialize(kdf_params)
            .map_err(|e| DatabaseError::Serialization(e.to_string()))?;
        let wrapped_dek_blob = bincode::serialize(wrapped_dek)
            .map_err(|e| DatabaseError::Serialization(e.to_string()))?;
        let nonce_blob = bincode::serialize(&wrapped_dek.nonce)
            .map_err(|e| DatabaseError::Serialization(e.to_string()))?;

        let now = Utc::now().timestamp();

        db.conn().execute(
            "INSERT INTO db_metadata (id, version, kdf_params, wrapped_dek, dek_nonce, created_at, last_modified)
             VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6)",
            (CURRENT_SCHEMA_VERSION, &kdf_params_blob, &wrapped_dek_blob, &nonce_blob, now, now),
        ).map_err(DatabaseError::Sqlite)?;

        Ok(())
    }

    fn record_failed_attempt(db: &Database) -> Result<()> {
        let now = Utc::now().timestamp();
        db.conn()
            .execute(
                "INSERT INTO failed_attempts (attempt_time, ip_address) VALUES (?1, NULL)",
                [now],
            )
            .map_err(DatabaseError::Sqlite)?;
        Ok(())
    }

    pub(super) fn clear_failed_attempts(db: &Database) -> Result<()> {
        db.conn()
            .execute("DELETE FROM failed_attempts", [])
            .map_err(DatabaseError::Sqlite)?;
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
            .map_err(DatabaseError::Sqlite)?;

        let Some(lockout_duration_seconds) = Self::lockout_duration_seconds(total_failed_attempts)
        else {
            return Ok(None);
        };

        let last_failed_attempt: Option<i64> = db
            .conn()
            .query_row("SELECT MAX(attempt_time) FROM failed_attempts", [], |row| {
                row.get(0)
            })
            .map_err(DatabaseError::Sqlite)?;

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
    pub(super) fn load_vault_metadata(
        db: &crate::database::Database,
    ) -> Result<(KdfParams, WrappedKey)> {
        let mut stmt = db
            .conn()
            .prepare("SELECT kdf_params, wrapped_dek FROM db_metadata WHERE id = 1")
            .map_err(DatabaseError::Sqlite)?;

        let result = stmt.query_row([], |row| {
            let kdf_params_blob: Vec<u8> = row.get(0)?;
            let wrapped_dek_blob: Vec<u8> = row.get(1)?;
            Ok((kdf_params_blob, wrapped_dek_blob))
        });

        match result {
            Ok((kdf_params_blob, wrapped_dek_blob)) => {
                let kdf_params: KdfParams = bincode::deserialize(&kdf_params_blob)
                    .map_err(|e| DatabaseError::Serialization(e.to_string()))?;
                let wrapped_dek: WrappedKey = bincode::deserialize(&wrapped_dek_blob)
                    .map_err(|e| DatabaseError::Serialization(e.to_string()))?;
                Ok((kdf_params, wrapped_dek))
            }
            Err(_) => Err(PasswordManagerError::NotFound("Vault metadata".to_string())),
        }
    }

    /// Load biometric key reference from database metadata.
    pub(super) fn load_biometric_ref(db: &crate::database::Database) -> Result<Option<String>> {
        db.conn()
            .query_row(
                "SELECT biometric_ref FROM db_metadata WHERE id = 1",
                [],
                |row| row.get(0),
            )
            .map_err(DatabaseError::Sqlite)
            .map_err(PasswordManagerError::from)
    }

    /// Update biometric key reference in database metadata.
    pub(super) fn set_biometric_ref(
        db: &crate::database::Database,
        biometric_ref: Option<&str>,
    ) -> Result<()> {
        db.conn()
            .execute(
                "UPDATE db_metadata SET biometric_ref = ?1 WHERE id = 1",
                [biometric_ref],
            )
            .map_err(DatabaseError::Sqlite)?;
        Ok(())
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
