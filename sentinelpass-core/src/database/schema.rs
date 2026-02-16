//! Database schema and connection management.

use crate::{DatabaseError, PasswordManagerError, Result};
use rusqlite::Connection;
use std::path::Path;

/// Current schema version. Incremented when the schema changes.
pub const CURRENT_SCHEMA_VERSION: i32 = 1;

/// Main database connection and schema manager
pub struct Database {
    conn: Connection,
}

impl Database {
    /// Open a database at the specified path
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let conn = Connection::open(path).map_err(DatabaseError::Sqlite)?;

        // Enable foreign key constraints
        conn.execute("PRAGMA foreign_keys = ON", [])
            .map_err(DatabaseError::Sqlite)?;

        Ok(Self { conn })
    }

    /// Create a new in-memory database for testing
    pub fn in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory().map_err(DatabaseError::Sqlite)?;

        conn.execute("PRAGMA foreign_keys = ON", [])
            .map_err(DatabaseError::Sqlite)?;

        Ok(Self { conn })
    }

    /// Initialize the database schema
    pub fn initialize_schema(&self) -> Result<()> {
        self.create_db_metadata_table()?;
        self.create_entries_table()?;
        self.create_domain_mappings_table()?;
        self.create_failed_attempts_table()?;
        self.create_ssh_keys_table()?;
        self.create_totp_secrets_table()?;
        self.create_indexes()?;
        self.create_triggers()?;
        Ok(())
    }

    fn create_db_metadata_table(&self) -> Result<()> {
        self.conn
            .execute(
                "CREATE TABLE IF NOT EXISTS db_metadata (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                version INTEGER NOT NULL,
                kdf_params BLOB NOT NULL,
                wrapped_dek BLOB NOT NULL,
                dek_nonce BLOB NOT NULL,
                created_at INTEGER NOT NULL,
                last_modified INTEGER NOT NULL,
                biometric_ref TEXT
            )",
                [],
            )
            .map_err(DatabaseError::Sqlite)?;
        Ok(())
    }

    fn create_entries_table(&self) -> Result<()> {
        self.conn
            .execute(
                "CREATE TABLE IF NOT EXISTS entries (
                entry_id INTEGER PRIMARY KEY AUTOINCREMENT,
                vault_id INTEGER NOT NULL,
                title BLOB NOT NULL,
                username BLOB NOT NULL,
                password BLOB NOT NULL,
                url BLOB,
                notes BLOB,
                entry_nonce BLOB NOT NULL,
                auth_tag BLOB NOT NULL,
                created_at INTEGER NOT NULL,
                modified_at INTEGER NOT NULL,
                favorite INTEGER NOT NULL DEFAULT 0
            )",
                [],
            )
            .map_err(DatabaseError::Sqlite)?;
        Ok(())
    }

    fn create_domain_mappings_table(&self) -> Result<()> {
        self.conn
            .execute(
                "CREATE TABLE IF NOT EXISTS domain_mappings (
                mapping_id INTEGER PRIMARY KEY,
                entry_id INTEGER NOT NULL,
                domain TEXT NOT NULL,
                is_primary INTEGER NOT NULL DEFAULT 1,
                FOREIGN KEY (entry_id) REFERENCES entries(entry_id) ON DELETE CASCADE
            )",
                [],
            )
            .map_err(DatabaseError::Sqlite)?;
        Ok(())
    }

    fn create_failed_attempts_table(&self) -> Result<()> {
        self.conn
            .execute(
                "CREATE TABLE IF NOT EXISTS failed_attempts (
                attempt_id INTEGER PRIMARY KEY AUTOINCREMENT,
                attempt_time INTEGER NOT NULL,
                ip_address TEXT
            )",
                [],
            )
            .map_err(DatabaseError::Sqlite)?;
        Ok(())
    }

    fn create_ssh_keys_table(&self) -> Result<()> {
        self.conn
            .execute(
                "CREATE TABLE IF NOT EXISTS ssh_keys (
                key_id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                comment TEXT,
                key_type TEXT NOT NULL,
                key_size INTEGER,
                public_key TEXT NOT NULL,
                private_key_encrypted BLOB NOT NULL,
                nonce BLOB NOT NULL,
                auth_tag BLOB NOT NULL,
                fingerprint TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                modified_at INTEGER NOT NULL
            )",
                [],
            )
            .map_err(DatabaseError::Sqlite)?;
        Ok(())
    }

    fn create_totp_secrets_table(&self) -> Result<()> {
        self.conn
            .execute(
                "CREATE TABLE IF NOT EXISTS totp_secrets (
                totp_id INTEGER PRIMARY KEY AUTOINCREMENT,
                entry_id INTEGER NOT NULL UNIQUE,
                secret_encrypted BLOB NOT NULL,
                nonce BLOB NOT NULL,
                auth_tag BLOB NOT NULL,
                algorithm TEXT NOT NULL DEFAULT 'SHA1',
                digits INTEGER NOT NULL DEFAULT 6,
                period INTEGER NOT NULL DEFAULT 30,
                issuer TEXT,
                account_name TEXT,
                created_at INTEGER NOT NULL,
                FOREIGN KEY (entry_id) REFERENCES entries(entry_id) ON DELETE CASCADE
            )",
                [],
            )
            .map_err(DatabaseError::Sqlite)?;
        Ok(())
    }

    fn create_indexes(&self) -> Result<()> {
        let indexes = [
            "CREATE INDEX IF NOT EXISTS idx_entries_vault_id ON entries(vault_id)",
            "CREATE INDEX IF NOT EXISTS idx_entries_favorite ON entries(favorite)",
            "CREATE INDEX IF NOT EXISTS idx_domain_mappings_entry_id ON domain_mappings(entry_id)",
            "CREATE INDEX IF NOT EXISTS idx_domain_mappings_domain ON domain_mappings(domain)",
            "CREATE INDEX IF NOT EXISTS idx_totp_secrets_entry_id ON totp_secrets(entry_id)",
        ];
        for sql in &indexes {
            self.conn.execute(sql, []).map_err(DatabaseError::Sqlite)?;
        }
        Ok(())
    }

    fn create_triggers(&self) -> Result<()> {
        self.conn
            .execute_batch(
                "CREATE TRIGGER IF NOT EXISTS update_db_metadata_timestamp
                 AFTER UPDATE ON db_metadata
                 FOR EACH ROW
                 BEGIN
                     UPDATE db_metadata SET last_modified = (strftime('%s', 'now')) WHERE id = 1;
                 END;

                 CREATE TRIGGER IF NOT EXISTS update_entry_modified_timestamp
                 AFTER UPDATE ON entries
                 FOR EACH ROW
                 BEGIN
                     UPDATE entries SET modified_at = (strftime('%s', 'now')) WHERE entry_id = NEW.entry_id;
                 END;",
            )
            .map_err(DatabaseError::Sqlite)?;
        Ok(())
    }

    /// Validate that the database schema version matches the expected version.
    pub fn validate_schema_version(&self) -> Result<()> {
        let version: i32 = self
            .conn
            .query_row("SELECT version FROM db_metadata WHERE id = 1", [], |row| {
                row.get(0)
            })
            .map_err(DatabaseError::Sqlite)?;
        if version != CURRENT_SCHEMA_VERSION {
            return Err(PasswordManagerError::from(DatabaseError::SchemaMismatch {
                expected: CURRENT_SCHEMA_VERSION,
                found: version,
            }));
        }
        Ok(())
    }

    /// Get a reference to the underlying connection
    pub fn conn(&self) -> &Connection {
        &self.conn
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_in_memory_database() {
        let db = Database::in_memory().unwrap();
        db.initialize_schema().unwrap();

        // Verify tables exist
        let table_names: Vec<String> = db
            .conn
            .prepare("SELECT name FROM sqlite_master WHERE type='table'")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap();

        assert!(table_names.contains(&"db_metadata".to_string()));
        assert!(table_names.contains(&"entries".to_string()));
        assert!(table_names.contains(&"domain_mappings".to_string()));
        assert!(table_names.contains(&"failed_attempts".to_string()));
        assert!(table_names.contains(&"ssh_keys".to_string()));
        assert!(table_names.contains(&"totp_secrets".to_string()));

        // Verify indexes exist
        let index_names: Vec<String> = db
            .conn
            .prepare("SELECT name FROM sqlite_master WHERE type='index' AND name LIKE 'idx_%'")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap();

        assert!(index_names.contains(&"idx_entries_vault_id".to_string()));
        assert!(index_names.contains(&"idx_entries_favorite".to_string()));
        assert!(index_names.contains(&"idx_domain_mappings_entry_id".to_string()));
        assert!(index_names.contains(&"idx_domain_mappings_domain".to_string()));
        assert!(index_names.contains(&"idx_totp_secrets_entry_id".to_string()));

        // Verify triggers exist
        let trigger_names: Vec<String> = db
            .conn
            .prepare("SELECT name FROM sqlite_master WHERE type='trigger'")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap();

        assert!(trigger_names.contains(&"update_db_metadata_timestamp".to_string()));
        assert!(trigger_names.contains(&"update_entry_modified_timestamp".to_string()));
    }
}
