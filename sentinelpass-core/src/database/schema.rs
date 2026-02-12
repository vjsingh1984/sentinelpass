//! Database schema and connection management.

use crate::crypto::{CryptoError, Result};
use rusqlite::Connection;
use std::path::Path;

/// Main database connection and schema manager
pub struct Database {
    conn: Connection,
}

impl Database {
    /// Open a database at the specified path
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let conn = Connection::open(path)
            .map_err(|e| CryptoError::EncryptionFailed(format!("Failed to open database: {}", e)))?;

        // Enable foreign key constraints
        conn.execute("PRAGMA foreign_keys = ON", [])
            .map_err(|e| CryptoError::EncryptionFailed(format!("Failed to enable FK: {}", e)))?;

        Ok(Self { conn })
    }

    /// Create a new in-memory database for testing
    pub fn in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()
            .map_err(|e| CryptoError::EncryptionFailed(format!("Failed to create in-memory DB: {}", e)))?;

        conn.execute("PRAGMA foreign_keys = ON", [])
            .map_err(|e| CryptoError::EncryptionFailed(format!("Failed to enable FK: {}", e)))?;

        Ok(Self { conn })
    }

    /// Initialize the database schema
    pub fn initialize_schema(&self) -> Result<()> {
        self.create_db_metadata_table()?;
        self.create_entries_table()?;
        self.create_domain_mappings_table()?;
        Ok(())
    }

    fn create_db_metadata_table(&self) -> Result<()> {
        self.conn.execute(
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
        ).map_err(|e| CryptoError::EncryptionFailed(format!("Failed to create db_metadata: {}", e)))?;
        Ok(())
    }

    fn create_entries_table(&self) -> Result<()> {
        self.conn.execute(
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
        ).map_err(|e| CryptoError::EncryptionFailed(format!("Failed to create entries: {}", e)))?;
        Ok(())
    }

    fn create_domain_mappings_table(&self) -> Result<()> {
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS domain_mappings (
                mapping_id INTEGER PRIMARY KEY,
                entry_id INTEGER NOT NULL,
                domain TEXT NOT NULL,
                is_primary INTEGER NOT NULL DEFAULT 1,
                FOREIGN KEY (entry_id) REFERENCES entries(entry_id) ON DELETE CASCADE
            )",
            [],
        ).map_err(|e| CryptoError::EncryptionFailed(format!("Failed to create domain_mappings: {}", e)))?;
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
        let table_names: Vec<String> = db.conn
            .prepare("SELECT name FROM sqlite_master WHERE type='table'")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap();

        assert!(table_names.contains(&"db_metadata".to_string()));
        assert!(table_names.contains(&"entries".to_string()));
        assert!(table_names.contains(&"domain_mappings".to_string()));
    }
}
