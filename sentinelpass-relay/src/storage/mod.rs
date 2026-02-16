//! SQLite storage backend for the relay.

pub mod models;

use crate::error::RelayError;
use rusqlite::Connection;
use std::path::Path;
use std::sync::{Arc, Mutex};

/// Thread-safe relay storage.
#[derive(Clone)]
pub struct RelayStorage {
    conn: Arc<Mutex<Connection>>,
}

impl RelayStorage {
    pub fn open(path: &Path) -> Result<Self, anyhow::Error> {
        let conn = Connection::open(path)?;
        conn.execute("PRAGMA foreign_keys = ON", [])?;
        conn.execute("PRAGMA journal_mode = WAL", [])?;

        let storage = Self {
            conn: Arc::new(Mutex::new(conn)),
        };
        storage.initialize_schema()?;
        Ok(storage)
    }

    #[allow(dead_code)]
    pub fn in_memory() -> Result<Self, anyhow::Error> {
        let conn = Connection::open_in_memory()?;
        conn.execute("PRAGMA foreign_keys = ON", [])?;

        let storage = Self {
            conn: Arc::new(Mutex::new(conn)),
        };
        storage.initialize_schema()?;
        Ok(storage)
    }

    fn initialize_schema(&self) -> Result<(), anyhow::Error> {
        let conn = self.conn.lock().map_err(|e| anyhow::anyhow!("{}", e))?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS vaults (
                vault_id TEXT PRIMARY KEY,
                created_at INTEGER NOT NULL,
                entry_count INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS devices (
                device_id TEXT PRIMARY KEY,
                vault_id TEXT NOT NULL,
                device_name TEXT NOT NULL,
                device_type TEXT NOT NULL,
                public_key BLOB NOT NULL,
                registered_at INTEGER NOT NULL,
                revoked INTEGER NOT NULL DEFAULT 0,
                revoked_at INTEGER,
                FOREIGN KEY (vault_id) REFERENCES vaults(vault_id)
            );

            CREATE TABLE IF NOT EXISTS sync_entries (
                sync_id TEXT NOT NULL,
                vault_id TEXT NOT NULL,
                entry_type TEXT NOT NULL,
                sync_version INTEGER NOT NULL,
                modified_at INTEGER NOT NULL,
                encrypted_payload BLOB NOT NULL,
                is_tombstone INTEGER NOT NULL DEFAULT 0,
                origin_device_id TEXT NOT NULL,
                server_sequence INTEGER NOT NULL,
                received_at INTEGER NOT NULL,
                PRIMARY KEY (sync_id, vault_id)
            );

            CREATE TABLE IF NOT EXISTS sequence_counters (
                vault_id TEXT PRIMARY KEY,
                current_sequence INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS device_sequences (
                device_id TEXT PRIMARY KEY,
                last_sequence INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS pairing_bootstraps (
                pairing_token TEXT PRIMARY KEY,
                vault_id TEXT NOT NULL,
                encrypted_bootstrap BLOB NOT NULL,
                pairing_salt BLOB NOT NULL,
                expires_at INTEGER NOT NULL,
                consumed INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS seen_nonces (
                nonce TEXT PRIMARY KEY,
                device_id TEXT NOT NULL,
                seen_at INTEGER NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_sync_entries_vault_seq
                ON sync_entries(vault_id, server_sequence);
            CREATE INDEX IF NOT EXISTS idx_devices_vault
                ON devices(vault_id);
            CREATE INDEX IF NOT EXISTS idx_seen_nonces_seen_at
                ON seen_nonces(seen_at);
            CREATE INDEX IF NOT EXISTS idx_pairing_expires
                ON pairing_bootstraps(expires_at);",
        )?;
        Ok(())
    }

    pub fn conn(&self) -> Result<std::sync::MutexGuard<'_, Connection>, RelayError> {
        self.conn
            .lock()
            .map_err(|e| RelayError::Internal(format!("Lock error: {}", e)))
    }
}
