//! Change tracking: query pending changes, create sync blobs, mark synced.

use crate::crypto::cipher::DataEncryptionKey;
use crate::sync::crypto::encrypt_for_sync;
use crate::sync::models::{
    CredentialPayload, DomainPayload, SshKeyPayload, SyncEntryBlob, SyncEntryType, TotpPayload,
};
use crate::{DatabaseError, Result};
use rusqlite::Connection;
use uuid::Uuid;

/// Query all entries with `sync_state = 'pending'` and build sync blobs.
pub fn collect_pending_credential_blobs(
    conn: &Connection,
    dek: &DataEncryptionKey,
    device_id: Uuid,
) -> Result<Vec<SyncEntryBlob>> {
    let mut stmt = conn
        .prepare(
            "SELECT entry_id, sync_id, sync_version, modified_at, is_deleted,
                    title, username, password, url, notes, favorite, created_at
             FROM entries
             WHERE sync_state = 'pending'",
        )
        .map_err(DatabaseError::Sqlite)?;

    let rows = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,             // entry_id
                row.get::<_, String>(1)?,          // sync_id
                row.get::<_, i64>(2)?,             // sync_version
                row.get::<_, i64>(3)?,             // modified_at
                row.get::<_, bool>(4)?,            // is_deleted
                row.get::<_, Vec<u8>>(5)?,         // title (encrypted blob)
                row.get::<_, Vec<u8>>(6)?,         // username
                row.get::<_, Vec<u8>>(7)?,         // password
                row.get::<_, Option<Vec<u8>>>(8)?, // url
                row.get::<_, Option<Vec<u8>>>(9)?, // notes
                row.get::<_, bool>(10)?,           // favorite
                row.get::<_, i64>(11)?,            // created_at
            ))
        })
        .map_err(DatabaseError::Sqlite)?;

    let mut blobs = Vec::new();

    for row in rows {
        let (
            entry_id,
            sync_id_str,
            sync_version,
            modified_at,
            is_deleted,
            title_blob,
            username_blob,
            password_blob,
            url_blob,
            notes_blob,
            favorite,
            created_at,
        ) = row.map_err(DatabaseError::Sqlite)?;

        let sync_id = Uuid::parse_str(&sync_id_str)
            .map_err(|e| DatabaseError::Other(format!("Invalid sync_id: {}", e)))?;

        if is_deleted {
            // Tombstone: empty encrypted payload
            let tombstone_data = serde_json::to_vec(&serde_json::json!({"tombstone": true}))
                .map_err(|e| DatabaseError::Serialization(e.to_string()))?;
            let encrypted = encrypt_for_sync(dek, &tombstone_data)
                .map_err(crate::PasswordManagerError::Crypto)?;

            blobs.push(SyncEntryBlob {
                sync_id,
                entry_type: SyncEntryType::Credential,
                sync_version: sync_version as u64,
                modified_at,
                encrypted_payload: encrypted,
                is_tombstone: true,
                origin_device_id: device_id,
            });
            continue;
        }

        // Load domain mappings for this entry
        let domains = load_domain_mappings(conn, entry_id)?;

        // Build credential payload from raw encrypted blobs
        // Note: we re-serialize the raw blobs as-is since they're already
        // encrypted locally. For sync, we need the *logical* plaintext to
        // re-encrypt under the sync wire format. But since the DEK is the
        // same, we decrypt locally and re-encrypt for transport.
        let title = decrypt_blob(dek, &title_blob)?;
        let username = decrypt_blob(dek, &username_blob)?;
        let password = decrypt_blob(dek, &password_blob)?;
        let url = url_blob
            .filter(|b| !b.is_empty())
            .map(|b| decrypt_blob(dek, &b))
            .transpose()?;
        let notes = notes_blob
            .filter(|b| !b.is_empty())
            .map(|b| decrypt_blob(dek, &b))
            .transpose()?;

        let payload = CredentialPayload {
            title,
            username,
            password,
            url,
            notes,
            favorite,
            domains,
            created_at,
            modified_at,
        };

        let payload_json = serde_json::to_vec(&payload)
            .map_err(|e| DatabaseError::Serialization(e.to_string()))?;

        let encrypted =
            encrypt_for_sync(dek, &payload_json).map_err(crate::PasswordManagerError::Crypto)?;

        blobs.push(SyncEntryBlob {
            sync_id,
            entry_type: SyncEntryType::Credential,
            sync_version: sync_version as u64,
            modified_at,
            encrypted_payload: encrypted,
            is_tombstone: false,
            origin_device_id: device_id,
        });
    }

    Ok(blobs)
}

/// Query pending SSH key changes and build sync blobs.
pub fn collect_pending_ssh_key_blobs(
    conn: &Connection,
    dek: &DataEncryptionKey,
    device_id: Uuid,
) -> Result<Vec<SyncEntryBlob>> {
    let mut stmt = conn
        .prepare(
            "SELECT key_id, sync_id, sync_version, modified_at, is_deleted,
                    name, comment, key_type, key_size, public_key,
                    private_key_encrypted, nonce, auth_tag, fingerprint, created_at
             FROM ssh_keys
             WHERE sync_state = 'pending'",
        )
        .map_err(DatabaseError::Sqlite)?;

    let rows = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(1)?,         // sync_id
                row.get::<_, i64>(2)?,            // sync_version
                row.get::<_, i64>(3)?,            // modified_at
                row.get::<_, bool>(4)?,           // is_deleted
                row.get::<_, String>(5)?,         // name
                row.get::<_, Option<String>>(6)?, // comment
                row.get::<_, String>(7)?,         // key_type
                row.get::<_, Option<i64>>(8)?,    // key_size
                row.get::<_, String>(9)?,         // public_key
                row.get::<_, Vec<u8>>(10)?,       // private_key_encrypted
                row.get::<_, Vec<u8>>(11)?,       // nonce
                row.get::<_, Vec<u8>>(12)?,       // auth_tag
                row.get::<_, String>(13)?,        // fingerprint
                row.get::<_, i64>(14)?,           // created_at
            ))
        })
        .map_err(DatabaseError::Sqlite)?;

    let mut blobs = Vec::new();

    for row in rows {
        let (
            sync_id_str,
            sync_version,
            modified_at,
            is_deleted,
            name,
            comment,
            key_type,
            key_size,
            public_key,
            private_key_encrypted,
            nonce,
            auth_tag,
            fingerprint,
            created_at,
        ) = row.map_err(DatabaseError::Sqlite)?;

        let sync_id = Uuid::parse_str(&sync_id_str)
            .map_err(|e| DatabaseError::Other(format!("Invalid sync_id: {}", e)))?;

        if is_deleted {
            let tombstone_data = serde_json::to_vec(&serde_json::json!({"tombstone": true}))
                .map_err(|e| DatabaseError::Serialization(e.to_string()))?;
            let encrypted = encrypt_for_sync(dek, &tombstone_data)
                .map_err(crate::PasswordManagerError::Crypto)?;

            blobs.push(SyncEntryBlob {
                sync_id,
                entry_type: SyncEntryType::SshKey,
                sync_version: sync_version as u64,
                modified_at,
                encrypted_payload: encrypted,
                is_tombstone: true,
                origin_device_id: device_id,
            });
            continue;
        }

        let payload = SshKeyPayload {
            name,
            comment,
            key_type,
            key_size,
            public_key,
            private_key_encrypted,
            nonce,
            auth_tag,
            fingerprint,
            created_at,
            modified_at,
        };

        let payload_json = serde_json::to_vec(&payload)
            .map_err(|e| DatabaseError::Serialization(e.to_string()))?;

        let encrypted =
            encrypt_for_sync(dek, &payload_json).map_err(crate::PasswordManagerError::Crypto)?;

        blobs.push(SyncEntryBlob {
            sync_id,
            entry_type: SyncEntryType::SshKey,
            sync_version: sync_version as u64,
            modified_at,
            encrypted_payload: encrypted,
            is_tombstone: false,
            origin_device_id: device_id,
        });
    }

    Ok(blobs)
}

/// Query pending TOTP secret changes and build sync blobs.
pub fn collect_pending_totp_blobs(
    conn: &Connection,
    dek: &DataEncryptionKey,
    device_id: Uuid,
) -> Result<Vec<SyncEntryBlob>> {
    let mut stmt = conn
        .prepare(
            "SELECT t.totp_id, t.sync_id, t.sync_version, t.created_at, t.is_deleted,
                    t.entry_id, t.secret_encrypted, t.nonce, t.auth_tag,
                    t.algorithm, t.digits, t.period, t.issuer, t.account_name,
                    e.sync_id as parent_sync_id
             FROM totp_secrets t
             LEFT JOIN entries e ON t.entry_id = e.entry_id
             WHERE t.sync_state = 'pending'",
        )
        .map_err(DatabaseError::Sqlite)?;

    let rows = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(1)?,          // sync_id
                row.get::<_, i64>(2)?,             // sync_version
                row.get::<_, i64>(3)?,             // created_at (used as modified_at)
                row.get::<_, bool>(4)?,            // is_deleted
                row.get::<_, Vec<u8>>(6)?,         // secret_encrypted
                row.get::<_, Vec<u8>>(7)?,         // nonce
                row.get::<_, Vec<u8>>(8)?,         // auth_tag
                row.get::<_, String>(9)?,          // algorithm
                row.get::<_, u8>(10)?,             // digits
                row.get::<_, u32>(11)?,            // period
                row.get::<_, Option<String>>(12)?, // issuer
                row.get::<_, Option<String>>(13)?, // account_name
                row.get::<_, Option<String>>(14)?, // parent_sync_id
            ))
        })
        .map_err(DatabaseError::Sqlite)?;

    let mut blobs = Vec::new();

    for row in rows {
        let (
            sync_id_str,
            sync_version,
            created_at,
            is_deleted,
            secret_encrypted,
            nonce,
            auth_tag,
            algorithm,
            digits,
            period,
            issuer,
            account_name,
            parent_sync_id_str,
        ) = row.map_err(DatabaseError::Sqlite)?;

        let sync_id = Uuid::parse_str(&sync_id_str)
            .map_err(|e| DatabaseError::Other(format!("Invalid sync_id: {}", e)))?;

        if is_deleted {
            let tombstone_data = serde_json::to_vec(&serde_json::json!({"tombstone": true}))
                .map_err(|e| DatabaseError::Serialization(e.to_string()))?;
            let encrypted = encrypt_for_sync(dek, &tombstone_data)
                .map_err(crate::PasswordManagerError::Crypto)?;

            blobs.push(SyncEntryBlob {
                sync_id,
                entry_type: SyncEntryType::TotpSecret,
                sync_version: sync_version as u64,
                modified_at: created_at,
                encrypted_payload: encrypted,
                is_tombstone: true,
                origin_device_id: device_id,
            });
            continue;
        }

        let parent_credential_sync_id = parent_sync_id_str.and_then(|s| Uuid::parse_str(&s).ok());

        let payload = TotpPayload {
            secret_encrypted,
            nonce,
            auth_tag,
            algorithm,
            digits,
            period,
            issuer,
            account_name,
            created_at,
            parent_credential_sync_id,
        };

        let payload_json = serde_json::to_vec(&payload)
            .map_err(|e| DatabaseError::Serialization(e.to_string()))?;

        let encrypted =
            encrypt_for_sync(dek, &payload_json).map_err(crate::PasswordManagerError::Crypto)?;

        blobs.push(SyncEntryBlob {
            sync_id,
            entry_type: SyncEntryType::TotpSecret,
            sync_version: sync_version as u64,
            modified_at: created_at,
            encrypted_payload: encrypted,
            is_tombstone: false,
            origin_device_id: device_id,
        });
    }

    Ok(blobs)
}

/// Mark entries as synced after successful push.
pub fn mark_entries_synced(conn: &Connection, sync_ids: &[Uuid]) -> Result<()> {
    let now = chrono::Utc::now().timestamp();
    for sync_id in sync_ids {
        let id_str = sync_id.to_string();
        conn.execute(
            "UPDATE entries SET sync_state = 'synced', last_synced_at = ?1 WHERE sync_id = ?2",
            rusqlite::params![now, id_str],
        )
        .map_err(DatabaseError::Sqlite)?;

        conn.execute(
            "UPDATE ssh_keys SET sync_state = 'synced', last_synced_at = ?1 WHERE sync_id = ?2",
            rusqlite::params![now, id_str],
        )
        .map_err(DatabaseError::Sqlite)?;

        conn.execute(
            "UPDATE totp_secrets SET sync_state = 'synced', last_synced_at = ?1 WHERE sync_id = ?2",
            rusqlite::params![now, id_str],
        )
        .map_err(DatabaseError::Sqlite)?;
    }

    Ok(())
}

/// Mark a tombstone as pushed.
pub fn mark_tombstone_pushed(conn: &Connection, sync_id: &Uuid) -> Result<()> {
    conn.execute(
        "UPDATE sync_tombstones SET pushed = 1 WHERE sync_id = ?1",
        [sync_id.to_string()],
    )
    .map_err(DatabaseError::Sqlite)?;

    Ok(())
}

/// Count pending changes across all entry types.
pub fn count_pending_changes(conn: &Connection) -> Result<u64> {
    let count: i64 = conn
        .query_row(
            "SELECT
                (SELECT COUNT(*) FROM entries WHERE sync_state = 'pending') +
                (SELECT COUNT(*) FROM ssh_keys WHERE sync_state = 'pending') +
                (SELECT COUNT(*) FROM totp_secrets WHERE sync_state = 'pending')",
            [],
            |row| row.get(0),
        )
        .map_err(DatabaseError::Sqlite)?;

    Ok(count as u64)
}

// --- Helpers ---

fn load_domain_mappings(conn: &Connection, entry_id: i64) -> Result<Vec<DomainPayload>> {
    let mut stmt = conn
        .prepare("SELECT domain, is_primary FROM domain_mappings WHERE entry_id = ?1")
        .map_err(DatabaseError::Sqlite)?;

    let domains = stmt
        .query_map([entry_id], |row| {
            Ok(DomainPayload {
                domain: row.get(0)?,
                is_primary: row.get(1)?,
            })
        })
        .map_err(DatabaseError::Sqlite)?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(DatabaseError::Sqlite)?;

    Ok(domains)
}

/// Decrypt a bincode-serialized EncryptedEntry blob to a String.
fn decrypt_blob(dek: &DataEncryptionKey, blob: &[u8]) -> Result<String> {
    let encrypted: crate::crypto::EncryptedEntry =
        bincode::deserialize(blob).map_err(|e| DatabaseError::Serialization(e.to_string()))?;
    crate::crypto::cipher::decrypt_to_string(dek, &encrypted)
        .map_err(crate::PasswordManagerError::Crypto)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::Database;

    fn setup_db_with_sync_schema() -> Database {
        let db = Database::in_memory().unwrap();
        db.initialize_schema().unwrap();
        // Schema already v2 from initialize_schema, no migration needed
        db
    }

    #[test]
    fn count_pending_empty() {
        let db = setup_db_with_sync_schema();
        let count = count_pending_changes(db.conn()).unwrap();
        assert_eq!(count, 0);
    }
}
