//! Sync data models: wire format, entry types, and device identity.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::CredentialType;

/// Type of syncable entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncEntryType {
    Credential,
    SshKey,
    TotpSecret,
}

/// Sync state of a local entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncState {
    Synced,
    Pending,
    Conflict,
}

impl SyncState {
    /// Convert sync state to its string representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Synced => "synced",
            Self::Pending => "pending",
            Self::Conflict => "conflict",
        }
    }

    /// Parse a sync state from its string representation.
    pub fn parse(s: &str) -> Self {
        match s {
            "synced" => Self::Synced,
            "conflict" => Self::Conflict,
            _ => Self::Pending,
        }
    }
}

/// A single entry blob for sync transport.
///
/// The `encrypted_payload` is `nonce(12) || ciphertext || auth_tag(16)`,
/// encrypted with the vault DEK via AES-256-GCM. Domain mappings are
/// included inside credential payloads (never sent separately).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncEntryBlob {
    /// Stable identifier across devices (not local entry_id).
    pub sync_id: Uuid,
    /// Entry type discriminator.
    pub entry_type: SyncEntryType,
    /// Monotonic per-entry version counter.
    pub sync_version: u64,
    /// Unix timestamp (cleartext hint for LWW ordering).
    pub modified_at: i64,
    /// `nonce(12) || ciphertext || auth_tag(16)` encrypted with DEK.
    #[serde(with = "base64_bytes")]
    pub encrypted_payload: Vec<u8>,
    /// Whether this entry has been soft-deleted.
    pub is_tombstone: bool,
    /// Device that last modified this entry.
    pub origin_device_id: Uuid,
}

/// Decrypted credential data transported over sync.
use zeroize::Zeroizing;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialPayload {
    pub title: String,
    pub username: String,
    pub password: String,
    #[serde(default)]
    pub credential_type: CredentialType,
    pub url: Option<String>,
    pub notes: Option<String>,
    pub favorite: bool,
    pub domains: Vec<DomainPayload>,
    pub created_at: i64,
    pub modified_at: i64,
}

/// Domain mapping within a credential sync payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainPayload {
    pub domain: String,
    pub is_primary: bool,
}

/// Decrypted SSH key data transported over sync. Debug is HAND-WRITTEN
/// to redact the private key (CLAUDE.md NEVER 1: log secrets — a derived
/// Debug would print the PEM on the first accidental `{:?}`).
#[derive(Clone, Serialize, Deserialize)]
pub struct SshKeyPayload {
    pub name: String,
    pub comment: Option<String>,
    pub key_type: String,
    pub key_size: Option<i64>,
    pub public_key: String,
    /// PLAINTEXT private key (PEM), zeroize-on-drop. The whole payload is
    /// DEK-encrypted for transport (encrypt_for_sync); storing the LOCAL
    /// v2 envelope here instead would transplant it to peers whose
    /// identity differs (WBS-304 adoption review, finding 3 class). Each
    /// device seals under its own identity on apply.
    /// `default`: EMPTY on a v0.8.x peer's payload (whose key material
    /// arrives in `private_key_encrypted` below) — resolve_sync_secret
    /// picks whichever shape is present.
    #[serde(default)]
    pub private_key: Zeroizing<String>,
    /// v0.8.x wire shape under the ORIGINAL field names: a context-free
    /// v1-style encryption of the SAME plaintext as `private_key`,
    /// EMITTED for pre-envelope peers (whose structs require these
    /// fields — without them their pull wedges; wire-compat review) and
    /// decrypted with the shared DEK when received from them.
    /// `rename` on the nonce/tag fields: the old wire emits/parses the
    /// top-level names `nonce`/`auth_tag` — without the rename this
    /// build would emit `legacy_nonce` (ignored by old peers, wedging
    /// their pull) and could never read theirs (cross-file angle).
    pub private_key_encrypted: Option<Vec<u8>>,
    #[serde(default, rename = "nonce")]
    pub legacy_nonce: Option<Vec<u8>>,
    #[serde(default, rename = "auth_tag")]
    pub legacy_auth_tag: Option<Vec<u8>>,
    pub fingerprint: String,
    pub created_at: i64,
    pub modified_at: i64,
}

/// Decrypted TOTP secret data transported over sync. Debug is
/// HAND-WRITTEN to redact the seed (see SshKeyPayload).
#[derive(Clone, Serialize, Deserialize)]
pub struct TotpPayload {
    /// PLAINTEXT normalized base32 secret, zeroize-on-drop `default`
    /// (see SshKeyPayload.private_key).
    #[serde(default)]
    pub secret: Zeroizing<String>,
    /// v0.8.x wire shape under the ORIGINAL field names (see
    /// SshKeyPayload.private_key_encrypted) — emitted for old peers.
    pub secret_encrypted: Option<Vec<u8>>,
    #[serde(default, rename = "nonce")]
    pub legacy_nonce: Option<Vec<u8>>,
    #[serde(default, rename = "auth_tag")]
    pub legacy_auth_tag: Option<Vec<u8>>,
    pub algorithm: String,
    pub digits: u8,
    pub period: u32,
    pub issuer: Option<String>,
    pub account_name: Option<String>,
    pub created_at: i64,
    /// The sync_id of the parent credential (so the receiving device
    /// can re-link `totp_secrets.entry_id`).
    pub parent_credential_sync_id: Option<Uuid>,
}

impl std::fmt::Debug for SshKeyPayload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SshKeyPayload")
            .field("name", &self.name)
            .field("key_type", &self.key_type)
            .field("fingerprint", &self.fingerprint)
            .field("private_key", &"[REDACTED]")
            .field(
                "private_key_encrypted",
                &self.private_key_encrypted.is_some(),
            )
            .finish()
    }
}

impl std::fmt::Debug for TotpPayload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TotpPayload")
            .field("algorithm", &self.algorithm)
            .field("digits", &self.digits)
            .field("period", &self.period)
            .field("issuer", &self.issuer)
            .field("account_name", &self.account_name)
            .field("secret", &"[REDACTED]")
            .field("secret_encrypted", &self.secret_encrypted.is_some())
            .finish()
    }
}

/// Bootstrap blob sent during device pairing (encrypted with pairing key).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultBootstrap {
    /// KDF parameters (salt, mem_cost, etc.) so new device can derive master key.
    pub kdf_params_blob: Vec<u8>,
    /// Wrapped DEK blob (encrypted with master key).
    pub wrapped_dek_blob: Vec<u8>,
    /// Relay server URL.
    pub relay_url: String,
    /// Vault identifier on the relay.
    pub vault_id: Uuid,
    /// Master-password key epoch (ADR-002) of the exporting vault at the
    /// time of export. Required to unwrap an epoch-bound `wrapped_dek_blob`
    /// (produced after a rotation) — the wrap binds `key_epoch` as AEAD
    /// associated data, so importing without it fails GCM authentication.
    /// Defaults to 1 (the un-rotated epoch) so bootstraps produced by
    /// binaries that predate this field still deserialize.
    #[serde(default = "default_key_epoch")]
    pub key_epoch: i64,
}

fn default_key_epoch() -> i64 {
    1
}

/// Current sync status summary for the local device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncStatus {
    pub enabled: bool,
    pub device_id: Option<Uuid>,
    pub device_name: Option<String>,
    pub relay_url: Option<String>,
    pub last_sync_at: Option<i64>,
    pub pending_changes: u64,
}

/// Information about a registered sync device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncDeviceInfo {
    pub device_id: Uuid,
    pub device_name: String,
    pub device_type: String,
    pub public_key: Vec<u8>,
    pub registered_at: i64,
    pub last_sync: Option<i64>,
    pub revoked: bool,
    pub revoked_at: Option<i64>,
}

/// Request body for pushing local changes to the relay.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PushRequest {
    pub device_sequence: u64,
    pub entries: Vec<SyncEntryBlob>,
}

/// Relay response after a push operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PushResponse {
    pub accepted: u64,
    pub rejected: u64,
    pub server_sequence: u64,
}

/// Request body for pulling remote changes from the relay.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PullRequest {
    pub since_sequence: u64,
    pub limit: Option<u64>,
}

/// Relay response containing pulled entries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PullResponse {
    pub entries: Vec<SyncEntryBlob>,
    /// Pagination cursor: the last returned server sequence in this page.
    pub server_sequence: u64,
    pub has_more: bool,
}

/// Custom base64 serialization for `Vec<u8>`.
mod base64_bytes {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        STANDARD.decode(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sync_state_roundtrip() {
        for state in [SyncState::Synced, SyncState::Pending, SyncState::Conflict] {
            assert_eq!(SyncState::parse(state.as_str()), state);
        }
    }

    #[test]
    fn sync_entry_blob_serialization() {
        let blob = SyncEntryBlob {
            sync_id: Uuid::new_v4(),
            entry_type: SyncEntryType::Credential,
            sync_version: 1,
            modified_at: 1700000000,
            encrypted_payload: vec![1, 2, 3, 4, 5],
            is_tombstone: false,
            origin_device_id: Uuid::new_v4(),
        };

        let json = serde_json::to_string(&blob).unwrap();
        let deserialized: SyncEntryBlob = serde_json::from_str(&json).unwrap();

        assert_eq!(blob.sync_id, deserialized.sync_id);
        assert_eq!(blob.sync_version, deserialized.sync_version);
        assert_eq!(blob.encrypted_payload, deserialized.encrypted_payload);
    }

    #[test]
    fn credential_payload_serialization() {
        let payload = CredentialPayload {
            title: "Test".to_string(),
            username: "user".to_string(),
            password: "pass".to_string(),
            credential_type: CredentialType::Password,
            url: Some("https://example.com".to_string()),
            notes: None,
            favorite: false,
            domains: vec![DomainPayload {
                domain: "example.com".to_string(),
                is_primary: true,
            }],
            created_at: 1700000000,
            modified_at: 1700000000,
        };

        let json = serde_json::to_string(&payload).unwrap();
        let deserialized: CredentialPayload = serde_json::from_str(&json).unwrap();

        assert_eq!(payload.title, deserialized.title);
        assert_eq!(payload.domains.len(), deserialized.domains.len());
    }
}

#[cfg(test)]
mod wire_compat_tests {
    use super::*;
    use zeroize::Zeroizing;

    /// THE v0.8.x interop pin (gate review, finding 6): the exact JSON an
    /// actual v0.8.2 peer emits for an SSH key payload (old top-level
    /// field names, required values) MUST deserialize with the plaintext
    /// empty and the legacy triplet populated — deleting an alias or
    /// default breaks v0.8.x interop while the rest of the suite is green.
    #[test]
    fn v0_8_2_ssh_payload_deserializes_into_legacy_fields() {
        let json = br#"{"name":"deploy","comment":null,"key_type":"ed25519","key_size":null,"public_key":"ssh-ed25519 AAAA","private_key_encrypted":[1,2,3,4],"nonce":[9,9,9,9,9,9,9,9,9,9,9,9],"auth_tag":[8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8],"fingerprint":"SHA256:x","created_at":100,"modified_at":100}"#;
        let payload: SshKeyPayload =
            serde_json::from_slice(json).expect("v0.8.x wire shape must deserialize");
        assert!(
            payload.private_key.is_empty(),
            "plaintext defaults to empty"
        );
        let legacy = payload
            .private_key_encrypted
            .expect("legacy triplet populated");
        assert_eq!(legacy, vec![1, 2, 3, 4]);
        assert_eq!(payload.legacy_nonce.as_deref(), Some(&[9u8; 12][..]));
        assert_eq!(payload.legacy_auth_tag.as_deref(), Some(&[8u8; 16][..]));
    }

    #[test]
    fn v0_8_2_totp_payload_deserializes_into_legacy_fields() {
        let json = br#"{"secret_encrypted":[5,6,7],"nonce":[1,1,1,1,1,1,1,1,1,1,1,1],"auth_tag":[2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2],"algorithm":"SHA1","digits":6,"period":30,"issuer":"I","account_name":"a","created_at":1,"parent_credential_sync_id":null}"#;
        let payload: TotpPayload =
            serde_json::from_slice(json).expect("v0.8.x wire shape must deserialize");
        assert!(payload.secret.is_empty());
        assert_eq!(payload.secret_encrypted.as_deref(), Some(&[5u8, 6, 7][..]));
        assert_eq!(payload.legacy_nonce.as_deref(), Some(&[1u8; 12][..]));
    }

    /// New-shape payloads must NOT serialize the legacy fields empty
    /// (old peers require them) — the emitter populates them; this pins
    /// the field PRESENCE in emitted JSON (the old peer's serde has no
    /// defaults).
    #[test]
    fn emitted_ssh_payload_carries_legacy_fields_for_old_peers() {
        let payload = SshKeyPayload {
            name: "n".into(),
            comment: None,
            key_type: "ed25519".into(),
            key_size: None,
            public_key: "ssh-ed25519 AAAA".into(),
            private_key: Zeroizing::new("KEYMATERIAL".into()),
            private_key_encrypted: Some(vec![1, 2, 3]),
            legacy_nonce: Some(vec![0; 12]),
            legacy_auth_tag: Some(vec![0; 16]),
            fingerprint: "SHA256:x".into(),
            created_at: 1,
            modified_at: 2,
        };
        let json = serde_json::to_vec(&payload).unwrap();
        let text = String::from_utf8(json).unwrap();
        assert!(text.contains(r#""private_key":"KEYMATERIAL""#));
        assert!(text.contains(r#""private_key_encrypted":[1,2,3]"#));
        assert!(text.contains(r#""nonce":"#));
        assert!(text.contains(r#""auth_tag":"#));
        // And Debug never prints the key material.
        let dbg = format!("{:?}", payload);
        assert!(!dbg.contains("KEYMATERIAL"), "Debug must redact");
    }
}
