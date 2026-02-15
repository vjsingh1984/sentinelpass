//! Password Manager Core Library
//!
//! This library provides the core functionality for the password manager,
//! including cryptographic operations, database management, and IPC.

pub mod audit;
pub mod biometric;
pub mod crypto;
pub mod daemon;
pub mod database;
pub mod import_export;
pub mod lockout;
pub mod platform;
pub mod ssh;
pub mod totp;
pub mod vault;

pub use audit::{get_audit_log_dir, get_audit_log_path, AuditEntry, AuditEventType, AuditLogger};
pub use biometric::{BiometricManager, BiometricResult};
pub use crypto::cipher::{decrypt_to_string, encrypt_string};
pub use crypto::{
    decrypt_entry, derive_master_key, encrypt_entry, verify_master_password, CryptoError,
    CryptoResult, DataEncryptionKey, EncryptedEntry, KdfParams, KeyHierarchy, MasterKey,
    WrappedKey,
};
pub use import_export::{
    export_to_csv, export_to_json, import_from_csv, import_from_json, ExportEntry,
};
pub use lockout::{LockoutConfig, LockoutManager, DEFAULT_MAX_ATTEMPTS};
pub use platform::{
    ensure_config_dir, ensure_data_dir, get_arch, get_binary_name, get_config_dir, get_data_dir,
    get_default_vault_path, get_platform,
};
pub use ssh::{SshAgentClient, SshKey, SshKeyGenerator, SshKeyImporter, SshKeySummary, SshKeyType};
pub use totp::{parse_otpauth_uri, ParsedTotpUri, TotpAlgorithm, TotpCode, TotpSecretMetadata};
pub use vault::{Entry, EntrySummary, VaultManager};

// Re-export common types
use thiserror::Error;

/// Result type for password manager operations
pub type Result<T> = std::result::Result<T, PasswordManagerError>;

/// General error type for password manager operations
#[derive(Error, Debug)]
pub enum PasswordManagerError {
    #[error("Crypto error: {0}")]
    Crypto(#[from] crypto::CryptoError),

    #[error("Database error: {0}")]
    Database(String),

    #[error("Vault is locked")]
    VaultLocked,

    #[error("Vault is locked out due to too many failed attempts. Try again in {0} seconds")]
    LockedOut(i64),

    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}
