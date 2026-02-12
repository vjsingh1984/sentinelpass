//! Password Manager Core Library
//!
//! This library provides the core functionality for the password manager,
//! including cryptographic operations, database management, and IPC.

pub mod crypto;
pub mod database;
pub mod daemon;
pub mod platform;
pub mod vault;

pub use crypto::{
    KdfParams, MasterKey, DataEncryptionKey, EncryptedEntry,
    KeyHierarchy, WrappedKey, CryptoError, CryptoResult,
    derive_master_key, verify_master_password,
    encrypt_entry, decrypt_entry,
};
pub use crypto::cipher::{encrypt_string, decrypt_to_string};
pub use platform::{
    get_data_dir, get_config_dir, get_default_vault_path, ensure_data_dir, ensure_config_dir,
    get_binary_name, get_platform, get_arch,
};
pub use vault::{VaultManager, Entry, EntrySummary};

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

    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}
