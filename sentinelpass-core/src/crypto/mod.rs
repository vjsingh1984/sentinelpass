//! Cryptographic primitives for the password manager.
//!
//! This module provides:
//! - Argon2id key derivation
//! - AES-256-GCM encryption/decryption
//! - Secure key management
//! - Zeroization utilities

pub mod kdf;
pub mod cipher;
pub mod keyring;
pub mod zero;

pub use kdf::{KdfParams, derive_master_key, verify_master_password};
pub use cipher::{EncryptedEntry, encrypt_entry, decrypt_entry, DataEncryptionKey};
pub use keyring::{MasterKey, WrappedKey, KeyHierarchy};
pub use zero::{SecureBuffer, zeroize_bytes};

use thiserror::Error;

/// Errors that can occur in cryptographic operations
#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Key derivation failed: {0}")]
    KdfFailed(String),

    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),

    #[error("Invalid key length: expected {expected}, got {got}")]
    InvalidKeyLength { expected: usize, got: usize },

    #[error("Invalid nonce: {0}")]
    InvalidNonce(String),

    #[error("Authentication failed - data may have been tampered with")]
    AuthenticationFailed,

    #[error("Random number generation failed: {0}")]
    RandomFailed(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// Result type for crypto operations
pub type Result<T> = std::result::Result<T, CryptoError>;
/// Alias for Result for backward compatibility
pub type CryptoResult<T> = Result<T>;
