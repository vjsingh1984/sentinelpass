// Error types for the mobile bridge

use std::fmt;
use thiserror::Error;

/// Error codes that can be returned to mobile platforms
///
/// These are designed to be stable across FFI boundaries and map to
/// platform-specific error types (NSError on iOS, Exception on Android).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorCode {
    /// Operation completed successfully
    Success = 0,

    /// Invalid parameter passed to function
    InvalidParam = -1,

    /// Vault is currently locked
    VaultLocked = -2,

    /// Entry not found
    NotFound = -3,

    /// Cryptographic operation failed
    Crypto = -4,

    /// Database operation failed
    Database = -5,

    /// Input/Output operation failed
    Io = -6,

    /// Vault is already unlocked
    AlreadyUnlocked = -7,

    /// Invalid master password
    InvalidPassword = -8,

    /// Vault not initialized (run init first)
    NotInitialized = -9,

    /// Biometric operation failed
    Biometric = -10,

    /// TOTP operation failed
    Totp = -11,

    /// Sync operation failed
    Sync = -12,

    /// Out of memory
    OutOfMemory = -13,

    /// Unknown or internal error
    Unknown = -99,
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorCode::Success => write!(f, "Success"),
            ErrorCode::InvalidParam => write!(f, "Invalid parameter"),
            ErrorCode::VaultLocked => write!(f, "Vault is locked"),
            ErrorCode::NotFound => write!(f, "Entry not found"),
            ErrorCode::Crypto => write!(f, "Cryptographic operation failed"),
            ErrorCode::Database => write!(f, "Database operation failed"),
            ErrorCode::Io => write!(f, "I/O operation failed"),
            ErrorCode::AlreadyUnlocked => write!(f, "Vault is already unlocked"),
            ErrorCode::InvalidPassword => write!(f, "Invalid master password"),
            ErrorCode::NotInitialized => write!(f, "Vault not initialized"),
            ErrorCode::Biometric => write!(f, "Biometric operation failed"),
            ErrorCode::Totp => write!(f, "TOTP operation failed"),
            ErrorCode::Sync => write!(f, "Sync operation failed"),
            ErrorCode::OutOfMemory => write!(f, "Out of memory"),
            ErrorCode::Unknown => write!(f, "Unknown error"),
        }
    }
}

impl std::error::Error for ErrorCode {}

/// Bridge-specific error type
#[derive(Debug, Error)]
pub enum BridgeError {
    #[error("Invalid parameter: {0}")]
    InvalidParam(String),

    #[error("Vault error: {0}")]
    Vault(#[from] sentinelpass_core::vault::VaultError),

    #[error("PasswordManager error: {0}")]
    PasswordManager(#[from] sentinelpass_core::PasswordManagerError),

    #[error("Crypto error: {0}")]
    Crypto(#[from] sentinelpass_core::crypto::CryptoError),

    #[error("Database error: {0}")]
    Database(#[from] sentinelpass_core::database::DatabaseError),

    #[error("TOTP error: {0}")]
    Totp(#[from] sentinelpass_core::totp::TotpError),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("UTF-8 error: {0}")]
    Utf8(#[from] std::str::Utf8Error),

    #[error("NUL byte in string")]
    NulError(#[from] std::ffi::NulError),

    #[error("Biometric error: {0}")]
    Biometric(String),

    #[error("Sync error: {0}")]
    Sync(String),

    #[error("Not initialized")]
    NotInitialized,

    #[error("Unknown error: {0}")]
    Unknown(String),
}

impl BridgeError {
    /// Convert to ErrorCode for FFI return
    pub fn to_error_code(&self) -> ErrorCode {
        match self {
            BridgeError::InvalidParam(_) => ErrorCode::InvalidParam,
            BridgeError::Vault(e) => match e {
                sentinelpass_core::vault::VaultError::Locked => ErrorCode::VaultLocked,
                sentinelpass_core::vault::VaultError::InvalidPassword => ErrorCode::InvalidPassword,
                sentinelpass_core::vault::VaultError::AlreadyUnlocked => ErrorCode::AlreadyUnlocked,
                sentinelpass_core::vault::VaultError::NotInitialized => ErrorCode::NotInitialized,
                _ => ErrorCode::Unknown,
            },
            BridgeError::PasswordManager(e) => match e {
                sentinelpass_core::PasswordManagerError::VaultLocked => ErrorCode::VaultLocked,
                sentinelpass_core::PasswordManagerError::NotFound(_) => ErrorCode::NotFound,
                sentinelpass_core::PasswordManagerError::InvalidInput(_) => ErrorCode::InvalidParam,
                sentinelpass_core::PasswordManagerError::LockedOut(_) => ErrorCode::VaultLocked,
                _ => ErrorCode::Unknown,
            },
            BridgeError::Crypto(_) => ErrorCode::Crypto,
            BridgeError::Database(_) => ErrorCode::Database,
            BridgeError::Totp(_) => ErrorCode::Totp,
            BridgeError::Io(_) => ErrorCode::Io,
            BridgeError::Biometric(_) => ErrorCode::Biometric,
            BridgeError::Sync(_) => ErrorCode::Sync,
            BridgeError::NotInitialized => ErrorCode::NotInitialized,
            _ => ErrorCode::Unknown,
        }
    }
}

/// Result type alias for bridge operations
pub type BridgeResult<T> = Result<T, BridgeError>;
