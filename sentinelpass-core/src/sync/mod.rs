//! E2E Encrypted Sync for SentinelPass
//!
//! Implements zero-knowledge device synchronization:
//! - Per-entry incremental sync with AES-256-GCM encryption
//! - Ed25519 device identity and request signing
//! - Last-write-wins conflict resolution
//! - Tombstone-based soft deletes
//! - Device pairing via 6-digit code + HKDF-derived key

pub mod auth;
pub mod change_tracker;
#[cfg(feature = "sync")]
pub mod client;
pub mod config;
pub mod conflict;
pub mod crypto;
pub mod device;
#[cfg(feature = "sync")]
pub mod engine;
pub mod models;
pub mod pairing;

pub use config::SyncConfig;
pub use conflict::ConflictResolver;
pub use models::{SyncEntryBlob, SyncEntryType, SyncStatus};
