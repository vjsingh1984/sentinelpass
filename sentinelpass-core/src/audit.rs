//! Audit logging for security events and operations

use crate::{DatabaseError, PasswordManagerError, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tracing::info;

/// Audit log entry types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditEventType {
    /// Vault operations
    VaultCreated,
    VaultUnlocked {
        success: bool,
    },
    VaultLocked,

    /// Credential operations
    CredentialCreated {
        entry_id: i64,
    },
    CredentialViewed {
        entry_id: i64,
    },
    CredentialModified {
        entry_id: i64,
    },
    CredentialDeleted {
        entry_id: i64,
    },
    CredentialsListed {
        count: usize,
    },

    /// Authentication events
    AuthenticationAttempt {
        success: bool,
    },
    AuthenticationFailure {
        reason: String,
    },

    /// Security events
    BruteForceDetected {
        ip_address: Option<String>,
    },
    VaultAutoLocked,
    VaultLockedManually,

    /// Import/Export
    DataExported {
        format: String,
    },
    DataImported {
        format: String,
        count: usize,
    },

    /// System events
    DaemonStarted,
    DaemonStopped,
    IpcServerStarted,
    IpcClientConnected,
}

/// Audit log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Timestamp of the event
    pub timestamp: DateTime<Utc>,
    /// Event type
    pub event_type: AuditEventType,
    /// Event severity (0-5, where 5 is most critical)
    pub severity: u8,
    /// Additional context data
    pub context: String,
    /// Process ID (if applicable)
    pub pid: Option<u32>,
    /// Thread ID (if applicable)
    pub tid: Option<u64>,
}

/// Audit logger
pub struct AuditLogger {
    log_file: PathBuf,
    writer: Arc<Mutex<Option<File>>>,
}

impl AuditLogger {
    /// Create a new audit logger
    pub fn new(log_dir: PathBuf) -> Result<Self> {
        let log_file = log_dir.join("audit.log");

        // Ensure log directory exists
        std::fs::create_dir_all(&log_dir).map_err(|e| {
            PasswordManagerError::from(DatabaseError::FileIo(format!(
                "Failed to create audit log directory: {}",
                e
            )))
        })?;

        // Open log file in append mode
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_file)
            .map_err(|e| {
                PasswordManagerError::from(DatabaseError::FileIo(format!(
                    "Failed to open audit log: {}",
                    e
                )))
            })?;

        info!("Audit logger initialized: {:?}", log_file);

        Ok(Self {
            log_file,
            writer: Arc::new(Mutex::new(Some(file))),
        })
    }

    /// Log an audit event
    pub fn log(&self, event_type: AuditEventType, context: &str) -> Result<()> {
        let severity = Self::severity_for_event(&event_type);

        let entry = AuditEntry {
            timestamp: Utc::now(),
            event_type,
            severity,
            context: context.to_string(),
            pid: std::env::var("PID").ok().and_then(|p| p.parse().ok()),
            tid: None, // ThreadId cannot be converted to u64, using None
        };

        let json = serde_json::to_string(&entry).map_err(|e| {
            PasswordManagerError::from(DatabaseError::Serialization(format!(
                "Failed to serialize audit entry: {}",
                e
            )))
        })?;

        let log_line = format!("{}\n", json);

        if let Some(ref mut writer) = *self.writer.lock().map_err(|_| {
            PasswordManagerError::from(DatabaseError::LockPoisoned(
                "Failed to lock audit writer".to_string(),
            ))
        })? {
            writer.write_all(log_line.as_bytes()).map_err(|e| {
                PasswordManagerError::from(DatabaseError::FileIo(format!(
                    "Failed to write audit log: {}",
                    e
                )))
            })?;
            writer.flush().map_err(|e| {
                PasswordManagerError::from(DatabaseError::FileIo(format!(
                    "Failed to flush audit log: {}",
                    e
                )))
            })?;
        }

        Ok(())
    }

    /// Get severity level for an event type (0-5)
    fn severity_for_event(event: &AuditEventType) -> u8 {
        match event {
            // Critical events (5)
            AuditEventType::VaultCreated | AuditEventType::DataExported { .. } => 5,

            // High severity (4)
            AuditEventType::CredentialDeleted { .. }
            | AuditEventType::BruteForceDetected { .. } => 4,

            // Medium-high severity (3)
            AuditEventType::VaultUnlocked { success: true }
            | AuditEventType::CredentialModified { .. } => 3,

            // Medium severity (2)
            AuditEventType::VaultLocked
            | AuditEventType::CredentialCreated { .. }
            | AuditEventType::CredentialViewed { .. }
            | AuditEventType::VaultAutoLocked => 2,

            // Low severity (1)
            AuditEventType::CredentialsListed { .. } | AuditEventType::DataImported { .. } => 1,

            // Info (0)
            AuditEventType::AuthenticationAttempt { .. }
            | AuditEventType::VaultLockedManually
            | AuditEventType::AuthenticationFailure { .. }
            | AuditEventType::VaultUnlocked { success: false }
            | AuditEventType::DaemonStarted
            | AuditEventType::DaemonStopped
            | AuditEventType::IpcServerStarted
            | AuditEventType::IpcClientConnected => 0,
        }
    }

    /// Get all audit entries
    pub fn get_entries(&self, limit: usize) -> Result<Vec<AuditEntry>> {
        let content = std::fs::read_to_string(&self.log_file).map_err(|e| {
            PasswordManagerError::from(DatabaseError::FileIo(format!(
                "Failed to read audit log: {}",
                e
            )))
        })?;

        let entries: Vec<AuditEntry> = content
            .lines()
            .filter(|line| !line.trim().is_empty())
            .filter_map(|line| serde_json::from_str::<AuditEntry>(line).ok())
            .rev()
            .take(limit)
            .collect();

        Ok(entries)
    }

    /// Get audit entries since a specific timestamp
    pub fn get_entries_since(&self, since: DateTime<Utc>) -> Result<Vec<AuditEntry>> {
        let content = std::fs::read_to_string(&self.log_file).map_err(|e| {
            PasswordManagerError::from(DatabaseError::FileIo(format!(
                "Failed to read audit log: {}",
                e
            )))
        })?;

        let entries: Vec<AuditEntry> = content
            .lines()
            .filter(|line| !line.trim().is_empty())
            .filter_map(|line| serde_json::from_str::<AuditEntry>(line).ok())
            .filter(|entry| entry.timestamp > since)
            .collect();

        Ok(entries)
    }

    /// Get audit entries by severity level
    pub fn get_entries_by_severity(&self, min_severity: u8) -> Result<Vec<AuditEntry>> {
        let content = std::fs::read_to_string(&self.log_file).map_err(|e| {
            PasswordManagerError::from(DatabaseError::FileIo(format!(
                "Failed to read audit log: {}",
                e
            )))
        })?;

        let entries: Vec<AuditEntry> = content
            .lines()
            .filter(|line| !line.trim().is_empty())
            .filter_map(|line| serde_json::from_str::<AuditEntry>(line).ok())
            .filter(|entry| entry.severity >= min_severity)
            .collect();

        Ok(entries)
    }
}

/// Get the default audit log directory
pub fn get_audit_log_dir() -> PathBuf {
    crate::get_config_dir().join("audit")
}

/// Get the default audit log file path
pub fn get_audit_log_path() -> PathBuf {
    get_audit_log_dir().join("audit.log")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_levels() {
        assert_eq!(
            AuditLogger::severity_for_event(&AuditEventType::BruteForceDetected {
                ip_address: None
            }),
            4
        );
        assert_eq!(
            AuditLogger::severity_for_event(&AuditEventType::VaultUnlocked { success: true }),
            3
        );
        assert_eq!(
            AuditLogger::severity_for_event(&AuditEventType::IpcClientConnected),
            0
        );
    }
}
