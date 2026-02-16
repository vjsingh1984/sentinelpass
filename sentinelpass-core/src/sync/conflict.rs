//! Last-Write-Wins conflict resolution.

use crate::sync::models::SyncEntryBlob;

/// Conflict resolution outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resolution {
    /// Accept the remote entry (remote is newer).
    AcceptRemote,
    /// Keep the local entry (local is newer or equal).
    KeepLocal,
}

pub struct ConflictResolver;

impl ConflictResolver {
    /// Resolve a conflict between local and remote versions of an entry.
    ///
    /// LWW rules:
    /// 1. Higher `sync_version` wins.
    /// 2. If versions are equal, higher `modified_at` wins.
    /// 3. If both are equal, keep local (local-preference tie-break).
    pub fn resolve(
        local_sync_version: u64,
        local_modified_at: i64,
        remote: &SyncEntryBlob,
    ) -> Resolution {
        if remote.sync_version > local_sync_version {
            Resolution::AcceptRemote
        } else if remote.sync_version == local_sync_version {
            if remote.modified_at > local_modified_at {
                Resolution::AcceptRemote
            } else {
                Resolution::KeepLocal
            }
        } else {
            Resolution::KeepLocal
        }
    }

    /// Check if an incoming entry should be accepted when there is no local copy.
    pub fn accept_new(remote: &SyncEntryBlob) -> bool {
        // Always accept entries we don't have locally, unless
        // sync_version is 0 (shouldn't happen, but guard).
        remote.sync_version > 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn make_blob(sync_version: u64, modified_at: i64) -> SyncEntryBlob {
        SyncEntryBlob {
            sync_id: Uuid::new_v4(),
            entry_type: crate::sync::models::SyncEntryType::Credential,
            sync_version,
            modified_at,
            encrypted_payload: vec![0u8; 29],
            is_tombstone: false,
            origin_device_id: Uuid::new_v4(),
        }
    }

    #[test]
    fn higher_version_wins() {
        let remote = make_blob(3, 1000);
        assert_eq!(
            ConflictResolver::resolve(2, 2000, &remote),
            Resolution::AcceptRemote
        );
    }

    #[test]
    fn lower_version_loses() {
        let remote = make_blob(1, 2000);
        assert_eq!(
            ConflictResolver::resolve(2, 1000, &remote),
            Resolution::KeepLocal
        );
    }

    #[test]
    fn same_version_newer_timestamp_wins() {
        let remote = make_blob(2, 2000);
        assert_eq!(
            ConflictResolver::resolve(2, 1000, &remote),
            Resolution::AcceptRemote
        );
    }

    #[test]
    fn same_version_same_timestamp_keeps_local() {
        let remote = make_blob(2, 1000);
        assert_eq!(
            ConflictResolver::resolve(2, 1000, &remote),
            Resolution::KeepLocal
        );
    }

    #[test]
    fn accept_new_with_valid_version() {
        let remote = make_blob(1, 1000);
        assert!(ConflictResolver::accept_new(&remote));
    }

    #[test]
    fn reject_new_with_zero_version() {
        let remote = make_blob(0, 1000);
        assert!(!ConflictResolver::accept_new(&remote));
    }

    // --- Security: rollback attack prevention ---

    #[test]
    fn rollback_to_older_version_rejected() {
        // Attacker tries to push an older version to rollback an entry
        let rollback = make_blob(1, 5000); // old version, even with newer timestamp
        assert_eq!(
            ConflictResolver::resolve(3, 1000, &rollback),
            Resolution::KeepLocal
        );
    }

    #[test]
    fn rollback_same_version_older_timestamp_rejected() {
        // Same version but older timestamp is rejected (keeps local)
        let rollback = make_blob(2, 500);
        assert_eq!(
            ConflictResolver::resolve(2, 1000, &rollback),
            Resolution::KeepLocal
        );
    }

    #[test]
    fn tombstone_with_lower_version_rejected() {
        // Attacker tries to delete an entry by sending a tombstone with old version
        let mut tombstone = make_blob(1, 5000);
        tombstone.is_tombstone = true;
        assert_eq!(
            ConflictResolver::resolve(3, 1000, &tombstone),
            Resolution::KeepLocal
        );
    }

    #[test]
    fn tombstone_with_higher_version_accepted() {
        // Legitimate deletion: tombstone with higher version
        let mut tombstone = make_blob(4, 2000);
        tombstone.is_tombstone = true;
        assert_eq!(
            ConflictResolver::resolve(3, 1000, &tombstone),
            Resolution::AcceptRemote
        );
    }
}
