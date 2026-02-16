//! Background cleanup tasks: prune nonces, tombstones, expired pairings.

use crate::storage::RelayStorage;
use std::time::Duration;
use tokio::time;

#[allow(dead_code)]
pub fn spawn_cleanup_task(storage: RelayStorage, tombstone_retention_days: u64) {
    tokio::spawn(async move {
        let mut interval = time::interval(Duration::from_secs(3600)); // hourly
        loop {
            interval.tick().await;
            if let Err(e) = run_cleanup(&storage, tombstone_retention_days) {
                tracing::error!("Cleanup error: {}", e);
            }
        }
    });
}

fn run_cleanup(storage: &RelayStorage, tombstone_retention_days: u64) -> Result<(), String> {
    let conn = storage.conn().map_err(|e| e.to_string())?;
    let now = chrono::Utc::now().timestamp();

    // Prune nonces older than 10 minutes
    let nonce_cutoff = now - 600;
    conn.execute("DELETE FROM seen_nonces WHERE seen_at < ?1", [nonce_cutoff])
        .map_err(|e| e.to_string())?;

    // Prune expired pairing bootstraps
    conn.execute(
        "DELETE FROM pairing_bootstraps WHERE expires_at < ?1 OR consumed = 1",
        [now],
    )
    .map_err(|e| e.to_string())?;

    // Prune old tombstones
    let tombstone_cutoff = now - (tombstone_retention_days as i64 * 86400);
    conn.execute(
        "DELETE FROM sync_entries WHERE is_tombstone = 1 AND received_at < ?1",
        [tombstone_cutoff],
    )
    .map_err(|e| e.to_string())?;

    tracing::debug!("Cleanup completed");
    Ok(())
}
