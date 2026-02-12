use anyhow::Result;
use rpassword::prompt_password;
use sentinelpass_core::daemon::DaemonVault;
use std::path::PathBuf;
use tokio::signal;
use tracing::{info, error, Level};
use tracing_subscriber::FmtSubscriber;
use zeroize::Zeroize;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const DEFAULT_INACTIVITY_TIMEOUT: u64 = 300; // 5 minutes

struct GlobalVault {
    vault: DaemonVault,
    _master_password: Vec<u8>, // Stored for potential re-unlock, zeroized on drop
}

impl Drop for GlobalVault {
    fn drop(&mut self) {
        self._master_password.zeroize();
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();

    tracing::subscriber::set_global_default(subscriber)
        .expect("setting default subscriber failed");

    info!("Starting SentinelPass Daemon v{}", VERSION);

    // Check if vault exists
    let vault_path = sentinelpass_core::get_default_vault_path();
    if !vault_path.exists() {
        error!("No vault found at {:?}. Please create one with: sentinelpass init", vault_path);
        return Ok(());
    }

    // Prompt for master password to unlock vault
    let master_password = prompt_password("Enter master password to unlock vault: ")?;
    let master_password_bytes = master_password.as_bytes().to_vec();

    // Create DaemonVault
    let vault = DaemonVault::new(Some(vault_path.clone()), DEFAULT_INACTIVITY_TIMEOUT)?;

    // Unlock the vault
    vault.unlock(&master_password_bytes).await
        .map_err(|e| anyhow::anyhow!("Failed to unlock vault: {}", e))?;

    info!("Vault unlocked successfully");

    // Store vault state globally for IPC access
    let global_vault = GlobalVault {
        vault,
        _master_password: master_password_bytes,
    };

    info!("Daemon ready. Press Ctrl+C to exit.");
    info!("Auto-lock enabled after {} seconds of inactivity", DEFAULT_INACTIVITY_TIMEOUT);

    // TODO: Start IPC server here to communicate with native messaging host
    // The native messaging host (pm-host) will communicate with this daemon
    // to get credentials for autofill

    // Wait for shutdown signal
    signal::ctrl_c().await?;
    info!("Received shutdown signal");

    // Lock vault before exiting
    info!("Locking vault...");
    global_vault.vault.lock().await;

    // Vault and master_password are dropped here, which zeros the password

    Ok(())
}
