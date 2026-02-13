use anyhow::Result;
use rpassword::prompt_password;
use sentinelpass_core::daemon::{DaemonVault, IpcServer, default_ipc_socket_path};
use std::sync::Arc;
use tokio::signal;
use tracing::{info, error, Level};
use tracing_subscriber::FmtSubscriber;
use zeroize::Zeroize;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const DEFAULT_INACTIVITY_TIMEOUT: u64 = 300; // 5 minutes

struct GlobalVault {
    vault: Arc<DaemonVault>,
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

    // Wrap vault in Arc for sharing with IPC server
    let vault_arc = Arc::new(vault);

    // Store vault state globally for IPC access
    let global_vault = GlobalVault {
        vault: vault_arc.clone(),
        _master_password: master_password_bytes,
    };

    // Start IPC server
    let ipc_socket_path = default_ipc_socket_path();
    let ipc_server = IpcServer::new(ipc_socket_path.clone(), vault_arc);

    // Spawn IPC server in background
    let ipc_handle = tokio::spawn(async move {
        info!("IPC server starting at {:?}", ipc_socket_path);
        if let Err(e) = ipc_server.run().await {
            error!("IPC server error: {}", e);
        }
    });

    info!("Daemon ready. Press Ctrl+C to exit.");
    info!("Auto-lock enabled after {} seconds of inactivity", DEFAULT_INACTIVITY_TIMEOUT);

    // Wait for shutdown signal
    signal::ctrl_c().await?;
    info!("Received shutdown signal");

    // Abort IPC server task
    ipc_handle.abort();

    // Lock vault before exiting
    info!("Locking vault...");
    global_vault.vault.lock().await;

    // Vault and master_password are dropped here, which zeros the password

    Ok(())
}
