use anyhow::Result;
use std::io::{self, Write};
use tracing::{error, info, warn, Level};
use tracing_subscriber::FmtSubscriber;

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();

    tracing::subscriber::set_global_default(subscriber)
        .expect("setting default subscriber failed");

    info!("Starting Password Manager Daemon v{}", VERSION);

    // TODO: Implement daemon functionality
    // - Load vault
    // - Start IPC server
    // - Handle native messaging requests
    // - Implement auto-lock timer

    warn!("Daemon functionality will be implemented in Phase 3");

    // For now, keep the process running
    println!("Password Manager Daemon is running. Press Ctrl+C to exit.");

    // Simple keep-alive loop
    tokio::signal::ctrl_c().await?;
    info!("Received shutdown signal");

    Ok(())
}
