//! SentinelPass Relay Server
//!
//! A self-hostable relay for E2E encrypted vault sync. The relay stores
//! only opaque ciphertexts and device public keys -- it never possesses
//! encryption keys or plaintext data.

mod auth;
mod cleanup;
mod config;
mod error;
mod handlers;
mod rate_limit;
mod server;
mod storage;

use clap::Parser;
use std::path::PathBuf;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "sentinelpass-relay", about = "SentinelPass sync relay server")]
struct Cli {
    /// Path to configuration file
    #[arg(short, long, default_value = "relay.toml")]
    config: PathBuf,

    /// Listen address override
    #[arg(short, long)]
    listen: Option<String>,

    /// Database path override
    #[arg(short, long)]
    database: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("info".parse()?))
        .init();

    let cli = Cli::parse();

    let mut cfg = if cli.config.exists() {
        config::RelayConfig::load(&cli.config)?
    } else {
        tracing::info!("No config file found, using defaults");
        config::RelayConfig::default()
    };

    if let Some(listen) = cli.listen {
        cfg.listen_addr = listen;
    }
    if let Some(database) = cli.database {
        cfg.storage_path = database;
    }

    tracing::info!("Starting SentinelPass relay on {}", cfg.listen_addr);

    let state = storage::RelayStorage::open(&cfg.storage_path)?;
    let app = server::build_router(state, &cfg);

    let listener = tokio::net::TcpListener::bind(&cfg.listen_addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
