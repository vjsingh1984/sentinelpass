use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

/// Password Manager CLI - A secure, local-first password manager
#[derive(Parser)]
#[command(name = "pm-cli")]
#[command(about = "Secure, local-first password manager", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a new password vault
    Init {
        /// Enable development mode (in-memory database)
        #[arg(long)]
        dev: bool,
    },

    /// Unlock the vault
    Unlock,

    /// Lock the vault
    Lock,

    /// Add a new credential entry
    Add {
        /// Title for the entry
        #[arg(long)]
        title: String,

        /// Username
        #[arg(long)]
        username: String,

        /// Password (will prompt if not provided)
        #[arg(long)]
        password: Option<String>,

        /// URL
        #[arg(long)]
        url: Option<String>,

        /// Notes
        #[arg(long)]
        notes: Option<String>,
    },

    /// List all entries
    List {
        /// Show passwords in plain text
        #[arg(long)]
        show_passwords: bool,
    },

    /// Get a specific entry
    Get {
        /// Entry ID
        id: i64,
    },

    /// Search entries
    Search {
        /// Search query
        query: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();

    tracing::subscriber::set_global_default(subscriber)
        .expect("setting default subscriber failed");

    let cli = Cli::parse();

    match cli.command {
        Commands::Init { dev } => {
            info!("Initializing new vault...");
            if dev {
                info!("Running in development mode (in-memory database)");
            }
            // TODO: Implement vault initialization
            println!("Vault initialization will be implemented in Phase 2");
        }
        Commands::Unlock => {
            info!("Unlocking vault...");
            // TODO: Implement vault unlock
            println!("Vault unlock will be implemented in Phase 2");
        }
        Commands::Lock => {
            info!("Locking vault...");
            // TODO: Implement vault lock
            println!("Vault lock will be implemented in Phase 2");
        }
        Commands::Add { title, username, password, url, notes } => {
            info!("Adding entry: {}", title);
            // TODO: Implement entry addition
            println!("Entry addition will be implemented in Phase 2");
        }
        Commands::List { show_passwords } => {
            info!("Listing entries...");
            // TODO: Implement entry listing
            println!("Entry listing will be implemented in Phase 2");
        }
        Commands::Get { id } => {
            info!("Getting entry: {}", id);
            // TODO: Implement entry retrieval
            println!("Entry retrieval will be implemented in Phase 2");
        }
        Commands::Search { query } => {
            info!("Searching entries: {}", query);
            // TODO: Implement entry search
            println!("Entry search will be implemented in Phase 2");
        }
    }

    Ok(())
}
