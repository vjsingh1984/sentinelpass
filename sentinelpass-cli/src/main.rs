use anyhow::Result;
use clap::{Parser, Subcommand};
use rpassword::prompt_password;
use sentinelpass_core::{VaultManager, Entry as VaultEntry, EntrySummary};
use std::path::PathBuf;
use tracing::{Level, error};
use tracing_subscriber::FmtSubscriber;

/// SentinelPass CLI - A secure, local-first password manager
#[derive(Parser)]
#[command(name = "sentinelpass")]
#[command(author = "VJ Singh <singhvjd@gmail.com>")]
#[command(version = "0.1.0")]
#[command(about = "Secure, local-first password manager with browser autofill", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Custom vault path (overrides default)
    #[arg(short, long, global = true)]
    vault: Option<PathBuf>,
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

        /// Mark as favorite
        #[arg(long)]
        favorite: bool,
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

    /// Delete an entry
    Delete {
        /// Entry ID
        id: i64,

        /// Skip confirmation
        #[arg(long)]
        force: bool,
    },
}

fn get_vault_path(cli: &Cli, dev: bool) -> PathBuf {
    if let Some(ref path) = cli.vault {
        path.clone()
    } else if dev {
        PathBuf::from(":memory:")
    } else {
        sentinelpass_core::get_default_vault_path()
    }
}

fn prompt_master_password(confirm: bool) -> Result<String> {
    let password = prompt_password("Enter master password: ")?;
    if confirm {
        let confirm_password = prompt_password("Confirm master password: ")?;
        if password != confirm_password {
            anyhow::bail!("Passwords do not match");
        }
    }
    Ok(password)
}

fn main() -> Result<()> {
    // Initialize logging
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::WARN)  // Reduce noise in CLI
        .finish();

    tracing::subscriber::set_global_default(subscriber)
        .expect("setting default subscriber failed");

    let cli = Cli::parse();

    match cli.command {
        Commands::Init { dev } => {
            println!("Initializing new SentinelPass vault...");
            if dev {
                println!("Running in development mode (in-memory database)");
            }

            let vault_path = get_vault_path(&cli, dev);

            // Check if vault already exists
            if !dev && vault_path.exists() {
                anyhow::bail!("Vault already exists at: {:?}", vault_path);
            }

            let password = prompt_master_password(true)?;

            // Create vault
            let vault = VaultManager::create(&vault_path, password.as_bytes())
                .map_err(|e| anyhow::anyhow!("Failed to create vault: {}", e))?;

            println!("✓ Vault created successfully at: {:?}", vault_path);
            println!("✓ Your vault is now unlocked and ready to use");
            println!();
            println!("Next steps:");
            println!("  sentinelpass add --title 'GitHub' --username 'user@example.com'");
            println!("  sentinelpass list");

            // Vault is dropped here, which locks it
            drop(vault);
        }

        Commands::Unlock => {
            let vault_path = get_vault_path(&cli, false);

            if !vault_path.exists() {
                anyhow::bail!("No vault found at: {:?}\nUse 'sentinelpass init' to create a new vault", vault_path);
            }

            let password = prompt_password("Enter master password: ")?;

            match VaultManager::open(&vault_path, password.as_bytes()) {
                Ok(vault) => {
                    println!("✓ Vault unlocked successfully");
                    drop(vault);
                }
                Err(e) => {
                    error!("Failed to unlock vault: {}", e);
                    anyhow::bail!("Incorrect password or corrupted vault");
                }
            }
        }

        Commands::Lock => {
            println!("Vault locks automatically when the process exits.");
            println!("The vault is only kept in memory during operations.");
        }

        Commands::Add { ref title, ref username, ref password, ref url, ref notes, favorite } => {
            let vault_path = get_vault_path(&cli, false);

            if !vault_path.exists() {
                anyhow::bail!("No vault found. Use 'sentinelpass init' to create a new vault");
            }

            let password_str = match password {
                Some(p) => p.to_string(),
                None => prompt_password("Enter password for entry: ")?,
            };

            let master_password = prompt_password("Enter master password to unlock vault: ")?;

            let vault = VaultManager::open(&vault_path, master_password.as_bytes())
                .map_err(|e| anyhow::anyhow!("Failed to unlock vault: {}", e))?;

            let entry = VaultEntry {
                entry_id: None,
                title: title.to_string(),
                username: username.to_string(),
                password: password_str,
                url: url.clone(),
                notes: notes.clone(),
                created_at: chrono::Utc::now(),
                modified_at: chrono::Utc::now(),
                favorite,
            };

            match vault.add_entry(&entry) {
                Ok(entry_id) => {
                    println!("✓ Entry created with ID: {}", entry_id);
                }
                Err(e) => {
                    error!("Failed to add entry: {}", e);
                    anyhow::bail!("Failed to add entry: {}", e);
                }
            }
        }

        Commands::List { show_passwords } => {
            let vault_path = get_vault_path(&cli, false);

            if !vault_path.exists() {
                anyhow::bail!("No vault found. Use 'sentinelpass init' to create a new vault");
            }

            let master_password = prompt_password("Enter master password: ")?;

            let vault = VaultManager::open(&vault_path, master_password.as_bytes())
                .map_err(|e| anyhow::anyhow!("Failed to unlock vault: {}", e))?;

            match vault.list_entries() {
                Ok(entries) => {
                    if entries.is_empty() {
                        println!("No entries found. Add one with 'sentinelpass add'");
                    } else {
                        println!();
                        println!("{:<5} {:<30} {:<30} {}", "ID", "Title", "Username", "Fav");
                        println!("{}", "-".repeat(80));
                        for entry in &entries {
                            let fav = if entry.favorite { "⭐" } else { "" };
                            println!("{:<5} {:<30} {:<30} {}", entry.entry_id, entry.title, entry.username, fav);
                        }
                        println!();
                        println!("Total: {} entries", entries.len());

                        if show_passwords {
                            println!();
                            println!("WARNING: Showing passwords (be careful of shoulder surfing!)");
                            println!();
                            for summary in &entries {
                                match vault.get_entry(summary.entry_id) {
                                    Ok(entry) => {
                                        println!("--- ID {} ---", summary.entry_id);
                                        println!("Password: {}", entry.password);
                                    }
                                    Err(_) => {}
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    error!("Failed to list entries: {}", e);
                    anyhow::bail!("Failed to list entries: {}", e);
                }
            }
        }

        Commands::Get { id } => {
            let vault_path = get_vault_path(&cli, false);

            if !vault_path.exists() {
                anyhow::bail!("No vault found. Use 'sentinelpass init' to create a new vault");
            }

            let master_password = prompt_password("Enter master password: ")?;

            let vault = VaultManager::open(&vault_path, master_password.as_bytes())
                .map_err(|e| anyhow::anyhow!("Failed to unlock vault: {}", e))?;

            match vault.get_entry(id) {
                Ok(entry) => {
                    println!();
                    println!("Title: {}", entry.title);
                    println!("Username: {}", entry.username);
                    println!("Password: {}", entry.password);
                    if let Some(url) = entry.url {
                        println!("URL: {}", url);
                    }
                    if let Some(notes) = entry.notes {
                        println!("Notes: {}", notes);
                    }
                    println!("Created: {}", entry.created_at.format("%Y-%m-%d %H:%M:%S UTC"));
                    if entry.favorite {
                        println!("⭐ Favorite");
                    }
                    println!();
                }
                Err(e) => {
                    error!("Failed to get entry: {}", e);
                    anyhow::bail!("Entry {} not found. Use 'sentinelpass list' to see all entries", id);
                }
            }
        }

        Commands::Search { ref query } => {
            let vault_path = get_vault_path(&cli, false);

            if !vault_path.exists() {
                anyhow::bail!("No vault found. Use 'sentinelpass init' to create a new vault");
            }

            let master_password = prompt_password("Enter master password: ")?;

            let vault = VaultManager::open(&vault_path, master_password.as_bytes())
                .map_err(|e| anyhow::anyhow!("Failed to unlock vault: {}", e))?;

            match vault.list_entries() {
                Ok(entries) => {
                    let query_lower = query.to_lowercase();
                    let filtered: Vec<EntrySummary> = entries.into_iter()
                        .filter(|e| {
                            e.title.to_lowercase().contains(&query_lower)
                                || e.username.to_lowercase().contains(&query_lower)
                        })
                        .collect();

                    if filtered.is_empty() {
                        println!("No entries found matching '{}'", query);
                    } else {
                        println!();
                        println!("Found {} entries matching '{}':", filtered.len(), query);
                        println!();
                        println!("{:<5} {:<30} {:<30}", "ID", "Title", "Username");
                        println!("{}", "-".repeat(60));
                        for entry in filtered {
                            println!("{:<5} {:<30} {:<30}", entry.entry_id, entry.title, entry.username);
                        }
                    }
                }
                Err(e) => {
                    error!("Failed to search entries: {}", e);
                    anyhow::bail!("Failed to search entries: {}", e);
                }
            }
        }

        Commands::Delete { id, force: _ } => {
            let vault_path = get_vault_path(&cli, false);

            if !vault_path.exists() {
                anyhow::bail!("No vault found. Use 'sentinelpass init' to create a new vault");
            }

            // Note: Delete functionality not yet implemented in VaultManager
            println!("Delete functionality will be implemented in the next phase");
            println!("Entry ID to delete: {}", id);
        }
    }

    Ok(())
}
