use anyhow::Result;
use base64::Engine;
use clap::{Parser, Subcommand};
use rpassword::prompt_password;
use sentinelpass_core::{
    crypto::{analyze_password, generate_password, PasswordGeneratorConfig},
    export_to_csv, export_to_json, import_from_csv, import_from_json, parse_otpauth_uri,
    Entry as VaultEntry, EntrySummary, SshAgentClient, SshKeyImporter, TotpAlgorithm, VaultManager,
};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use tracing::{error, Level};
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

    /// Show biometric unlock status for this vault
    BiometricStatus,

    /// Enable biometric unlock for this vault
    BiometricEnable {
        /// Master password (prompted securely if omitted)
        #[arg(long)]
        master_password: Option<String>,
    },

    /// Disable biometric unlock for this vault
    BiometricDisable,

    /// Unlock vault using biometric authentication
    UnlockBiometric,

    /// Check whether SSH agent integration is available
    SshAgentStatus,

    /// Add a private key file to SSH agent
    SshAgentAdd {
        /// Path to private key file
        key_path: PathBuf,
    },

    /// Add a stored vault SSH key to SSH agent without writing it to disk
    SshAgentAddStored {
        /// SSH key ID stored in vault
        id: i64,
    },

    /// Remove all identities from SSH agent
    SshAgentClear,

    /// Add an SSH private key to the vault
    SshKeyAdd {
        /// Display name for the key in vault
        #[arg(long)]
        name: String,

        /// Path to private key file
        #[arg(long)]
        private_key_file: PathBuf,

        /// Path to public key file (defaults to <private_key_file>.pub)
        #[arg(long)]
        public_key_file: Option<PathBuf>,

        /// Optional comment override
        #[arg(long)]
        comment: Option<String>,
    },

    /// List SSH keys stored in vault
    SshKeyList,

    /// Get SSH key details by ID
    SshKeyGet {
        /// SSH key ID
        id: i64,

        /// Also print decrypted private key
        #[arg(long)]
        show_private: bool,
    },

    /// Delete SSH key by ID
    SshKeyDelete {
        /// SSH key ID
        id: i64,

        /// Skip confirmation
        #[arg(long)]
        force: bool,
    },

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

    /// Edit an existing entry
    Edit {
        /// Entry ID
        #[arg(long)]
        id: i64,

        /// New title
        #[arg(long)]
        title: Option<String>,

        /// New username
        #[arg(long)]
        username: Option<String>,

        /// New password (will prompt if --new-password flag is set without value)
        #[arg(long)]
        password: Option<String>,

        /// Prompt for a new password
        #[arg(long)]
        new_password: bool,

        /// New URL
        #[arg(long)]
        url: Option<String>,

        /// New notes
        #[arg(long)]
        notes: Option<String>,

        /// Toggle favorite status
        #[arg(long)]
        favorite: Option<bool>,
    },

    /// Add or update a TOTP secret for an entry
    TotpAdd {
        /// Entry ID to attach TOTP to
        #[arg(long)]
        entry_id: i64,

        /// Base32 secret (prompted securely if omitted)
        #[arg(long)]
        secret: Option<String>,

        /// otpauth:// URI from QR provisioning payload
        #[arg(long)]
        otpauth_uri: Option<String>,

        /// HMAC algorithm override (sha1 or sha256)
        #[arg(long)]
        algorithm: Option<String>,

        /// TOTP digits override (6 or 8)
        #[arg(long)]
        digits: Option<u8>,

        /// TOTP period override in seconds
        #[arg(long)]
        period: Option<u32>,

        /// Optional issuer label
        #[arg(long)]
        issuer: Option<String>,

        /// Optional account label
        #[arg(long)]
        account: Option<String>,
    },

    /// Generate current TOTP code for an entry
    TotpCode {
        /// Entry ID with configured TOTP
        #[arg(long)]
        entry_id: i64,
    },

    /// Remove TOTP secret for an entry
    TotpRemove {
        /// Entry ID with configured TOTP
        #[arg(long)]
        entry_id: i64,

        /// Skip confirmation
        #[arg(long)]
        force: bool,
    },

    /// Generate a secure random password
    Generate {
        /// Password length (default: 16)
        #[arg(short, long, default_value = "16")]
        length: usize,

        /// Include lowercase letters (default: true)
        #[arg(long, default_value = "true")]
        lowercase: bool,

        /// Include uppercase letters (default: true)
        #[arg(long, default_value = "true")]
        uppercase: bool,

        /// Include digits (default: true)
        #[arg(long, default_value = "true")]
        digits: bool,

        /// Include symbols (default: true)
        #[arg(long, default_value = "true")]
        symbols: bool,

        /// Exclude ambiguous characters like l, 1, I, O, 0
        #[arg(long, default_value = "true")]
        exclude_ambiguous: bool,

        /// Number of passwords to generate
        #[arg(short, long, default_value = "1")]
        count: usize,
    },

    /// Check password strength
    Check {
        /// Password to check (will prompt if not provided)
        #[arg(short, long)]
        password: Option<String>,
    },

    /// Export vault to file
    Export {
        /// Output file path
        output: PathBuf,

        /// Export format (json or csv)
        #[arg(short, long, default_value = "json")]
        format: String,
    },

    /// Import entries from file
    Import {
        /// Input file path
        input: PathBuf,

        /// Import format (json or csv)
        #[arg(short, long, default_value = "json")]
        format: String,
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

fn open_vault_with_password(vault_path: &PathBuf, master_password: &[u8]) -> Result<VaultManager> {
    match VaultManager::open(vault_path, master_password) {
        Ok(vault) => Ok(vault),
        Err(sentinelpass_core::PasswordManagerError::LockedOut(remaining_seconds)) => {
            anyhow::bail!(
                "Vault is temporarily locked after failed attempts. Try again in {} seconds.",
                remaining_seconds
            );
        }
        Err(e) => Err(anyhow::anyhow!("Failed to unlock vault: {}", e)),
    }
}

fn default_public_key_path(
    private_key_path: &Path,
    explicit_public_key: Option<&PathBuf>,
) -> PathBuf {
    explicit_public_key.cloned().unwrap_or_else(|| {
        let path_str = private_key_path.to_string_lossy();
        PathBuf::from(format!("{}.pub", path_str))
    })
}

fn extract_public_key_comment(public_key_line: &str) -> Option<String> {
    let mut parts = public_key_line.split_whitespace();
    let _key_type = parts.next()?;
    let _key_data = parts.next()?;
    let comment = parts.collect::<Vec<_>>().join(" ");
    if comment.is_empty() {
        None
    } else {
        Some(comment)
    }
}

fn compute_ssh_fingerprint(public_key_line: &str) -> Result<String> {
    let mut parts = public_key_line.split_whitespace();
    let _key_type = parts
        .next()
        .ok_or_else(|| anyhow::anyhow!("Invalid public key format: missing key type"))?;
    let key_data_b64 = parts
        .next()
        .ok_or_else(|| anyhow::anyhow!("Invalid public key format: missing key data"))?;

    let key_data = base64::engine::general_purpose::STANDARD
        .decode(key_data_b64)
        .map_err(|e| anyhow::anyhow!("Invalid base64 in public key: {}", e))?;
    let digest = Sha256::digest(&key_data);
    let fingerprint_b64 = base64::engine::general_purpose::STANDARD_NO_PAD.encode(digest);

    Ok(format!("SHA256:{}", fingerprint_b64))
}

fn main() -> Result<()> {
    // Initialize logging
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::WARN) // Reduce noise in CLI
        .finish();

    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");

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
                anyhow::bail!(
                    "No vault found at: {:?}\nUse 'sentinelpass init' to create a new vault",
                    vault_path
                );
            }

            let password = prompt_password("Enter master password: ")?;

            match open_vault_with_password(&vault_path, password.as_bytes()) {
                Ok(vault) => {
                    println!("✓ Vault unlocked successfully");
                    drop(vault);
                }
                Err(e) => {
                    error!("Failed to unlock vault: {}", e);
                    return Err(e);
                }
            }
        }

        Commands::Lock => {
            println!("Vault locks automatically when the process exits.");
            println!("The vault is only kept in memory during operations.");
        }

        Commands::BiometricStatus => {
            let vault_path = get_vault_path(&cli, false);
            if !vault_path.exists() {
                anyhow::bail!("No vault found. Use 'sentinelpass init' to create a new vault");
            }

            let configured = VaultManager::is_biometric_unlock_enabled(&vault_path)?;
            let method_name = sentinelpass_core::BiometricManager::get_method_name();
            let available = sentinelpass_core::BiometricManager::is_available();
            let enrolled = sentinelpass_core::BiometricManager::is_enrolled();

            println!("Biometric method: {}", method_name);
            println!("Available: {}", if available { "yes" } else { "no" });
            println!("Enrolled: {}", if enrolled { "yes" } else { "no" });
            println!(
                "Configured for vault: {}",
                if configured { "yes" } else { "no" }
            );
        }

        Commands::BiometricEnable {
            ref master_password,
        } => {
            let vault_path = get_vault_path(&cli, false);
            if !vault_path.exists() {
                anyhow::bail!("No vault found. Use 'sentinelpass init' to create a new vault");
            }

            let master_password = match master_password {
                Some(value) => value.to_string(),
                None => prompt_password("Enter master password: ")?,
            };
            let vault = open_vault_with_password(&vault_path, master_password.as_bytes())?;
            vault.enable_biometric_unlock(master_password.as_bytes())?;
            println!("Biometric unlock enabled for this vault.");
        }

        Commands::BiometricDisable => {
            let vault_path = get_vault_path(&cli, false);
            if !vault_path.exists() {
                anyhow::bail!("No vault found. Use 'sentinelpass init' to create a new vault");
            }

            let master_password = prompt_password("Enter master password: ")?;
            let vault = open_vault_with_password(&vault_path, master_password.as_bytes())?;
            vault.disable_biometric_unlock()?;
            println!("Biometric unlock disabled for this vault.");
        }

        Commands::UnlockBiometric => {
            let vault_path = get_vault_path(&cli, false);
            if !vault_path.exists() {
                anyhow::bail!("No vault found. Use 'sentinelpass init' to create a new vault");
            }

            let reason = "Unlock SentinelPass vault";
            match VaultManager::open_with_biometric(&vault_path, reason) {
                Ok(vault) => {
                    println!("✓ Vault unlocked successfully via biometric authentication");
                    drop(vault);
                }
                Err(e) => {
                    error!("Failed biometric unlock: {}", e);
                    anyhow::bail!("Biometric unlock failed: {}", e);
                }
            }
        }

        Commands::SshAgentStatus => {
            let client = SshAgentClient::new()?;
            let available = client.is_available();
            println!(
                "SSH agent available: {}",
                if available { "yes" } else { "no" }
            );
            if !available {
                println!(
                    "Hint: ensure `ssh-add` is installed and your SSH agent service is running."
                );
            }
        }

        Commands::SshAgentAdd { ref key_path } => {
            let client = SshAgentClient::new()?;
            client
                .add_identity(key_path)
                .map_err(|e| anyhow::anyhow!("Failed to add key to SSH agent: {}", e))?;
            println!("Added SSH key to agent: {}", key_path.display());
        }

        Commands::SshAgentAddStored { id } => {
            let vault_path = get_vault_path(&cli, false);
            if !vault_path.exists() {
                anyhow::bail!("No vault found. Use 'sentinelpass init' to create a new vault");
            }

            let master_password = prompt_password("Enter master password: ")?;
            let vault = open_vault_with_password(&vault_path, master_password.as_bytes())?;
            let mut private_key = vault.export_ssh_private_key(id)?;

            let client = SshAgentClient::new()?;
            let add_result = client
                .add_identity_from_pem(&private_key)
                .map_err(|e| anyhow::anyhow!("Failed to add stored SSH key to agent: {}", e));
            private_key.clear();
            add_result?;

            println!("Added stored SSH key {} to agent.", id);
        }

        Commands::SshAgentClear => {
            let client = SshAgentClient::new()?;
            client
                .remove_all_identities()
                .map_err(|e| anyhow::anyhow!("Failed to clear SSH agent identities: {}", e))?;
            println!("Cleared all SSH agent identities.");
        }

        Commands::SshKeyAdd {
            ref name,
            ref private_key_file,
            ref public_key_file,
            ref comment,
        } => {
            let vault_path = get_vault_path(&cli, false);
            if !vault_path.exists() {
                anyhow::bail!("No vault found. Use 'sentinelpass init' to create a new vault");
            }

            let public_key_path =
                default_public_key_path(private_key_file, public_key_file.as_ref());
            if !private_key_file.exists() {
                anyhow::bail!("Private key file not found: {}", private_key_file.display());
            }
            if !public_key_path.exists() {
                anyhow::bail!("Public key file not found: {}", public_key_path.display());
            }

            let private_key = std::fs::read_to_string(private_key_file).map_err(|e| {
                anyhow::anyhow!(
                    "Failed to read private key file {}: {}",
                    private_key_file.display(),
                    e
                )
            })?;
            let (public_key, key_type) = SshKeyImporter::import_public_key(&public_key_path)
                .map_err(|e| {
                    anyhow::anyhow!(
                        "Failed to read public key file {}: {}",
                        public_key_path.display(),
                        e
                    )
                })?;

            let key_comment = comment
                .clone()
                .or_else(|| extract_public_key_comment(&public_key));
            let fingerprint = compute_ssh_fingerprint(&public_key)?;

            let master_password = prompt_password("Enter master password: ")?;
            let vault = open_vault_with_password(&vault_path, master_password.as_bytes())?;
            let key_id = vault.add_ssh_key_plaintext(
                name.to_string(),
                key_comment,
                key_type,
                None,
                public_key,
                private_key,
                fingerprint,
            )?;

            println!("SSH key added with ID: {}", key_id);
        }

        Commands::SshKeyList => {
            let vault_path = get_vault_path(&cli, false);
            if !vault_path.exists() {
                anyhow::bail!("No vault found. Use 'sentinelpass init' to create a new vault");
            }

            let master_password = prompt_password("Enter master password: ")?;
            let vault = open_vault_with_password(&vault_path, master_password.as_bytes())?;
            let keys = vault.list_ssh_keys()?;

            if keys.is_empty() {
                println!("No SSH keys found in vault.");
            } else {
                println!();
                println!("{:<5} {:<24} {:<18} Fingerprint", "ID", "Name", "Type");
                println!("{}", "-".repeat(96));
                for key in keys {
                    println!(
                        "{:<5} {:<24} {:<18} {}",
                        key.key_id, key.name, key.key_type, key.fingerprint
                    );
                }
                println!();
            }
        }

        Commands::SshKeyGet { id, show_private } => {
            let vault_path = get_vault_path(&cli, false);
            if !vault_path.exists() {
                anyhow::bail!("No vault found. Use 'sentinelpass init' to create a new vault");
            }

            let master_password = prompt_password("Enter master password: ")?;
            let vault = open_vault_with_password(&vault_path, master_password.as_bytes())?;
            let key = vault.get_ssh_key(id)?;

            println!();
            println!("ID: {}", id);
            println!("Name: {}", key.name);
            if let Some(comment) = key.comment {
                println!("Comment: {}", comment);
            }
            println!("Type: {}", key.key_type);
            println!("Fingerprint: {}", key.fingerprint);
            println!("Public key: {}", key.public_key);

            if show_private {
                let private_key = vault.export_ssh_private_key(id)?;
                println!();
                println!("Private key:");
                println!("{}", private_key);
            }
            println!();
        }

        Commands::SshKeyDelete { id, force } => {
            let vault_path = get_vault_path(&cli, false);
            if !vault_path.exists() {
                anyhow::bail!("No vault found. Use 'sentinelpass init' to create a new vault");
            }

            if !force {
                print!("Delete SSH key {}? [y/N]: ", id);
                use std::io::Write;
                std::io::stdout().flush()?;
                let mut confirmation = String::new();
                std::io::stdin().read_line(&mut confirmation)?;
                if !confirmation.trim().to_lowercase().starts_with('y') {
                    println!("Delete cancelled");
                    return Ok(());
                }
            }

            let master_password = prompt_password("Enter master password: ")?;
            let vault = open_vault_with_password(&vault_path, master_password.as_bytes())?;
            vault.delete_ssh_key(id)?;
            println!("Deleted SSH key {}", id);
        }

        Commands::Add {
            ref title,
            ref username,
            ref password,
            ref url,
            ref notes,
            favorite,
        } => {
            let vault_path = get_vault_path(&cli, false);

            if !vault_path.exists() {
                anyhow::bail!("No vault found. Use 'sentinelpass init' to create a new vault");
            }

            let password_str = match password {
                Some(p) => p.to_string(),
                None => prompt_password("Enter password for entry: ")?,
            };

            let master_password = prompt_password("Enter master password to unlock vault: ")?;

            let vault = open_vault_with_password(&vault_path, master_password.as_bytes())?;

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

            let vault = open_vault_with_password(&vault_path, master_password.as_bytes())?;

            match vault.list_entries() {
                Ok(entries) => {
                    if entries.is_empty() {
                        println!("No entries found. Add one with 'sentinelpass add'");
                    } else {
                        println!();
                        println!("{:<5} {:<30} {:<30} Fav", "ID", "Title", "Username");
                        println!("{}", "-".repeat(80));
                        for entry in &entries {
                            let fav = if entry.favorite { "⭐" } else { "" };
                            println!(
                                "{:<5} {:<30} {:<30} {}",
                                entry.entry_id, entry.title, entry.username, fav
                            );
                        }
                        println!();
                        println!("Total: {} entries", entries.len());

                        if show_passwords {
                            println!();
                            println!(
                                "WARNING: Showing passwords (be careful of shoulder surfing!)"
                            );
                            println!();
                            for summary in &entries {
                                if let Ok(entry) = vault.get_entry(summary.entry_id) {
                                    println!("--- ID {} ---", summary.entry_id);
                                    println!("Password: {}", entry.password);
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

            let vault = open_vault_with_password(&vault_path, master_password.as_bytes())?;

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
                    println!(
                        "Created: {}",
                        entry.created_at.format("%Y-%m-%d %H:%M:%S UTC")
                    );
                    if entry.favorite {
                        println!("⭐ Favorite");
                    }
                    println!();
                }
                Err(e) => {
                    error!("Failed to get entry: {}", e);
                    anyhow::bail!(
                        "Entry {} not found. Use 'sentinelpass list' to see all entries",
                        id
                    );
                }
            }
        }

        Commands::Search { ref query } => {
            let vault_path = get_vault_path(&cli, false);

            if !vault_path.exists() {
                anyhow::bail!("No vault found. Use 'sentinelpass init' to create a new vault");
            }

            let master_password = prompt_password("Enter master password: ")?;

            let vault = open_vault_with_password(&vault_path, master_password.as_bytes())?;

            match vault.list_entries() {
                Ok(entries) => {
                    let query_lower = query.to_lowercase();
                    let filtered: Vec<EntrySummary> = entries
                        .into_iter()
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
                            println!(
                                "{:<5} {:<30} {:<30}",
                                entry.entry_id, entry.title, entry.username
                            );
                        }
                    }
                }
                Err(e) => {
                    error!("Failed to search entries: {}", e);
                    anyhow::bail!("Failed to search entries: {}", e);
                }
            }
        }

        Commands::Delete { id, force } => {
            let vault_path = get_vault_path(&cli, false);

            if !vault_path.exists() {
                anyhow::bail!("No vault found. Use 'sentinelpass init' to create a new vault");
            }

            let master_password = prompt_password("Enter master password: ")?;
            let master_password_bytes = master_password.as_bytes();

            let vault = open_vault_with_password(&vault_path, master_password_bytes)?;

            // Get entry details for confirmation
            let entry = vault.get_entry(id)?;

            if !force {
                println!("Entry to delete:");
                println!("  Title: {}", entry.title);
                println!("  Username: {}", entry.username);
                println!();
                print!("Are you sure you want to delete this entry? [y/N]: ");
                use std::io::Write;
                std::io::stdout().flush()?;
                let mut confirmation = String::new();
                std::io::stdin().read_line(&mut confirmation)?;
                if !confirmation.trim().to_lowercase().starts_with('y') {
                    println!("Delete cancelled");
                    return Ok(());
                }
            }

            vault.delete_entry(id)?;
            println!("Entry deleted successfully");
        }

        Commands::Edit {
            id,
            ref title,
            ref username,
            ref password,
            new_password,
            ref url,
            ref notes,
            favorite,
        } => {
            let vault_path = get_vault_path(&cli, false);

            if !vault_path.exists() {
                anyhow::bail!("No vault found. Use 'sentinelpass init' to create a new vault");
            }

            let master_password = prompt_password("Enter master password: ")?;
            let master_password_bytes = master_password.as_bytes();

            let vault = open_vault_with_password(&vault_path, master_password_bytes)?;

            // Get existing entry
            let existing_entry = vault.get_entry(id)?;

            // Determine new values (use existing if not provided)
            let new_title = title
                .as_ref()
                .map(|x| x.as_str())
                .unwrap_or_else(|| existing_entry.title.as_str())
                .to_string();
            let new_username = username
                .as_ref()
                .map(|x| x.as_str())
                .unwrap_or_else(|| existing_entry.username.as_str())
                .to_string();

            // Handle password
            let new_password = if new_password {
                prompt_password("Enter new password: ")?
            } else {
                password
                    .as_ref()
                    .map(|x| x.as_str())
                    .unwrap_or_else(|| existing_entry.password.as_str())
                    .to_string()
            };

            let new_url = url.clone().or_else(|| existing_entry.url.clone());
            let new_notes = notes.clone().or_else(|| existing_entry.notes.clone());
            let new_favorite = favorite.unwrap_or(existing_entry.favorite);

            // Create updated entry
            use chrono::Utc;
            let updated_entry = VaultEntry {
                entry_id: Some(id),
                title: new_title,
                username: new_username,
                password: new_password,
                url: new_url,
                notes: new_notes,
                created_at: existing_entry.created_at,
                modified_at: Utc::now(),
                favorite: new_favorite,
            };

            vault.update_entry(id, &updated_entry)?;
            println!("Entry updated successfully");
        }

        Commands::TotpAdd {
            entry_id,
            ref secret,
            ref otpauth_uri,
            ref algorithm,
            digits,
            period,
            ref issuer,
            ref account,
        } => {
            let vault_path = get_vault_path(&cli, false);

            if !vault_path.exists() {
                anyhow::bail!("No vault found. Use 'sentinelpass init' to create a new vault");
            }

            let (uri_secret, uri_algorithm, uri_digits, uri_period, uri_issuer, uri_account) =
                if let Some(uri) = otpauth_uri.as_ref() {
                    let parsed = parse_otpauth_uri(uri).map_err(|e| anyhow::anyhow!("{}", e))?;
                    (
                        Some(parsed.secret_base32),
                        Some(parsed.algorithm),
                        Some(parsed.digits),
                        Some(parsed.period),
                        parsed.issuer,
                        parsed.account_name,
                    )
                } else {
                    (None, None, None, None, None, None)
                };

            let secret_value = match (secret.as_ref(), uri_secret.as_ref()) {
                (Some(value), _) => value.to_string(),
                (None, Some(value)) => value.to_string(),
                (None, None) => prompt_password("Enter TOTP secret (base32): ")?,
            };

            let algorithm = match algorithm {
                Some(value) => value
                    .parse::<TotpAlgorithm>()
                    .map_err(|e| anyhow::anyhow!("{}", e))?,
                None => uri_algorithm.unwrap_or(TotpAlgorithm::Sha1),
            };

            let digits = digits.or(uri_digits).unwrap_or(6);
            let period = period.or(uri_period).unwrap_or(30);
            let issuer_value = issuer.clone().or(uri_issuer);
            let account_value = account.clone().or(uri_account);

            let master_password = prompt_password("Enter master password: ")?;
            let vault = open_vault_with_password(&vault_path, master_password.as_bytes())?;

            let totp_id = vault.add_totp_secret(
                entry_id,
                &secret_value,
                algorithm,
                digits,
                period,
                issuer_value.as_deref(),
                account_value.as_deref(),
            )?;

            println!("TOTP secret saved (id: {}) for entry {}", totp_id, entry_id);
        }

        Commands::TotpCode { entry_id } => {
            let vault_path = get_vault_path(&cli, false);

            if !vault_path.exists() {
                anyhow::bail!("No vault found. Use 'sentinelpass init' to create a new vault");
            }

            let master_password = prompt_password("Enter master password: ")?;
            let vault = open_vault_with_password(&vault_path, master_password.as_bytes())?;

            let code = vault.generate_totp_code(entry_id)?;
            println!("TOTP code: {}", code.code);
            println!("Valid for: {} seconds", code.seconds_remaining);
        }

        Commands::TotpRemove { entry_id, force } => {
            let vault_path = get_vault_path(&cli, false);

            if !vault_path.exists() {
                anyhow::bail!("No vault found. Use 'sentinelpass init' to create a new vault");
            }

            if !force {
                print!("Remove TOTP secret for entry {}? [y/N]: ", entry_id);
                use std::io::Write;
                std::io::stdout().flush()?;
                let mut confirmation = String::new();
                std::io::stdin().read_line(&mut confirmation)?;
                if !confirmation.trim().to_lowercase().starts_with('y') {
                    println!("Removal cancelled");
                    return Ok(());
                }
            }

            let master_password = prompt_password("Enter master password: ")?;
            let vault = open_vault_with_password(&vault_path, master_password.as_bytes())?;
            vault.remove_totp_secret(entry_id)?;
            println!("TOTP secret removed for entry {}", entry_id);
        }

        Commands::Generate {
            length,
            lowercase,
            uppercase,
            digits,
            symbols,
            exclude_ambiguous,
            count,
        } => {
            let config = PasswordGeneratorConfig {
                length,
                include_lowercase: lowercase,
                include_uppercase: uppercase,
                include_digits: digits,
                include_symbols: symbols,
                exclude_ambiguous,
            };

            // Validate config
            if let Err(e) = config.validate() {
                anyhow::bail!("Invalid password generator configuration: {}", e);
            }

            println!();
            println!("Generated passwords:");
            println!();

            for i in 0..count {
                let password = generate_password(&config)?;
                println!("  {}: {}", i + 1, password);
            }

            println!();
        }

        Commands::Check { password } => {
            let password = password
                .map(Ok)
                .unwrap_or_else(|| prompt_password("Enter password to check: "))?;

            let analysis = analyze_password(&password)?;

            println!();
            println!("Password Analysis");
            println!("================");
            println!();

            // Print strength with color
            let color = analysis.strength.color_code();
            let reset = "\x1b[0m";
            println!(
                "Strength:  {}{}{}",
                color,
                analysis.strength.as_str(),
                reset
            );
            println!("Score:     {}/5", analysis.strength.score());
            println!();

            println!("Details:");
            println!("  Length:       {} characters", analysis.length);
            println!("  Entropy:      {:.2} bits", analysis.entropy_bits);
            println!("  Crack time:   {}", analysis.crack_time_human());
            println!();

            println!("Character types:");
            println!(
                "  Lowercase:    {}",
                if analysis.has_lowercase { "✓" } else { "✗" }
            );
            println!(
                "  Uppercase:    {}",
                if analysis.has_uppercase { "✓" } else { "✗" }
            );
            println!(
                "  Digits:       {}",
                if analysis.has_digits { "✓" } else { "✗" }
            );
            println!(
                "  Symbols:      {}",
                if analysis.has_symbols { "✓" } else { "✗" }
            );
            println!();

            if !analysis.warnings.is_empty() {
                println!("Warnings:");
                for warning in &analysis.warnings {
                    println!("  ⚠ {}", warning);
                }
                println!();
            }

            if !analysis.suggestions.is_empty() {
                println!("Suggestions:");
                for suggestion in &analysis.suggestions {
                    println!("  → {}", suggestion);
                }
                println!();
            }
        }

        Commands::Export {
            ref output,
            ref format,
        } => {
            let vault_path = get_vault_path(&cli, false);

            if !vault_path.exists() {
                anyhow::bail!("No vault found. Use 'sentinelpass init' to create a new vault");
            }

            let master_password = prompt_password("Enter master password: ")?;
            let master_password_bytes = master_password.as_bytes();

            let vault = open_vault_with_password(&vault_path, master_password_bytes)?;

            match format.as_str() {
                "json" => {
                    export_to_json(&vault, output)?;
                    println!(
                        "Exported {} entries to {}",
                        vault.list_entries()?.len(),
                        output.display()
                    );
                }
                "csv" => {
                    export_to_csv(&vault, output)?;
                    println!(
                        "Exported {} entries to {}",
                        vault.list_entries()?.len(),
                        output.display()
                    );
                }
                _ => anyhow::bail!("Unsupported format: {}. Use 'json' or 'csv'", format),
            }
        }

        Commands::Import {
            ref input,
            ref format,
        } => {
            let vault_path = get_vault_path(&cli, false);

            if !vault_path.exists() {
                anyhow::bail!("No vault found. Use 'sentinelpass init' to create a new vault");
            }

            let master_password = prompt_password("Enter master password: ")?;
            let master_password_bytes = master_password.as_bytes();

            let mut vault = open_vault_with_password(&vault_path, master_password_bytes)?;

            match format.as_str() {
                "json" => {
                    let count = import_from_json(&mut vault, input)?;
                    println!("Imported {} entries from {}", count, input.display());
                }
                "csv" => {
                    let count = import_from_csv(&mut vault, input)?;
                    println!("Imported {} entries from {}", count, input.display());
                }
                _ => anyhow::bail!("Unsupported format: {}. Use 'json' or 'csv'", format),
            }
        }
    }

    Ok(())
}
