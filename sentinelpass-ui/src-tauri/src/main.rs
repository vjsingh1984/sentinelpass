// Prevents additional console window on Windows in release builds
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use sentinelpass_core::daemon::{default_ipc_socket_path, IpcClient, IpcMessage};
use sentinelpass_core::{parse_otpauth_uri, Entry, EntrySummary, TotpAlgorithm, VaultManager};
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};
use tauri::{Manager, State};

// Application state
struct AppState {
    vault_manager: Arc<Mutex<Option<VaultManager>>>,
    daemon_process: Arc<Mutex<Option<Child>>>,
}

static RESOURCE_DIR: OnceLock<PathBuf> = OnceLock::new();

#[derive(Serialize, Deserialize)]
pub struct DaemonStatus {
    available: bool,
    unlocked: bool,
    message: Option<String>,
}

fn daemon_binary_name() -> &'static str {
    if cfg!(windows) {
        "sentinelpass-daemon.exe"
    } else {
        "sentinelpass-daemon"
    }
}

fn resolve_daemon_binary_path() -> std::path::PathBuf {
    let binary_name = daemon_binary_name();
    let mut candidates = Vec::new();

    if let Ok(explicit_path) = std::env::var("SENTINELPASS_DAEMON_PATH") {
        let trimmed = explicit_path.trim();
        if !trimmed.is_empty() {
            candidates.push(PathBuf::from(trimmed));
        }
    }

    if let Some(resource_dir) = RESOURCE_DIR.get() {
        candidates.push(
            resource_dir
                .join("src-tauri")
                .join("resources")
                .join("bin")
                .join(binary_name),
        );
        candidates.push(resource_dir.join("bin").join(binary_name));
        candidates.push(resource_dir.join(binary_name));
    }

    if let Ok(current_exe) = std::env::current_exe() {
        if let Some(exe_dir) = current_exe.parent() {
            candidates.push(exe_dir.join(binary_name));
            candidates.push(exe_dir.join("resources").join("bin").join(binary_name));
            candidates.push(
                exe_dir
                    .join("..")
                    .join("Resources")
                    .join("bin")
                    .join(binary_name),
            );
        }
    }

    for candidate in candidates {
        if candidate.exists() {
            return candidate;
        }
    }

    std::path::PathBuf::from(binary_name)
}

fn spawn_daemon_process() -> std::result::Result<Child, String> {
    let daemon_binary = resolve_daemon_binary_path();
    unlock_debug_log(&format!(
        "spawn_daemon_process: starting {} --start-locked",
        daemon_binary.display()
    ));

    let mut command = Command::new(&daemon_binary);
    command
        .arg("--start-locked")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        command.creation_flags(CREATE_NO_WINDOW);
    }

    command
        .spawn()
        .map_err(|error| format!("Failed to start {}: {}", daemon_binary.display(), error))
}

fn reap_managed_daemon_if_exited(state: &AppState) {
    let mut daemon_process = state.daemon_process.lock().unwrap();
    if let Some(child) = daemon_process.as_mut() {
        match child.try_wait() {
            Ok(Some(status)) => {
                unlock_debug_log(&format!(
                    "reap_managed_daemon_if_exited: daemon exited with status {}",
                    status
                ));
                *daemon_process = None;
            }
            Ok(None) => {}
            Err(error) => {
                unlock_debug_log(&format!(
                    "reap_managed_daemon_if_exited: failed to poll daemon status: {}",
                    error
                ));
                *daemon_process = None;
            }
        }
    }
}

async fn wait_for_daemon_ready(timeout: std::time::Duration) -> std::result::Result<(), String> {
    let deadline = tokio::time::Instant::now() + timeout;

    loop {
        match send_daemon_message(IpcMessage::CheckVault).await {
            Ok(IpcMessage::VaultStatusResponse { .. }) => {
                unlock_debug_log("wait_for_daemon_ready: daemon IPC ready");
                return Ok(());
            }
            Ok(other) => {
                unlock_debug_log(&format!(
                    "wait_for_daemon_ready: unexpected IPC response: {:?}",
                    other
                ));
            }
            Err(error) => {
                unlock_debug_log(&format!(
                    "wait_for_daemon_ready: daemon not ready yet: {}",
                    error
                ));
            }
        }

        if tokio::time::Instant::now() >= deadline {
            return Err("Daemon started but IPC did not become ready in time".to_string());
        }

        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    }
}

async fn ensure_daemon_running(state: &AppState) -> std::result::Result<(), String> {
    if matches!(
        send_daemon_message(IpcMessage::CheckVault).await,
        Ok(IpcMessage::VaultStatusResponse { .. })
    ) {
        return Ok(());
    }

    reap_managed_daemon_if_exited(state);

    let should_spawn = {
        let daemon_process = state.daemon_process.lock().unwrap();
        daemon_process.is_none()
    };

    if should_spawn {
        let child = spawn_daemon_process()?;
        let pid = child.id();
        {
            let mut daemon_process = state.daemon_process.lock().unwrap();
            *daemon_process = Some(child);
        }
        unlock_debug_log(&format!(
            "ensure_daemon_running: started managed daemon process pid={}",
            pid
        ));
    } else {
        unlock_debug_log("ensure_daemon_running: managed daemon already running");
    }

    wait_for_daemon_ready(std::time::Duration::from_secs(5)).await
}

fn stop_managed_daemon(state: &AppState) {
    let mut daemon_process = state.daemon_process.lock().unwrap();
    if let Some(child) = daemon_process.as_mut() {
        unlock_debug_log("stop_managed_daemon: stopping managed daemon process");
        let _ = child.kill();
        let _ = child.wait();
    }
    *daemon_process = None;
}

async fn send_daemon_message(message: IpcMessage) -> std::result::Result<IpcMessage, String> {
    unlock_debug_log("send_daemon_message: preparing IPC client");
    let socket_path = default_ipc_socket_path();
    let ipc_client =
        IpcClient::new(socket_path).map_err(|e| format!("Daemon unavailable: {}", e))?;
    let response = ipc_client
        .send(message)
        .await
        .map_err(|e| format!("Failed to communicate with daemon: {}", e))?;
    unlock_debug_log(&format!("send_daemon_message: response={:?}", response));
    Ok(response)
}

async fn unlock_daemon_with_password(master_password: &str) -> std::result::Result<(), String> {
    unlock_debug_log("unlock_daemon_with_password: requesting daemon unlock");
    let response = send_daemon_message(IpcMessage::UnlockVault {
        master_password: master_password.to_string(),
    })
    .await?;

    match response {
        IpcMessage::UnlockVaultResponse { success, error } if success => Ok(()),
        IpcMessage::UnlockVaultResponse {
            success: false,
            error,
        } => Err(error.unwrap_or_else(|| "Daemon unlock failed".to_string())),
        IpcMessage::VaultStatusResponse { unlocked } if unlocked => Ok(()),
        IpcMessage::VaultStatusResponse { unlocked: false } => {
            Err("Daemon remains locked".to_string())
        }
        _ => Err("Unexpected daemon response while unlocking".to_string()),
    }
}

async fn unlock_daemon_with_biometric() -> std::result::Result<(), String> {
    unlock_debug_log("unlock_daemon_with_biometric: requesting daemon biometric unlock");
    let response = send_daemon_message(IpcMessage::UnlockVaultBiometric {
        prompt_reason: Some("Unlock SentinelPass daemon for browser integration".to_string()),
    })
    .await?;

    match response {
        IpcMessage::UnlockVaultResponse { success, error } if success => Ok(()),
        IpcMessage::UnlockVaultResponse {
            success: false,
            error,
        } => Err(error.unwrap_or_else(|| "Daemon biometric unlock failed".to_string())),
        _ => Err("Unexpected daemon response while biometric unlocking".to_string()),
    }
}

async fn fetch_daemon_status() -> DaemonStatus {
    unlock_debug_log("fetch_daemon_status: querying daemon lock state");
    match send_daemon_message(IpcMessage::CheckVault).await {
        Ok(IpcMessage::VaultStatusResponse { unlocked }) => DaemonStatus {
            available: true,
            unlocked,
            message: None,
        },
        Ok(_) => DaemonStatus {
            available: true,
            unlocked: false,
            message: Some("Unexpected daemon response".to_string()),
        },
        Err(error) => DaemonStatus {
            available: false,
            unlocked: false,
            message: Some(error),
        },
    }
}

fn unlock_debug_log(message: &str) {
    if std::env::var("SENTINELPASS_DEBUG_UNLOCK").unwrap_or_default() != "1" {
        return;
    }

    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let line = format!("[{}] {}\n", ts, message);

    eprintln!("[SentinelPass UI Debug] {}", message);

    if let Ok(config_dir) = sentinelpass_core::ensure_config_dir() {
        let path = config_dir.join("ui_unlock_debug.log");
        if let Ok(mut file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
        {
            let _ = file.write_all(line.as_bytes());
            return;
        }
    }

    // Fallback path so debug logs are still available even if config directory writes fail.
    if let Ok(temp_dir) = std::env::var("TEMP") {
        let fallback = std::path::PathBuf::from(temp_dir).join("sentinelpass_ui_unlock_debug.log");
        if let Ok(mut file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(fallback)
        {
            let _ = file.write_all(line.as_bytes());
        }
    }
}

// Command: Create vault
#[tauri::command]
async fn create_vault(
    master_password: String,
    state: State<'_, AppState>,
) -> Result<String, String> {
    let vault_path = sentinelpass_core::get_default_vault_path();

    // Check if vault already exists
    if vault_path.exists() {
        return Err("Vault already exists".to_string());
    }

    // Ensure data directory exists
    sentinelpass_core::ensure_data_dir()
        .map_err(|e| format!("Failed to create data directory: {}", e))?;

    match VaultManager::create(&vault_path, master_password.as_bytes()) {
        Ok(vault) => {
            *state.vault_manager.lock().unwrap() = Some(vault);
            Ok("Vault created successfully".to_string())
        }
        Err(e) => Err(format!("Failed to create vault: {}", e)),
    }
}

// Command: Unlock vault
#[tauri::command]
async fn unlock_vault(
    master_password: String,
    state: State<'_, AppState>,
) -> Result<String, String> {
    unlock_debug_log("unlock_vault: command called");
    let vault_path = sentinelpass_core::get_default_vault_path();
    unlock_debug_log(&format!(
        "unlock_vault: vault_path={} exists={}",
        vault_path.display(),
        vault_path.exists()
    ));

    if !vault_path.exists() {
        return Err("No vault found".to_string());
    }

    match VaultManager::open(&vault_path, master_password.as_bytes()) {
        Ok(vault) => {
            unlock_debug_log("unlock_vault: local vault unlock success");
            *state.vault_manager.lock().unwrap() = Some(vault);
            match ensure_daemon_running(&state).await {
                Ok(_) => match unlock_daemon_with_password(&master_password).await {
                    Ok(_) => {
                        unlock_debug_log("unlock_vault: daemon unlock success");
                        Ok("Vault unlocked successfully".to_string())
                    }
                    Err(error) => {
                        unlock_debug_log(&format!("unlock_vault: daemon unlock failed: {}", error));
                        Ok(format!(
                            "Vault unlocked in app, but daemon unlock failed: {}. Browser integration will stay locked until daemon is unlocked.",
                            error
                        ))
                    }
                },
                Err(error) => {
                    unlock_debug_log(&format!(
                        "unlock_vault: daemon start/check failed: {}",
                        error
                    ));
                    Ok(format!(
                        "Vault unlocked in app, but daemon is unavailable: {}. Browser integration will stay unavailable until daemon starts.",
                        error
                    ))
                }
            }
        }
        Err(sentinelpass_core::PasswordManagerError::LockedOut(remaining_seconds)) => Err(format!(
            "Vault is temporarily locked after failed attempts. Try again in {} seconds.",
            remaining_seconds
        )),
        Err(e) => {
            unlock_debug_log(&format!("unlock_vault: local vault unlock failed: {}", e));
            Err(format!("Failed to unlock vault: {}", e))
        }
    }
}

// Command: Unlock vault via biometric authentication
#[tauri::command]
async fn unlock_vault_biometric(state: State<'_, AppState>) -> Result<String, String> {
    unlock_debug_log("unlock_vault_biometric: command called");
    let vault_path = sentinelpass_core::get_default_vault_path();

    if !vault_path.exists() {
        return Err("No vault found".to_string());
    }

    match VaultManager::open_with_biometric(&vault_path, "Unlock SentinelPass vault") {
        Ok(vault) => {
            unlock_debug_log("unlock_vault_biometric: local vault biometric unlock success");
            *state.vault_manager.lock().unwrap() = Some(vault);
            match ensure_daemon_running(&state).await {
                Ok(_) => match unlock_daemon_with_biometric().await {
                    Ok(_) => {
                        unlock_debug_log("unlock_vault_biometric: daemon biometric unlock success");
                        Ok("Vault unlocked successfully via biometric authentication".to_string())
                    }
                    Err(error) => {
                        unlock_debug_log(&format!(
                            "unlock_vault_biometric: daemon biometric unlock failed: {}",
                            error
                        ));
                        Ok(format!(
                            "Vault unlocked in app, but daemon biometric unlock failed: {}. Browser integration may still require unlock.",
                            error
                        ))
                    }
                },
                Err(error) => {
                    unlock_debug_log(&format!(
                        "unlock_vault_biometric: daemon start/check failed: {}",
                        error
                    ));
                    Ok(format!(
                        "Vault unlocked in app, but daemon is unavailable: {}. Browser integration may remain unavailable.",
                        error
                    ))
                }
            }
        }
        Err(e) => {
            unlock_debug_log(&format!(
                "unlock_vault_biometric: local biometric unlock failed: {}",
                e
            ));
            Err(format!("Failed biometric unlock: {}", e))
        }
    }
}

// Command: Get biometric capability/configuration status
#[tauri::command]
async fn biometric_status() -> Result<BiometricStatus, String> {
    let vault_path = sentinelpass_core::get_default_vault_path();
    let configured = if vault_path.exists() {
        VaultManager::is_biometric_unlock_enabled(&vault_path).map_err(|e| e.to_string())?
    } else {
        false
    };

    Ok(BiometricStatus {
        method_name: sentinelpass_core::BiometricManager::get_method_name().to_string(),
        available: sentinelpass_core::BiometricManager::is_available(),
        enrolled: sentinelpass_core::BiometricManager::is_enrolled(),
        configured,
    })
}

// Command: Enable biometric unlock for this vault
#[tauri::command]
async fn enable_biometric_unlock(
    master_password: String,
    state: State<'_, AppState>,
) -> Result<String, String> {
    if master_password.is_empty() {
        return Err("Master password cannot be empty".to_string());
    }

    let vault_path = sentinelpass_core::get_default_vault_path();
    if !vault_path.exists() {
        return Err("No vault found".to_string());
    }

    let mut guard = state.vault_manager.lock().unwrap();
    if let Some(vault) = guard.as_ref() {
        vault
            .enable_biometric_unlock(master_password.as_bytes())
            .map_err(|e| e.to_string())?;
        return Ok("Biometric unlock enabled".to_string());
    }

    let vault =
        VaultManager::open(&vault_path, master_password.as_bytes()).map_err(|e| e.to_string())?;
    vault
        .enable_biometric_unlock(master_password.as_bytes())
        .map_err(|e| e.to_string())?;
    *guard = Some(vault);

    Ok("Biometric unlock enabled".to_string())
}

// Command: Disable biometric unlock for this vault
#[tauri::command]
async fn disable_biometric_unlock(state: State<'_, AppState>) -> Result<String, String> {
    let guard = state.vault_manager.lock().unwrap();
    let vault = guard
        .as_ref()
        .ok_or("Vault not unlocked. Unlock first to disable biometric unlock.")?;
    vault
        .disable_biometric_unlock()
        .map_err(|e| e.to_string())?;
    Ok("Biometric unlock disabled".to_string())
}

// Command: Lock vault
#[tauri::command]
async fn lock_vault(state: State<'_, AppState>) -> Result<(), String> {
    {
        let mut vault_manager = state.vault_manager.lock().unwrap();
        if let Some(ref mut vault) = *vault_manager {
            vault.lock();
        }
        *vault_manager = None;
    }

    if let Err(error) = send_daemon_message(IpcMessage::LockVault).await {
        eprintln!("SentinelPass UI: failed to lock daemon via IPC: {}", error);
    }

    Ok(())
}

// Command: Check if vault is unlocked
#[tauri::command]
async fn is_unlocked(state: State<'_, AppState>) -> Result<bool, String> {
    Ok(state.vault_manager.lock().unwrap().is_some())
}

// Command: Check daemon availability/unlock state for browser integration.
#[tauri::command]
async fn daemon_status(state: State<'_, AppState>) -> Result<DaemonStatus, String> {
    if let Err(error) = ensure_daemon_running(&state).await {
        unlock_debug_log(&format!("daemon_status: daemon unavailable: {}", error));
        return Ok(DaemonStatus {
            available: false,
            unlocked: false,
            message: Some(error),
        });
    }

    Ok(fetch_daemon_status().await)
}

// Command: List entries
#[tauri::command]
async fn list_entries(state: State<'_, AppState>) -> Result<Vec<EntrySummary>, String> {
    let vault_manager = state.vault_manager.lock().unwrap();
    let vault = vault_manager.as_ref().ok_or("Vault not unlocked")?;
    vault.list_entries().map_err(|e| e.to_string())
}

// Command: Get entry
#[tauri::command]
async fn get_entry(entry_id: i64, state: State<'_, AppState>) -> Result<Entry, String> {
    let vault_manager = state.vault_manager.lock().unwrap();
    let vault = vault_manager.as_ref().ok_or("Vault not unlocked")?;
    vault.get_entry(entry_id).map_err(|e| e.to_string())
}

// Command: Add entry
#[tauri::command]
async fn add_entry(entry: Entry, state: State<'_, AppState>) -> Result<i64, String> {
    let vault_manager = state.vault_manager.lock().unwrap();
    let vault = vault_manager.as_ref().ok_or("Vault not unlocked")?;
    vault.add_entry(&entry).map_err(|e| e.to_string())
}

// Command: Update entry
#[tauri::command]
async fn update_entry(
    entry_id: i64,
    entry: Entry,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let vault_manager = state.vault_manager.lock().unwrap();
    let vault = vault_manager.as_ref().ok_or("Vault not unlocked")?;
    vault
        .update_entry(entry_id, &entry)
        .map_err(|e| e.to_string())
}

// Command: Delete entry
#[tauri::command]
async fn delete_entry(entry_id: i64, state: State<'_, AppState>) -> Result<(), String> {
    let vault_manager = state.vault_manager.lock().unwrap();
    let vault = vault_manager.as_ref().ok_or("Vault not unlocked")?;
    vault.delete_entry(entry_id).map_err(|e| e.to_string())
}

// Command: Generate password
#[tauri::command]
async fn generate_password(length: usize, include_symbols: bool) -> String {
    use sentinelpass_core::crypto::{generate_password, PasswordGeneratorConfig};

    let config = PasswordGeneratorConfig {
        length,
        include_lowercase: true,
        include_uppercase: true,
        include_digits: true,
        include_symbols,
        exclude_ambiguous: true,
    };

    generate_password(&config).unwrap_or_else(|_| "Password generation failed".to_string())
}

// Command: Check password strength
#[tauri::command]
async fn check_password_strength(password: String) -> Result<PasswordAnalysis, String> {
    use sentinelpass_core::crypto::analyze_password;

    let analysis = analyze_password(&password).map_err(|e| e.to_string())?;
    Ok(PasswordAnalysis {
        strength: analysis.strength.as_str().to_string(),
        score: analysis.strength.score(),
        entropy_bits: analysis.entropy_bits,
        crack_time_human: analysis.crack_time_human(),
        warnings: analysis.warnings,
        suggestions: analysis.suggestions,
        has_lowercase: analysis.has_lowercase,
        has_uppercase: analysis.has_uppercase,
        has_digits: analysis.has_digits,
        has_symbols: analysis.has_symbols,
    })
}

// Command: Check if TOTP is configured for an entry
#[tauri::command]
async fn has_totp(entry_id: i64, state: State<'_, AppState>) -> Result<bool, String> {
    let vault_manager = state.vault_manager.lock().unwrap();
    let vault = vault_manager.as_ref().ok_or("Vault not unlocked")?;
    match vault.get_totp_metadata(entry_id) {
        Ok(_) => Ok(true),
        Err(sentinelpass_core::PasswordManagerError::NotFound(_)) => Ok(false),
        Err(e) => Err(e.to_string()),
    }
}

// Command: Get current TOTP code for an entry
#[tauri::command]
async fn get_totp_code(
    entry_id: i64,
    state: State<'_, AppState>,
) -> Result<TotpCodeResponse, String> {
    let vault_manager = state.vault_manager.lock().unwrap();
    let vault = vault_manager.as_ref().ok_or("Vault not unlocked")?;
    let code = vault
        .generate_totp_code(entry_id)
        .map_err(|e| e.to_string())?;
    Ok(TotpCodeResponse {
        code: code.code,
        seconds_remaining: code.seconds_remaining,
    })
}

// Command: Get TOTP metadata for an entry
#[tauri::command]
async fn get_totp_metadata(
    entry_id: i64,
    state: State<'_, AppState>,
) -> Result<Option<TotpMetadataResponse>, String> {
    let vault_manager = state.vault_manager.lock().unwrap();
    let vault = vault_manager.as_ref().ok_or("Vault not unlocked")?;
    match vault.get_totp_metadata(entry_id) {
        Ok(meta) => Ok(Some(TotpMetadataResponse {
            algorithm: meta.algorithm.to_string(),
            digits: meta.digits,
            period: meta.period,
            issuer: meta.issuer,
            account_name: meta.account_name,
        })),
        Err(sentinelpass_core::PasswordManagerError::NotFound(_)) => Ok(None),
        Err(e) => Err(e.to_string()),
    }
}

// Command: Add or update TOTP configuration for an entry
#[tauri::command]
#[allow(clippy::too_many_arguments)]
async fn set_totp(
    entry_id: i64,
    secret: Option<String>,
    otpauth_uri: Option<String>,
    algorithm: Option<String>,
    digits: Option<u8>,
    period: Option<u32>,
    issuer: Option<String>,
    account_name: Option<String>,
    state: State<'_, AppState>,
) -> Result<String, String> {
    let vault_manager = state.vault_manager.lock().unwrap();
    let vault = vault_manager.as_ref().ok_or("Vault not unlocked")?;

    let parsed = if let Some(uri) = otpauth_uri.as_ref().filter(|v| !v.trim().is_empty()) {
        Some(parse_otpauth_uri(uri).map_err(|e| e.to_string())?)
    } else {
        None
    };

    let secret_value = secret
        .as_ref()
        .filter(|v| !v.trim().is_empty())
        .cloned()
        .or_else(|| parsed.as_ref().map(|p| p.secret_base32.clone()))
        .ok_or("TOTP secret is required (or provide otpauth URI)")?;

    let algorithm_value = if let Some(raw) = algorithm.as_ref().filter(|v| !v.trim().is_empty()) {
        raw.parse::<TotpAlgorithm>().map_err(|e| e.to_string())?
    } else {
        parsed
            .as_ref()
            .map(|p| p.algorithm)
            .unwrap_or(TotpAlgorithm::Sha1)
    };

    let digits_value = digits
        .or_else(|| parsed.as_ref().map(|p| p.digits))
        .unwrap_or(6);
    let period_value = period
        .or_else(|| parsed.as_ref().map(|p| p.period))
        .unwrap_or(30);
    let issuer_value = issuer.or_else(|| parsed.as_ref().and_then(|p| p.issuer.clone()));
    let account_value =
        account_name.or_else(|| parsed.as_ref().and_then(|p| p.account_name.clone()));

    vault
        .add_totp_secret(
            entry_id,
            &secret_value,
            algorithm_value,
            digits_value,
            period_value,
            issuer_value.as_deref(),
            account_value.as_deref(),
        )
        .map_err(|e| e.to_string())?;

    Ok("TOTP saved".to_string())
}

// Command: Remove TOTP configuration from an entry
#[tauri::command]
async fn remove_totp(entry_id: i64, state: State<'_, AppState>) -> Result<String, String> {
    let vault_manager = state.vault_manager.lock().unwrap();
    let vault = vault_manager.as_ref().ok_or("Vault not unlocked")?;
    vault
        .remove_totp_secret(entry_id)
        .map_err(|e| e.to_string())?;
    Ok("TOTP removed".to_string())
}

fn normalize_url_for_launch(url: &str) -> Result<String, String> {
    let trimmed = url.trim();
    if trimmed.is_empty() {
        return Err("URL is required".to_string());
    }
    if trimmed.chars().any(char::is_whitespace) {
        return Err("URL must not contain spaces".to_string());
    }

    let candidate = if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        trimmed.to_string()
    } else {
        format!("https://{}", trimmed)
    };

    if !(candidate.starts_with("http://") || candidate.starts_with("https://")) {
        return Err("Only http/https URLs are supported".to_string());
    }

    Ok(candidate)
}

// Command: Open entry URL in system default browser.
#[tauri::command]
async fn open_entry_url(url: String) -> Result<(), String> {
    let normalized = normalize_url_for_launch(&url)?;

    #[cfg(target_os = "windows")]
    {
        Command::new("explorer")
            .arg(&normalized)
            .spawn()
            .map_err(|e| format!("Failed to open URL in default browser: {}", e))?;
    }

    #[cfg(target_os = "macos")]
    {
        Command::new("open")
            .arg(&normalized)
            .spawn()
            .map_err(|e| format!("Failed to open URL in default browser: {}", e))?;
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    {
        Command::new("xdg-open")
            .arg(&normalized)
            .spawn()
            .map_err(|e| format!("Failed to open URL in default browser: {}", e))?;
    }

    Ok(())
}

#[derive(Serialize, Deserialize)]
pub struct PasswordAnalysis {
    strength: String,
    score: u8,
    entropy_bits: f64,
    crack_time_human: String,
    warnings: Vec<String>,
    suggestions: Vec<String>,
    has_lowercase: bool,
    has_uppercase: bool,
    has_digits: bool,
    has_symbols: bool,
}

#[derive(Serialize, Deserialize)]
pub struct BiometricStatus {
    method_name: String,
    available: bool,
    enrolled: bool,
    configured: bool,
}

#[derive(Serialize, Deserialize)]
pub struct TotpCodeResponse {
    code: String,
    seconds_remaining: u32,
}

#[derive(Serialize, Deserialize)]
pub struct TotpMetadataResponse {
    algorithm: String,
    digits: u8,
    period: u32,
    issuer: Option<String>,
    account_name: Option<String>,
}

fn main() {
    unlock_debug_log("startup: sentinelpass-ui main() entered");
    let app = tauri::Builder::default()
        .manage(AppState {
            vault_manager: Arc::new(Mutex::new(None)),
            daemon_process: Arc::new(Mutex::new(None)),
        })
        .setup(|app| {
            if let Ok(resource_dir) = app.path().resource_dir() {
                let _ = RESOURCE_DIR.set(resource_dir.clone());
                unlock_debug_log(&format!("setup: resource_dir={}", resource_dir.display()));
            }
            let app_handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                let state = app_handle.state::<AppState>();
                if let Err(error) = ensure_daemon_running(&state).await {
                    unlock_debug_log(&format!(
                        "setup: failed to start managed daemon automatically: {}",
                        error
                    ));
                } else {
                    unlock_debug_log("setup: managed daemon is ready");
                }
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            create_vault,
            unlock_vault,
            unlock_vault_biometric,
            lock_vault,
            is_unlocked,
            daemon_status,
            biometric_status,
            enable_biometric_unlock,
            disable_biometric_unlock,
            list_entries,
            get_entry,
            add_entry,
            update_entry,
            delete_entry,
            generate_password,
            check_password_strength,
            has_totp,
            get_totp_code,
            get_totp_metadata,
            set_totp,
            remove_totp,
            open_entry_url,
        ])
        .build(tauri::generate_context!())
        .expect("error while building tauri application");

    app.run(|app_handle, event| {
        if matches!(event, tauri::RunEvent::Exit) {
            let state = app_handle.state::<AppState>();
            stop_managed_daemon(&state);
        }
    });
}
