// Prevents additional console window on Windows in release builds
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use sentinelpass_core::{VaultManager, Entry, EntrySummary};
use std::sync::{Arc, Mutex};
use tauri::State;
use serde::{Deserialize, Serialize};

// Application state
struct AppState {
    vault_manager: Arc<Mutex<Option<VaultManager>>>,
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
    let vault_path = sentinelpass_core::get_default_vault_path();

    if !vault_path.exists() {
        return Err("No vault found".to_string());
    }

    match VaultManager::open(&vault_path, master_password.as_bytes()) {
        Ok(vault) => {
            *state.vault_manager.lock().unwrap() = Some(vault);
            Ok("Vault unlocked successfully".to_string())
        }
        Err(e) => Err(format!("Failed to unlock vault: {}", e)),
    }
}

// Command: Lock vault
#[tauri::command]
async fn lock_vault(state: State<'_, AppState>) -> Result<(), String> {
    let mut vault_manager = state.vault_manager.lock().unwrap();
    if let Some(ref mut vault) = *vault_manager {
        vault.lock();
    }
    *vault_manager = None;
    Ok(())
}

// Command: Check if vault is unlocked
#[tauri::command]
async fn is_unlocked(state: State<'_, AppState>) -> Result<bool, String> {
    Ok(state.vault_manager.lock().unwrap().is_some())
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
async fn update_entry(entry_id: i64, entry: Entry, state: State<'_, AppState>) -> Result<(), String> {
    let vault_manager = state.vault_manager.lock().unwrap();
    let vault = vault_manager.as_ref().ok_or("Vault not unlocked")?;
    vault.update_entry(entry_id, &entry).map_err(|e| e.to_string())
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
    use sentinelpass_core::crypto::{PasswordGeneratorConfig, generate_password};

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

fn main() {
    tauri::Builder::default()
        .manage(AppState {
            vault_manager: Arc::new(Mutex::new(None)),
        })
        .invoke_handler(tauri::generate_handler![
            create_vault,
            unlock_vault,
            lock_vault,
            is_unlocked,
            list_entries,
            get_entry,
            add_entry,
            update_entry,
            delete_entry,
            generate_password,
            check_password_strength,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
