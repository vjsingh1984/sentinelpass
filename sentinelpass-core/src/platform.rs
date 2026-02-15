//! Platform-specific utilities for cross-platform support

use std::path::PathBuf;

/// Get the platform-specific data directory for storing application data
///
/// Returns:
/// - Windows: %APPDATA%\PasswordManager
/// - macOS: ~/Library/Application Support/PasswordManager
/// - Linux/Other: ~/.config/passwordmanager
pub fn get_data_dir() -> PathBuf {
    let base = dirs::data_local_dir()
        .or_else(dirs::data_dir)
        .or_else(|| dirs::home_dir().map(|h| h.join(".data")))
        .unwrap_or_else(|| PathBuf::from("."));

    base.join("PasswordManager")
}

/// Get the platform-specific config directory
///
/// Returns:
/// - Windows: %APPDATA%\PasswordManager
/// - macOS: ~/Library/Application Support/PasswordManager
/// - Linux/Other: ~/.config/passwordmanager
pub fn get_config_dir() -> PathBuf {
    let base = dirs::config_dir()
        .or_else(dirs::data_dir)
        .or_else(|| dirs::home_dir().map(|h| h.join(".config")))
        .unwrap_or_else(|| PathBuf::from("."));

    base.join("PasswordManager")
}

/// Get the default vault database path
pub fn get_default_vault_path() -> PathBuf {
    get_data_dir().join("vault.db")
}

/// Get the installation directory for binaries
///
/// Returns different paths based on platform:
/// - Windows: C:\Program Files\PasswordManager
/// - macOS: /Applications/PasswordManager
/// - Linux: /opt/passwordmanager
pub fn get_install_dir() -> PathBuf {
    if cfg!(target_os = "windows") {
        PathBuf::from(r"C:\Program Files\PasswordManager")
    } else if cfg!(target_os = "macos") {
        PathBuf::from("/Applications/PasswordManager")
    } else {
        PathBuf::from("/opt/passwordmanager")
    }
}

/// Get Chrome's native messaging hosts directory
///
/// Returns different paths based on platform:
/// - Windows: %LOCALAPPDATA%\Google\Chrome\User Data\Default\Native Messaging Hosts
/// - macOS: ~/Library/Application Support/Google/Chrome/NativeMessagingHosts
/// - Linux: ~/.config/google-chrome/NativeMessagingHosts
pub fn get_chrome_native_messaging_dir() -> Option<PathBuf> {
    if cfg!(target_os = "windows") {
        // Windows: %LOCALAPPDATA%\Google\Chrome\User Data\Default\Native Messaging Hosts
        std::env::var("LOCALAPPDATA").ok().map(|p| {
            PathBuf::from(p)
                .join("Google")
                .join("Chrome")
                .join("User Data")
                .join("Default")
                .join("Native Messaging Hosts")
        })
    } else if cfg!(target_os = "macos") {
        // macOS: ~/Library/Application Support/Google/Chrome/NativeMessagingHosts
        dirs::home_dir().map(|h| {
            h.join("Library")
                .join("Application Support")
                .join("Google")
                .join("Chrome")
                .join("NativeMessagingHosts")
        })
    } else {
        // Linux: ~/.config/google-chrome/NativeMessagingHosts
        dirs::home_dir().map(|h| {
            h.join(".config")
                .join("google-chrome")
                .join("NativeMessagingHosts")
        })
    }
}

/// Get the native messaging host manifest path
pub fn get_native_messaging_manifest_path() -> PathBuf {
    get_install_dir().join("com.passwordmanager.host.json")
}

/// Ensure the data directory exists, creating it if necessary
pub fn ensure_data_dir() -> std::io::Result<PathBuf> {
    let dir = get_data_dir();
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

/// Ensure the config directory exists, creating it if necessary
pub fn ensure_config_dir() -> std::io::Result<PathBuf> {
    let dir = get_config_dir();
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

/// Get the binary name for the current platform
///
/// Returns the name with .exe extension on Windows, without on Unix
pub fn get_binary_name(base: &str) -> String {
    if cfg!(target_os = "windows") {
        format!("{}.exe", base)
    } else {
        base.to_string()
    }
}

/// Get current platform as a string
pub fn get_platform() -> &'static str {
    if cfg!(target_os = "windows") {
        "windows"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(target_os = "linux") {
        "linux"
    } else {
        "unknown"
    }
}

/// Get current architecture as a string
pub fn get_arch() -> &'static str {
    if cfg!(target_arch = "x86_64") {
        "x86_64"
    } else if cfg!(target_arch = "aarch64") {
        "aarch64"
    } else if cfg!(target_arch = "x86") {
        "x86"
    } else if cfg!(target_arch = "arm") {
        "arm"
    } else {
        "unknown"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_data_dir() {
        let dir = get_data_dir();
        // The directory should end with PasswordManager
        assert!(dir.to_string_lossy().ends_with("PasswordManager"));
    }

    #[test]
    fn test_get_config_dir() {
        let dir = get_config_dir();
        // The directory should end with PasswordManager
        assert!(dir.to_string_lossy().ends_with("PasswordManager"));
    }

    #[test]
    fn test_get_default_vault_path() {
        let path = get_default_vault_path();
        // The path should end with vault.db
        assert!(path.to_string_lossy().ends_with("vault.db"));
    }

    #[test]
    fn test_get_binary_name() {
        let cli_name = get_binary_name("pm-cli");
        let host_name = get_binary_name("pm-host");

        // Verify names are not empty
        assert!(!cli_name.is_empty());
        assert!(!host_name.is_empty());

        // On Windows, should have .exe extension
        if cfg!(target_os = "windows") {
            assert!(cli_name.ends_with(".exe"));
            assert!(host_name.ends_with(".exe"));
        } else {
            assert!(!cli_name.ends_with(".exe"));
            assert!(!host_name.ends_with(".exe"));
        }
    }

    #[test]
    fn test_get_platform() {
        let platform = get_platform();
        assert!(!platform.is_empty());
        assert!(
            platform == "windows"
                || platform == "macos"
                || platform == "linux"
                || platform == "unknown"
        );
    }

    #[test]
    fn test_get_arch() {
        let arch = get_arch();
        assert!(!arch.is_empty());
    }
}
