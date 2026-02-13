//! Biometric authentication support (Windows Hello, Touch ID)

use serde::{Deserialize, Serialize};

/// Result of a biometric operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BiometricResult {
    /// User successfully authenticated
    Success,
    /// User cancelled the operation
    Cancelled,
    /// Biometric hardware not available
    NotAvailable,
    /// Biometric operation failed
    Failed(String),
    /// Biometric not enrolled
    NotEnrolled,
}

/// Biometric authentication manager
pub struct BiometricManager;

impl BiometricManager {
    /// Check if biometric authentication is available on this system
    pub fn is_available() -> bool {
        #[cfg(windows)]
        return self::windows::is_hello_available();

        #[cfg(target_os = "macos")]
        return self::macos::is_touch_id_available();

        #[cfg(not(any(windows, target_os = "macos")))]
        return false;
    }

    /// Check if biometric authentication is enrolled
    pub fn is_enrolled() -> bool {
        #[cfg(windows)]
        return self::windows::is_hello_enrolled();

        #[cfg(target_os = "macos")]
        return self::macos::is_touch_id_enrolled();

        #[cfg(not(any(windows, target_os = "macos")))]
        return false;
    }

    /// Prompt for biometric authentication
    /// Returns BiometricResult::Success if authenticated successfully
    pub fn authenticate(reason: &str) -> BiometricResult {
        #[cfg(windows)]
        return self::windows::authenticate_with_hello(reason);

        #[cfg(target_os = "macos")]
        return self::macos::authenticate_with_touch_id(reason);

        #[cfg(not(any(windows, target_os = "macos")))]
        return BiometricResult::NotAvailable;
    }

    /// Get a human-readable name for the biometric method on this platform
    pub fn get_method_name() -> &'static str {
        #[cfg(windows)]
        return "Windows Hello";

        #[cfg(target_os = "macos")]
        return "Touch ID";

        #[cfg(not(any(windows, target_os = "macos")))]
        return "Biometric Authentication";
    }
}

/// Windows-specific implementation using Windows Hello
#[cfg(windows)]
mod windows {
    use super::BiometricResult;

    pub fn is_hello_available() -> bool {
        // Check if Windows Hello is available
        // This requires calling UserConsentVerifierAvailability
        unsafe {
            use windows::Win32::System::Com::CoInitializeEx;
            use windows::Win32::System::Com::COINIT_MULTITHREADED;

            // Initialize COM
            let _ = CoInitializeEx(None, COINIT_MULTITHREADED);

            // For now, return true if we're on Windows 10+
            // A proper implementation would check UserConsentVerifierAvailability
            true
        }
    }

    pub fn is_hello_enrolled() -> bool {
        // Check if Windows Hello has been set up
        // This requires checking UserConsentVerifierAvailability
        true
    }

    pub fn authenticate_with_hello(_reason: &str) -> BiometricResult {
        // Use Windows.Security.Credentials.UI.UserConsentVerifier
        // This is a simplified stub implementation
        BiometricResult::NotAvailable
    }
}

/// macOS-specific implementation using Touch ID
#[cfg(target_os = "macos")]
mod macos {
    use super::BiometricResult;

    pub fn is_touch_id_available() -> bool {
        // Check if Touch ID is available on this device
        // This requires using the LocalAuthentication framework
        true
    }

    pub fn is_touch_id_enrolled() -> bool {
        // Check if Touch ID has been set up with at least one fingerprint
        true
    }

    pub fn authenticate_with_touch_id(_reason: &str) -> BiometricResult {
        // Use LocalAuthentication framework to prompt for Touch ID
        // This is a simplified stub implementation
        BiometricResult::NotAvailable
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_biometric_method_name() {
        let name = BiometricManager::get_method_name();
        #[cfg(windows)]
        assert_eq!(name, "Windows Hello");
        #[cfg(target_os = "macos")]
        assert_eq!(name, "Touch ID");
    }

    #[test]
    fn test_is_available() {
        // This test will pass on supported platforms
        let _ = BiometricManager::is_available();
    }

    #[test]
    fn test_is_enrolled() {
        // This test will pass on supported platforms
        let _ = BiometricManager::is_enrolled();
    }
}
