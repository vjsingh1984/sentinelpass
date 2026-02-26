//! macOS-specific auto-fill implementation
//!
//! Uses macOS Accessibility API, NSPasteboard, and CGEvent for auto-fill.
//!
//! Note: This module requires Accessibility permissions for full functionality.
//! Users must grant the app Accessibility permissions in:
//! System Preferences > Security & Privacy > Privacy > Accessibility

use super::{AutoFillResult, CredentialMatch};
use crate::{PasswordManagerError, Result};
use objc::{msg_send, sel, sel_impl, class};
use cocoa::base::{id, nil};
use cocoa::foundation::{NSAutoreleasePool, NSString};
use std::ffi::c_char;
use std::ffi::CStr;
use std::thread;
use std::time::Duration;

/// Auto-fill context for macOS
pub struct AutoFillContext {
    /// Active window title
    pub window_title: String,
    /// Bundle identifier of active app
    pub bundle_id: String,
    /// Detected domain/URL
    pub domain: Option<String>,
    /// Process ID of active application
    pub pid: i32,
}

/// Get the current auto-fill context
///
/// Detects the active window and attempts to extract the domain/URL
pub fn get_context() -> Result<AutoFillContext> {
    unsafe {
        // Create autorelease pool
        let pool = NSAutoreleasePool::new(nil);

        // Get the shared workspace
        let workspace_class = class!(NSWorkspace);
        let workspace: id = msg_send![workspace_class, sharedWorkspace];

        if workspace == nil {
            let _: () = msg_send![pool, drain];
            return Err(PasswordManagerError::InvalidInput(
                "Failed to get workspace".to_string(),
            ));
        }

        // Get the frontmost application
        let frontmost_app: id = msg_send![workspace, frontmostApplication];

        if frontmost_app == nil {
            let _: () = msg_send![pool, drain];
            // Fallback: return minimal context
            return Ok(AutoFillContext {
                window_title: String::new(),
                bundle_id: String::new(),
                domain: None,
                pid: 0,
            });
        }

        // Get bundle ID
        let bundle_id: id = msg_send![frontmost_app, bundleIdentifier];
        let bundle_id_str = if bundle_id != nil {
            nsstring_to_string(bundle_id)
        } else {
            String::new()
        };

        // Get process ID
        let pid: i32 = msg_send![frontmost_app, processIdentifier];

        // Get application name as window title
        let app_name: id = msg_send![frontmost_app, localizedName];
        let window_title = if app_name != nil {
            nsstring_to_string(app_name)
        } else {
            String::new()
        };

        // Try to extract domain from title
        let domain = extract_domain_from_title(&window_title);

        // Drain the pool
        let _: () = msg_send![pool, drain];

        Ok(AutoFillContext {
            window_title,
            bundle_id: bundle_id_str,
            domain,
            pid,
        })
    }
}

/// Auto-fill via clipboard
///
/// Copies username/password to clipboard and notifies user
pub async fn autofill_via_clipboard(
    credential: &CredentialMatch,
    vault_manager: &crate::vault::VaultManager,
) -> Result<AutoFillResult> {
    // Parse entry ID
    let entry_id: i64 = credential.id.parse().map_err(|_| {
        PasswordManagerError::InvalidInput("Invalid entry ID".to_string())
    })?;

    // Get the full entry (password is included in decrypted Entry)
    let entry = vault_manager.get_entry(entry_id)?;

    unsafe {
        // Create autorelease pool
        let pool = NSAutoreleasePool::new(nil);

        // Get the general pasteboard
        let pasteboard_class = class!(NSPasteboard);
        let pasteboard: id = msg_send![pasteboard_class, generalPasteboard];

        if pasteboard != nil {
            // Copy username to clipboard first
            if !entry.username.is_empty() {
                let _: () = msg_send![pasteboard, clearContents];
                let ns_string = NSString::alloc(nil).init_str(&entry.username);
                let utf8_type = NSString::alloc(nil).init_str("public.utf8-plain-text");
                let _: () = msg_send![pasteboard, setString: ns_string forType: utf8_type];
            }

            // Small delay
            thread::sleep(Duration::from_millis(100));

            // Copy password
            let _: () = msg_send![pasteboard, clearContents];
            let ns_string = NSString::alloc(nil).init_str(&entry.password);
            let utf8_type = NSString::alloc(nil).init_str("public.utf8-plain-text");
            let _: () = msg_send![pasteboard, setString: ns_string forType: utf8_type];
        }

        // Drain the pool
        let _: () = msg_send![pool, drain];
    }

    // In production, show a notification using NSUserNotification
    Ok(AutoFillResult::Success)
}

/// Auto-fill via direct input simulation
///
/// Simulates keyboard input to type username/password directly
pub async fn autofill_via_input(
    credential: &CredentialMatch,
    vault_manager: &crate::vault::VaultManager,
) -> Result<AutoFillResult> {
    // Parse entry ID
    let entry_id: i64 = credential.id.parse().map_err(|_| {
        PasswordManagerError::InvalidInput("Invalid entry ID".to_string())
    })?;

    // Get the full entry (password is included in decrypted Entry)
    let entry = vault_manager.get_entry(entry_id)?;

    unsafe {
        // Small delay to ensure target window is ready
        thread::sleep(Duration::from_millis(100));

        // Type username
        if !entry.username.is_empty() {
            simulate_typing(&entry.username)?;
            simulate_key_stroke(48)?; // Tab key to move to password field
        }

        // Small delay between fields
        thread::sleep(Duration::from_millis(100));

        // Type password
        simulate_typing(&entry.password)?;

        // Press Enter to submit
        simulate_key_stroke(36)?; // Return key

        Ok(AutoFillResult::Success)
    }
}

/// Register global hotkey for auto-fill
///
/// Registers Command+Shift+P as the auto-fill hotkey
///
/// Note: This requires Accessibility permissions. The user must grant
/// the app Accessibility permissions in System Preferences > Security & Privacy > Privacy
///
/// Also requires creating an event tap in a separate thread with a runloop.
pub fn register_hotkey(_modifiers: u32, _vk: u32) -> Result<()> {
    // Full implementation requires:
    // 1. Creating an event tap using CGEventTapCreate
    // 2. Installing a callback to listen for the hotkey combination
    // 3. Running a CFRunLoop in a separate thread to process events
    //
    // For now, return NotImplemented as this requires significant setup
    Err(PasswordManagerError::NotImplemented(
        "Hotkey registration requires Accessibility permissions and event loop setup".to_string(),
    ))
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Convert NSString to String
unsafe fn nsstring_to_string(ns_string: id) -> String {
    if ns_string == nil {
        return String::new();
    }

    let c_string: *const c_char = msg_send![ns_string, UTF8String];
    if c_string.is_null() {
        return String::new();
    }

    CStr::from_ptr(c_string)
        .to_string_lossy()
        .to_string()
}

/// Extract domain from window title
fn extract_domain_from_title(title: &str) -> Option<String> {
    // Remove common browser/app suffixes
    let title = title
        .replace(" - Google Chrome", "")
        .replace(" - Safari", "")
        .replace(" - Firefox", "")
        .replace(" — Brave", "")
        .replace(" - Microsoft Edge", "")
        .replace(" - Vivaldi", "")
        .replace(" - Opera", "")
        .trim()
        .to_string();

    // Try to extract URL from title
    if title.starts_with("https://") || title.starts_with("http://") {
        if let Some(start) = title.find("://") {
            if let Some(end) = title[start + 3..].find('/') {
                return Some(title[start + 3..start + 3 + end].to_string());
            } else {
                return Some(title[start + 3..].to_string());
            }
        }
    }

    // Check for domain-like strings
    if title.contains('.') && !title.contains(' ') {
        // Check if it looks like a domain (has at least one dot)
        let parts: Vec<&str> = title.split('.').collect();
        if parts.len() >= 2 {
            return Some(title);
        }
    }

    None
}

// ============================================================================
// Keyboard Simulation (using low-level CGEvent FFI)
// ============================================================================

/// Simulate typing a string
unsafe fn simulate_typing(text: &str) -> Result<()> {
    for ch in text.chars() {
        let cg_code = char_to_cg_code(ch)?;
        simulate_key_event(cg_code, true)?; // key down
        simulate_key_event(cg_code, false)?; // key up
    }
    Ok(())
}

/// Simulate a key event using CGEvent API
unsafe fn simulate_key_event(keycode: u16, key_down: bool) -> Result<()> {
    // Low-level FFI declarations for CGEvent
    #[repr(C)]
    enum CGEventTapLocation {
        HID = 0,
        Session = 1,
        AnnotatedSession = 2,
    }

    #[repr(C)]
    enum CGEventSourceStateID {
        Private = -2,
        CombinedSessionState = -1,
        HIDSystemState = 0,
    }

    extern "C" {
        fn CGEventCreateKeyboardEvent(
            source: *const std::ffi::c_void,
            keycode: u16,
            keydown: bool,
        ) -> *mut std::ffi::c_void;

        fn CGEventPost(
            tap: CGEventTapLocation,
            event: *mut std::ffi::c_void,
        );

        fn CFRelease(obj: *const std::ffi::c_void);
    }

    let event = CGEventCreateKeyboardEvent(
        std::ptr::null(),
        keycode,
        key_down,
    );

    if !event.is_null() {
        CGEventPost(CGEventTapLocation::Session, event);
        CFRelease(event);
    }

    Ok(())
}

/// Convert character to CGKeyCode
///
/// Uses macOS virtual key code constants
unsafe fn char_to_cg_code(ch: char) -> Result<u16> {
    // Map characters to virtual key codes (kVK_* constants)
    let vk = match ch {
        'a' | 'A' => 0x00,  // kVK_ANSI_A
        'b' | 'B' => 0x0B,  // kVK_ANSI_B
        'c' | 'C' => 0x08,  // kVK_ANSI_C
        'd' | 'D' => 0x02,  // kVK_ANSI_D
        'e' | 'E' => 0x0E,  // kVK_ANSI_E
        'f' | 'F' => 0x03,  // kVK_ANSI_F
        'g' | 'G' => 0x05,  // kVK_ANSI_G
        'h' | 'H' => 0x04,  // kVK_ANSI_H
        'i' | 'I' => 0x22,  // kVK_ANSI_I
        'j' | 'J' => 0x26,  // kVK_ANSI_J
        'k' | 'K' => 0x28,  // kVK_ANSI_K
        'l' | 'L' => 0x25,  // kVK_ANSI_L
        'm' | 'M' => 0x2E,  // kVK_ANSI_M
        'n' | 'N' => 0x2D,  // kVK_ANSI_N
        'o' | 'O' => 0x1F,  // kVK_ANSI_O
        'p' | 'P' => 0x23,  // kVK_ANSI_P
        'q' | 'Q' => 0x0C,  // kVK_ANSI_Q
        'r' | 'R' => 0x0F,  // kVK_ANSI_R
        's' | 'S' => 0x01,  // kVK_ANSI_S
        't' | 'T' => 0x11,  // kVK_ANSI_T
        'u' | 'U' => 0x20,  // kVK_ANSI_U
        'v' | 'V' => 0x09,  // kVK_ANSI_V
        'w' | 'W' => 0x0D,  // kVK_ANSI_W
        'x' | 'X' => 0x07,  // kVK_ANSI_X
        'y' | 'Y' => 0x10,  // kVK_ANSI_Y
        'z' | 'Z' => 0x06,  // kVK_ANSI_Z
        '0' => 0x1D,        // kVK_ANSI_0
        '1' => 0x12,        // kVK_ANSI_1
        '2' => 0x13,        // kVK_ANSI_2
        '3' => 0x14,        // kVK_ANSI_3
        '4' => 0x15,        // kVK_ANSI_4
        '5' => 0x17,        // kVK_ANSI_5
        '6' => 0x16,        // kVK_ANSI_6
        '7' => 0x1A,        // kVK_ANSI_7
        '8' => 0x1C,        // kVK_ANSI_8
        '9' => 0x19,        // kVK_ANSI_9
        ' ' => 0x31,        // kVK_Space
        '\t' => 0x30,       // kVK_Tab
        '\n' => 0x24,       // kVK_Return
        '-' => 0x1B,        // kVK_ANSI_Minus
        '=' => 0x18,        // kVK_ANSI_Equal
        '@' => 0x32,        // kVK_ANSI_Grave (with shift)
        '.' => 0x2F,        // kVK_ANSI_Period
        ',' => 0x2B,        // kVK_ANSI_Comma
        '/' => 0x2C,        // kVK_ANSI_Slash
        ':' => 0x29,        // kVK_ANSI_Semicolon (with shift)
        _ => {
            // For special characters, we'd need a more comprehensive mapping
            // or use Unicode input events via CGEventCreateUnicodeStringEvent
            return Err(PasswordManagerError::InvalidInput(format!(
                "Cannot type character: {}",
                ch
            )));
        }
    };

    Ok(vk)
}

/// Simulate a key stroke (down and up)
unsafe fn simulate_key_stroke(vk: u32) -> Result<()> {
    simulate_key_event(vk as u16, true)?;
    simulate_key_event(vk as u16, false)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_domain_from_title() {
        // Test browser suffix removal
        assert_eq!(
            extract_domain_from_title("example.com - Google Chrome"),
            Some("example.com".to_string())
        );

        // Test URL extraction
        assert_eq!(
            extract_domain_from_title("https://www.example.com/path - Safari"),
            Some("www.example.com".to_string())
        );

        // Test plain domain
        assert_eq!(
            extract_domain_from_title("example.com"),
            Some("example.com".to_string())
        );

        // Test non-domain
        assert_eq!(extract_domain_from_title("Not a domain"), None);
    }
}
