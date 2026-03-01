//! Windows-specific auto-fill implementation
//!
//! Uses Windows API to:
//! - Detect active window and domain
//! - Simulate keyboard input for auto-fill
//! - Manage clipboard for credential copying
//! - Register global hotkeys

use super::{AutoFillResult, CredentialMatch};
use crate::{PasswordManagerError, Result};
use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use std::ptr;
use windows::core::PCWSTR;
use windows::Win32::Foundation::HWND;
use windows::Win32::System::Threading::{GetCurrentProcessId, GetCurrentThreadId};
use windows::Win32::UI::WindowsAndMessaging;

type UINT = u32;
type WPARAM = usize;
type LPARAM = isize;
type LRESULT = isize;
type HGLOBAL = isize;

// Windows API constants
const WM_HOTKEY: UINT = 0x0312;
const MOD_CONTROL: UINT = 0x0002;
const MOD_SHIFT: UINT = 0x0004;
const VK_F5: UINT = 0x74; // Example hotkey: Ctrl+Shift+F5
const VK_RETURN: u32 = 0x0D; // Return key

// Input constants
const INPUT_KEYBOARD: UINT = 1;
const KEYEVENTF_KEYUP: UINT = 0x0002;

// Clipboard formats
const CF_UNICODETEXT: UINT = 13;

/// Get the current auto-fill context
///
/// Detects the active window and attempts to extract the domain/URL
pub fn get_context() -> Result<AutoFillContext> {
    unsafe {
        // Get foreground window
        let hwnd = GetForegroundWindow();
        if hwnd.is_invalid() {
            return Err(PasswordManagerError::InvalidInput(
                "No active window found".to_string(),
            ));
        }

        // Get window title
        let mut title_buffer = [0u16; 512];
        let length = GetWindowTextW(hwnd, &mut title_buffer);

        let title = if length > 0 {
            OsString::from_wide(&title_buffer[..length as usize])
                .to_string_lossy()
                .to_string()
        } else {
            String::new()
        };

        // Try to extract domain from title
        // This is a simple implementation - in production, you'd also want to:
        // - Detect the browser type
        // - Read the URL from the address bar
        // - Use Accessibility API to get URL directly
        let domain = extract_domain_from_title(&title);

        Ok(AutoFillContext {
            window_handle: hwnd,
            window_title: title,
            domain,
        })
    }
}

/// Extract domain from window title
///
/// Simple heuristic-based extraction for titles like:
/// - "Example - Google Chrome"
/// - "Example.com - Microsoft Edge"
/// - "Sign in - Example.com"
fn extract_domain_from_title(title: &str) -> Option<String> {
    // Remove common browser suffixes
    let title = title
        .replace(" - Google Chrome", "")
        .replace(" - Microsoft Edge", "")
        .replace(" - Mozilla Firefox", "")
        .replace(" - Brave", "")
        .replace("Sign in - ", "")
        .replace("Log in to ", "")
        .trim();

    // Simple domain detection
    if title.contains('.') && !title.contains(' ') {
        // Likely a domain like "example.com"
        Some(title.to_string())
    } else if title.starts_with("https://") || title.starts_with("http://") {
        // URL format
        if let Some(start) = title.find("://") {
            if let Some(end) = title[start + 3..].find('/') {
                Some(title[start + 3..start + 3 + end].to_string())
            } else {
                Some(title[start + 3..].to_string())
            }
        } else {
            None
        }
    } else {
        None
    }
}

/// Auto-fill via clipboard
///
/// Copies username/password to clipboard and notifies user
pub fn autofill_via_clipboard(
    credential: &CredentialMatch,
    vault_manager: &crate::vault::VaultManager,
) -> Result<AutoFillResult> {
    // Get the full entry
    let entry_id = credential
        .id
        .parse::<i64>()
        .map_err(|_| PasswordManagerError::InvalidInput("Invalid entry ID format".to_string()))?;
    let entry = vault_manager.get_entry(entry_id)?;

    // Copy username to clipboard first
    if !entry.username.is_empty() {
        set_clipboard_text(&entry.username)?;

        // In production, you'd show a notification here
        // telling user "Username copied to clipboard, press Ctrl+V"
    }

    // Then copy password
    set_clipboard_text(&entry.password)?;

    // In production, show notification "Password copied to clipboard"

    Ok(AutoFillResult::Success)
}

/// Auto-fill via direct input simulation
///
/// Simulates keyboard input to type username/password directly
pub fn autofill_via_input(
    credential: &CredentialMatch,
    vault_manager: &crate::vault::VaultManager,
) -> Result<AutoFillResult> {
    // Get the full entry
    let entry_id = credential
        .id
        .parse::<i64>()
        .map_err(|_| PasswordManagerError::InvalidInput("Invalid entry ID format".to_string()))?;
    let entry = vault_manager.get_entry(entry_id)?;

    unsafe {
        // Small delay to ensure target window is ready
        std::thread::sleep(std::time::Duration::from_millis(100));

        // Type username
        if !entry.username.is_empty() {
            simulate_typing(&entry.username)?;
            simulate_key_stroke(VK_RETURN as u32)?; // Tab or Enter to move to password field
        }

        // Small delay between fields
        std::thread::sleep(std::time::Duration::from_millis(100));

        // Type password
        simulate_typing(&entry.password)?;

        Ok(AutoFillResult::Success)
    }
}

/// Set clipboard text
fn set_clipboard_text(text: &str) -> Result<()> {
    unsafe {
        if !OpenClipboard(HWND(0)) {
            return Err(PasswordManagerError::Io(std::io::Error::last_os_error()));
        }

        // Convert to UTF-16
        let text_wide: Vec<u16> = text.encode_utf16().collect();
        let size = text_wide.len() * 2;

        // Allocate global memory
        let handle = LocalAlloc(LMEM_FIXED, size as usize);
        if handle == 0 {
            CloseClipboard();
            return Err(PasswordManagerError::Io(std::io::Error::last_os_error()));
        }

        // Copy text to global memory
        let dst = handle as *mut u16;
        for (i, &ch) in text_wide.iter().enumerate() {
            *dst.add(i) = ch;
        }

        // Set clipboard data
        let result = SetClipboardData(CF_UNICODETEXT, handle);
        if result == 0 {
            LocalFree(handle);
            CloseClipboard();
            return Err(PasswordManagerError::Io(std::io::Error::last_os_error()));
        }

        CloseClipboard();
        Ok(())
    }
}

/// Simulate typing a string
unsafe fn simulate_typing(text: &str) -> Result<()> {
    for ch in text.chars() {
        let vk = char_to_virtual_key(ch)?;
        simulate_key_stroke(vk)?;
    }
    Ok(())
}

/// Simulate a key press (down and up)
unsafe fn simulate_key_stroke(vk: u32) -> Result<()> {
    let inputs = [
        INPUT {
            type_: INPUT_KEYBOARD,
            ki: KEYBDINPUT {
                wVk: vk as u16,
                dwFlags: 0,
                wScan: 0,
                time: 0,
                dwExtraInfo: 0,
            },
        },
        INPUT {
            type_: INPUT_KEYBOARD,
            ki: KEYBDINPUT {
                wVk: vk as u16,
                dwFlags: KEYEVENTF_KEYUP,
                wScan: 0,
                time: 0,
                dwExtraInfo: 0,
            },
        },
    ];

    let result = SendInput(
        2,
        &inputs as *const INPUT,
        std::mem::size_of::<INPUT>() as i32,
    );
    if result != 2 {
        return Err(PasswordManagerError::Io(std::io::Error::last_os_error()));
    }

    Ok(())
}

/// Convert character to virtual key code
unsafe fn char_to_virtual_key(ch: char) -> Result<u32> {
    // Map character to virtual key using VkKeyScan
    let vk = VkKeyScanW(ch as u16);

    if vk == 0xFFFF {
        // Character not found, try Unicode input
        // For simplicity, we'll skip this for now
        // In production, use SendInput with Unicode events
        return Err(PasswordManagerError::InvalidInput(format!(
            "Cannot type character: {}",
            ch
        )));
    }

    Ok((vk & 0xFF) as u32)
}

/// Register global hotkey for auto-fill
///
/// Registers Ctrl+Shift+F5 as the auto-fill hotkey
pub fn register_hotkey(modifiers: u32, vk: u32) -> Result<()> {
    unsafe {
        // Get the current process's main window (or console window)
        let hwnd = GetForegroundWindow(); // In production, use actual app window

        if !RegisterHotKey(hwnd, 1, modifiers, vk) {
            return Err(PasswordManagerError::Io(std::io::Error::last_os_error()));
        }

        Ok(())
    }
}

// Windows API FFI declarations
#[repr(C)]
struct KEYBDINPUT {
    wVk: u16,
    dwFlags: u32,
    wScan: u16,
    time: u32,
    dwExtraInfo: usize,
}

#[repr(C)]
struct INPUT {
    type_: u32,
    ki: KEYBDINPUT,
}

extern "system" {
    fn GetForegroundWindow() -> HWND;
    fn GetWindowTextW(hwnd: HWND, lpString: &mut [u16], nMaxCount: i32) -> i32;
    fn OpenClipboard(hwnd: HWND) -> i32;
    fn CloseClipboard() -> i32;
    fn SetClipboardData(uFormat: u32, hMem: HGLOBAL) -> HGLOBAL;
    fn LocalAlloc(uFlags: u32, uBytes: usize) -> HGLOBAL;
    fn LocalFree(hMem: HGLOBAL) -> HGLOBAL;
    fn SendInput(cInputs: u32, pInputs: *const INPUT, cbSize: i32) -> u32;
    fn VkKeyScanW(ch: u16) -> i32;
    fn RegisterHotKey(hwnd: HWND, id: i32, fsModifiers: u32, vk: u32) -> i32;
}

const LMEM_FIXED: u32 = 0x0000;

/// Windows-specific auto-fill context
pub struct AutoFillContext {
    /// Window handle
    pub window_handle: HWND,
    /// Window title
    pub window_title: String,
    /// Detected domain/URL
    pub domain: Option<String>,
}
