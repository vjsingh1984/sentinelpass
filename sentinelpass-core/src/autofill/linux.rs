//! Linux-specific auto-fill implementation
//!
//! Uses X11/Wayland APIs for auto-fill.
//!
//! ## X11 Support
//! - Xlib for window detection and properties
//! - XTest for keyboard simulation
//! - X clipboard for clipboard operations
//!
//! ## Wayland Support
//! Currently not implemented (requires Wayland client libraries and
//! virtual keyboard protocol support).
//!
//! ## Environment Variables
//! - `SENTINELPASS_DISPLAY`: Override the DISPLAY variable (default: ":0")
//! - `SENTINELPASS_WAYLAND`: Set to "1" to force Wayland mode

use super::{AutoFillResult, CredentialMatch};
use crate::{PasswordManagerError, Result};
use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::ptr;
use std::thread;
use std::time::Duration;

/// Auto-fill context for Linux
pub struct AutoFillContext {
    /// Active window title
    pub window_title: String,
    /// Window class/name (application identifier)
    pub window_class: String,
    /// Detected domain/URL
    pub domain: Option<String>,
    /// Window ID
    pub window_id: u64,
}

/// Get the current auto-fill context
///
/// Detects the active window and attempts to extract the domain/URL
pub fn get_context() -> Result<AutoFillContext> {
    // Try X11 first
    if is_wayland() {
        return Err(PasswordManagerError::NotImplemented(
            "Wayland auto-fill not yet implemented - requires virtual keyboard protocol".to_string(),
        ));
    }

    get_context_x11()
}

/// Check if running under Wayland
fn is_wayland() -> bool {
    std::env::var("WAYLAND_DISPLAY").is_ok()
        || std::env::var("SENTINELPASS_WAYLAND").is_ok()
}

/// Get context using X11
#[cfg(feature = "x11")]
fn get_context_x11() -> Result<AutoFillContext> {
    use x11::xlib;
    use x11::xtst;

    unsafe {
        // Open X display
        let display = open_display()?;
        let _display_guard = DisplayGuard(display);

        // Get the active window
        let window = get_active_window(display)?;

        // Get window title
        let window_title = get_window_title(display, window)?;

        // Get window class
        let window_class = get_window_class(display, window)?;

        // Try to extract domain
        let domain = extract_domain_from_title(&window_title);

        Ok(AutoFillContext {
            window_title,
            window_class,
            domain,
            window_id: window as u64,
        })
    }
}

/// Fallback when X11 feature is not enabled
#[cfg(not(feature = "x11"))]
fn get_context_x11() -> Result<AutoFillContext> {
    Err(PasswordManagerError::NotImplemented(
        "X11 support not enabled - build with 'x11' feature".to_string(),
    ))
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

    if is_wayland() {
        return Err(PasswordManagerError::NotImplemented(
            "Wayland clipboard not yet implemented".to_string(),
        ));
    }

    #[cfg(feature = "x11")]
    {
        autofill_via_clipboard_x11(&entry.username, &entry.password)?;
        Ok(AutoFillResult::Success)
    }

    #[cfg(not(feature = "x11"))]
    Err(PasswordManagerError::NotImplemented(
        "X11 support not enabled".to_string(),
    ))
}

/// Auto-fill via clipboard using X11
#[cfg(feature = "x11")]
fn autofill_via_clipboard_x11(username: &str, password: &str) -> Result<()> {
    use x11::xlib;

    unsafe {
        let display = open_display()?;
        let _display_guard = DisplayGuard(display);

        // Copy username first
        if !username.is_empty() {
            set_clipboard_text(display, username)?;
            thread::sleep(Duration::from_millis(100));
        }

        // Copy password
        set_clipboard_text(display, password)?;

        Ok(())
    }
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

    if is_wayland() {
        return Err(PasswordManagerError::NotImplemented(
            "Wayland input simulation not yet implemented".to_string(),
        ));
    }

    #[cfg(feature = "x11")]
    {
        unsafe {
            // Small delay to ensure target window is ready
            thread::sleep(Duration::from_millis(100));

            // Type username
            if !entry.username.is_empty() {
                simulate_typing_x11(&entry.username)?;
                simulate_key_stroke_x11(x11::keysym::XK_Tab as u32)?;
            }

            // Small delay between fields
            thread::sleep(Duration::from_millis(100));

            // Type password
            simulate_typing_x11(&entry.password)?;

            // Press Enter to submit
            simulate_key_stroke_x11(x11::keysym::XK_Return as u32)?;

            Ok(AutoFillResult::Success)
        }
    }

    #[cfg(not(feature = "x11"))]
    Err(PasswordManagerError::NotImplemented(
        "X11 support not enabled".to_string(),
    ))
}

/// Register global hotkey for auto-fill
///
/// Registers Ctrl+Shift+P as the auto-fill hotkey
///
/// Note: Requires X11 XTest extension or GrabKey
pub fn register_hotkey(_modifiers: u32, _vk: u32) -> Result<()> {
    // Full implementation requires:
    // 1. Creating a window to receive key events
    // 2. Using XGrabKey to grab the hotkey combination
    // 3. Running an event loop to process X events
    //
    // This requires a separate thread with an event loop

    if is_wayland() {
        return Err(PasswordManagerError::NotImplemented(
            "Wayland hotkey registration not yet implemented".to_string(),
        ));
    }

    Err(PasswordManagerError::NotImplemented(
        "Hotkey registration requires X11 event loop setup".to_string(),
    ))
}

// ============================================================================
// X11 Helper Functions
// ============================================================================

/// RAII guard for X11 display connection
struct DisplayGuard(*mut x11::xlib::Display);

impl Drop for DisplayGuard {
    fn drop(&mut self) {
        unsafe {
            x11::xlib::XCloseDisplay(self.0);
        }
    }
}

/// Open X11 display
unsafe fn open_display() -> Result<*mut x11::xlib::Display> {
    let display_name = std::env::var("SENTINELPASS_DISPLAY")
        .or_else(|_| std::env::var("DISPLAY"))
        .unwrap_or_else(|_| ":0".to_string());

    let display_name_c = CString::new(display_name).map_err(|_| {
        PasswordManagerError::InvalidInput("Invalid DISPLAY name".to_string())
    })?;

    let display = x11::xlib::XOpenDisplay(display_name_c.as_ptr());

    if display.is_null() {
        return Err(PasswordManagerError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "Cannot open X display - is X11 running?",
        )));
    }

    Ok(display)
}

/// Get the active (focused) window
#[cfg(feature = "x11")]
unsafe fn get_active_window(display: *mut x11::xlib::Display) -> Result<x11::xlib::Window> {
    use x11::xlib;

    // Get the root window
    let screen = xlib::XDefaultScreen(display);
    let root_window = xlib::XRootWindow(display, screen);

    // Atom for _NET_ACTIVE_WINDOW
    let net_active_window_atom = xlib::XInternAtom(
        display,
        CString::new("_NET_ACTIVE_WINDOW").unwrap().as_ptr(),
        xlib::True,
    );

    // Get the active window property
    let mut window_return: xlib::Window = 0;
    mut actual_type: xlib::Atom = 0;
    mut actual_format: i32 = 0;
    mut nitems: u64 = 0;
    mut bytes_after: u64 = 0;
    mut prop_return: *mut u8 = ptr::null_mut();

    let result = xlib::XGetWindowProperty(
        display,
        root_window,
        net_active_window_atom,
        0,
        1,
        xlib::False,
        xlib::AnyPropertyType,
        &mut actual_type,
        &mut actual_format,
        &mut nitems,
        &mut bytes_after,
        &mut prop_return,
    );

    if result == xlib::Success as i32 && !prop_return.is_null() && nitems > 0 {
        let window = *(prop_return as *const xlib::Window);
        xlib::XFree(prop_return as *mut std::ffi::c_void);
        return Ok(window);
    }

    // Fallback: try to get input focus window
    let mut focus_return: xlib::Window = 0;
    let mut revert_to: i32 = 0;
    xlib::XGetInputFocus(display, &mut focus_return, &mut revert_to);

    if focus_return != 0 {
        return Ok(focus_return);
    }

    Err(PasswordManagerError::Io(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        "Cannot determine active window",
    )))
}

/// Get window title using WM_NAME or _NET_WM_NAME
#[cfg(feature = "x11")]
unsafe fn get_window_title(
    display: *mut x11::xlib::Display,
    window: x11::xlib::Window,
) -> Result<String> {
    use x11::xlib;

    // Try _NET_WM_NAME first (UTF-8)
    let net_wm_name_atom = xlib::XInternAtom(
        display,
        CString::new("_NET_WM_NAME").unwrap().as_ptr(),
        xlib::True,
    );

    let mut actual_type: xlib::Atom = 0;
    let mut actual_format: i32 = 0;
    let mut nitems: u64 = 0;
    let mut bytes_after: u64 = 0;
    let mut prop_return: *mut u8 = ptr::null_mut();

    let result = xlib::XGetWindowProperty(
        display,
        window,
        net_wm_name_atom,
        0,
        std::i32::MAX as u64,
        xlib::False,
        xlib::AnyPropertyType,
        &mut actual_type,
        &mut actual_format,
        &mut nitems,
        &mut bytes_after,
        &mut prop_return,
    );

    if result == xlib::Success as i32 && !prop_return.is_null() && nitems > 0 {
        let title = String::from_utf8_lossy(std::slice::from_raw_parts(
            prop_return,
            nitems as usize,
        ))
        .to_string();
        xlib::XFree(prop_return as *mut std::ffi::c_void);
        return Ok(title);
    }

    // Fallback to WM_NAME (legacy)
    let mut window_name_return: *mut i8 = ptr::null_mut();
    xlib::XFetchName(
        display,
        window,
        &mut window_name_return,
    );

    if !window_name_return.is_null() {
        let title = CString::from_raw(window_name_return)
            .into_string()
            .unwrap_or_default();
        return Ok(title);
    }

    Ok(String::new())
}

/// Get window class (WM_CLASS)
#[cfg(feature = "x11")]
unsafe fn get_window_class(
    display: *mut x11::xlib::Display,
    window: xlib::xlib::Window,
) -> Result<String> {
    use x11::xlib;

    let wm_class_atom = xlib::XInternAtom(
        display,
        CString::new("WM_CLASS").unwrap().as_ptr(),
        xlib::False,
    );

    let mut actual_type: xlib::Atom = 0;
    let mut actual_format: i32 = 0;
    let mut nitems: u64 = 0;
    let mut bytes_after: u64 = 0;
    let mut prop_return: *mut u8 = ptr::null_mut();

    let result = xlib::XGetWindowProperty(
        display,
        window,
        wm_class_atom,
        0,
        std::i32::MAX as u64,
        xlib::False,
        xlib::AnyPropertyType,
        &mut actual_type,
        &mut actual_format,
        &mut nitems,
        &mut bytes_after,
        &mut prop_return,
    );

    if result == xlib::Success as i32 && !prop_return.is_null() && nitems > 0 {
        // WM_CLASS contains null-terminated strings
        let data = std::slice::from_raw_parts(prop_return, nitems as usize);
        if let Some(null_pos) = data.iter().position(|&x| x == 0) {
            let class = String::from_utf8_lossy(&data[..null_pos]).to_string();
            xlib::XFree(prop_return as *mut std::ffi::c_void);
            return Ok(class);
        }
        xlib::XFree(prop_return as *mut std::ffi::c_void);
    }

    Ok(String::new())
}

/// Set clipboard text using X11
#[cfg(feature = "x11")]
unsafe fn set_clipboard_text(
    display: *mut x11::xlib::Display,
    text: &str,
) -> Result<()> {
    use x11::xlib;

    let clipboard_atom = xlib::XInternAtom(
        display,
        CString::new("CLIPBOARD").unwrap().as_ptr(),
        xlib::False,
    );

    let utf8_string_atom = xlib::XInternAtom(
        display,
        CString::new("UTF8_STRING").unwrap().as_ptr(),
        xlib::False,
    );

    let screen = xlib::XDefaultScreen(display);
    let window = xlib::XRootWindow(display, screen);

    // Convert text to C string
    let text_c = CString::new(text).map_err(|_| {
        PasswordManagerError::InvalidInput("Invalid text for clipboard".to_string())
    })?;

    // Set the window property (clipboard selection)
    xlib::XChangeProperty(
        display,
        window,
        clipboard_atom,
        utf8_string_atom,
        8,
        xlib::PropModeReplace,
        text_c.as_bytes().as_ptr(),
        text.len() as i32,
    );

    Ok(())
}

/// Simulate typing a string using XTest
#[cfg(feature = "x11")]
unsafe fn simulate_typing_x11(text: &str) -> Result<()> {
    for ch in text.chars() {
        let keysym = char_to_keycode_x11(ch)?;
        simulate_key_stroke_x11(keysym)?;
    }
    Ok(())
}

/// Simulate a key stroke using XTest
#[cfg(feature = "x11")]
unsafe fn simulate_key_stroke_x11(keysym: u32) -> Result<()> {
    use x11::xtst;

    let display = open_display()?;
    let _display_guard = DisplayGuard(display);

    // Get keycode from keysym
    let keycode = x11::xlib::XKeysymToKeycode(display, keysym);

    if keycode == 0 {
        return Err(PasswordManagerError::InvalidInput(format!(
            "Cannot find keycode for keysym: {}",
            keysym
        )));
    }

    // Press key
    xtst::XTestFakeKeyEvent(display, keycode, 1, 0);

    // Small delay
    thread::sleep(Duration::from_millis(10));

    // Release key
    xtst::XTestFakeKeyEvent(display, keycode, 0, 0);

    // Flush to send events
    x11::xlib::XFlush(display);

    Ok(())
}

/// Convert character to X11 keysym
#[cfg(feature = "x11")]
unsafe fn char_to_keycode_x11(ch: char) -> Result<u32> {
    use x11::keysym;

    let keysym = match ch {
        'a' | 'A' => keysym::XK_a,
        'b' | 'B' => keysym::XK_b,
        'c' | 'C' => keysym::XK_c,
        'd' | 'D' => keysym::XK_d,
        'e' | 'E' => keysym::XK_e,
        'f' | 'F' => keysym::XK_f,
        'g' | 'G' => keysym::XK_g,
        'h' | 'H' => keysym::XK_h,
        'i' | 'I' => keysym::XK_i,
        'j' | 'J' => keysym::XK_j,
        'k' | 'K' => keysym::XK_k,
        'l' | 'L' => keysym::XK_l,
        'm' | 'M' => keysym::XK_m,
        'n' | 'N' => keysym::XK_n,
        'o' | 'O' => keysym::XK_o,
        'p' | 'P' => keysym::XK_p,
        'q' | 'Q' => keysym::XK_q,
        'r' | 'R' => keysym::XK_r,
        's' | 'S' => keysym::XK_s,
        't' | 'T' => keysym::XK_t,
        'u' | 'U' => keysym::XK_u,
        'v' | 'V' => keysym::XK_v,
        'w' | 'W' => keysym::XK_w,
        'x' | 'X' => keysym::XK_x,
        'y' | 'Y' => keysym::XK_y,
        'z' | 'Z' => keysym::XK_z,
        '0' => keysym::XK_0,
        '1' => keysym::XK_1,
        '2' => keysym::XK_2,
        '3' => keysym::XK_3,
        '4' => keysym::XK_4,
        '5' => keysym::XK_5,
        '6' => keysym::XK_6,
        '7' => keysym::XK_7,
        '8' => keysym::XK_8,
        '9' => keysym::XK_9,
        ' ' => keysym::XK_space,
        '\t' => keysym::XK_Tab,
        '\n' => keysym::XK_Return,
        '-' => keysym::XK_minus,
        '=' => keysym::XK_equal,
        '@' => keysym::XK_at,
        '.' => keysym::XK_period,
        ',' => keysym::XK_comma,
        '/' => keysym::XK_slash,
        ':' => keysym::XK_colon,
        _ => {
            return Err(PasswordManagerError::InvalidInput(format!(
                "Cannot type character: {}",
                ch
            )))
        }
    };

    Ok(keysym as u32)
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Extract domain from window title
fn extract_domain_from_title(title: &str) -> Option<String> {
    // Remove common browser/app suffixes
    let title = title
        .replace(" - Google Chrome", "")
        .replace(" - Mozilla Firefox", "")
        .replace(" — Brave", "")
        .replace(" - Microsoft Edge", "")
        .replace(" - Vivaldi", "")
        .replace(" - Opera", "")
        .replace(" - Chromium", "")
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
        let parts: Vec<&str> = title.split('.').collect();
        if parts.len() >= 2 {
            return Some(title);
        }
    }

    None
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
            extract_domain_from_title("https://www.example.com/path - Mozilla Firefox"),
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
