//! Linux-specific auto-fill implementation (stub)
//!
//! Uses X11/Wayland APIs for auto-fill.
//! This is a placeholder for future implementation.

use super::AutoFillResult;

pub struct AutoFillContext;

/// Get the current auto-fill context
pub fn get_context() -> Result<AutoFillContext, crate::PasswordManagerError> {
    Err(crate::PasswordManagerError::NotImplemented(
        "Linux auto-fill not yet implemented".to_string(),
    ))
}
