//! Daemon module for background service and native messaging.

pub mod native_messaging;
pub mod ipc;
pub mod autolock;

pub use native_messaging::{NativeMessagingHost, NativeMessage};
