//! Daemon module for background service and native messaging.

pub mod native_messaging;
pub mod ipc;
pub mod autolock;
pub mod vault_state;

pub use native_messaging::{NativeMessagingHost, NativeMessage};
pub use vault_state::{DaemonVault, VaultState, CredentialResponse};
pub use ipc::{IpcServer, IpcClient, IpcMessage, default_ipc_socket_path};
