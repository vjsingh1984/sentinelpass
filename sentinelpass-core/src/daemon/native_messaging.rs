//! Native messaging protocol for browser extension communication.

use crate::daemon::ipc::{IpcClient, IpcMessage, default_ipc_socket_path};
use serde::{Deserialize, Serialize};
use std::io::{self, Read, Write};
use tracing::{info, error};

/// Native messaging protocol version
pub const PROTOCOL_VERSION: u32 = 1;

/// Message types
pub const MSG_GET_CREDENTIAL: &str = "get_credential";
pub const MSG_CREDENTIAL_RESPONSE: &str = "credential_response";
pub const MSG_SAVE_CREDENTIAL: &str = "save_credential";
pub const MSG_CHECK_VAULT: &str = "check_vault_status";
pub const MSG_VAULT_STATUS: &str = "vault_status";

/// A native message from the browser extension
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NativeMessage {
    pub version: u32,
    #[serde(rename = "type")]
    pub msg_type: String,
    pub domain: Option<String>,
    #[serde(rename = "request_id")]
    pub request_id: Option<String>,
}

/// Response to a native message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NativeResponse {
    pub version: u32,
    #[serde(rename = "type")]
    pub msg_type: String,
    #[serde(rename = "request_id")]
    pub request_id: String,
    pub success: bool,
    pub data: Option<CredentialData>,
    pub error: Option<String>,
    pub unlocked: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialData {
    pub username: String,
    pub password: String,
    pub title: Option<String>,
}

/// Native messaging host for communication with browser
pub struct NativeMessagingHost;

impl Default for NativeMessagingHost {
    fn default() -> Self {
        Self::new()
    }
}

impl NativeMessagingHost {
    pub fn new() -> Self {
        Self
    }

    /// Run the native messaging host
    pub fn run(&mut self) -> Result<(), String> {
        // Read message from stdin
        let message = Self::read_message()?;

        info!("Received native message: type={}, domain={:?}",
            message.msg_type, message.domain);

        // Create IPC client to communicate with daemon
        let socket_path = default_ipc_socket_path();
        let ipc_client = IpcClient::new(socket_path);

        // Convert native message to IPC message
        let ipc_msg = match message.msg_type.as_str() {
            MSG_GET_CREDENTIAL => {
                if let Some(domain) = message.domain {
                    Some(IpcMessage::GetCredential { domain })
                } else {
                    Self::send_error(
                        message.request_id.unwrap_or_default(),
                        "Missing domain parameter"
                    )?;
                    return Ok(());
                }
            }
            MSG_CHECK_VAULT => Some(IpcMessage::CheckVault),
            _ => {
                Self::send_error(
                    message.request_id.unwrap_or_default(),
                    &format!("Unknown message type: {}", message.msg_type)
                )?;
                return Ok(());
            }
        };

        let request_id = message.request_id.unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

        // Send to daemon and get response
        let rt = tokio::runtime::Runtime::new()
            .map_err(|e| format!("Failed to create runtime: {}", e))?;

        let response = rt.block_on(async {
            ipc_client.send(ipc_msg.unwrap()).await
        });

        match response {
            Ok(IpcMessage::GetCredentialResponse { username, password, title }) => {
                if let (Some(user), Some(pass)) = (username, password) {
                    Self::send_credential(request_id, user, pass, title)?;
                } else {
                    Self::send_error(request_id, "No credential found for domain")?;
                }
            }
            Ok(IpcMessage::VaultStatusResponse { unlocked }) => {
                Self::send_vault_status(request_id, unlocked)?;
            }
            Ok(_) => {
                Self::send_error(request_id, "Unexpected response from daemon")?;
            }
            Err(e) => {
                error!("IPC error: {}", e);
                Self::send_error(request_id, &format!("Failed to communicate with daemon: {}", e))?;
            }
        }

        Ok(())
    }

    /// Read a message from stdin (length-prefixed JSON)
    fn read_message() -> Result<NativeMessage, String> {
        let mut length_bytes = [0u8; 4];
        io::stdin().read_exact(&mut length_bytes)
            .map_err(|e| format!("Failed to read length: {}", e))?;

        let length = u32::from_le_bytes(length_bytes) as usize;

        if length == 0 || length > 1024 * 1024 { // Max 1MB
            return Err("Invalid message length".to_string());
        }

        let mut buffer = vec![0u8; length];
        io::stdin().read_exact(&mut buffer)
            .map_err(|e| format!("Failed to read message: {}", e))?;

        serde_json::from_slice(&buffer)
            .map_err(|e| format!("Failed to parse JSON: {}", e))
    }

    /// Write a response to stdout (length-prefixed JSON)
    fn write_response(response: &NativeResponse) -> Result<(), String> {
        let json = serde_json::to_vec(response)
            .map_err(|e| format!("Failed to serialize response: {}", e))?;

        let length = json.len() as u32;
        io::stdout().write_all(&length.to_le_bytes())
            .map_err(|e| format!("Failed to write length: {}", e))?;

        io::stdout().write_all(&json)
            .map_err(|e| format!("Failed to write response: {}", e))?;

        io::stdout().flush()
            .map_err(|e| format!("Failed to flush: {}", e))?;

        Ok(())
    }

    /// Send error response
    pub fn send_error(request_id: String, error_msg: &str) -> Result<(), String> {
        let response = NativeResponse {
            version: PROTOCOL_VERSION,
            msg_type: MSG_CREDENTIAL_RESPONSE.to_string(),
            request_id,
            success: false,
            data: None,
            error: Some(error_msg.to_string()),
            unlocked: None,
        };
        Self::write_response(&response)
    }

    /// Send success response with credential
    pub fn send_credential(
        request_id: String,
        username: String,
        password: String,
        title: Option<String>,
    ) -> Result<(), String> {
        let response = NativeResponse {
            version: PROTOCOL_VERSION,
            msg_type: MSG_CREDENTIAL_RESPONSE.to_string(),
            request_id,
            success: true,
            data: Some(CredentialData { username, password, title }),
            error: None,
            unlocked: None,
        };
        Self::write_response(&response)
    }

    /// Send vault status response
    pub fn send_vault_status(request_id: String, unlocked: bool) -> Result<(), String> {
        let response = NativeResponse {
            version: PROTOCOL_VERSION,
            msg_type: MSG_VAULT_STATUS.to_string(),
            request_id,
            success: true,
            data: None,
            error: None,
            unlocked: Some(unlocked),
        };
        Self::write_response(&response)
    }
}
