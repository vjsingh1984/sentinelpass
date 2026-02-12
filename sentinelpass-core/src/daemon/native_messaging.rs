//! Native messaging protocol for browser extension communication.

use serde::{Deserialize, Serialize};
use std::io::{self, Read, Write};

/// Native messaging protocol version
pub const PROTOCOL_VERSION: u32 = 1;

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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialData {
    pub username: String,
    pub password: String,
}

/// Native messaging host for communication with browser
pub struct NativeMessagingHost;

impl NativeMessagingHost {
    pub fn new() -> Self {
        Self
    }

    /// Run the native messaging host
    pub fn run(&mut self) -> Result<(), String> {
        // Read message from stdin
        let message = Self::read_message()?;

        // Process message (placeholder)
        let response = NativeResponse {
            version: PROTOCOL_VERSION,
            msg_type: "credential_response".to_string(),
            request_id: message.request_id.unwrap_or_default(),
            success: false,
            data: None,
        };

        // Write response to stdout
        Self::write_response(&response)?;

        Ok(())
    }

    /// Read a message from stdin (length-prefixed JSON)
    fn read_message() -> Result<NativeMessage, String> {
        let mut length_bytes = [0u8; 4];
        io::stdin().read_exact(&mut length_bytes)
            .map_err(|e| format!("Failed to read length: {}", e))?;

        let length = u32::from_le_bytes(length_bytes) as usize;

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
}
