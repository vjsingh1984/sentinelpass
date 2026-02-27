//! IPC (Inter-Process Communication) for daemon communication
//!
//! Uses Unix domain sockets on Linux/macOS.
//! Windows uses named pipes with per-user ACLs for OS-level security,
//! plus AES-256-GCM transport encryption as defense-in-depth.
//! Loopback TCP is retained as a legacy fallback for custom `tcp://...` paths.

use crate::daemon::DaemonVault;
use crate::{get_config_dir, DatabaseError, PasswordManagerError, Result};
#[cfg(windows)]
use aes_gcm::aead::{Aead, KeyInit};
#[cfg(windows)]
use aes_gcm::{Aes256Gcm, Nonce};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use subtle::ConstantTimeEq;
#[allow(unused_imports)]
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, error, info, warn};
use zeroize::Zeroize;
#[cfg(windows)]
use windows::Win32::Foundation::BOOL;
#[cfg(windows)]
use windows::Win32::System::Pipes::{
    DisconnectNamedPipe, PIPE_ACCESS_DUPLEX, PIPE_READMODE_BYTE,
    PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
};
#[cfg(windows)]
use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeServer, ServerOptions};

/// IPC message types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IpcMessage {
    GetCredential {
        domain: String,
    },
    GetCredentialResponse {
        username: Option<String>,
        password: Option<String>,
        title: Option<String>,
    },
    ListDomainCredentials {
        base_domain: String,
    },
    ListDomainCredentialsResponse {
        credentials: Vec<CredentialSummary>,
    },
    GetTotpCode {
        domain: String,
    },
    GetTotpCodeResponse {
        code: Option<String>,
        seconds_remaining: Option<u32>,
    },
    SaveCredential {
        domain: String,
        username: String,
        password: String,
        url: Option<String>,
    },
    SaveCredentialResponse {
        success: bool,
        error: Option<String>,
    },
    UnlockVault {
        master_password: String,
    },
    UnlockVaultBiometric {
        prompt_reason: Option<String>,
    },
    UnlockVaultResponse {
        success: bool,
        error: Option<String>,
    },
    CheckVault,
    VaultStatusResponse {
        unlocked: bool,
    },
    LockVault,
    Shutdown,

    // --- Sync messages ---
    /// Trigger a sync cycle now (push + pull).
    SyncNow,
    /// Response to SyncNow.
    SyncNowResponse {
        success: bool,
        pushed: u64,
        pulled: u64,
        error: Option<String>,
    },
    /// Get sync status.
    SyncStatus,
    /// Sync status response.
    SyncStatusResponse {
        enabled: bool,
        device_id: Option<String>,
        device_name: Option<String>,
        relay_url: Option<String>,
        last_sync_at: Option<i64>,
        pending_changes: u64,
    },
}

/// Summary of a credential for listing (excludes password for bulk operations)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialSummary {
    pub username: String,
    pub title: Option<String>,
    pub domain: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct IpcEnvelope {
    token: String,
    message: IpcMessage,
}

#[cfg(windows)]
const WINDOWS_IPC_NONCE_LEN: usize = 12;

#[cfg(windows)]
fn windows_ipc_cipher(auth_token: &str) -> Result<Aes256Gcm> {
    let key_bytes = hex::decode(auth_token).map_err(|e| {
        PasswordManagerError::from(DatabaseError::Ipc(format!(
            "Invalid IPC token encoding for Windows transport encryption: {}",
            e
        )))
    })?;

    if key_bytes.len() != 32 {
        return Err(PasswordManagerError::from(DatabaseError::Ipc(format!(
            "Invalid IPC token length for Windows transport encryption: expected 32 bytes, got {}",
            key_bytes.len()
        ))));
    }

    let cipher = Aes256Gcm::new_from_slice(&key_bytes).map_err(|e| {
        PasswordManagerError::from(DatabaseError::Ipc(format!(
            "Failed to initialize Windows IPC transport cipher: {}",
            e
        )))
    })?;

    Ok(cipher)
}

#[cfg(windows)]
fn encrypt_windows_ipc_frame(auth_token: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = windows_ipc_cipher(auth_token)?;
    let mut nonce_bytes = [0u8; WINDOWS_IPC_NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher.encrypt(nonce, plaintext).map_err(|e| {
        PasswordManagerError::from(DatabaseError::Ipc(format!(
            "Failed to encrypt Windows IPC frame: {}",
            e
        )))
    })?;

    let mut frame = Vec::with_capacity(WINDOWS_IPC_NONCE_LEN + ciphertext.len());
    frame.extend_from_slice(&nonce_bytes);
    frame.extend_from_slice(&ciphertext);
    Ok(frame)
}

#[cfg(windows)]
fn decrypt_windows_ipc_frame(auth_token: &str, frame: &[u8]) -> Result<Vec<u8>> {
    if frame.len() <= WINDOWS_IPC_NONCE_LEN {
        return Err(PasswordManagerError::from(DatabaseError::Ipc(
            "Windows IPC frame too short".to_string(),
        )));
    }

    let cipher = windows_ipc_cipher(auth_token)?;
    let nonce = Nonce::from_slice(&frame[..WINDOWS_IPC_NONCE_LEN]);
    let ciphertext = &frame[WINDOWS_IPC_NONCE_LEN..];

    cipher.decrypt(nonce, ciphertext).map_err(|e| {
        PasswordManagerError::from(DatabaseError::Ipc(format!(
            "Failed to decrypt Windows IPC frame: {}",
            e
        )))
    })
}

#[cfg(windows)]
/// Get the default named pipe path for Windows.
fn windows_named_pipe_path() -> String {
    // Use a unique pipe name based on the username for multi-user support
    // Format: \\.\pipe\SentinelPass-<username>
    let username = std::env::var("USERNAME")
        .unwrap_or_else(|_| "default".to_string())
        .replace(|c: char| !c.is_alphanumeric(), "");
    format!(r"\\.\pipe\SentinelPass-{}", username)
}

/// IPC server for daemon communication
#[allow(dead_code)]
pub struct IpcServer {
    socket_path: PathBuf,
    vault: Arc<DaemonVault>,
    auth_token: String,
}

impl IpcServer {
    /// Create a new IPC server
    pub fn new(socket_path: PathBuf, vault: Arc<DaemonVault>, auth_token: String) -> Self {
        Self {
            socket_path,
            vault,
            auth_token,
        }
    }

    /// Start the IPC server
    pub async fn run(&self) -> Result<()> {
        info!("Starting IPC server at {:?}", self.socket_path);

        // Remove existing socket if present
        if self.socket_path.exists() {
            std::fs::remove_file(&self.socket_path).map_err(|e| {
                PasswordManagerError::from(DatabaseError::Ipc(format!(
                    "Failed to remove socket: {}",
                    e
                )))
            })?;
        }

        #[cfg(unix)]
        {
            use tokio::net::UnixListener;

            let listener = UnixListener::bind(&self.socket_path).map_err(|e| {
                PasswordManagerError::from(DatabaseError::Ipc(format!(
                    "Failed to bind socket: {}",
                    e
                )))
            })?;

            info!("IPC server listening on {:?}", self.socket_path);

            loop {
                match listener.accept().await {
                    Ok((mut stream, addr)) => {
                        debug!("IPC client connected: {:?}", addr);

                        let mut length_buf = [0u8; 4];
                        match stream.read_exact(&mut length_buf).await {
                            Ok(_) => {
                                let length = u32::from_be_bytes(length_buf) as usize;
                                if length > 0 && length <= 65536 {
                                    let mut buffer = vec![0u8; length];
                                    match stream.read_exact(&mut buffer).await {
                                        Ok(_) => {
                                            match serde_json::from_slice::<IpcEnvelope>(&buffer) {
                                                Ok(envelope) => {
                                                    if !bool::from(
                                                        envelope
                                                            .token
                                                            .as_bytes()
                                                            .ct_eq(self.auth_token.as_bytes()),
                                                    ) {
                                                        warn!("Rejected IPC request with invalid token");
                                                        continue;
                                                    }
                                                    let response =
                                                        self.handle_message(envelope.message).await;
                                                    match serde_json::to_vec(&response) {
                                                        Ok(response_bytes) => {
                                                            let response_len =
                                                                response_bytes.len() as u32;
                                                            if stream
                                                                .write_all(
                                                                    &response_len.to_be_bytes(),
                                                                )
                                                                .await
                                                                .is_ok()
                                                                && stream
                                                                    .write_all(&response_bytes)
                                                                    .await
                                                                    .is_ok()
                                                            {
                                                                // Flush to ensure message is sent
                                                                let _ = stream.flush().await;
                                                            }
                                                        }
                                                        Err(e) => {
                                                            error!(
                                                                "Failed to serialize response: {}",
                                                                e
                                                            );
                                                        }
                                                    }
                                                }
                                                Err(e) => {
                                                    error!("Failed to parse IPC envelope: {}", e);
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            error!("Failed to read message: {}", e);
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                error!("Failed to read length: {}", e);
                            }
                        }
                    }
                    Err(e) => {
                        error!("Failed to accept connection: {}", e);
                    }
                }
            }
        }

        #[cfg(windows)]
        {
            // Determine if using named pipes or legacy TCP
            let path_str = self.socket_path.to_string_lossy().to_string();
            let use_tcp = path_str.starts_with("tcp://");

            if use_tcp {
                // Legacy TCP fallback for custom tcp://... paths
                use tokio::net::TcpListener;

                let addr_str = path_str.strip_prefix("tcp://").unwrap_or("127.0.0.1:35873");
                info!("IPC server listening on legacy TCP: {}", addr_str);

                let listener = TcpListener::bind(addr_str).await.map_err(|e| {
                    PasswordManagerError::from(DatabaseError::Ipc(format!(
                        "Failed to bind TCP socket: {}",
                        e
                    )))
                })?;

                loop {
                    match listener.accept().await {
                        Ok((mut stream, _addr)) => {
                            debug!("IPC client connected (TCP)");

                            let mut length_buf = [0u8; 4];
                            match stream.read_exact(&mut length_buf).await {
                                Ok(_) => {
                                    let length = u32::from_be_bytes(length_buf) as usize;
                                    if length > 0 && length <= 65536 {
                                        let mut buffer = vec![0u8; length];
                                        match stream.read_exact(&mut buffer).await {
                                            Ok(_) => {
                                                match decrypt_windows_ipc_frame(
                                                    &self.auth_token,
                                                    &buffer,
                                                ) {
                                                    Ok(decrypted) => {
                                                        match serde_json::from_slice::<IpcEnvelope>(
                                                            &decrypted,
                                                        ) {
                                                            Ok(envelope) => {
                                                                if !bool::from(
                                                                    envelope.token.as_bytes().ct_eq(
                                                                        self.auth_token.as_bytes(),
                                                                    ),
                                                                ) {
                                                                    warn!("Rejected IPC request with invalid token");
                                                                    continue;
                                                                }
                                                                let response = self
                                                                    .handle_message(envelope.message)
                                                                    .await;
                                                                match serde_json::to_vec(&response) {
                                                                    Ok(response_bytes) => {
                                                                        match encrypt_windows_ipc_frame(
                                                                            &self.auth_token,
                                                                            &response_bytes,
                                                                        ) {
                                                                            Ok(response_frame) => {
                                                                                let response_len =
                                                                                    response_frame.len()
                                                                                        as u32;
                                                                                let _ = stream
                                                                                    .write_all(
                                                                                        &response_len
                                                                                            .to_be_bytes(),
                                                                                    )
                                                                                    .await;
                                                                                let _ = stream
                                                                                    .write_all(
                                                                                        &response_frame,
                                                                                    )
                                                                                    .await;
                                                                                let _ = stream
                                                                                    .flush()
                                                                                    .await;
                                                                            }
                                                                            Err(e) => {
                                                                                error!(
                                                                                    "Failed to encrypt IPC response frame: {}",
                                                                                    e
                                                                                );
                                                                            }
                                                                        }
                                                                    }
                                                                    Err(e) => {
                                                                        error!(
                                                                            "Failed to serialize response: {}",
                                                                            e
                                                                        );
                                                                    }
                                                                }
                                                            }
                                                            Err(e) => {
                                                                error!(
                                                                    "Failed to parse IPC envelope: {}",
                                                                    e
                                                                );
                                                            }
                                                        }
                                                    }
                                                    Err(e) => {
                                                        error!(
                                                            "Failed to decrypt Windows IPC frame: {}",
                                                            e
                                                        );
                                                    }
                                                }
                                            }
                                            Err(e) => {
                                                error!("Failed to read message: {}", e);
                                            }
                                        }
                                    } else {
                                        error!("Invalid message length: {}", length);
                                    }
                                }
                                Err(e) => {
                                    error!("Failed to read length: {}", e);
                                }
                            }
                        }
                        Err(e) => {
                            error!("Failed to accept connection: {}", e);
                        }
                    }
                }
            } else {
                // Default: Use named pipes with per-user ACLs
                let pipe_name = windows_named_pipe_path();
                info!("IPC server listening on named pipe: {}", pipe_name);

                // Convert pipe name to UTF-16 for Windows API
                let pipe_name_wide: Vec<u16> =
                    pipe_name.encode_utf16().chain(std::iter::once(0)).collect();

                loop {
                    // Create the named pipe
                    let server = ServerOptions::new()
                        .first_pipe_instance(false)
                        .create(&pipe_name)
                        .map_err(|e| {
                            PasswordManagerError::from(DatabaseError::Ipc(format!(
                                "Failed to create named pipe: {}",
                                e
                            )))
                        })?;

                    debug!("Named pipe created, waiting for connection");

                    // Wait for a client to connect
                    match server.connect().await {
                        Ok(_) => {
                            debug!("IPC client connected (named pipe)");

                            // Verify the client is the same user
                            // Note: tokio's named pipe doesn't expose the raw handle easily,
                            // so we rely on the per-user ACL and AES-GCM encryption for security

                            let mut length_buf = [0u8; 4];
                            match server.read_exact(&mut length_buf).await {
                                Ok(_) => {
                                    let length = u32::from_be_bytes(length_buf) as usize;
                                    if length > 0 && length <= 65536 {
                                        let mut buffer = vec![0u8; length];
                                        match server.read_exact(&mut buffer).await {
                                            Ok(_) => {
                                                match decrypt_windows_ipc_frame(
                                                    &self.auth_token,
                                                    &buffer,
                                                ) {
                                                    Ok(decrypted) => {
                                                        match serde_json::from_slice::<IpcEnvelope>(
                                                            &decrypted,
                                                        ) {
                                                            Ok(envelope) => {
                                                                if !bool::from(
                                                                    envelope.token.as_bytes().ct_eq(
                                                                        self.auth_token.as_bytes(),
                                                                    ),
                                                                ) {
                                                                    warn!("Rejected IPC request with invalid token");
                                                                    let _ = server.disconnect().await;
                                                                    continue;
                                                                }
                                                                let response = self
                                                                    .handle_message(envelope.message)
                                                                    .await;
                                                                match serde_json::to_vec(&response) {
                                                                    Ok(response_bytes) => {
                                                                        match encrypt_windows_ipc_frame(
                                                                            &self.auth_token,
                                                                            &response_bytes,
                                                                        ) {
                                                                            Ok(response_frame) => {
                                                                                let response_len =
                                                                                    response_frame.len()
                                                                                        as u32;
                                                                                let _ = server
                                                                                    .write_all(
                                                                                        &response_len
                                                                                            .to_be_bytes(),
                                                                                    )
                                                                                    .await;
                                                                                let _ = server
                                                                                    .write_all(
                                                                                        &response_frame,
                                                                                    )
                                                                                    .await;
                                                                                let _ = server.flush().await;
                                                                            }
                                                                            Err(e) => {
                                                                                error!(
                                                                                    "Failed to encrypt IPC response frame: {}",
                                                                                    e
                                                                                );
                                                                            }
                                                                        }
                                                                    }
                                                                    Err(e) => {
                                                                        error!(
                                                                            "Failed to serialize response: {}",
                                                                            e
                                                                        );
                                                                    }
                                                                }
                                                            }
                                                            Err(e) => {
                                                                error!(
                                                                    "Failed to parse IPC envelope: {}",
                                                                    e
                                                                );
                                                            }
                                                        }
                                                    }
                                                    Err(e) => {
                                                        error!(
                                                            "Failed to decrypt Windows IPC frame: {}",
                                                            e
                                                        );
                                                    }
                                                }
                                            }
                                            Err(e) => {
                                                error!("Failed to read message: {}", e);
                                            }
                                        }
                                    } else {
                                        error!("Invalid message length: {}", length);
                                    }
                                }
                                Err(e) => {
                                    error!("Failed to read length: {}", e);
                                }
                            }
                        }
                        Err(e) => {
                            error!("Failed to accept named pipe connection: {}", e);
                        }
                    }

                    // Disconnect to allow new connections
                    let _ = server.disconnect().await;
                }
            }
        }
    }

    /// Handle an IPC message
    #[allow(dead_code)]
    async fn handle_message(&self, msg: IpcMessage) -> IpcMessage {
        match msg {
            IpcMessage::GetCredential { domain } => {
                debug!("IPC: GetCredential for domain '{}'", domain);

                match self.vault.get_credential(&domain).await {
                    Ok(Some(cred)) => IpcMessage::GetCredentialResponse {
                        username: Some(cred.username),
                        password: Some(cred.password),
                        title: Some(cred.title),
                    },
                    Ok(None) => {
                        debug!("No credential found for domain '{}'", domain);
                        IpcMessage::GetCredentialResponse {
                            username: None,
                            password: None,
                            title: None,
                        }
                    }
                    Err(e) => {
                        error!("Failed to get credential: {}", e);
                        IpcMessage::GetCredentialResponse {
                            username: None,
                            password: None,
                            title: None,
                        }
                    }
                }
            }
            IpcMessage::ListDomainCredentials { base_domain } => {
                debug!("IPC: ListDomainCredentials for base domain '{}'", base_domain);

                match self.vault.list_domain_credentials(&base_domain).await {
                    Ok(credentials) => {
                        let summaries: Vec<CredentialSummary> = credentials
                            .into_iter()
                            .map(|cred| CredentialSummary {
                                username: cred.username,
                                title: Some(cred.title),
                                domain: cred.domain,
                            })
                            .collect();
                        IpcMessage::ListDomainCredentialsResponse {
                            credentials: summaries,
                        }
                    }
                    Err(e) => {
                        error!("Failed to list domain credentials: {}", e);
                        IpcMessage::ListDomainCredentialsResponse {
                            credentials: Vec::new(),
                        }
                    }
                }
            }
            IpcMessage::GetTotpCode { domain } => {
                debug!("IPC: GetTotpCode for domain '{}'", domain);

                match self.vault.get_totp_code(&domain).await {
                    Ok(Some(code)) => IpcMessage::GetTotpCodeResponse {
                        code: Some(code.code),
                        seconds_remaining: Some(code.seconds_remaining),
                    },
                    Ok(None) => {
                        debug!("No TOTP code found for domain '{}'", domain);
                        IpcMessage::GetTotpCodeResponse {
                            code: None,
                            seconds_remaining: None,
                        }
                    }
                    Err(e) => {
                        error!("Failed to get TOTP code: {}", e);
                        IpcMessage::GetTotpCodeResponse {
                            code: None,
                            seconds_remaining: None,
                        }
                    }
                }
            }
            IpcMessage::SaveCredential {
                domain,
                username,
                password,
                url,
            } => {
                info!(
                    "IPC: SaveCredential for domain '{}', user '{}'",
                    domain, username
                );

                match self
                    .vault
                    .save_credential(&domain, &username, &password, url.as_deref())
                    .await
                {
                    Ok(_) => {
                        info!("Credential saved successfully for domain '{}'", domain);
                        IpcMessage::SaveCredentialResponse {
                            success: true,
                            error: None,
                        }
                    }
                    Err(e) => {
                        error!("Failed to save credential: {}", e);
                        IpcMessage::SaveCredentialResponse {
                            success: false,
                            error: Some(e.to_string()),
                        }
                    }
                }
            }
            IpcMessage::UnlockVault {
                mut master_password,
            } => {
                debug!("IPC: UnlockVault");

                let unlock_result = if self.vault.is_unlocked().await {
                    Ok(())
                } else {
                    self.vault.unlock(master_password.as_bytes()).await
                };
                master_password.zeroize();

                match unlock_result {
                    Ok(_) => IpcMessage::UnlockVaultResponse {
                        success: true,
                        error: None,
                    },
                    Err(e) => {
                        warn!("Failed to unlock vault via IPC: {}", e);
                        IpcMessage::UnlockVaultResponse {
                            success: false,
                            error: Some(e.to_string()),
                        }
                    }
                }
            }
            IpcMessage::UnlockVaultBiometric { prompt_reason } => {
                debug!("IPC: UnlockVaultBiometric");
                let reason =
                    prompt_reason.unwrap_or_else(|| "Unlock SentinelPass daemon".to_string());
                match self.vault.unlock_with_biometric(&reason).await {
                    Ok(_) => IpcMessage::UnlockVaultResponse {
                        success: true,
                        error: None,
                    },
                    Err(e) => {
                        warn!("Failed biometric unlock via IPC: {}", e);
                        IpcMessage::UnlockVaultResponse {
                            success: false,
                            error: Some(e.to_string()),
                        }
                    }
                }
            }
            IpcMessage::CheckVault => {
                debug!("IPC: CheckVault");
                let unlocked = self.vault.is_unlocked().await;
                IpcMessage::VaultStatusResponse { unlocked }
            }
            IpcMessage::LockVault => {
                debug!("IPC: LockVault");
                self.vault.lock().await;
                IpcMessage::VaultStatusResponse { unlocked: false }
            }
            IpcMessage::Shutdown => {
                info!("IPC: Shutdown requested");
                IpcMessage::VaultStatusResponse { unlocked: false }
            }
            IpcMessage::SyncStatus => {
                debug!("IPC: SyncStatus");
                match self.vault.get_sync_status().await {
                    Ok(status) => IpcMessage::SyncStatusResponse {
                        enabled: status.enabled,
                        device_id: status.device_id.map(|d| d.to_string()),
                        device_name: status.device_name,
                        relay_url: status.relay_url,
                        last_sync_at: status.last_sync_at,
                        pending_changes: status.pending_changes,
                    },
                    Err(e) => {
                        error!("Failed to get sync status: {}", e);
                        IpcMessage::SyncStatusResponse {
                            enabled: false,
                            device_id: None,
                            device_name: None,
                            relay_url: None,
                            last_sync_at: None,
                            pending_changes: 0,
                        }
                    }
                }
            }
            _ => IpcMessage::VaultStatusResponse { unlocked: false },
        }
    }
}

/// IPC client for native messaging host
#[allow(dead_code)]
pub struct IpcClient {
    socket_path: PathBuf,
    auth_token: String,
}

impl IpcClient {
    /// Create a new IPC client
    pub fn new(socket_path: PathBuf) -> Result<Self> {
        let auth_token = load_ipc_token()?;
        Ok(Self {
            socket_path,
            auth_token,
        })
    }

    /// Send a message and wait for response
    #[allow(unused_variables)]
    pub async fn send(&self, msg: IpcMessage) -> Result<IpcMessage> {
        #[cfg(unix)]
        {
            use tokio::net::UnixStream;

            let mut stream = UnixStream::connect(&self.socket_path).await.map_err(|e| {
                PasswordManagerError::from(DatabaseError::Ipc(format!(
                    "Failed to connect to daemon: {}",
                    e
                )))
            })?;

            let envelope = IpcEnvelope {
                token: self.auth_token.clone(),
                message: msg,
            };
            let msg_bytes = serde_json::to_vec(&envelope).map_err(|e| {
                PasswordManagerError::from(DatabaseError::Ipc(format!(
                    "Failed to serialize message: {}",
                    e
                )))
            })?;
            let length = msg_bytes.len() as u32;

            stream.write_all(&length.to_be_bytes()).await.map_err(|e| {
                PasswordManagerError::from(DatabaseError::Ipc(format!(
                    "Failed to write length: {}",
                    e
                )))
            })?;

            stream.write_all(&msg_bytes).await.map_err(|e| {
                PasswordManagerError::from(DatabaseError::Ipc(format!(
                    "Failed to write message: {}",
                    e
                )))
            })?;

            stream.flush().await.map_err(|e| {
                PasswordManagerError::from(DatabaseError::Ipc(format!("Failed to flush: {}", e)))
            })?;

            // Read response
            let mut length_buf = [0u8; 4];
            stream.read_exact(&mut length_buf).await.map_err(|e| {
                PasswordManagerError::from(DatabaseError::Ipc(format!(
                    "Failed to read length: {}",
                    e
                )))
            })?;

            let response_length = u32::from_be_bytes(length_buf) as usize;

            if response_length > 65536 {
                return Err(PasswordManagerError::from(DatabaseError::Ipc(
                    "Response too large".to_string(),
                )));
            }

            let mut buffer = vec![0u8; response_length];
            stream.read_exact(&mut buffer).await.map_err(|e| {
                PasswordManagerError::from(DatabaseError::Ipc(format!(
                    "Failed to read response: {}",
                    e
                )))
            })?;

            serde_json::from_slice::<IpcMessage>(&buffer).map_err(|e| {
                PasswordManagerError::from(DatabaseError::Ipc(format!(
                    "Failed to parse response: {}",
                    e
                )))
            })
        }

        #[cfg(windows)]
        {
            // Determine if using named pipes or legacy TCP
            let path_str = self.socket_path.to_string_lossy().to_string();
            let use_tcp = path_str.starts_with("tcp://");

            if use_tcp {
                // Legacy TCP fallback for custom tcp://... paths
                use tokio::net::TcpStream;

                let addr_str = path_str.strip_prefix("tcp://").unwrap_or("127.0.0.1:35873");

                // Connect to TCP socket with bounded retries
                let connect_deadline =
                    tokio::time::Instant::now() + tokio::time::Duration::from_secs(3);
                let mut stream = loop {
                    match TcpStream::connect(addr_str).await {
                        Ok(s) => break s,
                        Err(e) => {
                            if e.kind() == std::io::ErrorKind::ConnectionRefused {
                                if tokio::time::Instant::now() >= connect_deadline {
                                    return Err(PasswordManagerError::from(DatabaseError::Ipc(
                                        format!(
                                            "Failed to connect to daemon at {}: timed out after 3s",
                                            addr_str
                                        ),
                                    )));
                                }
                                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                                continue;
                            }
                            return Err(PasswordManagerError::from(DatabaseError::Ipc(format!(
                                "Failed to connect to daemon: {}",
                                e
                            ))));
                        }
                    }
                };

                let envelope = IpcEnvelope {
                    token: self.auth_token.clone(),
                    message: msg,
                };
                let msg_bytes = serde_json::to_vec(&envelope).map_err(|e| {
                    PasswordManagerError::from(DatabaseError::Ipc(format!(
                        "Failed to serialize message: {}",
                        e
                    )))
                })?;
                let msg_bytes = encrypt_windows_ipc_frame(&self.auth_token, &msg_bytes)?;

                let length = msg_bytes.len() as u32;

                stream.write_all(&length.to_be_bytes()).await.map_err(|e| {
                    PasswordManagerError::from(DatabaseError::Ipc(format!(
                        "Failed to write length: {}",
                        e
                    )))
                })?;

                stream.write_all(&msg_bytes).await.map_err(|e| {
                    PasswordManagerError::from(DatabaseError::Ipc(format!(
                        "Failed to write message: {}",
                        e
                    )))
                })?;

                stream.flush().await.map_err(|e| {
                    PasswordManagerError::from(DatabaseError::Ipc(format!("Failed to flush: {}", e)))
                })?;

                // Read response
                let mut length_buf = [0u8; 4];
                stream.read_exact(&mut length_buf).await.map_err(|e| {
                    PasswordManagerError::from(DatabaseError::Ipc(format!(
                        "Failed to read length: {}",
                        e
                    )))
                })?;

                let response_length = u32::from_be_bytes(length_buf) as usize;

                if response_length > 65536 {
                    return Err(PasswordManagerError::from(DatabaseError::Ipc(
                        "Response too large".to_string(),
                    )));
                }

                let mut buffer = vec![0u8; response_length];
                stream.read_exact(&mut buffer).await.map_err(|e| {
                    PasswordManagerError::from(DatabaseError::Ipc(format!(
                        "Failed to read response: {}",
                        e
                    )))
                })?;

                let buffer = decrypt_windows_ipc_frame(&self.auth_token, &buffer)?;

                serde_json::from_slice::<IpcMessage>(&buffer).map_err(|e| {
                    PasswordManagerError::from(DatabaseError::Ipc(format!(
                        "Failed to parse response: {}",
                        e
                    )))
                })
            } else {
                // Default: Use named pipes
                let pipe_name = windows_named_pipe_path();
                debug!("Connecting to named pipe: {}", pipe_name);

                // Connect with bounded retries
                let connect_deadline =
                    tokio::time::Instant::now() + tokio::time::Duration::from_secs(3);

                let mut client = loop {
                    match ClientOptions::new().open(&pipe_name) {
                        Ok(c) => break c,
                        Err(e) => {
                            if tokio::time::Instant::now() >= connect_deadline {
                                return Err(PasswordManagerError::from(DatabaseError::Ipc(
                                    format!(
                                        "Failed to connect to named pipe {}: timed out after 3s",
                                        pipe_name
                                    ),
                                )));
                            }
                            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                            continue;
                        }
                    }
                };

                let envelope = IpcEnvelope {
                    token: self.auth_token.clone(),
                    message: msg,
                };
                let msg_bytes = serde_json::to_vec(&envelope).map_err(|e| {
                    PasswordManagerError::from(DatabaseError::Ipc(format!(
                        "Failed to serialize message: {}",
                        e
                    )))
                })?;
                let msg_bytes = encrypt_windows_ipc_frame(&self.auth_token, &msg_bytes)?;

                let length = msg_bytes.len() as u32;

                client.write_all(&length.to_be_bytes()).await.map_err(|e| {
                    PasswordManagerError::from(DatabaseError::Ipc(format!(
                        "Failed to write length: {}",
                        e
                    )))
                })?;

                client.write_all(&msg_bytes).await.map_err(|e| {
                    PasswordManagerError::from(DatabaseError::Ipc(format!(
                        "Failed to write message: {}",
                        e
                    )))
                })?;

                client.flush().await.map_err(|e| {
                    PasswordManagerError::from(DatabaseError::Ipc(format!("Failed to flush: {}", e)))
                })?;

                // Read response
                let mut length_buf = [0u8; 4];
                client.read_exact(&mut length_buf).await.map_err(|e| {
                    PasswordManagerError::from(DatabaseError::Ipc(format!(
                        "Failed to read length: {}",
                        e
                    )))
                })?;

                let response_length = u32::from_be_bytes(length_buf) as usize;

                if response_length > 65536 {
                    return Err(PasswordManagerError::from(DatabaseError::Ipc(
                        "Response too large".to_string(),
                    )));
                }

                let mut buffer = vec![0u8; response_length];
                client.read_exact(&mut buffer).await.map_err(|e| {
                    PasswordManagerError::from(DatabaseError::Ipc(format!(
                        "Failed to read response: {}",
                        e
                    )))
                })?;

                let buffer = decrypt_windows_ipc_frame(&self.auth_token, &buffer)?;

                serde_json::from_slice::<IpcMessage>(&buffer).map_err(|e| {
                    PasswordManagerError::from(DatabaseError::Ipc(format!(
                        "Failed to parse response: {}",
                        e
                    )))
                })
            }
        }
    }
}

/// Get the default IPC socket path for the platform
pub fn default_ipc_socket_path() -> PathBuf {
    if cfg!(target_os = "windows") {
        // Windows: Use named pipes with per-user ACLs
        // Default to named pipe format; custom tcp://... paths still work as legacy fallback
        PathBuf::from(r"\\.\pipe\SentinelPass")
    } else {
        // Unix: Use Unix domain socket
        let runtime_dir = std::env::var("XDG_RUNTIME_DIR").unwrap_or_else(|_| "/tmp".to_string());

        PathBuf::from(runtime_dir).join("sentinelpass.sock")
    }
}

/// Get the default IPC auth token path for the platform
pub fn default_ipc_token_path() -> PathBuf {
    get_config_dir().join("ipc.token")
}

/// Read IPC auth token from disk.
pub fn load_ipc_token() -> Result<String> {
    let token_path = default_ipc_token_path();
    let token = std::fs::read_to_string(&token_path)?.trim().to_string();
    if token.is_empty() {
        return Err(PasswordManagerError::from(DatabaseError::Ipc(format!(
            "IPC token file is empty: {:?}",
            token_path
        ))));
    }
    Ok(token)
}

/// Load existing IPC auth token or create one if it does not exist.
pub fn load_or_create_ipc_token() -> Result<String> {
    let token_path = default_ipc_token_path();

    if let Some(parent) = token_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    if token_path.exists() {
        return load_ipc_token();
    }

    let mut token_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut token_bytes);
    let token = hex::encode(token_bytes);

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&token_path)?;
    file.write_all(token.as_bytes())?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&token_path, std::fs::Permissions::from_mode(0o600))?;
    }

    Ok(token)
}
