//! IPC (Inter-Process Communication) for daemon communication
//!
//! Uses Unix domain sockets on Linux/macOS and named pipes on Windows.

use crate::daemon::DaemonVault;
use crate::{get_config_dir, DatabaseError, PasswordManagerError, Result};
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

#[derive(Debug, Clone, Serialize, Deserialize)]
struct IpcEnvelope {
    token: String,
    message: IpcMessage,
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
            use tokio::net::TcpListener;

            // Parse TCP address: tcp://127.0.0.1:35873
            let path_str = self.socket_path.to_string_lossy().to_string();
            let addr_str = path_str.strip_prefix("tcp://").unwrap_or("127.0.0.1:35873");

            info!("IPC server listening on TCP: {}", addr_str);

            let listener = TcpListener::bind(addr_str).await.map_err(|e| {
                PasswordManagerError::from(DatabaseError::Ipc(format!(
                    "Failed to bind TCP socket: {}",
                    e
                )))
            })?;

            loop {
                match listener.accept().await {
                    Ok((mut stream, _addr)) => {
                        debug!("IPC client connected");

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
                                                            let _ = stream
                                                                .write_all(
                                                                    &response_len.to_be_bytes(),
                                                                )
                                                                .await;
                                                            let _ = stream
                                                                .write_all(&response_bytes)
                                                                .await;
                                                            let _ = stream.flush().await;
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
            use tokio::net::TcpStream;

            // Parse TCP address: tcp://127.0.0.1:35873
            let path_str = self.socket_path.to_string_lossy().to_string();
            let addr_str = path_str.strip_prefix("tcp://").unwrap_or("127.0.0.1:35873");

            // Connect to TCP socket with bounded retries so callers don't hang forever
            let connect_deadline =
                tokio::time::Instant::now() + tokio::time::Duration::from_secs(3);
            let mut stream = loop {
                match TcpStream::connect(addr_str).await {
                    Ok(s) => break s,
                    Err(e) => {
                        // Server might not be ready yet, retry after a short delay
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
    }
}

/// Get the default IPC socket path for the platform
pub fn default_ipc_socket_path() -> PathBuf {
    if cfg!(target_os = "windows") {
        // Windows: Use TCP localhost (more reliable than named pipes)
        PathBuf::from("tcp://127.0.0.1:35873")
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
