//! IPC (Inter-Process Communication) for daemon communication
//!
//! Uses Unix domain sockets on Linux/macOS and named pipes on Windows.

use crate::{Result, PasswordManagerError};
use crate::daemon::DaemonVault;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::path::PathBuf;
#[allow(unused_imports)]
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{info, error, debug};

/// IPC message types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IpcMessage {
    GetCredential { domain: String },
    GetCredentialResponse { username: Option<String>, password: Option<String>, title: Option<String> },
    CheckVault,
    VaultStatusResponse { unlocked: bool },
    LockVault,
    Shutdown,
}

/// IPC server for daemon communication
#[allow(dead_code)]
pub struct IpcServer {
    socket_path: PathBuf,
    vault: Arc<DaemonVault>,
}

impl IpcServer {
    /// Create a new IPC server
    pub fn new(socket_path: PathBuf, vault: Arc<DaemonVault>) -> Self {
        Self { socket_path, vault }
    }

    /// Start the IPC server
    pub async fn run(&self) -> Result<()> {
        info!("Starting IPC server at {:?}", self.socket_path);

        // Remove existing socket if present
        if self.socket_path.exists() {
            std::fs::remove_file(&self.socket_path)
                .map_err(|e| PasswordManagerError::Database(format!("Failed to remove socket: {}", e)))?;
        }

        #[cfg(unix)]
        {
            use tokio::net::UnixListener;

            let listener = UnixListener::bind(&self.socket_path)
                .map_err(|e| PasswordManagerError::Database(format!("Failed to bind socket: {}", e)))?;

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
                                            match serde_json::from_slice::<IpcMessage>(&buffer) {
                                                Ok(msg) => {
                                                    let response = self.handle_message(msg).await;
                                                    match serde_json::to_vec(&response) {
                                                        Ok(response_bytes) => {
                                                            let response_len = response_bytes.len() as u32;
                                                            if stream.write_all(&response_len.to_be_bytes()).await.is_ok()
                                                                && stream.write_all(&response_bytes).await.is_ok()
                                                            {
                                                                // Flush to ensure message is sent
                                                                let _ = stream.flush().await;
                                                            }
                                                        }
                                                        Err(e) => {
                                                            error!("Failed to serialize response: {}", e);
                                                        }
                                                    }
                                                }
                                                Err(e) => {
                                                    error!("Failed to parse IPC message: {}", e);
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
            use tokio::net::windows::named_pipe::ServerOptions;
            use std::time::Duration;

            // Extract pipe name from path
            // Path format: \\.\pipe\sentinelpass
            let pipe_name = self.socket_path.to_string_lossy().replace("\\\\.\\pipe\\", "");

            info!("IPC server listening on named pipe: {}", pipe_name);

            loop {
                // Create named pipe server
                let server = match ServerOptions::new()
                    .first_pipe_instance(true)
                    .create(&pipe_name)
                {
                    Ok(s) => s,
                    Err(e) => {
                        error!("Failed to create named pipe: {}", e);
                        tokio::time::sleep(Duration::from_secs(1)).await;
                        continue;
                    }
                };

                // Wait for client connection
                match server.connect().await {
                    Ok(_) => {
                        debug!("IPC client connected to named pipe");

                        // Use the connected server directly for reading and writing
                        let mut server = server;

                        let mut length_buf = [0u8; 4];
                        match server.read_exact(&mut length_buf).await {
                            Ok(_) => {
                                let length = u32::from_be_bytes(length_buf) as usize;
                                if length > 0 && length <= 65536 {
                                    let mut buffer = vec![0u8; length];
                                    match server.read_exact(&mut buffer).await {
                                        Ok(_) => {
                                            match serde_json::from_slice::<IpcMessage>(&buffer) {
                                                Ok(msg) => {
                                                    let response = self.handle_message(msg).await;
                                                    match serde_json::to_vec(&response) {
                                                        Ok(response_bytes) => {
                                                            let response_len = response_bytes.len() as u32;
                                                            if server.write_all(&response_len.to_be_bytes()).await.is_ok()
                                                                && server.write_all(&response_bytes).await.is_ok()
                                                            {
                                                                let _ = server.flush().await;
                                                            }
                                                        }
                                                        Err(e) => {
                                                            error!("Failed to serialize response: {}", e);
                                                        }
                                                    }
                                                }
                                                Err(e) => {
                                                    error!("Failed to parse IPC message: {}", e);
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
    }

    /// Handle an IPC message
    #[allow(dead_code)]
    async fn handle_message(&self, msg: IpcMessage) -> IpcMessage {
        match msg {
            IpcMessage::GetCredential { domain } => {
                debug!("IPC: GetCredential for domain '{}'", domain);

                match self.vault.get_credential(&domain).await {
                    Ok(Some(cred)) => {
                        IpcMessage::GetCredentialResponse {
                            username: Some(cred.username),
                            password: Some(cred.password),
                            title: Some(cred.title),
                        }
                    }
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
            _ => {
                IpcMessage::VaultStatusResponse { unlocked: false }
            }
        }
    }
}

/// IPC client for native messaging host
#[allow(dead_code)]
pub struct IpcClient {
    socket_path: PathBuf,
}

impl IpcClient {
    /// Create a new IPC client
    pub fn new(socket_path: PathBuf) -> Self {
        Self { socket_path }
    }

    /// Send a message and wait for response
    #[allow(unused_variables)]
    pub async fn send(&self, msg: IpcMessage) -> Result<IpcMessage> {
        #[cfg(unix)]
        {
            use tokio::net::UnixStream;

            let mut stream = UnixStream::connect(&self.socket_path)
                .map_err(|e| PasswordManagerError::Database(format!("Failed to connect to daemon: {}", e)))?;

            let msg_bytes = serde_json::to_vec(&msg)
                .map_err(|e| PasswordManagerError::Database(format!("Failed to serialize message: {}", e)))?;

            let length = msg_bytes.len() as u32;

            stream.write_all(&length.to_be_bytes()).await
                .map_err(|e| PasswordManagerError::Database(format!("Failed to write length: {}", e)))?;

            stream.write_all(&msg_bytes).await
                .map_err(|e| PasswordManagerError::Database(format!("Failed to write message: {}", e)))?;

            stream.flush().await
                .map_err(|e| PasswordManagerError::Database(format!("Failed to flush: {}", e)))?;

            // Read response
            let mut length_buf = [0u8; 4];
            stream.read_exact(&mut length_buf).await
                .map_err(|e| PasswordManagerError::Database(format!("Failed to read length: {}", e)))?;

            let response_length = u32::from_be_bytes(length_buf) as usize;

            if response_length > 65536 {
                return Err(PasswordManagerError::Database("Response too large".to_string()));
            }

            let mut buffer = vec![0u8; response_length];
            stream.read_exact(&mut buffer).await
                .map_err(|e| PasswordManagerError::Database(format!("Failed to read response: {}", e)))?;

            serde_json::from_slice::<IpcMessage>(&buffer)
                .map_err(|e| PasswordManagerError::Database(format!("Failed to parse response: {}", e)))
        }

        #[cfg(windows)]
        {
            use tokio::net::windows::named_pipe::ClientOptions;

            // Extract pipe name from path
            let pipe_name = self.socket_path.to_string_lossy().replace("\\\\.\\pipe\\", "");

            // Connect to named pipe
            let mut client = loop {
                match ClientOptions::new().open(&pipe_name) {
                    Ok(c) => break c,
                    Err(e) => {
                        // Server might not be ready yet, retry after a short delay
                        if e.raw_os_error() == Some(2) || e.raw_os_error() == Some(231) {
                            // ERROR_FILE_NOT_FOUND or ERROR_PIPE_BUSY
                            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                            continue;
                        }
                        return Err(PasswordManagerError::Database(format!("Failed to connect to daemon: {}", e)));
                    }
                }
            };

            let msg_bytes = serde_json::to_vec(&msg)
                .map_err(|e| PasswordManagerError::Database(format!("Failed to serialize message: {}", e)))?;

            let length = msg_bytes.len() as u32;

            client.write_all(&length.to_be_bytes()).await
                .map_err(|e| PasswordManagerError::Database(format!("Failed to write length: {}", e)))?;

            client.write_all(&msg_bytes).await
                .map_err(|e| PasswordManagerError::Database(format!("Failed to write message: {}", e)))?;

            client.flush().await
                .map_err(|e| PasswordManagerError::Database(format!("Failed to flush: {}", e)))?;

            // Read response
            let mut length_buf = [0u8; 4];
            client.read_exact(&mut length_buf).await
                .map_err(|e| PasswordManagerError::Database(format!("Failed to read length: {}", e)))?;

            let response_length = u32::from_be_bytes(length_buf) as usize;

            if response_length > 65536 {
                return Err(PasswordManagerError::Database("Response too large".to_string()));
            }

            let mut buffer = vec![0u8; response_length];
            client.read_exact(&mut buffer).await
                .map_err(|e| PasswordManagerError::Database(format!("Failed to read response: {}", e)))?;

            serde_json::from_slice::<IpcMessage>(&buffer)
                .map_err(|e| PasswordManagerError::Database(format!("Failed to parse response: {}", e)))
        }
    }
}

/// Get the default IPC socket path for the platform
pub fn default_ipc_socket_path() -> PathBuf {
    if cfg!(target_os = "windows") {
        // Windows: Use named pipes (not yet implemented)
        PathBuf::from(r"\\.\pipe\sentinelpass")
    } else {
        // Unix: Use Unix domain socket
        let runtime_dir = std::env::var("XDG_RUNTIME_DIR")
            .unwrap_or_else(|_| "/tmp".to_string());

        PathBuf::from(runtime_dir).join("sentinelpass.sock")
    }
}
