//! Windows named pipe transport for IPC.

use super::{TransportConfig, TransportError, TransportResult, MAX_MESSAGE_SIZE};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Windows named pipe transport
pub struct WindowsNamedPipeTransport {
    pipe_name: String,
}

impl WindowsNamedPipeTransport {
    /// Create a new Windows named pipe transport
    pub fn new(config: TransportConfig) -> TransportResult<Self> {
        let pipe_name = config
            .windows_pipe_path
            .or_else(|| {
                // Default to named pipe
                Some(r"\\.\pipe\SentinelPass".to_string())
            })
            .ok_or_else(|| TransportError::Other("Windows pipe path not configured".to_string()))?;

        Ok(Self { pipe_name })
    }

    /// Get the pipe name
    pub fn pipe_name(&self) -> &str {
        &self.pipe_name
    }

    /// Create a new named pipe server instance
    pub fn create_server(
        &self,
    ) -> TransportResult<tokio::net::windows::named_pipe::NamedPipeServer> {
        tokio::net::windows::named_pipe::ServerOptions::new()
            .first_pipe_instance(false)
            .create(&self.pipe_name)
            .map_err(|e| {
                TransportError::ConnectionFailed(format!(
                    "Failed to create named pipe {}: {}",
                    self.pipe_name, e
                ))
            })
    }

    /// Connect as a client (with timeout)
    pub async fn connect(&self, timeout_ms: u64) -> TransportResult<WindowsNamedPipeConnection> {
        use tokio::time::{Duration, Instant};

        let deadline = Instant::now() + Duration::from_millis(timeout_ms);

        loop {
            let client = tokio::net::windows::named_pipe::ClientOptions::new()
                .open(&self.pipe_name)
                .await;
            match client {
                Ok(c) => {
                    return Ok(WindowsNamedPipeConnection::from_client(c));
                }
                Err(e) => {
                    // Check for NotFound specifically by trying to connect and checking the error
                    if Instant::now() >= deadline {
                        return Err(TransportError::Timeout);
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    }
}

/// Windows named pipe connection (can be either server or client side)
pub enum WindowsNamedPipeConnection {
    Server(tokio::net::windows::named_pipe::NamedPipeServer),
    Client(tokio::net::windows::named_pipe::NamedPipeClient),
}

impl WindowsNamedPipeConnection {
    /// Create a connection from a server-side pipe
    pub fn from_server(pipe: tokio::net::windows::named_pipe::NamedPipeServer) -> Self {
        Self::Server(pipe)
    }

    /// Create a connection from a client-side pipe
    pub fn from_client(pipe: tokio::net::windows::named_pipe::NamedPipeClient) -> Self {
        Self::Client(pipe)
    }

    /// Read a message from the connection
    pub async fn read_message(&mut self) -> TransportResult<Vec<u8>> {
        // Read message length (4 bytes, big-endian)
        let mut length_buf = [0u8; 4];
        match self {
            WindowsNamedPipeConnection::Server(p) => p.read_exact(&mut length_buf).await?,
            WindowsNamedPipeConnection::Client(p) => p.read_exact(&mut length_buf).await?,
        };

        let length = u32::from_be_bytes(length_buf) as usize;

        if length == 0 || length > MAX_MESSAGE_SIZE {
            return Err(TransportError::MessageTooLarge {
                size: length,
                max: MAX_MESSAGE_SIZE,
            });
        }

        // Read message payload
        let mut buffer = vec![0u8; length];
        match self {
            WindowsNamedPipeConnection::Server(p) => p.read_exact(&mut buffer).await?,
            WindowsNamedPipeConnection::Client(p) => p.read_exact(&mut buffer).await?,
        };

        Ok(buffer)
    }

    /// Write a message to the connection
    pub async fn write_message(&mut self, data: &[u8]) -> TransportResult<()> {
        let length = data.len() as u32;

        // Validate message size
        if length as usize > MAX_MESSAGE_SIZE {
            return Err(TransportError::MessageTooLarge {
                size: data.len(),
                max: MAX_MESSAGE_SIZE,
            });
        }

        // Write length prefix
        match self {
            WindowsNamedPipeConnection::Server(p) => p.write_all(&length.to_be_bytes()).await?,
            WindowsNamedPipeConnection::Client(p) => p.write_all(&length.to_be_bytes()).await?,
        };

        // Write payload
        match self {
            WindowsNamedPipeConnection::Server(p) => p.write_all(data).await?,
            WindowsNamedPipeConnection::Client(p) => p.write_all(data).await?,
        };

        // Flush
        match self {
            WindowsNamedPipeConnection::Server(p) => p.flush().await?,
            WindowsNamedPipeConnection::Client(p) => p.flush().await?,
        };

        Ok(())
    }

    /// Close the connection
    pub async fn close(&mut self) -> TransportResult<()> {
        match self {
            WindowsNamedPipeConnection::Server(p) => p.disconnect().await?,
            WindowsNamedPipeConnection::Client(p) => {
                // Client doesn't have a disconnect method - just drop it
            }
        };
        Ok(())
    }

    /// Check if the connection is still open
    pub fn is_open(&self) -> bool {
        // For named pipes, we can't easily check without I/O
        // Assume open if we haven't explicitly closed
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_windows_named_pipe_transport_creation() {
        let transport = WindowsNamedPipeTransport::new(TransportConfig {
            windows_pipe_path: Some(r"\\.\pipe\SentinelPass-Test".to_string()),
            ..Default::default()
        });

        assert!(transport.is_ok());
        let transport = transport.unwrap();
        assert_eq!(transport.pipe_name(), r"\\.\pipe\SentinelPass-Test");
    }

    #[test]
    fn test_windows_named_pipe_transport_default() {
        let transport = WindowsNamedPipeTransport::new(TransportConfig::default()).unwrap();
        assert_eq!(transport.pipe_name(), r"\\.\pipe\SentinelPass");
    }

    #[test]
    fn test_transport_config_for_windows() {
        let _config = TransportConfig::for_current_platform();
        // On Windows, this should have a pipe path
        // But this test runs on all platforms, so we just verify it doesn't panic
    }
}
