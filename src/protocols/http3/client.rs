//! HTTP/3 client implementation
//!
//! This module provides a simplified HTTP/3 client built on Quinn (QUIC).
//! It enables HTTP/3 fuzzing for discovering CVEs in HTTP/3 implementations.
//!
//! NOTE: Currently using manual HTTP/3 frame construction due to h3-quinn/quinn version
//! compatibility issues. Full h3 integration coming in future updates.

use anyhow::{Context, Result};
use async_trait::async_trait;
use quinn::{ClientConfig, Connection, Endpoint};
use rustls::pki_types::ServerName;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use url::Url;

use crate::core_types::FuzzerError;
use crate::protocols::traits::Protocol;

/// HTTP/3 client for fuzzing
///
/// Built on top of Quinn (QUIC).
/// Supports sending data over QUIC streams for HTTP/3 fuzzing.
pub struct Http3Client {
    /// The QUIC endpoint
    endpoint: Endpoint,

    /// Active QUIC connection (if connected)
    connection: Option<Connection>,

    /// Target server name for TLS
    server_name: String,

    /// Target server address
    address: SocketAddr,

    /// Target URL
    url: String,
}

impl Http3Client {
    /// Create a new HTTP/3 client for the given URL
    ///
    /// # Arguments
    /// * `url` - The target URL (must use https://)
    ///
    /// # Example
    /// ```no_run
    /// use proto_fuzzer::protocols::http3::client::Http3Client;
    ///
    /// #[tokio::main]
    /// async fn main() {
    ///     let client = Http3Client::new("https://cloudflare-quic.com").await.unwrap();
    /// }
    /// ```
    pub async fn new(url: &str) -> Result<Self> {
        // Parse URL
        let parsed_url = Url::parse(url).context("Invalid URL")?;

        // Validate scheme
        if parsed_url.scheme() != "https" {
            anyhow::bail!("Only https:// URLs are supported for HTTP/3");
        }

        // Extract server name
        let server_name = parsed_url
            .host_str()
            .context("No host in URL")?
            .to_string();

        // Resolve address
        let port = parsed_url.port().unwrap_or(443);
        let address = format!("{}:{}", server_name, port)
            .to_socket_addrs()
            .context("Failed to resolve address")?
            .next()
            .context("No addresses found")?;

        // Create TLS config with system root certificates
        let crypto = rustls::ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore {
                roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
            })
            .with_no_client_auth();

        let mut client_config = ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
                .context("Failed to create QUIC config")?,
        ));

        // Configure transport
        let mut transport_config = quinn::TransportConfig::default();
        transport_config.max_idle_timeout(Some(std::time::Duration::from_secs(30).try_into()?));
        transport_config.keep_alive_interval(Some(std::time::Duration::from_secs(5)));
        client_config.transport_config(Arc::new(transport_config));

        // Create endpoint
        let mut endpoint = Endpoint::client("0.0.0.0:0".parse()?)?;
        endpoint.set_default_client_config(client_config);

        Ok(Self {
            endpoint,
            connection: None,
            server_name,
            address,
            url: url.to_string(),
        })
    }

    /// Connect to the HTTP/3 server
    pub async fn connect(&mut self) -> Result<()> {
        let server_name = ServerName::try_from(self.server_name.clone())
            .map_err(|e| anyhow::anyhow!("Invalid server name: {:?}", e))?;

        let connection = self
            .endpoint
            .connect(self.address, &server_name.to_str())?
            .await
            .context("Failed to establish QUIC connection")?;

        self.connection = Some(connection);
        Ok(())
    }

    /// Send data over a QUIC stream (simulating HTTP/3 request)
    ///
    /// # Arguments
    /// * `data` - The data to send over the stream
    ///
    /// # Returns
    /// Response data read from the stream
    pub async fn send_data(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let conn = self
            .connection
            .as_ref()
            .context("Not connected - call connect() first")?;

        // Open bidirectional stream
        let (mut send, mut recv) = conn
            .open_bi()
            .await
            .context("Failed to open bidirectional stream")?;

        // Send data
        send.write_all(data)
            .await
            .context("Failed to write data")?;

        send.finish().context("Failed to finish send stream")?;

        // Read response (max 1MB)
        let response = recv
            .read_to_end(1024 * 1024)
            .await
            .context("Failed to read response")?;

        Ok(response)
    }

    /// Check if connected
    pub fn is_connected(&self) -> bool {
        self.connection.is_some()
    }

    /// Close the connection
    pub async fn close(&mut self) {
        if let Some(conn) = &self.connection {
            conn.close(0u32.into(), b"closing");
        }
        self.connection = None;
    }

    /// Get the target URL
    pub fn url(&self) -> &str {
        &self.url
    }
}

/// Implementation of Protocol trait for HTTP/3 client
#[async_trait]
impl Protocol for Http3Client {
    type Request = Vec<u8>;
    type Response = Vec<u8>;
    type Error = FuzzerError;

    async fn connect(&mut self, target: &str) -> Result<(), Self::Error> {
        // Create new client for target
        let mut new_client = Self::new(target)
            .await
            .map_err(|e| FuzzerError::Protocol(format!("Failed to create HTTP/3 client: {}", e)))?;

        new_client
            .connect()
            .await
            .map_err(|e| FuzzerError::Protocol(format!("Failed to connect: {}", e)))?;

        // Replace self with new client
        *self = new_client;
        Ok(())
    }

    async fn send_request(&mut self, req: Self::Request) -> Result<Self::Response, Self::Error> {
        self.send_data(&req)
            .await
            .map_err(|e| FuzzerError::Protocol(format!("HTTP/3 request failed: {}", e)))
    }

    async fn discover_schema(&mut self) -> Result<serde_json::Value, Self::Error> {
        // For HTTP/3, return metadata about the connection
        Ok(serde_json::json!({
            "protocol": "http/3",
            "server": self.server_name,
            "address": self.address.to_string(),
            "url": self.url,
            "connected": self.is_connected(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore] // Requires network access
    async fn test_http3_client_creation() {
        let client = Http3Client::new("https://cloudflare-quic.com").await;
        assert!(client.is_ok());
    }

    #[tokio::test]
    #[ignore] // Requires network access
    async fn test_http3_connect() {
        let mut client = Http3Client::new("https://cloudflare-quic.com")
            .await
            .unwrap();

        let result = client.connect().await;
        assert!(result.is_ok());
        assert!(client.is_connected());
    }

    #[test]
    fn test_invalid_url() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(Http3Client::new("http://example.com"));
        assert!(result.is_err());
    }

    #[test]
    fn test_malformed_url() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(Http3Client::new("not-a-url"));
        assert!(result.is_err());
    }

    #[test]
    #[ignore] // Requires DNS resolution
    fn test_is_connected_initial() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let client = rt
            .block_on(Http3Client::new("https://cloudflare-quic.com"))
            .unwrap();
        assert!(!client.is_connected());
    }

    #[test]
    #[ignore] // Requires DNS resolution
    fn test_url_getter() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let url = "https://cloudflare-quic.com";
        let client = rt.block_on(Http3Client::new(url)).unwrap();
        assert_eq!(client.url(), url);
    }
}
