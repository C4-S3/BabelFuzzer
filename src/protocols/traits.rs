// Protocol trait definitions

use async_trait::async_trait;

/// The Protocol trait defines the interface for protocol-specific implementations.
///
/// This trait allows for different protocol implementations (gRPC, HTTP/3, etc.)
/// to be used interchangeably in the fuzzer.
#[async_trait]
pub trait Protocol: Send + Sync {
    /// The request type for this protocol
    type Request: Send + Sync + 'static;

    /// The response type for this protocol
    type Response: Send + Sync + 'static;

    /// The error type for this protocol
    type Error: std::error::Error + Send + Sync + 'static;

    /// Connect to the target server
    ///
    /// # Arguments
    /// * `target` - The target address or URL to connect to
    ///
    /// # Returns
    /// * `Ok(())` if the connection was successful
    /// * `Err(Self::Error)` if the connection failed
    async fn connect(&mut self, target: &str) -> Result<(), Self::Error>;

    /// Send a request to the connected server
    ///
    /// # Arguments
    /// * `req` - The request to send
    ///
    /// # Returns
    /// * `Ok(Response)` if the request was successful
    /// * `Err(Self::Error)` if the request failed
    async fn send_request(&mut self, req: Self::Request) -> Result<Self::Response, Self::Error>;

    /// Discover the schema of the protocol
    ///
    /// This method is used to discover the schema of the protocol, which can be used
    /// for generating requests.
    ///
    /// # Returns
    /// * `Ok(serde_json::Value)` containing the schema
    /// * `Err(Self::Error)` if schema discovery failed
    async fn discover_schema(&mut self) -> Result<serde_json::Value, Self::Error>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core_types::FuzzerError;

    /// Dummy protocol implementation for testing
    struct DummyProtocol {
        connected: bool,
    }

    impl DummyProtocol {
        fn new() -> Self {
            Self { connected: false }
        }
    }

    #[async_trait]
    impl Protocol for DummyProtocol {
        type Request = Vec<u8>;
        type Response = Vec<u8>;
        type Error = FuzzerError;

        async fn connect(&mut self, _target: &str) -> Result<(), Self::Error> {
            self.connected = true;
            Ok(())
        }

        async fn send_request(&mut self, req: Self::Request) -> Result<Self::Response, Self::Error> {
            if !self.connected {
                return Err(FuzzerError::Protocol("Not connected".to_string()));
            }
            // Echo back the request as response
            Ok(req)
        }

        async fn discover_schema(&mut self) -> Result<serde_json::Value, Self::Error> {
            if !self.connected {
                return Err(FuzzerError::Protocol("Not connected".to_string()));
            }
            Ok(serde_json::json!({
                "type": "dummy",
                "version": "1.0"
            }))
        }
    }

    #[tokio::test]
    async fn test_protocol_trait_object() {
        // Test that a dummy struct implementing Protocol can be trait-object boxed and invoked
        let mut protocol: Box<dyn Protocol<Request=Vec<u8>, Response=Vec<u8>, Error=FuzzerError>> =
            Box::new(DummyProtocol::new());

        // Test connect
        let connect_result = protocol.connect("localhost:8080").await;
        assert!(connect_result.is_ok());

        // Test send_request
        let test_data = vec![1, 2, 3, 4, 5];
        let response = protocol.send_request(test_data.clone()).await;
        assert!(response.is_ok());
        assert_eq!(response.unwrap(), test_data);

        // Test discover_schema
        let schema = protocol.discover_schema().await;
        assert!(schema.is_ok());
        let schema_value = schema.unwrap();
        assert_eq!(schema_value["type"], "dummy");
        assert_eq!(schema_value["version"], "1.0");
    }

    #[tokio::test]
    async fn test_protocol_without_connection() {
        let mut protocol = DummyProtocol::new();

        // Test send_request without connecting first
        let test_data = vec![1, 2, 3];
        let response = protocol.send_request(test_data).await;
        assert!(response.is_err());

        // Test discover_schema without connecting first
        let schema = protocol.discover_schema().await;
        assert!(schema.is_err());
    }
}
