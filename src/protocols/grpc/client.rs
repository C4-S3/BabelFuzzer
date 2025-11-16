// gRPC client implementation
use anyhow::{Context, Result};
use async_trait::async_trait;
use tonic::transport::Channel;
use crate::core_types::FuzzerError;
use crate::protocols::traits::Protocol;

// Include the generated proto code
pub mod echo {
    tonic::include_proto!("echo");
}

use echo::echo_client::EchoClient;
use echo::EchoRequest;

/// gRPC client for fuzzing
pub struct GrpcClient {
    endpoint: String,
    channel: Channel,
}

impl GrpcClient {
    /// Create a new gRPC client connected to the specified endpoint
    pub async fn new(endpoint: &str) -> Result<Self> {
        let channel = Channel::from_shared(endpoint.to_string())
            .context("Invalid endpoint URL")?
            .connect()
            .await
            .context("Failed to connect to gRPC server")?;

        Ok(Self {
            endpoint: endpoint.to_string(),
            channel,
        })
    }

    /// Send data to the Echo service and return the response
    pub async fn echo(&self, data: Vec<u8>) -> Result<Vec<u8>> {
        let mut client = EchoClient::new(self.channel.clone());

        let request = tonic::Request::new(EchoRequest { payload: data });

        let response = client
            .echo_message(request)
            .await
            .context("Failed to call echo_message")?;

        Ok(response.into_inner().payload)
    }

    /// Get the endpoint this client is connected to
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }
}

/// Implementation of the Protocol trait for GrpcClient
#[async_trait]
impl Protocol for GrpcClient {
    type Request = Vec<u8>;
    type Response = Vec<u8>;
    type Error = FuzzerError;

    async fn connect(&mut self, target: &str) -> Result<(), Self::Error> {
        // Create a new channel
        let channel = Channel::from_shared(target.to_string())
            .map_err(|e| FuzzerError::Protocol(format!("Invalid endpoint URL: {}", e)))?
            .connect()
            .await
            .map_err(|e| FuzzerError::Protocol(format!("Failed to connect to gRPC server: {}", e)))?;

        self.endpoint = target.to_string();
        self.channel = channel;
        Ok(())
    }

    async fn send_request(&mut self, req: Self::Request) -> Result<Self::Response, Self::Error> {
        self.echo(req)
            .await
            .map_err(|e| FuzzerError::Protocol(format!("Failed to send gRPC request: {}", e)))
    }

    async fn discover_schema(&mut self) -> Result<serde_json::Value, Self::Error> {
        // TODO: Implement full gRPC reflection-based schema discovery
        // For now, return a basic schema for the Echo service
        Ok(serde_json::json!({
            "protocol": "grpc",
            "services": [{
                "name": "echo.Echo",
                "methods": [{
                    "name": "EchoMessage",
                    "input_type": "echo.EchoRequest",
                    "output_type": "echo.EchoResponse"
                }]
            }],
            "endpoint": self.endpoint
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::{sleep, Duration};

    // Re-use the service implementation from the example
    pub mod server {
        use tonic::{Request, Response, Status};

        pub mod echo {
            tonic::include_proto!("echo");
        }

        use echo::echo_server::Echo;
        use echo::{EchoRequest, EchoResponse};

        #[derive(Debug, Default)]
        pub struct EchoService;

        #[tonic::async_trait]
        impl Echo for EchoService {
            async fn echo_message(
                &self,
                request: Request<EchoRequest>,
            ) -> Result<Response<EchoResponse>, Status> {
                let payload = request.into_inner().payload;

                if payload == b"CRASH_ME" {
                    panic!("Intentional crash triggered by payload: CRASH_ME");
                }

                let response = EchoResponse { payload };
                Ok(Response::new(response))
            }
        }
    }

    #[tokio::test]
    async fn test_grpc_client_echo() {
        use server::echo::echo_server::EchoServer;
        use tonic::transport::Server;

        // Spawn server on a background task
        let _server_handle = tokio::spawn(async {
            let addr = "127.0.0.1:50052".parse().unwrap();
            let echo_service = server::EchoService::default();

            Server::builder()
                .add_service(EchoServer::new(echo_service))
                .serve(addr)
                .await
                .unwrap();
        });

        // Give the server time to start
        sleep(Duration::from_millis(100)).await;

        // Create client and send request
        let client = GrpcClient::new("http://127.0.0.1:50052")
            .await
            .expect("Failed to create client");

        let response = client
            .echo(b"hi".to_vec())
            .await
            .expect("Failed to echo");

        assert_eq!(response, b"hi");
        assert_eq!(client.endpoint(), "http://127.0.0.1:50052");
    }

    #[tokio::test]
    async fn test_grpc_client_echo_different_data() {
        use server::echo::echo_server::EchoServer;
        use tonic::transport::Server;

        // Spawn server on a background task
        let _server_handle = tokio::spawn(async {
            let addr = "127.0.0.1:50053".parse().unwrap();
            let echo_service = server::EchoService::default();

            Server::builder()
                .add_service(EchoServer::new(echo_service))
                .serve(addr)
                .await
                .unwrap();
        });

        // Give the server time to start
        sleep(Duration::from_millis(100)).await;

        // Create client and send request
        let client = GrpcClient::new("http://127.0.0.1:50053")
            .await
            .expect("Failed to create client");

        let test_data = b"test fuzzing payload".to_vec();
        let response = client
            .echo(test_data.clone())
            .await
            .expect("Failed to echo");

        assert_eq!(response, test_data);
    }
}
