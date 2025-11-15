// gRPC connection pool implementation for improved throughput
use anyhow::{Context, Result};
use std::sync::atomic::{AtomicUsize, Ordering};
use tonic::transport::Channel;

use super::client::echo::echo_client::EchoClient;
use super::client::echo::EchoRequest;

/// Connection pool for gRPC clients using round-robin channel selection
pub struct GrpcPool {
    channels: Vec<Channel>,
    next: AtomicUsize,
}

impl GrpcPool {
    /// Create a new connection pool with the specified number of connections
    pub async fn new(endpoint: &str, pool_size: usize) -> Result<Self> {
        if pool_size == 0 {
            anyhow::bail!("Pool size must be at least 1");
        }

        let mut channels = Vec::with_capacity(pool_size);

        for _ in 0..pool_size {
            let channel = Channel::from_shared(endpoint.to_string())
                .context("Invalid endpoint URL")?
                .connect()
                .await
                .context("Failed to connect to gRPC server")?;
            channels.push(channel);
        }

        Ok(Self {
            channels,
            next: AtomicUsize::new(0),
        })
    }

    /// Get a channel from the pool using round-robin selection
    pub fn get_channel(&self) -> Channel {
        let index = self.next.fetch_add(1, Ordering::Relaxed);
        self.channels[index % self.channels.len()].clone()
    }

    /// Send data to the Echo service using a channel from the pool
    pub async fn echo(&self, data: Vec<u8>) -> Result<Vec<u8>> {
        let channel = self.get_channel();
        let mut client = EchoClient::new(channel);

        let request = tonic::Request::new(EchoRequest { payload: data });

        let response = client
            .echo_message(request)
            .await
            .context("Failed to call echo_message")?;

        Ok(response.into_inner().payload)
    }

    /// Get the number of channels in the pool
    pub fn pool_size(&self) -> usize {
        self.channels.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::{sleep, Duration};

    // Re-use the service implementation from the client tests
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
                let response = EchoResponse { payload };
                Ok(Response::new(response))
            }
        }
    }

    #[tokio::test]
    async fn test_pool_round_robin() {
        use server::echo::echo_server::EchoServer;
        use tonic::transport::Server;

        // Spawn server on a background task
        let _server_handle = tokio::spawn(async {
            let addr = "[::1]:50057".parse().unwrap();
            let echo_service = server::EchoService::default();

            Server::builder()
                .add_service(EchoServer::new(echo_service))
                .serve(addr)
                .await
                .unwrap();
        });

        // Give the server time to start
        sleep(Duration::from_millis(100)).await;

        // Create a pool with 3 channels
        let pool = GrpcPool::new("http://[::1]:50057", 3)
            .await
            .expect("Failed to create pool");

        assert_eq!(pool.pool_size(), 3);

        // Get channels and verify round-robin behavior
        // We track the internal counter to verify it cycles through all channels
        let initial_index = pool.next.load(Ordering::Relaxed);

        let _ch1 = pool.get_channel();
        assert_eq!(pool.next.load(Ordering::Relaxed), initial_index + 1);

        let _ch2 = pool.get_channel();
        assert_eq!(pool.next.load(Ordering::Relaxed), initial_index + 2);

        let _ch3 = pool.get_channel();
        assert_eq!(pool.next.load(Ordering::Relaxed), initial_index + 3);

        // Fourth call should wrap around (index % 3)
        let _ch4 = pool.get_channel();
        assert_eq!(pool.next.load(Ordering::Relaxed), initial_index + 4);
    }

    #[tokio::test]
    async fn test_pool_echo() {
        use server::echo::echo_server::EchoServer;
        use tonic::transport::Server;

        // Spawn server on a background task
        let _server_handle = tokio::spawn(async {
            let addr = "[::1]:50058".parse().unwrap();
            let echo_service = server::EchoService::default();

            Server::builder()
                .add_service(EchoServer::new(echo_service))
                .serve(addr)
                .await
                .unwrap();
        });

        // Give the server time to start
        sleep(Duration::from_millis(100)).await;

        // Create a pool with 2 channels
        let pool = GrpcPool::new("http://[::1]:50058", 2)
            .await
            .expect("Failed to create pool");

        // Test echo functionality
        let response = pool
            .echo(b"test".to_vec())
            .await
            .expect("Failed to echo");

        assert_eq!(response, b"test");
    }

    #[tokio::test]
    async fn test_pool_concurrent_requests() {
        use server::echo::echo_server::EchoServer;
        use tonic::transport::Server;

        // Spawn server on a background task
        let _server_handle = tokio::spawn(async {
            let addr = "[::1]:50059".parse().unwrap();
            let echo_service = server::EchoService::default();

            Server::builder()
                .add_service(EchoServer::new(echo_service))
                .serve(addr)
                .await
                .unwrap();
        });

        // Give the server time to start
        sleep(Duration::from_millis(100)).await;

        // Create a pool with 4 channels
        let pool = std::sync::Arc::new(
            GrpcPool::new("http://[::1]:50059", 4)
                .await
                .expect("Failed to create pool")
        );

        // Send multiple concurrent requests
        let mut handles = vec![];
        for i in 0..10 {
            let pool_clone = pool.clone();
            let handle = tokio::spawn(async move {
                let data = format!("request_{}", i).into_bytes();
                pool_clone.echo(data.clone()).await.expect("Echo failed")
            });
            handles.push(handle);
        }

        // Wait for all requests to complete
        for handle in handles {
            let _ = handle.await.expect("Task failed");
        }
    }
}
