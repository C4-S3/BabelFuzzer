use tokio::time::{sleep, Duration};

// Include the generated proto code
pub mod echo {
    tonic::include_proto!("echo");
}

use echo::echo_client::EchoClient;
use echo::EchoRequest;

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
async fn test_grpc_echo_server() {
    use server::echo::echo_server::EchoServer;
    use tonic::transport::Server;

    // Spawn server on a background task
    let server_handle = tokio::spawn(async {
        let addr = "[::1]:50051".parse().unwrap();
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
    let mut client = EchoClient::connect("http://[::1]:50051")
        .await
        .expect("Failed to connect to server");

    let request = tonic::Request::new(EchoRequest {
        payload: b"hello".to_vec(),
    });

    let response = client
        .echo_message(request)
        .await
        .expect("Failed to get response");

    let response_payload = response.into_inner().payload;

    // Assert response matches input
    assert_eq!(response_payload, b"hello");

    // Clean up: abort the server task
    server_handle.abort();
}
