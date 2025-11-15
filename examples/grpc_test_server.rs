use tonic::{transport::Server, Request, Response, Status};

// Include the generated proto code
pub mod echo {
    tonic::include_proto!("echo");
}

use echo::echo_server::{Echo, EchoServer};
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

        // Intentional crash for fuzzing validation
        if payload == b"CRASH_ME" {
            panic!("Intentional crash triggered by payload: CRASH_ME");
        }

        // Normal echo behavior
        let response = EchoResponse { payload };
        Ok(Response::new(response))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = "[::1]:50051".parse()?;
    let echo_service = EchoService::default();

    println!("gRPC Echo server listening on {}", addr);
    println!("Send payload 'CRASH_ME' to trigger intentional crash");

    Server::builder()
        .add_service(EchoServer::new(echo_service))
        .serve(addr)
        .await?;

    Ok(())
}
