use std::process::Command;
use tokio::time::{sleep, Duration};

// Re-use the service implementation from other tests
mod server {
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
                return Err(Status::internal("Intentional crash triggered by payload"));
            }

            let response = EchoResponse { payload };
            Ok(Response::new(response))
        }
    }
}

#[tokio::test]
async fn test_cli_fuzz_run() {
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
    sleep(Duration::from_millis(200)).await;

    // Build the binary first
    let build_status = Command::new("cargo")
        .args(&["build", "--bin", "proto-fuzzer"])
        .status()
        .expect("Failed to build binary");

    assert!(build_status.success(), "Binary build failed");

    // Run the fuzzer CLI
    let output = Command::new("cargo")
        .args(&[
            "run",
            "--bin",
            "proto-fuzzer",
            "--",
            "--target",
            "http://[::1]:50057",
            "--iterations",
            "5",
            "--timeout-ms",
            "100",
        ])
        .env("RUST_LOG", "error") // Reduce log noise in test output
        .output()
        .expect("Failed to execute fuzzer");

    // Check that the command succeeded
    if !output.status.success() {
        eprintln!("stdout: {}", String::from_utf8_lossy(&output.stdout));
        eprintln!("stderr: {}", String::from_utf8_lossy(&output.stderr));
    }
    assert!(
        output.status.success(),
        "Fuzzer command failed with exit code: {:?}",
        output.status.code()
    );

    // Parse the JSON output
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Split by lines and look for JSON lines (starting with { or })
    let lines: Vec<&str> = stdout.lines().collect();
    let mut json_lines = Vec::new();
    let mut in_json = false;
    let mut brace_count = 0;

    for line in lines.iter() {
        let trimmed = line.trim();

        // Start of JSON
        if trimmed.starts_with('{') && !in_json {
            in_json = true;
            brace_count = 0;
        }

        if in_json {
            json_lines.push(*line);

            // Count braces
            for c in trimmed.chars() {
                if c == '{' {
                    brace_count += 1;
                } else if c == '}' {
                    brace_count -= 1;
                }
            }

            // End of JSON
            if brace_count == 0 {
                break;
            }
        }
    }

    let json_str = json_lines.join("\n");

    let json: serde_json::Value =
        serde_json::from_str(&json_str).expect("Failed to parse JSON output");

    // Validate the JSON structure
    assert!(
        json.get("iterations").is_some(),
        "JSON missing 'iterations' key"
    );
    assert!(json.get("crashes").is_some(), "JSON missing 'crashes' key");

    // Check that iterations matches what we requested
    assert_eq!(
        json["iterations"].as_u64().unwrap(),
        5,
        "Expected 5 iterations"
    );

    // Crashes should be an array (might be empty or have crashes depending on mutations)
    assert!(
        json["crashes"].is_array(),
        "crashes should be an array"
    );

    println!("Fuzzer output JSON: {}", json_str);
}

#[tokio::test]
async fn test_cli_invalid_target() {
    // Run fuzzer with invalid target
    let output = Command::new("cargo")
        .args(&[
            "run",
            "--bin",
            "proto-fuzzer",
            "--",
            "--target",
            "http://localhost:9999", // Non-existent server
            "--iterations",
            "1",
        ])
        .env("RUST_LOG", "error")
        .output()
        .expect("Failed to execute fuzzer");

    // Should fail to connect
    assert!(
        !output.status.success(),
        "Fuzzer should fail with invalid target"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Check for error in either stderr or stdout
    let has_error = stderr.contains("Failed to connect")
        || stderr.contains("error")
        || stderr.contains("connection")
        || stdout.contains("Failed to connect")
        || stdout.contains("error")
        || stdout.contains("connection");

    assert!(has_error, "Expected connection error in output");
}
