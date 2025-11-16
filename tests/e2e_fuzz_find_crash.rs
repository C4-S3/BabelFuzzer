use proto_fuzzer::core_types::{CrashInfo, TestCase};
use proto_fuzzer::engine::corpus::Corpus;
use proto_fuzzer::engine::mutator::Mutator;
use proto_fuzzer::orchestrator::reporter;
use proto_fuzzer::protocols::grpc::client::GrpcClient;
use proto_fuzzer::protocols::grpc::fuzzer::fuzz_once;
use tempfile::TempDir;
use tokio::time::{sleep, Duration};

// Test server implementation that crashes on CRASH_ME
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

            // Simulate crash on CRASH_ME payload
            if payload == b"CRASH_ME" {
                return Err(Status::internal("Intentional crash triggered by payload: CRASH_ME"));
            }

            let response = EchoResponse { payload };
            Ok(Response::new(response))
        }
    }
}

/// Custom mutator that always returns CRASH_ME to guarantee we find the crash
struct CrashMutator;

impl Mutator for CrashMutator {
    fn mutate(&self, _input: &[u8]) -> Vec<u8> {
        b"CRASH_ME".to_vec()
    }
}

/// Simple fuzz loop that runs fuzz_once for up to max_iterations
async fn fuzz_loop(
    client: &GrpcClient,
    mutator: &dyn Mutator,
    corpus: &Corpus,
    timeout_ms: u64,
    max_iterations: usize,
) -> Vec<CrashInfo> {
    let mut crashes = Vec::new();

    for _i in 0..max_iterations {
        match fuzz_once(client, mutator, corpus, timeout_ms).await {
            Ok(Some(crash_info)) => {
                crashes.push(crash_info);
            }
            Ok(None) => {
                // No crash, continue fuzzing
            }
            Err(e) => {
                eprintln!("Fuzzing error: {:?}", e);
                // Continue fuzzing even on errors
            }
        }
    }

    crashes
}

#[tokio::test]
async fn test_e2e_fuzz_finds_crash() {
    use server::echo::echo_server::EchoServer;
    use tonic::transport::Server;

    // Spawn test server on a background task
    let _server_handle = tokio::spawn(async {
        let addr = "127.0.0.1:50070".parse().unwrap();
        let echo_service = server::EchoService::default();

        Server::builder()
            .add_service(EchoServer::new(echo_service))
            .serve(addr)
            .await
            .unwrap();
    });

    // Give the server time to start
    sleep(Duration::from_millis(200)).await;

    // Create client
    let client = GrpcClient::new("http://127.0.0.1:50070")
        .await
        .expect("Failed to create client");

    // Create corpus seeded with initial input
    let corpus = Corpus::new();
    corpus.add(TestCase::new(
        "seed-1".to_string(),
        b"seed".to_vec(),
        serde_json::json!({}),
    ));

    // Use CrashMutator that always returns CRASH_ME
    let mutator = CrashMutator;

    // Run fuzz loop for up to 50 iterations
    let crashes = fuzz_loop(&client, &mutator, &corpus, 1000, 50).await;

    // Assert at least one crash was found
    assert!(
        !crashes.is_empty(),
        "Expected to find at least one crash, but found none"
    );

    // Assert the crash contains expected error message
    let crash = &crashes[0];
    assert!(
        crash.error.contains("CRASH_ME")
            || crash.error.contains("internal")
            || crash.error.contains("Internal")
            || crash.error.contains("Server error"),
        "Expected crash error to contain 'CRASH_ME', 'internal', 'Internal', or 'Server error', got: {}",
        crash.error
    );

    // Assert the crash input is CRASH_ME
    assert_eq!(
        crash.input,
        b"CRASH_ME",
        "Expected crash input to be CRASH_ME"
    );

    // Test JSON report persistence
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let report_path = temp_dir.path().join("crashes.json");

    // Write JSON report
    reporter::write_json_report(&crashes, &report_path).expect("Failed to write JSON report");

    // Assert report file was created
    assert!(report_path.exists(), "JSON report file should exist");

    // Read and parse the JSON report
    let report_content =
        std::fs::read_to_string(&report_path).expect("Failed to read JSON report");
    let report_json: serde_json::Value =
        serde_json::from_str(&report_content).expect("Failed to parse JSON report");

    // Assert the JSON is an array (report writes crashes directly as array)
    let crashes_array = report_json
        .as_array()
        .expect("Report should be an array of crashes");

    assert!(
        !crashes_array.is_empty(),
        "Crashes array in JSON report should not be empty"
    );

    // Verify crash details in JSON
    let first_crash = &crashes_array[0];
    assert!(
        first_crash
            .get("error")
            .and_then(|e| e.as_str())
            .map(|s| {
                s.contains("CRASH_ME")
                    || s.contains("internal")
                    || s.contains("Internal")
                    || s.contains("Server error")
            })
            .unwrap_or(false),
        "First crash in JSON should contain 'CRASH_ME', 'internal', 'Internal', or 'Server error' in error"
    );
}

#[tokio::test]
async fn test_e2e_fuzz_with_multiple_crashes() {
    use server::echo::echo_server::EchoServer;
    use tonic::transport::Server;

    // Spawn test server on a background task
    let _server_handle = tokio::spawn(async {
        let addr = "127.0.0.1:50071".parse().unwrap();
        let echo_service = server::EchoService::default();

        Server::builder()
            .add_service(EchoServer::new(echo_service))
            .serve(addr)
            .await
            .unwrap();
    });

    // Give the server time to start
    sleep(Duration::from_millis(200)).await;

    // Create client
    let client = GrpcClient::new("http://127.0.0.1:50071")
        .await
        .expect("Failed to create client");

    // Create empty corpus (will use default seed)
    let corpus = Corpus::new();

    // Use CrashMutator that always returns CRASH_ME
    let mutator = CrashMutator;

    // Run fuzz loop for 10 iterations - should find crash on every iteration
    let crashes = fuzz_loop(&client, &mutator, &corpus, 1000, 10).await;

    // Assert we found crashes (should be 10 since every iteration triggers crash)
    assert!(
        crashes.len() >= 5,
        "Expected to find at least 5 crashes, but found {}",
        crashes.len()
    );

    // Verify all crashes have the expected input
    for crash in &crashes {
        assert_eq!(
            crash.input,
            b"CRASH_ME",
            "All crashes should have CRASH_ME as input"
        );
    }
}
