use clap::Parser;
use proto_fuzzer::core_types::{CrashInfo, TestCase};
use proto_fuzzer::engine::corpus::Corpus;
use proto_fuzzer::engine::mutator::BitFlip;
use proto_fuzzer::protocols::grpc::client::GrpcClient;
use proto_fuzzer::protocols::grpc::fuzzer::fuzz_once;
use serde::Serialize;
use tracing::{error, info};
use tracing_subscriber;

#[derive(Parser, Debug)]
#[command(name = "proto-fuzzer")]
#[command(about = "A protocol fuzzer for gRPC services (HTTP/3 support planned)", long_about = None)]
struct Args {
    /// Target service to fuzz (e.g., http://localhost:50051)
    #[arg(short, long)]
    target: String,

    /// Number of iterations to run
    #[arg(short, long, default_value = "100")]
    iterations: u64,

    /// Timeout for each request in milliseconds
    #[arg(long, default_value = "1000")]
    timeout_ms: u64,
}

#[derive(Serialize)]
struct FuzzingSummary {
    iterations: u64,
    crashes: Vec<CrashInfo>,
}

#[tokio::main]
async fn main() {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();

    let args = Args::parse();

    info!("Protocol Fuzzer Starting");
    info!("Target:      {}", args.target);
    info!("Iterations:  {}", args.iterations);
    info!("Timeout:     {}ms", args.timeout_ms);

    // Create gRPC client
    let client = match GrpcClient::new(&args.target).await {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to connect to target: {}", e);
            std::process::exit(1);
        }
    };

    info!("Connected to target: {}", client.endpoint());

    // Initialize corpus with a seed
    let corpus = Corpus::new();
    corpus.add(TestCase::new(
        "seed-1".to_string(),
        b"init".to_vec(),
        serde_json::json!({"source": "initial_seed"}),
    ));

    // Create mutator
    let mutator = BitFlip::new();

    // Run fuzzing loop
    let mut crashes = Vec::new();

    for i in 0..args.iterations {
        if i % 10 == 0 && i > 0 {
            info!("Progress: {}/{} iterations", i, args.iterations);
        }

        match fuzz_once(&client, &mutator, &corpus, args.timeout_ms).await {
            Ok(Some(crash)) => {
                info!("Crash detected: {}", crash.error);
                crashes.push(crash);
            }
            Ok(None) => {
                // Normal execution, no crash
            }
            Err(e) => {
                error!("Error during fuzzing iteration {}: {}", i, e);
            }
        }
    }

    // Print summary
    let summary = FuzzingSummary {
        iterations: args.iterations,
        crashes,
    };

    let json = serde_json::to_string_pretty(&summary).expect("Failed to serialize summary");
    println!("{}", json);

    info!("Fuzzing complete. Found {} crashes", summary.crashes.len());
}
