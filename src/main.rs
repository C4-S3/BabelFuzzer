use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "proto-fuzzer")]
#[command(about = "A protocol fuzzer for gRPC and HTTP/3", long_about = None)]
struct Args {
    /// Target service to fuzz (e.g., grpc://localhost:50051)
    #[arg(short, long)]
    target: String,

    /// Duration to run fuzzing campaign in seconds
    #[arg(short, long)]
    duration: u64,
}

fn main() {
    let args = Args::parse();

    println!("Protocol Fuzzer");
    println!("===============");
    println!("Target:   {}", args.target);
    println!("Duration: {} seconds", args.duration);
    println!("\nFuzzer configuration parsed successfully.");
}
