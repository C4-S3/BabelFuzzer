# Protocol Fuzzer

A high-performance protocol fuzzer for gRPC and HTTP/3 services.

## Overview

This fuzzer is designed to discover security vulnerabilities and bugs in network protocol implementations by generating malformed and unexpected inputs.

## Features

- gRPC protocol fuzzing with reflection-based schema discovery
- HTTP/3 protocol fuzzing
- Coverage-guided mutation strategies
- Crash detection and classification
- Automatic test case minimization

## Getting Started

### Prerequisites

- Rust 1.70 or later
- Cargo

### Building

To build the project:

```bash
cargo build
```

To build in release mode for optimal performance:

```bash
cargo build --release
```

### Running Tests

To run all tests:

```bash
cargo test
```

### Usage

Basic usage:

```bash
cargo run -- --target grpc://localhost:50051 --duration 60
```

This will fuzz a gRPC service running on localhost:50051 for 60 seconds.

## Project Structure

- `src/engine/` - Core fuzzing engine (mutation, generation, corpus management)
- `src/protocols/` - Protocol-specific implementations (gRPC, HTTP/3)
- `src/detection/` - Crash detection and classification
- `src/orchestrator/` - Campaign scheduling and execution
- `src/utils/` - Utility functions and metrics

## Development

This project is under active development. See the architecture documentation for details on the internal design.

## License

MIT
