# BabelFuzzer - Modern Protocol Fuzzer

A high-performance protocol fuzzer with production-ready gRPC support and planned HTTP/3 capabilities.

## Current Status

**Production Ready:**
- ✅ **gRPC Fuzzing** - Fully functional with automatic reflection-based schema discovery
- ✅ **Crash Detection** - Comprehensive timeout, panic, and error classification
- ✅ **Mutation Engine** - BitFlip and Truncate strategies with property-tested invariants
- ✅ **Corpus Management** - SHA256-based deduplication with persistence
- ✅ **Reporting** - JSON and HTML report generation

**Planned (Not Yet Implemented):**
- 🚧 **HTTP/3 Fuzzing** - Architecture defined, implementation in Phase 1 (see ROADMAP.md)
- 🚧 **Coverage-Guided Fuzzing** - Black-box coverage tracking planned
- 🚧 **Advanced Mutations** - Dictionary, arithmetic, and havoc modes planned
- 🚧 **State Machine Fuzzing** - Multi-request sequence testing planned

> **Note**: This project currently focuses on gRPC fuzzing. HTTP/3 support is planned for future releases. See [ROADMAP.md](ROADMAP.md) for the complete development plan.

## Overview

BabelFuzzer is designed to discover security vulnerabilities and bugs in network protocol implementations by generating malformed and unexpected inputs. It currently specializes in gRPC services with automatic schema discovery via server reflection.

## Features

### Currently Available
- ✅ gRPC protocol fuzzing with reflection-based schema discovery
- ✅ Automatic connection pooling for high throughput
- ✅ Crash detection and classification (timeouts, panics, RPC errors)
- ✅ Corpus management with SHA256 deduplication
- ✅ BitFlip and Truncate mutation strategies
- ✅ JSON and HTML crash reporting
- ✅ Property-tested fuzzing invariants
- ✅ 71 comprehensive tests (100% passing)

### Planned for Future Releases
- 🚧 HTTP/3 protocol fuzzing (Phase 1 - Months 1-4)
- 🚧 Coverage-guided mutation strategies (Phase 2)
- 🚧 Advanced mutation strategies (Dictionary, Arithmetic, Havoc)
- 🚧 State machine fuzzing for multi-request flows
- 🚧 Web dashboard for monitoring campaigns

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
