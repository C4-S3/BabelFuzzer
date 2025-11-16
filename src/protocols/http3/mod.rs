// HTTP/3 protocol fuzzing module
//
// CURRENT STATUS: Stub implementation only (not functional)
//
// This module contains placeholder code for the planned HTTP/3 fuzzing
// implementation. See ROADMAP.md Phase 1 for the complete implementation plan.
//
// For detailed implementation plans, see:
// - client.rs: HTTP/3 client with Quinn/QUIC (Phase 1 Milestone 1.1-1.2)
// - fuzzer.rs: HTTP/3-specific fuzzing logic (Phase 1 Milestone 1.3)
//
// Dependencies required for implementation (already in Cargo.toml):
// - quinn 0.11: QUIC protocol implementation
// - h3 0.0.8: HTTP/3 frame handling
//
// Timeline: Planned for Months 1-4 (see ROADMAP.md)
// Target: v0.2.0 release with functional HTTP/3 fuzzing

pub mod client;
pub mod fuzzer;
