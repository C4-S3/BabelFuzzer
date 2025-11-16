// QUIC protocol fuzzing module
//
// IMPLEMENTATION STATUS: Phase 1.1 - In Progress (Week 1-2)
//
// This module implements QUIC protocol fuzzing based on the comprehensive
// plan in docs/QUIC_FUZZER_PLAN.md. It provides the foundation for HTTP/3
// fuzzing by implementing protocol-aware mutations targeting QUIC implementations.
//
// Modules:
// - client: Quinn-based QUIC client with fuzzing hooks
// - crypto: TLS 1.3 cryptographic state tracking for packet encryption/decryption
// - state: QUIC connection state machine tracking (Phase 1.2)
// - frames: QUIC frame parsing and serialization (Phase 1.2)
// - mutations: Protocol-aware mutation strategies (Phase 1.3)
// - fuzzer: Main fuzzing loop and crash detection (Phase 1.3)
//
// Timeline:
// - Phase 1.1 (Weeks 1-4): Quinn client + crypto state tracking
// - Phase 1.2 (Weeks 5-8): State machine + frame handling
// - Phase 1.3 (Weeks 9-12): Fuzzing logic + mutations
// - Phase 1.4 (Weeks 13-16): Testing + validation
//
// See docs/QUIC_FUZZER_PLAN.md for complete implementation details.

pub mod client;
pub mod crypto;

// Phase 1.2 modules (to be implemented)
// pub mod state;
// pub mod frames;

// Phase 1.3 modules (to be implemented)
// pub mod mutations;
// pub mod fuzzer;
