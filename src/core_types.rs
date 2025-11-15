// Core types used throughout the fuzzer

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Represents a test case for fuzzing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestCase {
    /// Unique identifier for this test case
    pub id: String,

    /// The raw test data
    pub data: Vec<u8>,

    /// Additional metadata about the test case
    pub metadata: serde_json::Value,
}

impl TestCase {
    /// Create a new test case
    pub fn new(id: String, data: Vec<u8>, metadata: serde_json::Value) -> Self {
        Self { id, data, metadata }
    }
}

/// Information about a crash discovered during fuzzing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrashInfo {
    /// Unique identifier for this crash
    pub id: String,

    /// The input that caused the crash
    pub input: Vec<u8>,

    /// Error message or crash description
    pub error: String,

    /// When the crash was discovered
    pub timestamp: DateTime<Utc>,
}

impl CrashInfo {
    /// Create a new crash info
    pub fn new(id: String, input: Vec<u8>, error: String) -> Self {
        Self {
            id,
            input,
            error,
            timestamp: Utc::now(),
        }
    }

    /// Create a crash info with a specific timestamp
    pub fn with_timestamp(id: String, input: Vec<u8>, error: String, timestamp: DateTime<Utc>) -> Self {
        Self {
            id,
            input,
            error,
            timestamp,
        }
    }
}

/// Error types for the fuzzer
#[derive(Debug, Error)]
pub enum FuzzerError {
    /// I/O error
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Protocol-specific error
    #[error("Protocol error: {0}")]
    Protocol(String),

    /// Timeout error
    #[error("Timeout error: {0}")]
    Timeout(String),

    /// Other errors
    #[error("Other error: {0}")]
    Other(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_test_case_creation() {
        let id = "test-1".to_string();
        let data = vec![1, 2, 3, 4, 5];
        let metadata = serde_json::json!({
            "source": "generator",
            "timestamp": "2024-01-01T00:00:00Z"
        });

        let test_case = TestCase::new(id.clone(), data.clone(), metadata.clone());

        assert_eq!(test_case.id, id);
        assert_eq!(test_case.data, data);
        assert_eq!(test_case.metadata, metadata);
    }

    #[test]
    fn test_test_case_serialization() {
        let test_case = TestCase::new(
            "test-1".to_string(),
            vec![1, 2, 3],
            serde_json::json!({"key": "value"}),
        );

        let serialized = serde_json::to_string(&test_case).unwrap();
        let deserialized: TestCase = serde_json::from_str(&serialized).unwrap();

        assert_eq!(test_case.id, deserialized.id);
        assert_eq!(test_case.data, deserialized.data);
        assert_eq!(test_case.metadata, deserialized.metadata);
    }

    #[test]
    fn test_crash_info_creation() {
        let id = "crash-1".to_string();
        let input = vec![0xFF, 0xFF, 0xFF];
        let error = "Segmentation fault".to_string();

        let crash_info = CrashInfo::new(id.clone(), input.clone(), error.clone());

        assert_eq!(crash_info.id, id);
        assert_eq!(crash_info.input, input);
        assert_eq!(crash_info.error, error);
        assert!(crash_info.timestamp <= Utc::now());
    }

    #[test]
    fn test_crash_info_with_timestamp() {
        let timestamp = Utc::now();
        let crash_info = CrashInfo::with_timestamp(
            "crash-1".to_string(),
            vec![1, 2, 3],
            "Error".to_string(),
            timestamp,
        );

        assert_eq!(crash_info.timestamp, timestamp);
    }

    #[test]
    fn test_crash_info_serialization() {
        let crash_info = CrashInfo::new(
            "crash-1".to_string(),
            vec![1, 2, 3],
            "Test error".to_string(),
        );

        let serialized = serde_json::to_string(&crash_info).unwrap();
        let deserialized: CrashInfo = serde_json::from_str(&serialized).unwrap();

        assert_eq!(crash_info.id, deserialized.id);
        assert_eq!(crash_info.input, deserialized.input);
        assert_eq!(crash_info.error, deserialized.error);
        assert_eq!(crash_info.timestamp, deserialized.timestamp);
    }

    #[test]
    fn test_fuzzer_error_io() {
        let io_error = std::io::Error::new(std::io::ErrorKind::NotFound, "File not found");
        let fuzzer_error = FuzzerError::from(io_error);

        match fuzzer_error {
            FuzzerError::Io(_) => assert!(true),
            _ => panic!("Expected FuzzerError::Io"),
        }
    }

    #[test]
    fn test_fuzzer_error_protocol() {
        let error = FuzzerError::Protocol("Connection refused".to_string());
        assert_eq!(error.to_string(), "Protocol error: Connection refused");
    }

    #[test]
    fn test_fuzzer_error_timeout() {
        let error = FuzzerError::Timeout("Request timed out after 30s".to_string());
        assert_eq!(error.to_string(), "Timeout error: Request timed out after 30s");
    }

    #[test]
    fn test_fuzzer_error_other() {
        let error = FuzzerError::Other("Unknown error occurred".to_string());
        assert_eq!(error.to_string(), "Other error: Unknown error occurred");
    }

    #[test]
    fn test_fuzzer_error_is_error_trait() {
        let error = FuzzerError::Protocol("test".to_string());
        // Test that it implements std::error::Error
        let _: &dyn std::error::Error = &error;
    }

    #[test]
    fn test_fuzzer_error_send_sync() {
        // Ensure FuzzerError is Send + Sync
        fn assert_send<T: Send>() {}
        fn assert_sync<T: Sync>() {}

        assert_send::<FuzzerError>();
        assert_sync::<FuzzerError>();
    }
}
