// Bug classification logic

use super::monitor::TimeoutMonitor;

/// Classify an error message into a category
///
/// # Arguments
/// * `error` - The error message string to classify
///
/// # Returns
/// A string representing the error category:
/// - "timeout" - For timeout and deadline exceeded errors
/// - "panic" - For panic errors
/// - "rpc_error" - For RPC-related errors
/// - "unknown" - For unrecognized error types
pub fn classify(error: &str) -> String {
    let error_lower = error.to_lowercase();

    // Check for timeout first using the TimeoutMonitor
    if TimeoutMonitor::is_timeout(error) {
        return "timeout".to_string();
    }

    // Check for panic
    if error_lower.contains("panic") || error_lower.contains("panicked") {
        return "panic".to_string();
    }

    // Check for RPC errors
    if error_lower.contains("rpc")
        || error_lower.contains("grpc")
        || error_lower.contains("status code")
        || error_lower.contains("transport error") {
        return "rpc_error".to_string();
    }

    // Default to unknown
    "unknown".to_string()
}

pub struct Classifier;

impl Classifier {
    pub fn new() -> Self {
        Self
    }

    /// Classify an error message into a category
    pub fn classify(&self, error: &str) -> String {
        classify(error)
    }
}

impl Default for Classifier {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_panic_classified() {
        // Test panic classification
        assert_eq!(classify("panic: index out of bounds"), "panic");
        assert_eq!(classify("thread panicked at 'assertion failed'"), "panic");
        assert_eq!(classify("PANIC occurred in module"), "panic");
        assert_eq!(classify("The application panicked"), "panic");
    }

    #[test]
    fn test_timeout_classified() {
        // Test timeout classification
        assert_eq!(classify("Connection timed out"), "timeout");
        assert_eq!(classify("Deadline exceeded"), "timeout");
        assert_eq!(classify("Request timed out after 30s"), "timeout");
    }

    #[test]
    fn test_rpc_error_classified() {
        // Test RPC error classification
        assert_eq!(classify("RPC call failed"), "rpc_error");
        assert_eq!(classify("gRPC connection error"), "rpc_error");
        assert_eq!(classify("Status code: 404"), "rpc_error");
        assert_eq!(classify("Transport error occurred"), "rpc_error");
    }

    #[test]
    fn test_unknown_classified() {
        // Test unknown error classification
        assert_eq!(classify("Some random error"), "unknown");
        assert_eq!(classify("Invalid input"), "unknown");
        assert_eq!(classify("File not found"), "unknown");
    }

    #[test]
    fn test_classifier_struct() {
        // Test the Classifier struct methods
        let classifier = Classifier::new();
        assert_eq!(classifier.classify("panic: test"), "panic");
        assert_eq!(classifier.classify("timed out"), "timeout");
    }

    #[test]
    fn test_case_insensitive_classification() {
        // Verify classification is case-insensitive
        assert_eq!(classify("PANIC: ERROR"), "panic");
        assert_eq!(classify("Timed Out"), "timeout");
        assert_eq!(classify("RPC Error"), "rpc_error");
    }
}
