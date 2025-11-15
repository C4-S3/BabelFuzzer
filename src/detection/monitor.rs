// Crash and timeout detection

/// Monitor for detecting timeouts in error messages
pub struct TimeoutMonitor;

impl TimeoutMonitor {
    /// Create a new TimeoutMonitor instance
    pub fn new() -> Self {
        Self
    }

    /// Check if an error string indicates a timeout
    ///
    /// # Arguments
    /// * `error` - The error message string to analyze
    ///
    /// # Returns
    /// `true` if the error indicates a timeout, `false` otherwise
    pub fn is_timeout(error: &str) -> bool {
        let error_lower = error.to_lowercase();
        error_lower.contains("timed out") || error_lower.contains("deadline exceeded")
    }
}

impl Default for TimeoutMonitor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timeout_detected() {
        // Test various timeout error messages
        assert!(TimeoutMonitor::is_timeout("Connection timed out"));
        assert!(TimeoutMonitor::is_timeout("Request timed out after 5s"));
        assert!(TimeoutMonitor::is_timeout("TIMED OUT"));
        assert!(TimeoutMonitor::is_timeout("The operation timed out"));

        assert!(TimeoutMonitor::is_timeout("Deadline exceeded"));
        assert!(TimeoutMonitor::is_timeout("deadline exceeded for request"));
        assert!(TimeoutMonitor::is_timeout("DEADLINE EXCEEDED"));

        // Test non-timeout errors
        assert!(!TimeoutMonitor::is_timeout("Connection refused"));
        assert!(!TimeoutMonitor::is_timeout("Invalid argument"));
        assert!(!TimeoutMonitor::is_timeout("panic: index out of bounds"));
    }

    #[test]
    fn test_timeout_case_insensitive() {
        assert!(TimeoutMonitor::is_timeout("TIMED OUT"));
        assert!(TimeoutMonitor::is_timeout("Timed Out"));
        assert!(TimeoutMonitor::is_timeout("timed out"));
        assert!(TimeoutMonitor::is_timeout("DeAdLiNe ExCeEdEd"));
    }

    #[test]
    fn test_timeout_partial_match() {
        assert!(TimeoutMonitor::is_timeout("Error: connection timed out while waiting"));
        assert!(TimeoutMonitor::is_timeout("RPC failed: deadline exceeded"));
    }
}
