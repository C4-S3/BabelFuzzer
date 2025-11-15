// Crash deduplication

use crate::core_types::CrashInfo;
use sha2::{Digest, Sha256};

/// Compute a unique hash for a crash based on input and error signature
///
/// # Arguments
/// * `crash` - The crash information to hash
///
/// # Returns
/// A hex-encoded SHA256 hash string
pub fn crash_hash(crash: &CrashInfo) -> String {
    let mut hasher = Sha256::new();

    // Hash the input bytes
    hasher.update(&crash.input);

    // Hash the error string
    hasher.update(crash.error.as_bytes());

    // Return hex-encoded hash
    format!("{:x}", hasher.finalize())
}

pub struct Deduplicator;

impl Deduplicator {
    pub fn new() -> Self {
        Self
    }
}

impl Default for Deduplicator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crash_hash_consistent() {
        // Test that same input+error produces same hash
        let crash1 = CrashInfo::new(
            "crash-1".to_string(),
            vec![1, 2, 3, 4, 5],
            "panic: index out of bounds".to_string(),
        );

        let crash2 = CrashInfo::new(
            "crash-2".to_string(), // Different ID
            vec![1, 2, 3, 4, 5],   // Same input
            "panic: index out of bounds".to_string(), // Same error
        );

        let hash1 = crash_hash(&crash1);
        let hash2 = crash_hash(&crash2);

        // Same input + error should produce same hash regardless of ID
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 64); // SHA256 hex is 64 characters
    }

    #[test]
    fn test_crash_hash_different_input() {
        // Different input should produce different hash
        let crash1 = CrashInfo::new(
            "crash-1".to_string(),
            vec![1, 2, 3],
            "error".to_string(),
        );

        let crash2 = CrashInfo::new(
            "crash-2".to_string(),
            vec![4, 5, 6],
            "error".to_string(),
        );

        let hash1 = crash_hash(&crash1);
        let hash2 = crash_hash(&crash2);

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_crash_hash_different_error() {
        // Different error should produce different hash
        let crash1 = CrashInfo::new(
            "crash-1".to_string(),
            vec![1, 2, 3],
            "error1".to_string(),
        );

        let crash2 = CrashInfo::new(
            "crash-2".to_string(),
            vec![1, 2, 3],
            "error2".to_string(),
        );

        let hash1 = crash_hash(&crash1);
        let hash2 = crash_hash(&crash2);

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_crash_hash_hex_format() {
        // Verify hash is valid hex string
        let crash = CrashInfo::new(
            "crash-1".to_string(),
            vec![0xFF, 0xAA, 0x55],
            "test error".to_string(),
        );

        let hash = crash_hash(&crash);

        // Should be 64 hex characters
        assert_eq!(hash.len(), 64);

        // Should only contain hex characters (0-9, a-f)
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
