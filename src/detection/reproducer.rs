// Crash reproducer generation

use crate::core_types::CrashInfo;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Result as IoResult;
use std::path::{Path, PathBuf};

/// Information for reproducing a crash
#[derive(Debug, Serialize, Deserialize)]
pub struct ReproducerInfo {
    /// Crash identifier
    pub crash_id: String,

    /// Crash hash for deduplication
    pub crash_hash: String,

    /// Error message
    pub error: String,

    /// Timestamp when crash was discovered
    pub timestamp: String,

    /// Base64-encoded input data
    pub input_base64: String,

    /// Example command to reproduce the crash
    pub reproduction_command: String,

    /// Additional notes
    pub notes: String,
}

/// Write a reproducer file for a crash
///
/// Creates a JSON file containing all information needed to reproduce the crash,
/// including the input data and example CLI commands.
///
/// # Arguments
/// * `crash` - The crash information to write
/// * `path` - Directory path where the reproducer file should be written
///
/// # Returns
/// Path to the created reproducer file
///
/// # Errors
/// Returns an error if the file cannot be created or written
pub fn write_reproducer(crash: &CrashInfo, path: &Path) -> IoResult<PathBuf> {
    use super::dedup::crash_hash;

    // Ensure the directory exists
    fs::create_dir_all(path)?;

    // Compute crash hash
    let hash = crash_hash(crash);

    // Create reproducer info
    let reproducer = ReproducerInfo {
        crash_id: crash.id.clone(),
        crash_hash: hash.clone(),
        error: crash.error.clone(),
        timestamp: crash.timestamp.to_rfc3339(),
        input_base64: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &crash.input),
        reproduction_command: format!(
            "proto-fuzzer --replay-file crash-{}.input --target <TARGET_URL>",
            crash.id
        ),
        notes: format!(
            "This crash was discovered on {}. To reproduce:\n\
             1. Save the base64 input to a file: echo '{}' | base64 -d > crash-{}.input\n\
             2. Run the reproduction command above\n\
             3. The crash should occur with the same error message",
            crash.timestamp.format("%Y-%m-%d %H:%M:%S UTC"),
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &crash.input),
            crash.id
        ),
    };

    // Write JSON file
    let filename = format!("crash-{}-{}.json", crash.id, &hash[..8]);
    let filepath = path.join(&filename);

    let json = serde_json::to_string_pretty(&reproducer)?;
    fs::write(&filepath, json)?;

    Ok(filepath)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_write_reproducer_creates_file() {
        // Create temporary directory for test
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();

        // Create crash info
        let crash = CrashInfo::new(
            "test-crash-1".to_string(),
            vec![1, 2, 3, 4, 5],
            "panic: index out of bounds".to_string(),
        );

        // Write reproducer
        let result = write_reproducer(&crash, temp_path);
        assert!(result.is_ok(), "write_reproducer should succeed");

        let filepath = result.unwrap();

        // Verify file exists
        assert!(filepath.exists(), "Reproducer file should exist");

        // Read and parse JSON
        let content = fs::read_to_string(&filepath).unwrap();
        let reproducer: ReproducerInfo = serde_json::from_str(&content).unwrap();

        // Verify contents
        assert_eq!(reproducer.crash_id, "test-crash-1");
        assert_eq!(reproducer.error, "panic: index out of bounds");
        assert!(!reproducer.crash_hash.is_empty());
        assert!(reproducer.reproduction_command.contains("--replay-file"));
    }

    #[test]
    fn test_write_reproducer_base64_encoding() {
        let temp_dir = TempDir::new().unwrap();
        let crash = CrashInfo::new(
            "crash-2".to_string(),
            vec![0xFF, 0xAA, 0x55, 0x00],
            "test error".to_string(),
        );

        let filepath = write_reproducer(&crash, temp_dir.path()).unwrap();
        let content = fs::read_to_string(&filepath).unwrap();
        let reproducer: ReproducerInfo = serde_json::from_str(&content).unwrap();

        // Decode base64 and verify it matches original input
        let decoded = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &reproducer.input_base64,
        )
        .unwrap();
        assert_eq!(decoded, crash.input);
    }

    #[test]
    fn test_write_reproducer_directory_creation() {
        // Test that it creates nested directories if they don't exist
        let temp_dir = TempDir::new().unwrap();
        let nested_path = temp_dir.path().join("nested").join("path");

        let crash = CrashInfo::new(
            "crash-3".to_string(),
            vec![1, 2, 3],
            "error".to_string(),
        );

        let result = write_reproducer(&crash, &nested_path);
        assert!(result.is_ok(), "Should create nested directories");
        assert!(result.unwrap().exists());
    }

    #[test]
    fn test_write_reproducer_json_structure() {
        let temp_dir = TempDir::new().unwrap();
        let crash = CrashInfo::new(
            "crash-4".to_string(),
            vec![10, 20, 30],
            "timeout error".to_string(),
        );

        let filepath = write_reproducer(&crash, temp_dir.path()).unwrap();
        let content = fs::read_to_string(&filepath).unwrap();

        // Verify it's valid JSON
        let value: serde_json::Value = serde_json::from_str(&content).unwrap();

        // Check required fields exist
        assert!(value.get("crash_id").is_some());
        assert!(value.get("crash_hash").is_some());
        assert!(value.get("error").is_some());
        assert!(value.get("timestamp").is_some());
        assert!(value.get("input_base64").is_some());
        assert!(value.get("reproduction_command").is_some());
        assert!(value.get("notes").is_some());
    }

    #[test]
    fn test_write_reproducer_filename_format() {
        let temp_dir = TempDir::new().unwrap();
        let crash = CrashInfo::new(
            "my-crash".to_string(),
            vec![1],
            "error".to_string(),
        );

        let filepath = write_reproducer(&crash, temp_dir.path()).unwrap();
        let filename = filepath.file_name().unwrap().to_str().unwrap();

        // Should start with crash-{id}- and end with .json
        assert!(filename.starts_with("crash-my-crash-"));
        assert!(filename.ends_with(".json"));
    }
}
