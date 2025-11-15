// Report generation

use crate::core_types::CrashInfo;
use crate::detection::classifier::classify;
use crate::detection::dedup::crash_hash;
use std::collections::HashMap;
use std::fs;
use std::io::Result as IoResult;
use std::path::Path;

/// Write crash reports to a JSON file
///
/// # Arguments
/// * `crashes` - Slice of crash information to report
/// * `path` - File path where the JSON report should be written
///
/// # Returns
/// Result indicating success or failure
///
/// # Errors
/// Returns an error if the file cannot be written
pub fn write_json_report(crashes: &[CrashInfo], path: &Path) -> IoResult<()> {
    let json = serde_json::to_string_pretty(crashes)?;
    fs::write(path, json)?;
    Ok(())
}

/// Write an HTML summary report of crashes
///
/// Creates a simple HTML page with crash statistics and a list of all crashes
///
/// # Arguments
/// * `crashes` - Slice of crash information to summarize
/// * `path` - File path where the HTML summary should be written
///
/// # Returns
/// Result indicating success or failure
///
/// # Errors
/// Returns an error if the file cannot be written
pub fn write_html_summary(crashes: &[CrashInfo], path: &Path) -> IoResult<()> {
    // Compute statistics
    let total_crashes = crashes.len();

    // Count crashes by category
    let mut category_counts: HashMap<String, usize> = HashMap::new();
    for crash in crashes {
        let category = classify(&crash.error);
        *category_counts.entry(category).or_insert(0) += 1;
    }

    // Count unique crashes (by hash)
    let mut unique_hashes = std::collections::HashSet::new();
    for crash in crashes {
        unique_hashes.insert(crash_hash(crash));
    }
    let unique_crashes = unique_hashes.len();

    // Build HTML content
    let mut html = String::new();
    html.push_str("<!DOCTYPE html>\n");
    html.push_str("<html>\n");
    html.push_str("<head>\n");
    html.push_str("  <meta charset=\"UTF-8\">\n");
    html.push_str("  <title>Fuzzing Report</title>\n");
    html.push_str("  <style>\n");
    html.push_str("    body { font-family: Arial, sans-serif; margin: 40px; }\n");
    html.push_str("    h1 { color: #333; }\n");
    html.push_str("    .stats { background: #f5f5f5; padding: 20px; border-radius: 5px; margin: 20px 0; }\n");
    html.push_str("    .crash { border: 1px solid #ddd; padding: 15px; margin: 10px 0; border-radius: 5px; }\n");
    html.push_str("    .crash-id { font-weight: bold; color: #0066cc; }\n");
    html.push_str("    .error { color: #cc0000; font-family: monospace; }\n");
    html.push_str("    .timestamp { color: #666; font-size: 0.9em; }\n");
    html.push_str("    table { border-collapse: collapse; width: 100%; }\n");
    html.push_str("    th, td { text-align: left; padding: 8px; border-bottom: 1px solid #ddd; }\n");
    html.push_str("    th { background-color: #4CAF50; color: white; }\n");
    html.push_str("  </style>\n");
    html.push_str("</head>\n");
    html.push_str("<body>\n");

    html.push_str("  <h1>Fuzzing Report</h1>\n");

    // Statistics section
    html.push_str("  <div class=\"stats\">\n");
    html.push_str("    <h2>Summary</h2>\n");
    html.push_str(&format!("    <p><strong>Total Crashes:</strong> {}</p>\n", total_crashes));
    html.push_str(&format!("    <p><strong>Unique Crashes:</strong> {}</p>\n", unique_crashes));

    if !category_counts.is_empty() {
        html.push_str("    <h3>Crashes by Category</h3>\n");
        html.push_str("    <table>\n");
        html.push_str("      <tr><th>Category</th><th>Count</th></tr>\n");

        let mut categories: Vec<_> = category_counts.iter().collect();
        categories.sort_by_key(|(_, count)| std::cmp::Reverse(**count));

        for (category, count) in categories {
            html.push_str(&format!("      <tr><td>{}</td><td>{}</td></tr>\n", category, count));
        }
        html.push_str("    </table>\n");
    }
    html.push_str("  </div>\n");

    // Crashes list
    html.push_str("  <h2>Crash Details</h2>\n");

    if crashes.is_empty() {
        html.push_str("  <p>No crashes found.</p>\n");
    } else {
        for crash in crashes {
            let category = classify(&crash.error);
            let hash = crash_hash(crash);

            html.push_str("  <div class=\"crash\">\n");
            html.push_str(&format!("    <p class=\"crash-id\">Crash ID: {}</p>\n", crash.id));
            html.push_str(&format!("    <p><strong>Category:</strong> {}</p>\n", category));
            html.push_str(&format!("    <p><strong>Hash:</strong> {}</p>\n", &hash[..16]));
            html.push_str(&format!("    <p class=\"error\"><strong>Error:</strong> {}</p>\n", crash.error));
            html.push_str(&format!("    <p class=\"timestamp\"><strong>Timestamp:</strong> {}</p>\n", crash.timestamp.format("%Y-%m-%d %H:%M:%S UTC")));
            html.push_str(&format!("    <p><strong>Input size:</strong> {} bytes</p>\n", crash.input.len()));
            html.push_str("  </div>\n");
        }
    }

    html.push_str("</body>\n");
    html.push_str("</html>\n");

    fs::write(path, html)?;
    Ok(())
}

pub struct Reporter;

impl Reporter {
    pub fn new() -> Self {
        Self
    }
}

impl Default for Reporter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_write_json_report() {
        // Create temporary directory
        let temp_dir = TempDir::new().unwrap();
        let report_path = temp_dir.path().join("crashes.json");

        // Create test crashes
        let crashes = vec![
            CrashInfo::new(
                "crash-1".to_string(),
                vec![1, 2, 3],
                "panic: index out of bounds".to_string(),
            ),
            CrashInfo::new(
                "crash-2".to_string(),
                vec![4, 5, 6],
                "timeout error".to_string(),
            ),
        ];

        // Write JSON report
        let result = write_json_report(&crashes, &report_path);
        assert!(result.is_ok(), "write_json_report should succeed");

        // Verify file exists
        assert!(report_path.exists(), "Report file should exist");

        // Read and parse JSON
        let content = fs::read_to_string(&report_path).unwrap();
        let loaded_crashes: Vec<CrashInfo> = serde_json::from_str(&content).unwrap();

        // Verify contents match
        assert_eq!(loaded_crashes.len(), 2);
        assert_eq!(loaded_crashes[0].id, "crash-1");
        assert_eq!(loaded_crashes[0].error, "panic: index out of bounds");
        assert_eq!(loaded_crashes[1].id, "crash-2");
        assert_eq!(loaded_crashes[1].error, "timeout error");
    }

    #[test]
    fn test_write_json_report_empty() {
        let temp_dir = TempDir::new().unwrap();
        let report_path = temp_dir.path().join("empty.json");

        let crashes: Vec<CrashInfo> = vec![];
        let result = write_json_report(&crashes, &report_path);

        assert!(result.is_ok());
        assert!(report_path.exists());

        let content = fs::read_to_string(&report_path).unwrap();
        let loaded: Vec<CrashInfo> = serde_json::from_str(&content).unwrap();
        assert_eq!(loaded.len(), 0);
    }

    #[test]
    fn test_write_html_summary() {
        let temp_dir = TempDir::new().unwrap();
        let html_path = temp_dir.path().join("summary.html");

        let crashes = vec![
            CrashInfo::new(
                "crash-1".to_string(),
                vec![1, 2, 3],
                "panic: test error".to_string(),
            ),
            CrashInfo::new(
                "crash-2".to_string(),
                vec![4, 5, 6],
                "Connection timed out".to_string(),
            ),
        ];

        let result = write_html_summary(&crashes, &html_path);
        assert!(result.is_ok(), "write_html_summary should succeed");

        // Verify file exists
        assert!(html_path.exists(), "HTML file should exist");

        // Read and verify content
        let content = fs::read_to_string(&html_path).unwrap();

        // Check for expected headlines and structure
        assert!(content.contains("Fuzzing Report"), "Should contain headline");
        assert!(content.contains("<!DOCTYPE html>"), "Should be valid HTML");
        assert!(content.contains("Total Crashes"), "Should contain total count");
        assert!(content.contains("crash-1"), "Should list crash IDs");
        assert!(content.contains("crash-2"), "Should list crash IDs");
        assert!(content.contains("panic: test error"), "Should show error messages");
        assert!(content.contains("Connection timed out"), "Should show error messages");
    }

    #[test]
    fn test_write_html_summary_empty() {
        let temp_dir = TempDir::new().unwrap();
        let html_path = temp_dir.path().join("empty.html");

        let crashes: Vec<CrashInfo> = vec![];
        let result = write_html_summary(&crashes, &html_path);

        assert!(result.is_ok());
        assert!(html_path.exists());

        let content = fs::read_to_string(&html_path).unwrap();
        assert!(content.contains("Fuzzing Report"));
        assert!(content.contains("No crashes found"));
        assert!(content.contains("Total Crashes:") && content.contains("</strong> 0"));
    }

    #[test]
    fn test_write_html_summary_statistics() {
        let temp_dir = TempDir::new().unwrap();
        let html_path = temp_dir.path().join("stats.html");

        // Create crashes with different categories
        let crashes = vec![
            CrashInfo::new(
                "crash-1".to_string(),
                vec![1],
                "panic: error".to_string(),
            ),
            CrashInfo::new(
                "crash-2".to_string(),
                vec![2],
                "panic: another".to_string(),
            ),
            CrashInfo::new(
                "crash-3".to_string(),
                vec![3],
                "timeout".to_string(),
            ),
        ];

        write_html_summary(&crashes, &html_path).unwrap();
        let content = fs::read_to_string(&html_path).unwrap();

        // Should show statistics
        assert!(content.contains("Total Crashes:") && content.contains("</strong> 3"));
        assert!(content.contains("Crashes by Category"));
        assert!(content.contains("panic"));
    }

    #[test]
    fn test_write_html_summary_unique_count() {
        let temp_dir = TempDir::new().unwrap();
        let html_path = temp_dir.path().join("unique.html");

        // Create duplicate crashes (same input and error)
        let crashes = vec![
            CrashInfo::new(
                "crash-1".to_string(),
                vec![1, 2, 3],
                "same error".to_string(),
            ),
            CrashInfo::new(
                "crash-2".to_string(),
                vec![1, 2, 3],
                "same error".to_string(),
            ),
            CrashInfo::new(
                "crash-3".to_string(),
                vec![4, 5, 6],
                "different error".to_string(),
            ),
        ];

        write_html_summary(&crashes, &html_path).unwrap();
        let content = fs::read_to_string(&html_path).unwrap();

        // Should show 3 total crashes but only 2 unique
        assert!(content.contains("Total Crashes:") && content.contains("</strong> 3"));
        assert!(content.contains("Unique Crashes:") && content.contains("</strong> 2"));
    }
}
