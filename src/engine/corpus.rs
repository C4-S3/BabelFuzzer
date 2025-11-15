// Corpus management

use crate::core_types::TestCase;
use anyhow::Result;
use dashmap::DashMap;
use rand::seq::IteratorRandom;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;
use std::sync::Arc;

/// In-memory corpus with SHA256-based deduplication
#[derive(Clone)]
pub struct Corpus {
    map: Arc<DashMap<String, TestCase>>,
}

impl Corpus {
    /// Create a new empty corpus
    pub fn new() -> Self {
        Self {
            map: Arc::new(DashMap::new()),
        }
    }

    /// Add a test case to the corpus
    ///
    /// Computes SHA256 hash of the test case data and uses it as the key.
    /// Returns true if the test case was inserted (new), false if it was a duplicate.
    pub fn add(&self, tc: TestCase) -> bool {
        // Compute SHA256 hash of the data
        let mut hasher = Sha256::new();
        hasher.update(&tc.data);
        let hash = hasher.finalize();
        let hash_hex = format!("{:x}", hash);

        // Try to insert - returns None if key didn't exist (new entry)
        self.map.insert(hash_hex, tc).is_none()
    }

    /// Select a random test case from the corpus
    ///
    /// Returns None if the corpus is empty.
    pub fn select(&self) -> Option<TestCase> {
        let mut rng = rand::rng();
        self.map
            .iter()
            .choose(&mut rng)
            .map(|entry| entry.value().clone())
    }

    /// Get the number of test cases in the corpus
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Check if the corpus is empty
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Persist the corpus to a JSON file
    pub fn persist_to_file(&self, path: &Path) -> Result<()> {
        // Collect all test cases into a serializable format
        let entries: Vec<CorpusEntry> = self
            .map
            .iter()
            .map(|entry| CorpusEntry {
                hash: entry.key().clone(),
                test_case: entry.value().clone(),
            })
            .collect();

        let corpus_data = CorpusData { entries };
        let json = serde_json::to_string_pretty(&corpus_data)?;
        fs::write(path, json)?;
        Ok(())
    }

    /// Load the corpus from a JSON file
    pub fn load_from_file(path: &Path) -> Result<Self> {
        let json = fs::read_to_string(path)?;
        let corpus_data: CorpusData = serde_json::from_str(&json)?;

        let corpus = Self::new();
        for entry in corpus_data.entries {
            corpus.map.insert(entry.hash, entry.test_case);
        }

        Ok(corpus)
    }
}

impl Default for Corpus {
    fn default() -> Self {
        Self::new()
    }
}

/// Serializable representation of the corpus
#[derive(Debug, Serialize, Deserialize)]
struct CorpusData {
    entries: Vec<CorpusEntry>,
}

/// A single entry in the corpus (hash + test case)
#[derive(Debug, Serialize, Deserialize)]
struct CorpusEntry {
    hash: String,
    test_case: TestCase,
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_corpus_dedup() {
        let corpus = Corpus::new();

        // Create a test case
        let tc = TestCase::new(
            "test-1".to_string(),
            vec![1, 2, 3, 4, 5],
            serde_json::json!({"source": "test"}),
        );

        // First insert should return true (new)
        assert!(corpus.add(tc.clone()));
        assert_eq!(corpus.len(), 1);

        // Second insert of same data should return false (duplicate)
        let tc2 = TestCase::new(
            "test-2".to_string(), // Different ID
            vec![1, 2, 3, 4, 5],  // Same data
            serde_json::json!({"source": "test2"}), // Different metadata
        );
        assert!(!corpus.add(tc2));
        assert_eq!(corpus.len(), 1, "Duplicate test case should not be added");
    }

    #[test]
    fn test_persist_roundtrip() {
        let corpus = Corpus::new();

        // Add multiple test cases
        let tc1 = TestCase::new(
            "test-1".to_string(),
            vec![1, 2, 3],
            serde_json::json!({"source": "generator"}),
        );
        let tc2 = TestCase::new(
            "test-2".to_string(),
            vec![4, 5, 6],
            serde_json::json!({"source": "mutator"}),
        );
        let tc3 = TestCase::new(
            "test-3".to_string(),
            vec![7, 8, 9],
            serde_json::json!({"source": "manual"}),
        );

        corpus.add(tc1.clone());
        corpus.add(tc2.clone());
        corpus.add(tc3.clone());

        assert_eq!(corpus.len(), 3);

        // Persist to temporary file
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path();
        corpus.persist_to_file(path).unwrap();

        // Load from file
        let loaded_corpus = Corpus::load_from_file(path).unwrap();

        // Verify counts match
        assert_eq!(
            loaded_corpus.len(),
            corpus.len(),
            "Loaded corpus should have same count as original"
        );

        // Verify data equality by checking if we can find each original test case's data
        let loaded_data: Vec<Vec<u8>> = loaded_corpus
            .map
            .iter()
            .map(|entry| entry.value().data.clone())
            .collect();

        assert!(loaded_data.contains(&vec![1, 2, 3]));
        assert!(loaded_data.contains(&vec![4, 5, 6]));
        assert!(loaded_data.contains(&vec![7, 8, 9]));
    }

    #[test]
    fn test_select_empty_corpus() {
        let corpus = Corpus::new();
        assert_eq!(corpus.select(), None);
    }

    #[test]
    fn test_select_single_item() {
        let corpus = Corpus::new();
        let tc = TestCase::new(
            "test-1".to_string(),
            vec![1, 2, 3],
            serde_json::json!({}),
        );
        corpus.add(tc.clone());

        let selected = corpus.select().unwrap();
        assert_eq!(selected.data, vec![1, 2, 3]);
    }

    #[test]
    fn test_select_returns_valid_item() {
        let corpus = Corpus::new();

        // Add multiple items
        for i in 0..10 {
            let tc = TestCase::new(
                format!("test-{}", i),
                vec![i as u8],
                serde_json::json!({}),
            );
            corpus.add(tc);
        }

        // Select multiple times and verify we always get a valid item
        for _ in 0..20 {
            let selected = corpus.select().unwrap();
            assert!(selected.data.len() == 1);
            assert!(selected.data[0] < 10);
        }
    }

    #[test]
    fn test_different_data_same_id() {
        let corpus = Corpus::new();

        let tc1 = TestCase::new(
            "same-id".to_string(),
            vec![1, 2, 3],
            serde_json::json!({}),
        );
        let tc2 = TestCase::new(
            "same-id".to_string(),
            vec![4, 5, 6], // Different data
            serde_json::json!({}),
        );

        assert!(corpus.add(tc1));
        assert!(corpus.add(tc2)); // Should be added because data is different
        assert_eq!(corpus.len(), 2);
    }

    // Proptest: SHA256 hashes should be consistent for the same input
    proptest! {
        #[test]
        fn test_sha256_consistency(data: Vec<u8>) {
            let corpus1 = Corpus::new();
            let corpus2 = Corpus::new();

            let tc1 = TestCase::new(
                "test-1".to_string(),
                data.clone(),
                serde_json::json!({}),
            );
            let tc2 = TestCase::new(
                "test-2".to_string(),
                data.clone(),
                serde_json::json!({}),
            );

            // Add to first corpus
            corpus1.add(tc1);

            // Try to add to second corpus - should work
            assert!(corpus2.add(tc2.clone()));

            // Try to add again to second corpus - should be duplicate
            let tc3 = TestCase::new(
                "test-3".to_string(),
                data,
                serde_json::json!({}),
            );
            assert!(!corpus2.add(tc3));
        }

        #[test]
        fn test_persist_roundtrip_property(test_cases: Vec<Vec<u8>>) {
            let corpus = Corpus::new();

            // Add all test cases
            let mut expected_count = 0;
            let mut seen_hashes = std::collections::HashSet::new();

            for (i, data) in test_cases.iter().enumerate() {
                let tc = TestCase::new(
                    format!("test-{}", i),
                    data.clone(),
                    serde_json::json!({}),
                );

                // Compute expected hash
                let mut hasher = Sha256::new();
                hasher.update(data);
                let hash = hasher.finalize();
                let hash_hex = format!("{:x}", hash);

                if seen_hashes.insert(hash_hex) {
                    expected_count += 1;
                }

                corpus.add(tc);
            }

            // Persist and reload
            let temp_file = NamedTempFile::new().unwrap();
            let path = temp_file.path();
            corpus.persist_to_file(path).unwrap();
            let loaded = Corpus::load_from_file(path).unwrap();

            // Verify count matches (accounting for deduplication)
            assert_eq!(loaded.len(), expected_count);
        }
    }
}
