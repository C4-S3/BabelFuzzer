//! Property-based tests for corpus deduplication and mutator invariants
//!
//! These tests use proptest to verify key invariants hold for arbitrary inputs.

use proptest::prelude::*;
use proto_fuzzer::core_types::TestCase;
use proto_fuzzer::engine::corpus::Corpus;
use proto_fuzzer::engine::mutator::{BitFlip, Mutator};

proptest! {
    /// Property: BitFlip always returns a Vec<u8> with the same length as input
    /// for any non-empty input
    #[test]
    fn prop_bitflip_preserves_length_invariant(input in prop::collection::vec(any::<u8>(), 1..1000)) {
        let mutator = BitFlip::new();
        let mutated = mutator.mutate(&input);

        prop_assert_eq!(
            mutated.len(),
            input.len(),
            "BitFlip must always preserve input length for non-empty inputs"
        );
    }

    /// Property: Corpus uses SHA256 for deduplication and does not increase map size
    /// when re-adding the same data
    #[test]
    fn prop_corpus_dedup_invariant(data in prop::collection::vec(any::<u8>(), 0..1000)) {
        let corpus = Corpus::new();

        // Create first test case with the data
        let tc1 = TestCase::new(
            "test-1".to_string(),
            data.clone(),
            serde_json::json!({"source": "first"}),
        );

        // Add first test case - should succeed (new entry)
        let first_add = corpus.add(tc1);
        let size_after_first = corpus.len();

        // Create second test case with same data but different metadata
        let tc2 = TestCase::new(
            "test-2".to_string(),
            data.clone(),
            serde_json::json!({"source": "second"}),
        );

        // Add second test case - should be deduplicated
        let second_add = corpus.add(tc2);
        let size_after_second = corpus.len();

        // First add should return true (new entry)
        prop_assert!(
            first_add,
            "First add of unique data should return true"
        );

        // Second add should return false (duplicate detected via SHA256)
        prop_assert!(
            !second_add,
            "Second add of same data should return false (duplicate)"
        );

        // Corpus size should not increase on duplicate add
        prop_assert_eq!(
            size_after_second,
            size_after_first,
            "Corpus size must not increase when adding duplicate data"
        );
    }

    /// Property: Multiple additions of the same data do not increase corpus size
    #[test]
    fn prop_corpus_idempotent_add(
        data in prop::collection::vec(any::<u8>(), 0..500),
        num_adds in 2usize..10
    ) {
        let corpus = Corpus::new();

        // Add the same data multiple times
        for i in 0..num_adds {
            let tc = TestCase::new(
                format!("test-{}", i),
                data.clone(),
                serde_json::json!({"iteration": i}),
            );
            corpus.add(tc);
        }

        // Corpus should only contain one entry (deduplication via SHA256)
        prop_assert_eq!(
            corpus.len(),
            1,
            "Corpus should contain exactly 1 entry after adding same data {} times",
            num_adds
        );
    }

    /// Property: Corpus correctly handles multiple distinct data entries
    #[test]
    fn prop_corpus_distinct_entries(test_data in prop::collection::vec(any::<u8>(), 1..100)) {
        let corpus = Corpus::new();

        // Create distinct data by appending index
        let mut unique_count = 0;
        let mut seen_data = std::collections::HashSet::new();

        for (i, byte_val) in test_data.iter().enumerate() {
            let data = vec![*byte_val, i as u8]; // Make each entry unique

            if seen_data.insert(data.clone()) {
                unique_count += 1;
            }

            let tc = TestCase::new(
                format!("test-{}", i),
                data,
                serde_json::json!({}),
            );
            corpus.add(tc);
        }

        // Corpus size should match number of unique data entries
        prop_assert_eq!(
            corpus.len(),
            unique_count,
            "Corpus size should match number of unique data entries"
        );
    }

    /// Property: BitFlip preserves length across multiple mutations
    #[test]
    fn prop_bitflip_repeated_mutations_preserve_length(
        input in prop::collection::vec(any::<u8>(), 1..500),
        num_mutations in 1usize..20
    ) {
        let mutator = BitFlip::new();
        let mut current = input.clone();
        let original_len = input.len();

        for _ in 0..num_mutations {
            current = mutator.mutate(&current);
            prop_assert_eq!(
                current.len(),
                original_len,
                "Length must be preserved across multiple BitFlip mutations"
            );
        }
    }
}

#[cfg(test)]
mod standard_tests {
    use super::*;

    #[test]
    fn test_corpus_dedup_deterministic() {
        let corpus = Corpus::new();

        // Add same data multiple times
        let data = vec![1, 2, 3, 4, 5];

        let tc1 = TestCase::new("tc1".to_string(), data.clone(), serde_json::json!({}));
        let tc2 = TestCase::new("tc2".to_string(), data.clone(), serde_json::json!({}));
        let tc3 = TestCase::new("tc3".to_string(), data, serde_json::json!({}));

        assert!(corpus.add(tc1), "First add should succeed");
        assert!(!corpus.add(tc2), "Second add should be deduplicated");
        assert!(!corpus.add(tc3), "Third add should be deduplicated");
        assert_eq!(corpus.len(), 1, "Corpus should contain only 1 entry");
    }

    #[test]
    fn test_bitflip_length_preservation() {
        let mutator = BitFlip::new();

        let inputs = vec![
            vec![1],
            vec![1, 2, 3],
            vec![0xFF; 100],
            vec![0; 255],
        ];

        for input in inputs {
            let original_len = input.len();
            let mutated = mutator.mutate(&input);
            assert_eq!(
                mutated.len(),
                original_len,
                "BitFlip must preserve length for input of size {}",
                original_len
            );
        }
    }
}
