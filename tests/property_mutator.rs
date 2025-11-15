//! Property-based tests for mutation engine
//!
//! These tests use proptest to verify properties hold for arbitrary inputs.

use proptest::prelude::*;
use proto_fuzzer::engine::mutator::{BitFlip, Mutator, Truncate};

proptest! {
    /// Property: BitFlip always returns a Vec<u8> with the same length as input
    /// for any non-empty input
    #[test]
    fn prop_bitflip_preserves_length(input in prop::collection::vec(any::<u8>(), 1..1000)) {
        let mutator = BitFlip::new();
        let mutated = mutator.mutate(&input);

        prop_assert_eq!(mutated.len(), input.len(),
            "BitFlip must preserve input length");
    }

    /// Property: BitFlip with specific positions also preserves length
    #[test]
    fn prop_bitflip_with_positions_preserves_length(
        input in prop::collection::vec(any::<u8>(), 1..1000),
        positions in prop::collection::vec(any::<usize>(), 1..10)
    ) {
        let mutator = BitFlip::with_positions(positions);
        let mutated = mutator.mutate(&input);

        prop_assert_eq!(mutated.len(), input.len(),
            "BitFlip with positions must preserve input length");
    }

    /// Property: Truncate always returns length <= min(input.len(), max_len)
    #[test]
    fn prop_truncate_respects_bounds(
        input in prop::collection::vec(any::<u8>(), 1..1000),
        max_len in 1usize..500
    ) {
        let mutator = Truncate::new(max_len);
        let mutated = mutator.mutate(&input);

        let expected_max = input.len().min(max_len);

        prop_assert!(mutated.len() <= input.len(),
            "Truncate must never increase input length: got {}, input was {}",
            mutated.len(), input.len());

        prop_assert!(mutated.len() <= max_len,
            "Truncate must respect max_len: got {}, max_len is {}",
            mutated.len(), max_len);

        prop_assert!(mutated.len() <= expected_max,
            "Truncate result must be <= min(input.len(), max_len)");
    }

    /// Property: Truncate result is always a prefix of the input
    #[test]
    fn prop_truncate_is_prefix(
        input in prop::collection::vec(any::<u8>(), 1..1000),
        max_len in 1usize..500
    ) {
        let mutator = Truncate::new(max_len);
        let mutated = mutator.mutate(&input);

        // The mutated data should be a prefix of the input
        prop_assert_eq!(&mutated[..], &input[..mutated.len()],
            "Truncate result must be a prefix of the input");
    }

    /// Property: BitFlip actually changes data (at least one bit is different)
    /// for non-trivial inputs
    #[test]
    fn prop_bitflip_changes_data(input in prop::collection::vec(any::<u8>(), 1..1000)) {
        let mutator = BitFlip::new();
        let mutated = mutator.mutate(&input);

        // For any non-empty input, at least one bit should be flipped
        // So the mutated output should differ from input
        prop_assert_ne!(mutated, input,
            "BitFlip should change the input data");
    }

    /// Property: Multiple mutations can be applied sequentially
    #[test]
    fn prop_mutations_composable(
        input in prop::collection::vec(any::<u8>(), 10..100),
        max_len in 5usize..50
    ) {
        let bitflip = BitFlip::new();
        let truncate = Truncate::new(max_len);

        // Apply BitFlip first, then Truncate
        let step1 = bitflip.mutate(&input);
        let step2 = truncate.mutate(&step1);

        prop_assert_eq!(step1.len(), input.len(),
            "BitFlip should preserve length");
        prop_assert!(step2.len() <= step1.len(),
            "Truncate should not increase length");
        prop_assert!(step2.len() <= max_len,
            "Truncate should respect max_len");
    }
}

#[cfg(test)]
mod standard_tests {
    use super::*;

    #[test]
    fn test_bitflip_empty_input() {
        let mutator = BitFlip::new();
        let result = mutator.mutate(&[]);
        assert_eq!(result, Vec::<u8>::new());
    }

    #[test]
    fn test_truncate_empty_input() {
        let mutator = Truncate::new(10);
        let result = mutator.mutate(&[]);
        assert_eq!(result, Vec::<u8>::new());
    }
}
