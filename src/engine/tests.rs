//! Unit tests for the mutation engine

use super::mutator::{BitFlip, Mutator, Truncate};

#[test]
fn test_bitflip_changes_data() {
    let mutator = BitFlip::new();
    let input = vec![0xFF, 0xFF, 0xFF, 0xFF]; // Non-empty input

    // Run mutation multiple times to ensure it changes data
    // (with random bit flipping, there's always a change)
    let mutated = mutator.mutate(&input);

    // The mutated data should be different from the input
    // (at least one bit should be flipped)
    assert_ne!(mutated, input, "BitFlip should change the input data");

    // Verify length is preserved
    assert_eq!(
        mutated.len(),
        input.len(),
        "BitFlip should preserve input length"
    );
}

#[test]
fn test_bitflip_changes_data_single_byte() {
    let mutator = BitFlip::new();
    let input = vec![0x00]; // Single byte

    let mutated = mutator.mutate(&input);

    // Should be different
    assert_ne!(mutated, input, "BitFlip should change single byte input");
    assert_eq!(mutated.len(), 1, "BitFlip should preserve length");
}

#[test]
fn test_truncate_never_increases_length() {
    let mutator = Truncate::new(10);
    let input = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];

    // Run multiple times to account for randomness
    for _ in 0..20 {
        let mutated = mutator.mutate(&input);

        // Should never increase length
        assert!(
            mutated.len() <= input.len(),
            "Truncate should never increase input length: got {}, expected <= {}",
            mutated.len(),
            input.len()
        );

        // Should respect max_len
        assert!(
            mutated.len() <= 10,
            "Truncate should respect max_len: got {}, expected <= 10",
            mutated.len()
        );
    }
}

#[test]
fn test_truncate_with_small_max_len() {
    let mutator = Truncate::new(3);
    let input = vec![1, 2, 3, 4, 5, 6, 7, 8];

    for _ in 0..20 {
        let mutated = mutator.mutate(&input);

        assert!(
            mutated.len() <= input.len(),
            "Truncate should never increase length"
        );
        assert!(mutated.len() <= 3, "Truncate should respect max_len of 3");
    }
}

#[test]
fn test_truncate_when_input_smaller_than_max() {
    let mutator = Truncate::new(100);
    let input = vec![1, 2, 3];

    for _ in 0..20 {
        let mutated = mutator.mutate(&input);

        assert!(
            mutated.len() <= input.len(),
            "Truncate should never increase length even when max_len > input.len()"
        );
    }
}
