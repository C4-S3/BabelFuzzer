//! Mutation strategies and engine
//!
//! This module provides the core mutation functionality for the fuzzer.
//! Mutations are applied to inputs to generate new test cases.

use rand::Rng;

/// Trait for mutation strategies
///
/// All mutators must be thread-safe (Send + Sync) to support parallel fuzzing.
pub trait Mutator: Send + Sync {
    /// Apply mutation to input and return a new mutated byte vector
    fn mutate(&self, input: &[u8]) -> Vec<u8>;
}

/// BitFlip mutator - flips bits in the input
///
/// If `positions` is None, flips a single random bit.
/// If `positions` is Some, flips bits at the specified positions (with wrap-around).
#[derive(Debug, Clone)]
pub struct BitFlip {
    pub positions: Option<Vec<usize>>,
}

impl BitFlip {
    /// Create a new BitFlip mutator that flips random bits
    pub fn new() -> Self {
        Self { positions: None }
    }

    /// Create a BitFlip mutator that flips specific bit positions
    pub fn with_positions(positions: Vec<usize>) -> Self {
        Self {
            positions: Some(positions),
        }
    }
}

impl Default for BitFlip {
    fn default() -> Self {
        Self::new()
    }
}

impl Mutator for BitFlip {
    fn mutate(&self, input: &[u8]) -> Vec<u8> {
        if input.is_empty() {
            return Vec::new();
        }

        let mut result = input.to_vec();
        let total_bits = input.len() * 8;

        match &self.positions {
            None => {
                // Flip a single random bit
                let mut rng = rand::rng();
                let bit_pos = rng.random_range(0..total_bits);
                let byte_idx = bit_pos / 8;
                let bit_idx = bit_pos % 8;
                result[byte_idx] ^= 1 << bit_idx;
            }
            Some(positions) => {
                // Flip bits at specified positions (with wrap-around)
                for &pos in positions {
                    let bit_pos = pos % total_bits; // Wrap around
                    let byte_idx = bit_pos / 8;
                    let bit_idx = bit_pos % 8;
                    result[byte_idx] ^= 1 << bit_idx;
                }
            }
        }

        result
    }
}

/// Truncate mutator - randomly truncates input to a maximum length
///
/// The truncated length will be <= min(input.len(), max_len)
#[derive(Debug, Clone)]
pub struct Truncate {
    pub max_len: usize,
}

impl Truncate {
    /// Create a new Truncate mutator with the specified maximum length
    pub fn new(max_len: usize) -> Self {
        Self { max_len }
    }
}

impl Mutator for Truncate {
    fn mutate(&self, input: &[u8]) -> Vec<u8> {
        if input.is_empty() {
            return Vec::new();
        }

        let mut rng = rand::rng();
        let max_possible = input.len().min(self.max_len);

        // Randomly truncate to a length between 0 and max_possible (inclusive)
        let new_len = rng.random_range(0..=max_possible);

        input[..new_len].to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bitflip_empty_input() {
        let mutator = BitFlip::new();
        let result = mutator.mutate(&[]);
        assert_eq!(result, Vec::<u8>::new());
    }

    #[test]
    fn test_bitflip_single_byte() {
        let mutator = BitFlip::with_positions(vec![0]);
        let input = vec![0b00000000];
        let result = mutator.mutate(&input);
        assert_eq!(result, vec![0b00000001]);
    }

    #[test]
    fn test_bitflip_wrap_around() {
        let mutator = BitFlip::with_positions(vec![8, 9]); // Wrap to bits 0 and 1
        let input = vec![0b00000000];
        let result = mutator.mutate(&input);
        // Bit 8 wraps to bit 0, bit 9 wraps to bit 1
        assert_eq!(result, vec![0b00000011]);
    }

    #[test]
    fn test_bitflip_preserves_length() {
        let mutator = BitFlip::new();
        let input = vec![1, 2, 3, 4, 5];
        let result = mutator.mutate(&input);
        assert_eq!(result.len(), input.len());
    }

    #[test]
    fn test_truncate_empty_input() {
        let mutator = Truncate::new(10);
        let result = mutator.mutate(&[]);
        assert_eq!(result, Vec::<u8>::new());
    }

    #[test]
    fn test_truncate_respects_max_len() {
        let mutator = Truncate::new(3);
        let input = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let result = mutator.mutate(&input);
        assert!(result.len() <= 3);
    }

    #[test]
    fn test_truncate_never_increases_length() {
        let mutator = Truncate::new(100);
        let input = vec![1, 2, 3, 4, 5];

        // Run multiple times to account for randomness
        for _ in 0..10 {
            let result = mutator.mutate(&input);
            assert!(result.len() <= input.len());
            assert!(result.len() <= 100);
        }
    }
}
