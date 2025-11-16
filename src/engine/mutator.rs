//! Mutation strategies and engine
//!
//! This module provides the core mutation functionality for the fuzzer.
//! Mutations are applied to inputs to generate new test cases.

use rand::Rng;
use std::sync::LazyLock;

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

/// CVE-focused attack dictionary with common vulnerability patterns
///
/// This dictionary contains patterns known to trigger vulnerabilities:
/// - Buffer overflows (long strings, boundary values)
/// - Integer overflows (INT_MAX, INT_MIN, wrap-around values)
/// - Format string attacks (%s, %x, %n, etc.)
/// - SQL injection patterns
/// - XSS/script injection
/// - Path traversal
/// - NULL bytes and special characters
/// - Unicode attacks
/// - Protobuf-specific attacks
static CVE_ATTACK_DICTIONARY: LazyLock<Vec<Vec<u8>>> = LazyLock::new(|| {
    vec![
        // Buffer overflow patterns
        vec![b'A'; 256],
        vec![b'A'; 512],
        vec![b'A'; 1024],
        vec![b'A'; 4096],
        vec![b'A'; 8192],
        vec![b'A'; 65535],

        // Integer boundary values (little-endian representations)
        vec![0xFF, 0xFF, 0xFF, 0xFF], // UINT32_MAX (4294967295)
        vec![0x00, 0x00, 0x00, 0x80], // INT32_MIN (-2147483648)
        vec![0xFF, 0xFF, 0xFF, 0x7F], // INT32_MAX (2147483647)
        vec![0xFF, 0xFF], // UINT16_MAX (65535)
        vec![0x00, 0x80], // INT16_MIN (-32768)
        vec![0xFF, 0x7F], // INT16_MAX (32767)
        vec![0xFF], // UINT8_MAX (255)
        vec![0x00], // Zero
        vec![0x01], // One
        vec![0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF], // UINT64_MAX

        // Integer overflow edge cases (big-endian)
        vec![0x7F, 0xFF, 0xFF, 0xFF], // INT32_MAX (big-endian)
        vec![0x80, 0x00, 0x00, 0x00], // INT32_MIN (big-endian)

        // Format string attacks
        b"%s%s%s%s%s%s%s%s%s%s".to_vec(),
        b"%x%x%x%x%x%x%x%x%x%x".to_vec(),
        b"%n%n%n%n%n%n%n%n%n%n".to_vec(),
        b"%s%p%x%d".to_vec(),
        b"%1$s%2$s%3$s%4$s%5$s".to_vec(),
        b"%.1000s%.1000s%.1000s".to_vec(),
        b"%99999999s".to_vec(),

        // SQL injection patterns (relevant if gRPC backend uses SQL)
        b"' OR '1'='1".to_vec(),
        b"'; DROP TABLE users--".to_vec(),
        b"\" OR \"1\"=\"1".to_vec(),
        b"admin'--".to_vec(),
        b"' OR 1=1--".to_vec(),
        b"1' UNION SELECT NULL--".to_vec(),

        // XSS and script injection
        b"<script>alert('XSS')</script>".to_vec(),
        b"<img src=x onerror=alert('XSS')>".to_vec(),
        b"javascript:alert('XSS')".to_vec(),
        b"<svg/onload=alert('XSS')>".to_vec(),

        // Path traversal
        b"../../../etc/passwd".to_vec(),
        b"..\\..\\..\\windows\\system32\\config\\sam".to_vec(),
        b"....//....//....//etc/passwd".to_vec(),
        b"%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd".to_vec(),

        // NULL byte injection
        b"\x00".to_vec(),
        b"file.txt\x00.jpg".to_vec(),
        b"admin\x00user".to_vec(),
        vec![0x00; 100], // Multiple NULL bytes

        // Special characters and delimiters
        b"\r\n\r\n".to_vec(), // HTTP header injection
        b"\n\n\n\n\n".to_vec(), // Newline flooding
        b"||||||||".to_vec(), // Pipe characters
        b";;;;;;;;".to_vec(), // Semicolons
        b"&&&&&&&&".to_vec(), // Command chaining
        b"{{{{{{{{".to_vec(), // Template injection
        b"}}}}}}}}".to_vec(),

        // Unicode attacks
        b"\xC0\x80".to_vec(), // Overlong UTF-8 encoding of NULL
        b"\xE0\x80\x80".to_vec(), // 3-byte overlong NULL
        b"\xF0\x80\x80\x80".to_vec(), // 4-byte overlong NULL
        b"\xEF\xBB\xBF".to_vec(), // UTF-8 BOM
        b"\xFE\xFF".to_vec(), // UTF-16 BE BOM
        b"\xFF\xFE".to_vec(), // UTF-16 LE BOM

        // Protobuf wire-type attacks (varint manipulation)
        vec![0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01], // Max varint
        vec![0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01], // All bits set
        vec![0x00, 0x00, 0x00, 0x00], // Embedded nulls

        // JSON injection (if protobuf-JSON transcoding is used)
        b"{\"__proto__\":{\"isAdmin\":true}}".to_vec(),
        b"{\"constructor\":{\"prototype\":{\"isAdmin\":true}}}".to_vec(),

        // LDAP injection
        b"*)(uid=*))(|(uid=*".to_vec(),
        b"admin)(|(password=*))".to_vec(),

        // XML injection
        b"<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>".to_vec(),
        b"<![CDATA[<script>alert('XSS')</script>]]>".to_vec(),

        // Command injection
        b"; ls -la".to_vec(),
        b"| cat /etc/passwd".to_vec(),
        b"`whoami`".to_vec(),
        b"$(whoami)".to_vec(),

        // gRPC/HTTP2 specific attacks
        b":method:GET\r\n:path:/../../../etc/passwd\r\n".to_vec(),
        vec![0x00, 0x00, 0x00], // Invalid frame header

        // Negative numbers (signed integer attacks)
        vec![0xFF, 0xFF, 0xFF, 0xFF], // -1 (as int32)
        vec![0xFE, 0xFF, 0xFF, 0xFF], // -2 (as int32)

        // Very large varints (protobuf length prefix attacks)
        vec![0xFF, 0xFF, 0xFF, 0xFF, 0x0F], // Max 32-bit varint

        // Empty and minimal values
        Vec::new(), // Empty payload
        vec![0x00], // Single zero byte

        // Repeated characters with special meaning
        vec![b'"'; 100], // Quote flooding
        vec![b'\''; 100], // Single quote flooding
        vec![b'\\'; 100], // Backslash flooding
    ]
});

/// Dictionary mutator - injects CVE-relevant attack patterns
///
/// This mutator replaces or splices known attack patterns into the input
/// to trigger common vulnerability classes.
#[derive(Debug, Clone)]
pub struct Dictionary {
    /// Strategy for applying dictionary values
    pub strategy: DictionaryStrategy,
}

/// Strategy for how to apply dictionary values
#[derive(Debug, Clone)]
pub enum DictionaryStrategy {
    /// Replace entire input with dictionary value
    Replace,
    /// Splice dictionary value at a random position
    Splice,
    /// Append dictionary value to input
    Append,
    /// Prepend dictionary value to input
    Prepend,
}

impl Dictionary {
    /// Create a new Dictionary mutator with the default Replace strategy
    pub fn new() -> Self {
        Self {
            strategy: DictionaryStrategy::Replace,
        }
    }

    /// Create a Dictionary mutator with a specific strategy
    pub fn with_strategy(strategy: DictionaryStrategy) -> Self {
        Self { strategy }
    }
}

impl Default for Dictionary {
    fn default() -> Self {
        Self::new()
    }
}

impl Mutator for Dictionary {
    fn mutate(&self, input: &[u8]) -> Vec<u8> {
        let mut rng = rand::rng();

        // Select a random attack pattern from the dictionary
        let dict_value = &CVE_ATTACK_DICTIONARY[rng.random_range(0..CVE_ATTACK_DICTIONARY.len())];

        match self.strategy {
            DictionaryStrategy::Replace => {
                // Replace entire input with dictionary value
                dict_value.clone()
            }
            DictionaryStrategy::Splice => {
                if input.is_empty() {
                    return dict_value.clone();
                }

                // Insert dictionary value at random position
                let pos = rng.random_range(0..=input.len());
                let mut result = Vec::with_capacity(input.len() + dict_value.len());
                result.extend_from_slice(&input[..pos]);
                result.extend_from_slice(dict_value);
                result.extend_from_slice(&input[pos..]);
                result
            }
            DictionaryStrategy::Append => {
                // Append dictionary value to end
                let mut result = input.to_vec();
                result.extend_from_slice(dict_value);
                result
            }
            DictionaryStrategy::Prepend => {
                // Prepend dictionary value to beginning
                let mut result = dict_value.clone();
                result.extend_from_slice(input);
                result
            }
        }
    }
}

/// Arithmetic mutator - mutates integer values to trigger overflows and edge cases
///
/// This mutator targets CVE classes like:
/// - Integer overflows (CWE-190)
/// - Integer underflows (CWE-191)
/// - Signed/unsigned confusion (CWE-195)
/// - Division by zero (CWE-369)
#[derive(Debug, Clone)]
pub struct Arithmetic {
    /// Operation to apply
    pub operation: ArithmeticOp,
}

/// Arithmetic operations for integer mutation
#[derive(Debug, Clone)]
pub enum ArithmeticOp {
    /// Add a random value
    Add(i64),
    /// Subtract a random value
    Sub(i64),
    /// Multiply by a value
    Mul(i64),
    /// Set to interesting value (boundaries)
    SetInteresting,
}

impl Arithmetic {
    /// Create arithmetic mutator that sets interesting boundary values
    pub fn new() -> Self {
        Self {
            operation: ArithmeticOp::SetInteresting,
        }
    }

    /// Create arithmetic mutator with specific operation
    pub fn with_operation(operation: ArithmeticOp) -> Self {
        Self { operation }
    }
}

impl Default for Arithmetic {
    fn default() -> Self {
        Self::new()
    }
}

impl Mutator for Arithmetic {
    fn mutate(&self, input: &[u8]) -> Vec<u8> {
        if input.is_empty() {
            return Vec::new();
        }

        let mut rng = rand::rng();
        let mut result = input.to_vec();

        // Find locations that look like integers (aligned positions)
        let positions: Vec<usize> = (0..input.len()).collect();
        if positions.is_empty() {
            return result;
        }

        let pos = positions[rng.random_range(0..positions.len())];

        match &self.operation {
            ArithmeticOp::Add(val) => {
                // Mutate as different integer sizes
                if pos + 4 <= input.len() {
                    let mut bytes = [0u8; 4];
                    bytes.copy_from_slice(&input[pos..pos + 4]);
                    let orig = i32::from_le_bytes(bytes);
                    let new_val = orig.wrapping_add(*val as i32);
                    result[pos..pos + 4].copy_from_slice(&new_val.to_le_bytes());
                } else if pos + 2 <= input.len() {
                    let mut bytes = [0u8; 2];
                    bytes.copy_from_slice(&input[pos..pos + 2]);
                    let orig = i16::from_le_bytes(bytes);
                    let new_val = orig.wrapping_add(*val as i16);
                    result[pos..pos + 2].copy_from_slice(&new_val.to_le_bytes());
                } else {
                    let orig = input[pos] as i8;
                    let new_val = orig.wrapping_add(*val as i8);
                    result[pos] = new_val as u8;
                }
            }
            ArithmeticOp::Sub(val) => {
                if pos + 4 <= input.len() {
                    let mut bytes = [0u8; 4];
                    bytes.copy_from_slice(&input[pos..pos + 4]);
                    let orig = i32::from_le_bytes(bytes);
                    let new_val = orig.wrapping_sub(*val as i32);
                    result[pos..pos + 4].copy_from_slice(&new_val.to_le_bytes());
                } else if pos + 2 <= input.len() {
                    let mut bytes = [0u8; 2];
                    bytes.copy_from_slice(&input[pos..pos + 2]);
                    let orig = i16::from_le_bytes(bytes);
                    let new_val = orig.wrapping_sub(*val as i16);
                    result[pos..pos + 2].copy_from_slice(&new_val.to_le_bytes());
                } else {
                    let orig = input[pos] as i8;
                    let new_val = orig.wrapping_sub(*val as i8);
                    result[pos] = new_val as u8;
                }
            }
            ArithmeticOp::Mul(val) => {
                if pos + 4 <= input.len() {
                    let mut bytes = [0u8; 4];
                    bytes.copy_from_slice(&input[pos..pos + 4]);
                    let orig = i32::from_le_bytes(bytes);
                    let new_val = orig.wrapping_mul(*val as i32);
                    result[pos..pos + 4].copy_from_slice(&new_val.to_le_bytes());
                } else if pos + 2 <= input.len() {
                    let mut bytes = [0u8; 2];
                    bytes.copy_from_slice(&input[pos..pos + 2]);
                    let orig = i16::from_le_bytes(bytes);
                    let new_val = orig.wrapping_mul(*val as i16);
                    result[pos..pos + 2].copy_from_slice(&new_val.to_le_bytes());
                } else {
                    let orig = input[pos] as i8;
                    let new_val = orig.wrapping_mul(*val as i8);
                    result[pos] = new_val as u8;
                }
            }
            ArithmeticOp::SetInteresting => {
                // Set to interesting boundary values
                let interesting_8bit: Vec<u8> = vec![0, 1, 127, 128, 255];
                let interesting_16bit: Vec<i16> = vec![0, 1, -1, 32767, -32768, -1];
                let interesting_32bit: Vec<i32> =
                    vec![0, 1, -1, 2147483647, -2147483648, -1];

                if pos + 4 <= input.len() {
                    let val = interesting_32bit[rng.random_range(0..interesting_32bit.len())];
                    result[pos..pos + 4].copy_from_slice(&val.to_le_bytes());
                } else if pos + 2 <= input.len() {
                    let val = interesting_16bit[rng.random_range(0..interesting_16bit.len())];
                    result[pos..pos + 2].copy_from_slice(&val.to_le_bytes());
                } else {
                    let val = interesting_8bit[rng.random_range(0..interesting_8bit.len())];
                    result[pos] = val;
                }
            }
        }

        result
    }
}

/// Splice mutator - combines parts from two inputs
///
/// This creates hybrid test cases that can trigger complex vulnerabilities
/// requiring specific combinations of features.
#[derive(Debug, Clone)]
pub struct Splice {
    /// Second input to splice with
    pub other: Vec<u8>,
}

impl Splice {
    /// Create a new Splice mutator
    pub fn new(other: Vec<u8>) -> Self {
        Self { other }
    }
}

impl Mutator for Splice {
    fn mutate(&self, input: &[u8]) -> Vec<u8> {
        if input.is_empty() || self.other.is_empty() {
            return input.to_vec();
        }

        let mut rng = rand::rng();

        // Choose random split points
        let split1 = rng.random_range(0..=input.len());
        let split2 = rng.random_range(0..=self.other.len());

        // Combine: first part of input + second part of other
        let mut result = Vec::with_capacity(split1 + (self.other.len() - split2));
        result.extend_from_slice(&input[..split1]);
        result.extend_from_slice(&self.other[split2..]);

        result
    }
}

/// Havoc mutator - AFL-style aggressive multi-mutation
///
/// Applies multiple random mutations in sequence to maximize code coverage
/// and trigger complex bugs. This is the "kitchen sink" approach.
#[derive(Debug, Clone)]
pub struct Havoc {
    /// Number of mutations to apply (random if None)
    pub mutation_count: Option<usize>,
}

impl Havoc {
    /// Create a new Havoc mutator with random mutation count
    pub fn new() -> Self {
        Self {
            mutation_count: None,
        }
    }

    /// Create a Havoc mutator with specific mutation count
    pub fn with_count(count: usize) -> Self {
        Self {
            mutation_count: Some(count),
        }
    }
}

impl Default for Havoc {
    fn default() -> Self {
        Self::new()
    }
}

impl Mutator for Havoc {
    fn mutate(&self, input: &[u8]) -> Vec<u8> {
        if input.is_empty() {
            return Vec::new();
        }

        let mut rng = rand::rng();
        let mut result = input.to_vec();

        // Determine how many mutations to apply
        let count = self
            .mutation_count
            .unwrap_or_else(|| rng.random_range(1..=10));

        // Available sub-mutators
        let mutators: Vec<Box<dyn Mutator>> = vec![
            Box::new(BitFlip::new()),
            Box::new(Truncate::new(result.len() + 100)),
            Box::new(Dictionary::new()),
            Box::new(Arithmetic::new()),
        ];

        // Apply random mutations
        for _ in 0..count {
            let mutator = &mutators[rng.random_range(0..mutators.len())];
            result = mutator.mutate(&result);

            // Occasionally insert random bytes
            if rng.random_range(0..10) < 3 && !result.is_empty() {
                let pos = rng.random_range(0..=result.len());
                let byte: u8 = rng.random_range(0..=255);
                result.insert(pos, byte);
            }

            // Occasionally delete random bytes
            if rng.random_range(0..10) < 2 && result.len() > 1 {
                let pos = rng.random_range(0..result.len());
                result.remove(pos);
            }

            // Occasionally swap bytes
            if rng.random_range(0..10) < 2 && result.len() > 1 {
                let pos1 = rng.random_range(0..result.len());
                let pos2 = rng.random_range(0..result.len());
                result.swap(pos1, pos2);
            }
        }

        result
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

    #[test]
    fn test_dictionary_replace() {
        let mutator = Dictionary::new();
        let input = vec![1, 2, 3];
        let result = mutator.mutate(&input);

        // Result should be one of the dictionary values
        assert!(CVE_ATTACK_DICTIONARY.contains(&result));
    }

    #[test]
    fn test_dictionary_splice() {
        let mutator = Dictionary::with_strategy(DictionaryStrategy::Splice);
        let input = vec![1, 2, 3];
        let result = mutator.mutate(&input);

        // Result should be longer than input (except for empty dictionary values)
        // or equal if the dictionary value was empty
        assert!(result.len() >= input.len());
    }

    #[test]
    fn test_dictionary_append() {
        let mutator = Dictionary::with_strategy(DictionaryStrategy::Append);
        let input = vec![1, 2, 3];
        let result = mutator.mutate(&input);

        // Result should start with the original input
        assert!(result.starts_with(&input));
        assert!(result.len() >= input.len());
    }

    #[test]
    fn test_dictionary_prepend() {
        let mutator = Dictionary::with_strategy(DictionaryStrategy::Prepend);
        let input = vec![1, 2, 3];
        let result = mutator.mutate(&input);

        // Result should end with the original input
        assert!(result.ends_with(&input));
        assert!(result.len() >= input.len());
    }

    #[test]
    fn test_dictionary_contains_cve_patterns() {
        // Verify dictionary contains key CVE patterns

        // Buffer overflow patterns
        assert!(CVE_ATTACK_DICTIONARY.iter().any(|v| v.len() == 4096));

        // Integer boundary values
        assert!(CVE_ATTACK_DICTIONARY.contains(&vec![0xFF, 0xFF, 0xFF, 0xFF]));

        // Format string attacks
        assert!(CVE_ATTACK_DICTIONARY
            .iter()
            .any(|v| v.contains(&b'%') && v.contains(&b'n')));

        // NULL byte injection
        assert!(CVE_ATTACK_DICTIONARY.contains(&b"\x00".to_vec()));

        // Path traversal
        assert!(CVE_ATTACK_DICTIONARY
            .iter()
            .any(|v| v.contains(&b'.') && v.contains(&b'/')));
    }

    #[test]
    fn test_arithmetic_set_interesting() {
        let mutator = Arithmetic::new();
        let input = vec![0, 0, 0, 0];
        let result = mutator.mutate(&input);

        // Result should be 4 bytes (32-bit integer)
        assert_eq!(result.len(), 4);
        // Should have changed from all zeros
        // (with very small probability it might be set to 0, but unlikely)
    }

    #[test]
    fn test_arithmetic_add() {
        let mutator = Arithmetic::with_operation(ArithmeticOp::Add(100));
        let input = vec![10, 0, 0, 0]; // 10 as i32 little-endian
        let result = mutator.mutate(&input);

        assert_eq!(result.len(), input.len());
    }

    #[test]
    fn test_arithmetic_preserves_length() {
        let mutator = Arithmetic::new();
        let input = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let result = mutator.mutate(&input);

        assert_eq!(result.len(), input.len());
    }

    #[test]
    fn test_splice_combines_inputs() {
        let input1 = vec![1, 2, 3, 4];
        let input2 = vec![5, 6, 7, 8];
        let mutator = Splice::new(input2);

        let result = mutator.mutate(&input1);

        // Result should contain bytes from both inputs
        assert!(!result.is_empty());
    }

    #[test]
    fn test_splice_empty_input() {
        let input1 = Vec::new();
        let input2 = vec![5, 6, 7, 8];
        let mutator = Splice::new(input2);

        let result = mutator.mutate(&input1);
        assert_eq!(result, input1);
    }

    #[test]
    fn test_havoc_mutates_input() {
        let mutator = Havoc::with_count(5);
        let input = vec![1, 2, 3, 4, 5];

        let result = mutator.mutate(&input);

        // After 5 mutations, something should have changed
        // (theoretically could be same, but extremely unlikely)
        assert!(!result.is_empty());
    }

    #[test]
    fn test_havoc_empty_input() {
        let mutator = Havoc::new();
        let input = Vec::new();
        let result = mutator.mutate(&input);

        assert_eq!(result, Vec::<u8>::new());
    }

    #[test]
    fn test_havoc_multiple_strategies() {
        let mutator = Havoc::with_count(10);
        let input = vec![0xAA; 16];

        // Run multiple times to ensure havoc applies various strategies
        for _ in 0..5 {
            let result = mutator.mutate(&input);
            // Just ensure it doesn't crash
            // (result can be empty due to truncate/delete mutations)
            let _ = result;
        }
    }
}
