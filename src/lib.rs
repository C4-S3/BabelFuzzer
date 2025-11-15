pub mod core_types;
pub mod engine;
pub mod protocols;
pub mod detection;
pub mod orchestrator;
pub mod utils;

#[cfg(test)]
mod tests {
    #[test]
    fn test_library_builds() {
        // Trivial test to verify the library builds correctly
        assert_eq!(2 + 2, 4);
    }
}
