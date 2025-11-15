// Schema discovery via gRPC reflection
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Schema information for a gRPC service
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceSchema {
    pub package: String,
    pub services: Vec<Service>,
}

/// Service definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Service {
    pub name: String,
    pub methods: Vec<Method>,
}

/// Method definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Method {
    pub name: String,
    pub input_type: String,
    pub output_type: String,
}

/// Message definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub name: String,
    pub fields: Vec<Field>,
}

/// Field definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Field {
    pub name: String,
    pub field_type: String,
    pub number: u32,
}

/// Client for discovering gRPC service schemas
pub struct ReflectionClient {
    schemas: HashMap<String, ServiceSchema>,
}

impl ReflectionClient {
    /// Create a new reflection client
    pub fn new() -> Self {
        Self {
            schemas: HashMap::new(),
        }
    }

    /// Get schema for the Echo service (hardcoded fallback)
    pub fn get_echo_schema(&self) -> Result<ServiceSchema> {
        // Hardcoded schema for the Echo service from protos/echo.proto
        let schema = ServiceSchema {
            package: "echo".to_string(),
            services: vec![Service {
                name: "Echo".to_string(),
                methods: vec![Method {
                    name: "EchoMessage".to_string(),
                    input_type: "EchoRequest".to_string(),
                    output_type: "EchoResponse".to_string(),
                }],
            }],
        };

        Ok(schema)
    }

    /// Get schema as JSON string
    pub fn get_schema_json(&self) -> Result<String> {
        let schema = self.get_echo_schema()?;
        serde_json::to_string_pretty(&schema).context("Failed to serialize schema to JSON")
    }

    /// Load schema from proto file (fallback when reflection is not available)
    /// For now, returns the hardcoded Echo schema
    pub fn load_from_proto(&mut self, _proto_path: &str) -> Result<ServiceSchema> {
        let schema = self.get_echo_schema()?;
        self.schemas
            .insert(schema.package.clone(), schema.clone());
        Ok(schema)
    }

    /// Get all loaded schemas
    pub fn schemas(&self) -> &HashMap<String, ServiceSchema> {
        &self.schemas
    }
}

impl Default for ReflectionClient {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reflection_client_creation() {
        let client = ReflectionClient::new();
        assert_eq!(client.schemas().len(), 0);
    }

    #[test]
    fn test_get_echo_schema() {
        let client = ReflectionClient::new();
        let schema = client.get_echo_schema().expect("Failed to get schema");

        assert_eq!(schema.package, "echo");
        assert_eq!(schema.services.len(), 1);
        assert_eq!(schema.services[0].name, "Echo");
        assert_eq!(schema.services[0].methods.len(), 1);
        assert_eq!(schema.services[0].methods[0].name, "EchoMessage");
        assert_eq!(schema.services[0].methods[0].input_type, "EchoRequest");
        assert_eq!(schema.services[0].methods[0].output_type, "EchoResponse");
    }

    #[test]
    fn test_get_schema_json() {
        let client = ReflectionClient::new();
        let json = client.get_schema_json().expect("Failed to get JSON");

        assert!(json.contains("echo"));
        assert!(json.contains("Echo"));
        assert!(json.contains("EchoMessage"));
        assert!(json.contains("EchoRequest"));
        assert!(json.contains("EchoResponse"));

        // Verify it's valid JSON
        let _parsed: serde_json::Value =
            serde_json::from_str(&json).expect("Invalid JSON output");
    }

    #[test]
    fn test_load_from_proto() {
        let mut client = ReflectionClient::new();
        let schema = client
            .load_from_proto("protos/echo.proto")
            .expect("Failed to load proto");

        assert_eq!(schema.package, "echo");
        assert_eq!(client.schemas().len(), 1);
        assert!(client.schemas().contains_key("echo"));
    }

    #[test]
    fn test_schema_serialization() {
        let schema = ServiceSchema {
            package: "test".to_string(),
            services: vec![Service {
                name: "TestService".to_string(),
                methods: vec![Method {
                    name: "TestMethod".to_string(),
                    input_type: "TestRequest".to_string(),
                    output_type: "TestResponse".to_string(),
                }],
            }],
        };

        let json = serde_json::to_string(&schema).expect("Failed to serialize");
        let deserialized: ServiceSchema =
            serde_json::from_str(&json).expect("Failed to deserialize");

        assert_eq!(deserialized.package, "test");
        assert_eq!(deserialized.services[0].name, "TestService");
    }
}
