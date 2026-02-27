// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

use std::collections::HashMap;
use std::collections::hash_map::DefaultHasher;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::time::SystemTime;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// SchemaFormat
// ---------------------------------------------------------------------------

/// Format of a registered schema definition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SchemaFormat {
    /// OMG IDL v4 text.
    Idl4,
    /// JSON-based schema description.
    Json,
    /// XTypes type hash (opaque identifier).
    XTypesHash,
}

// ---------------------------------------------------------------------------
// SchemaEntry
// ---------------------------------------------------------------------------

/// A single versioned schema stored in the registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchemaEntry {
    /// Fully-qualified type name (e.g. "sensor_msgs::PointCloud2").
    pub name: String,
    /// Monotonically increasing version number starting at 1.
    pub version: u32,
    /// Source format.
    pub format: SchemaFormat,
    /// Raw schema content (IDL text, JSON, ...).
    pub content: String,
    /// 64-bit hash of `content` for fast equality checks.
    pub hash: u64,
    /// Timestamp of registration.
    pub registered_at: SystemTime,
}

// ---------------------------------------------------------------------------
// RegistryError
// ---------------------------------------------------------------------------

/// Errors produced by the schema registry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistryError {
    /// The schema content is empty.
    EmptyContent,
    /// A schema with the exact same hash already exists at that version.
    DuplicateContent,
    /// Generic I/O or persistence error.
    IoError(String),
    /// Schema with the given name was not found.
    NotFound(String),
}

impl fmt::Display for RegistryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RegistryError::EmptyContent => write!(f, "schema content is empty"),
            RegistryError::DuplicateContent => {
                write!(f, "identical schema content already registered")
            }
            RegistryError::IoError(msg) => write!(f, "I/O error: {}", msg),
            RegistryError::NotFound(name) => write!(f, "schema not found: {}", name),
        }
    }
}

impl std::error::Error for RegistryError {}

// ---------------------------------------------------------------------------
// SchemaRegistry
// ---------------------------------------------------------------------------

/// In-memory store of versioned schemas keyed by type name.
pub struct SchemaRegistry {
    /// Map from schema name to an ordered list of versions (index 0 = v1).
    schemas: HashMap<String, Vec<SchemaEntry>>,
}

impl SchemaRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        SchemaRegistry {
            schemas: HashMap::new(),
        }
    }

    /// Reconstruct a registry from a raw map (used by persistence layer).
    pub(crate) fn from_raw(schemas: HashMap<String, Vec<SchemaEntry>>) -> Self {
        SchemaRegistry { schemas }
    }

    /// Expose the inner map (used by persistence layer).
    pub(crate) fn inner(&self) -> &HashMap<String, Vec<SchemaEntry>> {
        &self.schemas
    }

    /// Register a new schema version.
    ///
    /// Returns the assigned version number on success.  If the exact same
    /// content already exists for this name (same hash), returns
    /// `DuplicateContent`.
    pub fn register(
        &mut self,
        name: &str,
        content: &str,
        format: SchemaFormat,
    ) -> Result<u32, RegistryError> {
        if content.is_empty() {
            return Err(RegistryError::EmptyContent);
        }

        let hash = Self::compute_hash(content);

        // Check for duplicate content in existing versions.
        if let Some(versions) = self.schemas.get(name) {
            for entry in versions {
                if entry.hash == hash && entry.content == content {
                    return Err(RegistryError::DuplicateContent);
                }
            }
        }

        let versions = self.schemas.entry(name.to_string()).or_default();
        let version = (versions.len() as u32) + 1;

        let entry = SchemaEntry {
            name: name.to_string(),
            version,
            format,
            content: content.to_string(),
            hash,
            registered_at: SystemTime::now(),
        };

        versions.push(entry);
        Ok(version)
    }

    /// Return the latest version of a schema, or `None` if not found.
    pub fn get_latest(&self, name: &str) -> Option<&SchemaEntry> {
        self.schemas.get(name).and_then(|v| v.last())
    }

    /// Return a specific version of a schema (1-indexed).
    pub fn get_version(&self, name: &str, version: u32) -> Option<&SchemaEntry> {
        if version == 0 {
            return None;
        }
        self.schemas
            .get(name)
            .and_then(|v| v.get((version - 1) as usize))
    }

    /// List all registered schema names (sorted for determinism).
    pub fn list_schemas(&self) -> Vec<String> {
        let mut names: Vec<String> = self.schemas.keys().cloned().collect();
        names.sort();
        names
    }

    /// List all version numbers for a given schema name.
    pub fn list_versions(&self, name: &str) -> Vec<u32> {
        match self.schemas.get(name) {
            Some(versions) => versions.iter().map(|e| e.version).collect(),
            None => Vec::new(),
        }
    }

    /// Total number of distinct schema names.
    pub fn schema_count(&self) -> usize {
        self.schemas.len()
    }

    /// Compute a deterministic 64-bit hash for the given content.
    pub(crate) fn compute_hash(content: &str) -> u64 {
        let mut hasher = DefaultHasher::new();
        content.hash(&mut hasher);
        hasher.finish()
    }
}

impl Default for SchemaRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_schema() {
        let mut reg = SchemaRegistry::new();
        let v = reg
            .register("Sensor", "struct Sensor { long id; };", SchemaFormat::Idl4)
            .unwrap();
        assert_eq!(v, 1);
        assert_eq!(reg.schema_count(), 1);
    }

    #[test]
    fn register_same_name_increments_version() {
        let mut reg = SchemaRegistry::new();
        let v1 = reg
            .register("Sensor", "struct Sensor { long id; };", SchemaFormat::Idl4)
            .unwrap();
        let v2 = reg
            .register(
                "Sensor",
                "struct Sensor { long id; string name; };",
                SchemaFormat::Idl4,
            )
            .unwrap();
        assert_eq!(v1, 1);
        assert_eq!(v2, 2);
    }

    #[test]
    fn get_latest() {
        let mut reg = SchemaRegistry::new();
        reg.register("Sensor", "struct Sensor { long id; };", SchemaFormat::Idl4)
            .unwrap();
        reg.register(
            "Sensor",
            "struct Sensor { long id; string name; };",
            SchemaFormat::Idl4,
        )
        .unwrap();

        let latest = reg.get_latest("Sensor").unwrap();
        assert_eq!(latest.version, 2);
        assert!(latest.content.contains("string name"));
    }

    #[test]
    fn get_specific_version() {
        let mut reg = SchemaRegistry::new();
        reg.register("Sensor", "struct Sensor { long id; };", SchemaFormat::Idl4)
            .unwrap();
        reg.register(
            "Sensor",
            "struct Sensor { long id; string name; };",
            SchemaFormat::Idl4,
        )
        .unwrap();

        let v1 = reg.get_version("Sensor", 1).unwrap();
        assert_eq!(v1.version, 1);
        assert!(!v1.content.contains("string name"));

        let v2 = reg.get_version("Sensor", 2).unwrap();
        assert_eq!(v2.version, 2);
    }

    #[test]
    fn list_schemas() {
        let mut reg = SchemaRegistry::new();
        reg.register("Zebra", "struct Zebra {};", SchemaFormat::Idl4)
            .unwrap();
        reg.register("Alpha", "struct Alpha {};", SchemaFormat::Idl4)
            .unwrap();

        let names = reg.list_schemas();
        assert_eq!(names, vec!["Alpha", "Zebra"]);
    }

    #[test]
    fn list_versions() {
        let mut reg = SchemaRegistry::new();
        reg.register("S", "v1", SchemaFormat::Json).unwrap();
        reg.register("S", "v2", SchemaFormat::Json).unwrap();
        reg.register("S", "v3", SchemaFormat::Json).unwrap();

        assert_eq!(reg.list_versions("S"), vec![1, 2, 3]);
        assert!(reg.list_versions("Missing").is_empty());
    }

    #[test]
    fn schema_not_found_returns_none() {
        let reg = SchemaRegistry::new();
        assert!(reg.get_latest("DoesNotExist").is_none());
        assert!(reg.get_version("DoesNotExist", 1).is_none());
    }

    #[test]
    fn duplicate_content_rejected() {
        let mut reg = SchemaRegistry::new();
        reg.register("S", "struct S { long x; };", SchemaFormat::Idl4)
            .unwrap();
        let err = reg
            .register("S", "struct S { long x; };", SchemaFormat::Idl4)
            .unwrap_err();
        assert_eq!(err, RegistryError::DuplicateContent);
    }

    #[test]
    fn empty_content_rejected() {
        let mut reg = SchemaRegistry::new();
        let err = reg.register("S", "", SchemaFormat::Idl4).unwrap_err();
        assert_eq!(err, RegistryError::EmptyContent);
    }

    #[test]
    fn schema_hash_uniqueness() {
        let hash_a = SchemaRegistry::compute_hash("struct A { long x; };");
        let hash_b = SchemaRegistry::compute_hash("struct B { long x; };");
        assert_ne!(hash_a, hash_b, "different content should yield different hashes");

        let hash_a2 = SchemaRegistry::compute_hash("struct A { long x; };");
        assert_eq!(hash_a, hash_a2, "same content should yield the same hash");
    }
}
