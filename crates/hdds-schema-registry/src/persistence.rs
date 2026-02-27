// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use crate::registry::{RegistryError, SchemaEntry, SchemaRegistry};

// ---------------------------------------------------------------------------
// FilePersistence
// ---------------------------------------------------------------------------

/// File-based persistence for `SchemaRegistry`.
///
/// Stores each schema version as a JSON file at:
///   `{directory}/{schema_name}/v{version}.json`
pub struct FilePersistence {
    directory: PathBuf,
}

impl FilePersistence {
    /// Create a new `FilePersistence` rooted at the given directory.
    ///
    /// The directory is created if it does not exist.
    pub fn new(directory: PathBuf) -> Result<Self, RegistryError> {
        if !directory.exists() {
            fs::create_dir_all(&directory).map_err(|e| {
                RegistryError::IoError(format!(
                    "failed to create directory {}: {}",
                    directory.display(),
                    e
                ))
            })?;
        }
        Ok(FilePersistence { directory })
    }

    /// Persist the entire registry to disk.
    ///
    /// Each schema name gets its own subdirectory, and each version is stored
    /// as `v{n}.json`.  Existing files are overwritten.
    pub fn save(&self, registry: &SchemaRegistry) -> Result<(), RegistryError> {
        for (name, versions) in registry.inner() {
            let schema_dir = self.directory.join(sanitize_name(name));
            if !schema_dir.exists() {
                fs::create_dir_all(&schema_dir).map_err(|e| {
                    RegistryError::IoError(format!(
                        "failed to create schema dir {}: {}",
                        schema_dir.display(),
                        e
                    ))
                })?;
            }

            for entry in versions {
                let filename = format!("v{}.json", entry.version);
                let path = schema_dir.join(filename);
                let json = serde_json::to_string_pretty(entry).map_err(|e| {
                    RegistryError::IoError(format!("serialization error: {}", e))
                })?;
                fs::write(&path, json).map_err(|e| {
                    RegistryError::IoError(format!(
                        "failed to write {}: {}",
                        path.display(),
                        e
                    ))
                })?;
            }
        }
        Ok(())
    }

    /// Load a registry from disk.
    ///
    /// Scans all subdirectories of the root for `v*.json` files and
    /// reconstructs the registry.
    pub fn load(&self) -> Result<SchemaRegistry, RegistryError> {
        let mut schemas: HashMap<String, Vec<SchemaEntry>> = HashMap::new();

        if !self.directory.exists() {
            return Ok(SchemaRegistry::new());
        }

        let entries = fs::read_dir(&self.directory).map_err(|e| {
            RegistryError::IoError(format!(
                "failed to read directory {}: {}",
                self.directory.display(),
                e
            ))
        })?;

        for dir_entry in entries {
            let dir_entry = dir_entry.map_err(|e| {
                RegistryError::IoError(format!("directory entry error: {}", e))
            })?;

            let path = dir_entry.path();
            if !path.is_dir() {
                continue;
            }

            let mut versions: Vec<SchemaEntry> = Vec::new();

            let version_files = fs::read_dir(&path).map_err(|e| {
                RegistryError::IoError(format!(
                    "failed to read schema dir {}: {}",
                    path.display(),
                    e
                ))
            })?;

            for vf in version_files {
                let vf = vf.map_err(|e| {
                    RegistryError::IoError(format!("version file entry error: {}", e))
                })?;
                let vpath = vf.path();

                let fname = match vpath.file_name().and_then(|n| n.to_str()) {
                    Some(n) => n.to_string(),
                    None => continue,
                };

                if !fname.starts_with('v') || !fname.ends_with(".json") {
                    continue;
                }

                let json = fs::read_to_string(&vpath).map_err(|e| {
                    RegistryError::IoError(format!(
                        "failed to read {}: {}",
                        vpath.display(),
                        e
                    ))
                })?;

                let entry: SchemaEntry = serde_json::from_str(&json).map_err(|e| {
                    RegistryError::IoError(format!(
                        "failed to deserialize {}: {}",
                        vpath.display(),
                        e
                    ))
                })?;

                versions.push(entry);
            }

            // Sort by version number to maintain ordering.
            versions.sort_by_key(|e| e.version);

            if !versions.is_empty() {
                // Use the schema name from the entries themselves (not dir name).
                let name = versions[0].name.clone();
                schemas.insert(name, versions);
            }
        }

        Ok(SchemaRegistry::from_raw(schemas))
    }
}

/// Sanitize a schema name for use as a directory name.
///
/// Replaces characters that are problematic in filesystem paths with
/// underscores.
fn sanitize_name(name: &str) -> String {
    name.chars()
        .map(|c| match c {
            '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|' => '_',
            _ => c,
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::SchemaFormat;

    #[test]
    fn save_and_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let persistence = FilePersistence::new(dir.path().to_path_buf()).unwrap();

        let mut reg = SchemaRegistry::new();
        reg.register("Sensor", "struct Sensor { long id; };", SchemaFormat::Idl4)
            .unwrap();
        reg.register(
            "Sensor",
            "struct Sensor { long id; string name; };",
            SchemaFormat::Idl4,
        )
        .unwrap();
        reg.register("Motor", r#"{"rpm": "uint32"}"#, SchemaFormat::Json)
            .unwrap();

        persistence.save(&reg).unwrap();

        let loaded = persistence.load().unwrap();

        assert_eq!(loaded.schema_count(), 2);
        assert_eq!(loaded.list_versions("Sensor"), vec![1, 2]);
        assert_eq!(loaded.list_versions("Motor"), vec![1]);

        let sensor_v2 = loaded.get_version("Sensor", 2).unwrap();
        assert_eq!(sensor_v2.content, "struct Sensor { long id; string name; };");
        assert_eq!(sensor_v2.format, SchemaFormat::Idl4);
    }

    #[test]
    fn directory_creation() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("deep").join("nested").join("registry");
        assert!(!nested.exists());

        let _persistence = FilePersistence::new(nested.clone()).unwrap();
        assert!(nested.exists());
    }

    #[test]
    fn load_empty_directory() {
        let dir = tempfile::tempdir().unwrap();
        let persistence = FilePersistence::new(dir.path().to_path_buf()).unwrap();
        let reg = persistence.load().unwrap();
        assert_eq!(reg.schema_count(), 0);
    }

    #[test]
    fn sanitize_name_replaces_special_chars() {
        assert_eq!(sanitize_name("sensor_msgs::PointCloud2"), "sensor_msgs__PointCloud2");
        assert_eq!(sanitize_name("a/b\\c"), "a_b_c");
    }
}
