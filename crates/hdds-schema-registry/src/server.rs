// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

use std::sync::{Arc, RwLock};

use crate::compatibility::{check_compatibility, CompatibilityResult};
use crate::registry::{RegistryError, SchemaEntry, SchemaFormat, SchemaRegistry};

// ---------------------------------------------------------------------------
// SchemaRegistryApi
// ---------------------------------------------------------------------------

/// Thread-safe API facade for the schema registry.
///
/// This struct wraps `SchemaRegistry` behind an `Arc<RwLock<>>` to enable
/// safe concurrent access. It carries no HTTP dependency itself; the
/// `server` feature adds [`crate::http`], which serves exactly this API.
///
/// REST mapping (see [`crate::http::router`]):
///   GET  /schemas                        -> `list_schemas()`
///   POST /schemas                        -> `register_schema(name, content, format)`
///   GET  /schemas/{name}                 -> `get_schema(name)`
///   GET  /schemas/{name}/versions        -> `list_versions(name)`
///   GET  /schemas/{name}/versions/{n}    -> `get_version(name, n)`
///   POST /schemas/{name}/compatibility   -> `check_compatibility(name, content)`
pub struct SchemaRegistryApi {
    registry: Arc<RwLock<SchemaRegistry>>,
}

impl SchemaRegistryApi {
    /// Create a new API facade wrapping the given shared registry.
    pub fn new(registry: Arc<RwLock<SchemaRegistry>>) -> Self {
        SchemaRegistryApi { registry }
    }

    /// GET /schemas -- list all registered schema names.
    pub fn list_schemas(&self) -> Vec<String> {
        let reg = self.registry.read().expect("registry lock poisoned");
        reg.list_schemas()
    }

    /// GET /schemas/{name} -- return the latest version of the named schema.
    pub fn get_schema(&self, name: &str) -> Option<SchemaEntry> {
        let reg = self.registry.read().expect("registry lock poisoned");
        reg.get_latest(name).cloned()
    }

    /// POST /schemas -- register a new schema version.
    pub fn register_schema(
        &self,
        name: &str,
        content: &str,
        format: SchemaFormat,
    ) -> Result<u32, RegistryError> {
        let mut reg = self.registry.write().expect("registry lock poisoned");
        reg.register(name, content, format)
    }

    /// GET /schemas/{name}/versions/{version} -- one specific version.
    pub fn get_version(&self, name: &str, version: u32) -> Option<SchemaEntry> {
        let reg = self.registry.read().expect("registry lock poisoned");
        reg.get_version(name, version).cloned()
    }

    /// Register a version AND persist the registry, as one step.
    ///
    /// A registry that cannot durably record a schema must not claim it did.
    /// Registering first and persisting afterwards left the version live on
    /// every read route while the POST answered 500, so a retry of the same
    /// body got 409 and the caller had no way back. Here the whole thing
    /// happens under one write lock and a persistence failure rolls the
    /// registration back.
    pub fn register_schema_durable(
        &self,
        name: &str,
        content: &str,
        format: SchemaFormat,
        persistence: Option<&crate::persistence::FilePersistence>,
    ) -> Result<u32, RegistryError> {
        let mut reg = self.registry.write().expect("registry lock poisoned");
        let version = reg.register(name, content, format)?;
        if let Some(persistence) = persistence {
            if let Err(e) = persistence.save(&reg) {
                reg.remove_last_version(name, version);
                return Err(e);
            }
        }
        Ok(version)
    }

    /// Write the whole registry through a persistence backend.
    pub fn persist(
        &self,
        persistence: &crate::persistence::FilePersistence,
    ) -> Result<(), RegistryError> {
        let reg = self.registry.read().expect("registry lock poisoned");
        persistence.save(&reg)
    }

    /// The shared registry, for callers that need it directly (distribution).
    pub fn registry(&self) -> Arc<RwLock<SchemaRegistry>> {
        Arc::clone(&self.registry)
    }

    /// GET /schemas/{name}/versions -- list all version numbers.
    pub fn list_versions(&self, name: &str) -> Vec<u32> {
        let reg = self.registry.read().expect("registry lock poisoned");
        reg.list_versions(name)
    }

    /// GET /schemas/{name}/compatibility -- check compatibility of new
    /// content against the latest registered version.
    pub fn check_compatibility(&self, name: &str, content: &str) -> CompatibilityResult {
        let reg = self.registry.read().expect("registry lock poisoned");
        match reg.get_latest(name) {
            Some(latest) => check_compatibility(&latest.content, content, latest.format.clone()),
            None => CompatibilityResult {
                compatibility: crate::compatibility::Compatibility::Full,
                details: vec!["no previous version exists; trivially compatible".to_string()],
            },
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_api() -> SchemaRegistryApi {
        let reg = Arc::new(RwLock::new(SchemaRegistry::new()));
        SchemaRegistryApi::new(reg)
    }

    #[test]
    fn api_facade_delegates_to_registry() {
        let api = make_api();

        // Register two schemas.
        let v1 = api
            .register_schema("Sensor", "struct Sensor { long id; };", SchemaFormat::Idl4)
            .unwrap();
        assert_eq!(v1, 1);

        let v2 = api
            .register_schema(
                "Sensor",
                "struct Sensor { long id; string name; };",
                SchemaFormat::Idl4,
            )
            .unwrap();
        assert_eq!(v2, 2);

        // list_schemas
        let names = api.list_schemas();
        assert_eq!(names, vec!["Sensor"]);

        // get_schema returns latest
        let latest = api.get_schema("Sensor").unwrap();
        assert_eq!(latest.version, 2);

        // list_versions
        assert_eq!(api.list_versions("Sensor"), vec![1, 2]);

        // get_schema for unknown
        assert!(api.get_schema("Unknown").is_none());
    }

    #[test]
    fn api_compatibility_check() {
        let api = make_api();
        api.register_schema("S", "struct S { long x; };", SchemaFormat::Idl4)
            .unwrap();

        // Adding a field should be backward compatible.
        let result = api.check_compatibility("S", "struct S { long x; string y; };");
        assert_eq!(
            result.compatibility,
            crate::compatibility::Compatibility::Backward
        );
    }

    #[test]
    fn api_compatibility_no_previous_version() {
        let api = make_api();
        let result = api.check_compatibility("Missing", "struct M { long x; };");
        assert_eq!(
            result.compatibility,
            crate::compatibility::Compatibility::Full
        );
    }
}
