// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Service registry for tracking active RPC services.
//!
//! Provides a thread-safe, global registry of service metadata
//! for introspection and discovery.

use std::sync::RwLock;

/// Metadata about an active RPC service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceInfo {
    /// Service name (e.g., "calculator")
    pub name: String,
    /// Request type name (e.g., "CalculatorRequest")
    pub request_type: String,
    /// Reply type name (e.g., "CalculatorReply")
    pub reply_type: String,
}

/// Global, thread-safe registry of active RPC services.
///
/// Services register themselves on creation and unregister on drop.
/// The registry can be queried to list all active services.
// @audit-ok: Global service registry for RPC introspection. Thread-safe via RwLock, no data races.
static SERVICE_REGISTRY: RwLock<Vec<ServiceInfo>> = RwLock::new(Vec::new());

/// Register a service in the global registry.
pub(crate) fn register_service(info: ServiceInfo) {
    if let Ok(mut registry) = SERVICE_REGISTRY.write() {
        // Avoid duplicates (same service name)
        if !registry.iter().any(|s| s.name == info.name) {
            log::debug!("RPC registry: registered service '{}'", info.name);
            registry.push(info);
        }
    }
}

/// Unregister a service from the global registry by name.
pub(crate) fn unregister_service(name: &str) {
    if let Ok(mut registry) = SERVICE_REGISTRY.write() {
        let before = registry.len();
        registry.retain(|s| s.name != name);
        if registry.len() < before {
            log::debug!("RPC registry: unregistered service '{}'", name);
        }
    }
}

/// List all currently registered services.
pub fn list_services() -> Vec<ServiceInfo> {
    SERVICE_REGISTRY
        .read()
        .map(|r| r.clone())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_and_list() {
        // Clean up from any prior test state
        unregister_service("test_svc_reg");

        let info = ServiceInfo {
            name: "test_svc_reg".to_string(),
            request_type: "Req".to_string(),
            reply_type: "Rep".to_string(),
        };
        register_service(info.clone());

        let services = list_services();
        assert!(services.iter().any(|s| s.name == "test_svc_reg"));

        unregister_service("test_svc_reg");
        let services = list_services();
        assert!(!services.iter().any(|s| s.name == "test_svc_reg"));
    }

    #[test]
    fn no_duplicates() {
        unregister_service("test_dup");

        let info = ServiceInfo {
            name: "test_dup".to_string(),
            request_type: "A".to_string(),
            reply_type: "B".to_string(),
        };
        register_service(info.clone());
        register_service(info);

        let count = list_services()
            .iter()
            .filter(|s| s.name == "test_dup")
            .count();
        assert_eq!(count, 1);

        unregister_service("test_dup");
    }
}
