// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Service registry for tracking active RPC services.
//!
//! Provides a thread-safe, global registry of service metadata
//! for process-local introspection. It does not perform remote discovery.

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

/// Process-local registrations, grouped by service name across domains.
// @audit-ok: Process-wide introspection is intentional; every access holds the RwLock and returns owned metadata.
static SERVICE_REGISTRY: RwLock<Vec<RegistryEntry>> = RwLock::new(Vec::new());

struct RegistryEntry {
    info: ServiceInfo,
    owners: usize,
}

/// Keeps a local registration alive for exactly one server's lifetime.
pub(crate) struct ServiceRegistration {
    name: String,
}

pub(crate) fn register_service(info: ServiceInfo) -> ServiceRegistration {
    let name = info.name.clone();
    let mut registry = SERVICE_REGISTRY.write().unwrap_or_else(|e| e.into_inner());
    if let Some(entry) = registry.iter_mut().find(|entry| entry.info.name == name) {
        entry.owners += 1;
    } else {
        registry.push(RegistryEntry { info, owners: 1 });
    }
    ServiceRegistration { name }
}

impl Drop for ServiceRegistration {
    fn drop(&mut self) {
        let mut registry = SERVICE_REGISTRY.write().unwrap_or_else(|e| e.into_inner());
        if let Some(index) = registry
            .iter()
            .position(|entry| entry.info.name == self.name)
        {
            registry[index].owners -= 1;
            if registry[index].owners == 0 {
                registry.remove(index);
            }
        }
    }
}

/// Snapshot of locally created server handles, grouped by name across domains.
///
/// Presence does not imply that a server is spinning or remotely reachable.
/// The registration ends when the underlying ServiceServer is dropped, including
/// when its owning spin future finishes or is cancelled.
pub fn list_services() -> Vec<ServiceInfo> {
    SERVICE_REGISTRY
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .iter()
        .map(|entry| entry.info.clone())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duplicate_registration_lives_until_last_owner_drops() {
        let info = ServiceInfo {
            name: "registry_duplicate_lifetime".into(),
            request_type: "RpcMessage".into(),
            reply_type: "RpcMessage".into(),
        };
        let first = register_service(info.clone());
        let second = register_service(info.clone());
        assert_eq!(
            list_services()
                .iter()
                .filter(|s| s.name == info.name)
                .count(),
            1
        );
        drop(first);
        assert!(list_services().contains(&info));
        drop(second);
        assert!(!list_services().contains(&info));
    }
}
