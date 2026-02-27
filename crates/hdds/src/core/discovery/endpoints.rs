// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Shared endpoint registry for discovered participants
//! Connects discovery (SPDP) -> writer (DATA routing)

use crate::core::discovery::guid::GUID;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};

/// Registry of discovered remote endpoints (participants)
/// Updated by discovery FSM, consumed by writers
#[derive(Clone, Debug)]
pub struct EndpointRegistry {
    /// Map: participant GUID -> unicast endpoint (IP:port)
    endpoints: Arc<RwLock<HashMap<GUID, SocketAddr>>>,
}

impl EndpointRegistry {
    pub fn new() -> Self {
        Self {
            endpoints: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Register a remote participant's unicast endpoint (from SPDP)
    pub fn register(&self, guid: GUID, endpoint: SocketAddr) {
        if let Ok(mut map) = self.endpoints.write() {
            map.insert(guid, endpoint);
            log::debug!("[discovery] Registered endpoint: {} -> {}", guid, endpoint);
        }
    }

    /// Get unicast endpoint for a participant (for DATA routing)
    pub fn get(&self, guid: &GUID) -> Option<SocketAddr> {
        self.endpoints.read().ok()?.get(guid).copied()
    }

    /// Get any discovered endpoint (fallback for topic-based routing)
    pub fn get_any(&self) -> Option<SocketAddr> {
        self.endpoints.read().ok()?.values().next().copied()
    }

    /// Get a snapshot of all discovered endpoints (GUID + socket address).
    pub fn entries(&self) -> Vec<(GUID, SocketAddr)> {
        self.endpoints
            .read()
            .ok()
            .map(|map| map.iter().map(|(guid, addr)| (*guid, *addr)).collect())
            .unwrap_or_default()
    }

    /// Remove a participant (on lease expiry)
    pub fn remove(&self, guid: &GUID) {
        if let Ok(mut map) = self.endpoints.write() {
            map.remove(guid);
        }
    }

    /// Get count of discovered endpoints
    pub fn len(&self) -> usize {
        self.endpoints.read().ok().map_or(0, |m| m.len())
    }

    /// Check if registry is empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for EndpointRegistry {
    fn default() -> Self {
        Self::new()
    }
}
