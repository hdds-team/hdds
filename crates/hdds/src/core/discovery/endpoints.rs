// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Shared endpoint registry for discovered participants
//! Connects discovery (SPDP) -> writer (DATA routing)

use crate::core::discovery::guid::GUID;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};

/// Registry of discovered remote endpoints (participants and readers).
///
/// Two levels of locator resolution:
/// - **Participant-level** (from SPDP): `participant_guid -> SocketAddr` (default_unicast)
/// - **Reader-level** (from SEDP): `reader_guid -> SocketAddr` (per-reader unicast)
///
/// Writers send DATA to each matched reader's SEDP-announced locator.
/// Falls back to the participant's SPDP default_unicast if no reader locator is known.
#[derive(Clone, Debug)]
pub struct EndpointRegistry {
    /// Map: participant GUID -> unicast endpoint (IP:port) from SPDP default_unicast_locator
    endpoints: Arc<RwLock<HashMap<GUID, SocketAddr>>>,
    /// Map: reader endpoint GUID -> unicast endpoint (IP:port) from SEDP PID_UNICAST_LOCATOR
    reader_locators: Arc<RwLock<HashMap<GUID, SocketAddr>>>,
    /// Map: writer endpoint GUID -> unicast endpoint (IP:port) from SEDP PID_UNICAST_LOCATOR.
    /// Readers send user-traffic ACKNACKs here (never to the metatraffic port).
    writer_locators: Arc<RwLock<HashMap<GUID, SocketAddr>>>,
}

impl EndpointRegistry {
    pub fn new() -> Self {
        Self {
            endpoints: Arc::new(RwLock::new(HashMap::new())),
            reader_locators: Arc::new(RwLock::new(HashMap::new())),
            writer_locators: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Register a remote participant's unicast endpoint (from SPDP)
    pub fn register(&self, guid: GUID, endpoint: SocketAddr) {
        if let Ok(mut map) = self.endpoints.write() {
            map.insert(guid, endpoint);
            log::debug!("[discovery] Registered endpoint: {} -> {}", guid, endpoint);
        }
    }

    /// Register a remote reader's unicast locator (from SEDP).
    ///
    /// This is the port the reader actually listens on for user DATA.
    /// May differ from the participant's SPDP default_unicast_locator
    /// (e.g. FastDDS uses ephemeral ports for reader endpoints).
    pub fn register_reader_locator(&self, reader_guid: GUID, locator: SocketAddr) {
        if let Ok(mut map) = self.reader_locators.write() {
            map.insert(reader_guid, locator);
            log::debug!(
                "[discovery] Registered reader locator: {} -> {}",
                reader_guid,
                locator
            );
        }
    }

    /// Get the best unicast address to send user DATA for a given reader.
    ///
    /// Prefers the reader's own SEDP locator (per-reader port) over the
    /// participant's SPDP default_unicast (which may be a different port).
    pub fn get_reader_locator(&self, reader_guid: &GUID) -> Option<SocketAddr> {
        if let Some(addr) = self.reader_locators.read().ok()?.get(reader_guid).copied() {
            return Some(addr);
        }
        None
    }

    /// Register a remote writer's unicast locator (from SEDP publication data).
    ///
    /// This is the port the writer listens on for user traffic (ACKNACK/NACK_FRAG);
    /// it is NOT the participant's metatraffic port.
    pub fn register_writer_locator(&self, writer_guid: GUID, locator: SocketAddr) {
        if let Ok(mut map) = self.writer_locators.write() {
            map.insert(writer_guid, locator);
            log::debug!(
                "[discovery] Registered writer locator: {} -> {}",
                writer_guid,
                locator
            );
        }
    }

    /// Get the writer's SEDP-announced user-traffic locator (ACKNACK destination).
    pub fn get_writer_locator(&self, writer_guid: &GUID) -> Option<SocketAddr> {
        self.writer_locators.read().ok()?.get(writer_guid).copied()
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

    /// Remove a participant and all its reader locators (on lease expiry).
    pub fn remove(&self, guid: &GUID) {
        if let Ok(mut map) = self.endpoints.write() {
            map.remove(guid);
        }
        // Remove all endpoint locators belonging to this participant (same GUID prefix)
        let prefix = &guid.as_bytes()[..12];
        if let Ok(mut map) = self.reader_locators.write() {
            map.retain(|reader_guid, _| &reader_guid.as_bytes()[..12] != prefix);
        }
        if let Ok(mut map) = self.writer_locators.write() {
            map.retain(|writer_guid, _| &writer_guid.as_bytes()[..12] != prefix);
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
