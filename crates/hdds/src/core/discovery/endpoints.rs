// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Shared endpoint registry for discovered participants
//! Connects discovery (SPDP) -> writer (DATA routing)

use crate::core::discovery::guid::GUID;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};

/// Registry of discovered remote endpoints (participants, readers, writers).
///
/// Three levels of locator resolution:
/// - **Participant-level** (from SPDP): `participant_guid -> SocketAddr` (default_unicast)
/// - **Reader-level** (from SEDP): `reader_guid -> SocketAddr` (per-reader unicast)
/// - **Writer-level** (from SEDP): `writer_guid -> SocketAddr` (per-writer unicast)
///
/// Writers send DATA to each matched reader's SEDP-announced locator.
/// Readers send user ACKNACKs to each matched writer's SEDP-announced locator
/// when the peer vendor requires them on its user-data port.
/// Falls back to the participant's SPDP default_unicast if no endpoint locator is known.
#[derive(Clone, Debug)]
pub struct EndpointRegistry {
    /// Map: participant GUID -> unicast endpoint (IP:port) from SPDP default_unicast_locator
    endpoints: Arc<RwLock<HashMap<GUID, SocketAddr>>>,
    /// Map: reader endpoint GUID -> unicast endpoint (IP:port) from SEDP PID_UNICAST_LOCATOR
    reader_locators: Arc<RwLock<HashMap<GUID, SocketAddr>>>,
    /// Map: writer endpoint GUID -> unicast endpoint (IP:port) from SEDP PID_UNICAST_LOCATOR
    writer_locators: Arc<RwLock<HashMap<GUID, SocketAddr>>>,
    /// Cached `endpoints.len()`, updated under the write guard at every
    /// mutation. Shared across clones (`Arc`) so the writer hot path can
    /// answer "any remote peers?" with a single atomic load instead of a
    /// RwLock read + full-map collect.
    endpoint_count: Arc<AtomicUsize>,
}

impl EndpointRegistry {
    pub fn new() -> Self {
        Self {
            endpoints: Arc::new(RwLock::new(HashMap::new())),
            reader_locators: Arc::new(RwLock::new(HashMap::new())),
            writer_locators: Arc::new(RwLock::new(HashMap::new())),
            endpoint_count: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Register a remote participant's unicast endpoint (from SPDP)
    pub fn register(&self, guid: GUID, endpoint: SocketAddr) {
        let mut map = self.endpoints.write().unwrap_or_else(|e| e.into_inner());
        map.insert(guid, endpoint);
        self.endpoint_count.store(map.len(), Ordering::Release);
        log::debug!("[discovery] Registered endpoint: {} -> {}", guid, endpoint);
    }

    /// Register a remote reader's unicast locator (from SEDP).
    ///
    /// This is the port the reader actually listens on for user DATA.
    /// May differ from the participant's SPDP default_unicast_locator
    /// (a reader endpoint may announce a port of its own, ephemeral or not).
    pub fn register_reader_locator(&self, reader_guid: GUID, locator: SocketAddr) {
        let mut map = self
            .reader_locators
            .write()
            .unwrap_or_else(|e| e.into_inner());
        map.insert(reader_guid, locator);
        log::debug!(
            "[discovery] Registered reader locator: {} -> {}",
            reader_guid,
            locator
        );
    }

    /// Register a remote writer's unicast locator (from SEDP).
    ///
    /// This is the port the writer's participant actually listens on for
    /// user-session traffic (user ACKNACK/NACK_FRAG destinations). May differ
    /// from both the participant's metatraffic port and the default port
    /// mapping (a writer may announce a dedicated user port of its own).
    pub fn register_writer_locator(&self, writer_guid: GUID, locator: SocketAddr) {
        let mut map = self
            .writer_locators
            .write()
            .unwrap_or_else(|e| e.into_inner());
        map.insert(writer_guid, locator);
        log::debug!(
            "[discovery] Registered writer locator: {} -> {}",
            writer_guid,
            locator
        );
    }

    /// Get the SEDP-announced unicast locator for a remote writer, if known.
    ///
    /// Used to aim user ACKNACKs at the port the peer's user-data stack
    /// actually reads, for vendors whose discovery receiver drops user
    /// control messages arriving on the metatraffic port.
    pub fn get_writer_locator(&self, writer_guid: &GUID) -> Option<SocketAddr> {
        self.writer_locators
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(writer_guid)
            .copied()
    }

    /// Get the best unicast address to send user DATA for a given reader.
    ///
    /// Prefers the reader's own SEDP locator (per-reader port) over the
    /// participant's SPDP default_unicast (which may be a different port).
    pub fn get_reader_locator(&self, reader_guid: &GUID) -> Option<SocketAddr> {
        self.reader_locators
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(reader_guid)
            .copied()
    }

    /// Get unicast endpoint for a participant (for DATA routing)
    pub fn get(&self, guid: &GUID) -> Option<SocketAddr> {
        self.endpoints
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(guid)
            .copied()
    }

    /// Get any discovered endpoint (fallback for topic-based routing)
    pub fn get_any(&self) -> Option<SocketAddr> {
        self.endpoints
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .next()
            .copied()
    }

    /// Get a snapshot of all discovered endpoints (GUID + socket address).
    pub fn entries(&self) -> Vec<(GUID, SocketAddr)> {
        self.endpoints
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .map(|(guid, addr)| (*guid, *addr))
            .collect()
    }

    /// Remove a participant and all its endpoint locators (on lease expiry).
    pub fn remove(&self, guid: &GUID) {
        {
            let mut map = self.endpoints.write().unwrap_or_else(|e| e.into_inner());
            map.remove(guid);
            self.endpoint_count.store(map.len(), Ordering::Release);
        }
        // Remove all endpoint locators belonging to this participant (same GUID prefix)
        let prefix = &guid.as_bytes()[..12];
        self.remove_endpoint_locators(|endpoint_guid| &endpoint_guid.as_bytes()[..12] == prefix);
    }

    /// Remove the SEDP-announced locator of every reader and writer whose
    /// GUID `is_gone` selects. Shared by participant removal (a whole prefix)
    /// and single-endpoint removal (one GUID).
    pub(crate) fn remove_endpoint_locators(&self, is_gone: impl Fn(&GUID) -> bool) {
        self.reader_locators
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|reader_guid, _| !is_gone(reader_guid));
        self.writer_locators
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|writer_guid, _| !is_gone(writer_guid));
    }

    /// Lock-free count of discovered endpoints (cached at mutation time).
    ///
    /// Hot-path companion to [`Self::entries`]: lets callers skip the
    /// RwLock read + map collect entirely when the registry is empty.
    pub fn endpoint_count(&self) -> usize {
        self.endpoint_count.load(Ordering::Acquire)
    }

    /// Get count of discovered endpoints
    pub fn len(&self) -> usize {
        self.endpoints
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .len()
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
