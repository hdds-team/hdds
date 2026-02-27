// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Stream mapping for LBW transport.
//!
//! Each stream_id maps to a (topic_hash, type_hash) pair.
//! TX and RX mappings are tracked separately since the stream_id is
//! "defined by the sender" - each side allocates its own IDs.
//!
//! # Reliable Mapping Protocol
//!
//! Mappings are exchanged via CONTROL stream messages:
//! - **MAP_ADD**: Announce a new stream mapping (sender -> receiver)
//! - **MAP_ACK**: Acknowledge a mapping was received
//! - **MAP_REQ**: Request mapping info for an unknown stream_id
//!
//! The mapping protocol uses "sticky until ack":
//! - MAP_ADD is retransmitted until MAP_ACK is received
//! - Unknown stream_id triggers MAP_REQ and drops the record
//!
//! # Usage
//!
//! ```ignore
//! let mut mapper = StreamMapper::new(MapperConfig::default());
//!
//! // Register a local stream (TX side)
//! let stream_id = mapper.add_tx_stream(topic_hash, type_hash, Priority::P1, flags);
//!
//! // Poll for MAP_ADD messages to send
//! while let Some(msg) = mapper.poll_pending_map_add() {
//!     send_control_message(&msg);
//! }
//!
//! // On receiving MAP_ACK
//! mapper.on_map_ack(epoch, stream_id);
//!
//! // On receiving MAP_ADD from remote
//! mapper.on_map_add(epoch, stream_id, topic_hash, type_hash, flags);
//! send_map_ack(epoch, stream_id);
//!
//! // Lookup RX stream
//! if let Some(info) = mapper.get_rx_stream(stream_id) {
//!     // Process record...
//! }
//! ```

use std::collections::HashMap;
use std::time::{Duration, Instant};

use super::control::{MapAck, MapAdd, MapReq};
use super::record::Priority;

/// Stream mapping configuration.
#[derive(Debug, Clone)]
pub struct MapperConfig {
    /// Maximum number of TX streams.
    pub max_tx_streams: u8,
    /// Maximum number of RX streams.
    pub max_rx_streams: u8,
    /// MAP_ADD retransmit interval.
    pub map_add_interval: Duration,
    /// Maximum MAP_ADD retries before giving up.
    pub map_add_max_retries: u32,
    /// Starting epoch.
    pub initial_epoch: u16,
}

impl Default for MapperConfig {
    fn default() -> Self {
        Self {
            max_tx_streams: 64,
            max_rx_streams: 64,
            map_add_interval: Duration::from_millis(500),
            map_add_max_retries: 10,
            initial_epoch: 1,
        }
    }
}

/// Stream info for TX side (our streams).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxStreamInfo {
    /// Stream ID (1-255, 0 is reserved for CONTROL).
    pub stream_id: u8,
    /// Topic hash.
    pub topic_hash: u64,
    /// Type hash.
    pub type_hash: u64,
    /// Priority level.
    pub priority: Priority,
    /// Stream flags (delta_enabled, reliable, etc.).
    pub flags: u8,
    /// Whether the remote has ACKed this mapping.
    pub acked: bool,
    /// Whether the mapping has failed (exceeded max retries).
    pub failed: bool,
    /// Last MAP_ADD send time.
    pub last_sent: Option<Instant>,
    /// Number of MAP_ADD retries.
    pub retries: u32,
    /// Epoch when this mapping was created.
    pub epoch: u16,
}

/// Stream info for RX side (remote's streams).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RxStreamInfo {
    /// Stream ID.
    pub stream_id: u8,
    /// Topic hash.
    pub topic_hash: u64,
    /// Type hash.
    pub type_hash: u64,
    /// Priority level.
    pub priority: Priority,
    /// Stream flags.
    pub flags: u8,
    /// Epoch when this mapping was received.
    pub epoch: u16,
}

/// Stream flags for MapAdd.
pub mod stream_flags {
    /// Stream supports delta encoding.
    pub const DELTA_ENABLED: u8 = 0x01;
    /// Stream is reliable (P0).
    pub const RELIABLE: u8 = 0x02;
    /// Stream is compressed.
    pub const COMPRESSED: u8 = 0x04;
}

/// Mapping statistics.
#[derive(Debug, Default, Clone)]
pub struct MapperStats {
    /// Total MAP_ADD sent.
    pub map_adds_sent: u64,
    /// Total MAP_ACK sent.
    pub map_acks_sent: u64,
    /// Total MAP_REQ sent.
    pub map_reqs_sent: u64,
    /// Total MAP_ADD received.
    pub map_adds_received: u64,
    /// Total MAP_ACK received.
    pub map_acks_received: u64,
    /// Total MAP_REQ received.
    pub map_reqs_received: u64,
    /// Records dropped due to unknown mapping.
    pub unknown_mapping_drops: u64,
    /// Mappings that exceeded max retries.
    pub mapping_failures: u64,
}

/// Stream mapper for LBW transport.
pub struct StreamMapper {
    /// Configuration.
    config: MapperConfig,
    /// Current epoch.
    epoch: u16,
    /// TX stream mappings (our streams).
    tx_streams: HashMap<u8, TxStreamInfo>,
    /// RX stream mappings (remote's streams).
    rx_streams: HashMap<u8, RxStreamInfo>,
    /// Next TX stream ID to allocate.
    next_tx_id: u8,
    /// Pending MAP_REQ stream IDs.
    pending_map_reqs: Vec<u8>,
    /// Statistics.
    stats: MapperStats,
}

impl StreamMapper {
    /// Create a new stream mapper.
    pub fn new(config: MapperConfig) -> Self {
        Self {
            epoch: config.initial_epoch,
            config,
            tx_streams: HashMap::new(),
            rx_streams: HashMap::new(),
            next_tx_id: 1, // 0 is reserved for CONTROL
            pending_map_reqs: Vec::new(),
            stats: MapperStats::default(),
        }
    }

    /// Get current epoch.
    #[inline]
    pub fn epoch(&self) -> u16 {
        self.epoch
    }

    /// Increment epoch.
    pub fn bump_epoch(&mut self) {
        self.epoch = self.epoch.wrapping_add(1);
    }

    /// Get statistics.
    pub fn stats(&self) -> &MapperStats {
        &self.stats
    }

    /// Reset statistics.
    pub fn reset_stats(&mut self) {
        self.stats = MapperStats::default();
    }

    // ========================================================================
    // TX Stream Management (our streams)
    // ========================================================================

    /// Add a TX stream and return its stream_id.
    ///
    /// Returns `None` if no more stream IDs are available.
    pub fn add_tx_stream(
        &mut self,
        topic_hash: u64,
        type_hash: u64,
        priority: Priority,
        flags: u8,
    ) -> Option<u8> {
        // Check if we've hit the max
        if self.tx_streams.len() >= self.config.max_tx_streams as usize {
            return None;
        }

        // Find next available stream ID
        let mut id = self.next_tx_id;
        let max = self.config.max_tx_streams;

        for _ in 0..max {
            if !self.tx_streams.contains_key(&id) {
                let info = TxStreamInfo {
                    stream_id: id,
                    topic_hash,
                    type_hash,
                    priority,
                    flags,
                    acked: false,
                    failed: false,
                    last_sent: None,
                    retries: 0,
                    epoch: self.epoch,
                };
                self.tx_streams.insert(id, info);
                self.next_tx_id = id.wrapping_add(1).max(1); // Skip 0
                return Some(id);
            }
            id = id.wrapping_add(1).max(1);
        }

        None // No available IDs
    }

    /// Remove a TX stream.
    pub fn remove_tx_stream(&mut self, stream_id: u8) -> Option<TxStreamInfo> {
        self.tx_streams.remove(&stream_id)
    }

    /// Get TX stream info.
    pub fn get_tx_stream(&self, stream_id: u8) -> Option<&TxStreamInfo> {
        self.tx_streams.get(&stream_id)
    }

    /// Check if TX stream is acked.
    pub fn is_tx_stream_acked(&self, stream_id: u8) -> bool {
        self.tx_streams
            .get(&stream_id)
            .map(|s| s.acked)
            .unwrap_or(false)
    }

    /// Get all TX streams.
    pub fn tx_streams(&self) -> impl Iterator<Item = &TxStreamInfo> {
        self.tx_streams.values()
    }

    /// Poll for a pending MAP_ADD message to send.
    ///
    /// Returns a MAP_ADD for unacked streams that need (re)transmission.
    pub fn poll_pending_map_add(&mut self) -> Option<MapAdd> {
        let now = Instant::now();

        for info in self.tx_streams.values_mut() {
            if info.acked || info.failed {
                continue;
            }

            let needs_send = match info.last_sent {
                None => true,
                Some(last) => now.duration_since(last) >= self.config.map_add_interval,
            };

            if needs_send {
                if info.retries >= self.config.map_add_max_retries {
                    info.failed = true;
                    self.stats.mapping_failures += 1;
                    continue;
                }

                info.last_sent = Some(now);
                info.retries += 1;
                self.stats.map_adds_sent += 1;

                return Some(MapAdd {
                    epoch: info.epoch,
                    stream_id: info.stream_id,
                    topic_hash: info.topic_hash,
                    type_hash: info.type_hash,
                    stream_flags: info.flags,
                });
            }
        }

        None
    }

    /// Handle received MAP_ACK.
    pub fn on_map_ack(&mut self, ack: &MapAck) {
        self.stats.map_acks_received += 1;

        if let Some(info) = self.tx_streams.get_mut(&ack.stream_id) {
            if info.epoch == ack.epoch {
                info.acked = true;
            }
        }
    }

    // ========================================================================
    // RX Stream Management (remote's streams)
    // ========================================================================

    /// Handle received MAP_ADD.
    ///
    /// Returns `true` if the mapping was new or updated.
    pub fn on_map_add(&mut self, add: &MapAdd) -> bool {
        self.stats.map_adds_received += 1;

        // Check if we already have this mapping
        if let Some(existing) = self.rx_streams.get(&add.stream_id) {
            if existing.epoch == add.epoch {
                return false; // Already have this exact mapping
            }
        }

        // Add/update mapping
        let info = RxStreamInfo {
            stream_id: add.stream_id,
            topic_hash: add.topic_hash,
            type_hash: add.type_hash,
            priority: Priority::from_flags(add.stream_flags),
            flags: add.stream_flags,
            epoch: add.epoch,
        };
        self.rx_streams.insert(add.stream_id, info);
        true
    }

    /// Get RX stream info.
    pub fn get_rx_stream(&self, stream_id: u8) -> Option<&RxStreamInfo> {
        self.rx_streams.get(&stream_id)
    }

    /// Get all RX streams.
    pub fn rx_streams(&self) -> impl Iterator<Item = &RxStreamInfo> {
        self.rx_streams.values()
    }

    /// Handle received MAP_REQ.
    ///
    /// Returns the TxStreamInfo if we have a mapping for this stream_id.
    pub fn on_map_req(&mut self, req: &MapReq) -> Option<MapAdd> {
        self.stats.map_reqs_received += 1;

        self.tx_streams.get(&req.stream_id).map(|info| MapAdd {
            epoch: info.epoch,
            stream_id: info.stream_id,
            topic_hash: info.topic_hash,
            type_hash: info.type_hash,
            stream_flags: info.flags,
        })
    }

    // ========================================================================
    // Unknown Stream Handling
    // ========================================================================

    /// Called when a record with unknown stream_id is received.
    ///
    /// Queues a MAP_REQ for this stream_id.
    pub fn on_unknown_stream(&mut self, stream_id: u8) {
        self.stats.unknown_mapping_drops += 1;

        // Don't queue duplicate requests
        if !self.pending_map_reqs.contains(&stream_id) {
            self.pending_map_reqs.push(stream_id);
        }
    }

    /// Poll for a pending MAP_REQ to send.
    pub fn poll_pending_map_req(&mut self) -> Option<MapReq> {
        if let Some(stream_id) = self.pending_map_reqs.pop() {
            self.stats.map_reqs_sent += 1;
            return Some(MapReq {
                epoch: self.epoch,
                stream_id,
            });
        }
        None
    }

    /// Create a MAP_ACK for a received MAP_ADD.
    pub fn create_map_ack(&mut self, epoch: u16, stream_id: u8) -> MapAck {
        self.stats.map_acks_sent += 1;
        MapAck { epoch, stream_id }
    }

    // ========================================================================
    // Utility
    // ========================================================================

    /// Clear all mappings.
    pub fn clear(&mut self) {
        self.tx_streams.clear();
        self.rx_streams.clear();
        self.pending_map_reqs.clear();
        self.next_tx_id = 1;
    }

    /// Get number of TX streams.
    pub fn tx_stream_count(&self) -> usize {
        self.tx_streams.len()
    }

    /// Get number of RX streams.
    pub fn rx_stream_count(&self) -> usize {
        self.rx_streams.len()
    }

    /// Get number of unacked TX streams.
    pub fn unacked_tx_count(&self) -> usize {
        self.tx_streams.values().filter(|s| !s.acked).count()
    }
}

impl Priority {
    /// Extract priority from stream flags.
    fn from_flags(flags: u8) -> Self {
        // Priority is encoded in bits 4-5 of flags
        match (flags >> 4) & 0x03 {
            0 => Priority::P0,
            1 => Priority::P1,
            _ => Priority::P2,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_tx_stream() {
        let mut mapper = StreamMapper::new(MapperConfig::default());

        let id1 = mapper.add_tx_stream(0x1234, 0x5678, Priority::P1, 0);
        assert_eq!(id1, Some(1)); // First ID after CONTROL

        let id2 = mapper.add_tx_stream(0xAAAA, 0xBBBB, Priority::P0, stream_flags::RELIABLE);
        assert_eq!(id2, Some(2));

        assert_eq!(mapper.tx_stream_count(), 2);
    }

    #[test]
    fn test_tx_stream_limit() {
        let config = MapperConfig {
            max_tx_streams: 3,
            ..Default::default()
        };
        let mut mapper = StreamMapper::new(config);

        assert!(mapper.add_tx_stream(1, 1, Priority::P1, 0).is_some());
        assert!(mapper.add_tx_stream(2, 2, Priority::P1, 0).is_some());
        assert!(mapper.add_tx_stream(3, 3, Priority::P1, 0).is_some());
        // Should fail - no more IDs
        assert!(mapper.add_tx_stream(4, 4, Priority::P1, 0).is_none());
    }

    #[test]
    fn test_remove_tx_stream() {
        let mut mapper = StreamMapper::new(MapperConfig::default());

        let id = mapper
            .add_tx_stream(0x1234, 0x5678, Priority::P1, 0)
            .unwrap();
        assert_eq!(mapper.tx_stream_count(), 1);

        let removed = mapper.remove_tx_stream(id);
        assert!(removed.is_some());
        assert_eq!(mapper.tx_stream_count(), 0);
    }

    #[test]
    fn test_poll_pending_map_add() {
        let config = MapperConfig {
            map_add_interval: Duration::from_millis(10),
            ..Default::default()
        };
        let mut mapper = StreamMapper::new(config);

        mapper.add_tx_stream(0x1234, 0x5678, Priority::P1, 0);

        // First poll should return MAP_ADD
        let add = mapper.poll_pending_map_add();
        assert!(add.is_some());
        let add = add.unwrap();
        assert_eq!(add.stream_id, 1);
        assert_eq!(add.topic_hash, 0x1234);

        // Immediate second poll should return None (interval not elapsed)
        assert!(mapper.poll_pending_map_add().is_none());

        // After interval, should resend
        std::thread::sleep(Duration::from_millis(15));
        assert!(mapper.poll_pending_map_add().is_some());
    }

    #[test]
    fn test_map_ack() {
        let mut mapper = StreamMapper::new(MapperConfig::default());
        let id = mapper
            .add_tx_stream(0x1234, 0x5678, Priority::P1, 0)
            .unwrap();

        assert!(!mapper.is_tx_stream_acked(id));

        // ACK with correct epoch
        let ack = MapAck {
            epoch: mapper.epoch(),
            stream_id: id,
        };
        mapper.on_map_ack(&ack);

        assert!(mapper.is_tx_stream_acked(id));

        // Should not poll any more MAP_ADD
        assert!(mapper.poll_pending_map_add().is_none());
    }

    #[test]
    fn test_map_ack_wrong_epoch() {
        let mut mapper = StreamMapper::new(MapperConfig::default());
        let id = mapper
            .add_tx_stream(0x1234, 0x5678, Priority::P1, 0)
            .unwrap();

        // ACK with wrong epoch should be ignored
        let ack = MapAck {
            epoch: 999,
            stream_id: id,
        };
        mapper.on_map_ack(&ack);

        assert!(!mapper.is_tx_stream_acked(id));
    }

    #[test]
    fn test_on_map_add() {
        let mut mapper = StreamMapper::new(MapperConfig::default());

        let add = MapAdd {
            epoch: 1,
            stream_id: 5,
            topic_hash: 0xABCD,
            type_hash: 0xEF01,
            stream_flags: 0,
        };

        let is_new = mapper.on_map_add(&add);
        assert!(is_new);
        assert_eq!(mapper.rx_stream_count(), 1);

        let info = mapper.get_rx_stream(5).unwrap();
        assert_eq!(info.topic_hash, 0xABCD);
        assert_eq!(info.type_hash, 0xEF01);

        // Same mapping again should return false
        let is_new = mapper.on_map_add(&add);
        assert!(!is_new);
    }

    #[test]
    fn test_unknown_stream_and_map_req() {
        let mut mapper = StreamMapper::new(MapperConfig::default());

        // Unknown stream triggers MAP_REQ
        mapper.on_unknown_stream(10);
        mapper.on_unknown_stream(10); // Duplicate should be ignored

        let req = mapper.poll_pending_map_req();
        assert!(req.is_some());
        assert_eq!(req.unwrap().stream_id, 10);

        // Second poll should return None
        assert!(mapper.poll_pending_map_req().is_none());

        assert_eq!(mapper.stats().unknown_mapping_drops, 2);
    }

    #[test]
    fn test_on_map_req() {
        let mut mapper = StreamMapper::new(MapperConfig::default());

        // Add TX stream
        let id = mapper
            .add_tx_stream(0x1234, 0x5678, Priority::P1, 0x10)
            .unwrap();

        // Request for existing stream
        let req = MapReq {
            epoch: 1,
            stream_id: id,
        };
        let response = mapper.on_map_req(&req);
        assert!(response.is_some());
        let add = response.unwrap();
        assert_eq!(add.stream_id, id);
        assert_eq!(add.topic_hash, 0x1234);

        // Request for non-existing stream
        let req = MapReq {
            epoch: 1,
            stream_id: 99,
        };
        let response = mapper.on_map_req(&req);
        assert!(response.is_none());
    }

    #[test]
    fn test_create_map_ack() {
        let mut mapper = StreamMapper::new(MapperConfig::default());

        let ack = mapper.create_map_ack(5, 10);
        assert_eq!(ack.epoch, 5);
        assert_eq!(ack.stream_id, 10);
        assert_eq!(mapper.stats().map_acks_sent, 1);
    }

    #[test]
    fn test_max_retries() {
        let config = MapperConfig {
            map_add_interval: Duration::from_millis(1),
            map_add_max_retries: 3,
            ..Default::default()
        };
        let mut mapper = StreamMapper::new(config);

        mapper.add_tx_stream(0x1234, 0x5678, Priority::P1, 0);

        // Exhaust retries
        for _ in 0..5 {
            let _ = mapper.poll_pending_map_add();
            std::thread::sleep(Duration::from_millis(2));
        }

        // After max retries, should stop trying
        assert!(mapper.poll_pending_map_add().is_none());
        assert_eq!(mapper.stats().mapping_failures, 1);
    }

    #[test]
    fn test_clear() {
        let mut mapper = StreamMapper::new(MapperConfig::default());

        mapper.add_tx_stream(0x1234, 0x5678, Priority::P1, 0);
        mapper.on_map_add(&MapAdd {
            epoch: 1,
            stream_id: 5,
            topic_hash: 0xABCD,
            type_hash: 0xEF01,
            stream_flags: 0,
        });
        mapper.on_unknown_stream(10);

        mapper.clear();

        assert_eq!(mapper.tx_stream_count(), 0);
        assert_eq!(mapper.rx_stream_count(), 0);
        assert!(mapper.poll_pending_map_req().is_none());
    }

    #[test]
    fn test_epoch_bump() {
        let mut mapper = StreamMapper::new(MapperConfig::default());

        let initial = mapper.epoch();
        mapper.bump_epoch();
        assert_eq!(mapper.epoch(), initial + 1);
    }

    #[test]
    fn test_stream_flags_priority() {
        // P0 = bits 4-5 = 0b00
        assert_eq!(Priority::from_flags(0x00), Priority::P0);
        // P1 = bits 4-5 = 0b01
        assert_eq!(Priority::from_flags(0x10), Priority::P1);
        // P2 = bits 4-5 = 0b10
        assert_eq!(Priority::from_flags(0x20), Priority::P2);
    }

    #[test]
    fn test_mapping_full_flow() {
        // Simulate two mappers exchanging mappings

        let config = MapperConfig {
            map_add_interval: Duration::from_millis(10),
            ..Default::default()
        };

        let mut mapper_a = StreamMapper::new(config.clone());
        let mut mapper_b = StreamMapper::new(config);

        // A creates a stream
        let id = mapper_a
            .add_tx_stream(0x1234, 0x5678, Priority::P1, 0)
            .unwrap();

        // A polls MAP_ADD
        let add = mapper_a.poll_pending_map_add().unwrap();
        assert_eq!(add.stream_id, id);

        // B receives MAP_ADD
        assert!(mapper_b.on_map_add(&add));

        // B sends MAP_ACK
        let ack = mapper_b.create_map_ack(add.epoch, add.stream_id);

        // A receives MAP_ACK
        mapper_a.on_map_ack(&ack);

        // A's stream is now acked
        assert!(mapper_a.is_tx_stream_acked(id));

        // B can now lookup the stream
        let info = mapper_b.get_rx_stream(id).unwrap();
        assert_eq!(info.topic_hash, 0x1234);
    }

    #[test]
    fn test_mapping_recovery_via_map_req() {
        // Simulate recovery when MAP_ADD was lost

        let config = MapperConfig {
            map_add_interval: Duration::from_millis(10),
            ..Default::default()
        };

        let mut mapper_a = StreamMapper::new(config.clone());
        let mut mapper_b = StreamMapper::new(config);

        // A creates a stream
        let id = mapper_a
            .add_tx_stream(0x1234, 0x5678, Priority::P1, 0)
            .unwrap();

        // Pretend MAP_ADD was lost...
        // B receives a record with unknown stream_id
        mapper_b.on_unknown_stream(id);

        // B sends MAP_REQ
        let req = mapper_b.poll_pending_map_req().unwrap();
        assert_eq!(req.stream_id, id);

        // A receives MAP_REQ and responds with MAP_ADD
        let add = mapper_a.on_map_req(&req).unwrap();
        assert_eq!(add.stream_id, id);

        // B receives MAP_ADD
        assert!(mapper_b.on_map_add(&add));

        // B can now lookup the stream
        assert!(mapper_b.get_rx_stream(id).is_some());
    }
}
