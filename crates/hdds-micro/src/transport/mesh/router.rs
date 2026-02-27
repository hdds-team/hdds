// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Mesh router and relay decision logic

use super::header::MeshHeader;
use super::neighbor::NeighborTable;
use super::seen::SeenCache;
use super::{MeshStats, DEFAULT_TTL, MAX_TTL};

/// Mesh routing configuration
#[derive(Debug, Clone, Copy)]
pub struct MeshConfig {
    /// Default TTL for new messages
    pub default_ttl: u8,
    /// Whether to relay messages
    pub relay_enabled: bool,
    /// Whether to relay broadcast messages
    pub relay_broadcast: bool,
    /// Minimum RSSI to consider for relay (-dBm)
    pub min_relay_rssi: i16,
    /// Neighbor table lifetime (ticks)
    pub neighbor_lifetime: u32,
    /// Seen cache lifetime (ticks)
    pub seen_lifetime: u32,
}

impl Default for MeshConfig {
    fn default() -> Self {
        Self {
            default_ttl: DEFAULT_TTL,
            relay_enabled: true,
            relay_broadcast: true,
            min_relay_rssi: -100,   // Accept all
            neighbor_lifetime: 300, // 5 minutes at 1 tick/sec
            seen_lifetime: 60,      // 1 minute
        }
    }
}

impl MeshConfig {
    /// Create config for a relay node
    pub fn relay_node() -> Self {
        Self {
            relay_enabled: true,
            relay_broadcast: true,
            ..Default::default()
        }
    }

    /// Create config for an endpoint (no relay)
    pub fn endpoint() -> Self {
        Self {
            relay_enabled: false,
            relay_broadcast: false,
            ..Default::default()
        }
    }

    /// Create config for a gateway
    pub fn gateway() -> Self {
        Self {
            default_ttl: MAX_TTL,
            relay_enabled: true,
            relay_broadcast: true,
            ..Default::default()
        }
    }
}

/// Decision about what to do with a received message
#[derive(Debug, Clone)]
pub enum RelayDecision {
    /// Deliver to local application
    Deliver,
    /// Relay to network (with updated header)
    Relay(MeshHeader),
    /// Drop (duplicate or TTL expired)
    Drop,
}

/// Mesh router
pub struct MeshRouter<const NEIGHBORS: usize, const SEEN: usize> {
    /// Our node ID
    node_id: u8,
    /// Configuration
    config: MeshConfig,
    /// Neighbor table
    neighbors: NeighborTable<NEIGHBORS>,
    /// Seen message cache
    seen: SeenCache<SEEN>,
    /// Statistics
    stats: MeshStats,
}

impl<const NEIGHBORS: usize, const SEEN: usize> MeshRouter<NEIGHBORS, SEEN> {
    /// Create a new mesh router
    pub fn new(node_id: u8, config: MeshConfig) -> Self {
        Self {
            node_id,
            config,
            neighbors: NeighborTable::new(config.neighbor_lifetime),
            seen: SeenCache::new(config.seen_lifetime),
            stats: MeshStats::default(),
        }
    }

    /// Get configuration
    pub fn config(&self) -> &MeshConfig {
        &self.config
    }

    /// Get neighbor table
    pub fn neighbors(&self) -> &NeighborTable<NEIGHBORS> {
        &self.neighbors
    }

    /// Get statistics
    pub fn stats(&self) -> MeshStats {
        self.stats
    }

    /// Advance time (call periodically, e.g., once per second)
    pub fn tick(&mut self) {
        self.neighbors.tick();
        self.seen.tick();
        self.neighbors.expire_old();
    }

    /// Process a received message and decide what to do
    pub fn process_received(&mut self, header: &MeshHeader, rssi: Option<i16>) -> RelayDecision {
        // Update neighbor info if RSSI available
        if let Some(rssi) = rssi {
            self.neighbors.update(header.src, rssi);
        }

        // Check if we've seen this message before
        let msg_id = header.message_id();
        if self.seen.check_and_mark(msg_id) {
            self.stats.rx_duplicate += 1;
            return RelayDecision::Drop;
        }

        // Check if message is for us
        let is_for_us = header.dst == self.node_id || header.dst == 0xFF;

        // Check if we should relay
        let should_relay = self.should_relay(header, rssi);

        if should_relay {
            if let Some(relay_header) = header.for_relay() {
                self.stats.tx_relayed += 1;

                if is_for_us {
                    self.stats.rx_delivered += 1;
                }

                return RelayDecision::Relay(relay_header);
            }

            // TTL expired
            self.stats.rx_ttl_expired += 1;

            if is_for_us {
                self.stats.rx_delivered += 1;
                return RelayDecision::Deliver;
            }

            return RelayDecision::Drop;
        }

        if is_for_us {
            self.stats.rx_delivered += 1;
            RelayDecision::Deliver
        } else {
            RelayDecision::Drop
        }
    }

    /// Determine if we should relay a message
    fn should_relay(&self, header: &MeshHeader, rssi: Option<i16>) -> bool {
        // Don't relay our own messages
        if header.src == self.node_id {
            return false;
        }

        // Don't relay unicast messages addressed to us
        if header.dst == self.node_id {
            return false;
        }

        // Check if relay is enabled
        if !self.config.relay_enabled {
            return false;
        }

        // Check broadcast relay setting
        if header.is_broadcast() && !self.config.relay_broadcast {
            return false;
        }

        // Check RSSI threshold
        if let Some(rssi) = rssi {
            if rssi < self.config.min_relay_rssi {
                return false;
            }
        }

        // Check TTL
        if header.ttl == 0 {
            return false;
        }

        true
    }

    /// Record that we originated a message
    pub fn record_originated(&mut self, header: &MeshHeader) {
        self.seen.mark_seen(header.message_id());
        self.stats.tx_originated += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_router_creation() {
        let router: MeshRouter<8, 32> = MeshRouter::new(1, MeshConfig::default());
        assert_eq!(router.config().default_ttl, DEFAULT_TTL);
    }

    #[test]
    fn test_relay_decision_deliver() {
        let mut router: MeshRouter<8, 32> = MeshRouter::new(1, MeshConfig::endpoint());

        // Message addressed to us
        let header = MeshHeader::new(2, 1, 100, 3);
        let decision = router.process_received(&header, Some(-70));

        match decision {
            RelayDecision::Deliver => {}
            _ => panic!("Expected Deliver"),
        }
    }

    #[test]
    fn test_relay_decision_broadcast() {
        let mut router: MeshRouter<8, 32> = MeshRouter::new(1, MeshConfig::relay_node());

        // Broadcast message
        let header = MeshHeader::broadcast(2, 100, 3);
        let decision = router.process_received(&header, Some(-70));

        match decision {
            RelayDecision::Relay(new_header) => {
                assert_eq!(new_header.ttl, 2); // Decremented
                assert_eq!(new_header.hop_count, 1); // Incremented
            }
            _ => panic!("Expected Relay"),
        }
    }

    #[test]
    fn test_relay_decision_duplicate() {
        let mut router: MeshRouter<8, 32> = MeshRouter::new(1, MeshConfig::relay_node());

        let header = MeshHeader::broadcast(2, 100, 3);

        // First time - should relay
        let decision1 = router.process_received(&header, Some(-70));
        assert!(matches!(decision1, RelayDecision::Relay(_)));

        // Second time - duplicate
        let decision2 = router.process_received(&header, Some(-70));
        assert!(matches!(decision2, RelayDecision::Drop));

        assert_eq!(router.stats().rx_duplicate, 1);
    }

    #[test]
    fn test_relay_decision_ttl_expired() {
        let mut router: MeshRouter<8, 32> = MeshRouter::new(1, MeshConfig::relay_node());

        // Message with TTL=0
        let header = MeshHeader::new(2, 3, 100, 0);
        let decision = router.process_received(&header, Some(-70));

        // Should not relay, not for us -> drop
        assert!(matches!(decision, RelayDecision::Drop));
    }

    #[test]
    fn test_relay_disabled() {
        let mut router: MeshRouter<8, 32> = MeshRouter::new(1, MeshConfig::endpoint());

        // Broadcast from another node
        let header = MeshHeader::broadcast(2, 100, 3);
        let decision = router.process_received(&header, Some(-70));

        // Should deliver (broadcast) but not relay
        match decision {
            RelayDecision::Deliver => {}
            _ => panic!("Expected Deliver (not Relay)"),
        }
    }

    #[test]
    fn test_own_message_not_relayed() {
        let mut router: MeshRouter<8, 32> = MeshRouter::new(1, MeshConfig::relay_node());

        // Message from ourselves
        let header = MeshHeader::broadcast(1, 100, 3);
        let decision = router.process_received(&header, Some(-70));

        // Should deliver (broadcast to us) but not relay
        match decision {
            RelayDecision::Deliver => {}
            _ => panic!("Expected Deliver"),
        }
    }

    #[test]
    fn test_rssi_threshold() {
        let config = MeshConfig {
            min_relay_rssi: -80,
            relay_enabled: true,
            relay_broadcast: true,
            ..Default::default()
        };
        let mut router: MeshRouter<8, 32> = MeshRouter::new(1, config);

        // Strong signal - should relay
        let header1 = MeshHeader::broadcast(2, 100, 3);
        let decision1 = router.process_received(&header1, Some(-70));
        assert!(matches!(decision1, RelayDecision::Relay(_)));

        // Weak signal - should not relay (but deliver since broadcast)
        let header2 = MeshHeader::broadcast(3, 101, 3);
        let decision2 = router.process_received(&header2, Some(-90));
        assert!(matches!(decision2, RelayDecision::Deliver));
    }

    #[test]
    fn test_neighbor_tracking() {
        let mut router: MeshRouter<8, 32> = MeshRouter::new(1, MeshConfig::relay_node());

        // Receive messages from multiple sources
        let h1 = MeshHeader::broadcast(2, 100, 3);
        let h2 = MeshHeader::broadcast(3, 101, 3);
        let h3 = MeshHeader::broadcast(4, 102, 3);

        router.process_received(&h1, Some(-70));
        router.process_received(&h2, Some(-80));
        router.process_received(&h3, Some(-60));

        assert_eq!(router.neighbors().len(), 3);

        let best = router.neighbors().best_neighbor().unwrap();
        assert_eq!(best.node_id, 4); // Strongest signal
    }

    #[test]
    fn test_stats_tracking() {
        let mut router: MeshRouter<8, 32> = MeshRouter::new(1, MeshConfig::relay_node());

        // Relayed message
        let h1 = MeshHeader::broadcast(2, 100, 3);
        router.process_received(&h1, Some(-70));

        // Duplicate
        router.process_received(&h1, Some(-70));

        // For us only
        let h2 = MeshHeader::new(3, 1, 101, 3);
        router.process_received(&h2, Some(-70));

        let stats = router.stats();
        assert_eq!(stats.tx_relayed, 1);
        assert_eq!(stats.rx_duplicate, 1);
        assert_eq!(stats.rx_delivered, 2); // broadcast + unicast
    }

    #[test]
    fn test_config_presets() {
        let relay = MeshConfig::relay_node();
        assert!(relay.relay_enabled);
        assert!(relay.relay_broadcast);

        let endpoint = MeshConfig::endpoint();
        assert!(!endpoint.relay_enabled);

        let gateway = MeshConfig::gateway();
        assert_eq!(gateway.default_ttl, MAX_TTL);
    }
}
