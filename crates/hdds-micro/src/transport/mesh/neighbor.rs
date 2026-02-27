// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Neighbor table for mesh routing

/// Information about a neighboring node
#[derive(Debug, Clone, Copy, Default)]
pub struct Neighbor {
    /// Node ID
    pub node_id: u8,
    /// Last RSSI value (-dBm, higher = better)
    pub rssi: i16,
    /// Last seen tick
    pub last_seen: u32,
    /// Messages received from this neighbor
    pub rx_count: u16,
    /// Valid flag
    valid: bool,
}

impl Neighbor {
    /// Create a new neighbor entry
    pub fn new(node_id: u8, rssi: i16, tick: u32) -> Self {
        Self {
            node_id,
            rssi,
            last_seen: tick,
            rx_count: 1,
            valid: true,
        }
    }

    /// Update neighbor info
    pub fn update(&mut self, rssi: i16, tick: u32) {
        // Exponential moving average for RSSI
        self.rssi = ((self.rssi as i32 * 7 + rssi as i32) / 8) as i16;
        self.last_seen = tick;
        self.rx_count = self.rx_count.saturating_add(1);
    }

    /// Check if neighbor is valid
    pub fn is_valid(&self) -> bool {
        self.valid
    }

    /// Calculate link quality (0-100)
    pub fn link_quality(&self) -> u8 {
        // Map RSSI to quality
        // -50 dBm = excellent (100)
        // -100 dBm = poor (0)
        let rssi = self.rssi.clamp(-100, -50);
        ((rssi + 100) * 2).min(100) as u8
    }
}

/// Fixed-size neighbor table
pub struct NeighborTable<const N: usize> {
    /// Neighbor entries
    entries: [Neighbor; N],
    /// Current tick
    tick: u32,
    /// Neighbor lifetime in ticks
    lifetime: u32,
}

impl<const N: usize> NeighborTable<N> {
    /// Create a new neighbor table
    pub fn new(lifetime: u32) -> Self {
        Self {
            entries: [Neighbor::default(); N],
            tick: 0,
            lifetime,
        }
    }

    /// Advance the tick counter
    pub fn tick(&mut self) {
        self.tick = self.tick.wrapping_add(1);
    }

    /// Update or add a neighbor
    pub fn update(&mut self, node_id: u8, rssi: i16) {
        // First, try to find existing entry
        for entry in &mut self.entries {
            if entry.valid && entry.node_id == node_id {
                entry.update(rssi, self.tick);
                return;
            }
        }

        // Not found, try to add new entry
        // First, try to find an invalid or expired slot
        for entry in &mut self.entries {
            if !entry.valid {
                *entry = Neighbor::new(node_id, rssi, self.tick);
                return;
            }

            let age = self.tick.wrapping_sub(entry.last_seen);
            if age > self.lifetime {
                *entry = Neighbor::new(node_id, rssi, self.tick);
                return;
            }
        }

        // Table full, replace weakest link
        let mut worst_idx = 0;
        let mut worst_quality = 255u8;

        for (i, entry) in self.entries.iter().enumerate() {
            if entry.valid {
                let quality = entry.link_quality();
                if quality < worst_quality {
                    worst_quality = quality;
                    worst_idx = i;
                }
            }
        }

        // Only replace if new neighbor has better signal
        let new_quality = Neighbor::new(node_id, rssi, self.tick).link_quality();
        if new_quality > worst_quality {
            self.entries[worst_idx] = Neighbor::new(node_id, rssi, self.tick);
        }
    }

    /// Get neighbor by node ID
    pub fn get(&self, node_id: u8) -> Option<&Neighbor> {
        for entry in &self.entries {
            if entry.valid && entry.node_id == node_id {
                let age = self.tick.wrapping_sub(entry.last_seen);
                if age <= self.lifetime {
                    return Some(entry);
                }
            }
        }
        None
    }

    /// Get best neighbor (highest link quality)
    pub fn best_neighbor(&self) -> Option<&Neighbor> {
        let mut best: Option<&Neighbor> = None;
        let mut best_quality = 0u8;

        for entry in &self.entries {
            if entry.valid {
                let age = self.tick.wrapping_sub(entry.last_seen);
                if age <= self.lifetime {
                    let quality = entry.link_quality();
                    if quality > best_quality {
                        best_quality = quality;
                        best = Some(entry);
                    }
                }
            }
        }

        best
    }

    /// Get all valid neighbors
    pub fn iter(&self) -> impl Iterator<Item = &Neighbor> {
        let tick = self.tick;
        let lifetime = self.lifetime;

        self.entries
            .iter()
            .filter(move |e| e.valid && tick.wrapping_sub(e.last_seen) <= lifetime)
    }

    /// Get number of valid neighbors
    pub fn len(&self) -> usize {
        self.iter().count()
    }

    /// Check if table is empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Clear all entries
    pub fn clear(&mut self) {
        for entry in &mut self.entries {
            entry.valid = false;
        }
    }

    /// Expire old entries
    pub fn expire_old(&mut self) {
        for entry in &mut self.entries {
            if entry.valid {
                let age = self.tick.wrapping_sub(entry.last_seen);
                if age > self.lifetime {
                    entry.valid = false;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_neighbor_creation() {
        let neighbor = Neighbor::new(1, -70, 0);
        assert_eq!(neighbor.node_id, 1);
        assert_eq!(neighbor.rssi, -70);
        assert!(neighbor.is_valid());
    }

    #[test]
    fn test_neighbor_link_quality() {
        // Excellent signal
        let n1 = Neighbor::new(1, -50, 0);
        assert_eq!(n1.link_quality(), 100);

        // Good signal
        let n2 = Neighbor::new(2, -70, 0);
        assert_eq!(n2.link_quality(), 60);

        // Poor signal
        let n3 = Neighbor::new(3, -95, 0);
        assert_eq!(n3.link_quality(), 10);

        // Very poor (clamped)
        let n4 = Neighbor::new(4, -120, 0);
        assert_eq!(n4.link_quality(), 0);
    }

    #[test]
    fn test_neighbor_table_basic() {
        let mut table: NeighborTable<8> = NeighborTable::new(100);

        table.update(1, -70);
        table.update(2, -80);

        assert_eq!(table.len(), 2);
        assert!(table.get(1).is_some());
        assert!(table.get(2).is_some());
        assert!(table.get(3).is_none());
    }

    #[test]
    fn test_neighbor_table_update() {
        let mut table: NeighborTable<8> = NeighborTable::new(100);

        table.update(1, -70);
        assert_eq!(table.get(1).unwrap().rx_count, 1);

        table.update(1, -65);
        let neighbor = table.get(1).unwrap();
        assert_eq!(neighbor.rx_count, 2);
        // RSSI should be smoothed
        assert!(neighbor.rssi > -70 && neighbor.rssi < -65);
    }

    #[test]
    fn test_neighbor_table_expiry() {
        let mut table: NeighborTable<8> = NeighborTable::new(10);

        table.update(1, -70);
        assert_eq!(table.len(), 1);

        // Advance time past lifetime
        for _ in 0..15 {
            table.tick();
        }

        // Should be expired
        assert!(table.get(1).is_none());
        assert_eq!(table.len(), 0);
    }

    #[test]
    fn test_neighbor_table_best() {
        let mut table: NeighborTable<8> = NeighborTable::new(100);

        table.update(1, -90); // Poor
        table.update(2, -60); // Good
        table.update(3, -80); // Medium

        let best = table.best_neighbor().unwrap();
        assert_eq!(best.node_id, 2);
    }

    #[test]
    fn test_neighbor_table_full() {
        let mut table: NeighborTable<4> = NeighborTable::new(1000);

        // Fill table with weak signals
        table.update(1, -95);
        table.update(2, -95);
        table.update(3, -95);
        table.update(4, -95);
        assert_eq!(table.len(), 4);

        // Add stronger signal - should replace weakest
        table.update(5, -60);
        assert_eq!(table.len(), 4);
        assert!(table.get(5).is_some());
    }

    #[test]
    fn test_neighbor_table_clear() {
        let mut table: NeighborTable<8> = NeighborTable::new(100);

        table.update(1, -70);
        table.update(2, -80);
        assert_eq!(table.len(), 2);

        table.clear();
        assert_eq!(table.len(), 0);
        assert!(table.is_empty());
    }
}
