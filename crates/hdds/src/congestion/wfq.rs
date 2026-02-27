// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Weighted Fair Queuing (WFQ) for HDDS.
//!
//! WFQ provides fair bandwidth allocation between writers within the same
//! priority level, based on configurable weights. This prevents a single
//! high-rate writer from starving others.
//!
//! # Algorithm
//!
//! WFQ uses virtual time and finish times to schedule packets:
//!
//! 1. Each writer has a weight (default 1.0)
//! 2. Virtual finish time = virtual_start + (packet_size / weight)
//! 3. Packets are dequeued in order of finish time
//!
//! This ensures that over time, each writer gets bandwidth proportional
//! to its weight, regardless of packet arrival order.
//!
//! # Example
//!
//! ```rust,ignore
//! use hdds::congestion::wfq::{WfqScheduler, WfqWriter};
//!
//! let mut scheduler = WfqScheduler::new();
//!
//! // Add writers with weights
//! scheduler.add_writer(1, 2.0);  // Gets 2x bandwidth
//! scheduler.add_writer(2, 1.0);  // Gets 1x bandwidth
//!
//! // Enqueue packets
//! scheduler.enqueue(1, packet1, 100);  // Writer 1, 100 bytes
//! scheduler.enqueue(2, packet2, 100);  // Writer 2, 100 bytes
//!
//! // Dequeue in fair order
//! let next = scheduler.dequeue();  // Returns packet with lowest finish time
//! ```

use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap};

/// Writer identifier.
pub type WriterId = u64;

/// A packet in the WFQ scheduler.
#[derive(Debug)]
pub struct WfqPacket<T> {
    /// Writer that owns this packet.
    pub writer_id: WriterId,
    /// The packet data.
    pub data: T,
    /// Packet size in bytes.
    pub size: usize,
    /// Virtual finish time (for scheduling).
    finish_time: f64,
}

impl<T> WfqPacket<T> {
    /// Get the virtual finish time.
    pub fn finish_time(&self) -> f64 {
        self.finish_time
    }
}

// Implement Ord for BinaryHeap (min-heap by finish_time)
impl<T> Eq for WfqPacket<T> {}

impl<T> PartialEq for WfqPacket<T> {
    fn eq(&self, other: &Self) -> bool {
        self.finish_time == other.finish_time
    }
}

impl<T> Ord for WfqPacket<T> {
    fn cmp(&self, other: &Self) -> Ordering {
        // Reverse for min-heap (lower finish time = higher priority)
        other
            .finish_time
            .partial_cmp(&self.finish_time)
            .unwrap_or(Ordering::Equal)
    }
}

impl<T> PartialOrd for WfqPacket<T> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Per-writer state in WFQ.
#[derive(Debug, Clone)]
pub struct WfqWriter {
    /// Writer weight (higher = more bandwidth).
    pub weight: f64,
    /// Virtual start time for next packet.
    virtual_start: f64,
    /// Total bytes scheduled.
    pub bytes_scheduled: u64,
    /// Total packets scheduled.
    pub packets_scheduled: u64,
    /// Active (has pending packets).
    pub active: bool,
}

impl WfqWriter {
    /// Create a new writer with given weight.
    pub fn new(weight: f64) -> Self {
        Self {
            weight: weight.max(0.1), // Minimum weight to avoid division issues
            virtual_start: 0.0,
            bytes_scheduled: 0,
            packets_scheduled: 0,
            active: false,
        }
    }

    /// Create with default weight (1.0).
    pub fn default_weight() -> Self {
        Self::new(1.0)
    }
}

/// WFQ scheduler statistics.
#[derive(Debug, Clone, Default)]
pub struct WfqStats {
    /// Total packets scheduled.
    pub total_packets: u64,
    /// Total bytes scheduled.
    pub total_bytes: u64,
    /// Current virtual time.
    pub virtual_time: f64,
    /// Number of active writers.
    pub active_writers: usize,
}

/// Weighted Fair Queuing scheduler.
///
/// Schedules packets from multiple writers fairly based on weights.
#[derive(Debug)]
pub struct WfqScheduler<T> {
    /// Per-writer state.
    writers: HashMap<WriterId, WfqWriter>,
    /// Priority queue of packets (min-heap by finish time).
    queue: BinaryHeap<WfqPacket<T>>,
    /// Global virtual time.
    virtual_time: f64,
    /// Maximum queue depth.
    max_queue_size: usize,
    /// Statistics.
    stats: WfqStats,
}

impl<T> Default for WfqScheduler<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> WfqScheduler<T> {
    /// Create a new WFQ scheduler.
    pub fn new() -> Self {
        Self::with_max_queue(10_000)
    }

    /// Create with custom max queue size.
    pub fn with_max_queue(max_size: usize) -> Self {
        Self {
            writers: HashMap::new(),
            queue: BinaryHeap::new(),
            virtual_time: 0.0,
            max_queue_size: max_size,
            stats: WfqStats::default(),
        }
    }

    /// Add a writer with given weight.
    ///
    /// Weight determines bandwidth share. A writer with weight 2.0 gets
    /// twice the bandwidth of a writer with weight 1.0.
    pub fn add_writer(&mut self, writer_id: WriterId, weight: f64) {
        self.writers.insert(writer_id, WfqWriter::new(weight));
    }

    /// Remove a writer.
    ///
    /// Note: Packets from this writer already in queue will still be delivered.
    pub fn remove_writer(&mut self, writer_id: WriterId) -> bool {
        self.writers.remove(&writer_id).is_some()
    }

    /// Update a writer's weight.
    pub fn set_weight(&mut self, writer_id: WriterId, weight: f64) -> bool {
        if let Some(writer) = self.writers.get_mut(&writer_id) {
            writer.weight = weight.max(0.1);
            true
        } else {
            false
        }
    }

    /// Get a writer's current weight.
    pub fn get_weight(&self, writer_id: WriterId) -> Option<f64> {
        self.writers.get(&writer_id).map(|w| w.weight)
    }

    /// Enqueue a packet.
    ///
    /// Returns `Err` if queue is full or writer not registered.
    pub fn enqueue(&mut self, writer_id: WriterId, data: T, size: usize) -> Result<(), WfqError> {
        if self.queue.len() >= self.max_queue_size {
            return Err(WfqError::QueueFull);
        }

        let writer = self
            .writers
            .get_mut(&writer_id)
            .ok_or(WfqError::UnknownWriter)?;

        // Calculate virtual start time
        // If writer was idle, start from current virtual time
        if !writer.active {
            writer.virtual_start = self.virtual_time;
            writer.active = true;
        }

        // Calculate finish time: start + (size / weight)
        let service_time = size as f64 / writer.weight;
        let finish_time = writer.virtual_start + service_time;

        // Update writer's virtual start for next packet
        writer.virtual_start = finish_time;
        writer.bytes_scheduled += size as u64;
        writer.packets_scheduled += 1;

        // Enqueue packet
        self.queue.push(WfqPacket {
            writer_id,
            data,
            size,
            finish_time,
        });

        self.stats.total_packets += 1;
        self.stats.total_bytes += size as u64;

        Ok(())
    }

    /// Dequeue the next packet (lowest finish time).
    pub fn dequeue(&mut self) -> Option<WfqPacket<T>> {
        let packet = self.queue.pop()?;

        // Update virtual time
        self.virtual_time = self.virtual_time.max(packet.finish_time);
        self.stats.virtual_time = self.virtual_time;

        // Check if writer is still active
        // Calculate has_pending first to avoid borrow conflict
        let writer_id = packet.writer_id;
        let has_pending = self.queue.iter().any(|p| p.writer_id == writer_id);
        if let Some(writer) = self.writers.get_mut(&writer_id) {
            // Writer becomes inactive if no more packets pending
            writer.active = has_pending;
        }

        Some(packet)
    }

    /// Peek at the next packet without removing it.
    pub fn peek(&self) -> Option<&WfqPacket<T>> {
        self.queue.peek()
    }

    /// Get queue length.
    pub fn len(&self) -> usize {
        self.queue.len()
    }

    /// Check if queue is empty.
    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    /// Get statistics.
    pub fn stats(&self) -> WfqStats {
        WfqStats {
            total_packets: self.stats.total_packets,
            total_bytes: self.stats.total_bytes,
            virtual_time: self.virtual_time,
            active_writers: self.writers.values().filter(|w| w.active).count(),
        }
    }

    /// Get number of registered writers.
    pub fn writer_count(&self) -> usize {
        self.writers.len()
    }

    /// Get writer statistics.
    pub fn writer_stats(&self, writer_id: WriterId) -> Option<&WfqWriter> {
        self.writers.get(&writer_id)
    }

    /// Reset virtual time (call periodically to prevent overflow).
    pub fn reset_virtual_time(&mut self) {
        if self.queue.is_empty() {
            self.virtual_time = 0.0;
            for writer in self.writers.values_mut() {
                writer.virtual_start = 0.0;
            }
        }
    }

    /// Drain all packets for a specific writer.
    pub fn drain_writer(&mut self, writer_id: WriterId) -> Vec<T> {
        let mut packets = Vec::new();
        let mut remaining = BinaryHeap::new();

        while let Some(packet) = self.queue.pop() {
            if packet.writer_id == writer_id {
                packets.push(packet.data);
            } else {
                remaining.push(packet);
            }
        }

        self.queue = remaining;

        if let Some(writer) = self.writers.get_mut(&writer_id) {
            writer.active = false;
        }

        packets
    }
}

/// WFQ error types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WfqError {
    /// Queue is full.
    QueueFull,
    /// Writer not registered.
    UnknownWriter,
}

impl std::fmt::Display for WfqError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WfqError::QueueFull => write!(f, "WFQ queue full"),
            WfqError::UnknownWriter => write!(f, "unknown writer"),
        }
    }
}

impl std::error::Error for WfqError {}

/// Priority-aware WFQ scheduler.
///
/// Combines priority queuing with WFQ within each priority level.
/// P0 always goes first, then P1, then P2. Within each level,
/// packets are scheduled fairly using WFQ.
#[derive(Debug)]
pub struct PriorityWfqScheduler<T> {
    /// P0 (critical) scheduler.
    p0: WfqScheduler<T>,
    /// P1 (normal) scheduler.
    p1: WfqScheduler<T>,
    /// P2 (background) scheduler.
    p2: WfqScheduler<T>,
}

impl<T> Default for PriorityWfqScheduler<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> PriorityWfqScheduler<T> {
    /// Create a new priority-aware WFQ scheduler.
    pub fn new() -> Self {
        Self {
            p0: WfqScheduler::with_max_queue(1000),
            p1: WfqScheduler::with_max_queue(5000),
            p2: WfqScheduler::with_max_queue(1000),
        }
    }

    /// Add a writer at a specific priority level.
    pub fn add_writer(&mut self, writer_id: WriterId, priority: u8, weight: f64) {
        match priority {
            0 => self.p0.add_writer(writer_id, weight),
            1 => self.p1.add_writer(writer_id, weight),
            _ => self.p2.add_writer(writer_id, weight),
        }
    }

    /// Remove a writer from all priority levels.
    pub fn remove_writer(&mut self, writer_id: WriterId) {
        self.p0.remove_writer(writer_id);
        self.p1.remove_writer(writer_id);
        self.p2.remove_writer(writer_id);
    }

    /// Enqueue a packet at a specific priority level.
    pub fn enqueue(
        &mut self,
        writer_id: WriterId,
        priority: u8,
        data: T,
        size: usize,
    ) -> Result<(), WfqError> {
        match priority {
            0 => self.p0.enqueue(writer_id, data, size),
            1 => self.p1.enqueue(writer_id, data, size),
            _ => self.p2.enqueue(writer_id, data, size),
        }
    }

    /// Dequeue the highest priority packet.
    ///
    /// Returns (priority, packet) where priority is 0, 1, or 2.
    pub fn dequeue(&mut self) -> Option<(u8, WfqPacket<T>)> {
        // P0 first
        if let Some(packet) = self.p0.dequeue() {
            return Some((0, packet));
        }
        // Then P1
        if let Some(packet) = self.p1.dequeue() {
            return Some((1, packet));
        }
        // Finally P2
        if let Some(packet) = self.p2.dequeue() {
            return Some((2, packet));
        }
        None
    }

    /// Get total queue length across all priorities.
    pub fn len(&self) -> usize {
        self.p0.len() + self.p1.len() + self.p2.len()
    }

    /// Check if all queues are empty.
    pub fn is_empty(&self) -> bool {
        self.p0.is_empty() && self.p1.is_empty() && self.p2.is_empty()
    }

    /// Get queue length per priority.
    pub fn len_by_priority(&self) -> (usize, usize, usize) {
        (self.p0.len(), self.p1.len(), self.p2.len())
    }

    /// Reset virtual times (call periodically).
    pub fn reset_virtual_times(&mut self) {
        self.p0.reset_virtual_time();
        self.p1.reset_virtual_time();
        self.p2.reset_virtual_time();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wfq_basic_enqueue_dequeue() {
        let mut scheduler: WfqScheduler<Vec<u8>> = WfqScheduler::new();
        scheduler.add_writer(1, 1.0);

        scheduler.enqueue(1, vec![1, 2, 3], 3).unwrap();
        scheduler.enqueue(1, vec![4, 5, 6], 3).unwrap();

        let p1 = scheduler.dequeue().unwrap();
        assert_eq!(p1.data, vec![1, 2, 3]);

        let p2 = scheduler.dequeue().unwrap();
        assert_eq!(p2.data, vec![4, 5, 6]);

        assert!(scheduler.dequeue().is_none());
    }

    #[test]
    fn test_wfq_fair_scheduling() {
        let mut scheduler: WfqScheduler<u8> = WfqScheduler::new();

        // Two writers with equal weight
        scheduler.add_writer(1, 1.0);
        scheduler.add_writer(2, 1.0);

        // Writer 1 sends 3 packets
        scheduler.enqueue(1, 1, 100).unwrap();
        scheduler.enqueue(1, 2, 100).unwrap();
        scheduler.enqueue(1, 3, 100).unwrap();

        // Writer 2 sends 3 packets
        scheduler.enqueue(2, 10, 100).unwrap();
        scheduler.enqueue(2, 20, 100).unwrap();
        scheduler.enqueue(2, 30, 100).unwrap();

        // Should interleave fairly
        let mut from_w1 = 0;
        let mut from_w2 = 0;
        let mut order = Vec::new();

        while let Some(p) = scheduler.dequeue() {
            order.push(p.writer_id);
            if p.writer_id == 1 {
                from_w1 += 1;
            } else {
                from_w2 += 1;
            }
        }

        assert_eq!(from_w1, 3);
        assert_eq!(from_w2, 3);

        // With equal weights, should alternate: 1, 2, 1, 2, 1, 2
        // (First packet from each has same finish time, order depends on insertion)
        // The key is that after 2 packets, each writer should have 1 packet sent
        let first_two: Vec<_> = order.iter().take(2).cloned().collect();
        assert!(first_two.contains(&1));
        assert!(first_two.contains(&2));
    }

    #[test]
    fn test_wfq_weighted_scheduling() {
        let mut scheduler: WfqScheduler<u8> = WfqScheduler::new();

        // Writer 1 has 2x weight
        scheduler.add_writer(1, 2.0);
        scheduler.add_writer(2, 1.0);

        // Both send same size packets
        for i in 0..6 {
            scheduler.enqueue(1, i, 100).unwrap();
        }
        for i in 0..3 {
            scheduler.enqueue(2, 100 + i, 100).unwrap();
        }

        // Writer 1 should get roughly 2x the packets in first N dequeues
        let mut w1_count = 0;
        let mut w2_count = 0;

        for _ in 0..6 {
            if let Some(p) = scheduler.dequeue() {
                if p.writer_id == 1 {
                    w1_count += 1;
                } else {
                    w2_count += 1;
                }
            }
        }

        // In first 6 packets, writer 1 (weight 2) should have ~4, writer 2 ~2
        assert!(w1_count >= 3, "w1 should get at least 3, got {}", w1_count);
        assert!(w2_count >= 1, "w2 should get at least 1, got {}", w2_count);
    }

    #[test]
    fn test_wfq_unknown_writer() {
        let mut scheduler: WfqScheduler<u8> = WfqScheduler::new();

        let result = scheduler.enqueue(999, 1, 100);
        assert_eq!(result, Err(WfqError::UnknownWriter));
    }

    #[test]
    fn test_wfq_queue_full() {
        let mut scheduler: WfqScheduler<u8> = WfqScheduler::with_max_queue(2);
        scheduler.add_writer(1, 1.0);

        scheduler.enqueue(1, 1, 100).unwrap();
        scheduler.enqueue(1, 2, 100).unwrap();

        let result = scheduler.enqueue(1, 3, 100);
        assert_eq!(result, Err(WfqError::QueueFull));
    }

    #[test]
    fn test_wfq_set_weight() {
        let mut scheduler: WfqScheduler<u8> = WfqScheduler::new();
        scheduler.add_writer(1, 1.0);

        assert_eq!(scheduler.get_weight(1), Some(1.0));

        scheduler.set_weight(1, 3.0);
        assert_eq!(scheduler.get_weight(1), Some(3.0));

        // Unknown writer
        assert!(!scheduler.set_weight(999, 1.0));
    }

    #[test]
    fn test_wfq_stats() {
        let mut scheduler: WfqScheduler<u8> = WfqScheduler::new();
        scheduler.add_writer(1, 1.0);

        scheduler.enqueue(1, 1, 100).unwrap();
        scheduler.enqueue(1, 2, 200).unwrap();

        let stats = scheduler.stats();
        assert_eq!(stats.total_packets, 2);
        assert_eq!(stats.total_bytes, 300);

        scheduler.dequeue();
        let stats2 = scheduler.stats();
        assert!(stats2.virtual_time > 0.0);
    }

    #[test]
    fn test_wfq_drain_writer() {
        let mut scheduler: WfqScheduler<u8> = WfqScheduler::new();
        scheduler.add_writer(1, 1.0);
        scheduler.add_writer(2, 1.0);

        scheduler.enqueue(1, 1, 100).unwrap();
        scheduler.enqueue(2, 2, 100).unwrap();
        scheduler.enqueue(1, 3, 100).unwrap();

        let drained = scheduler.drain_writer(1);
        assert_eq!(drained.len(), 2);
        assert!(drained.contains(&1));
        assert!(drained.contains(&3));

        // Only writer 2's packet remains
        assert_eq!(scheduler.len(), 1);
        let p = scheduler.dequeue().unwrap();
        assert_eq!(p.writer_id, 2);
    }

    #[test]
    fn test_wfq_reset_virtual_time() {
        let mut scheduler: WfqScheduler<u8> = WfqScheduler::new();
        scheduler.add_writer(1, 1.0);

        scheduler.enqueue(1, 1, 100).unwrap();
        scheduler.dequeue();

        assert!(scheduler.stats().virtual_time > 0.0);

        // Reset only works when queue is empty
        scheduler.reset_virtual_time();
        assert_eq!(scheduler.stats().virtual_time, 0.0);
    }

    #[test]
    fn test_priority_wfq_basic() {
        let mut scheduler: PriorityWfqScheduler<u8> = PriorityWfqScheduler::new();

        scheduler.add_writer(1, 0, 1.0); // P0
        scheduler.add_writer(2, 1, 1.0); // P1
        scheduler.add_writer(3, 2, 1.0); // P2

        // Enqueue in reverse priority order
        scheduler.enqueue(3, 2, 30, 100).unwrap(); // P2
        scheduler.enqueue(2, 1, 20, 100).unwrap(); // P1
        scheduler.enqueue(1, 0, 10, 100).unwrap(); // P0

        // Should dequeue in priority order: P0, P1, P2
        let (p, packet) = scheduler.dequeue().unwrap();
        assert_eq!(p, 0);
        assert_eq!(packet.data, 10);

        let (p, packet) = scheduler.dequeue().unwrap();
        assert_eq!(p, 1);
        assert_eq!(packet.data, 20);

        let (p, packet) = scheduler.dequeue().unwrap();
        assert_eq!(p, 2);
        assert_eq!(packet.data, 30);
    }

    #[test]
    fn test_priority_wfq_len() {
        let mut scheduler: PriorityWfqScheduler<u8> = PriorityWfqScheduler::new();

        scheduler.add_writer(1, 0, 1.0);
        scheduler.add_writer(2, 1, 1.0);
        scheduler.add_writer(3, 2, 1.0);

        scheduler.enqueue(1, 0, 1, 100).unwrap();
        scheduler.enqueue(2, 1, 2, 100).unwrap();
        scheduler.enqueue(2, 1, 3, 100).unwrap();
        scheduler.enqueue(3, 2, 4, 100).unwrap();

        assert_eq!(scheduler.len(), 4);
        assert_eq!(scheduler.len_by_priority(), (1, 2, 1));
    }

    #[test]
    fn test_wfq_minimum_weight() {
        let mut scheduler: WfqScheduler<u8> = WfqScheduler::new();

        // Very small weight should be clamped to minimum
        scheduler.add_writer(1, 0.001);

        // Should not panic or cause issues
        scheduler.enqueue(1, 1, 100).unwrap();
        let p = scheduler.dequeue().unwrap();
        assert_eq!(p.data, 1);

        // Weight should be at least 0.1
        let weight = scheduler.get_weight(1).unwrap();
        assert!(weight >= 0.1);
    }

    #[test]
    fn test_wfq_different_packet_sizes() {
        let mut scheduler: WfqScheduler<&str> = WfqScheduler::new();

        scheduler.add_writer(1, 1.0);
        scheduler.add_writer(2, 1.0);

        // Writer 1 sends small packets
        scheduler.enqueue(1, "small1", 10).unwrap();
        scheduler.enqueue(1, "small2", 10).unwrap();

        // Writer 2 sends one large packet
        scheduler.enqueue(2, "large", 100).unwrap();

        // Small packets should finish before large packet
        let p1 = scheduler.dequeue().unwrap();
        assert_eq!(p1.data, "small1");
        assert_eq!(p1.finish_time(), 10.0);

        let p2 = scheduler.dequeue().unwrap();
        assert_eq!(p2.data, "small2");
        assert_eq!(p2.finish_time(), 20.0);

        let p3 = scheduler.dequeue().unwrap();
        assert_eq!(p3.data, "large");
        assert_eq!(p3.finish_time(), 100.0);
    }

    #[test]
    fn test_wfq_writer_becomes_inactive() {
        let mut scheduler: WfqScheduler<u8> = WfqScheduler::new();
        scheduler.add_writer(1, 1.0);

        scheduler.enqueue(1, 1, 100).unwrap();

        {
            let writer = scheduler.writer_stats(1).unwrap();
            assert!(writer.active);
        }

        scheduler.dequeue();

        {
            let writer = scheduler.writer_stats(1).unwrap();
            assert!(!writer.active);
        }
    }

    #[test]
    fn test_wfq_reactivation() {
        let mut scheduler: WfqScheduler<u8> = WfqScheduler::new();
        scheduler.add_writer(1, 1.0);

        // First batch
        scheduler.enqueue(1, 1, 100).unwrap();
        scheduler.dequeue();

        // Writer should be inactive
        assert!(!scheduler.writer_stats(1).unwrap().active);

        // Second batch - should reactivate from current virtual time
        scheduler.enqueue(1, 2, 100).unwrap();
        assert!(scheduler.writer_stats(1).unwrap().active);

        let p = scheduler.dequeue().unwrap();
        // Finish time should be relative to when it was reactivated
        assert!(p.finish_time() >= 100.0);
    }
}
