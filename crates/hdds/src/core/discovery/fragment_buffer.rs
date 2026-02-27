// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Fragment reassembly buffer for RTPS DATA_FRAG submessages.
//!
//
// RTI Connext sends large discovery messages (SPDP, SEDP) as fragmented DATA_FRAG
// packets. Fragments can arrive out-of-order or some may be missing. This module
// implements a production-grade fragment buffer with:
//
// - Out-of-order fragment reassembly
// - Timeout-based eviction for incomplete sequences
// - LRU eviction when buffer is full
// - Memory-bounded operation (max 256 sequences by default)
//
// RTPS v2.3 spec Sec.8.3.7.4: DATA_FRAG Submessage

use crate::core::discovery::GUID;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// Fragment reassembly buffer.
///
/// Buffers incoming DATA_FRAG fragments by (writerGUID, seqNum) and reassembles
/// them into complete payloads when all fragments are received.
///
/// # Memory Management
///
/// - `max_pending`: Maximum number of incomplete sequences (default: 256)
/// - `timeout_ms`: Evict incomplete sequences after this duration (default: 500ms)
///
/// When `max_pending` is reached, the oldest sequence is evicted (LRU).
///
/// # Usage
///
/// ```ignore
/// let mut buffer = FragmentBuffer::new(256, 500);
///
/// // Insert fragment #3
/// let result = buffer.insert_fragment(writer_guid, seq_num, 3, 4, fragment3_data);
/// assert!(result.is_none()); // Incomplete
///
/// // Insert fragment #1
/// let result = buffer.insert_fragment(writer_guid, seq_num, 1, 4, fragment1_data);
/// assert!(result.is_none()); // Still incomplete
///
/// // Insert fragment #2 and #4
/// buffer.insert_fragment(writer_guid, seq_num, 2, 4, fragment2_data);
/// let result = buffer.insert_fragment(writer_guid, seq_num, 4, 4, fragment4_data);
///
/// // Complete! Returns reassembled payload
/// assert!(result.is_some());
/// let complete_payload = result.unwrap();
/// ```
pub struct FragmentBuffer {
    /// Pending incomplete sequences: (writerGUID, seqNum) -> FragmentSet
    pending: HashMap<(GUID, u64), FragmentSet>,

    /// Maximum number of pending sequences (LRU eviction when exceeded)
    max_pending: usize,

    /// Timeout in milliseconds for incomplete sequences
    timeout_ms: u64,
}

/// A set of fragments for a specific (writerGUID, seqNum) sequence.
struct FragmentSet {
    /// Fragment data indexed by fragment number (1-based)
    fragments: HashMap<u32, Vec<u8>>,

    /// Total number of fragments expected (from fragmentsInSubmessage field)
    total_fragments: u16,

    /// Timestamp when first fragment was received (for timeout)
    first_seen: Instant,

    /// Timestamp when last fragment was received (for LRU eviction)
    last_updated: Instant,

    /// Source address for NACK_FRAG responses
    source_addr: Option<SocketAddr>,
}

impl FragmentBuffer {
    /// Create a new fragment buffer.
    ///
    /// # Arguments
    ///
    /// - `max_pending`: Maximum number of incomplete sequences (typical: 256)
    /// - `timeout_ms`: Evict incomplete sequences after this duration (typical: 100-500ms)
    ///
    /// # Memory Bound
    ///
    /// Worst case: `max_pending x average_fragments x fragment_size`
    /// Example: 256 sequences x 4 fragments x 1KB = ~1MB
    pub fn new(max_pending: usize, timeout_ms: u64) -> Self {
        Self {
            pending: HashMap::with_capacity(max_pending),
            max_pending,
            timeout_ms,
        }
    }

    /// Insert a fragment and attempt reassembly.
    ///
    /// # Arguments
    ///
    /// - `writer_guid`: RTPS GUID of the writer that sent this fragment
    /// - `seq_num`: Sequence number (all fragments of same message share this)
    /// - `frag_num`: Fragment number (1-based, from fragmentStartingNum)
    /// - `total_frags`: Total fragments in message (from fragmentsInSubmessage)
    /// - `data`: Fragment payload (raw bytes)
    ///
    /// # Returns
    ///
    /// - `Some(Vec<u8>)`: Complete reassembled payload (all fragments received)
    /// - `None`: Still waiting for more fragments
    ///
    /// # Example
    ///
    /// ```ignore
    /// let payload = buffer.insert_fragment(guid, 1, 3, 4, frag3_data);
    /// if let Some(complete) = payload {
    ///     // All fragments received, parse complete message
    ///     parse_spdp(&complete)?;
    /// }
    /// ```
    pub fn insert_fragment(
        &mut self,
        writer_guid: GUID,
        seq_num: u64,
        frag_num: u32,
        total_frags: u16,
        data: Vec<u8>,
    ) -> Option<Vec<u8>> {
        self.insert_fragment_with_addr(writer_guid, seq_num, frag_num, total_frags, data, None)
    }

    /// Insert a fragment with source address tracking for NACK_FRAG responses.
    pub fn insert_fragment_with_addr(
        &mut self,
        writer_guid: GUID,
        seq_num: u64,
        frag_num: u32,
        total_frags: u16,
        data: Vec<u8>,
        source_addr: Option<SocketAddr>,
    ) -> Option<Vec<u8>> {
        let key = (writer_guid, seq_num);
        let now = Instant::now();

        // Get or create FragmentSet for this sequence
        let frag_set = self.pending.entry(key).or_insert_with(|| FragmentSet {
            fragments: HashMap::new(),
            total_fragments: total_frags,
            first_seen: now,
            last_updated: now,
            source_addr: None,
        });

        // Update source address if provided
        if source_addr.is_some() {
            frag_set.source_addr = source_addr;
        }

        // Update timestamp for LRU
        frag_set.last_updated = now;

        // Update total_fragments if this fragment has a different value
        // (should be consistent, but use the latest value we see)
        if frag_set.total_fragments != total_frags {
            log::debug!(
                "[FragBuf] [!]  GUID={:?} seqNum={} total_fragments mismatch: was {}, now {}",
                writer_guid,
                seq_num,
                frag_set.total_fragments,
                total_frags
            );
            frag_set.total_fragments = total_frags;
        }

        // Insert fragment (overwrites if duplicate)
        frag_set.fragments.insert(frag_num, data);

        log::debug!(
            "[FragBuf] GUID={:?} seqNum={} frag={}/{} stored ({} fragments buffered)",
            writer_guid,
            seq_num,
            frag_num,
            total_frags,
            frag_set.fragments.len()
        );

        // Check if complete
        if frag_set.fragments.len() == total_frags as usize {
            // All fragments received! Reassemble and remove from pending
            log::debug!(
                "[FragBuf] [OK] COMPLETE! GUID={:?} seqNum={} ({} fragments)",
                writer_guid,
                seq_num,
                total_frags
            );

            // Remove from pending and reassemble
            // SAFETY: We just checked that fragments.len() == total_frags, so the key must exist
            if let Some(frag_set) = self.pending.remove(&key) {
                let complete = Self::reassemble_static(&frag_set);
                Some(complete)
            } else {
                // This should never happen since we just verified len() == total_frags
                log::debug!(
                    "[FragBuf] [!]  INTERNAL ERROR: FragmentSet disappeared after len check!"
                );
                None
            }
        } else {
            // Still incomplete, check if we need to evict old sequences
            if self.pending.len() > self.max_pending {
                self.evict_lru();
            }
            None
        }
    }

    /// Reassemble fragments into a complete payload.
    ///
    /// Fragments are concatenated in order: frag#1 + frag#2 + ... + frag#N.
    ///
    /// Note: Fragment #1 typically includes the encapsulation header (4 bytes)
    /// that other fragments don't have.
    fn reassemble_static(frag_set: &FragmentSet) -> Vec<u8> {
        let total_size: usize = frag_set.fragments.values().map(|v| v.len()).sum();
        let mut payload = Vec::with_capacity(total_size);

        // Concatenate fragments in order (1, 2, 3, ...)
        for frag_num in 1..=frag_set.total_fragments {
            if let Some(data) = frag_set.fragments.get(&(frag_num as u32)) {
                payload.extend_from_slice(data);
            } else {
                log::debug!(
                    "[FragBuf] [!]  Missing fragment #{} during reassembly (should not happen!)",
                    frag_num
                );
            }
        }

        log::debug!(
            "[FragBuf] Reassembled {} bytes from {} fragments",
            payload.len(),
            frag_set.total_fragments
        );
        payload
    }

    /// Evict expired incomplete sequences (timeout-based cleanup).
    ///
    /// Call this periodically (e.g., every 100ms) to free memory from
    /// sequences that will never complete.
    ///
    /// # Returns
    ///
    /// Number of sequences evicted.
    pub fn evict_expired(&mut self) -> usize {
        let now = Instant::now();
        let timeout = Duration::from_millis(self.timeout_ms);
        let mut evicted = 0;

        self.pending.retain(|(guid, seq_num), frag_set| {
            let age = now.duration_since(frag_set.first_seen);
            if age > timeout {
                log::debug!(
                    "[FragBuf] [time]  TIMEOUT EVICT: GUID={:?} seqNum={} ({}/{} fragments after {:?})",
                    guid,
                    seq_num,
                    frag_set.fragments.len(),
                    frag_set.total_fragments,
                    age
                );
                evicted += 1;
                false // Remove from pending
            } else {
                true // Keep
            }
        });

        // Shrink capacity to avoid memory accumulation over time
        if evicted > 0 {
            self.pending.shrink_to_fit();
        }

        evicted
    }

    /// Evict the oldest sequence (LRU) to make room for new fragments.
    ///
    /// Called automatically when `pending.len() > max_pending`.
    fn evict_lru(&mut self) {
        // Find oldest (minimum last_updated timestamp)
        let oldest_key = self
            .pending
            .iter()
            .min_by_key(|(_, frag_set)| frag_set.last_updated)
            .map(|(key, _)| *key);

        if let Some(key) = oldest_key {
            if let Some(frag_set) = self.pending.remove(&key) {
                log::debug!(
                    "[FragBuf] [*]  LRU EVICT: GUID={:?} seqNum={} ({}/{} fragments, age={:?})",
                    key.0,
                    key.1,
                    frag_set.fragments.len(),
                    frag_set.total_fragments,
                    Instant::now().duration_since(frag_set.first_seen)
                );
            }
        }
    }

    /// Get current number of pending incomplete sequences (for monitoring).
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Get missing fragment numbers for a specific (writerGUID, seqNum).
    ///
    /// Returns a list of fragment numbers (1-based) that haven't been received yet.
    /// Used to construct NACK_FRAG submessages for reliable fragmented data.
    ///
    /// # Returns
    ///
    /// - `Some((missing, total))`: List of missing fragment numbers and total expected
    /// - `None`: No such sequence in buffer (either complete or never seen)
    pub fn get_missing_fragments(
        &self,
        writer_guid: &GUID,
        seq_num: u64,
    ) -> Option<(Vec<u32>, u16)> {
        let key = (*writer_guid, seq_num);
        let frag_set = self.pending.get(&key)?;

        let mut missing = Vec::new();
        for frag_num in 1..=frag_set.total_fragments {
            if !frag_set.fragments.contains_key(&(frag_num as u32)) {
                missing.push(frag_num as u32);
            }
        }

        Some((missing, frag_set.total_fragments))
    }

    /// Get all incomplete sequences that have been waiting longer than `min_age_ms`.
    ///
    /// Used to decide which sequences need NACK_FRAG retransmission requests.
    ///
    /// # Returns
    ///
    /// List of (writerGUID, seqNum, missing_count, total_fragments, age_ms)
    /// Returns: Vec of (GUID, seq_num, missing_count, total_frags, age_ms, source_addr)
    pub fn get_stale_sequences(
        &self,
        min_age_ms: u64,
    ) -> Vec<(GUID, u64, usize, u16, u64, Option<SocketAddr>)> {
        let now = Instant::now();
        let min_age = Duration::from_millis(min_age_ms);

        self.pending
            .iter()
            .filter_map(|((guid, seq_num), frag_set)| {
                let age = now.duration_since(frag_set.first_seen);
                if age >= min_age {
                    let missing_count =
                        frag_set.total_fragments as usize - frag_set.fragments.len();
                    Some((
                        *guid,
                        *seq_num,
                        missing_count,
                        frag_set.total_fragments,
                        age.as_millis() as u64,
                        frag_set.source_addr,
                    ))
                } else {
                    None
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fragment_buffer_in_order() {
        let mut buffer = FragmentBuffer::new(256, 500);
        let guid = GUID::from_bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);

        // Insert fragments in order
        let r1 = buffer.insert_fragment(guid, 1, 1, 3, vec![0xAA, 0xBB]);
        assert!(r1.is_none());

        let r2 = buffer.insert_fragment(guid, 1, 2, 3, vec![0xCC, 0xDD]);
        assert!(r2.is_none());

        let r3 = buffer.insert_fragment(guid, 1, 3, 3, vec![0xEE, 0xFF]);
        assert!(r3.is_some());

        let complete = r3.expect("Should return complete payload after inserting final fragment");
        assert_eq!(complete, vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    }

    #[test]
    fn test_fragment_buffer_out_of_order() {
        let mut buffer = FragmentBuffer::new(256, 500);
        let guid = GUID::from_bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);

        // Insert fragment #3 first (like RTI does!)
        let r3 = buffer.insert_fragment(guid, 1, 3, 4, vec![0xEE, 0xFF]);
        assert!(r3.is_none());

        // Insert fragment #1
        let r1 = buffer.insert_fragment(guid, 1, 1, 4, vec![0xAA, 0xBB]);
        assert!(r1.is_none());

        // Insert fragment #4
        let r4 = buffer.insert_fragment(guid, 1, 4, 4, vec![0x11, 0x22]);
        assert!(r4.is_none());

        // Insert fragment #2 (last one)
        let r2 = buffer.insert_fragment(guid, 1, 2, 4, vec![0xCC, 0xDD]);
        assert!(r2.is_some());

        let complete = r2.expect("Should return complete payload after out-of-order reassembly");
        assert_eq!(
            complete,
            vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22]
        );
    }

    #[test]
    fn test_timeout_eviction() {
        let mut buffer = FragmentBuffer::new(256, 100); // 100ms timeout
        let guid = GUID::from_bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);

        // Insert partial sequence
        buffer.insert_fragment(guid, 1, 1, 3, vec![0xAA]);
        assert_eq!(buffer.pending_count(), 1);

        // Wait for timeout
        std::thread::sleep(std::time::Duration::from_millis(150));

        // Evict expired
        let evicted = buffer.evict_expired();
        assert_eq!(evicted, 1);
        assert_eq!(buffer.pending_count(), 0);
    }

    #[test]
    fn test_lru_eviction() {
        let mut buffer = FragmentBuffer::new(2, 500); // Max 2 sequences
        let guid = GUID::from_bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);

        // Fill buffer
        buffer.insert_fragment(guid, 1, 1, 2, vec![0xAA]);
        buffer.insert_fragment(guid, 2, 1, 2, vec![0xBB]);
        assert_eq!(buffer.pending_count(), 2);

        // Insert 3rd sequence -> should evict oldest (seqNum=1)
        buffer.insert_fragment(guid, 3, 1, 2, vec![0xCC]);
        assert_eq!(buffer.pending_count(), 2);

        // Verify seqNum=1 was evicted
        assert!(!buffer.pending.contains_key(&(guid, 1)));
        assert!(buffer.pending.contains_key(&(guid, 2)));
        assert!(buffer.pending.contains_key(&(guid, 3)));
    }

    #[test]
    fn test_get_missing_fragments() {
        let mut buffer = FragmentBuffer::new(256, 500);
        let guid = GUID::from_bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);

        // Insert fragments 1 and 3 (missing 2 and 4)
        buffer.insert_fragment(guid, 1, 1, 4, vec![0xAA]);
        buffer.insert_fragment(guid, 1, 3, 4, vec![0xCC]);

        let result = buffer.get_missing_fragments(&guid, 1);
        assert!(result.is_some());

        let (missing, total) = result.unwrap();
        assert_eq!(total, 4);
        assert_eq!(missing, vec![2, 4]); // Missing fragments 2 and 4
    }

    #[test]
    fn test_get_missing_fragments_not_found() {
        let buffer = FragmentBuffer::new(256, 500);
        let guid = GUID::from_bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);

        // No fragments inserted - should return None
        let result = buffer.get_missing_fragments(&guid, 99);
        assert!(result.is_none());
    }

    #[test]
    fn test_get_stale_sequences() {
        let mut buffer = FragmentBuffer::new(256, 500);
        let guid = GUID::from_bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);

        // Insert partial sequence
        buffer.insert_fragment(guid, 1, 1, 4, vec![0xAA]);
        buffer.insert_fragment(guid, 1, 2, 4, vec![0xBB]);

        // Not stale yet (0ms threshold)
        let stale = buffer.get_stale_sequences(0);
        assert_eq!(stale.len(), 1);
        assert_eq!(stale[0].0, guid); // GUID
        assert_eq!(stale[0].1, 1); // seq_num
        assert_eq!(stale[0].2, 2); // missing_count (fragments 3, 4)
        assert_eq!(stale[0].3, 4); // total_fragments

        // Wait and check again with high threshold - should be empty
        let stale = buffer.get_stale_sequences(10000);
        assert_eq!(stale.len(), 0);
    }
}
