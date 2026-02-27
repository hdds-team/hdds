// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Packet fragmentation for LoRa transport
//!
//! LoRa has a 255-byte maximum packet size. This module provides
//! fragmentation and reassembly for larger RTPS messages.
//!
//! ## Fragment Header Format
//!
//! ```text
//! +--------+--------+--------+--------+
//! | src_id | msg_seq| frag_id|total_fr|
//! +--------+--------+--------+--------+
//!     1B       1B       1B       1B
//! ```
//!
//! - `src_node`: Source node ID (0-255)
//! - `msg_seq`: Message sequence number (0-255)
//! - `frag_idx`: Fragment index (0 = first, 255 = single packet)
//! - `total_frags`: Total fragments (1-255, or 0 for single packet marker)

use crate::error::{Error, Result};

/// Maximum number of fragments we can reassemble
const MAX_FRAGMENTS: usize = 16;

/// Maximum payload per fragment (255 - 4 header bytes)
const MAX_FRAGMENT_PAYLOAD: usize = 251;

/// Maximum reassembled message size (16 fragments * 251 bytes payload)
const MAX_MESSAGE_SIZE: usize = MAX_FRAGMENTS * MAX_FRAGMENT_PAYLOAD;

/// Fragment header size in bytes
pub const FRAGMENT_HEADER_SIZE: usize = 4;

/// Fragment header
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FragmentHeader {
    /// Source node ID
    pub src_node: u8,
    /// Message sequence number
    pub msg_seq: u8,
    /// Fragment index (255 = single unfragmented packet)
    pub frag_idx: u8,
    /// Total number of fragments (0 = single packet)
    pub total_frags: u8,
}

impl FragmentHeader {
    /// Header size in bytes
    pub const SIZE: usize = FRAGMENT_HEADER_SIZE;

    /// Create header for a single (unfragmented) packet
    pub const fn single(src_node: u8, msg_seq: u8) -> Self {
        Self {
            src_node,
            msg_seq,
            frag_idx: 255,
            total_frags: 0,
        }
    }

    /// Create header for a fragment
    pub const fn fragment(src_node: u8, msg_seq: u8, frag_idx: u8, total_frags: u8) -> Self {
        Self {
            src_node,
            msg_seq,
            frag_idx,
            total_frags,
        }
    }

    /// Check if this is a single (unfragmented) packet
    pub const fn is_single(&self) -> bool {
        self.frag_idx == 255 && self.total_frags == 0
    }

    /// Check if this is the first fragment
    pub const fn is_first(&self) -> bool {
        self.frag_idx == 0
    }

    /// Check if this is the last fragment
    pub const fn is_last(&self) -> bool {
        self.total_frags > 0 && self.frag_idx + 1 == self.total_frags
    }

    /// Encode header into buffer
    ///
    /// # Returns
    ///
    /// Number of bytes written (always 4)
    pub fn encode(&self, buf: &mut [u8]) -> Result<usize> {
        if buf.len() < Self::SIZE {
            return Err(Error::BufferTooSmall);
        }

        buf[0] = self.src_node;
        buf[1] = self.msg_seq;
        buf[2] = self.frag_idx;
        buf[3] = self.total_frags;

        Ok(Self::SIZE)
    }

    /// Decode header from buffer
    pub fn decode(buf: &[u8]) -> Result<Self> {
        if buf.len() < Self::SIZE {
            return Err(Error::BufferTooSmall);
        }

        Ok(Self {
            src_node: buf[0],
            msg_seq: buf[1],
            frag_idx: buf[2],
            total_frags: buf[3],
        })
    }
}

/// State of a message being reassembled
///
/// Uses fixed-size slots for each fragment, allowing out-of-order arrival.
/// When complete, data is compacted into a contiguous buffer.
#[derive(Debug)]
struct ReassemblyState {
    /// Source node ID
    src_node: u8,
    /// Message sequence number
    msg_seq: u8,
    /// Expected total fragments
    total_frags: u8,
    /// Received fragment bitmap (up to 16 fragments)
    received_mask: u16,
    /// Fragment slots (each can hold up to MAX_FRAGMENT_PAYLOAD bytes)
    slots: [[u8; MAX_FRAGMENT_PAYLOAD]; MAX_FRAGMENTS],
    /// Fragment payload sizes (actual data length in each slot)
    slot_sizes: [u8; MAX_FRAGMENTS],
    /// Compacted output buffer (filled when complete)
    output: [u8; MAX_MESSAGE_SIZE],
    /// Output data length
    output_len: usize,
}

impl ReassemblyState {
    fn new() -> Self {
        Self {
            src_node: 0,
            msg_seq: 0,
            total_frags: 0,
            received_mask: 0,
            slots: [[0u8; MAX_FRAGMENT_PAYLOAD]; MAX_FRAGMENTS],
            slot_sizes: [0u8; MAX_FRAGMENTS],
            output: [0u8; MAX_MESSAGE_SIZE],
            output_len: 0,
        }
    }

    fn reset(&mut self, src_node: u8, msg_seq: u8, total_frags: u8) {
        self.src_node = src_node;
        self.msg_seq = msg_seq;
        self.total_frags = total_frags;
        self.received_mask = 0;
        self.slot_sizes = [0u8; MAX_FRAGMENTS];
        self.output_len = 0;
    }

    fn matches(&self, src_node: u8, msg_seq: u8) -> bool {
        self.src_node == src_node && self.msg_seq == msg_seq && self.total_frags > 0
    }

    fn add_fragment(&mut self, frag_idx: u8, payload: &[u8]) -> bool {
        if frag_idx as usize >= MAX_FRAGMENTS {
            return false;
        }

        if payload.len() > MAX_FRAGMENT_PAYLOAD {
            return false;
        }

        let mask = 1u16 << frag_idx;

        // Already received this fragment?
        if self.received_mask & mask != 0 {
            return self.is_complete();
        }

        // Store fragment in its slot
        let slot_idx = frag_idx as usize;
        self.slots[slot_idx][..payload.len()].copy_from_slice(payload);
        self.slot_sizes[slot_idx] = payload.len() as u8;
        self.received_mask |= mask;

        // Check if complete
        if self.is_complete() {
            // Compact all fragments into output buffer
            self.compact();
            true
        } else {
            false
        }
    }

    fn is_complete(&self) -> bool {
        if self.total_frags == 0 {
            return false;
        }

        // Check if we have all fragments
        let expected_mask = (1u16 << self.total_frags) - 1;
        self.received_mask == expected_mask
    }

    /// Compact all fragments into contiguous output buffer
    fn compact(&mut self) {
        let mut offset = 0;
        for i in 0..self.total_frags as usize {
            let size = self.slot_sizes[i] as usize;
            self.output[offset..offset + size].copy_from_slice(&self.slots[i][..size]);
            offset += size;
        }
        self.output_len = offset;
    }

    fn get_data(&self) -> &[u8] {
        &self.output[..self.output_len]
    }
}

/// Fragment assembler for incoming packets
///
/// Handles reassembly of fragmented RTPS messages.
/// Uses a simple single-slot cache (one message at a time per source).
pub struct FragmentAssembler {
    /// Reassembly states (one per source, simple LRU)
    states: [ReassemblyState; 4],
    /// Next slot to use (round-robin)
    next_slot: usize,
}

impl FragmentAssembler {
    /// Create a new fragment assembler
    pub fn new() -> Self {
        Self {
            states: [
                ReassemblyState::new(),
                ReassemblyState::new(),
                ReassemblyState::new(),
                ReassemblyState::new(),
            ],
            next_slot: 0,
        }
    }

    /// Add a fragment and return complete message if ready
    ///
    /// # Arguments
    ///
    /// * `header` - Fragment header
    /// * `payload` - Fragment payload (without header)
    ///
    /// # Returns
    ///
    /// Complete message data if all fragments received, None otherwise
    pub fn add_fragment(
        &mut self,
        header: &FragmentHeader,
        payload: &[u8],
    ) -> Result<Option<&[u8]>> {
        if header.is_single() {
            // Single packet - shouldn't go through assembler
            return Err(Error::InvalidParameter);
        }

        if header.total_frags as usize > MAX_FRAGMENTS {
            return Err(Error::BufferTooSmall);
        }

        // Find existing state for this message
        let slot = self.find_or_create_slot(header.src_node, header.msg_seq, header.total_frags);

        // Add fragment to state
        if self.states[slot].add_fragment(header.frag_idx, payload) {
            // Complete! Return the data
            Ok(Some(self.states[slot].get_data()))
        } else {
            Ok(None)
        }
    }

    /// Find existing slot or create new one
    fn find_or_create_slot(&mut self, src_node: u8, msg_seq: u8, total_frags: u8) -> usize {
        // Look for existing state
        for (i, state) in self.states.iter().enumerate() {
            if state.matches(src_node, msg_seq) {
                return i;
            }
        }

        // Not found, use next slot (round-robin eviction)
        let slot = self.next_slot;
        self.next_slot = (self.next_slot + 1) % self.states.len();

        // Reset slot for new message
        self.states[slot].reset(src_node, msg_seq, total_frags);

        slot
    }

    /// Clear all reassembly state
    pub fn clear(&mut self) {
        for state in &mut self.states {
            state.reset(0, 0, 0);
        }
        self.next_slot = 0;
    }
}

impl Default for FragmentAssembler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fragment_header_single() {
        let header = FragmentHeader::single(42, 5);
        assert!(header.is_single());
        assert!(!header.is_first());
        assert!(!header.is_last());
    }

    #[test]
    fn test_fragment_header_fragment() {
        let header = FragmentHeader::fragment(42, 5, 0, 3);
        assert!(!header.is_single());
        assert!(header.is_first());
        assert!(!header.is_last());

        let header = FragmentHeader::fragment(42, 5, 2, 3);
        assert!(!header.is_single());
        assert!(!header.is_first());
        assert!(header.is_last());
    }

    #[test]
    fn test_fragment_header_encode_decode() {
        let header = FragmentHeader::fragment(42, 5, 1, 3);

        let mut buf = [0u8; 8];
        let len = header.encode(&mut buf).unwrap();
        assert_eq!(len, 4);

        let decoded = FragmentHeader::decode(&buf).unwrap();
        assert_eq!(decoded, header);
    }

    #[test]
    fn test_assembler_single_message() {
        let mut assembler = FragmentAssembler::new();

        // 3 fragments
        let h0 = FragmentHeader::fragment(1, 0, 0, 3);
        let h1 = FragmentHeader::fragment(1, 0, 1, 3);
        let h2 = FragmentHeader::fragment(1, 0, 2, 3);

        let p0 = b"Hello";
        let p1 = b", ";
        let p2 = b"World!";

        // Add fragments
        assert!(assembler.add_fragment(&h0, p0).unwrap().is_none());
        assert!(assembler.add_fragment(&h1, p1).unwrap().is_none());

        // Last fragment completes the message
        let result = assembler.add_fragment(&h2, p2).unwrap();
        assert!(result.is_some());

        let data = result.unwrap();
        assert_eq!(data, b"Hello, World!");
    }

    #[test]
    fn test_assembler_out_of_order() {
        let mut assembler = FragmentAssembler::new();

        let h0 = FragmentHeader::fragment(1, 0, 0, 3);
        let h1 = FragmentHeader::fragment(1, 0, 1, 3);
        let h2 = FragmentHeader::fragment(1, 0, 2, 3);

        // Add out of order: 2, 0, 1
        assert!(assembler.add_fragment(&h2, b"C").unwrap().is_none());
        assert!(assembler.add_fragment(&h0, b"A").unwrap().is_none());

        // Last one completes
        let result = assembler.add_fragment(&h1, b"B").unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap(), b"ABC");
    }

    #[test]
    fn test_assembler_duplicate_fragment() {
        let mut assembler = FragmentAssembler::new();

        let h0 = FragmentHeader::fragment(1, 0, 0, 2);
        let h1 = FragmentHeader::fragment(1, 0, 1, 2);

        // Add first fragment twice
        assert!(assembler.add_fragment(&h0, b"A").unwrap().is_none());
        assert!(assembler.add_fragment(&h0, b"A").unwrap().is_none());

        // Complete with second fragment
        let result = assembler.add_fragment(&h1, b"B").unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap(), b"AB");
    }

    #[test]
    fn test_assembler_multiple_messages() {
        let mut assembler = FragmentAssembler::new();

        // Two different messages from same source
        let h0_m0 = FragmentHeader::fragment(1, 0, 0, 2);
        let h1_m0 = FragmentHeader::fragment(1, 0, 1, 2);

        let h0_m1 = FragmentHeader::fragment(1, 1, 0, 2);
        let h1_m1 = FragmentHeader::fragment(1, 1, 1, 2);

        // Interleave fragments
        assert!(assembler.add_fragment(&h0_m0, b"A0").unwrap().is_none());
        assert!(assembler.add_fragment(&h0_m1, b"B0").unwrap().is_none());

        // Complete message 0
        let result = assembler.add_fragment(&h1_m0, b"A1").unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap(), b"A0A1");

        // Complete message 1
        let result = assembler.add_fragment(&h1_m1, b"B1").unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap(), b"B0B1");
    }

    #[test]
    fn test_assembler_clear() {
        let mut assembler = FragmentAssembler::new();

        let h0 = FragmentHeader::fragment(1, 0, 0, 2);
        assembler.add_fragment(&h0, b"data").unwrap();

        assembler.clear();

        // After clear, we start fresh
        let h0 = FragmentHeader::fragment(1, 0, 0, 2);
        let h1 = FragmentHeader::fragment(1, 0, 1, 2);

        assert!(assembler.add_fragment(&h0, b"X").unwrap().is_none());
        let result = assembler.add_fragment(&h1, b"Y").unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap(), b"XY");
    }

    #[test]
    fn test_fragment_header_buffer_too_small() {
        let header = FragmentHeader::single(1, 1);
        let mut buf = [0u8; 2]; // Too small
        assert_eq!(header.encode(&mut buf), Err(Error::BufferTooSmall));

        let buf = [0u8; 2]; // Too small
        assert_eq!(FragmentHeader::decode(&buf), Err(Error::BufferTooSmall));
    }
}
