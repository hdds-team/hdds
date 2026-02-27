// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Fragmentation and reassembly for LBW transport.
//!
//! When a record payload exceeds the MTU, it must be fragmented into
//! multiple smaller records. This module handles:
//!
//! - **Fragmentation**: Split large payloads into MTU-sized fragments
//! - **Reassembly**: Reconstruct original payload from fragments
//! - **Timeout**: Clean up incomplete fragment groups
//! - **Memory bounds**: Limit pending reassembly buffers
//!
//! # Fragment Header
//!
//! Each fragment record contains a header in its payload:
//!
//! ```text
//! FragHeader = group_id(varint) | frag_idx(varint) | frag_cnt(varint) | orig_len(varint)
//! ```
//!
//! - `group_id`: Message sequence identifying this fragment group
//! - `frag_idx`: Fragment index (0 to frag_cnt-1)
//! - `frag_cnt`: Total number of fragments
//! - `orig_len`: Original payload length (for validation)
//!
//! # Usage
//!
//! ## Sender Side
//!
//! ```ignore
//! let fragmenter = Fragmenter::new(mtu);
//!
//! if payload.len() > mtu {
//!     let fragments = fragmenter.fragment(payload, msg_seq, stream_id);
//!     for frag in fragments {
//!         send_record(frag);
//!     }
//! }
//! ```
//!
//! ## Receiver Side
//!
//! ```ignore
//! let mut reassembler = Reassembler::new(ReassemblerConfig::default());
//!
//! // On fragment received
//! if let Some(payload) = reassembler.on_fragment(stream_id, frag_header, frag_data) {
//!     // Complete payload reassembled
//!     deliver(payload);
//! }
//!
//! // Periodically clean up stale groups
//! reassembler.tick();
//! ```

use std::collections::HashMap;
use std::time::{Duration, Instant};

use super::varint::{decode_varint, encode_varint, varint_len};

/// Fragment header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FragHeader {
    /// Group ID (typically msg_seq of the original message).
    pub group_id: u32,
    /// Fragment index (0 to frag_cnt-1).
    pub frag_idx: u16,
    /// Total fragment count.
    pub frag_cnt: u16,
    /// Original payload length.
    pub orig_len: u32,
    /// This fragment's data length.
    pub frag_len: u16,
}

impl FragHeader {
    /// Create a new fragment header.
    pub fn new(group_id: u32, frag_idx: u16, frag_cnt: u16, orig_len: u32, frag_len: u16) -> Self {
        Self {
            group_id,
            frag_idx,
            frag_cnt,
            orig_len,
            frag_len,
        }
    }

    /// Encode the fragment header to bytes.
    ///
    /// Returns the number of bytes written.
    pub fn encode(&self, buf: &mut [u8]) -> Result<usize, FragError> {
        let needed = self.encoded_len();
        if buf.len() < needed {
            return Err(FragError::BufferTooSmall);
        }

        let mut offset = 0;
        offset += encode_varint(self.group_id as u64, &mut buf[offset..]);
        offset += encode_varint(self.frag_idx as u64, &mut buf[offset..]);
        offset += encode_varint(self.frag_cnt as u64, &mut buf[offset..]);
        offset += encode_varint(self.orig_len as u64, &mut buf[offset..]);
        offset += encode_varint(self.frag_len as u64, &mut buf[offset..]);

        Ok(offset)
    }

    /// Decode a fragment header from bytes.
    ///
    /// Returns the header and number of bytes consumed.
    pub fn decode(buf: &[u8]) -> Result<(Self, usize), FragError> {
        let mut offset = 0;

        let (group_id, n) = decode_varint(&buf[offset..]).map_err(|_| FragError::InvalidHeader)?;
        offset += n;

        let (frag_idx, n) = decode_varint(&buf[offset..]).map_err(|_| FragError::InvalidHeader)?;
        offset += n;

        let (frag_cnt, n) = decode_varint(&buf[offset..]).map_err(|_| FragError::InvalidHeader)?;
        offset += n;

        let (orig_len, n) = decode_varint(&buf[offset..]).map_err(|_| FragError::InvalidHeader)?;
        offset += n;

        let (frag_len, n) = decode_varint(&buf[offset..]).map_err(|_| FragError::InvalidHeader)?;
        offset += n;

        // Validate ranges
        if frag_idx > u16::MAX as u64 || frag_cnt > u16::MAX as u64 || frag_len > u16::MAX as u64 {
            return Err(FragError::InvalidHeader);
        }
        if frag_idx >= frag_cnt {
            return Err(FragError::InvalidHeader);
        }

        Ok((
            Self {
                group_id: group_id as u32,
                frag_idx: frag_idx as u16,
                frag_cnt: frag_cnt as u16,
                orig_len: orig_len as u32,
                frag_len: frag_len as u16,
            },
            offset,
        ))
    }

    /// Get encoded length.
    pub fn encoded_len(&self) -> usize {
        varint_len(self.group_id as u64)
            + varint_len(self.frag_idx as u64)
            + varint_len(self.frag_cnt as u64)
            + varint_len(self.orig_len as u64)
            + varint_len(self.frag_len as u64)
    }
}

/// Fragment error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FragError {
    /// Buffer too small for encoding.
    BufferTooSmall,
    /// Invalid fragment header.
    InvalidHeader,
    /// Payload too large to fragment.
    PayloadTooLarge,
    /// Fragment group not found.
    GroupNotFound,
    /// Duplicate fragment.
    DuplicateFragment,
    /// Fragment count mismatch.
    CountMismatch,
    /// Original length mismatch.
    LengthMismatch,
    /// Reassembly timeout.
    Timeout,
    /// Too many pending groups.
    TooManyGroups,
}

impl std::fmt::Display for FragError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BufferTooSmall => write!(f, "buffer too small"),
            Self::InvalidHeader => write!(f, "invalid fragment header"),
            Self::PayloadTooLarge => write!(f, "payload too large"),
            Self::GroupNotFound => write!(f, "fragment group not found"),
            Self::DuplicateFragment => write!(f, "duplicate fragment"),
            Self::CountMismatch => write!(f, "fragment count mismatch"),
            Self::LengthMismatch => write!(f, "original length mismatch"),
            Self::Timeout => write!(f, "reassembly timeout"),
            Self::TooManyGroups => write!(f, "too many pending groups"),
        }
    }
}

impl std::error::Error for FragError {}

/// A single fragment ready for transmission.
#[derive(Debug, Clone)]
pub struct Fragment {
    /// Fragment header.
    pub header: FragHeader,
    /// Fragment data (portion of original payload).
    pub data: Vec<u8>,
}

impl Fragment {
    /// Encode the fragment to bytes (header + data).
    pub fn encode(&self, buf: &mut [u8]) -> Result<usize, FragError> {
        let header_len = self.header.encoded_len();
        let total = header_len + self.data.len();

        if buf.len() < total {
            return Err(FragError::BufferTooSmall);
        }

        let n = self.header.encode(buf)?;
        buf[n..n + self.data.len()].copy_from_slice(&self.data);

        Ok(total)
    }

    /// Decode a fragment from bytes.
    pub fn decode(buf: &[u8]) -> Result<(Self, usize), FragError> {
        let (header, header_len) = FragHeader::decode(buf)?;

        let frag_size = header.frag_len as usize;

        if buf.len() < header_len + frag_size {
            return Err(FragError::InvalidHeader);
        }

        let data = buf[header_len..header_len + frag_size].to_vec();

        Ok((Self { header, data }, header_len + frag_size))
    }
}

/// Calculate the size of a specific fragment.
fn calculate_fragment_size(orig_len: u32, frag_cnt: u16, frag_idx: u16) -> usize {
    let base_size = orig_len as usize / frag_cnt as usize;
    let remainder = orig_len as usize % frag_cnt as usize;

    // Distribute remainder across first `remainder` fragments
    if (frag_idx as usize) < remainder {
        base_size + 1
    } else {
        base_size
    }
}

/// Calculate the offset of a specific fragment in the original payload.
#[allow(dead_code)] // Part of fragmentation API, used during fragment reassembly
fn calculate_fragment_offset(orig_len: u32, frag_cnt: u16, frag_idx: u16) -> usize {
    let base_size = orig_len as usize / frag_cnt as usize;
    let remainder = orig_len as usize % frag_cnt as usize;

    let full_frags_before = frag_idx as usize;
    let extra_bytes = full_frags_before.min(remainder);

    full_frags_before * base_size + extra_bytes
}

// ============================================================================
// Fragmenter (Sender Side)
// ============================================================================

/// Fragmenter for splitting large payloads.
#[derive(Debug, Clone)]
pub struct Fragmenter {
    /// Maximum payload size per fragment (MTU - overhead).
    max_frag_payload: usize,
}

impl Fragmenter {
    /// Create a new fragmenter.
    ///
    /// # Arguments
    /// * `mtu` - Maximum transmission unit (frame size)
    /// * `overhead` - Overhead for frame/record headers (typically 16-20 bytes)
    pub fn new(mtu: usize, overhead: usize) -> Self {
        // Reserve space for fragment header (typically 4-8 bytes for varints)
        let frag_header_reserve = 12;
        let max_frag_payload = mtu.saturating_sub(overhead + frag_header_reserve);

        Self {
            max_frag_payload: max_frag_payload.max(16), // Minimum 16 bytes
        }
    }

    /// Check if a payload needs fragmentation.
    pub fn needs_fragmentation(&self, payload_len: usize) -> bool {
        payload_len > self.max_frag_payload
    }

    /// Fragment a payload into multiple fragments.
    ///
    /// # Arguments
    /// * `payload` - Original payload to fragment
    /// * `group_id` - Group ID (typically msg_seq)
    ///
    /// # Returns
    /// Vector of fragments, or error if payload is too large.
    pub fn fragment(&self, payload: &[u8], group_id: u32) -> Result<Vec<Fragment>, FragError> {
        if payload.is_empty() {
            return Ok(vec![Fragment {
                header: FragHeader::new(group_id, 0, 1, 0, 0),
                data: vec![],
            }]);
        }

        let frag_cnt = payload.len().div_ceil(self.max_frag_payload);

        if frag_cnt > u16::MAX as usize {
            return Err(FragError::PayloadTooLarge);
        }

        let frag_cnt = frag_cnt as u16;
        let orig_len = payload.len() as u32;

        let mut fragments = Vec::with_capacity(frag_cnt as usize);
        let mut offset = 0;

        for frag_idx in 0..frag_cnt {
            let frag_size = calculate_fragment_size(orig_len, frag_cnt, frag_idx);
            let end = (offset + frag_size).min(payload.len());
            let frag_data = &payload[offset..end];

            fragments.push(Fragment {
                header: FragHeader::new(
                    group_id,
                    frag_idx,
                    frag_cnt,
                    orig_len,
                    frag_data.len() as u16,
                ),
                data: frag_data.to_vec(),
            });

            offset = end;
        }

        Ok(fragments)
    }

    /// Get maximum fragment payload size.
    pub fn max_payload(&self) -> usize {
        self.max_frag_payload
    }
}

// ============================================================================
// Reassembler (Receiver Side)
// ============================================================================

/// Reassembler configuration.
#[derive(Debug, Clone)]
pub struct ReassemblerConfig {
    /// Maximum pending fragment groups.
    pub max_groups: usize,
    /// Reassembly timeout.
    pub timeout: Duration,
    /// Maximum original payload size.
    pub max_payload_size: usize,
}

impl Default for ReassemblerConfig {
    fn default() -> Self {
        Self {
            max_groups: 16,
            timeout: Duration::from_secs(5),
            max_payload_size: 64 * 1024, // 64KB
        }
    }
}

/// Pending fragment group being reassembled.
#[derive(Debug)]
struct PendingGroup {
    /// Expected fragment count.
    frag_cnt: u16,
    /// Original payload length.
    orig_len: u32,
    /// Received fragments (indexed by frag_idx).
    fragments: HashMap<u16, Vec<u8>>,
    /// Creation time.
    created_at: Instant,
    /// Stream ID (for cleanup tracking).
    #[allow(dead_code)] // Used for tracking/debugging purposes
    stream_id: u8,
}

impl PendingGroup {
    fn new(stream_id: u8, frag_cnt: u16, orig_len: u32) -> Self {
        Self {
            frag_cnt,
            orig_len,
            fragments: HashMap::with_capacity(frag_cnt as usize),
            created_at: Instant::now(),
            stream_id,
        }
    }

    fn is_complete(&self) -> bool {
        self.fragments.len() == self.frag_cnt as usize
    }

    fn add_fragment(&mut self, frag_idx: u16, data: Vec<u8>) -> Result<(), FragError> {
        if self.fragments.contains_key(&frag_idx) {
            return Err(FragError::DuplicateFragment);
        }
        self.fragments.insert(frag_idx, data);
        Ok(())
    }

    fn reassemble(&self) -> Result<Vec<u8>, FragError> {
        if !self.is_complete() {
            return Err(FragError::GroupNotFound);
        }

        let mut payload = Vec::with_capacity(self.orig_len as usize);

        for frag_idx in 0..self.frag_cnt {
            let frag_data = self
                .fragments
                .get(&frag_idx)
                .ok_or(FragError::GroupNotFound)?;
            payload.extend_from_slice(frag_data);
        }

        if payload.len() != self.orig_len as usize {
            return Err(FragError::LengthMismatch);
        }

        Ok(payload)
    }
}

/// Key for identifying a fragment group.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct GroupKey {
    stream_id: u8,
    group_id: u32,
}

/// Reassembler statistics.
#[derive(Debug, Default, Clone)]
pub struct ReassemblerStats {
    /// Fragments received.
    pub fragments_received: u64,
    /// Payloads reassembled.
    pub payloads_reassembled: u64,
    /// Duplicates dropped.
    pub duplicates_dropped: u64,
    /// Groups timed out.
    pub groups_timed_out: u64,
    /// Groups dropped (too many).
    pub groups_dropped: u64,
    /// Current pending groups.
    pub pending_groups: usize,
}

/// Fragment reassembler.
pub struct Reassembler {
    /// Configuration.
    config: ReassemblerConfig,
    /// Pending fragment groups.
    pending: HashMap<GroupKey, PendingGroup>,
    /// Statistics.
    stats: ReassemblerStats,
}

impl Reassembler {
    /// Create a new reassembler.
    pub fn new(config: ReassemblerConfig) -> Self {
        Self {
            config,
            pending: HashMap::new(),
            stats: ReassemblerStats::default(),
        }
    }

    /// Get statistics.
    pub fn stats(&self) -> ReassemblerStats {
        let mut stats = self.stats.clone();
        stats.pending_groups = self.pending.len();
        stats
    }

    /// Reset statistics.
    pub fn reset_stats(&mut self) {
        self.stats = ReassemblerStats::default();
    }

    /// Handle a received fragment.
    ///
    /// Returns `Some(payload)` if the fragment completed a group.
    pub fn on_fragment(
        &mut self,
        stream_id: u8,
        header: &FragHeader,
        data: Vec<u8>,
    ) -> Result<Option<Vec<u8>>, FragError> {
        self.stats.fragments_received += 1;

        // Validate
        if header.orig_len as usize > self.config.max_payload_size {
            return Err(FragError::PayloadTooLarge);
        }

        let key = GroupKey {
            stream_id,
            group_id: header.group_id,
        };

        // Get or create group
        if !self.pending.contains_key(&key) {
            // Check group limit
            if self.pending.len() >= self.config.max_groups {
                // Evict oldest group
                self.evict_oldest();
            }

            self.pending.insert(
                key,
                PendingGroup::new(stream_id, header.frag_cnt, header.orig_len),
            );
        }

        #[allow(clippy::unwrap_used)] // key was just inserted or already existed above
        let group = self.pending.get_mut(&key).unwrap();

        // Validate consistency
        if group.frag_cnt != header.frag_cnt {
            return Err(FragError::CountMismatch);
        }
        if group.orig_len != header.orig_len {
            return Err(FragError::LengthMismatch);
        }

        // Add fragment
        match group.add_fragment(header.frag_idx, data) {
            Ok(()) => {}
            Err(FragError::DuplicateFragment) => {
                self.stats.duplicates_dropped += 1;
                return Ok(None);
            }
            Err(e) => return Err(e),
        }

        // Check if complete
        if group.is_complete() {
            let payload = group.reassemble()?;
            self.pending.remove(&key);
            self.stats.payloads_reassembled += 1;
            return Ok(Some(payload));
        }

        Ok(None)
    }

    /// Evict the oldest pending group.
    fn evict_oldest(&mut self) {
        if let Some(oldest_key) = self
            .pending
            .iter()
            .min_by_key(|(_, g)| g.created_at)
            .map(|(k, _)| *k)
        {
            self.pending.remove(&oldest_key);
            self.stats.groups_dropped += 1;
        }
    }

    /// Tick the reassembler (clean up timed-out groups).
    pub fn tick(&mut self) {
        let timeout = self.config.timeout;
        let now = Instant::now();

        let timed_out: Vec<GroupKey> = self
            .pending
            .iter()
            .filter(|(_, g)| now.duration_since(g.created_at) >= timeout)
            .map(|(k, _)| *k)
            .collect();

        for key in timed_out {
            self.pending.remove(&key);
            self.stats.groups_timed_out += 1;
        }
    }

    /// Clear all pending groups.
    pub fn clear(&mut self) {
        self.pending.clear();
    }

    /// Get number of pending groups.
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // FragHeader Tests
    // ========================================================================

    #[test]
    fn test_frag_header_encode_decode() {
        let header = FragHeader::new(12345, 2, 5, 1000, 200);

        let mut buf = [0u8; 32];
        let encoded_len = header.encode(&mut buf).unwrap();

        let (decoded, consumed) = FragHeader::decode(&buf).unwrap();

        assert_eq!(encoded_len, consumed);
        assert_eq!(decoded, header);
    }

    #[test]
    fn test_frag_header_invalid_idx() {
        // frag_idx >= frag_cnt is invalid
        let mut buf = [0u8; 32];
        let mut offset = 0;
        offset += encode_varint(100, &mut buf[offset..]); // group_id
        offset += encode_varint(5, &mut buf[offset..]); // frag_idx = 5
        offset += encode_varint(5, &mut buf[offset..]); // frag_cnt = 5
        offset += encode_varint(1000, &mut buf[offset..]); // orig_len
        let _ = encode_varint(100, &mut buf[offset..]); // frag_len

        let result = FragHeader::decode(&buf);
        assert!(matches!(result, Err(FragError::InvalidHeader)));
    }

    // ========================================================================
    // Fragmenter Tests
    // ========================================================================

    #[test]
    fn test_fragmenter_no_fragmentation_needed() {
        let fragmenter = Fragmenter::new(256, 20);

        let payload = vec![1u8; 100];
        assert!(!fragmenter.needs_fragmentation(payload.len()));

        let fragments = fragmenter.fragment(&payload, 1).unwrap();
        assert_eq!(fragments.len(), 1);
        assert_eq!(fragments[0].data, payload);
    }

    #[test]
    fn test_fragmenter_basic() {
        let fragmenter = Fragmenter::new(100, 20); // ~68 byte max payload

        let payload = vec![0xABu8; 200];
        assert!(fragmenter.needs_fragmentation(payload.len()));

        let fragments = fragmenter.fragment(&payload, 42).unwrap();

        assert!(fragments.len() >= 3);

        // All fragments should have same group_id and frag_cnt
        for frag in &fragments {
            assert_eq!(frag.header.group_id, 42);
            assert_eq!(frag.header.frag_cnt, fragments.len() as u16);
            assert_eq!(frag.header.orig_len, 200);
        }

        // Total data should equal original
        let total_data: usize = fragments.iter().map(|f| f.data.len()).sum();
        assert_eq!(total_data, 200);
    }

    #[test]
    fn test_fragmenter_empty_payload() {
        let fragmenter = Fragmenter::new(256, 20);

        let fragments = fragmenter.fragment(&[], 1).unwrap();
        assert_eq!(fragments.len(), 1);
        assert_eq!(fragments[0].header.orig_len, 0);
        assert!(fragments[0].data.is_empty());
    }

    #[test]
    fn test_fragmenter_exact_fit() {
        let fragmenter = Fragmenter::new(100, 20);
        let max_payload = fragmenter.max_payload();

        let payload = vec![0xCDu8; max_payload];
        let fragments = fragmenter.fragment(&payload, 1).unwrap();

        assert_eq!(fragments.len(), 1);
    }

    // ========================================================================
    // Reassembler Tests
    // ========================================================================

    #[test]
    fn test_reassembler_single_fragment() {
        let mut reassembler = Reassembler::new(ReassemblerConfig::default());

        let data = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let header = FragHeader::new(1, 0, 1, 10, data.len() as u16);

        let result = reassembler.on_fragment(1, &header, data.clone()).unwrap();

        assert!(result.is_some());
        assert_eq!(result.unwrap(), data);
    }

    #[test]
    fn test_reassembler_multiple_fragments() {
        let mut reassembler = Reassembler::new(ReassemblerConfig::default());

        let orig = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];

        // Fragment 0
        let d0 = vec![1, 2, 3, 4, 5];
        let h0 = FragHeader::new(1, 0, 2, 10, d0.len() as u16);
        let r0 = reassembler.on_fragment(1, &h0, d0).unwrap();
        assert!(r0.is_none()); // Not complete yet

        // Fragment 1
        let d1 = vec![6, 7, 8, 9, 10];
        let h1 = FragHeader::new(1, 1, 2, 10, d1.len() as u16);
        let r1 = reassembler.on_fragment(1, &h1, d1).unwrap();

        assert!(r1.is_some());
        assert_eq!(r1.unwrap(), orig);
    }

    #[test]
    fn test_reassembler_out_of_order() {
        let mut reassembler = Reassembler::new(ReassemblerConfig::default());

        let orig = vec![1, 2, 3, 4, 5, 6, 7, 8, 9];

        // Send fragment 2 first
        let d2 = vec![7, 8, 9];
        let h2 = FragHeader::new(1, 2, 3, 9, d2.len() as u16);
        assert!(reassembler.on_fragment(1, &h2, d2).unwrap().is_none());

        // Then fragment 0
        let d0 = vec![1, 2, 3];
        let h0 = FragHeader::new(1, 0, 3, 9, d0.len() as u16);
        assert!(reassembler.on_fragment(1, &h0, d0).unwrap().is_none());

        // Finally fragment 1
        let d1 = vec![4, 5, 6];
        let h1 = FragHeader::new(1, 1, 3, 9, d1.len() as u16);
        let result = reassembler.on_fragment(1, &h1, d1).unwrap();

        assert!(result.is_some());
        assert_eq!(result.unwrap(), orig);
    }

    #[test]
    fn test_reassembler_duplicate() {
        let mut reassembler = Reassembler::new(ReassemblerConfig::default());

        let d0 = vec![1, 2, 3, 4, 5];
        let h0 = FragHeader::new(1, 0, 2, 10, d0.len() as u16);

        // First fragment
        reassembler.on_fragment(1, &h0, d0.clone()).unwrap();

        // Duplicate
        let result = reassembler.on_fragment(1, &h0, d0).unwrap();
        assert!(result.is_none());
        assert_eq!(reassembler.stats().duplicates_dropped, 1);
    }

    #[test]
    fn test_reassembler_timeout() {
        let config = ReassemblerConfig {
            timeout: Duration::from_millis(10),
            ..Default::default()
        };
        let mut reassembler = Reassembler::new(config);

        let d0 = vec![1, 2, 3, 4, 5];
        let h0 = FragHeader::new(1, 0, 2, 10, d0.len() as u16);
        reassembler.on_fragment(1, &h0, d0).unwrap();

        assert_eq!(reassembler.pending_count(), 1);

        // Wait for timeout
        std::thread::sleep(Duration::from_millis(15));
        reassembler.tick();

        assert_eq!(reassembler.pending_count(), 0);
        assert_eq!(reassembler.stats().groups_timed_out, 1);
    }

    #[test]
    fn test_reassembler_max_groups() {
        let config = ReassemblerConfig {
            max_groups: 2,
            ..Default::default()
        };
        let mut reassembler = Reassembler::new(config);

        // Add 3 incomplete groups
        for group_id in 0..3 {
            let d = vec![1, 2, 3, 4, 5];
            let h = FragHeader::new(group_id, 0, 2, 10, d.len() as u16);
            reassembler.on_fragment(1, &h, d).unwrap();
        }

        // Should have evicted oldest, keeping only 2
        assert_eq!(reassembler.pending_count(), 2);
        assert_eq!(reassembler.stats().groups_dropped, 1);
    }

    #[test]
    fn test_reassembler_separate_streams() {
        let mut reassembler = Reassembler::new(ReassemblerConfig::default());

        // Stream 1, group 1
        let d1 = vec![1, 2, 3, 4, 5];
        let h1 = FragHeader::new(1, 0, 1, 5, d1.len() as u16);

        // Stream 2, group 1 (same group_id, different stream)
        let d2 = vec![6, 7, 8];
        let h2 = FragHeader::new(1, 0, 1, 3, d2.len() as u16);

        let r1 = reassembler.on_fragment(1, &h1, d1.clone()).unwrap();
        let r2 = reassembler.on_fragment(2, &h2, d2.clone()).unwrap();

        assert_eq!(r1.unwrap(), d1);
        assert_eq!(r2.unwrap(), d2);
    }

    // ========================================================================
    // Integration Tests
    // ========================================================================

    #[test]
    fn test_fragment_reassemble_roundtrip() {
        let fragmenter = Fragmenter::new(50, 20);
        let mut reassembler = Reassembler::new(ReassemblerConfig::default());

        let original = (0u8..=255).collect::<Vec<u8>>();

        // Fragment
        let fragments = fragmenter.fragment(&original, 42).unwrap();
        assert!(fragments.len() > 1);

        // Reassemble
        let mut result = None;
        for frag in fragments {
            result = reassembler.on_fragment(1, &frag.header, frag.data).unwrap();
        }

        assert!(result.is_some());
        assert_eq!(result.unwrap(), original);
    }

    #[test]
    fn test_fragment_encode_decode_roundtrip() {
        let frag = Fragment {
            header: FragHeader::new(100, 2, 5, 500, 4), // frag_len = 4 bytes
            data: vec![0xDE, 0xAD, 0xBE, 0xEF],
        };

        let mut buf = [0u8; 64];
        let encoded_len = frag.encode(&mut buf).unwrap();

        let (decoded, consumed) = Fragment::decode(&buf[..encoded_len]).unwrap();

        assert_eq!(consumed, encoded_len);
        assert_eq!(decoded.header, frag.header);
        assert_eq!(decoded.data, frag.data);
    }

    #[test]
    fn test_calculate_fragment_size() {
        // 10 bytes split into 3 fragments: 4, 3, 3
        assert_eq!(calculate_fragment_size(10, 3, 0), 4);
        assert_eq!(calculate_fragment_size(10, 3, 1), 3);
        assert_eq!(calculate_fragment_size(10, 3, 2), 3);

        // 9 bytes split into 3 fragments: 3, 3, 3
        assert_eq!(calculate_fragment_size(9, 3, 0), 3);
        assert_eq!(calculate_fragment_size(9, 3, 1), 3);
        assert_eq!(calculate_fragment_size(9, 3, 2), 3);
    }

    #[test]
    fn test_calculate_fragment_offset() {
        // 10 bytes split into 3 fragments: 4, 3, 3
        assert_eq!(calculate_fragment_offset(10, 3, 0), 0);
        assert_eq!(calculate_fragment_offset(10, 3, 1), 4);
        assert_eq!(calculate_fragment_offset(10, 3, 2), 7);
    }
}
