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

use super::varint::{decode_varint_u16, decode_varint_u32, encode_varint, varint_len};

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

        // Each field is decoded straight into its wire width, so a value that
        // does not fit is refused by the decoder. Decoding as u64 and casting
        // would fold a `group_id` or `orig_len` above u32::MAX silently, and a
        // corrupt header could land in another group's reassembly.
        let (group_id, n) =
            decode_varint_u32(&buf[offset..]).map_err(|_| FragError::InvalidHeader)?;
        offset += n;

        let (frag_idx, n) =
            decode_varint_u16(&buf[offset..]).map_err(|_| FragError::InvalidHeader)?;
        offset += n;

        let (frag_cnt, n) =
            decode_varint_u16(&buf[offset..]).map_err(|_| FragError::InvalidHeader)?;
        offset += n;

        let (orig_len, n) =
            decode_varint_u32(&buf[offset..]).map_err(|_| FragError::InvalidHeader)?;
        offset += n;

        let (frag_len, n) =
            decode_varint_u16(&buf[offset..]).map_err(|_| FragError::InvalidHeader)?;
        offset += n;

        if frag_idx >= frag_cnt {
            return Err(FragError::InvalidHeader);
        }

        Ok((
            Self {
                group_id,
                frag_idx,
                frag_cnt,
                orig_len,
                frag_len,
            },
            offset,
        ))
    }

    /// The widest this header can ever encode to.
    ///
    /// Five varints: `group_id` and `orig_len` are u32, so 5 octets each at
    /// their widest; `frag_idx`, `frag_cnt` and `frag_len` are u16, so 3 each.
    pub const MAX_ENCODED_LEN: usize = 5 + 3 + 3 + 5 + 3;

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

/// Octets `Fragmenter::new` holds back for the fragment header.
///
/// The header is five varints and so has no single width:
/// `FragHeader::MAX_ENCODED_LEN` is what it reaches at its widest. This
/// reserve is deliberately short of that - see `Fragmenter::new` for the
/// octets closing the gap would cost and for what happens when it is reached.
const FRAG_HEADER_RESERVE: usize = 12;

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
        // The reserve is short of the widest header the encoder can produce,
        // and that is a decision rather than an oversight: closing it costs
        // every fragment on every link 7 octets of payload, for good, to
        // defend a case that needs one stream to have sent 2^28 messages AND
        // one message of several megabytes. Reached, it costs a `send`
        // refused with `PayloadTooLarge` - not a queue that stops - because
        // `Scheduler::max_record_size` refuses the record and `LowBwTransport`
        // checks the whole message before it enqueues any of it. The exact
        // overage is pinned by `the_reserve_is_short_of_the_widest_header`.
        let max_frag_payload = mtu.saturating_sub(overhead + FRAG_HEADER_RESERVE);

        // Minimum 16 bytes. The ceiling is the wire's: `frag_len` travels as
        // a u16, so no fragment can carry more than that whatever the MTU
        // says, and an MTU above it is honoured with more fragments rather
        // than with a header field that wrapped.
        Self {
            max_frag_payload: max_frag_payload.clamp(16, usize::from(u16::MAX)),
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

        // `frag_cnt` and `frag_len` travel as u16 and `orig_len` as u32 (see
        // `FragHeader`): the conversions are the range checks, and a payload
        // the header cannot describe is refused before a byte is framed.
        let frag_cnt = u16::try_from(payload.len().div_ceil(self.max_frag_payload))
            .map_err(|_| FragError::PayloadTooLarge)?;
        let orig_len = u32::try_from(payload.len()).map_err(|_| FragError::PayloadTooLarge)?;

        let mut fragments = Vec::with_capacity(usize::from(frag_cnt));
        let mut offset = 0;

        for frag_idx in 0..frag_cnt {
            let frag_size = calculate_fragment_size(orig_len, frag_cnt, frag_idx);
            let end = (offset + frag_size).min(payload.len());
            let frag_data = &payload[offset..end];
            let frag_len =
                u16::try_from(frag_data.len()).map_err(|_| FragError::PayloadTooLarge)?;

            fragments.push(Fragment {
                header: FragHeader::new(group_id, frag_idx, frag_cnt, orig_len, frag_len),
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

        // Get or create group. Eviction is decided before the entry is taken
        // (the key is not present, so it cannot evict itself), and the entry
        // API makes "just inserted or already there" a property of the call
        // rather than a comment next to an unwrap.
        if !self.pending.contains_key(&key) && self.pending.len() >= self.config.max_groups {
            self.evict_oldest();
        }
        let group = self
            .pending
            .entry(key)
            .or_insert_with(|| PendingGroup::new(stream_id, header.frag_cnt, header.orig_len));

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
#[path = "fragment_test.rs"]
mod tests;
