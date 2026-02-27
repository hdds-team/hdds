// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Delta encoding for telemetry efficiency on low-bandwidth links.
//!
//! This module implements "stateless patch" delta encoding:
//! - **FULL (keyframe)**: Complete state snapshot, sent periodically
//! - **DELTA (patch)**: Only changed fields since last FULL
//! - **Redundancy**: Multiple FULL copies spaced apart for loss resilience
//!
//! # Design
//!
//! The delta encoding is "stateless" in that each DELTA patch contains
//! absolute field values (not increments), so any single patch can be
//! applied to a FULL to get partial state. This is more robust than
//! incremental deltas which require all patches in order.
//!
//! # Wire Format
//!
//! FULL payload:
//! ```text
//! full_seq: varint    // Sequence number of this FULL
//! field_count: varint // Number of fields
//! [field_id: varint, value_len: varint, value: [u8]]*
//! ```
//!
//! DELTA payload:
//! ```text
//! base_full_seq: varint  // Which FULL this patches
//! patch_seq: varint      // Sequence within the FULL epoch
//! field_count: varint    // Number of changed fields
//! [field_id: varint, value_len: varint, value: [u8]]*
//! ```
//!
//! # Usage
//!
//! ```ignore
//! // Sender side
//! let mut encoder = DeltaEncoder::new(DeltaConfig::default());
//! encoder.update_field(0, &temperature_bytes);
//! encoder.update_field(1, &humidity_bytes);
//! let record = encoder.poll_record(); // Returns FULL or DELTA
//!
//! // Receiver side
//! let mut decoder = DeltaDecoder::new();
//! decoder.on_record(&record_payload, is_delta);
//! let current_temp = decoder.get_field(0);
//! ```

use super::varint::{decode_varint, encode_varint, varint_len};
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Delta encoding configuration.
#[derive(Debug, Clone)]
pub struct DeltaConfig {
    /// Period between FULL keyframes (default: 5000ms).
    pub keyframe_period: Duration,
    /// Number of redundant FULL copies to send (default: 2).
    pub keyframe_redundancy: u8,
    /// Spacing between redundant copies (default: 200ms).
    pub redundancy_spacing: Duration,
    /// Maximum fields per message (default: 64).
    pub max_fields: usize,
}

impl Default for DeltaConfig {
    fn default() -> Self {
        Self {
            keyframe_period: Duration::from_millis(5000),
            keyframe_redundancy: 2,
            redundancy_spacing: Duration::from_millis(200),
            max_fields: 64,
        }
    }
}

/// Error type for delta operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeltaError {
    /// Buffer too small for encoding.
    BufferTooSmall,
    /// Invalid delta payload.
    InvalidPayload,
    /// Unknown field ID.
    UnknownField(u32),
    /// Too many fields.
    TooManyFields,
    /// Varint decode error.
    VarintError,
    /// Base FULL not found for delta.
    BaseMissing(u32),
}

impl std::fmt::Display for DeltaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BufferTooSmall => write!(f, "buffer too small"),
            Self::InvalidPayload => write!(f, "invalid payload"),
            Self::UnknownField(id) => write!(f, "unknown field {}", id),
            Self::TooManyFields => write!(f, "too many fields"),
            Self::VarintError => write!(f, "varint decode error"),
            Self::BaseMissing(seq) => write!(f, "base FULL seq {} not found", seq),
        }
    }
}

impl std::error::Error for DeltaError {}

/// Statistics for delta encoding.
#[derive(Debug, Clone, Default)]
pub struct DeltaEncoderStats {
    /// Number of FULL keyframes sent.
    pub fulls_sent: u64,
    /// Number of DELTA patches sent.
    pub deltas_sent: u64,
    /// Number of redundant FULLs sent.
    pub redundant_fulls_sent: u64,
    /// Total bytes saved by delta encoding.
    pub bytes_saved: u64,
}

/// Statistics for delta decoding.
#[derive(Debug, Clone, Default)]
pub struct DeltaDecoderStats {
    /// Number of FULL keyframes received.
    pub fulls_received: u64,
    /// Number of DELTA patches received.
    pub deltas_received: u64,
    /// Number of resyncs (FULL after gap).
    pub resyncs: u64,
    /// Number of deltas dropped (base missing).
    pub deltas_dropped: u64,
    /// Number of STATE_ACKs sent.
    pub state_acks_sent: u64,
}

/// Type of record to send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeltaRecord {
    /// Full keyframe with all fields.
    Full {
        /// Sequence number of this FULL.
        full_seq: u32,
        /// Encoded payload.
        payload: Vec<u8>,
    },
    /// Delta patch with changed fields only.
    Delta {
        /// Which FULL this patches.
        base_full_seq: u32,
        /// Patch sequence within the epoch.
        patch_seq: u32,
        /// Encoded payload.
        payload: Vec<u8>,
    },
    /// No record to send (no changes).
    None,
}

/// Field value with change tracking.
#[derive(Debug, Clone)]
struct TrackedField {
    /// Current value.
    value: Vec<u8>,
    /// Changed since last FULL.
    dirty: bool,
    /// Changed since last DELTA.
    changed_this_epoch: bool,
}

/// Delta encoder for the sender side.
#[derive(Debug)]
pub struct DeltaEncoder {
    config: DeltaConfig,
    /// Current field values.
    fields: HashMap<u32, TrackedField>,
    /// Current FULL sequence number.
    full_seq: u32,
    /// Current patch sequence within epoch.
    patch_seq: u32,
    /// Last FULL send time.
    last_full_time: Option<Instant>,
    /// Redundant FULL copies remaining.
    redundant_remaining: u8,
    /// Time of last redundant copy.
    last_redundant_time: Option<Instant>,
    /// Snapshot of fields at last FULL (for redundancy).
    full_snapshot: HashMap<u32, Vec<u8>>,
    /// Statistics.
    pub stats: DeltaEncoderStats,
}

impl DeltaEncoder {
    /// Create a new delta encoder.
    pub fn new(config: DeltaConfig) -> Self {
        Self {
            config,
            fields: HashMap::new(),
            full_seq: 0,
            patch_seq: 0,
            last_full_time: None,
            redundant_remaining: 0,
            last_redundant_time: None,
            full_snapshot: HashMap::new(),
            stats: DeltaEncoderStats::default(),
        }
    }

    /// Update a field value.
    pub fn update_field(&mut self, field_id: u32, value: &[u8]) {
        let entry = self.fields.entry(field_id).or_insert_with(|| TrackedField {
            value: Vec::new(),
            dirty: true,
            changed_this_epoch: true,
        });

        if entry.value != value {
            entry.value = value.to_vec();
            entry.dirty = true;
            entry.changed_this_epoch = true;
        }
    }

    /// Check if it's time for a FULL keyframe.
    pub fn needs_full(&self, now: Instant) -> bool {
        match self.last_full_time {
            None => true,
            Some(t) => now.duration_since(t) >= self.config.keyframe_period,
        }
    }

    /// Check if we need to send a redundant FULL.
    pub fn needs_redundant_full(&self, now: Instant) -> bool {
        if self.redundant_remaining == 0 {
            return false;
        }
        match self.last_redundant_time {
            None => true,
            Some(t) => now.duration_since(t) >= self.config.redundancy_spacing,
        }
    }

    /// Check if there are dirty fields to send as DELTA.
    pub fn has_dirty_fields(&self) -> bool {
        self.fields.values().any(|f| f.dirty)
    }

    /// Poll for a record to send.
    pub fn poll_record(&mut self, now: Instant) -> DeltaRecord {
        // Priority 1: Send redundant FULL if pending
        if self.needs_redundant_full(now) {
            return self.send_redundant_full(now);
        }

        // Priority 2: Send new FULL if period elapsed
        if self.needs_full(now) {
            return self.send_full(now);
        }

        // Priority 3: Send DELTA if dirty fields
        if self.has_dirty_fields() {
            return self.send_delta();
        }

        DeltaRecord::None
    }

    /// Force sending a FULL keyframe.
    pub fn force_full(&mut self, now: Instant) -> DeltaRecord {
        self.send_full(now)
    }

    fn send_full(&mut self, now: Instant) -> DeltaRecord {
        self.full_seq = self.full_seq.wrapping_add(1);
        self.patch_seq = 0;
        self.last_full_time = Some(now);
        self.redundant_remaining = self.config.keyframe_redundancy;
        self.last_redundant_time = Some(now);

        // Snapshot current state for redundancy
        self.full_snapshot.clear();
        for (id, field) in &self.fields {
            self.full_snapshot.insert(*id, field.value.clone());
        }

        // Clear dirty flags
        for field in self.fields.values_mut() {
            field.dirty = false;
            field.changed_this_epoch = false;
        }

        // Encode FULL
        let payload = self.encode_full();
        self.stats.fulls_sent += 1;

        DeltaRecord::Full {
            full_seq: self.full_seq,
            payload,
        }
    }

    fn send_redundant_full(&mut self, now: Instant) -> DeltaRecord {
        self.redundant_remaining = self.redundant_remaining.saturating_sub(1);
        self.last_redundant_time = Some(now);

        // Encode from snapshot
        let payload = self.encode_full_from_snapshot();
        self.stats.redundant_fulls_sent += 1;

        DeltaRecord::Full {
            full_seq: self.full_seq,
            payload,
        }
    }

    fn send_delta(&mut self) -> DeltaRecord {
        self.patch_seq = self.patch_seq.wrapping_add(1);

        // Collect dirty fields
        let dirty_fields: Vec<(u32, Vec<u8>)> = self
            .fields
            .iter()
            .filter(|(_, f)| f.dirty)
            .map(|(id, f)| (*id, f.value.clone()))
            .collect();

        // Calculate bytes saved vs FULL
        let full_size: usize = self.fields.values().map(|f| f.value.len() + 8).sum();
        let delta_size: usize = dirty_fields.iter().map(|(_, v)| v.len() + 8).sum();
        if full_size > delta_size {
            self.stats.bytes_saved += (full_size - delta_size) as u64;
        }

        // Clear dirty flags
        for field in self.fields.values_mut() {
            field.dirty = false;
        }

        // Encode DELTA
        let payload = self.encode_delta(&dirty_fields);
        self.stats.deltas_sent += 1;

        DeltaRecord::Delta {
            base_full_seq: self.full_seq,
            patch_seq: self.patch_seq,
            payload,
        }
    }

    fn encode_full(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(256);
        let mut tmp = [0u8; 10];

        // full_seq
        let n = encode_varint(self.full_seq as u64, &mut tmp);
        buf.extend_from_slice(&tmp[..n]);

        // field_count
        let n = encode_varint(self.fields.len() as u64, &mut tmp);
        buf.extend_from_slice(&tmp[..n]);

        // fields (sorted by ID for determinism)
        let mut field_ids: Vec<_> = self.fields.keys().copied().collect();
        field_ids.sort();

        for field_id in field_ids {
            let field = &self.fields[&field_id];

            // field_id
            let n = encode_varint(field_id as u64, &mut tmp);
            buf.extend_from_slice(&tmp[..n]);

            // value_len
            let n = encode_varint(field.value.len() as u64, &mut tmp);
            buf.extend_from_slice(&tmp[..n]);

            // value
            buf.extend_from_slice(&field.value);
        }

        buf
    }

    fn encode_full_from_snapshot(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(256);
        let mut tmp = [0u8; 10];

        // full_seq
        let n = encode_varint(self.full_seq as u64, &mut tmp);
        buf.extend_from_slice(&tmp[..n]);

        // field_count
        let n = encode_varint(self.full_snapshot.len() as u64, &mut tmp);
        buf.extend_from_slice(&tmp[..n]);

        // fields (sorted by ID)
        let mut field_ids: Vec<_> = self.full_snapshot.keys().copied().collect();
        field_ids.sort();

        for field_id in field_ids {
            let value = &self.full_snapshot[&field_id];

            // field_id
            let n = encode_varint(field_id as u64, &mut tmp);
            buf.extend_from_slice(&tmp[..n]);

            // value_len
            let n = encode_varint(value.len() as u64, &mut tmp);
            buf.extend_from_slice(&tmp[..n]);

            // value
            buf.extend_from_slice(value);
        }

        buf
    }

    fn encode_delta(&self, dirty_fields: &[(u32, Vec<u8>)]) -> Vec<u8> {
        let mut buf = Vec::with_capacity(128);
        let mut tmp = [0u8; 10];

        // base_full_seq
        let n = encode_varint(self.full_seq as u64, &mut tmp);
        buf.extend_from_slice(&tmp[..n]);

        // patch_seq
        let n = encode_varint(self.patch_seq as u64, &mut tmp);
        buf.extend_from_slice(&tmp[..n]);

        // field_count
        let n = encode_varint(dirty_fields.len() as u64, &mut tmp);
        buf.extend_from_slice(&tmp[..n]);

        // fields (sorted by ID)
        let mut sorted: Vec<_> = dirty_fields.to_vec();
        sorted.sort_by_key(|(id, _)| *id);

        for (field_id, value) in sorted {
            // field_id
            let n = encode_varint(field_id as u64, &mut tmp);
            buf.extend_from_slice(&tmp[..n]);

            // value_len
            let n = encode_varint(value.len() as u64, &mut tmp);
            buf.extend_from_slice(&tmp[..n]);

            // value
            buf.extend_from_slice(&value);
        }

        buf
    }

    /// Get current statistics.
    pub fn stats(&self) -> &DeltaEncoderStats {
        &self.stats
    }

    /// Reset statistics.
    pub fn reset_stats(&mut self) {
        self.stats = DeltaEncoderStats::default();
    }
}

/// Delta decoder for the receiver side.
#[derive(Debug)]
pub struct DeltaDecoder {
    /// Current field values (reconstructed state).
    fields: HashMap<u32, Vec<u8>>,
    /// Last received FULL sequence.
    last_full_seq: Option<u32>,
    /// Last received patch sequence.
    last_patch_seq: u32,
    /// Statistics.
    pub stats: DeltaDecoderStats,
}

impl DeltaDecoder {
    /// Create a new delta decoder.
    pub fn new() -> Self {
        Self {
            fields: HashMap::new(),
            last_full_seq: None,
            last_patch_seq: 0,
            stats: DeltaDecoderStats::default(),
        }
    }

    /// Process a received FULL record.
    pub fn on_full(&mut self, payload: &[u8]) -> Result<u32, DeltaError> {
        let (full_seq, fields) = Self::decode_full(payload)?;

        // Check for resync
        if let Some(last) = self.last_full_seq {
            if full_seq != last && full_seq != last.wrapping_add(1) {
                self.stats.resyncs += 1;
            }
        }

        self.fields = fields;
        self.last_full_seq = Some(full_seq);
        self.last_patch_seq = 0;
        self.stats.fulls_received += 1;

        Ok(full_seq)
    }

    /// Process a received DELTA record.
    pub fn on_delta(&mut self, payload: &[u8]) -> Result<u32, DeltaError> {
        let (base_full_seq, patch_seq, changed_fields) = Self::decode_delta(payload)?;

        // Check if we have the base FULL
        match self.last_full_seq {
            None => {
                self.stats.deltas_dropped += 1;
                return Err(DeltaError::BaseMissing(base_full_seq));
            }
            Some(last) if last != base_full_seq => {
                self.stats.deltas_dropped += 1;
                return Err(DeltaError::BaseMissing(base_full_seq));
            }
            _ => {}
        }

        // Apply patch
        for (field_id, value) in changed_fields {
            self.fields.insert(field_id, value);
        }

        self.last_patch_seq = patch_seq;
        self.stats.deltas_received += 1;

        Ok(patch_seq)
    }

    /// Process a record (auto-detect FULL vs DELTA).
    pub fn on_record(&mut self, payload: &[u8], is_delta: bool) -> Result<(), DeltaError> {
        if is_delta {
            self.on_delta(payload)?;
        } else {
            self.on_full(payload)?;
        }
        Ok(())
    }

    /// Get the current value of a field.
    pub fn get_field(&self, field_id: u32) -> Option<&[u8]> {
        self.fields.get(&field_id).map(|v| v.as_slice())
    }

    /// Get all current field values.
    pub fn get_all_fields(&self) -> &HashMap<u32, Vec<u8>> {
        &self.fields
    }

    /// Get the last received FULL sequence.
    pub fn last_full_seq(&self) -> Option<u32> {
        self.last_full_seq
    }

    /// Check if decoder has valid state (received at least one FULL).
    pub fn has_valid_state(&self) -> bool {
        self.last_full_seq.is_some()
    }

    /// Generate a STATE_ACK message to confirm FULL reception.
    pub fn generate_state_ack(&mut self) -> Option<StateAck> {
        self.last_full_seq.map(|seq| {
            self.stats.state_acks_sent += 1;
            StateAck { last_full_seq: seq }
        })
    }

    /// Get current statistics.
    pub fn stats(&self) -> &DeltaDecoderStats {
        &self.stats
    }

    /// Reset statistics.
    pub fn reset_stats(&mut self) {
        self.stats = DeltaDecoderStats::default();
    }

    fn decode_full(payload: &[u8]) -> Result<(u32, HashMap<u32, Vec<u8>>), DeltaError> {
        let mut offset = 0;

        // full_seq
        let (full_seq, n) =
            decode_varint(&payload[offset..]).map_err(|_| DeltaError::VarintError)?;
        offset += n;
        let full_seq = full_seq as u32;

        // field_count
        if offset >= payload.len() {
            return Err(DeltaError::InvalidPayload);
        }
        let (field_count, n) =
            decode_varint(&payload[offset..]).map_err(|_| DeltaError::VarintError)?;
        offset += n;

        let mut fields = HashMap::new();

        for _ in 0..field_count {
            if offset >= payload.len() {
                return Err(DeltaError::InvalidPayload);
            }

            // field_id
            let (field_id, n) =
                decode_varint(&payload[offset..]).map_err(|_| DeltaError::VarintError)?;
            offset += n;

            // value_len
            if offset >= payload.len() {
                return Err(DeltaError::InvalidPayload);
            }
            let (value_len, n) =
                decode_varint(&payload[offset..]).map_err(|_| DeltaError::VarintError)?;
            offset += n;

            // value
            let value_len = value_len as usize;
            if offset + value_len > payload.len() {
                return Err(DeltaError::InvalidPayload);
            }
            let value = payload[offset..offset + value_len].to_vec();
            offset += value_len;

            fields.insert(field_id as u32, value);
        }

        Ok((full_seq, fields))
    }

    #[allow(clippy::type_complexity)] // Delta decode result: (base_seq, delta_seq, field_updates)
    fn decode_delta(payload: &[u8]) -> Result<(u32, u32, Vec<(u32, Vec<u8>)>), DeltaError> {
        let mut offset = 0;

        // base_full_seq
        let (base_full_seq, n) =
            decode_varint(&payload[offset..]).map_err(|_| DeltaError::VarintError)?;
        offset += n;
        let base_full_seq = base_full_seq as u32;

        // patch_seq
        if offset >= payload.len() {
            return Err(DeltaError::InvalidPayload);
        }
        let (patch_seq, n) =
            decode_varint(&payload[offset..]).map_err(|_| DeltaError::VarintError)?;
        offset += n;
        let patch_seq = patch_seq as u32;

        // field_count
        if offset >= payload.len() {
            return Err(DeltaError::InvalidPayload);
        }
        let (field_count, n) =
            decode_varint(&payload[offset..]).map_err(|_| DeltaError::VarintError)?;
        offset += n;

        let mut fields = Vec::new();

        for _ in 0..field_count {
            if offset >= payload.len() {
                return Err(DeltaError::InvalidPayload);
            }

            // field_id
            let (field_id, n) =
                decode_varint(&payload[offset..]).map_err(|_| DeltaError::VarintError)?;
            offset += n;

            // value_len
            if offset >= payload.len() {
                return Err(DeltaError::InvalidPayload);
            }
            let (value_len, n) =
                decode_varint(&payload[offset..]).map_err(|_| DeltaError::VarintError)?;
            offset += n;

            // value
            let value_len = value_len as usize;
            if offset + value_len > payload.len() {
                return Err(DeltaError::InvalidPayload);
            }
            let value = payload[offset..offset + value_len].to_vec();
            offset += value_len;

            fields.push((field_id as u32, value));
        }

        Ok((base_full_seq, patch_seq, fields))
    }
}

impl Default for DeltaDecoder {
    fn default() -> Self {
        Self::new()
    }
}

/// STATE_ACK message to confirm FULL reception.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateAck {
    /// Last received FULL sequence number.
    pub last_full_seq: u32,
}

impl StateAck {
    /// Encode STATE_ACK to buffer.
    pub fn encode(&self, buf: &mut [u8]) -> Result<usize, DeltaError> {
        let len = varint_len(self.last_full_seq as u64);
        if buf.len() < len {
            return Err(DeltaError::BufferTooSmall);
        }
        let n = encode_varint(self.last_full_seq as u64, buf);
        Ok(n)
    }

    /// Decode STATE_ACK from buffer.
    pub fn decode(buf: &[u8]) -> Result<(Self, usize), DeltaError> {
        let (last_full_seq, n) = decode_varint(buf).map_err(|_| DeltaError::VarintError)?;
        Ok((
            Self {
                last_full_seq: last_full_seq as u32,
            },
            n,
        ))
    }
}

/// Helper to calculate FULL payload size.
pub fn estimate_full_size(fields: &[(u32, &[u8])]) -> usize {
    let mut size = 0;
    // full_seq (assume 2 bytes avg)
    size += 2;
    // field_count
    size += varint_len(fields.len() as u64);
    // fields
    for (field_id, value) in fields {
        size += varint_len(*field_id as u64);
        size += varint_len(value.len() as u64);
        size += value.len();
    }
    size
}

/// Helper to calculate DELTA payload size.
pub fn estimate_delta_size(base_full_seq: u32, patch_seq: u32, fields: &[(u32, &[u8])]) -> usize {
    let mut size = 0;
    size += varint_len(base_full_seq as u64);
    size += varint_len(patch_seq as u64);
    size += varint_len(fields.len() as u64);
    for (field_id, value) in fields {
        size += varint_len(*field_id as u64);
        size += varint_len(value.len() as u64);
        size += value.len();
    }
    size
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_delta_config_default() {
        let config = DeltaConfig::default();
        assert_eq!(config.keyframe_period, Duration::from_millis(5000));
        assert_eq!(config.keyframe_redundancy, 2);
        assert_eq!(config.redundancy_spacing, Duration::from_millis(200));
        assert_eq!(config.max_fields, 64);
    }

    #[test]
    fn test_encoder_first_poll_is_full() {
        let mut encoder = DeltaEncoder::new(DeltaConfig::default());
        encoder.update_field(0, b"temp=25.5");
        encoder.update_field(1, b"humidity=60");

        let now = Instant::now();
        let record = encoder.poll_record(now);

        match record {
            DeltaRecord::Full { full_seq, payload } => {
                assert_eq!(full_seq, 1);
                assert!(!payload.is_empty());
            }
            other => unreachable!("Expected FULL record, got {:?}", other),
        }
    }

    #[test]
    fn test_encoder_delta_after_full() {
        let mut encoder = DeltaEncoder::new(DeltaConfig::default());
        encoder.update_field(0, b"temp=25.5");

        let now = Instant::now();

        // First poll: FULL
        let _ = encoder.poll_record(now);

        // Update field
        encoder.update_field(0, b"temp=26.0");

        // Second poll: DELTA
        let record = encoder.poll_record(now);

        match record {
            DeltaRecord::Delta {
                base_full_seq,
                patch_seq,
                payload,
            } => {
                assert_eq!(base_full_seq, 1);
                assert_eq!(patch_seq, 1);
                assert!(!payload.is_empty());
            }
            other => unreachable!("Expected DELTA record, got {:?}", other),
        }
    }

    #[test]
    fn test_encoder_no_change_no_record() {
        let mut encoder = DeltaEncoder::new(DeltaConfig::default());
        encoder.update_field(0, b"temp=25.5");

        let now = Instant::now();

        // First poll: FULL
        let _ = encoder.poll_record(now);

        // No changes - should return None
        let record = encoder.poll_record(now);
        assert_eq!(record, DeltaRecord::None);
    }

    #[test]
    fn test_encoder_redundant_fulls() {
        let config = DeltaConfig {
            keyframe_redundancy: 2,
            redundancy_spacing: Duration::from_millis(100),
            ..Default::default()
        };
        let mut encoder = DeltaEncoder::new(config);
        encoder.update_field(0, b"temp=25.5");

        let start = Instant::now();

        // First poll: FULL
        let record1 = encoder.poll_record(start);
        assert!(matches!(record1, DeltaRecord::Full { .. }));

        // Immediately after: no record (spacing not elapsed)
        let record2 = encoder.poll_record(start);
        assert_eq!(record2, DeltaRecord::None);

        // After spacing: redundant FULL
        let later = start + Duration::from_millis(150);
        let record3 = encoder.poll_record(later);
        assert!(matches!(record3, DeltaRecord::Full { .. }));

        // After another spacing: second redundant FULL
        let even_later = later + Duration::from_millis(150);
        let record4 = encoder.poll_record(even_later);
        assert!(matches!(record4, DeltaRecord::Full { .. }));

        // No more redundant FULLs
        let much_later = even_later + Duration::from_millis(150);
        let record5 = encoder.poll_record(much_later);
        assert_eq!(record5, DeltaRecord::None);

        assert_eq!(encoder.stats.fulls_sent, 1);
        assert_eq!(encoder.stats.redundant_fulls_sent, 2);
    }

    #[test]
    fn test_encoder_periodic_full() {
        let config = DeltaConfig {
            keyframe_period: Duration::from_millis(100),
            keyframe_redundancy: 0,
            ..Default::default()
        };
        let mut encoder = DeltaEncoder::new(config);
        encoder.update_field(0, b"temp=25.5");

        let start = Instant::now();

        // First poll: FULL
        let record1 = encoder.poll_record(start);
        assert!(matches!(record1, DeltaRecord::Full { full_seq: 1, .. }));

        // Before period: no FULL
        encoder.update_field(0, b"temp=26.0");
        let record2 = encoder.poll_record(start + Duration::from_millis(50));
        assert!(matches!(record2, DeltaRecord::Delta { .. }));

        // After period: new FULL
        encoder.update_field(0, b"temp=27.0");
        let record3 = encoder.poll_record(start + Duration::from_millis(150));
        assert!(matches!(record3, DeltaRecord::Full { full_seq: 2, .. }));
    }

    #[test]
    fn test_decoder_full_decode() {
        let mut decoder = DeltaDecoder::new();

        // Create a FULL payload manually
        let mut encoder = DeltaEncoder::new(DeltaConfig::default());
        encoder.update_field(0, b"temp=25.5");
        encoder.update_field(1, b"humidity=60");

        let now = Instant::now();
        let record = encoder.poll_record(now);

        if let DeltaRecord::Full { payload, .. } = record {
            let full_seq = decoder.on_full(&payload).unwrap();
            assert_eq!(full_seq, 1);
            assert_eq!(decoder.get_field(0), Some(b"temp=25.5".as_slice()));
            assert_eq!(decoder.get_field(1), Some(b"humidity=60".as_slice()));
        }
    }

    #[test]
    fn test_decoder_delta_decode() {
        let mut encoder = DeltaEncoder::new(DeltaConfig::default());
        let mut decoder = DeltaDecoder::new();

        encoder.update_field(0, b"temp=25.5");
        encoder.update_field(1, b"humidity=60");

        let now = Instant::now();

        // FULL
        if let DeltaRecord::Full { payload, .. } = encoder.poll_record(now) {
            decoder.on_full(&payload).unwrap();
        }

        // Update and DELTA
        encoder.update_field(0, b"temp=26.0");
        if let DeltaRecord::Delta { payload, .. } = encoder.poll_record(now) {
            let patch_seq = decoder.on_delta(&payload).unwrap();
            assert_eq!(patch_seq, 1);
            assert_eq!(decoder.get_field(0), Some(b"temp=26.0".as_slice()));
            assert_eq!(decoder.get_field(1), Some(b"humidity=60".as_slice())); // unchanged
        }
    }

    #[test]
    fn test_decoder_delta_without_base() {
        let mut decoder = DeltaDecoder::new();

        // Try to decode a DELTA without having received FULL
        let mut encoder = DeltaEncoder::new(DeltaConfig::default());
        encoder.update_field(0, b"temp=25.5");

        let now = Instant::now();
        let _ = encoder.poll_record(now); // FULL (discard)

        encoder.update_field(0, b"temp=26.0");
        if let DeltaRecord::Delta { payload, .. } = encoder.poll_record(now) {
            let result = decoder.on_delta(&payload);
            assert!(matches!(result, Err(DeltaError::BaseMissing(_))));
            assert_eq!(decoder.stats.deltas_dropped, 1);
        }
    }

    #[test]
    fn test_decoder_resync_detection() {
        let mut decoder = DeltaDecoder::new();

        // First FULL (seq=1)
        let mut encoder = DeltaEncoder::new(DeltaConfig {
            keyframe_period: Duration::from_millis(1),
            keyframe_redundancy: 0,
            ..Default::default()
        });
        encoder.update_field(0, b"temp=25.5");

        let now = Instant::now();
        if let DeltaRecord::Full { payload, .. } = encoder.poll_record(now) {
            decoder.on_full(&payload).unwrap();
        }

        // Simulate gap: send seq=5 (skipped 2,3,4)
        for _ in 0..4 {
            encoder.update_field(0, b"x");
            let later = now + Duration::from_millis(10);
            let _ = encoder.poll_record(later); // force new FULLs
        }

        // This should trigger resync
        encoder.update_field(0, b"temp=30.0");
        let much_later = now + Duration::from_millis(100);
        if let DeltaRecord::Full { payload, .. } = encoder.poll_record(much_later) {
            decoder.on_full(&payload).unwrap();
        }

        assert!(decoder.stats.resyncs > 0);
    }

    #[test]
    fn test_state_ack_encode_decode() {
        let ack = StateAck { last_full_seq: 42 };

        let mut buf = [0u8; 16];
        let len = ack.encode(&mut buf).unwrap();

        let (decoded, consumed) = StateAck::decode(&buf[..len]).unwrap();
        assert_eq!(decoded.last_full_seq, 42);
        assert_eq!(consumed, len);
    }

    #[test]
    fn test_decoder_generate_state_ack() {
        let mut decoder = DeltaDecoder::new();

        // No FULL yet
        assert!(decoder.generate_state_ack().is_none());

        // After FULL
        let mut encoder = DeltaEncoder::new(DeltaConfig::default());
        encoder.update_field(0, b"data");
        if let DeltaRecord::Full { payload, .. } = encoder.poll_record(Instant::now()) {
            decoder.on_full(&payload).unwrap();
        }

        let ack = decoder.generate_state_ack();
        assert!(ack.is_some());
        assert_eq!(ack.unwrap().last_full_seq, 1);
        assert_eq!(decoder.stats.state_acks_sent, 1);
    }

    #[test]
    fn test_estimate_full_size() {
        let fields: Vec<(u32, &[u8])> = vec![(0, b"temp"), (1, b"humidity")];
        let size = estimate_full_size(&fields);
        // full_seq(~2) + field_count(1) + field0(1+1+4) + field1(1+1+8) = ~19
        assert!(size > 15 && size < 30);
    }

    #[test]
    fn test_estimate_delta_size() {
        let fields: Vec<(u32, &[u8])> = vec![(0, b"temp")];
        let size = estimate_delta_size(1, 1, &fields);
        // base_seq(1) + patch_seq(1) + count(1) + field(1+1+4) = ~9
        assert!(size > 5 && size < 15);
    }

    #[test]
    fn test_encoder_stats() {
        let config = DeltaConfig {
            keyframe_redundancy: 1,
            redundancy_spacing: Duration::from_millis(1),
            ..Default::default()
        };
        let mut encoder = DeltaEncoder::new(config);
        encoder.update_field(0, b"temp=25.5");

        let now = Instant::now();

        // FULL
        let _ = encoder.poll_record(now);
        assert_eq!(encoder.stats.fulls_sent, 1);

        // Redundant FULL
        let later = now + Duration::from_millis(10);
        let _ = encoder.poll_record(later);
        assert_eq!(encoder.stats.redundant_fulls_sent, 1);

        // DELTA
        encoder.update_field(0, b"temp=26.0");
        let _ = encoder.poll_record(later);
        assert_eq!(encoder.stats.deltas_sent, 1);
    }

    #[test]
    fn test_decoder_stats() {
        let mut encoder = DeltaEncoder::new(DeltaConfig::default());
        let mut decoder = DeltaDecoder::new();

        encoder.update_field(0, b"data");
        let now = Instant::now();

        // FULL
        if let DeltaRecord::Full { payload, .. } = encoder.poll_record(now) {
            decoder.on_full(&payload).unwrap();
        }
        assert_eq!(decoder.stats.fulls_received, 1);

        // DELTA
        encoder.update_field(0, b"new_data");
        if let DeltaRecord::Delta { payload, .. } = encoder.poll_record(now) {
            decoder.on_delta(&payload).unwrap();
        }
        assert_eq!(decoder.stats.deltas_received, 1);
    }

    #[test]
    fn test_force_full() {
        let mut encoder = DeltaEncoder::new(DeltaConfig::default());
        encoder.update_field(0, b"data");

        let now = Instant::now();

        // Force FULL (even though no poll needed)
        let record = encoder.force_full(now);
        assert!(matches!(record, DeltaRecord::Full { .. }));
    }

    #[test]
    fn test_full_roundtrip_many_fields() {
        let mut encoder = DeltaEncoder::new(DeltaConfig::default());
        let mut decoder = DeltaDecoder::new();

        // Add many fields
        for i in 0..20 {
            encoder.update_field(i, format!("field_{}", i).as_bytes());
        }

        let now = Instant::now();
        if let DeltaRecord::Full { payload, .. } = encoder.poll_record(now) {
            decoder.on_full(&payload).unwrap();
        }

        // Verify all fields
        for i in 0..20 {
            let expected = format!("field_{}", i);
            assert_eq!(decoder.get_field(i), Some(expected.as_bytes()));
        }
    }

    #[test]
    fn test_delta_only_dirty_fields() {
        let mut encoder = DeltaEncoder::new(DeltaConfig::default());
        let mut decoder = DeltaDecoder::new();

        encoder.update_field(0, b"field0");
        encoder.update_field(1, b"field1");
        encoder.update_field(2, b"field2");

        let now = Instant::now();

        // FULL with 3 fields
        if let DeltaRecord::Full { payload, .. } = encoder.poll_record(now) {
            decoder.on_full(&payload).unwrap();
        }

        // Update only field 1
        encoder.update_field(1, b"field1_updated");

        if let DeltaRecord::Delta { payload, .. } = encoder.poll_record(now) {
            // DELTA should be smaller than FULL
            let full_size =
                estimate_full_size(&[(0, b"field0"), (1, b"field1_updated"), (2, b"field2")]);
            assert!(payload.len() < full_size);

            decoder.on_delta(&payload).unwrap();
        }

        // Verify state
        assert_eq!(decoder.get_field(0), Some(b"field0".as_slice()));
        assert_eq!(decoder.get_field(1), Some(b"field1_updated".as_slice()));
        assert_eq!(decoder.get_field(2), Some(b"field2".as_slice()));
    }

    #[test]
    fn test_decode_invalid_full() {
        let mut decoder = DeltaDecoder::new();

        // Empty payload
        assert!(decoder.on_full(&[]).is_err());

        // Truncated payload
        assert!(decoder.on_full(&[0x01]).is_err());

        // Invalid field count
        assert!(decoder.on_full(&[0x01, 0xFF, 0xFF, 0xFF, 0xFF]).is_err());
    }

    #[test]
    fn test_decode_invalid_delta() {
        let mut decoder = DeltaDecoder::new();

        // Need a base FULL first
        let mut encoder = DeltaEncoder::new(DeltaConfig::default());
        encoder.update_field(0, b"data");
        if let DeltaRecord::Full { payload, .. } = encoder.poll_record(Instant::now()) {
            decoder.on_full(&payload).unwrap();
        }

        // Empty delta payload
        assert!(decoder.on_delta(&[]).is_err());

        // Truncated delta payload
        assert!(decoder.on_delta(&[0x01]).is_err());
    }

    #[test]
    fn test_has_valid_state() {
        let mut decoder = DeltaDecoder::new();
        assert!(!decoder.has_valid_state());

        let mut encoder = DeltaEncoder::new(DeltaConfig::default());
        encoder.update_field(0, b"data");
        if let DeltaRecord::Full { payload, .. } = encoder.poll_record(Instant::now()) {
            decoder.on_full(&payload).unwrap();
        }

        assert!(decoder.has_valid_state());
    }

    #[test]
    fn test_get_all_fields() {
        let mut decoder = DeltaDecoder::new();
        let mut encoder = DeltaEncoder::new(DeltaConfig::default());

        encoder.update_field(0, b"a");
        encoder.update_field(1, b"b");

        if let DeltaRecord::Full { payload, .. } = encoder.poll_record(Instant::now()) {
            decoder.on_full(&payload).unwrap();
        }

        let fields = decoder.get_all_fields();
        assert_eq!(fields.len(), 2);
        assert_eq!(fields.get(&0), Some(&b"a".to_vec()));
        assert_eq!(fields.get(&1), Some(&b"b".to_vec()));
    }
}
