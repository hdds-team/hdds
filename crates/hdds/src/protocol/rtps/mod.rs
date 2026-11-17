// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! # Standard RTPS Submessage Encoders (OMG RTPS 2.3 Specification)
//!
//! This module contains **vendor-neutral** RTPS encoding logic per the OMG specification.
//! Dialect modules import from here - NEVER the reverse.
//!
//! If a vendor needs different encoding, they override in their dialect module.
//!
//! # ARCHITECTURAL CONSTRAINT
//!
//! ```text
//! ALLOWED:   dialect::* -> protocol::rtps::*
//! FORBIDDEN: protocol::rtps -> dialect::*
//! ```
//!
//! # Submessages
//!
//! - ACKNACK (0x06): Positive/negative acknowledgment
//! - HEARTBEAT (0x07): Writer liveliness and available sequences
//! - GAP (0x08): Irrelevant sequence numbers
//! - DATA (0x15): User data payload
//! - DATA_FRAG (0x16): Fragmented user data
//! - INFO_TS (0x09): Timestamp for subsequent submessages
//! - INFO_DST (0x0E): Destination GUID prefix
//!
//! # References
//!
//! - OMG RTPS 2.3 spec: Section 8.3.7 (Submessages)
//! - OMG RTPS 2.3 spec: Section 9.4.5 (SequenceNumberSet)

mod acknack;
mod data;
mod gap;
mod heartbeat;
mod info;
mod locator;
pub mod participant_message;

pub use acknack::{encode_acknack, encode_acknack_with_count, encode_acknack_with_final};
pub use data::{encode_data, encode_data_frag};
pub use gap::encode_gap;
pub use heartbeat::{encode_heartbeat, encode_heartbeat_final};
pub use info::{encode_info_dst, encode_info_ts};
pub(crate) use locator::encode_locator_parameter;
pub use locator::{encode_multicast_locator, encode_unicast_locator};

/// Result type for RTPS encoding operations.
pub type RtpsEncodeResult<T> = Result<T, RtpsEncodeError>;

/// Split a 64-bit sequence number into the two words of an RTPS
/// `SequenceNumber_t` (DDSI-RTPS v2.5 Sec.9.4.2.5): the signed high word and
/// the unsigned low word, with `value = high * 2^32 + low`.
///
/// This is the ONE place the crate narrows a sequence number. Every encoder
/// writes both words, so no information is lost: the receive side
/// (`protocol::builder::extract::extract_sequence_number`) reassembles the
/// same 64-bit value from the two words. Keeping the split here means the
/// encoders share a single justified site instead of each carrying a cast.
#[inline]
#[must_use]
pub fn split_sequence_number(sn: u64) -> (i32, u32) {
    let sn_high = (sn >> 32) as i32; // @audit-ok: RTPS SequenceNumber_t high word (DDSI-RTPS 9.4.2.5); both words are emitted and extract_sequence_number reassembles them
    let sn_low = sn as u32; // @audit-ok: RTPS SequenceNumber_t low word (DDSI-RTPS 9.4.2.5); both words are emitted and extract_sequence_number reassembles them
    (sn_high, sn_low)
}

/// Wire bytes of an RTPS `SequenceNumber_t` in little-endian order: the high
/// word first, then the low word (DDSI-RTPS v2.5 Sec.9.4.2.5).
#[inline]
#[must_use]
pub fn sequence_number_le_bytes(sn: u64) -> [u8; 8] {
    let (sn_high, sn_low) = split_sequence_number(sn);
    let mut bytes = [0u8; 8];
    bytes[..4].copy_from_slice(&sn_high.to_le_bytes());
    bytes[4..].copy_from_slice(&sn_low.to_le_bytes());
    bytes
}

/// Narrow a submessage body length to the `octetsToNextHeader` field
/// (DDSI-RTPS v2.5 Sec.9.4.5.1.3, a u16). A body that does not fit is an
/// encoding error, never a truncated header: the caller must fragment
/// (DATA_FRAG) or shrink the payload.
///
/// This is the rule for a submessage that may be FOLLOWED by another one
/// (a DATA with a HEARTBEAT appended, say): the field must then carry the
/// exact length, and 0 is not available to it. A submessage the caller
/// knows to be the last in its message may use
/// [`octets_to_next_header_for_last_submessage`] instead. The two are the
/// same rule with its one exception, kept together here; the dialect layer
/// (`protocol::dialect::common::octets_to_next_header`) delegates to this
/// function rather than restating it.
#[inline]
pub fn octets_to_next_header(submsg_len: usize) -> RtpsEncodeResult<u16> {
    u16::try_from(submsg_len).map_err(|_| {
        RtpsEncodeError::InvalidParameter("submessage body exceeds octetsToNextHeader (u16)")
    })
}

/// `octetsToNextHeader` for a submessage that is the LAST one in its message.
///
/// DDSI-RTPS v2.5 Sec.9.4.5.1.3: on a submessage other than PAD and INFO_TS,
/// `octetsToNextHeader == 0` means "extends to the end of the message". So a
/// body that does not fit the u16 is not an encoding error for the last
/// submessage: it is encoded as 0, and the receiver reads to the end of the
/// datagram (HDDS does, in `protocol::builder::packet`, `engine::router` and
/// the multicast classifier). At exactly 65536 body octets the only correct
/// encoding IS the sentinel, which is why this cannot be folded into the
/// checked variant above: the checked variant refuses that value, correctly,
/// because a submessage with a successor has no sentinel available.
///
/// The body still has to fit the transport; a UDP datagram cannot carry it,
/// and the send fails there, by name. This function only refuses to lie in
/// the length field about a body some transport can carry.
#[inline]
#[must_use]
pub fn octets_to_next_header_for_last_submessage(submsg_len: usize) -> u16 {
    u16::try_from(submsg_len).unwrap_or(0)
}

/// Errors that can occur during RTPS encoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RtpsEncodeError {
    /// Buffer is too small for the encoded data.
    BufferTooSmall,
    /// Invalid parameter provided.
    InvalidParameter(&'static str),
}

impl std::fmt::Display for RtpsEncodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BufferTooSmall => write!(f, "buffer too small for RTPS encoding"),
            Self::InvalidParameter(msg) => write!(f, "invalid parameter: {}", msg),
        }
    }
}

impl std::error::Error for RtpsEncodeError {}

#[cfg(test)]
mod tests {
    use super::*;

    /// The checked rule refuses a body that does not fit, INCLUDING exactly
    /// 65536: a submessage that may have a successor has no sentinel.
    #[test]
    fn a_submessage_with_a_successor_refuses_a_body_that_does_not_fit() {
        assert_eq!(octets_to_next_header(0), Ok(0));
        assert_eq!(octets_to_next_header(65_535), Ok(65_535));
        assert!(octets_to_next_header(65_536).is_err());
        assert!(octets_to_next_header(70_000).is_err());
    }

    /// The last submessage gets the sentinel instead, at exactly 65536 (the
    /// one value where 0 is the ONLY correct encoding) and above.
    #[test]
    fn the_last_submessage_uses_the_sentinel_where_the_field_runs_out() {
        assert_eq!(octets_to_next_header_for_last_submessage(65_535), 65_535);
        assert_eq!(octets_to_next_header_for_last_submessage(65_536), 0);
        assert_eq!(octets_to_next_header_for_last_submessage(70_000), 0);
        assert_eq!(octets_to_next_header_for_last_submessage(12), 12);
    }

    /// Both words are emitted, so the split loses nothing: the wire bytes
    /// reassemble to the input for values that need both words.
    #[test]
    fn the_split_keeps_both_words() {
        let sn = 0x0000_0001_0000_0002u64;
        assert_eq!(split_sequence_number(sn), (1, 2));
        let bytes = sequence_number_le_bytes(sn);
        let high = i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let low = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        assert_eq!(
            (i64::from(high) << 32) | i64::from(low),
            0x0000_0001_0000_0002
        );
    }
}
