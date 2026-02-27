// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! HEARTBEAT submessage encoder (RTPS 2.3 Section 8.3.7.5)
//!
//! The HEARTBEAT submessage is sent by a Writer to inform Readers about
//! the availability of DATA messages and to keep the communication alive.

use super::RtpsEncodeResult;

/// Encode a HEARTBEAT submessage per RTPS 2.3 specification.
///
/// # Arguments
///
/// * `reader_id` - EntityId of the target Reader (can be ENTITYID_UNKNOWN)
/// * `writer_id` - EntityId of the Writer sending the HEARTBEAT
/// * `first_sn` - First available sequence number
/// * `last_sn` - Last available sequence number
/// * `count` - HEARTBEAT count (monotonically increasing)
///
/// # Returns
///
/// Encoded HEARTBEAT submessage bytes (32 bytes).
///
/// # RTPS Format
///
/// ```text
/// 0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |   HEARTBEAT   |     flags     |      octetsToNextHeader       |
/// +---------------+---------------+-------------------------------+
/// |                         readerId                              |
/// +---------------------------------------------------------------+
/// |                         writerId                              |
/// +---------------------------------------------------------------+
/// |                                                               |
/// +                     firstSN (SequenceNumber)                  +
/// |                                                               |
/// +---------------------------------------------------------------+
/// |                                                               |
/// +                     lastSN (SequenceNumber)                   +
/// |                                                               |
/// +---------------------------------------------------------------+
/// |                           count                               |
/// +---------------------------------------------------------------+
/// ```
pub fn encode_heartbeat(
    reader_id: &[u8; 4],
    writer_id: &[u8; 4],
    first_sn: u64,
    last_sn: u64,
    count: u32,
) -> RtpsEncodeResult<Vec<u8>> {
    let mut buf = vec![0u8; 32];

    // Submessage header
    buf[0] = 0x07; // HEARTBEAT
    buf[1] = 0x01; // Flags: Endianness=LE
    buf[2..4].copy_from_slice(&28u16.to_le_bytes()); // octetsToNextHeader

    // Reader EntityId
    buf[4..8].copy_from_slice(reader_id);

    // Writer EntityId
    buf[8..12].copy_from_slice(writer_id);

    // First available sequence number (SequenceNumber_t = high:i32 + low:u32)
    let first_high = (first_sn >> 32) as i32;
    let first_low = first_sn as u32;
    buf[12..16].copy_from_slice(&first_high.to_le_bytes());
    buf[16..20].copy_from_slice(&first_low.to_le_bytes());

    // Last sequence number
    let last_high = (last_sn >> 32) as i32;
    let last_low = last_sn as u32;
    buf[20..24].copy_from_slice(&last_high.to_le_bytes());
    buf[24..28].copy_from_slice(&last_low.to_le_bytes());

    // Count
    buf[28..32].copy_from_slice(&count.to_le_bytes());

    Ok(buf)
}

/// Encode a HEARTBEAT with the Final flag set.
///
/// The Final flag (F) indicates that the Writer does not require a response
/// from the Reader. This is used when the Writer has no data (firstSN > lastSN)
/// to prevent infinite HEARTBEAT/ACKNACK loops.
///
/// v138: Fix RTI interop - set Final flag to stop ACKNACK loop.
pub fn encode_heartbeat_final(
    reader_id: &[u8; 4],
    writer_id: &[u8; 4],
    first_sn: u64,
    last_sn: u64,
    count: u32,
) -> RtpsEncodeResult<Vec<u8>> {
    let mut buf = vec![0u8; 32];

    // Submessage header
    buf[0] = 0x07; // HEARTBEAT
    buf[1] = 0x03; // Flags: Final=1, Endianness=LE (v138: set Final flag)
    buf[2..4].copy_from_slice(&28u16.to_le_bytes());

    buf[4..8].copy_from_slice(reader_id);
    buf[8..12].copy_from_slice(writer_id);

    let first_high = (first_sn >> 32) as i32;
    let first_low = first_sn as u32;
    buf[12..16].copy_from_slice(&first_high.to_le_bytes());
    buf[16..20].copy_from_slice(&first_low.to_le_bytes());

    let last_high = (last_sn >> 32) as i32;
    let last_low = last_sn as u32;
    buf[20..24].copy_from_slice(&last_high.to_le_bytes());
    buf[24..28].copy_from_slice(&last_low.to_le_bytes());

    buf[28..32].copy_from_slice(&count.to_le_bytes());

    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_heartbeat_encoding() {
        let reader_id = [0x00, 0x00, 0x00, 0x00]; // ENTITYID_UNKNOWN
        let writer_id = [0x00, 0x00, 0x03, 0xC2]; // SEDP publications writer
        let first_sn = 1u64;
        let last_sn = 10u64;
        let count = 5u32;

        let result = encode_heartbeat(&reader_id, &writer_id, first_sn, last_sn, count);
        assert!(result.is_ok());

        let buf = result.unwrap();
        assert_eq!(buf.len(), 32);
        assert_eq!(buf[0], 0x07); // HEARTBEAT
        assert_eq!(buf[1], 0x01); // LE flag

        // Verify count at offset 28
        let encoded_count = u32::from_le_bytes([buf[28], buf[29], buf[30], buf[31]]);
        assert_eq!(encoded_count, 5);
    }
}
