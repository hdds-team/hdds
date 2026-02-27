// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! INFO_TS and INFO_DST submessage encoders (RTPS 2.3 Section 8.3.7.7-8)
//!
//! INFO_TS provides timestamp information for subsequent submessages.
//! INFO_DST specifies the destination GUID prefix for subsequent submessages.

/// Encode an INFO_TS submessage per RTPS 2.3 specification.
///
/// # Arguments
///
/// * `timestamp_sec` - Seconds part of the timestamp
/// * `timestamp_frac` - Fractional part of the timestamp (1/2^32 seconds)
///
/// # Returns
///
/// Encoded INFO_TS submessage bytes (12 bytes).
pub fn encode_info_ts(timestamp_sec: u32, timestamp_frac: u32) -> Vec<u8> {
    let mut buf = vec![0u8; 12];

    // Submessage header
    buf[0] = 0x09; // INFO_TS
    buf[1] = 0x01; // Flags: LE
    buf[2..4].copy_from_slice(&8u16.to_le_bytes()); // length

    // Timestamp (Time_t = sec:u32 + frac:u32)
    buf[4..8].copy_from_slice(&timestamp_sec.to_le_bytes());
    buf[8..12].copy_from_slice(&timestamp_frac.to_le_bytes());

    buf
}

/// Encode an INFO_DST submessage per RTPS 2.3 specification.
///
/// # Arguments
///
/// * `guid_prefix` - 12-byte GUID prefix of the destination participant
///
/// # Returns
///
/// Encoded INFO_DST submessage bytes (16 bytes).
pub fn encode_info_dst(guid_prefix: &[u8; 12]) -> Vec<u8> {
    let mut buf = vec![0u8; 16];

    // Submessage header
    buf[0] = 0x0E; // INFO_DST
    buf[1] = 0x01; // Flags: LE
    buf[2..4].copy_from_slice(&12u16.to_le_bytes()); // length

    // GUID prefix
    buf[4..16].copy_from_slice(guid_prefix);

    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_INFO_TS_SEC: u32 = 1_234_567_890;
    const TEST_INFO_TS_FRAC: u32 = 0x8000_0000;

    #[test]
    fn test_info_ts_encoding() {
        let buf = encode_info_ts(TEST_INFO_TS_SEC, TEST_INFO_TS_FRAC);

        assert_eq!(buf.len(), 12);
        assert_eq!(buf[0], 0x09); // INFO_TS
        assert_eq!(buf[1], 0x01); // LE flag

        let sec = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
        assert_eq!(sec, TEST_INFO_TS_SEC);
    }

    #[test]
    fn test_info_dst_encoding() {
        let guid_prefix = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
        ];
        let buf = encode_info_dst(&guid_prefix);

        assert_eq!(buf.len(), 16);
        assert_eq!(buf[0], 0x0E); // INFO_DST
        assert_eq!(&buf[4..16], &guid_prefix);
    }
}
