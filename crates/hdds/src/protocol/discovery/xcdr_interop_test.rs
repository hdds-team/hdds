// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Unit tests for XCDR multi-vendor interoperability.
//!
//! These tests verify that the XCDR parser can handle packets from different
//! DDS vendors (RTI, FastDDS, Cyclone) with various encapsulation formats.

#[cfg(test)]
mod tests {
    use crate::core::discovery::GUID;
    use crate::protocol::discovery::spdp::parse_spdp;

    /// Test parsing RTI Connext SPDP packet with PL_CDR_BE (0x0002).
    ///
    /// This simulates a real RTI packet with big-endian parameter list encoding.
    #[test]
    fn test_parse_rti_pl_cdr_be() {
        // Simulated RTI SPDP packet with PL_CDR_BE encapsulation (0x0002)
        let packet = vec![
            // Encapsulation header (4 bytes) - ALWAYS big-endian per CDR spec
            0x00, 0x02, // PL_CDR_BE (0x0002)
            0x00, 0x00, // Options
            // Parameter: PID_PARTICIPANT_GUID (0x0050)
            0x00, 0x50, // PID (big-endian)
            0x00, 0x10, // Length = 16 (big-endian)
            // GUID (16 bytes)
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x00, 0x00,
            0x01, 0xc1, // Parameter: PID_PARTICIPANT_LEASE_DURATION (0x0002)
            0x00, 0x02, // PID (big-endian)
            0x00, 0x08, // Length = 8 (big-endian)
            0x00, 0x00, 0x00, 0x1e, // 30 seconds (big-endian)
            0x00, 0x00, 0x00, 0x00, // 0 nanoseconds
            // Sentinel
            0x00, 0x01, // PID_SENTINEL (big-endian)
            0x00, 0x00, // Length = 0
        ];

        let result = parse_spdp(&packet);
        assert!(result.is_ok(), "Failed to parse RTI PL_CDR_BE packet");

        let spdp = result.expect("RTI PL_CDR_BE packet should parse");
        assert_eq!(
            spdp.participant_guid,
            GUID::from_bytes([
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x00, 0x00,
                0x01, 0xc1
            ])
        );
        assert_eq!(spdp.lease_duration_ms, 30_000); // 30 seconds
    }

    /// Test parsing HDDS SPDP packet with PL_CDR_LE (0x0003).
    ///
    /// This is the current HDDS format (little-endian parameter list).
    #[test]
    fn test_parse_hdds_pl_cdr_le() {
        // HDDS SPDP packet with PL_CDR_LE encapsulation (0x0003)
        let packet = vec![
            // Encapsulation header
            0x00, 0x03, // PL_CDR_LE (little-endian)
            0x00, 0x00, // Options
            // Parameter: PID_PARTICIPANT_GUID
            0x50, 0x00, // PID (little-endian)
            0x10, 0x00, // Length = 16 (little-endian)
            // GUID (16 bytes)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
            0x01, 0xc1, // Parameter: PID_PARTICIPANT_LEASE_DURATION
            0x02, 0x00, // PID (little-endian)
            0x08, 0x00, // Length = 8 (little-endian)
            0xdc, 0x05, 0x00, 0x00, // 1500 seconds (little-endian)
            0x00, 0x00, 0x00, 0x00, // 0 nanoseconds
            // Sentinel
            0x01, 0x00, // PID_SENTINEL (little-endian)
            0x00, 0x00, // Length = 0
        ];

        let result = parse_spdp(&packet);
        assert!(result.is_ok(), "Failed to parse HDDS PL_CDR_LE packet");

        let spdp = result.expect("HDDS PL_CDR_LE packet should parse");
        assert_eq!(
            spdp.participant_guid,
            GUID::from_bytes([
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
                0x01, 0xc1
            ])
        );
        assert_eq!(spdp.lease_duration_ms, 1_500_000); // 1500 seconds
    }

    /// Test rejection of non-parameter-list format (plain CDR).
    ///
    /// SPDP requires parameter list encoding, plain CDR should be rejected.
    #[test]
    fn test_reject_plain_cdr() {
        // Plain CDR_LE packet (0x0001) - not valid for SPDP
        let packet = vec![
            0x01, 0x00, // CDR_LE (plain, not parameter list)
            0x00, 0x00, // Options
            // Some data...
            0x01, 0x02, 0x03, 0x04,
        ];

        let result = parse_spdp(&packet);
        assert!(
            result.is_err(),
            "Should reject non-parameter-list format for SPDP"
        );
    }

    /// Test handling of unknown encapsulation format.
    #[test]
    fn test_reject_unknown_encapsulation() {
        // Unknown encapsulation 0xFFFF
        let packet = vec![0xff, 0xff, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04];

        let result = parse_spdp(&packet);
        assert!(
            result.is_err(),
            "Should reject unknown encapsulation format"
        );
    }

    /// Test handling of truncated packet.
    #[test]
    fn test_reject_truncated_packet() {
        // Packet too short (less than 4 bytes header)
        let packet = vec![0x00, 0x03];

        let result = parse_spdp(&packet);
        assert!(result.is_err(), "Should reject truncated packet");
    }
}
