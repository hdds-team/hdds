// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! RTPS protocol constants (DDS-RTPS v2.3 Sec.8.3 / v2.5)
//!
//!
//! Centralizes all RTPS magic numbers, vendor IDs, entity IDs, and protocol constants
//! to avoid duplication and make version/vendor changes easier.
//!
//! # Built-in Endpoint Sets
//!
//! Standard RTPS participants implement these built-in endpoints for discovery:
//! - **SPDP** (Simple Participant Discovery): Entity IDs 0x000100C1 (reader) / 0x000100C2 (writer)
//! - **SEDP** (Simple Endpoint Discovery): Publications and Subscriptions via separate entity IDs
//! - **P2P** (Participant-to-Participant): Liveliness heartbeats via 0x000200C2/C7
//! - **TypeLookup** (XTypes): Type information lookup via 0x000300C3/C4 (FastDDS, RTI Connext)
//!
//! # XTypes / TypeLookup Support
//!
//! FastDDS and RTI Connext use special entity IDs for dynamic type discovery (XTypes):
//! - Reader: [0x00, 0x03, 0x00, 0xC3] (0x000300C3)
//! - Writer: [0x00, 0x03, 0x00, 0xC4] (0x000300C4)
//!
//! These are currently NOT actively processed by HDDS but are recognized as valid built-in
//! endpoints. Full XTypes support is planned for future releases.

/// RTPS protocol magic string: "RTPS" (Sec.8.3.3.1)
pub const RTPS_MAGIC: &[u8; 4] = b"RTPS";

/// RTPS protocol version: 2.4 (Sec.8.3.3.1)
///
/// v192: Changed from 2.3 to 2.4 for OpenDDS compatibility.
/// OpenDDS requires RTPS v2.4 in packet headers and ignores v2.3 packets.
/// All major DDS vendors (RTI, FastDDS, OpenDDS) support v2.4.
pub const RTPS_VERSION_MAJOR: u8 = 0x02;
pub const RTPS_VERSION_MINOR: u8 = 0x04;

// ============================================================================
// VENDOR IDs (OMG DDS Vendor Registry)
// ============================================================================
// Official registry: https://www.dds-foundation.org/dds-rtps-vendor-and-product-ids/
//
// To register a vendor ID: contact dds-chair@omg.org
//
// IMPORTANT: Change this to your registered vendor ID in production!
//            For experimental/research use, 0x01AA is fine.
//
// Known vendor IDs:
// - 0x0101: RTI Connext DDS
// - 0x0102: OpenSplice DDS (ADLink)
// - 0x0103: OpenDDS (OCI)
// - 0x010F: FastDDS/FastRTPS (eProsima)
// - 0x0110: Cyclone DDS (Eclipse)
// - 0x0112: RustDDS (Atostek)
// ============================================================================

/// HDDS Vendor ID (EXPERIMENTAL - not registered with OMG).
///
/// Current value: 0x01AA (experimental, not assigned in OMG registry).
/// Production deployments should register an official OMG vendor ID.
pub const HDDS_VENDOR_ID: [u8; 2] = [0x01, 0xAA];

// For easy comparison in parsers
pub const HDDS_VENDOR_ID_U16: u16 = 0x01AA;

/// RTI Connext vendor ID (for interop testing)
pub const RTI_VENDOR_ID_U16: u16 = 0x0101;

/// eProsima FastDDS vendor ID (for interop testing)
pub const EPROSIMA_VENDOR_ID_U16: u16 = 0x010F;

// ============================================================================
// RTPS Entity IDs (Sec.8.2.4.3)
// ============================================================================

/// SPDP built-in participant reader entity ID (ENTITYID_SPDP_BUILTIN_RTPSParticipant_READER = 0x000100C7)
pub const RTPS_ENTITYID_SPDP_READER: [u8; 4] = [0x00, 0x01, 0x00, 0xC7];

/// SPDP built-in participant writer entity ID (ENTITYID_SPDP_BUILTIN_RTPSParticipant_WRITER = 0x000100C2)
pub const RTPS_ENTITYID_SPDP_WRITER: [u8; 4] = [0x00, 0x01, 0x00, 0xC2];

/// SEDP publications (DataWriter) built-in reader entity ID
/// v93: REVERT v91/v92 - EntityId_t is ALWAYS BIG-ENDIAN per RTPS v2.3 Sec.9.4.5.3
pub const RTPS_ENTITYID_SEDP_PUBLICATIONS_READER: [u8; 4] = [0x00, 0x00, 0x03, 0xC7];

/// SEDP publications (DataWriter) built-in writer entity ID
/// v93: REVERT v91/v92 - EntityId_t is ALWAYS BIG-ENDIAN per RTPS v2.3 Sec.9.4.5.3
pub const RTPS_ENTITYID_SEDP_PUBLICATIONS_WRITER: [u8; 4] = [0x00, 0x00, 0x03, 0xC2];

/// SEDP subscriptions (DataReader) built-in reader entity ID
/// v93: REVERT v91/v92 - EntityId_t is ALWAYS BIG-ENDIAN per RTPS v2.3 Sec.9.4.5.3
pub const RTPS_ENTITYID_SEDP_SUBSCRIPTIONS_READER: [u8; 4] = [0x00, 0x00, 0x04, 0xC7];

/// SEDP subscriptions (DataReader) built-in writer entity ID
/// v93: REVERT v91/v92 - EntityId_t is ALWAYS BIG-ENDIAN per RTPS v2.3 Sec.9.4.5.3
pub const RTPS_ENTITYID_SEDP_SUBSCRIPTIONS_WRITER: [u8; 4] = [0x00, 0x00, 0x04, 0xC2];

/// Participant entity ID
pub const RTPS_ENTITYID_PARTICIPANT: [u8; 4] = [0x00, 0x00, 0x01, 0xC1];

/// User data writer entity kind (RTPS v2.3 Table 9.2 - entityKind = 0x03 for writers)
pub const ENTITY_KIND_USER_WRITER: u8 = 0x03;

/// User data reader entity kind (RTPS v2.3 Table 9.2 - entityKind = 0x04 for NO_KEY readers)
pub const ENTITY_KIND_USER_READER: u8 = 0x04;

/// P2P (Participant-to-Participant) built-in PARTICIPANT_MESSAGE DataWriter entity ID
///
/// Used for liveliness heartbeats and P2P communication between participants.
/// Per RTPS v2.5 Sec.8.2.4.3, this is a built-in endpoint for ParticipantMessage.
/// Entity ID value: 0x000200C2 (big-endian, as all EntityId_t values are per spec)
///
/// Reference:
/// - RTPS v2.5 Table 9.12: BuiltinEndpointSet_t bitmask
/// - Bit 10 (0x400): BUILTIN_ENDPOINT_PARTICIPANT_MESSAGE_DATA_WRITER
pub const RTPS_ENTITYID_P2P_BUILTIN_PARTICIPANT_MESSAGE_WRITER: [u8; 4] = [0x00, 0x02, 0x00, 0xC2];

/// P2P (Participant-to-Participant) built-in PARTICIPANT_MESSAGE DataReader entity ID
///
/// Used for receiving liveliness heartbeats and P2P messages from other participants.
/// Per RTPS v2.5 Sec.8.2.4.3, this is a built-in endpoint for ParticipantMessage.
/// Entity ID value: 0x000200C7 (big-endian, as all EntityId_t values are per spec)
///
/// Reference:
/// - RTPS v2.5 Table 9.12: BuiltinEndpointSet_t bitmask
/// - Bit 11 (0x800): BUILTIN_ENDPOINT_PARTICIPANT_MESSAGE_DATA_READER
pub const RTPS_ENTITYID_P2P_BUILTIN_PARTICIPANT_MESSAGE_READER: [u8; 4] = [0x00, 0x02, 0x00, 0xC7];

/// TypeLookup built-in reader entity ID (XTypes request/reply reader)
/// Entity ID value: 0x000300C3
pub const RTPS_ENTITYID_TYPELOOKUP_READER: [u8; 4] = [0x00, 0x03, 0x00, 0xC3];

/// TypeLookup built-in writer entity ID (XTypes request/reply writer)
/// Entity ID value: 0x000300C4
pub const RTPS_ENTITYID_TYPELOOKUP_WRITER: [u8; 4] = [0x00, 0x03, 0x00, 0xC4];

// ============================================================================
// RTPS Submessage IDs (RTPS v2.3 Table 8.13)
// ============================================================================

/// INFO_TS submessage ID - Timestamp information
pub const RTPS_SUBMSG_INFO_TS: u8 = 0x09;

/// INFO_DST submessage ID - Destination GUID prefix
pub const RTPS_SUBMSG_INFO_DST: u8 = 0x0e;

/// ACKNACK submessage ID - Reliable protocol acknowledgment (RTPS v2.3 Sec.8.3.5.4)
pub const RTPS_SUBMSG_ACKNACK: u8 = 0x06;

/// HEARTBEAT submessage ID - Reliable protocol heartbeat (RTPS v2.3 Sec.8.3.5.5)
pub const RTPS_SUBMSG_HEARTBEAT: u8 = 0x07;

/// GAP submessage ID - Indicates irrelevant sequence numbers
pub const RTPS_SUBMSG_GAP: u8 = 0x08;

/// DATA submessage ID - Complete user/discovery data
pub const RTPS_SUBMSG_DATA: u8 = 0x15;

/// DATA_FRAG submessage ID - Fragmented user/discovery data
pub const RTPS_SUBMSG_DATA_FRAG: u8 = 0x16;

/// HEADER_EXTENSION submessage ID (non-standard, used by some vendors)
pub const RTPS_SUBMSG_HEADER_EXTENSION: u8 = 0x00;

// ============================================================================
// Protocol sizes and offsets (Sec.8.3.3)
// ============================================================================

/// RTPS header size (magic + version + vendor + GUID prefix)
pub const RTPS_HEADER_SIZE: usize = 20;

/// GUID prefix size (RTPS v2.3 spec: 12 bytes)
pub const RTPS_GUID_PREFIX_SIZE: usize = 12;

/// Minimum submessage header size
pub const RTPS_SUBMSG_HEADER_MIN_SIZE: usize = 4;

// ============================================================================
// CDR Encapsulation constants (Sec.10)
// ============================================================================
// v111: Re-export from discovery/constants.rs to eliminate duplication
// The canonical definitions are in protocol/discovery/constants.rs

pub use super::discovery::constants::{
    CDR2_BE, CDR2_LE, CDR_BE, CDR_BE_VENDOR, CDR_LE, CDR_LE_VENDOR, PLAIN_CDR_BE, PLAIN_CDR_LE,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rtps_constants() {
        assert_eq!(RTPS_MAGIC, b"RTPS");
        assert_eq!(RTPS_VERSION_MAJOR, 2);
        assert_eq!(RTPS_VERSION_MINOR, 4);
        assert_eq!(RTPS_HEADER_SIZE, 20);
        assert_eq!(RTPS_GUID_PREFIX_SIZE, 12);
    }

    #[test]
    fn test_vendor_id_format() {
        // Ensure vendor ID is in big-endian format (wire format)
        assert_eq!(HDDS_VENDOR_ID, [0x01, 0xAA]);
        assert_eq!(
            u16::from_be_bytes(HDDS_VENDOR_ID),
            HDDS_VENDOR_ID_U16,
            "Vendor ID array and u16 must match"
        );
    }

    #[test]
    fn test_entity_ids_unique() {
        // Verify all entity IDs are distinct
        assert_ne!(RTPS_ENTITYID_SPDP_READER, RTPS_ENTITYID_SPDP_WRITER);
        assert_ne!(
            RTPS_ENTITYID_SEDP_PUBLICATIONS_READER,
            RTPS_ENTITYID_SEDP_PUBLICATIONS_WRITER
        );
        assert_ne!(
            RTPS_ENTITYID_SEDP_SUBSCRIPTIONS_READER,
            RTPS_ENTITYID_SEDP_SUBSCRIPTIONS_WRITER
        );
        // P2P EntityIds should be distinct
        assert_ne!(
            RTPS_ENTITYID_P2P_BUILTIN_PARTICIPANT_MESSAGE_WRITER,
            RTPS_ENTITYID_P2P_BUILTIN_PARTICIPANT_MESSAGE_READER
        );
    }

    #[test]
    fn test_p2p_entity_ids() {
        // Verify P2P Participant Message EntityIds per RTPS v2.5 Sec.8.2.4.3
        assert_eq!(
            RTPS_ENTITYID_P2P_BUILTIN_PARTICIPANT_MESSAGE_WRITER,
            [0x00, 0x02, 0x00, 0xC2],
            "P2P writer EntityId should match RTPS spec value"
        );
        assert_eq!(
            RTPS_ENTITYID_P2P_BUILTIN_PARTICIPANT_MESSAGE_READER,
            [0x00, 0x02, 0x00, 0xC7],
            "P2P reader EntityId should match RTPS spec value"
        );

        // Verify they're recognized as built-in endpoints (last byte 0xC2/0xC7)
        assert_eq!(
            RTPS_ENTITYID_P2P_BUILTIN_PARTICIPANT_MESSAGE_WRITER[3], 0xC2,
            "P2P writer last byte should be built-in indicator"
        );
        assert_eq!(
            RTPS_ENTITYID_P2P_BUILTIN_PARTICIPANT_MESSAGE_READER[3], 0xC7,
            "P2P reader last byte should be built-in indicator"
        );
    }

    #[test]
    fn test_p2p_vs_sedp_entity_ids() {
        // P2P and SEDP EntityIds should be distinct
        assert_ne!(
            RTPS_ENTITYID_P2P_BUILTIN_PARTICIPANT_MESSAGE_WRITER,
            RTPS_ENTITYID_SEDP_PUBLICATIONS_WRITER
        );
        assert_ne!(
            RTPS_ENTITYID_P2P_BUILTIN_PARTICIPANT_MESSAGE_READER,
            RTPS_ENTITYID_SEDP_SUBSCRIPTIONS_READER
        );

        // P2P uses 0x02 entity ID (vs 0x03/0x04 for SEDP)
        assert_eq!(
            RTPS_ENTITYID_P2P_BUILTIN_PARTICIPANT_MESSAGE_WRITER[1], 0x02,
            "P2P EntityIds use 0x02 entity key"
        );
        assert_eq!(
            RTPS_ENTITYID_SEDP_PUBLICATIONS_WRITER[1], 0x00,
            "SEDP EntityIds use 0x00 entity key"
        );
    }
}
