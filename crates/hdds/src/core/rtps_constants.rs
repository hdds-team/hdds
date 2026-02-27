// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! RTPS protocol constants (DDS-RTPS v2.3 Sec.8.3)
//!
//! Centralizes all RTPS magic numbers, vendor IDs, entity IDs, and protocol constants
//! to avoid duplication and make version/vendor changes easier.
//!

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

/// OCI OpenDDS vendor ID (for interop testing)
pub const OPENDDS_VENDOR_ID_U16: u16 = 0x0103;

/// Eclipse Cyclone DDS vendor ID (for interop testing)
pub const CYCLONEDDS_VENDOR_ID_U16: u16 = 0x0110;

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

/// TypeLookup built-in reader entity ID (XTypes request/reply reader)
/// Entity ID value: 0x000300C3
pub const RTPS_ENTITYID_TYPELOOKUP_READER: [u8; 4] = [0x00, 0x03, 0x00, 0xC3];

/// TypeLookup built-in writer entity ID (XTypes request/reply writer)
/// Entity ID value: 0x000300C4
pub const RTPS_ENTITYID_TYPELOOKUP_WRITER: [u8; 4] = [0x00, 0x03, 0x00, 0xC4];

/// Participant entity ID
pub const RTPS_ENTITYID_PARTICIPANT: [u8; 4] = [0x00, 0x00, 0x01, 0xC1];

/// User data writer entity kind (RTPS v2.3 Table 9.2 - entityKind = 0x03 for writers)
pub const ENTITY_KIND_USER_WRITER: u8 = 0x03;

/// User data reader entity kind (RTPS v2.3 Table 9.2 - entityKind = 0x04 for NO_KEY readers)
pub const ENTITY_KIND_USER_READER: u8 = 0x04;

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

/// NACK_FRAG submessage ID - Request retransmission of specific fragments (RTPS v2.3 Sec.8.3.7.5)
pub const RTPS_SUBMSG_NACK_FRAG: u8 = 0x12;

/// HEARTBEAT_FRAG submessage ID - Fragment-level heartbeat for reliable fragmented data (RTPS v2.3 Sec.8.3.7.6)
pub const RTPS_SUBMSG_HEARTBEAT_FRAG: u8 = 0x13;

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

/// CDR Little-Endian encapsulation kind
pub const CDR_LE: u16 = 0x0003;

/// CDR Big-Endian encapsulation kind
pub const CDR_BE: u16 = 0x0000;

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
        assert_ne!(
            RTPS_ENTITYID_TYPELOOKUP_READER,
            RTPS_ENTITYID_TYPELOOKUP_WRITER
        );
    }
}
