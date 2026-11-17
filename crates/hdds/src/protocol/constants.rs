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
//! - **TypeLookup** (XTypes): Type information lookup via 0x000300C3/C4
//!   (DDS-XTypes 1.3 Sec.7.6.3.3)
//!
//! # XTypes / TypeLookup Support
//!
//! DDS-XTypes 1.3 Sec.7.6.3.3.3 defines special entity IDs for dynamic type discovery:
//! - Reader: [0x00, 0x03, 0x00, 0xC3] (0x000300C3)
//! - Writer: [0x00, 0x03, 0x00, 0xC4] (0x000300C4)
//!
//! These are currently NOT actively processed by HDDS but are recognized as valid built-in
//! endpoints. Full XTypes support is planned for future releases.

/// RTPS protocol magic string: "RTPS" (Sec.8.3.3.1)
pub const RTPS_MAGIC: &[u8; 4] = b"RTPS";

/// RTPS protocol version: 2.4 (Sec.8.3.3.1)
///
/// HDDS announces 2.4 in its message headers (raised from 2.3): a receiver
/// that only accepts 2.4 or newer would otherwise discard HDDS messages,
/// and 2.4 is accepted by receivers implementing any 2.x version.
pub const RTPS_VERSION_MAJOR: u8 = 0x02;
pub const RTPS_VERSION_MINOR: u8 = 0x04;

// ============================================================================
// VENDOR IDs (OMG DDS Vendor Registry)
// ============================================================================
// Official registry: https://www.dds-foundation.org/dds-rtps-vendor-and-product-ids/
//
// To register a vendor ID: contact dds-chair@omg.org
//
// Known vendor IDs:
// - 0x0101: RTI Connext DDS
// - 0x000A: OpenSplice DDS (ADLink)
// - 0x000B: OpenDDS (OCI)
// - 0x010F: FastDDS/FastRTPS (eProsima)
// - 0x0110: Cyclone DDS (Eclipse)
// - 0x0112: RustDDS (Atostek)
// - 0x011A: HDDS (Naskel)
// ============================================================================

/// HDDS Vendor ID (official DDS Foundation assignment).
///
/// Current value: 0x011A, {0x01, 0x1A} on the wire. Assigned by the DDS
/// Foundation (dds-rtps-vendor-and-product-ids registry) to Naskel / HDDS
/// (High Performance DDS), per the DDS-SIG vendor ID registry. Supersedes the
/// pre-assignment experimental placeholder 0x01AA.
pub const HDDS_VENDOR_ID: [u8; 2] = [0x01, 0x1A];

// For easy comparison in parsers
pub const HDDS_VENDOR_ID_U16: u16 = 0x011A;

/// RTI Connext vendor ID (for interop testing)
pub const RTI_VENDOR_ID_U16: u16 = 0x0101;

/// eProsima FastDDS vendor ID (for interop testing)
pub const EPROSIMA_VENDOR_ID_U16: u16 = 0x010F;

/// Zenzen DDS (zzdds) vendor ID as registered with the DDS Foundation
/// (0x01 0x1B). zzdds announces it from 0.3.1 on.
pub const ZZDDS_VENDOR_ID_U16: u16 = 0x011B;

/// The pre-registration vendor ID zzdds announced up to 0.2.0. Kept so a
/// peer running an older zzdds still resolves to the same dialect.
pub const ZZDDS_LEGACY_VENDOR_ID_U16: u16 = 0x0123;

/// True for either vendor ID zzdds has announced. The dialect is the
/// same stack under two IDs, so every zzdds-keyed decision goes through
/// this predicate and never through one literal: when zzdds moved from
/// its placeholder 0x0123 to the registered 0x011B (0.3.1), a check keyed
/// on the literal stopped matching and every non-volatile zzdds writer
/// went silent for an HDDS reader (its user ACKNACKs went back to the
/// metatraffic port instead of the port the zzdds dialect selects).
pub const fn is_zzdds_vendor(vendor_id: u16) -> bool {
    vendor_id == ZZDDS_VENDOR_ID_U16 || vendor_id == ZZDDS_LEGACY_VENDOR_ID_U16
}

// ============================================================================
// RTPS Entity IDs (Sec.8.2.4.3)
// ============================================================================

/// SPDP built-in participant reader entity ID (ENTITYID_SPDP_BUILTIN_RTPSParticipant_READER = 0x000100C7)
pub const RTPS_ENTITYID_SPDP_READER: [u8; 4] = [0x00, 0x01, 0x00, 0xC7];

/// SPDP built-in participant writer entity ID (ENTITYID_SPDP_BUILTIN_RTPSParticipant_WRITER = 0x000100C2)
pub const RTPS_ENTITYID_SPDP_WRITER: [u8; 4] = [0x00, 0x01, 0x00, 0xC2];

/// SEDP publications (DataWriter) built-in reader entity ID
/// REVERT v91/v92 - EntityId_t is ALWAYS BIG-ENDIAN per RTPS v2.3 Sec.9.4.5.3
pub const RTPS_ENTITYID_SEDP_PUBLICATIONS_READER: [u8; 4] = [0x00, 0x00, 0x03, 0xC7];

/// SEDP publications (DataWriter) built-in writer entity ID
/// REVERT v91/v92 - EntityId_t is ALWAYS BIG-ENDIAN per RTPS v2.3 Sec.9.4.5.3
pub const RTPS_ENTITYID_SEDP_PUBLICATIONS_WRITER: [u8; 4] = [0x00, 0x00, 0x03, 0xC2];

/// SEDP subscriptions (DataReader) built-in reader entity ID
/// REVERT v91/v92 - EntityId_t is ALWAYS BIG-ENDIAN per RTPS v2.3 Sec.9.4.5.3
pub const RTPS_ENTITYID_SEDP_SUBSCRIPTIONS_READER: [u8; 4] = [0x00, 0x00, 0x04, 0xC7];

/// SEDP subscriptions (DataReader) built-in writer entity ID
/// REVERT v91/v92 - EntityId_t is ALWAYS BIG-ENDIAN per RTPS v2.3 Sec.9.4.5.3
pub const RTPS_ENTITYID_SEDP_SUBSCRIPTIONS_WRITER: [u8; 4] = [0x00, 0x00, 0x04, 0xC2];

/// Participant entity ID
pub const RTPS_ENTITYID_PARTICIPANT: [u8; 4] = [0x00, 0x00, 0x01, 0xC1];

/// User data writer entity kind (RTPS v2.5 Table 9.1)
/// 0x02 = WITH_KEY, 0x03 = NO_KEY. HDDS uses 0x03 for standard user writers (as FastDDS does).
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
pub use crate::core::rtps_constants::RTPS_ENTITYID_P2P_BUILTIN_PARTICIPANT_MESSAGE_WRITER;

/// P2P (Participant-to-Participant) built-in PARTICIPANT_MESSAGE DataReader entity ID
///
/// Used for receiving liveliness heartbeats and P2P messages from other participants.
/// Per RTPS v2.5 Sec.8.2.4.3, this is a built-in endpoint for ParticipantMessage.
/// Entity ID value: 0x000200C7 (big-endian, as all EntityId_t values are per spec)
///
/// Reference:
/// - RTPS v2.5 Table 9.12: BuiltinEndpointSet_t bitmask
/// - Bit 11 (0x800): BUILTIN_ENDPOINT_PARTICIPANT_MESSAGE_DATA_READER
pub use crate::core::rtps_constants::RTPS_ENTITYID_P2P_BUILTIN_PARTICIPANT_MESSAGE_READER;

/// TypeLookup Service Request Writer entity ID (XTypes v1.3 sec. 7.6.3.3.3 Table 61)
/// Entity value: 0x000300C3
pub const RTPS_ENTITYID_TYPELOOKUP_REQUEST_WRITER: [u8; 4] = [0x00, 0x03, 0x00, 0xC3];

/// TypeLookup Service Request Reader entity ID (XTypes v1.3 sec. 7.6.3.3.3 Table 61)
/// Entity value: 0x000300C4
pub const RTPS_ENTITYID_TYPELOOKUP_REQUEST_READER: [u8; 4] = [0x00, 0x03, 0x00, 0xC4];

// ============================================================================
// DDS-Security Built-in Endpoint Entity IDs (DDS Security v1.1 sec. 7.4.1.3 Table 11)
// ============================================================================
// Mirrored from `core/rtps_constants.rs` for consumers that import from this
// constants module. See the canonical block there for full documentation.
//
// 4 secure tunnels x (writer + reader) = 8 endpoints under the 0xff vendor-secure
// prefix, plus 2 stateless endpoints (0x000201) for the unencrypted handshake
// and 2 secure-volatile endpoints (0xff0202) for key exchange.
// ============================================================================

/// SPDP secure participant writer -- 0xff0101c2.
pub const RTPS_ENTITYID_SPDP_SECURE_WRITER: [u8; 4] = [0xff, 0x01, 0x01, 0xc2];

/// SPDP secure participant reader -- 0xff0101c7.
pub const RTPS_ENTITYID_SPDP_SECURE_READER: [u8; 4] = [0xff, 0x01, 0x01, 0xc7];

/// SEDP secure publications writer -- 0xff0003c2.
pub const RTPS_ENTITYID_SEDP_PUBLICATIONS_SECURE_WRITER: [u8; 4] = [0xff, 0x00, 0x03, 0xc2];

/// SEDP secure publications reader -- 0xff0003c7.
pub const RTPS_ENTITYID_SEDP_PUBLICATIONS_SECURE_READER: [u8; 4] = [0xff, 0x00, 0x03, 0xc7];

/// SEDP secure subscriptions writer -- 0xff0004c2.
pub const RTPS_ENTITYID_SEDP_SUBSCRIPTIONS_SECURE_WRITER: [u8; 4] = [0xff, 0x00, 0x04, 0xc2];

/// SEDP secure subscriptions reader -- 0xff0004c7.
pub const RTPS_ENTITYID_SEDP_SUBSCRIPTIONS_SECURE_READER: [u8; 4] = [0xff, 0x00, 0x04, 0xc7];

/// P2P participant-message secure writer -- 0xff0200c2.
pub const RTPS_ENTITYID_P2P_BUILTIN_PARTICIPANT_MESSAGE_SECURE_WRITER: [u8; 4] =
    [0xff, 0x02, 0x00, 0xc2];

/// P2P participant-message secure reader -- 0xff0200c7.
pub const RTPS_ENTITYID_P2P_BUILTIN_PARTICIPANT_MESSAGE_SECURE_READER: [u8; 4] =
    [0xff, 0x02, 0x00, 0xc7];

/// Participant-Stateless-Message writer (plaintext handshake) -- 0x000201c3.
pub const RTPS_ENTITYID_BUILTIN_PARTICIPANT_STATELESS_MESSAGE_WRITER: [u8; 4] =
    [0x00, 0x02, 0x01, 0xc3];

/// Participant-Stateless-Message reader (plaintext handshake) -- 0x000201c4.
pub const RTPS_ENTITYID_BUILTIN_PARTICIPANT_STATELESS_MESSAGE_READER: [u8; 4] =
    [0x00, 0x02, 0x01, 0xc4];

/// Participant-Volatile-Message secure writer (crypto key exchange) -- 0xff0202c3.
pub const RTPS_ENTITYID_BUILTIN_PARTICIPANT_VOLATILE_MESSAGE_SECURE_WRITER: [u8; 4] =
    [0xff, 0x02, 0x02, 0xc3];

/// Participant-Volatile-Message secure reader (crypto key exchange) -- 0xff0202c4.
pub const RTPS_ENTITYID_BUILTIN_PARTICIPANT_VOLATILE_MESSAGE_SECURE_READER: [u8; 4] =
    [0xff, 0x02, 0x02, 0xc4];

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
// Re-export from discovery/constants.rs to eliminate duplication
// The canonical definitions are in protocol/discovery/constants.rs

pub use super::discovery::constants::{
    CDR_BE, CDR_BE_VENDOR, CDR_LE, CDR_LE_VENDOR, PLAIN_CDR_BE, PLAIN_CDR_LE, PL_CDR2_BE,
    PL_CDR2_LE,
};

#[cfg(test)]
mod tests {
    #[test]
    fn is_zzdds_vendor_accepts_both_ids_and_nothing_else() {
        assert!(super::is_zzdds_vendor(super::ZZDDS_VENDOR_ID_U16));
        assert!(super::is_zzdds_vendor(super::ZZDDS_LEGACY_VENDOR_ID_U16));
        assert!(!super::is_zzdds_vendor(super::HDDS_VENDOR_ID_U16));
        assert!(!super::is_zzdds_vendor(super::EPROSIMA_VENDOR_ID_U16));
        assert!(!super::is_zzdds_vendor(0x011C));
    }

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
        assert_eq!(HDDS_VENDOR_ID, [0x01, 0x1A]);
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
