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
/// Changed from 2.3 to 2.4, so that a receiver that does not process
/// 2.3 headers accepts our messages.
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
// - 0x0102: OpenSplice DDS (ADLink)
// - 0x0103: OpenDDS (OCI)
// - 0x010F: FastDDS/FastRTPS (eProsima)
// - 0x0110: Cyclone DDS (Eclipse)
// - 0x0112: RustDDS (Atostek)
// - 0x0114: Dust DDS (S2E Software Systems B.V.)
// - 0x011A: HDDS (Naskel)
// ============================================================================

/// HDDS Vendor ID (official DDS Foundation assignment).
///
/// Current value: 0x011A, {0x01, 0x1A} on the wire. Assigned by the DDS
/// Foundation (dds-rtps-vendor-and-product-ids registry) to Naskel / HDDS
/// (High Performance DDS), per the DDS-SIG vendor ID registry. Supersedes the pre-assignment experimental placeholder 0x01AA.
pub const HDDS_VENDOR_ID: [u8; 2] = [0x01, 0x1A];

// For easy comparison in parsers
pub const HDDS_VENDOR_ID_U16: u16 = 0x011A;

/// RTI Connext vendor ID (for interop testing)
pub const RTI_VENDOR_ID_U16: u16 = 0x0101;

/// eProsima FastDDS vendor ID (for interop testing)
pub const EPROSIMA_VENDOR_ID_U16: u16 = 0x010F;

/// OCI OpenDDS vendor ID (for interop testing)
pub const OPENDDS_VENDOR_ID_U16: u16 = 0x0103;

/// Eclipse Cyclone DDS vendor ID (for interop testing)
pub const CYCLONEDDS_VENDOR_ID_U16: u16 = 0x0110;

/// InterCOM DDS vendor ID (for interop testing).
///
/// Peers with this vendorId are given the NO_KEY (0x04) reader kind in the
/// NACK_FRAG readerId (see `engine::router`), the kind their fragment repair
/// acts on; without it reliable large-data fragment repair toward them
/// stalls. Every other vendor gets the truthful WITH_KEY (0x07).
pub const INTERCOM_VENDOR_ID_U16: u16 = 0x0105;

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

/// TypeLookup Service Request Writer entity ID (XTypes v1.3 sec. 7.6.3.1)
///
/// Entity ID value: 0x000300C3 (entityKind 0xC3 = Builtin Writer)
/// FastDDS: ENTITYID_TL_SVC_REQ_WRITER
pub const RTPS_ENTITYID_TYPELOOKUP_REQUEST_WRITER: [u8; 4] = [0x00, 0x03, 0x00, 0xC3];

/// TypeLookup Service Request Reader entity ID (XTypes v1.3 sec. 7.6.3.1)
///
/// Entity ID value: 0x000300C4 (entityKind 0xC4 = Builtin Reader)
/// FastDDS: ENTITYID_TL_SVC_REQ_READER
pub const RTPS_ENTITYID_TYPELOOKUP_REQUEST_READER: [u8; 4] = [0x00, 0x03, 0x00, 0xC4];

/// TypeLookup Service Reply Writer entity ID (XTypes v1.3 sec. 7.6.3.1)
///
/// Entity ID value: 0x000301C3 (entityKind 0xC3 = Builtin Writer)
/// FastDDS: ENTITYID_TL_SVC_REPLY_WRITER
pub const RTPS_ENTITYID_TYPELOOKUP_REPLY_WRITER: [u8; 4] = [0x00, 0x03, 0x01, 0xC3];

/// TypeLookup Service Reply Reader entity ID (XTypes v1.3 sec. 7.6.3.1)
///
/// Entity ID value: 0x000301C4 (entityKind 0xC4 = Builtin Reader)
/// FastDDS: ENTITYID_TL_SVC_REPLY_READER
pub const RTPS_ENTITYID_TYPELOOKUP_REPLY_READER: [u8; 4] = [0x00, 0x03, 0x01, 0xC4];

// ============================================================================
// DDS-Security Built-in Endpoint Entity IDs (DDS Security v1.1 sec. 7.4.1.3 Table 11)
// ============================================================================
//
// 12 entity IDs covering 4 secure tunnels:
//   * SPDP secure (participant discovery encrypted)        -- 0xff0101 prefix
//   * SEDP secure publications / subscriptions             -- 0xff0003 / 0xff0004 prefix
//   * ParticipantMessage secure (liveliness encrypted)     -- 0xff0200 prefix
//   * ParticipantStatelessMessage (auth handshake, plain)  -- 0x000201 prefix
//   * ParticipantVolatileMessage secure (key exchange)     -- 0xff0202 prefix
//
// Wire format: 4 bytes big-endian (RTPS v2.3 sec. 9.4.5.3, EntityId_t is BE).
// First three bytes = entityKey; last byte = entityKind:
//   * 0xC2 -- BUILTIN_WRITER_WITH_KEY
//   * 0xC7 -- BUILTIN_READER_WITH_KEY
//   * 0xC3 -- BUILTIN_WRITER_NO_KEY (StatelessMessage, VolatileMessageSecure writers)
//   * 0xC4 -- BUILTIN_READER_NO_KEY (StatelessMessage, VolatileMessageSecure readers)
//
// Vendor-secure prefix 0xff: marks the endpoint as belonging to the DDS-Security
// reserved namespace and triggers crypto transformation on the wire (see
// `SecureSubMsg` / `SecureBodySubMsg` in DDS-Security v1.1 sec. 7.3.6).
//
// Stateless endpoints (0x000201xx) deliberately use the standard 0x00 prefix
// because the bootstrap handshake exchanges authentication tokens BEFORE any
// crypto material is available; payloads here are plaintext per sec. 7.4.5.
// ============================================================================

/// SPDP secure built-in participant writer (DDS Security v1.1 sec. 7.4.1.3)
/// Entity value: 0xff0101c2 (vendor-secure prefix, entityKind = builtin writer w/key).
pub const RTPS_ENTITYID_SPDP_SECURE_WRITER: [u8; 4] = [0xff, 0x01, 0x01, 0xc2];

/// SPDP secure built-in participant reader (DDS Security v1.1 sec. 7.4.1.3)
/// Entity value: 0xff0101c7 (vendor-secure prefix, entityKind = builtin reader w/key).
pub const RTPS_ENTITYID_SPDP_SECURE_READER: [u8; 4] = [0xff, 0x01, 0x01, 0xc7];

/// SEDP secure publications (DataWriter) built-in writer (DDS Security v1.1 sec. 7.4.1.3)
/// Entity value: 0xff0003c2.
pub const RTPS_ENTITYID_SEDP_PUBLICATIONS_SECURE_WRITER: [u8; 4] = [0xff, 0x00, 0x03, 0xc2];

/// SEDP secure publications (DataWriter) built-in reader (DDS Security v1.1 sec. 7.4.1.3)
/// Entity value: 0xff0003c7.
pub const RTPS_ENTITYID_SEDP_PUBLICATIONS_SECURE_READER: [u8; 4] = [0xff, 0x00, 0x03, 0xc7];

/// SEDP secure subscriptions (DataReader) built-in writer (DDS Security v1.1 sec. 7.4.1.3)
/// Entity value: 0xff0004c2.
pub const RTPS_ENTITYID_SEDP_SUBSCRIPTIONS_SECURE_WRITER: [u8; 4] = [0xff, 0x00, 0x04, 0xc2];

/// SEDP secure subscriptions (DataReader) built-in reader (DDS Security v1.1 sec. 7.4.1.3)
/// Entity value: 0xff0004c7.
pub const RTPS_ENTITYID_SEDP_SUBSCRIPTIONS_SECURE_READER: [u8; 4] = [0xff, 0x00, 0x04, 0xc7];

/// P2P participant-message built-in writer (RTPS v2.5 Sec.8.4.13, Table 9.4).
/// Entity value: 0x000200c2. Carries ParticipantMessageData - the liveliness
/// assertion a participant sends on its own behalf.
///
/// Announced by bit 10 of `PID_BUILTIN_ENDPOINT_SET`, which our own default
/// mask lights (`BUILTIN_ENDPOINT_SET_DEFAULT = 0x000F_0C3F`), so this is
/// traffic we ask every conforming peer for.
pub const RTPS_ENTITYID_P2P_BUILTIN_PARTICIPANT_MESSAGE_WRITER: [u8; 4] = [0x00, 0x02, 0x00, 0xc2];

/// P2P participant-message built-in reader (RTPS v2.5 Sec.8.4.13, Table 9.4).
/// Entity value: 0x000200c7. Announced by bit 11 of the same mask.
pub const RTPS_ENTITYID_P2P_BUILTIN_PARTICIPANT_MESSAGE_READER: [u8; 4] = [0x00, 0x02, 0x00, 0xc7];

/// Participant-Message secure built-in writer (DDS Security v1.1 sec. 7.4.1.3)
/// Entity value: 0xff0200c2. Liveliness messages, encrypted.
pub const RTPS_ENTITYID_P2P_BUILTIN_PARTICIPANT_MESSAGE_SECURE_WRITER: [u8; 4] =
    [0xff, 0x02, 0x00, 0xc2];

/// Participant-Message secure built-in reader (DDS Security v1.1 sec. 7.4.1.3)
/// Entity value: 0xff0200c7. Liveliness messages, encrypted.
pub const RTPS_ENTITYID_P2P_BUILTIN_PARTICIPANT_MESSAGE_SECURE_READER: [u8; 4] =
    [0xff, 0x02, 0x00, 0xc7];

/// Participant-Stateless-Message writer (DDS Security v1.1 sec. 7.4.1.3 + sec. 7.4.5)
/// Entity value: 0x000201c3. Plaintext channel for the PKI-DH handshake. NO_KEY.
pub const RTPS_ENTITYID_BUILTIN_PARTICIPANT_STATELESS_MESSAGE_WRITER: [u8; 4] =
    [0x00, 0x02, 0x01, 0xc3];

/// Participant-Stateless-Message reader (DDS Security v1.1 sec. 7.4.1.3 + sec. 7.4.5)
/// Entity value: 0x000201c4. Plaintext channel for the PKI-DH handshake. NO_KEY.
pub const RTPS_ENTITYID_BUILTIN_PARTICIPANT_STATELESS_MESSAGE_READER: [u8; 4] =
    [0x00, 0x02, 0x01, 0xc4];

/// Participant-Volatile-Message secure writer (DDS Security v1.1 sec. 7.4.1.3 + sec. 7.4.4)
/// Entity value: 0xff0202c3. Crypto-key exchange channel. NO_KEY, encrypted.
pub const RTPS_ENTITYID_BUILTIN_PARTICIPANT_VOLATILE_MESSAGE_SECURE_WRITER: [u8; 4] =
    [0xff, 0x02, 0x02, 0xc3];

/// Participant-Volatile-Message secure reader (DDS Security v1.1 sec. 7.4.1.3 + sec. 7.4.4)
/// Entity value: 0xff0202c4. Crypto-key exchange channel. NO_KEY, encrypted.
pub const RTPS_ENTITYID_BUILTIN_PARTICIPANT_VOLATILE_MESSAGE_SECURE_READER: [u8; 4] =
    [0xff, 0x02, 0x02, 0xc4];

/// Participant entity ID
pub const RTPS_ENTITYID_PARTICIPANT: [u8; 4] = [0x00, 0x00, 0x01, 0xC1];

/// User data writer entity kind -- WITH_KEY (RTPS v2.5 Table 9.1)
/// Used for types that have @key fields (e.g. ShapeType with @key color)
pub const ENTITY_KIND_USER_WRITER_WITH_KEY: u8 = 0x02;

/// User data writer entity kind -- NO_KEY (RTPS v2.5 Table 9.1)
/// Used for types without @key fields
pub const ENTITY_KIND_USER_WRITER_NO_KEY: u8 = 0x03;

/// User data reader entity kind -- NO_KEY (RTPS v2.5 Table 9.1)
pub const ENTITY_KIND_USER_READER_NO_KEY: u8 = 0x04;

/// User data reader entity kind -- WITH_KEY (RTPS v2.5 Table 9.1)
pub const ENTITY_KIND_USER_READER_WITH_KEY: u8 = 0x07;

/// Legacy aliases (kept for backwards compatibility with existing code)
pub const ENTITY_KIND_USER_WRITER: u8 = ENTITY_KIND_USER_WRITER_NO_KEY;
pub const ENTITY_KIND_USER_READER: u8 = ENTITY_KIND_USER_READER_NO_KEY;

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

/// NACK_FRAG submessage ID - Request retransmission of specific fragments (RTPS v2.5 Sec.8.3.8.12)
pub const RTPS_SUBMSG_NACK_FRAG: u8 = 0x12;

/// HEARTBEAT_FRAG submessage ID - Fragment-level heartbeat for reliable fragmented data (RTPS v2.5 Sec.8.3.8.7)
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

/// CDR Big-Endian encapsulation kind (Sec.10)
/// NOTE: The canonical CDR_BE (0x0002) is at `protocol/discovery/constants.rs`.
/// This value is kept for local use but should be considered deprecated.
pub const CDR_BE: u16 = 0x0002;

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
        assert_ne!(
            RTPS_ENTITYID_TYPELOOKUP_REQUEST_WRITER,
            RTPS_ENTITYID_TYPELOOKUP_REQUEST_READER
        );
    }
}
