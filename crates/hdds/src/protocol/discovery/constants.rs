// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

pub(super) const FNV1A_OFFSET_BASIS_64: u64 = 0xcbf2_9ce4_8422_2325;
pub(super) const FNV1A_PRIME_64: u64 = 0x0100_0000_01b3;

pub(crate) const PID_SENTINEL: u16 = 0x0001;
pub(crate) const PID_PARTICIPANT_GUID: u16 = 0x0050;
pub(super) const PID_PARTICIPANT_LEASE_DURATION: u16 = 0x0002;
pub(super) const PID_BUILTIN_ENDPOINT_SET: u16 = 0x0058;
#[allow(dead_code)] // Reserved for future builtin endpoint QoS support
pub(super) const PID_BUILTIN_ENDPOINT_QOS: u16 = 0x0077; // QoS for builtin endpoints (RTPS v2.3 Table 9.12)
pub(crate) const PID_METATRAFFIC_UNICAST_LOCATOR: u16 = 0x0032;
pub(super) const PID_METATRAFFIC_MULTICAST_LOCATOR: u16 = 0x0033;
pub(super) const PID_TOPIC_NAME: u16 = 0x0005; // REVERTED - Correct per RTPS v2.5 spec line 13320-13322
pub(super) const PID_TYPE_NAME: u16 = 0x0007; // REVERTED - Correct per RTPS v2.5 spec line 13326-13328
pub(super) const PID_DOMAIN_ID: u16 = 0x000f; // Domain ID (RTPS v2.3 Table 8.73 - mandatory)
pub(super) const PID_USER_DATA: u16 = 0x002c; // DDS-RTPS Sec.9.6.2.2.1 - UserDataQosPolicy
pub(super) const PID_PROTOCOL_VERSION: u16 = 0x0015;
pub(crate) const PID_VENDOR_ID: u16 = 0x0016;
pub(super) const PID_ENDPOINT_GUID: u16 = 0x005a;
pub(super) const PID_PROPERTY_LIST: u16 = 0x0059;
pub(super) const PID_ENTITY_NAME: u16 = 0x0062;
pub(super) const PID_TYPE_OBJECT: u16 = 0x0072;
pub(super) const PID_DATA_REPRESENTATION: u16 = 0x0073;
/// `PID_TYPE_INFORMATION` per OMG DDS-XTypes v1.3 sec. 7.6.3.2 -- carries
/// `TypeIdentifierWithDependencies` for Minimal + Complete TypeObject views,
/// consulted by cross-vendor readers to resolve type-identifier matching
/// alongside `PID_TYPE_OBJECT`.
pub(crate) const PID_TYPE_INFORMATION: u16 = 0x0075;

// Endpoint identification PIDs
pub(crate) const PID_KEY_HASH: u16 = 0x0070; // DDS-RTPS Sec.9.6.2.2.1 - KeyHash_t parameter
pub(crate) const PID_STATUS_INFO: u16 = 0x0071; // DDS-RTPS Sec.9.6.4.9 - StatusInfo_t (dispose/unregister)
pub(super) const PID_RECV_QUEUE_SIZE: u16 = 0x0018; // Deprecated (still parsed if received)
pub(crate) const PID_GROUP_GUID: u16 = 0x0052; // Publisher/Subscriber group GUID
pub(crate) const PID_GROUP_ENTITY_ID: u16 = 0x0053; // Publisher/Subscriber group ID
pub(super) const PID_TYPE_CONSISTENCY: u16 = 0x0074; // XTypes compatibility rules (CRITICAL)
pub(super) const PID_EXPECTS_INLINE_QOS: u16 = 0x0043; // DDS-RTPS Table 9.14 - Reader expects inline QoS

// Coherent-set / group presentation PIDs (RTPS v2.5 sec. 8.7.5).
//
// `PID_COHERENT_SET` (0x0056) and `PID_GROUP_COHERENT_SET` (0x0063) carry the
// SequenceNumber_t of the writer's last sample in the coherent set
// (TOPIC/INSTANCE scope) and the Publisher Group Sequence Number for samples
// in a GROUP-scope coherent set respectively. End-of-Coherent-Set DATA
// submessages (D=0 K=0 Q=1) also use these PIDs to mark set boundaries.
pub(crate) const PID_COHERENT_SET: u16 = 0x0056;
pub(crate) const PID_GROUP_COHERENT_SET: u16 = 0x0063;

// HDDS vendor-specific GROUP-coherent-set PID (RTPS v2.5 sec. 7.6.4.2.1: the
// 0x8000-0xFFFF range is reserved for vendor-specific PIDs; unused by any
// vendor currently interop-tested against HDDS -- see the 0x8000-0x8024
// vendor id 0x0101 cluster below). HDDS-self keys its own GROUP-scope member
// DATA and ECS marker on this PID INSTEAD OF the standard
// PID_GROUP_COHERENT_SET (0x0063): HDDS closes a set with a bare no-QoS DATA
// (writer scope only) and never emits a vendor-specific group END marker
// (see `protocol::builder::extract::extract_end_group_coherent_set`), so a
// member tagged 0x0063 can leave a GROUP-scope subscriber waiting for a group
// end that never comes. An implementation that does not recognize a
// vendor-specific PID skips it (DDSI-RTPS 2.5 Sec.9.4.2.11, Table 9.6), so
// tagging with 0x8030 instead never opens a group set at a foreign reader.
// Carries the Publisher Group Sequence Number (GSN), identical wire
// encoding (SequenceNumber_t) to PID_GROUP_COHERENT_SET.
pub(crate) const PID_GROUP_COHERENT_SET_HDDS: u16 = 0x8030;

// HDDS vendor-specific SHM transport capability hint (same 0x8000-0xFFFF
// vendor-reserved range as PID_GROUP_COHERENT_SET_HDDS immediately above).
// Carries "shm=1;host_id=XXXXXXXX;v=1" (see
// transport::shm::format_shm_user_data / select_transport) so a peer can
// decide whether same-host SHM transport is usable. This is deliberately
// NOT the standard PID_USER_DATA (0x002c, UserDataQosPolicy,
// DDS-RTPS Sec.9.6.2.2.1): that PID is application-owned, and an internal
// capability hint has no business overwriting it or leaking to a foreign
// vendor. Every vendor ignores an unrecognized vendor-specific PID, which is
// exactly why this range is the correct carrier for a proprietary hint.
pub(crate) const PID_HDDS_SHM_CAPABILITY: u16 = 0x8031;

// HDDS vendor-specific capability bitmask (same vendor-reserved range),
// in SPDP: a uint32, each bit one wire behaviour this HDDS participant
// speaks, decided once per peer at pairing (`protocol::group::GroupDialect`).
// Interpreted only from a participant whose vendorId is HDDS's (DDSI-RTPS
// 2.5 Sec.9.4.2.11: a vendor-range PID means what its sender's vendor says).
// An HDDS participant without it (1.4.x) speaks none of them.
pub(crate) const PID_HDDS_CAPABILITIES: u16 = 0x8032;

// DDS Security v1.1 sec. 7.4.1.4 ParameterId values carried inside SPDP
// ParticipantBuiltinTopicDataSecure as DataHolder structures
// (DDS Security v1.1 sec. 7.2.4).
pub(crate) const PID_IDENTITY_TOKEN: u16 = 0x1001;
/// 0x1002, DDS Security v1.1 Table 10 (identity 0x1001, permissions 0x1002,
/// data tags 0x1003, endpoint security info 0x1004, participant security info
/// 0x1005, identity status token 0x1006). A value of 0x1007 would be wrong: neither the vendor bit (0x8000) nor the
/// incompatible bit (0x4000) is set in it, so a conformant peer would drop
/// HDDS's PermissionsToken in silence and its own 0x1002 would land in the
/// wildcard arm here. Third-party check without the PDF:
/// `tshark -G values | grep PID_PERMISSIONS_TOKEN` prints 0x1002.
pub(crate) const PID_PERMISSIONS_TOKEN: u16 = 0x1002;
/// PID_DATA_TAGS (DDS Security v1.1 Sec.7.4.1.7 Table 14, Sec.7.4.1.8
/// Table 15): the DataTags of a PublicationBuiltinTopicDataSecure or a
/// SubscriptionBuiltinTopicDataSecure.
pub(crate) const PID_DATA_TAGS: u16 = 0x1003;

/// PID_ENDPOINT_SECURITY_INFO (DDS Security v1.1 Sec.7.4.1.5 Table 12,
/// Sec.7.2.8): the two u32 `EndpointSecurityInfo` masks a DataWriter or
/// DataReader announces for itself. Mirrors the constant of the same value
/// in `core::discovery::multicast::rtps_packet`, which inserts it on the
/// emission side; this one is for SEDP's own parser.
pub(crate) const PID_ENDPOINT_SECURITY_INFO: u16 = 0x1004;

// DDS Security v1.1 sec. 7.4.1.5 ParticipantSecurityInfo PID. Two u32
// attribute masks (8 bytes total) advertising the local participant's
// security posture. Required for a remote participant to start the
// PKI-DH handshake even when IdentityToken is also present.
pub(crate) const PID_PARTICIPANT_SECURITY_INFO: u16 = 0x1005;

// QoS Policy PIDs (RTPS v2.3 Table 9.12, DDS v1.4 Sec.2.2.3)
pub(super) const PID_RELIABILITY: u16 = 0x001A;
pub(super) const PID_DURABILITY: u16 = 0x001D;
pub(super) const PID_HISTORY: u16 = 0x0040;
pub(super) const PID_RESOURCE_LIMITS: u16 = 0x0041;
pub(super) const PID_DEADLINE: u16 = 0x0023;
pub(super) const PID_LIVELINESS: u16 = 0x001B;
pub(super) const PID_OWNERSHIP: u16 = 0x001F;
pub(super) const PID_OWNERSHIP_STRENGTH: u16 = 0x0006;
pub(super) const PID_PARTITION: u16 = 0x0029;
pub(super) const PID_TIME_BASED_FILTER: u16 = 0x0004;
pub(super) const PID_DURABILITY_SERVICE: u16 = 0x001E; // DDS v1.4 Sec.2.2.3.5
pub(super) const PID_PRESENTATION: u16 = 0x0021; // DDS v1.4 Sec.2.2.3.6
pub(super) const PID_LIFESPAN: u16 = 0x002B; // DDS v1.4 Sec.2.2.3.16
pub(super) const PID_DESTINATION_ORDER: u16 = 0x0025; // RTPS v2.5 Table 9.12
pub(super) const PID_LATENCY_BUDGET: u16 = 0x0027; // RTPS v2.5 Table 9.12

// SEDP locator parameters - required for user data delivery
pub(super) const PID_UNICAST_LOCATOR: u16 = 0x002f;
pub(super) const PID_DEFAULT_UNICAST_LOCATOR: u16 = 0x0031;
#[allow(dead_code)] // Reserved for future multicast locator support
pub(super) const PID_DEFAULT_MULTICAST_LOCATOR: u16 = 0x0048;

// Vendor-specific PIDs (0x8000+) as interpreted under vendor id 0x0101, with
// the names and layouts of the public Wireshark RTPS dissector.
// NOTE: a vendor-range PID takes its meaning from the sender's vendor id
// (DDSI-RTPS 2.5 Sec.9.6.2.2.1, Table 9.6). HDDS (vendor 0x011A) does NOT
// send these PIDs in generic discovery. These constants are kept for parsing.
#[allow(dead_code)] // Used by RTI dialect encoder only
pub(super) const PID_PRODUCT_VERSION: u16 = 0x8000; // Product version, vendor 0x0101
#[allow(dead_code)] // Reserved for RTI interop parsing
pub(super) const PID_ENTITY_VIRTUAL_GUID: u16 = 0x8002; // virtual GUID, vendor 0x0101
#[allow(dead_code)] // Reserved for RTI interop parsing
pub(super) const PID_EXPECTS_VIRTUAL_HB: u16 = 0x8009; // virtual HB, vendor 0x0101
#[allow(dead_code)] // Used by RTI dialect encoder only
pub(super) const PID_RTI_DOMAIN_ID: u16 = 0x800f; // Domain ID, vendor 0x0101
#[allow(dead_code)] // Used by RTI dialect encoder only
pub(super) const PID_TRANSPORT_INFO_LIST: u16 = 0x8010; // Transport capabilities (UDPv4, SHMEM, etc.)
#[allow(dead_code)] // Reserved for RTI interop parsing
pub(super) const PID_ENDPOINT_PROPERTY_CHANGE_EPOCH: u16 = 0x8015; // epoch, vendor 0x0101
#[allow(dead_code)] // Used by RTI dialect encoder only
pub(super) const PID_REACHABILITY_LEASE_DURATION: u16 = 0x8016; // Reachability lease duration
#[allow(dead_code)] // Used by RTI dialect encoder only
pub(super) const PID_VENDOR_BUILTIN_ENDPOINT_SET: u16 = 0x8017; // Vendor builtin endpoints (service request, etc.)
#[allow(dead_code)] // Reserved for XTypes support
pub(super) const PID_TYPE_OBJECT_LB: u16 = 0x8021; // Compressed TypeObject (large binary)

/// RTPS v2.3 BuiltinEndpointSet_t bitmask (Table 9.12)
/// Indicates which builtin discovery endpoints are available on this participant
//   Bits 0-5   (0x003F):  SPDP + SEDP endpoints
//   Bits 10-11 (0x0C00):  ParticipantMessage Writer/Reader (liveliness)
//   Bits 16-19 (0xF0000): SECURE SEDP publications/subscriptions writers and
//                         readers (DDS Security v1.1 Sec.7.4.1.4, Table 11)
//
// Bits 16-19 are set with or without security. A participant without
// security serves none of those four endpoints, so this announces endpoints
// it does not serve. Wire observations: a Fast DDS participant was captured
// announcing 0x000FFC3F; Connext peers (6.1, 7.3, public 7.7 shape_main)
// announce 0x00000C3F. The value is kept until an OMG interop matrix run
// measures what dropping the bits changes; `BUILTIN_ENDPOINT_SET_SECURITY`
// holds the secure endpoints this participant serves.
//
// Value 0x000F0C3F.
pub(crate) const BUILTIN_ENDPOINT_SET_DEFAULT: u32 = 0x000F_0C3F;
// Bit 0  (0x00000001): DISC_BUILTIN_ENDPOINT_PARTICIPANT_ANNOUNCER (SPDPbuiltinParticipantWriter)
// Bit 1  (0x00000002): DISC_BUILTIN_ENDPOINT_PARTICIPANT_DETECTOR (SPDPbuiltinParticipantReader)
// Bit 2  (0x00000004): DISC_BUILTIN_ENDPOINT_PUBLICATIONS_ANNOUNCER (SEDPbuiltinPublicationsWriter)
// Bit 3  (0x00000008): DISC_BUILTIN_ENDPOINT_PUBLICATIONS_DETECTOR (SEDPbuiltinPublicationsReader)
// Bit 4  (0x00000010): DISC_BUILTIN_ENDPOINT_SUBSCRIPTIONS_ANNOUNCER (SEDPbuiltinSubscriptionsWriter)
// Bit 5  (0x00000020): DISC_BUILTIN_ENDPOINT_SUBSCRIPTIONS_DETECTOR (SEDPbuiltinSubscriptionsReader)
// Bit 10 (0x00000400): BUILTIN_ENDPOINT_PARTICIPANT_MESSAGE_DATA_WRITER
// Bit 11 (0x00000800): BUILTIN_ENDPOINT_PARTICIPANT_MESSAGE_DATA_READER
// Bit 16 (0x00010000): BUILTIN_ENDPOINT_PARTICIPANT_STATELESS_MESSAGE_WRITER (legacy name)
// Bit 17 (0x00020000): BUILTIN_ENDPOINT_PARTICIPANT_STATELESS_MESSAGE_READER (legacy name)
// Bit 18 (0x00040000): SECURE_PUBLICATION_WRITER (legacy name)
// Bit 19 (0x00080000): SECURE_SUBSCRIPTION_READER (legacy name)

/// The DDS-Security builtin endpoints this participant SERVES, OR-ed into
/// `PID_BUILTIN_ENDPOINT_SET` when it runs with security (DDS Security v1.1
/// Sec.7.4.1.4, Table 11). The one definition: the SPDP announcement and the
/// discovery-server registration both read it.
///
/// | bits  | endpoints (Table 11)                                   | served by        |
/// |-------|--------------------------------------------------------|------------------|
/// | 16-19 | SEDPbuiltinPublications/SubscriptionsSecure W/R        | `secure_sedp`    |
/// | 22-23 | BuiltinParticipantStatelessMessage W/R                 | the handshake    |
/// | 24-25 | BuiltinParticipantVolatileMessageSecure W/R            | key distribution |
///
/// Not announced, because nothing serves them, and a peer that believes an
/// announcement sends there and is never heard:
/// - 20-21, BuiltinParticipantMessageSecure W/R: nothing sends on 0xff0200c2,
///   and what arrives there is not read as liveliness;
/// - 26-27, SPDPbuiltinParticipantSecure W/R (DCPSParticipantsSecure,
///   Sec.7.4.1.6): participant departures use the standard status change
///   (`DiscoveryFsm::sealed_departure_for`), protected as governance requires.
///   General participant data updates are not implemented, so the complete
///   topic is not advertised;
/// - 28-29: not DDS-Security's at all. DDS-Security reserves 16-27; RTPS v2.5
///   Sec.9.3.2 assigns 28 and 29 to DISC_BUILTIN_ENDPOINT_TOPICS_ANNOUNCER and
///   _DETECTOR (DCPSTopic), which this participant does not serve either.
///
/// Bits 16-19 are also in `BUILTIN_ENDPOINT_SET_DEFAULT`, with or without
/// security (an interop fix); see the comment there.
pub(crate) const BUILTIN_ENDPOINT_SET_SECURITY: u32 = 0x000F_0000 | 0x00C0_0000 | 0x0300_0000;

/// RTPS v2.3 BuiltinEndpointQos_t bitmask (Section 9.6.2.2.1)
/// Provides QoS information for builtin endpoints
/// Bit 0: BEST_EFFORT_PARTICIPANT_MESSAGE_DATA_READER
#[allow(dead_code)] // Reserved for future builtin endpoint QoS support
pub(super) const BUILTIN_ENDPOINT_QOS_DEFAULT: u32 = 0x0000_0001; // interop compatibility

// ============================================================================
// CDR Encapsulation Constants (RTPS v2.3 Sec.10.2)
// ============================================================================
// These are the canonical definitions used throughout HDDS.
// All other modules should import from here to avoid duplication.

/// PLAIN_CDR_BE (0x0000): Plain CDR with Big-Endian data encoding
/// Used for USER DATA payloads (NOT SPDP/SEDP which use Parameter List)
/// Reference: DDS-RTPS v2.5 Sec.10.2.1 - Plain CDR format for application data
pub const PLAIN_CDR_BE: u16 = 0x0000;

/// PLAIN_CDR_LE (0x0001): Plain CDR with Little-Endian data encoding
/// Used for USER DATA payloads (NOT SPDP/SEDP which use Parameter List)
/// Common encapsulation for application user data
/// Reference: DDS-RTPS v2.5 Sec.10.2.1 - Plain CDR format for application data
pub const PLAIN_CDR_LE: u16 = 0x0001;

/// PL_CDR_BE (0x0002): Parameter List with Big-Endian data encoding
/// Valid for discovery (SPDP/SEDP) payloads (DDSI-RTPS 2.5 Sec.10.3)
pub const CDR_BE: u16 = 0x0002;

/// PL_CDR_LE (0x0003): Parameter List with Little-Endian data encoding
/// Used by HDDS and FastDDS for discovery (SPDP/SEDP) packets
pub const CDR_LE: u16 = 0x0003;

// CDR2 encapsulation identifiers per OMG DDS-XTypes v1.3 sec. 7.6.3.1.2 Table 60.
//
// PLAIN_CDR2 (`@final`), DELIMITED_CDR (`@appendable` with DHEADER), and
// PL_CDR2 (`@mutable` with DHEADER + EMHEADER) each have BE + LE variants.
//
// Spec note: Table 60 contains a typo on the PL_CDR2_LE row, printed
// as `PL_CDR_LE` instead of `PL_CDR2_LE`. The value 0x000B is
// unambiguous from the column context (XCDR MUTABLE encoding version 2
// little-endian).

/// PLAIN_CDR2_BE (0x0006): Plain CDR2 with Big-Endian encoding;
/// used for `@final` extensibility under XCDR2.
pub const PLAIN_CDR2_BE: u16 = 0x0006;

/// PLAIN_CDR2_LE (0x0007): Plain CDR2 with Little-Endian encoding;
/// used for `@final` extensibility under XCDR2.
pub const PLAIN_CDR2_LE: u16 = 0x0007;

/// D_CDR2_BE (0x0008): Delimited CDR2 with Big-Endian encoding (DHEADER);
/// used for `@appendable` extensibility under XCDR2.
pub const D_CDR2_BE: u16 = 0x0008;

/// D_CDR2_LE (0x0009): Delimited CDR2 with Little-Endian encoding (DHEADER);
/// used for `@appendable` extensibility under XCDR2.
pub const D_CDR2_LE: u16 = 0x0009;

/// PL_CDR2_BE (0x000A): Parameter List CDR2 with Big-Endian encoding
/// (DHEADER + EMHEADER); used for `@mutable` extensibility under XCDR2.
pub const PL_CDR2_BE: u16 = 0x000A;

/// PL_CDR2_LE (0x000B): Parameter List CDR2 with Little-Endian encoding
/// (DHEADER + EMHEADER); used for `@mutable` extensibility under XCDR2.
pub const PL_CDR2_LE: u16 = 0x000B;

// FastDDS vendor-specific encapsulation variants (0x8000 = vendor flag)

/// FastDDS vendor-specific PL_CDR_LE with vendor flag (0x8001)
pub const CDR_LE_VENDOR: u16 = 0x8001;

/// FastDDS vendor-specific PL_CDR_BE with vendor flag (0x8002)
pub const CDR_BE_VENDOR: u16 = 0x8002;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plain_cdr_constants() {
        // Plain CDR encapsulation IDs per DDS-RTPS v2.5 Sec.10.2.1
        assert_eq!(PLAIN_CDR_BE, 0x0000, "PLAIN_CDR_BE should be 0x0000");
        assert_eq!(PLAIN_CDR_LE, 0x0001, "PLAIN_CDR_LE should be 0x0001");
    }

    #[test]
    fn test_cdr_vs_plain_cdr_distinction() {
        // Verify that Parameter List and Plain CDR IDs are distinct
        assert_ne!(
            PLAIN_CDR_LE, CDR_LE,
            "Plain CDR (0x0001) != PL_CDR_LE (0x0003)"
        );
        assert_ne!(
            PLAIN_CDR_BE, CDR_BE,
            "Plain CDR (0x0000) != PL_CDR_BE (0x0002)"
        );

        // Plain CDR IDs should be lower than Parameter List IDs
        // Use const assertions for compile-time known values
        const _: () = assert!(PLAIN_CDR_LE < CDR_LE);
        const _: () = assert!(PLAIN_CDR_BE < CDR_BE);
    }

    #[test]
    fn test_cdr_encapsulation_ordering() {
        // Encapsulation ID layout per OMG DDS-XTypes v1.3 sec. 7.6.3.1.2 Table 60:
        //   PLAIN_CDR     0x0000-0x0001  (CDR_BE/LE)
        //   PL_CDR        0x0002-0x0003  (PL_CDR_BE/LE -- XCDR1 MUTABLE)
        //   XML           0x0004         (not used here)
        //   PLAIN_CDR2    0x0006-0x0007  (XCDR2 FINAL)
        //   D_CDR2        0x0008-0x0009  (XCDR2 APPENDABLE)
        //   PL_CDR2       0x000A-0x000B  (XCDR2 MUTABLE)
        //   Vendor        0x8001-0x8002
        const _: () = assert!(PLAIN_CDR_BE < PLAIN_CDR_LE);
        const _: () = assert!(PLAIN_CDR_LE < CDR_BE);
        const _: () = assert!(CDR_BE < CDR_LE);
        const _: () = assert!(CDR_LE < PLAIN_CDR2_BE);
        const _: () = assert!(PLAIN_CDR2_BE < PLAIN_CDR2_LE);
        const _: () = assert!(PLAIN_CDR2_LE < D_CDR2_BE);
        const _: () = assert!(D_CDR2_BE < D_CDR2_LE);
        const _: () = assert!(D_CDR2_LE < PL_CDR2_BE);
        const _: () = assert!(PL_CDR2_BE < PL_CDR2_LE);
        const _: () = assert!(PL_CDR2_LE < CDR_LE_VENDOR);
    }

    #[test]
    fn test_xcdr2_encapsulation_spec_values() {
        // OMG DDS-XTypes v1.3 Sec.7.6.3.1.2 Table 60 -- exact wire values.
        assert_eq!(PLAIN_CDR2_BE, 0x0006);
        assert_eq!(PLAIN_CDR2_LE, 0x0007);
        assert_eq!(D_CDR2_BE, 0x0008);
        assert_eq!(D_CDR2_LE, 0x0009);
        assert_eq!(PL_CDR2_BE, 0x000A);
        assert_eq!(PL_CDR2_LE, 0x000B);
    }
}
