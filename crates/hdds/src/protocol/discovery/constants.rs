// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

pub(super) const FNV1A_OFFSET_BASIS_64: u64 = 0xcbf29ce484222325;
pub(super) const FNV1A_PRIME_64: u64 = 0x100000001b3;

pub(super) const PID_SENTINEL: u16 = 0x0001;
pub(super) const PID_PARTICIPANT_GUID: u16 = 0x0050;
pub(super) const PID_PARTICIPANT_LEASE_DURATION: u16 = 0x0002;
pub(super) const PID_BUILTIN_ENDPOINT_SET: u16 = 0x0058;
#[allow(dead_code)] // Reserved for future builtin endpoint QoS support
pub(super) const PID_BUILTIN_ENDPOINT_QOS: u16 = 0x0077; // v81: QoS for builtin endpoints (RTPS v2.3 Table 9.12)
pub(crate) const PID_METATRAFFIC_UNICAST_LOCATOR: u16 = 0x0032;
pub(super) const PID_METATRAFFIC_MULTICAST_LOCATOR: u16 = 0x0033;
pub(super) const PID_TOPIC_NAME: u16 = 0x0005; // v109: REVERTED - Correct per RTPS v2.5 spec line 13320-13322
pub(super) const PID_TYPE_NAME: u16 = 0x0007; // v109: REVERTED - Correct per RTPS v2.5 spec line 13326-13328
pub(super) const PID_DOMAIN_ID: u16 = 0x000f; // v80: Domain ID (RTPS v2.3 Table 8.73 - mandatory)
pub(super) const PID_USER_DATA: u16 = 0x002c; // DDS-RTPS Sec.9.6.2.2.1 - UserDataQosPolicy
pub(super) const PID_PROTOCOL_VERSION: u16 = 0x0015;
pub(super) const PID_VENDOR_ID: u16 = 0x0016;
pub(super) const PID_ENDPOINT_GUID: u16 = 0x005a;
pub(super) const PID_PROPERTY_LIST: u16 = 0x0059;
pub(super) const PID_ENTITY_NAME: u16 = 0x0062;
pub(super) const PID_TYPE_OBJECT: u16 = 0x0072;
pub(super) const PID_DATA_REPRESENTATION: u16 = 0x0073;

// Endpoint identification PIDs
#[allow(dead_code)] // Reserved for future keyed topic support
pub(super) const PID_KEY_HASH: u16 = 0x0070; // DDS-RTPS Sec.9.6.2.2.1 - KeyHash_t parameter
pub(super) const PID_RECV_QUEUE_SIZE: u16 = 0x0018; // v85: Deprecated but RTI still sends it
pub(super) const PID_GROUP_ENTITY_ID: u16 = 0x0053; // v85: Publisher/Subscriber group ID
pub(super) const PID_TYPE_CONSISTENCY: u16 = 0x0074; // v85: XTypes compatibility rules (CRITICAL)
pub(super) const PID_EXPECTS_INLINE_QOS: u16 = 0x0043; // DDS-RTPS Table 9.14 - Reader expects inline QoS

// QoS Policy PIDs (RTPS v2.3 Table 9.12, DDS v1.4 Sec.2.2.3)
pub(super) const PID_RELIABILITY: u16 = 0x001A;
pub(super) const PID_DURABILITY: u16 = 0x001D;
pub(super) const PID_HISTORY: u16 = 0x0040;
pub(super) const PID_RESOURCE_LIMITS: u16 = 0x0041;
pub(super) const PID_DEADLINE: u16 = 0x0023;
pub(super) const PID_LIVELINESS: u16 = 0x001B;
pub(super) const PID_OWNERSHIP: u16 = 0x001F;
pub(super) const PID_PARTITION: u16 = 0x0029;
pub(super) const PID_TIME_BASED_FILTER: u16 = 0x0004;
pub(super) const PID_DURABILITY_SERVICE: u16 = 0x001E; // DDS v1.4 Sec.2.2.3.5
pub(super) const PID_PRESENTATION: u16 = 0x0021; // DDS v1.4 Sec.2.2.3.6

// SEDP locator parameters - required for user data delivery
pub(super) const PID_UNICAST_LOCATOR: u16 = 0x002f;
pub(super) const PID_DEFAULT_UNICAST_LOCATOR: u16 = 0x0031;
#[allow(dead_code)] // Reserved for future multicast locator support
pub(super) const PID_DEFAULT_MULTICAST_LOCATOR: u16 = 0x0048;

// RTI vendor-specific PIDs (0x8000+)
// NOTE: These PIDs are ONLY valid from RTI vendor (0x0101). HDDS (vendor 0x01AA)
// must NOT send these PIDs in generic discovery - RTI will reject them.
// These constants are kept for parsing/parsing purposes and for the RTI dialect encoder.
#[allow(dead_code)] // Used by RTI dialect encoder only
pub(super) const PID_PRODUCT_VERSION: u16 = 0x8000; // RTI Product version (major.minor.release.build)
#[allow(dead_code)] // Reserved for RTI interop parsing
pub(super) const PID_ENTITY_VIRTUAL_GUID: u16 = 0x8002; // v85: RTI virtual GUID for endpoint
#[allow(dead_code)] // Reserved for RTI interop parsing
pub(super) const PID_EXPECTS_VIRTUAL_HB: u16 = 0x8009; // v85: RTI virtual heartbeat expectations
#[allow(dead_code)] // Used by RTI dialect encoder only
pub(super) const PID_RTI_DOMAIN_ID: u16 = 0x800f; // RTI Domain ID (duplicate but required by RTI)
#[allow(dead_code)] // Used by RTI dialect encoder only
pub(super) const PID_TRANSPORT_INFO_LIST: u16 = 0x8010; // Transport capabilities (UDPv4, SHMEM, etc.)
#[allow(dead_code)] // Reserved for RTI interop parsing
pub(super) const PID_ENDPOINT_PROPERTY_CHANGE_EPOCH: u16 = 0x8015; // v85: RTI endpoint versioning
#[allow(dead_code)] // Used by RTI dialect encoder only
pub(super) const PID_REACHABILITY_LEASE_DURATION: u16 = 0x8016; // Reachability lease duration
#[allow(dead_code)] // Used by RTI dialect encoder only
pub(super) const PID_VENDOR_BUILTIN_ENDPOINT_SET: u16 = 0x8017; // Vendor builtin endpoints (service request, etc.)
#[allow(dead_code)] // Reserved for XTypes support
pub(super) const PID_TYPE_OBJECT_LB: u16 = 0x8021; // v85: Compressed TypeObject (large binary)

/// RTPS v2.3 BuiltinEndpointSet_t bitmask (Table 9.12)
/// Indicates which builtin discovery endpoints are available on this participant
// v120: CRITICAL - Extended BUILTIN_ENDPOINT_SET for RTI interop
// RTPS v2.3 Table 9.12 + RTI extensions:
//   Bits 0-5   (0x003F):  SPDP + SEDP endpoints
//   Bits 10-11 (0x0C00):  ParticipantMessage Writer/Reader (liveliness)
//   Bits 16-19 (0xF0000): Participant Stateless Message endpoints (RTI REQUIRED)
//
// RTI Connext REQUIRES bits 16-19, otherwise it logs
// `subscriptionReaderListenerOnSampleLost` and refuses SEDP matching.
// FastDDS/Cyclone ignore unknown bits per RTPS spec, so this is safe.
//
// Value 0x000F0C3F matches FastDDS reference captures.
pub(super) const BUILTIN_ENDPOINT_SET_DEFAULT: u32 = 0x000F0C3F;
// Bit 0  (0x00000001): DISC_BUILTIN_ENDPOINT_PARTICIPANT_ANNOUNCER (SPDPbuiltinParticipantWriter)
// Bit 1  (0x00000002): DISC_BUILTIN_ENDPOINT_PARTICIPANT_DETECTOR (SPDPbuiltinParticipantReader)
// Bit 2  (0x00000004): DISC_BUILTIN_ENDPOINT_PUBLICATIONS_ANNOUNCER (SEDPbuiltinPublicationsWriter)
// Bit 3  (0x00000008): DISC_BUILTIN_ENDPOINT_PUBLICATIONS_DETECTOR (SEDPbuiltinPublicationsReader)
// Bit 4  (0x00000010): DISC_BUILTIN_ENDPOINT_SUBSCRIPTIONS_ANNOUNCER (SEDPbuiltinSubscriptionsWriter)
// Bit 5  (0x00000020): DISC_BUILTIN_ENDPOINT_SUBSCRIPTIONS_DETECTOR (SEDPbuiltinSubscriptionsReader)
// Bit 10 (0x00000400): BUILTIN_ENDPOINT_PARTICIPANT_MESSAGE_DATA_WRITER
// Bit 11 (0x00000800): BUILTIN_ENDPOINT_PARTICIPANT_MESSAGE_DATA_READER
// Bit 16 (0x00010000): BUILTIN_ENDPOINT_PARTICIPANT_STATELESS_MESSAGE_WRITER (RTI)
// Bit 17 (0x00020000): BUILTIN_ENDPOINT_PARTICIPANT_STATELESS_MESSAGE_READER (RTI)
// Bit 18 (0x00040000): SECURE_PUBLICATION_WRITER (RTI)
// Bit 19 (0x00080000): SECURE_SUBSCRIPTION_READER (RTI)

/// RTPS v2.3 BuiltinEndpointQos_t bitmask (Section 9.6.2.2.1)
/// Provides QoS information for builtin endpoints
/// Bit 0: BEST_EFFORT_PARTICIPANT_MESSAGE_DATA_READER
#[allow(dead_code)] // Reserved for future builtin endpoint QoS support
pub(super) const BUILTIN_ENDPOINT_QOS_DEFAULT: u32 = 0x00000001; // v81: RTI compatibility

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
/// FastDDS and RTI use this encapsulation for application user data
/// Reference: DDS-RTPS v2.5 Sec.10.2.1 - Plain CDR format for application data
pub const PLAIN_CDR_LE: u16 = 0x0001;

/// PL_CDR_BE (0x0002): Parameter List with Big-Endian data encoding
/// Used by RTI Connext for discovery (SPDP/SEDP) packets
pub const CDR_BE: u16 = 0x0002;

/// PL_CDR_LE (0x0003): Parameter List with Little-Endian data encoding
/// Used by HDDS and FastDDS for discovery (SPDP/SEDP) packets
pub const CDR_LE: u16 = 0x0003;

/// PL_CDR2_BE (0x0102): CDR2 Parameter List with Big-Endian data encoding
/// Future XTypes support
pub const CDR2_BE: u16 = 0x0102;

/// PL_CDR2_LE (0x0103): CDR2 Parameter List with Little-Endian data encoding
/// Future XTypes support
pub const CDR2_LE: u16 = 0x0103;

// v97: FastDDS vendor-specific encapsulation variants (0x8000 = vendor flag)

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
        // Verify CDR variant ordering per RTPS spec
        // Plain CDR: 0x0000-0x0001
        // PL_CDR: 0x0002-0x0003
        // PL_CDR2: 0x0102-0x0103
        // Vendor: 0x8001-0x8002
        const _: () = assert!(PLAIN_CDR_BE < PLAIN_CDR_LE);
        const _: () = assert!(PLAIN_CDR_LE < CDR_BE);
        const _: () = assert!(CDR_BE < CDR_LE);
        const _: () = assert!(CDR_LE < CDR2_BE);
        const _: () = assert!(CDR2_BE < CDR2_LE);
        const _: () = assert!(CDR2_LE < CDR_LE_VENDOR);
    }
}
