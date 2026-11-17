// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

use crate::core::discovery::GUID;
use crate::xtypes::{CompleteTypeObject, EquivalenceHash};
use std::net::SocketAddr;

/// A single element of the `dependent_typeids` sequence in
/// `TypeIdentifierWithDependencies` (DDS-XTypes v1.3 sec. 7.6.3.2.1).
///
/// Wire layout (24 bytes total per element including element DHEADER):
///   DHEADER_tiws(4) + kind(1) + hash(`[u8; 14]`) + pad(1) + size(4)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypeIdentifierWithSize {
    /// Discriminator: EK_MINIMAL (0xF1) or EK_COMPLETE (0xF2).
    pub kind: u8,
    /// MD5 of the CDR2-serialised TypeObject, truncated to 14 bytes.
    pub hash: EquivalenceHash,
    /// CDR2-serialised byte count of the corresponding TypeObject view.
    pub typeobject_serialized_size: u32,
}

/// One member of `PID_TYPE_INFORMATION` -- the wire-level
/// `TypeIdentifierWithDependencies` per OMG DDS-XTypes v1.3 sec. 7.6.3.2.1.
///
/// `dependent_typeids` is populated when the `xtypes-structural-assignability`
/// feature is enabled and the type has resolvable complex member types.
/// When the feature is OFF or no dependencies are found the sequence is empty
/// and the encoder emits the Fast-DDS-compatible 12-byte sentinel triple.
/// On RX the field is populated from parsed wire bytes for any format
/// (NEXTINT=36 sentinel -> empty, NEXTINT>=40 new format -> filled).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypeIdentifierWithDependencies {
    /// `EquivalenceHash` extracted from the inner TypeIdentifier
    /// (`MD5(CDR2(TypeObject))[..14]` per sec. 7.3.4.8).
    pub hash: EquivalenceHash,
    /// CDR2-serialised size of the corresponding TypeObject view.
    pub typeobject_serialized_size: u32,
    /// Direct type dependencies required to interpret this TypeObject.
    /// Empty when using the Fast-DDS sentinel wire format (NEXTINT=36).
    pub dependent_typeids: Vec<TypeIdentifierWithSize>,
}

/// Parsed `PID_TYPE_INFORMATION` (0x0075) payload per OMG DDS-XTypes v1.3
/// sec. 7.6.3.2. Stores the two `TypeIdentifierWithDependencies` members:
/// minimal (member id 0x1001) and complete (member id 0x1002). Either may
/// be `None` if the peer omitted the corresponding TypeObject view.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TypeInformation {
    pub minimal: Option<TypeIdentifierWithDependencies>,
    pub complete: Option<TypeIdentifierWithDependencies>,
}

/// Parsed `PID_TYPE_CONSISTENCY_ENFORCEMENT` (0x0074) per OMG DDS-XTypes v1.3 sec. 7.6.3.3.3.
///
/// Signals the peer's coercion policy for type assignability checking at match time.
/// `kind == 0` means DISALLOW_TYPE_COERCION (strict); `kind == 1` means
/// ALLOW_TYPE_COERCION (permissive). The ignore_* / prevent_* / force_* flags control
/// specific aspects of the XTypes assignability algorithm (sec. 7.6.3.4).
///
/// Wire layout (8-byte payload, LE after the 4-byte PID header):
///   `kind(u16) ignore_seq(u8) ignore_str(u8) ignore_names(u8) prevent_widening(u8) force_validation(u8) pad(u8)`
///
/// Spec defaults (sec. 7.6.3.4):
///   - `kind` = ALLOW_TYPE_COERCION (1)
///   - `ignore_sequence_bounds` = true
///   - `ignore_string_bounds` = true
///   - `ignore_member_names` = false
///   - `prevent_type_widening` = false
///   - `force_type_validation` = false
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypeConsistencyEnforcement {
    /// 0 = DISALLOW_TYPE_COERCION, 1 = ALLOW_TYPE_COERCION
    pub kind: u16,
    /// When true, sequence bound mismatches are not treated as incompatible.
    pub ignore_sequence_bounds: bool,
    /// When true, string bound mismatches are not treated as incompatible.
    pub ignore_string_bounds: bool,
    /// When true, member names are not used to match struct fields; member IDs
    /// (hash-IDs or sequential IDs) are the sole discriminator.
    pub ignore_member_names: bool,
    /// When false (default), assignability allows the writer to have extra
    /// optional fields not present in the reader. When true, the reader must
    /// be a strict subset of the writer (no new reader fields allowed).
    pub prevent_type_widening: bool,
    /// When true, type validation is performed even for types that do not carry
    /// a `PID_TYPE_INFORMATION` or `PID_TYPE_OBJECT` in SEDP.
    pub force_type_validation: bool,
}

impl Default for TypeConsistencyEnforcement {
    /// Returns the XTypes-permissive default profile (ALLOW_TYPE_COERCION, ignore bounds).
    fn default() -> Self {
        Self {
            kind: 1,
            ignore_sequence_bounds: true,
            ignore_string_bounds: true,
            ignore_member_names: false,
            prevent_type_widening: false,
            force_type_validation: false,
        }
    }
}

/// Parse error types for SPDP/SEDP helpers.
#[derive(Debug, PartialEq, Eq)]
pub enum ParseError {
    TruncatedData,
    InvalidEncapsulation,
    InvalidFormat,
    BufferTooSmall,
    EncodingError,
}

/// Narrow a computed ParameterList value length to `parameterLength` (u16,
/// RTPS v2.5 Sec.9.4.2.11). A value that does not fit the field is an
/// encoding error, never a wrapped length.
#[inline]
pub(crate) fn parameter_length(len: usize) -> Result<u16, ParseError> {
    u16::try_from(len).map_err(|_| ParseError::EncodingError)
}

/// Narrow a computed length or count to a 32-bit wire field (CDR string or
/// sequence prefix, DHEADER, NEXTINT, dependency count). Same contract as
/// [`parameter_length`]: refuse, never wrap.
#[inline]
pub(crate) fn wire_u32(len: usize) -> Result<u32, ParseError> {
    u32::try_from(len).map_err(|_| ParseError::EncodingError)
}

/// `ParticipantSecurityInfo` (DDS-Security v1.1 Sec.7.2.7): the two masks a
/// participant announces in `PID_PARTICIPANT_SECURITY_INFO` (0x1005,
/// Sec.7.4.1.4), `ParticipantSecurityAttributesMask` (Table 28) and
/// `PluginParticipantSecurityAttributesMask` (Table 60).
///
/// Kept as the wire masks rather than the attributes for the same reason as
/// [`EndpointSecurityInfo`]: discovery does not depend on the `security`
/// feature to carry and read them. `Default` is the all-zero mask, read the
/// same as a missing `PID_PARTICIPANT_SECURITY_INFO`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ParticipantSecurityInfo {
    /// `participant_security_attributes`.
    pub participant_security_attributes: u32,
    /// `plugin_participant_security_attributes`.
    pub plugin_participant_security_attributes: u32,
}

impl ParticipantSecurityInfo {
    /// `PARTICIPANT_SECURITY_ATTRIBUTES_FLAG_IS_VALID` (Sec.7.2.7).
    pub const IS_VALID: u32 = 1 << 31;
    /// `PARTICIPANT_SECURITY_ATTRIBUTES_FLAG_IS_RTPS_PROTECTED` (Table 28).
    pub const IS_RTPS_PROTECTED: u32 = 1 << 0;
    /// `PARTICIPANT_SECURITY_ATTRIBUTES_FLAG_IS_DISCOVERY_PROTECTED` (Table 28).
    pub const IS_DISCOVERY_PROTECTED: u32 = 1 << 1;
    /// `PARTICIPANT_SECURITY_ATTRIBUTES_FLAG_IS_LIVELINESS_PROTECTED` (Table 28).
    pub const IS_LIVELINESS_PROTECTED: u32 = 1 << 2;

    /// The plugin mask's own is_valid bit (Sec.7.2.7).
    pub const PLUGIN_IS_VALID: u32 = 1 << 31;
    /// `PLUGIN_PARTICIPANT_SECURITY_ATTRIBUTES_FLAG_IS_RTPS_ENCRYPTED` (Table 60).
    pub const PLUGIN_IS_RTPS_ENCRYPTED: u32 = 1 << 0;
    /// `PLUGIN_PARTICIPANT_SECURITY_ATTRIBUTES_FLAG_IS_DISCOVERY_ENCRYPTED` (Table 60).
    pub const PLUGIN_IS_DISCOVERY_ENCRYPTED: u32 = 1 << 1;
    /// `PLUGIN_PARTICIPANT_SECURITY_ATTRIBUTES_FLAG_IS_LIVELINESS_ENCRYPTED` (Table 60).
    pub const PLUGIN_IS_LIVELINESS_ENCRYPTED: u32 = 1 << 2;
    /// `..._IS_RTPS_ORIGIN_AUTHENTICATED` (Table 60).
    pub const PLUGIN_IS_RTPS_ORIGIN_AUTHENTICATED: u32 = 1 << 3;
    /// `..._IS_DISCOVERY_ORIGIN_AUTHENTICATED` (Table 60).
    pub const PLUGIN_IS_DISCOVERY_ORIGIN_AUTHENTICATED: u32 = 1 << 4;
    /// `..._IS_LIVELINESS_ORIGIN_AUTHENTICATED` (Table 60).
    pub const PLUGIN_IS_LIVELINESS_ORIGIN_AUTHENTICATED: u32 = 1 << 5;

    /// The 8 octets of `PID_PARTICIPANT_SECURITY_INFO`, little endian
    /// (Sec.7.4.1.4): `participant_security_attributes` then
    /// `plugin_participant_security_attributes`, as
    /// `SpdpData::participant_security_info` carries them.
    #[must_use]
    pub fn from_le_bytes(bytes: [u8; 8]) -> Self {
        let mut mask = [0u8; 4];
        mask.copy_from_slice(&bytes[..4]);
        let mut plugin = [0u8; 4];
        plugin.copy_from_slice(&bytes[4..]);
        Self {
            participant_security_attributes: u32::from_le_bytes(mask),
            plugin_participant_security_attributes: u32::from_le_bytes(plugin),
        }
    }

    /// A bit of `participant_security_attributes`, `false` whenever
    /// `IS_VALID` is clear.
    fn bit(&self, flag: u32) -> bool {
        self.participant_security_attributes & Self::IS_VALID != 0
            && self.participant_security_attributes & flag != 0
    }

    /// A bit of `plugin_participant_security_attributes`, gated by its own
    /// is_valid bit the same way.
    fn plugin_bit(&self, flag: u32) -> bool {
        self.plugin_participant_security_attributes & Self::PLUGIN_IS_VALID != 0
            && self.plugin_participant_security_attributes & flag != 0
    }

    /// Table 28 `is_rtps_protected`.
    #[must_use]
    pub fn is_rtps_protected(&self) -> bool {
        self.bit(Self::IS_RTPS_PROTECTED)
    }

    /// Table 28 `is_discovery_protected`.
    #[must_use]
    pub fn is_discovery_protected(&self) -> bool {
        self.bit(Self::IS_DISCOVERY_PROTECTED)
    }

    /// Table 28 `is_liveliness_protected`.
    #[must_use]
    pub fn is_liveliness_protected(&self) -> bool {
        self.bit(Self::IS_LIVELINESS_PROTECTED)
    }

    /// Table 60 `is_rtps_encrypted`.
    #[must_use]
    pub fn is_rtps_encrypted(&self) -> bool {
        self.plugin_bit(Self::PLUGIN_IS_RTPS_ENCRYPTED)
    }

    /// Table 60 `is_discovery_encrypted`.
    #[must_use]
    pub fn is_discovery_encrypted(&self) -> bool {
        self.plugin_bit(Self::PLUGIN_IS_DISCOVERY_ENCRYPTED)
    }

    /// Table 60 `is_liveliness_encrypted`.
    #[must_use]
    pub fn is_liveliness_encrypted(&self) -> bool {
        self.plugin_bit(Self::PLUGIN_IS_LIVELINESS_ENCRYPTED)
    }

    /// Table 60 `is_rtps_origin_authenticated`.
    #[must_use]
    pub fn is_rtps_origin_authenticated(&self) -> bool {
        self.plugin_bit(Self::PLUGIN_IS_RTPS_ORIGIN_AUTHENTICATED)
    }

    /// Table 60 `is_discovery_origin_authenticated`.
    #[must_use]
    pub fn is_discovery_origin_authenticated(&self) -> bool {
        self.plugin_bit(Self::PLUGIN_IS_DISCOVERY_ORIGIN_AUTHENTICATED)
    }

    /// Table 60 `is_liveliness_origin_authenticated`.
    #[must_use]
    pub fn is_liveliness_origin_authenticated(&self) -> bool {
        self.plugin_bit(Self::PLUGIN_IS_LIVELINESS_ORIGIN_AUTHENTICATED)
    }

    /// Compare each mask independently (DDS-Security v1.1 Sec.7.2.7).
    /// An invalid mask says nothing; otherwise the complete values must
    /// agree. The plugin mask is opaque except for its validity bit.
    #[must_use]
    pub fn matches(&self, other: &Self) -> bool {
        (self.participant_security_attributes & Self::IS_VALID == 0
            || other.participant_security_attributes & Self::IS_VALID == 0
            || self.participant_security_attributes == other.participant_security_attributes)
            && (self.plugin_participant_security_attributes & Self::PLUGIN_IS_VALID == 0
                || other.plugin_participant_security_attributes & Self::PLUGIN_IS_VALID == 0
                || self.plugin_participant_security_attributes
                    == other.plugin_participant_security_attributes)
    }
}

/// `EndpointSecurityInfo` (DDS-Security v1.1 Sec.7.2.8): the two masks an
/// endpoint announces in `PID_ENDPOINT_SECURITY_INFO` (0x1004, Sec.7.4.1.5),
/// `EndpointSecurityAttributesMask` (Table 31) and
/// `PluginEndpointSecurityAttributesMask` (Table 62).
///
/// Kept as the wire masks rather than the attributes so that discovery, which
/// does not depend on the security feature, can carry and read them.
///
/// `Default` is the all-zero mask: both `is_valid` bits are clear, so
/// [`Self::matches`] skips both comparisons, as for a missing PID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct EndpointSecurityInfo {
    /// `endpoint_security_attributes`.
    pub endpoint_security_attributes: u32,
    /// `plugin_endpoint_security_attributes`.
    pub plugin_endpoint_security_attributes: u32,
}

impl EndpointSecurityInfo {
    /// `ENDPOINT_SECURITY_ATTRIBUTES_FLAG_IS_VALID` (Sec.7.2.8).
    pub const IS_VALID: u32 = 1 << 31;
    /// `ENDPOINT_SECURITY_ATTRIBUTES_FLAG_IS_READ_PROTECTED` (Table 31).
    pub const IS_READ_PROTECTED: u32 = 1 << 0;
    /// `ENDPOINT_SECURITY_ATTRIBUTES_FLAG_IS_WRITE_PROTECTED` (Table 31).
    pub const IS_WRITE_PROTECTED: u32 = 1 << 1;
    /// `ENDPOINT_SECURITY_ATTRIBUTES_FLAG_IS_DISCOVERY_PROTECTED` (Table 31).
    pub const IS_DISCOVERY_PROTECTED: u32 = 1 << 2;
    /// `ENDPOINT_SECURITY_ATTRIBUTES_FLAG_IS_SUBMESSAGE_PROTECTED` (Table 31).
    pub const IS_SUBMESSAGE_PROTECTED: u32 = 1 << 3;
    /// `ENDPOINT_SECURITY_ATTRIBUTES_FLAG_IS_PAYLOAD_PROTECTED` (Table 31).
    pub const IS_PAYLOAD_PROTECTED: u32 = 1 << 4;
    /// `ENDPOINT_SECURITY_ATTRIBUTES_FLAG_IS_KEY_PROTECTED` (Table 31).
    pub const IS_KEY_PROTECTED: u32 = 1 << 5;
    /// `ENDPOINT_SECURITY_ATTRIBUTES_FLAG_IS_LIVELINESS_PROTECTED` (Table 31).
    pub const IS_LIVELINESS_PROTECTED: u32 = 1 << 6;

    /// The plugin mask's own is_valid bit (Sec.7.2.8): the same bit position
    /// as `IS_VALID`, kept distinct because it gates a different 32-bit word.
    pub const PLUGIN_IS_VALID: u32 = 1 << 31;
    /// `PLUGIN_ENDPOINT_SECURITY_ATTRIBUTES_FLAG_IS_SUBMESSAGE_ENCRYPTED` (Table 62).
    pub const PLUGIN_IS_SUBMESSAGE_ENCRYPTED: u32 = 1 << 0;
    /// `PLUGIN_ENDPOINT_SECURITY_ATTRIBUTES_FLAG_IS_PAYLOAD_ENCRYPTED` (Table 62).
    pub const PLUGIN_IS_PAYLOAD_ENCRYPTED: u32 = 1 << 1;
    /// `PLUGIN_ENDPOINT_SECURITY_ATTRIBUTES_FLAG_IS_SUBMESSAGE_ORIGIN_AUTHENTICATED` (Table 62).
    pub const PLUGIN_IS_SUBMESSAGE_ORIGIN_AUTHENTICATED: u32 = 1 << 2;

    /// A bit of `endpoint_security_attributes`, `false` whenever `IS_VALID`
    /// is clear (Sec.7.2.8: an invalid mask "says nothing").
    fn bit(&self, flag: u32) -> bool {
        self.endpoint_security_attributes & Self::IS_VALID != 0
            && self.endpoint_security_attributes & flag != 0
    }

    /// A bit of `plugin_endpoint_security_attributes`, gated by its own
    /// is_valid bit the same way.
    fn plugin_bit(&self, flag: u32) -> bool {
        self.plugin_endpoint_security_attributes & Self::PLUGIN_IS_VALID != 0
            && self.plugin_endpoint_security_attributes & flag != 0
    }

    /// Table 31 `is_read_protected`.
    #[must_use]
    pub fn is_read_protected(&self) -> bool {
        self.bit(Self::IS_READ_PROTECTED)
    }

    /// Table 31 `is_write_protected`.
    #[must_use]
    pub fn is_write_protected(&self) -> bool {
        self.bit(Self::IS_WRITE_PROTECTED)
    }

    /// Whether the endpoint is announced on the secure discovery topics
    /// (Table 29, `is_discovery_protected`). A mask whose is_valid bit is
    /// clear says nothing (Sec.7.2.8), and reads as not protected.
    #[must_use]
    pub fn is_discovery_protected(&self) -> bool {
        self.bit(Self::IS_DISCOVERY_PROTECTED)
    }

    /// Table 31 `is_submessage_protected`.
    #[must_use]
    pub fn is_submessage_protected(&self) -> bool {
        self.bit(Self::IS_SUBMESSAGE_PROTECTED)
    }

    /// Table 31 `is_payload_protected`.
    #[must_use]
    pub fn is_payload_protected(&self) -> bool {
        self.bit(Self::IS_PAYLOAD_PROTECTED)
    }

    /// Table 31 `is_key_protected`.
    #[must_use]
    pub fn is_key_protected(&self) -> bool {
        self.bit(Self::IS_KEY_PROTECTED)
    }

    /// Table 31 `is_liveliness_protected`.
    #[must_use]
    pub fn is_liveliness_protected(&self) -> bool {
        self.bit(Self::IS_LIVELINESS_PROTECTED)
    }

    /// Table 62 `is_submessage_encrypted`.
    #[must_use]
    pub fn is_submessage_encrypted(&self) -> bool {
        self.plugin_bit(Self::PLUGIN_IS_SUBMESSAGE_ENCRYPTED)
    }

    /// Table 62 `is_payload_encrypted`.
    #[must_use]
    pub fn is_payload_encrypted(&self) -> bool {
        self.plugin_bit(Self::PLUGIN_IS_PAYLOAD_ENCRYPTED)
    }

    /// Table 62 `is_submessage_origin_authenticated`.
    #[must_use]
    pub fn is_submessage_origin_authenticated(&self) -> bool {
        self.plugin_bit(Self::PLUGIN_IS_SUBMESSAGE_ORIGIN_AUTHENTICATED)
    }

    /// Compare each mask independently (DDS-Security v1.1 Sec.7.2.8).
    /// An invalid mask says nothing; otherwise the complete values must
    /// agree, including access, discovery and liveliness attributes.
    /// The plugin mask is opaque except for its validity bit.
    #[must_use]
    pub fn matches(&self, other: &Self) -> bool {
        (self.endpoint_security_attributes & Self::IS_VALID == 0
            || other.endpoint_security_attributes & Self::IS_VALID == 0
            || self.endpoint_security_attributes == other.endpoint_security_attributes)
            && (self.plugin_endpoint_security_attributes & Self::PLUGIN_IS_VALID == 0
                || other.plugin_endpoint_security_attributes & Self::PLUGIN_IS_VALID == 0
                || self.plugin_endpoint_security_attributes
                    == other.plugin_endpoint_security_attributes)
    }
}

/// SEDP (Simple Endpoint Discovery Protocol) parsed data.
#[derive(Debug, Clone)]
pub struct SedpData {
    pub topic_name: String,
    pub type_name: String,
    pub participant_guid: GUID, // Added for PID_PARTICIPANT_GUID (0x0050)
    pub endpoint_guid: GUID,
    pub qos_hash: u64,
    pub qos: Option<crate::dds::QoS>, // Added to use actual QoS values instead of hardcoding!
    pub type_object: Option<CompleteTypeObject>,
    /// Named-type (struct/union/enum/alias) dependents transitively
    /// reachable from `type_object`'s members, keyed by the Minimal
    /// `EquivalenceHash` embedded in the corresponding
    /// `TypeIdentifier::Minimal(_)` member reference. Always empty unless
    /// `type_object` was decoded from a legacy TypeObject v1 (XCDR1)
    /// payload (`PID_TYPE_OBJECT` or `PID_TYPE_OBJECT_LB` carrying an RTI/
    /// CoreDX `--type-object-version 1` encoding) -- see
    /// `xtypes::decode_type_object_v1`. CDR2 `CompleteTypeObject` payloads
    /// carry their nested named types as local endpoint TypeDescriptors
    /// instead (`MatchNotificationRegistry::register_type_objects`), not
    /// through this field.
    pub dependents: Vec<(EquivalenceHash, CompleteTypeObject)>,
    /// True when `type_object` was decoded from a legacy TypeObject v1
    /// (XCDR1) payload. The v1 wire format is LOSSY for 8-bit types: RTI
    /// Connext 7.7.0 emits the single v1 kind BYTE (2) for IDL `byte`,
    /// `uint8` AND `int8` members and discriminators (measured: the OMG
    /// suite's struct_byte_int8 / struct_byte_uint8 negatives fail as
    /// false-accepts even in the connext-vs-connext control cell, which is
    /// only possible under a three-way collapse). Consumers use this flag
    /// to prefer a same-named locally-registered CompleteTypeObject over
    /// the reconstructed one (the local object is strictly more faithful
    /// to the IDL); when no same-named local type exists the reconstructed
    /// object remains authoritative. Always false for CDR2 payloads.
    pub type_object_legacy_v1: bool,
    /// Parsed `PID_TYPE_INFORMATION` (0x0075). Populated by `parse.rs` when
    /// a peer SEDP DATA(w/r) carries the PID; `None` when absent. The
    /// matcher does not consume this field today (name-based matching is
    /// the active path); the field is retained for future XTypes
    /// Assignability runtime work and for diagnostic logging.
    pub type_information: Option<TypeInformation>,
    pub unicast_locators: Vec<SocketAddr>,
    /// Application `UserDataQosPolicy` (DDS-RTPS Sec.9.6.2.2.1), carried
    /// verbatim in PID_USER_DATA (0x002c). This is APPLICATION-owned data;
    /// nothing internal to HDDS may write or read a capability hint through
    /// this field. See `shm_capability` for the HDDS-internal equivalent.
    pub user_data: Option<String>,
    /// HDDS vendor-specific SHM transport capability hint (PID 0x8031,
    /// `PID_HDDS_SHM_CAPABILITY`), format "shm=1;host_id=XXXXXXXX;v=1".
    /// Deliberately NOT `user_data`: PID_USER_DATA (0x002c) is a standard,
    /// application-owned QoS field (DDS-RTPS Sec.9.6.2.2.1), and squatting
    /// it would (a) silently replace an application's own USER_DATA on the
    /// wire and (b) leak a proprietary hint to a foreign vendor whenever the
    /// default encoding dialect resolves to Hdds before a peer's real vendor
    /// is known (see `spdp_handler.rs`'s `Dialect::Hdds` default and
    /// `get_encoder(Dialect::Hdds)` in `rtps_packet.rs`). Consumed by
    /// `select_transport`'s `remote_user_data` argument once parsed back out
    /// on receive (see `sedp/parse.rs`).
    pub shm_capability: Option<String>,
    /// Whether PID_RELIABILITY was explicitly present in the SEDP data.
    /// Used to distinguish "not set" (apply spec default) from "set to BEST_EFFORT".
    pub has_explicit_reliability: bool,
    /// Whether PID_OWNERSHIP was explicitly present in the SEDP data.
    pub has_explicit_ownership: bool,
    /// Whether PID_OWNERSHIP_STRENGTH was explicitly present.
    /// If present, the writer is definitely EXCLUSIVE (SHARED doesn't have strength).
    pub has_ownership_strength: bool,
    /// Parsed `PID_TYPE_CONSISTENCY_ENFORCEMENT` (0x0074). None when the peer
    /// did not include the PID (treat as permissive XTypes default).
    pub type_consistency: Option<TypeConsistencyEnforcement>,
    /// The EntityId of the endpoint's group, its Publisher or Subscriber
    /// (`PID_GROUP_GUID` 0x0052 = participant prefix + this, and
    /// `PID_GROUP_ENTITY_ID` 0x0053, RTPS v2.5 Sec.9.6.2.2.5). On a local
    /// announcement, the group the endpoint belongs to (`None`: the
    /// participant's default group for its kind); parsed from a remote one.
    pub group_entity_id: Option<[u8; 4]>,
    /// Parsed `PID_ENDPOINT_SECURITY_INFO` (0x1004, DDS-Security v1.1
    /// Sec.7.2.8, 7.4.1.5): the two masks the peer announced for this
    /// endpoint. `None` when the PID was absent, which defaults to two
    /// invalid masks and skips both comparisons in [`EndpointSecurityInfo::matches`].
    pub endpoint_security_info: Option<EndpointSecurityInfo>,
}

#[cfg(test)]
mod security_info_tests {
    use super::{EndpointSecurityInfo, ParticipantSecurityInfo};

    /// A mask with the is_valid bit clear says nothing (Sec.7.2.8): every
    /// attribute reads `false`, whatever the other bits hold -- an invalid
    /// mask with every protection bit set must still read as unprotected.
    #[test]
    fn an_invalid_endpoint_mask_reads_every_attribute_false() {
        let info = EndpointSecurityInfo {
            endpoint_security_attributes: 0x7FFF_FFFF,
            plugin_endpoint_security_attributes: 0x7FFF_FFFF,
        };
        assert!(!info.is_read_protected());
        assert!(!info.is_write_protected());
        assert!(!info.is_discovery_protected());
        assert!(!info.is_submessage_protected());
        assert!(!info.is_payload_protected());
        assert!(!info.is_key_protected());
        assert!(!info.is_liveliness_protected());
        assert!(!info.is_submessage_encrypted());
        assert!(!info.is_payload_encrypted());
        assert!(!info.is_submessage_origin_authenticated());
    }

    // Numeric fixtures are independent of the decoder's flag constants.
    // Sec.7.2.7/7.2.8: invalidity skips only the corresponding mask.
    macro_rules! mask_matching_tests {
        ($validity:ident, $bits:ident, $info:ident, $standard:ident, $plugin:ident) => {
            #[test]
            fn $validity() {
                for local_standard_valid in [0, 0x8000_0000] {
                    for remote_standard_valid in [0, 0x8000_0000] {
                        for local_plugin_valid in [0, 0x8000_0000] {
                            for remote_plugin_valid in [0, 0x8000_0000] {
                                for standard_differs in [false, true] {
                                    for plugin_differs in [false, true] {
                                        let local = $info {
                                            $standard: local_standard_valid | 0x01,
                                            $plugin: local_plugin_valid | 0x02,
                                        };
                                        let remote = $info {
                                            $standard: remote_standard_valid
                                                | if standard_differs { 0x04 } else { 0x01 },
                                            $plugin: remote_plugin_valid
                                                | if plugin_differs { 0x08 } else { 0x02 },
                                        };
                                        let standard_conflict = local_standard_valid != 0
                                            && remote_standard_valid != 0
                                            && standard_differs;
                                        let plugin_conflict = local_plugin_valid != 0
                                            && remote_plugin_valid != 0
                                            && plugin_differs;
                                        assert_eq!(
                                            local.matches(&remote),
                                            !standard_conflict && !plugin_conflict,
                                            "local={local:?}, remote={remote:?}"
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
                let protected = $info {
                    $standard: 0xffff_ffff,
                    $plugin: 0xffff_ffff,
                };
                assert!($info::default().matches(&protected));
                assert!(protected.matches(&$info::default()));
            }

            #[test]
            fn $bits() {
                let base = $info {
                    $standard: 0x8000_0000,
                    $plugin: 0x8000_0000,
                };
                assert!(base.matches(&base));
                // All value bits, including unknown plugin bits, are compared.
                for bit in 0..31 {
                    let standard = $info {
                        $standard: 0x8000_0000 | (1 << bit),
                        ..base
                    };
                    let plugin = $info {
                        $plugin: 0x8000_0000 | (1 << bit),
                        ..base
                    };
                    assert!(!base.matches(&standard), "standard bit {bit}");
                    assert!(!standard.matches(&base), "standard bit {bit}, reversed");
                    assert!(!base.matches(&plugin), "opaque plugin bit {bit}");
                    assert!(!plugin.matches(&base), "opaque plugin bit {bit}, reversed");
                }
            }
        };
    }

    mask_matching_tests!(
        endpoint_masks_have_independent_validity,
        matches_compares_every_endpoint_value_bit,
        EndpointSecurityInfo,
        endpoint_security_attributes,
        plugin_endpoint_security_attributes
    );
    mask_matching_tests!(
        participant_masks_have_independent_validity,
        matches_compares_every_participant_value_bit,
        ParticipantSecurityInfo,
        participant_security_attributes,
        plugin_participant_security_attributes
    );

    /// `PID_PARTICIPANT_SECURITY_INFO`'s 8 octets, little endian
    /// (Sec.7.4.1.4): the mask then the plugin mask.
    #[test]
    fn participant_security_info_decodes_from_its_little_endian_octets() {
        let bytes = [0x07, 0x00, 0x00, 0x80, 0x3F, 0x00, 0x00, 0x80];
        let info = ParticipantSecurityInfo::from_le_bytes(bytes);
        assert!(info.is_rtps_protected());
        assert!(info.is_discovery_protected());
        assert!(info.is_liveliness_protected());
        assert!(info.is_rtps_encrypted());
        assert!(info.is_discovery_encrypted());
        assert!(info.is_liveliness_encrypted());
        assert!(info.is_rtps_origin_authenticated());
        assert!(info.is_discovery_origin_authenticated());
        assert!(info.is_liveliness_origin_authenticated());
    }
}
