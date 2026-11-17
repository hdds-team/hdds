// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! The writers of a group (a Publisher), as DDSI-RTPS v2.5 names them on the
//! wire: `GroupDigest_t` (Sec.9.3.2.5), the `writerSet` of
//! `PID_WRITER_GROUP_INFO` (0x0065, Table 8.88) that tells a GROUP-scope
//! reader whether it discovered the whole Publisher (Sec.8.7.5).

use md5::{Digest, Md5};

/// The group sequence information of one change of a GROUP Publisher's
/// writer (RTPS v2.5 Sec.8.7.5, Sec.9.6.4.4, Sec.9.6.4.5): what its DATA
/// carries in `PID_GROUP_SEQ_NUM` (0x0064) and `PID_WRITER_GROUP_INFO`
/// (0x0065), journaled with the change so a repair carries the same.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GroupTag {
    /// The change's group sequence number.
    pub gsn: u64,
    /// The `GroupDigest_t` of the Publisher's writers when it was written.
    pub writer_set: [u8; 4],
    /// The GSN of the first change of the coherent set the change belongs
    /// to (`PID_GROUP_COHERENT_SET`, 0x0063, Sec.8.7.6), `None` outside a
    /// set.
    pub set_first_gsn: Option<u64>,
    /// For an end of set: the SN of the writer's first change in the set,
    /// or the end of set's own SN when the writer wrote none in it (its
    /// `PID_COHERENT_SET`, Table 9.23, D6). `None` for any other change.
    pub part_first_sn: Option<u64>,
}

/// `PID_HDDS_CAPABILITIES` bit: the participant speaks the RTPS v2.5 GROUP
/// coherent protocol (Sec.8.7.5, Sec.8.7.6: a GSN on every change of a
/// GROUP Publisher, its end of set from every writer, `writerSet` digests).
pub const CAP_SPEC_GROUP_COHERENT: u32 = 1 << 0;

/// `PID_HDDS_CAPABILITIES` bit: the participant reads a TypeObject whose
/// string members carry the TypeIdentifier DDS-XTypes 1.3 Sec.7.3.4.4 gives
/// a string (TI_STRING8_SMALL / TI_STRING8_LARGE), in PID_TYPE_OBJECT, as
/// the type it describes. HDDS 1.4.x does not: it holds such a member
/// incompatible with its own bare TK_STRING8 (0x20) and drops every sample
/// of the writer (`TypeObjectPid`).
pub const CAP_TYPE_OBJECT_SPEC_STRINGS: u32 = 1 << 1;

/// `PID_HDDS_CAPABILITIES` bit: the participant protects its secure SEDP
/// announcements with DDS-Security 1.1 submessage protection
/// (SEC_PREFIX / SEC_BODY / SEC_POSTFIX, Sec.9.5.3.3.4.5) and reads only
/// that from every authenticated peer. The bit remains advertised for
/// diagnostics; HDDS 1.4.x cannot complete the current handshake.
pub const CAP_SPEC_SECURE_SEDP: u32 = 1 << 2;

/// `PID_HDDS_CAPABILITIES` bit: as responder, the participant announces one
/// future_challenge per remote identity (DDS-Security 1.1 Sec.9.3.3,
/// Table 52), and as initiator it begins a session on a request carrying the
/// challenge its completed session answered once that request can no longer
/// be one that crossed its completion. Every HDDS release that does not
/// announce it is a 1.4.x one, whose handshake signatures are not those of
/// Sec.9.3.2.5.2 and Sec.9.3.2.5.3: such a peer cannot authenticate with
/// this release, and is reported once as such
/// (`security::handshake::HandshakeMachine::note_peer_capabilities`).
pub const CAP_ONE_FUTURE_CHALLENGE: u32 = 1 << 3;

/// `PID_HDDS_CAPABILITIES` bit: every `hdds_gen`-generated or
/// `#[derive(DDS)]` keyed type on this participant computes its
/// `PID_KEY_HASH` as DDSI-RTPS v2.5 9.6.4.8 / DDS-XTypes 1.3 7.6.8 define it
/// (the KeyHolder MD5/zero-pad reduction), not the FNV-1a hash that
/// pre-1.5.0 `hdds_gen` backends emitted. Like `CAP_ONE_FUTURE_CHALLENGE`:
/// every HDDS release that does not announce it is a 1.4.x one (or an
/// unreleased 1.5.0 snapshot that predates this bit), and a dispose or
/// unregister from such a peer whose `encode_key` is empty cannot be named
/// by this `PID_KEY_HASH` directly -- the reader instead
/// resolves it against the hashes its OWN ordinary samples from that writer
/// already carried (`engine::demux::TopicRegistry::resolve_legacy_key_hash_instance`).
pub const CAP_CONFORMANT_KEY_HASH: u32 = 1 << 4;

/// What this build announces in `PID_HDDS_CAPABILITIES`: the RTPS v2.5
/// GROUP coherent protocol, spoken with a peer that announces it too, the
/// reading of spec string TypeIdentifiers, the conformant KeyHash, and,
/// with the `security` feature, the spec protection of secure SEDP and one
/// future_challenge per remote identity.
#[cfg(feature = "security")]
pub const LOCAL_CAPABILITIES: u32 = CAP_SPEC_GROUP_COHERENT
    | CAP_TYPE_OBJECT_SPEC_STRINGS
    | CAP_SPEC_SECURE_SEDP
    | CAP_ONE_FUTURE_CHALLENGE
    | CAP_CONFORMANT_KEY_HASH;

/// What this build announces in `PID_HDDS_CAPABILITIES` (see the
/// `security` variant): no security behaviour without the feature.
#[cfg(not(feature = "security"))]
pub const LOCAL_CAPABILITIES: u32 =
    CAP_SPEC_GROUP_COHERENT | CAP_TYPE_OBJECT_SPEC_STRINGS | CAP_CONFORMANT_KEY_HASH;

/// The GROUP-scope wire a remote participant speaks, decided once at
/// pairing from its SPDP vendorId and HDDS capabilities, and kept per peer:
/// the hot path reads it, never the header of each datagram.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GroupDialect {
    /// The RTPS v2.5 GROUP protocol (HDDS announcing
    /// `CAP_SPEC_GROUP_COHERENT`).
    Spec,
    /// HDDS without the capability (1.4.x): the set id in vendor PID 0x8030,
    /// an end of set only from the writers that wrote, its PID_COHERENT_SET
    /// the last SN of the writer's part.
    HddsLegacy,
    /// Vendor 0x0101: per-writer PID_COHERENT_SET and a standalone end
    /// marker in its vendor PIDs 0x8022-0x8024.
    VendorEndMarker,
    /// Vendor 0x0114: writes the RTPS v2.5 GROUP protocol (members tagged
    /// PID_GROUP_COHERENT_SET + PID_GROUP_SEQ_NUM, a dataless end of set per
    /// writer carrying PID_WRITER_GROUP_INFO), so its writers are read as
    /// `Spec`; it reads only per-writer sets, so HDDS writes to it as to a
    /// `Classic` peer.
    SpecReceive,
    /// Every other vendor: per-writer PID_COHERENT_SET only.
    Classic,
}

impl GroupDialect {
    /// Classic peers requiring a per-reader wire sequence origin.
    pub(crate) fn needs_sequence_window(vendor_id: Option<u16>) -> bool {
        matches!(vendor_id, Some(0x0101 | 0x010a))
    }

    /// The dialect of a participant announcing `vendor_id` and
    /// `hdds_capabilities` (`PID_HDDS_CAPABILITIES`, meaningful only from an
    /// HDDS participant: a vendor-range PID means what its sender's vendor
    /// says, DDSI-RTPS v2.5 Sec.9.4.2.11).
    #[must_use]
    pub fn of(vendor_id: Option<u16>, hdds_capabilities: Option<u32>) -> Self {
        match vendor_id {
            Some(crate::core::rtps_constants::HDDS_VENDOR_ID_U16) => {
                if hdds_capabilities.is_some_and(|caps| caps & CAP_SPEC_GROUP_COHERENT != 0) {
                    Self::Spec
                } else {
                    Self::HddsLegacy
                }
            }
            Some(0x0101) => Self::VendorEndMarker,
            Some(0x0114) => Self::SpecReceive,
            _ => Self::Classic,
        }
    }
}

/// The `GroupDigest_t` of the writers `entity_ids` of one group (DDSI-RTPS
/// v2.5 Sec.9.3.2.5): the `EntityIdSet_t` sorted by each EntityId read as
/// the little-endian serialization of a signed 32-bit integer, serialized as
/// CDR big-endian (a `uint32` length, then the 4 octets of each id), hashed
/// with MD5; the digest is the leading 4 octets. The empty group is
/// `00 00 00 00`, not the hash of an empty sequence. A writer named twice
/// counts once.
#[must_use]
pub fn group_digest(entity_ids: impl IntoIterator<Item = [u8; 4]>) -> [u8; 4] {
    let mut ids: Vec<[u8; 4]> = entity_ids.into_iter().collect();
    if ids.is_empty() {
        return [0; 4];
    }
    ids.sort_unstable_by_key(|id| i32::from_le_bytes(*id));
    ids.dedup();
    let mut hasher = Md5::new();
    hasher.update(u32::try_from(ids.len()).unwrap_or(u32::MAX).to_be_bytes());
    for id in &ids {
        hasher.update(id);
    }
    let hash = hasher.finalize();
    [hash[0], hash[1], hash[2], hash[3]]
}

/// The writer-set digest of the writers `entity_ids` as Dust DDS (vendor
/// 0x0114) computes it for PID_WRITER_GROUP_INFO: the MD5 of the 4 octets of
/// each EntityId, the ids in ascending octet order, with no length prefix
/// and no CDR; the first 4 octets of that 16-octet digest are the value an
/// HDDS reader compares. Taken from a wire capture, not from the spec text: for
/// writers 01000002, 01010002 and 01020002 the capture carries
/// `0d 56 65 de ...`. `group_digest` gives
/// `78 01 33 df` for the same writers, so the two cannot be mixed.
#[must_use]
pub fn group_digest_dust(entity_ids: impl IntoIterator<Item = [u8; 4]>) -> [u8; 4] {
    let mut ids: Vec<[u8; 4]> = entity_ids.into_iter().collect();
    if ids.is_empty() {
        return [0; 4];
    }
    ids.sort_unstable();
    ids.dedup();
    let mut hasher = Md5::new();
    for id in &ids {
        hasher.update(id);
    }
    let hash = hasher.finalize();
    [hash[0], hash[1], hash[2], hash[3]]
}

#[cfg(test)]
mod tests {
    use super::{group_digest, group_digest_dust};

    fn id(hex: u32) -> [u8; 4] {
        hex.to_be_bytes()
    }

    /// Vectors computed outside HDDS, from the text of Sec.9.3.2.5 alone,
    /// by a 12-line Python script (`hashlib.md5` over `struct.pack(">I",
    /// n)` and the ids sorted by `struct.unpack("<i", id)`), and recomputed
    /// independently by a second derivation.
    #[test]
    fn group_digest_matches_the_vectors_derived_from_the_spec_text() {
        assert_eq!(group_digest([id(0x0000_0102)]), [0xfe, 0x84, 0xc0, 0x2b]);
        assert_eq!(
            group_digest([id(0x0000_0102), id(0x0000_0202)]),
            [0x6f, 0x62, 0x13, 0x62]
        );
        // Sorted by the little-endian int32: 00000202 (0x02020000) before
        // 00000103 (0x03010000).
        assert_eq!(
            group_digest([id(0x0000_0202), id(0x0000_0102), id(0x0000_0103)]),
            [0xae, 0x48, 0xea, 0x1a]
        );
        // Kind 0xC2 makes the int32 negative: it sorts first.
        assert_eq!(
            group_digest([id(0x0000_01c2), id(0x0000_0102)]),
            [0xbd, 0xc6, 0x83, 0x6e]
        );
        assert_eq!(
            group_digest([id(0x0000_2108), id(0x0000_0102)]),
            [0xc9, 0x82, 0x95, 0x36]
        );
        assert_eq!(group_digest([]), [0, 0, 0, 0], "the empty group");
    }

    /// The value Dust DDS 0.17.0 wrote in PID_WRITER_GROUP_INFO (16 octets,
    /// `0d5665dee729f32b4eca660335930cf3`) for writers 01000002, 01010002,
    /// 01020002, in dust-h cap.pcap (frame 117, and CoreDX run frame 139).
    #[test]
    fn group_digest_dust_matches_the_value_dust_wrote_on_the_wire() {
        let ids = [
            [0x01, 0x00, 0x00, 0x02],
            [0x01, 0x01, 0x00, 0x02],
            [0x01, 0x02, 0x00, 0x02],
        ];
        assert_eq!(group_digest_dust(ids), [0x0d, 0x56, 0x65, 0xde]);
        assert_ne!(
            group_digest_dust(ids),
            group_digest(ids),
            "the Dust form is not the CDR form"
        );
        assert_eq!(group_digest_dust([]), [0, 0, 0, 0], "the empty group");
    }

    #[test]
    fn group_digest_does_not_depend_on_the_order_given() {
        let a = [id(0x0000_0103), id(0x0000_0202), id(0x0000_0102)];
        let mut b = a;
        b.reverse();
        assert_eq!(group_digest(a), group_digest(b));
        assert_eq!(
            group_digest([id(0x102), id(0x102)]),
            group_digest([id(0x102)])
        );
    }

    use super::{GroupDialect, CAP_SPEC_GROUP_COHERENT};
    use crate::protocol::discovery::spdp::SpdpData;

    fn spdp(capabilities: Option<u32>) -> SpdpData {
        SpdpData {
            participant_guid: crate::core::discovery::GUID::from_bytes([
                0x01, 0x1a, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0, 0, 1, 0xc1,
            ]),
            lease_duration_ms: 100_000,
            domain_id: 0,
            metatraffic_unicast_locators: vec![],
            default_unicast_locators: vec![],
            default_multicast_locators: vec![],
            metatraffic_multicast_locators: vec![],
            identity_token: None,
            permissions_token: None,
            participant_security_info: None,
            vendor_id: None,
            hdds_capabilities: capabilities,
            builtin_endpoint_set: None,
        }
    }

    /// The capability bitmask on the wire, decoded by hand: PID 0x8032,
    /// length 4, the uint32 in the ParameterList's little-endian order; no
    /// parameter when there is nothing to announce.
    #[test]
    fn spdp_carries_the_capability_bitmask() {
        let mut buf = vec![0u8; 2048];
        let len = crate::protocol::discovery::build_spdp(&spdp(Some(0x0000_0105)), &mut buf)
            .expect("build");
        let bytes = &buf[..len];
        let at = bytes
            .windows(4)
            .position(|w| w == [0x32, 0x80, 0x04, 0x00])
            .expect("PID_HDDS_CAPABILITIES with length 4");
        assert_eq!(&bytes[at + 4..at + 8], &[0x05, 0x01, 0x00, 0x00]);
        assert_eq!(
            crate::protocol::discovery::parse_spdp(bytes)
                .expect("parse")
                .hdds_capabilities,
            Some(0x0000_0105)
        );
        let len = crate::protocol::discovery::build_spdp(&spdp(None), &mut buf).expect("build");
        assert!(!buf[..len].windows(2).any(|w| w == [0x32, 0x80]), "absent");
        assert_eq!(
            crate::protocol::discovery::parse_spdp(&buf[..len])
                .expect("parse")
                .hdds_capabilities,
            None
        );
    }

    /// Big-endian ParameterList (PL_CDR_BE): the bitmask is read in the
    /// list's order.
    #[test]
    fn a_big_endian_announcement_reads_its_bitmask_big_endian() {
        let mut b = vec![0x00, 0x02, 0x00, 0x00]; // PL_CDR_BE
        b.extend_from_slice(&[0x00, 0x50, 0x00, 0x10]); // PID_PARTICIPANT_GUID
        b.extend_from_slice(&[0x01, 0x1a, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0, 0, 1, 0xc1]);
        b.extend_from_slice(&[0x80, 0x32, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01]);
        b.extend_from_slice(&[0x00, 0x01, 0x00, 0x00]);
        assert_eq!(
            crate::protocol::discovery::parse_spdp(&b)
                .expect("parse")
                .hdds_capabilities,
            Some(1)
        );
    }

    #[test]
    fn the_dialect_is_the_vendors_and_the_capability_only_from_hdds() {
        let hdds = Some(crate::core::rtps_constants::HDDS_VENDOR_ID_U16);
        let spec = Some(CAP_SPEC_GROUP_COHERENT);
        assert_eq!(GroupDialect::of(hdds, spec), GroupDialect::Spec);
        assert_eq!(GroupDialect::of(hdds, Some(0)), GroupDialect::HddsLegacy);
        assert_eq!(
            GroupDialect::of(hdds, None),
            GroupDialect::HddsLegacy,
            "1.4.x"
        );
        assert_eq!(
            GroupDialect::of(Some(0x0101), spec),
            GroupDialect::VendorEndMarker,
            "another vendor's 0x8032 means what that vendor says"
        );
        assert_eq!(GroupDialect::of(Some(0x0110), spec), GroupDialect::Classic);
        assert_eq!(
            GroupDialect::of(Some(0x0114), spec),
            GroupDialect::SpecReceive
        );
        assert_eq!(GroupDialect::of(None, spec), GroupDialect::Classic);
    }

    /// Discovery decides a peer's dialect from its SPDP, once.
    #[test]
    fn discovery_keeps_the_dialect_a_peer_announced() {
        use crate::core::discovery::multicast::DiscoveryFsm;
        let fsm = DiscoveryFsm::new(crate::core::discovery::GUID::zero(), 100_000);
        fsm.set_local_capabilities(CAP_SPEC_GROUP_COHERENT);
        let mut data = spdp(Some(CAP_SPEC_GROUP_COHERENT));
        let prefix = data.participant_guid.prefix;
        assert_eq!(
            fsm.group_dialect_of(&prefix),
            GroupDialect::Classic,
            "unknown"
        );
        data.vendor_id = Some(crate::core::rtps_constants::HDDS_VENDOR_ID_U16);
        fsm.handle_spdp(data.clone());
        assert_eq!(fsm.group_dialect_of(&prefix), GroupDialect::Spec);
        // A later announcement without the parameter changes nothing.
        data.hdds_capabilities = None;
        fsm.handle_spdp(data.clone());
        assert_eq!(fsm.group_dialect_of(&prefix), GroupDialect::Spec);
        // A participant that does not speak it reads the same peer in the
        // 1.4.x dialect: the spec one is spoken only by both sides.
        let old = DiscoveryFsm::new(crate::core::discovery::GUID::zero(), 100_000);
        old.set_local_capabilities(0);
        data.hdds_capabilities = Some(CAP_SPEC_GROUP_COHERENT);
        old.handle_spdp(data.clone());
        assert_eq!(old.group_dialect_of(&prefix), GroupDialect::HddsLegacy);
        assert!(!old.speaks_spec_group(&prefix));
        // The send paths' lock-free view agrees, and forgets a departed
        // peer.
        assert!(fsm.speaks_spec_group(&prefix));
        fsm.remove_participant(data.participant_guid);
        assert!(!fsm.speaks_spec_group(&prefix), "departed");
        // A peer seen first without the capability, then with it.
        let late = DiscoveryFsm::new(crate::core::discovery::GUID::zero(), 100_000);
        late.set_local_capabilities(CAP_SPEC_GROUP_COHERENT);
        data.hdds_capabilities = None;
        late.handle_spdp(data.clone());
        assert!(!late.speaks_spec_group(&prefix));
        data.hdds_capabilities = Some(CAP_SPEC_GROUP_COHERENT);
        late.handle_spdp(data);
        assert!(late.speaks_spec_group(&prefix), "learned on refresh");
    }
}
