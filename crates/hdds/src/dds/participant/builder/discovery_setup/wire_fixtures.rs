// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Wire fixtures for the discovery tests, written once.
//!
//! Three test modules need the same bytes: `fragment_handler`, which asks what
//! reassembly does with a fragmented sample, `dispatch`, which asks whether it
//! reaches reassembly at all and which door it leaves by, and
//! `type_lookup_handler`, whose parser tests read the getTypes request built
//! below. A second copy of these builders would be another
//! two-copies-one-question defect, and the worst place for
//! one: every builder here ASSERTS ITS OWN WIRE INVARIANTS, and a fork that
//! drifts stops asserting the thing the original was written to catch.
//!
//! Entity ids are written as LITERALS, never as the crate's constants: a
//! fixture built from the constant it is meant to pin cannot notice the
//! constant changing.

use crate::core::discovery::multicast::dialect_detector::DialectDetector;
use crate::core::discovery::multicast::FragmentMetadata;
use crate::core::discovery::multicast::{DiscoveryFsm, Origin, PacketKind};
use crate::core::discovery::{FragmentBuffer, GUID};
use crate::core::reader::ReaderProxyRegistry;
use crate::engine::TopicRegistry;
use crate::protocol::discovery::{build_spdp, SpdpData};
use crate::test_support::domains::unique_domain;
use crate::transport::UdpTransport;
use parking_lot::Mutex;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};

use super::dispatch::DiscoveryDispatch;
use super::type_lookup_handler::TypeLookupHandle;
use super::SpdpSecurityTokens;

/// The remote participant of the fixtures, and ours below it. Both begin
/// with `test_pki::TEST_IDENTITY_PREFIX_HEAD`, the six octets that bind a
/// prefix to the test identity certificate (DDS-Security 1.1 Sec.9.3.3,
/// Table 52), so the handshakes the security fixtures run between them pass
/// that check; the sender stays above us.
pub(super) const SENDER_PREFIX: [u8; 12] = [
    0xbe, 0x8b, 0x4f, 0x5e, 0xe2, 0x4e, 0xAA, 0xBB, 0xCC, 0xDD, 0x01, 0x02,
];
pub(super) const OUR_PREFIX: [u8; 12] = [
    0xbe, 0x8b, 0x4f, 0x5e, 0xe2, 0x4e, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
];

#[cfg(all(test, feature = "security"))]
#[test]
fn the_fixture_prefixes_are_bound_to_the_test_identity() {
    use crate::security::test_pki::TEST_IDENTITY_PREFIX_HEAD;
    assert_eq!(SENDER_PREFIX[..6], TEST_IDENTITY_PREFIX_HEAD);
    assert_eq!(OUR_PREFIX[..6], TEST_IDENTITY_PREFIX_HEAD);
    assert!(OUR_PREFIX < SENDER_PREFIX);
}

/// The (reader, writer) entity-id pair a DATA or DATA_FRAG is addressed with.
///
/// The two travel together on the wire and the classifier reads only the
/// writer, but a fixture that stamps the SPDP reader onto a TypeLookup
/// submessage is a fixture that lies about the packet it claims to be - and
/// the day a reader-side filter lands (there is none today), every test built
/// on it would pass for the wrong reason.
pub(super) struct Endpoints {
    pub reader: [u8; 4],
    pub writer: [u8; 4],
}

/// SPDP builtin participant reader/writer (RTPS v2.5 Sec.9.3.1.2 Table 9.1).
pub(super) const SPDP: Endpoints = Endpoints {
    reader: [0x00, 0x01, 0x00, 0xC7],
    writer: [0x00, 0x01, 0x00, 0xC2],
};

/// SEDP publications reader/writer (RTPS v2.5 Sec.9.3.1.2 Table 9.1).
pub(super) const SEDP_PUBLICATIONS: Endpoints = Endpoints {
    reader: [0x00, 0x00, 0x03, 0xC7],
    writer: [0x00, 0x00, 0x03, 0xC2],
};

/// TypeLookup service request reader/writer (DDS-XTypes v1.3 Sec.7.6.3.3.3
/// Table 61).
pub(super) const TYPELOOKUP_REQUEST: Endpoints = Endpoints {
    reader: [0x00, 0x03, 0x00, 0xC4],
    writer: [0x00, 0x03, 0x00, 0xC3],
};

/// TypeLookup service reply reader/writer (DDS-XTypes v1.3 Sec.7.6.3.3.3
/// Table 61).
pub(super) const TYPELOOKUP_REPLY: Endpoints = Endpoints {
    reader: [0x00, 0x03, 0x01, 0xC4],
    writer: [0x00, 0x03, 0x01, 0xC3],
};

/// An ordinary application endpoint: nothing builtin owns these ids, so a
/// sample from this writer is the router's business and not discovery's.
pub(super) const A_USER_ENDPOINT: Endpoints = Endpoints {
    reader: [0x00, 0x00, 0x00, 0x00],
    writer: [0x00, 0x00, 0x12, 0x02],
};

/// RTPS header (20) + the fixed DATA_FRAG fields (32) + its own 4-octet
/// submessage header.
pub(super) const FRAGMENT_AT: usize = 56;

/// RTPS header (20) + the fixed DATA fields (20) + its own 4-octet
/// submessage header.
pub(super) const SAMPLE_AT: usize = 44;

/// A real announcement, from our own encoder.
///
/// Using it as the fixture is deliberate here and not the usual sin of
/// ratifying our own layout: the question under test is what OUR reader
/// does with OUR announcement cut in two, which is the HDDS-to-HDDS path
/// exactly. Every value below is distinctive, because the defect this
/// pins does not lose the announcement, it replaces its fields with
/// constants.
pub(super) fn announcement_from(prefix: [u8; 12]) -> (SpdpData, Vec<u8>) {
    let data = SpdpData {
        participant_guid: GUID::new(prefix, [0x00, 0x00, 0x01, 0xC1]),
        lease_duration_ms: 30_000,
        domain_id: 39,
        metatraffic_unicast_locators: vec!["192.0.2.7:7410".parse().unwrap()],
        default_unicast_locators: vec!["192.0.2.7:7411".parse().unwrap()],
        default_multicast_locators: vec![],
        metatraffic_multicast_locators: vec![],
        // Small on purpose. The parameters that carry the lease, the
        // domain and the security tokens are written LAST, so a big token
        // pushes the whole tail of the list past the halfway cut and the
        // interesting fields end up in fragment 1 - which is exactly the
        // fixture that proves nothing. The `lease_at >= cut` check below
        // is what keeps this honest.
        identity_token: Some(vec![0x5A; 16]),
        permissions_token: Some(vec![0x6B; 16]),
        participant_security_info: Some([0x01, 0, 0, 0, 0x02, 0, 0, 0]),
        vendor_id: Some(0x0112),
        hdds_capabilities: None,
        builtin_endpoint_set: None,
    };
    let mut buf = vec![0u8; 8192];
    let n = build_spdp(&data, &mut buf).expect("build the announcement");
    buf.truncate(n);
    assert!(
        n.is_multiple_of(4),
        "PL_CDR pads every parameter to 4, so the announcement is too: {n}"
    );
    (data, buf)
}

/// A real announcement that carries NO metatraffic locator of its own.
///
/// Otherwise identical to `announcement_from`. The SPDP handler infers a
/// metatraffic locator from the datagram's source address exactly when the
/// announcement's own list is empty (RTPS gives no such rule; it is a
/// vendor-interop fallback) -- so this is the fixture that exercises that
/// inference, and RTPS 2.5 8.3.8.10's refusal of it behind an INFO_SRC.
pub(super) fn announcement_without_metatraffic_locator_from(
    prefix: [u8; 12],
) -> (SpdpData, Vec<u8>) {
    let data = SpdpData {
        participant_guid: GUID::new(prefix, [0x00, 0x00, 0x01, 0xC1]),
        lease_duration_ms: 30_000,
        domain_id: 39,
        metatraffic_unicast_locators: vec![],
        default_unicast_locators: vec!["192.0.2.7:7411".parse().unwrap()],
        default_multicast_locators: vec![],
        metatraffic_multicast_locators: vec![],
        identity_token: None,
        permissions_token: None,
        participant_security_info: None,
        vendor_id: Some(0x0112),
        hdds_capabilities: None,
        builtin_endpoint_set: None,
    };
    let mut buf = vec![0u8; 8192];
    let n = build_spdp(&data, &mut buf).expect("build the announcement");
    buf.truncate(n);
    (data, buf)
}

/// Where `two_fragments` cuts a sample of `sample_len` octets.
///
/// Exposed because every test built on the cut has to PROVE that the value it
/// asserts on lies behind it - otherwise the test passes on a fixture whose
/// interesting bytes all sit in fragment 1, and deleting reassembly would not
/// fail it.
pub(super) fn fragment_cut(sample_len: usize) -> usize {
    sample_len.div_ceil(2).next_multiple_of(4)
}

/// The four fields of a DATA_FRAG that say how the sample was cut
/// (RTPS v2.5 Sec.8.3.8.3), as a group.
///
/// They travel together and both readers compute `total_frags` from them with
/// the same arithmetic - `if fragmentSize > 0 { ceil(sampleSize / fragmentSize) }
/// else { fragmentsInSubmessage }` - so a fixture that sets one of them in
/// isolation is describing a submessage no writer emits. Grouping them is also
/// what keeps the zero-fragment door below reachable from the same builder
/// instead of a second copy of it.
pub(super) struct Fragmentation {
    pub frag_num: u32,
    pub frags_in_submessage: u16,
    pub frag_size: u16,
    pub sample_size: u32,
}

/// One DATA_FRAG datagram carrying `payload` as fragment `cut.frag_num`.
///
/// The builder asserts its own wire invariants rather than trusting the
/// arithmetic above it: a fixture that declares a length it does not
/// carry has passed a test for a rule it never exercised.
///
/// `octetsToNextHeader` is written out rather than left at the Sec.8.3.3.3
/// zero sentinel, so the DATA_FRAG keeps declaring its own end once another
/// submessage is appended behind it.
pub(super) fn data_frag_datagram(
    sender_prefix: [u8; 12],
    endpoints: &Endpoints,
    cut: Fragmentation,
    payload: &[u8],
) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(b"RTPS");
    p.extend_from_slice(&[0x02, 0x04, 0x01, 0x12]);
    p.extend_from_slice(&sender_prefix);

    let body_len = 32 + payload.len();
    p.push(0x16); // DATA_FRAG
    p.push(0x01); // E flag: little-endian
    p.extend_from_slice(&(body_len as u16).to_le_bytes());
    p.extend_from_slice(&0u16.to_le_bytes()); // extraFlags
    p.extend_from_slice(&28u16.to_le_bytes()); // octetsToInlineQos
    p.extend_from_slice(&endpoints.reader);
    p.extend_from_slice(&endpoints.writer);
    p.extend_from_slice(&0u32.to_le_bytes()); // writerSN high
    p.extend_from_slice(&7u32.to_le_bytes()); // writerSN low
    p.extend_from_slice(&cut.frag_num.to_le_bytes());
    p.extend_from_slice(&cut.frags_in_submessage.to_le_bytes());
    p.extend_from_slice(&cut.frag_size.to_le_bytes());
    p.extend_from_slice(&cut.sample_size.to_le_bytes());
    p.extend_from_slice(payload);

    assert_eq!(
        p.len(),
        20 + 4 + body_len,
        "the declared body must be the body that is there"
    );
    assert_eq!(
        FRAGMENT_AT,
        20 + 4 + 32,
        "the fixed DATA_FRAG fields end where the payload starts"
    );
    assert_eq!(
        &p[FRAGMENT_AT..],
        payload,
        "the payload must sit exactly at the offset the classifier computes"
    );
    p
}

/// Offset of `pid` in a PL_CDR_LE parameter list, or `None`.
///
/// Used by the test below to PROVE that the value it asserts on could only
/// have come from the second fragment. Without that proof the assertion
/// passes on a fixture whose interesting fields all sit before the cut.
pub(super) fn pid_offset(cdr: &[u8], pid: u16) -> Option<usize> {
    let mut off = 4; // encapsulation + padding
    while off + 4 <= cdr.len() {
        let here = u16::from_le_bytes([cdr[off], cdr[off + 1]]);
        let len = u16::from_le_bytes([cdr[off + 2], cdr[off + 3]]) as usize;
        if here == pid {
            return Some(off);
        }
        if here == 0x0001 {
            return None; // PID_SENTINEL
        }
        off += 4 + len;
    }
    None
}

/// Cut `sample` in two at a 4-octet boundary and wrap each half in its own
/// DATA_FRAG datagram, the way a peer whose sample does not fit one packet
/// actually sends it.
pub(super) fn two_fragments(
    sender_prefix: [u8; 12],
    endpoints: &Endpoints,
    sample: &[u8],
) -> (Vec<u8>, Vec<u8>, FragmentMetadata, FragmentMetadata) {
    let frag_size = fragment_cut(sample.len()) as u16;
    let sample_size = sample.len() as u32;
    assert_eq!(
        sample_size.div_ceil(u32::from(frag_size)),
        2,
        "the fixture must really be two fragments"
    );
    let cut = usize::from(frag_size);
    let shape = |frag_num| Fragmentation {
        frag_num,
        frags_in_submessage: 1,
        frag_size,
        sample_size,
    };
    let one = data_frag_datagram(sender_prefix, endpoints, shape(1), &sample[..cut]);
    let two = data_frag_datagram(sender_prefix, endpoints, shape(2), &sample[cut..]);
    // The metadata comes from the classifier, not from this builder: it is
    // what production hands the door, `total_frags` and the geometry are
    // COMPUTED, and a fixture that declares one fragmentation and tests
    // another pins nothing.
    let meta_one = fragment_meta_of(&one);
    let meta_two = fragment_meta_of(&two);
    assert_eq!(
        (meta_one.frag_num, meta_two.frag_num),
        (1, 2),
        "the two datagrams must be fragments 1 and 2 of the same sample"
    );
    assert_eq!(
        meta_one.geometry, meta_two.geometry,
        "and they must describe the same sample"
    );
    assert_eq!(
        meta_one.writer_guid,
        GUID::new(sender_prefix, endpoints.writer),
        "sent by the writer the caller asked for"
    );
    (one, two, meta_one, meta_two)
}

/// One DATA_FRAG that declares NO fragment at all.
///
/// `fragmentSize == 0` gives `ceil(sampleSize / fragmentSize)` nothing to
/// divide by, and RTPS v2.5 Sec.8.3.8.3 gives zero no meaning. The count used
/// to fall back on `fragmentsInSubmessage` when that happened, which is how a
/// submessage the scan refuses outright could still announce a fragment; the
/// geometry has no such fallback, so a zero fragment size names no fragment
/// whatever else the submessage says.
pub(super) fn a_zero_fragment_datagram(
    sender_prefix: [u8; 12],
    endpoints: &Endpoints,
    payload: &[u8],
) -> Vec<u8> {
    let datagram = data_frag_datagram(
        sender_prefix,
        endpoints,
        Fragmentation {
            frag_num: 1,
            frags_in_submessage: 0,
            frag_size: 0,
            sample_size: payload.len() as u32,
        },
        payload,
    );
    let (_kind, _at, meta, _ctx) = crate::core::discovery::multicast::classify_rtps(&datagram);
    assert!(
        meta.is_none(),
        "the fixture must really declare no fragment, and it is the classifier \
         that decides whether it does"
    );
    datagram
}

/// Append the HEARTBEAT a reliable writer sends behind its fragments.
///
/// Returns the datagram and the offset the HEARTBEAT starts at.
///
/// Nothing here is chosen for the test. `firstSN.low` is 1 because 1 is the
/// first sequence number a writer has, and those four octets are
/// `01 00 00 00`: a parameter-list reader that runs past the DATA_FRAG's own
/// end reads them as PID_SENTINEL (0x0001) and stops there. That is how a
/// parse which should have failed on a truncated list ends in success, on
/// octets the peer never put in the sample.
pub(super) fn followed_by_a_heartbeat(datagram: &[u8], endpoints: &Endpoints) -> (Vec<u8>, usize) {
    let start = datagram.len();
    assert!(
        start.is_multiple_of(4),
        "a submessage starts on a 4-octet boundary (RTPS v2.5 Sec.8.3.3), not at {start}"
    );
    let mut p = datagram.to_vec();
    p.push(0x07); // HEARTBEAT
    p.push(0x01); // E flag: little-endian
    p.extend_from_slice(&28u16.to_le_bytes()); // octetsToNextHeader
    p.extend_from_slice(&endpoints.reader);
    p.extend_from_slice(&endpoints.writer);
    p.extend_from_slice(&0u32.to_le_bytes()); // firstSN high
    p.extend_from_slice(&1u32.to_le_bytes()); // firstSN low
    p.extend_from_slice(&0u32.to_le_bytes()); // lastSN high
    p.extend_from_slice(&7u32.to_le_bytes()); // lastSN low
    p.extend_from_slice(&1u32.to_le_bytes()); // count
    assert_eq!(
        p.len() - start,
        4 + 28,
        "the declared body must be the body that is there"
    );
    assert_eq!(
        &p[start + 16..start + 20],
        &[0x01, 0x00, 0x00, 0x00],
        "firstSN.low is the word a runaway parameter-list reader takes for \
         PID_SENTINEL, and the tests below land on it deliberately"
    );
    (p, start)
}

/// The fragment metadata the REAL classifier reads out of `datagram`.
///
/// A `FragmentMetadata` written by hand pins a door to a value no production
/// reader ever had to produce - and `total_frags` in particular is computed,
/// not carried on the wire. Asking `classify_rtps` for it means the fixture
/// cannot declare one fragmentation and test another, and the two assertions
/// on the way through say what the datagram has to be for the answer to mean
/// anything.
pub(super) fn fragment_meta_of(datagram: &[u8]) -> FragmentMetadata {
    let (_kind, at, meta, _ctx) = crate::core::discovery::multicast::classify_rtps(datagram);
    assert_eq!(
        at,
        Some(FRAGMENT_AT),
        "the classifier must find the payload where the builder put it"
    );
    // The KIND is not checked, and that is the point: the classifier names a
    // DATA_FRAG after its WRITER, so a fragmented announcement comes back as
    // `PacketKind::Spdp` and a fragmented TypeLookup as `PacketKind::TypeLookup`.
    // What says "this is a fragment" is the metadata being published at all -
    // the shape of the submessage, which is what the dispatch routes on.
    meta.expect("the classifier publishes fragment metadata exactly for a DATA_FRAG")
}

/// One DATA datagram carrying `sample` whole - the one that fits.
///
/// The counterpart of `data_frag_datagram`, and the reason it exists: the
/// dispatch has to send this one to its parser and a fragment to reassembly,
/// and a test that only ever feeds it fragments cannot tell that rule from
/// "always reassemble".
pub(super) fn data_datagram(
    sender_prefix: [u8; 12],
    endpoints: &Endpoints,
    sample: &[u8],
) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(b"RTPS");
    p.extend_from_slice(&[0x02, 0x04, 0x01, 0x12]);
    p.extend_from_slice(&sender_prefix);

    let body_len = 20 + sample.len();
    p.push(0x15); // DATA
    p.push(0x01); // E flag: little-endian
    p.extend_from_slice(&(body_len as u16).to_le_bytes());
    p.extend_from_slice(&0u16.to_le_bytes()); // extraFlags
    p.extend_from_slice(&16u16.to_le_bytes()); // octetsToInlineQos
    p.extend_from_slice(&endpoints.reader);
    p.extend_from_slice(&endpoints.writer);
    p.extend_from_slice(&0u32.to_le_bytes()); // writerSN high
    p.extend_from_slice(&7u32.to_le_bytes()); // writerSN low
    p.extend_from_slice(sample);

    assert_eq!(
        p.len(),
        20 + 4 + body_len,
        "the declared body must be the body that is there"
    );
    assert_eq!(
        &p[SAMPLE_AT..],
        sample,
        "the sample must sit exactly at the offset the classifier computes"
    );
    p
}

/// The writer GUID in the RequestHeader of [`get_types_request`]: the
/// SampleIdentity's `writer_guid` (DDS-XTypes 1.3 7.6.3.3.2, lines
/// 10425-10448 of the text export cited at [`get_types_request`]). A
/// participant prefix chosen for the test, distinct from the `SENDER_PREFIX`
/// the dispatch tests wrap the request in, then ENTITYID_TL_SVC_REQ_WRITER
/// {{00,03,00},c3}, the writer a getTypes request comes from (7.6.3.3.3
/// Table 61, line 10500).
pub(super) const GET_TYPES_REQUESTER_GUID: [u8; 16] = [
    0x71, 0x6c, 0x2d, 0x72, 0x65, 0x71, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2e, // guidPrefix
    0x00, 0x03, 0x00, 0xc3, // entityId
];

/// The SampleIdentity's `sequence_number` of [`get_types_request`], high
/// then low half (`SequenceNumber_t`, line 10439), chosen for the test. The
/// high half is not zero, so a parser that swapped or truncated the halves
/// reads a different value.
pub(super) const GET_TYPES_REQUEST_SN: (i32, u32) = (1, 0x0000_0204);

/// The `EquivalenceHash` (`octet[14]`, DDS-XTypes 1.3 Annex B, line 12286)
/// of the first TypeIdentifier [`get_types_request`] asks for. Chosen for
/// the test, not computed from a TypeObject: the service looks types up by
/// these bytes, which is all the dispatch tests need it to do.
pub(super) const GET_TYPES_FIRST_MINIMAL_HASH: [u8; 14] = [
    0x3c, 0x91, 0x0e, 0x55, 0xa7, 0x12, 0x68, 0xd4, 0x0b, 0xe3, 0x7f, 0x26, 0x9a, 0x41,
];

/// The `EquivalenceHash` of the second TypeIdentifier of the request.
pub(super) const GET_TYPES_SECOND_MINIMAL_HASH: [u8; 14] = [
    0xc8, 0x05, 0x6f, 0xb2, 0x19, 0x84, 0x3d, 0xe0, 0x57, 0x2a, 0x91, 0x6c, 0x0d, 0xe3,
];

/// The Service instanceName of the RequestHeader (7.6.3.3.4, line 10659):
/// "dds.builtin.TOS." followed by the requesting DomainParticipant's GUID in
/// lower-case hexadecimal, no "0x". The clause says "16-character string"
/// and its example has 15 digits, but a GUID is 16 octets; this writes all
/// 32 hex digits of the participant GUID (the requester's prefix and
/// ENTITYID_PARTICIPANT {{00,00,01},c1}, DDSI-RTPS 2.5 9.3.1.2). The parser
/// skips the name by its length, so the choice does not change what it
/// reads; what matters is that the serialized string (48 characters plus
/// NUL = 49 octets) leaves the stream 3 octets short of the 4-octet boundary
/// the next DHEADER needs.
pub(super) fn get_types_instance_name() -> String {
    let mut name = String::from("dds.builtin.TOS.");
    for octet in GET_TYPES_REQUESTER_GUID[..12]
        .iter()
        .chain(&[0x00, 0x00, 0x01, 0xc1])
    {
        name.push_str(&format!("{octet:02x}"));
    }
    name
}

/// A TypeLookup getTypes REQUEST sample (serializedPayload of the DATA, from
/// its encapsulation header on), built for the tests field by field from
/// the DDS-XTypes 1.3 text. Section numbers are the reference; the line
/// numbers beside them are those of a plain-text export of the
/// specification, given only as a finding aid. It is not produced by the
/// HDDS encoder:
/// a fixture from our own encoder only ratifies our own layout, so the
/// bytes here follow the spec, and `encode_omg_get_types_request` is checked
/// against the parser separately.
///
/// `TypeLookup_Request { RequestHeader header; TypeLookup_Call data; }`
/// (7.6.3.3.3, line 10586), XCDR version 2, little-endian:
///
/// * encapsulation CDR2_LE {0x00, 0x07} (7.6.3.1.2, line 10197), options
///   whose two low bits count the padding after the payload (line 10217);
/// * `RequestHeader { SampleIdentity requestId; InstanceName instanceName; }`
///   (7.6.3.3.2, line 10481): writer GUID (16 octets), sequence number
///   (`long high`, `unsigned long low`), then `string<255>` as rule (3) of
///   7.4.3.5.3 (line 6772): UInt32 length including the NUL, the characters,
///   the NUL;
/// * `TypeLookup_Call`, a union switch(long) (line 10577), framed as an
///   APPENDABLE union: DHEADER (rule (30), line 7013, aligned to 4 per
///   7.4.3.4.1, line 6512) then the discriminator
///   `TypeLookup_getTypes_HashId` = 0x018252d3 (line 10525);
/// * `getTypes_In`, MUTABLE (line 10532): DHEADER (rule (21), line 6922),
///   then its one member `type_ids` (rule (22), line 6929): EMHEADER1 with
///   M_FLAG 0, LC 5 and the @hashid member id (7.3.1.2.1.1, line 3869),
///   whose NEXTINT is reused as the first word of the member (line 6554),
///   here the DHEADER of the sequence (rule (12), line 6834);
/// * `sequence<TypeIdentifier>`: length 2, then two TypeIdentifiers, a FINAL
///   union switch(octet) (Annex B, line 12507): discriminator EK_MINIMAL 0xF1
///   (line 12182) and the 14-octet EquivalenceHash.
///
/// The extensibility of `TypeLookup_Request` and `TypeLookup_Call` is not
/// annotated in 7.6.3.3.3; the request is framed as HDDS's parser and
/// encoder frame it (Request FINAL, Call APPENDABLE).
///
/// Features the parser has to get right: the 3 octets of padding after the
/// instance name, the Call's DHEADER before the discriminator, the MUTABLE
/// DHEADER and the LC=5 EMHEADER/NEXTINT pair, two TypeIdentifiers back to
/// back at an odd offset, and 2 octets of trailing padding counted by the
/// options.
pub(super) fn get_types_request() -> Vec<u8> {
    use md5::{Digest, Md5};

    // Member id from a string (7.3.1.2.1.1, line 3869): the first 4 octets
    // of MD5 of the string, read as a little-endian UInt32, top 4 bits
    // cleared.
    fn hash_id(name: &str) -> u32 {
        let digest = Md5::digest(name.as_bytes());
        u32::from_le_bytes([digest[0], digest[1], digest[2], digest[3]]) & 0x0FFF_FFFF
    }
    fn patch_dheader(body: &mut [u8], at: usize) {
        let size = (body.len() - at - 4) as u32;
        body[at..at + 4].copy_from_slice(&size.to_le_bytes());
    }

    // The XCDR stream; alignment is relative to its first octet, right after
    // the encapsulation header.
    let mut body = Vec::new();

    // RequestHeader.requestId.writer_guid, then sequence_number.
    body.extend_from_slice(&GET_TYPES_REQUESTER_GUID);
    body.extend_from_slice(&GET_TYPES_REQUEST_SN.0.to_le_bytes());
    body.extend_from_slice(&GET_TYPES_REQUEST_SN.1.to_le_bytes());

    // RequestHeader.instanceName.
    let name = get_types_instance_name();
    body.extend_from_slice(&(name.len() as u32 + 1).to_le_bytes());
    body.extend_from_slice(name.as_bytes());
    body.push(0);
    assert_ne!(
        body.len() % 4,
        0,
        "the instance name must leave the stream unaligned, or the padding \
         before the next DHEADER is never exercised"
    );

    // TypeLookup_Call: ALIGN(4), DHEADER, discriminator.
    while body.len() % 4 != 0 {
        body.push(0);
    }
    let call_at = body.len();
    body.extend_from_slice(&[0; 4]);
    let get_types = hash_id("getTypes");
    assert_eq!(
        get_types, 0x0182_52d3,
        "@hashid(\"getTypes\") is the TypeLookup_getTypes_HashId of line 10525"
    );
    body.extend_from_slice(&get_types.to_le_bytes());

    // getTypes_In: DHEADER, then the member `type_ids`.
    let in_at = body.len();
    body.extend_from_slice(&[0; 4]);
    let length_code: u32 = 5;
    body.extend_from_slice(&((length_code << 28) | hash_id("type_ids")).to_le_bytes());
    // NEXTINT, reused as the sequence's DHEADER.
    let seq_at = body.len();
    body.extend_from_slice(&[0; 4]);
    body.extend_from_slice(&2u32.to_le_bytes());
    for hash in [GET_TYPES_FIRST_MINIMAL_HASH, GET_TYPES_SECOND_MINIMAL_HASH] {
        body.push(0xF1); // EK_MINIMAL
        body.extend_from_slice(&hash);
    }
    patch_dheader(&mut body, seq_at);
    patch_dheader(&mut body, in_at);
    patch_dheader(&mut body, call_at);

    // Encapsulation header and the padding its options count.
    let pad = (4 - body.len() % 4) % 4;
    assert_ne!(pad, 0, "the options must count a non-zero padding");
    let mut sample = vec![0x00, 0x07, 0x00, pad as u8];
    sample.extend_from_slice(&body);
    sample.resize(sample.len() + pad, 0);
    sample
}

// ---------------------------------------------------------------------------
// The dispatch under test, as a value
// ---------------------------------------------------------------------------

/// A `DiscoveryDispatch` a test can hand datagrams to, with the sockets and
/// the domain lease it needs.
///
/// It lives here rather than in `dispatch`'s own test module because three
/// modules drive it now: `dispatch` asks which door a delivery leaves by,
/// and `type_lookup_handler` asks what the service does once a reassembled
/// sample reaches it - a question that needs the CDR encoders, which are
/// private to that file. A second Harness would be another
/// two-copies-one-question defect.
pub(super) struct Harness {
    pub(super) dispatch: DiscoveryDispatch,
    _domain: crate::test_support::domains::DomainLease,
}

impl Harness {
    pub(super) fn new() -> Self {
        Self::with_type_lookup(|_, _| None)
    }

    /// Build the dispatch, letting the caller attach a TypeLookup service
    /// built on the same FSM and transport.
    ///
    /// The service needs both, and both belong to the dispatch, so a
    /// caller cannot simply hand one in from outside.
    pub(super) fn with_type_lookup(
        service: impl FnOnce(&Arc<DiscoveryFsm>, &Arc<UdpTransport>) -> TypeLookupHandle,
    ) -> Self {
        Self::with_configured_fsm(|_| {}, service)
    }

    /// `with_type_lookup`, the FSM configured by `configure` first (a
    /// governance document, a handshake machine).
    pub(super) fn with_configured_fsm(
        configure: impl FnOnce(&mut DiscoveryFsm),
        service: impl FnOnce(&Arc<DiscoveryFsm>, &Arc<UdpTransport>) -> TypeLookupHandle,
    ) -> Self {
        let domain = unique_domain();
        let port_mapping =
            crate::transport::PortMapping::calculate(domain.id(), 0).expect("port mapping");
        let transport =
            Arc::new(UdpTransport::new(domain.id(), 0, port_mapping).expect("a test transport"));
        let mut fsm = DiscoveryFsm::new(GUID::new(OUR_PREFIX, [0, 0, 1, 0xC1]), 30_000);
        configure(&mut fsm);
        let fsm = Arc::new(fsm);
        let type_lookup = service(&fsm, &transport);
        Self {
            dispatch: DiscoveryDispatch {
                our_guid_prefix: OUR_PREFIX,
                transport,
                fsm,
                registry: Arc::new(TopicRegistry::new()),
                sedp_cache: Arc::new(RwLock::new(
                    crate::core::discovery::multicast::SedpHistory::new(),
                )),
                sedp_reader_registry: ReaderProxyRegistry::new(),
                dialect_detector: Arc::new(std::sync::Mutex::new(DialectDetector::new())),
                port_mapping,
                spdp_security_tokens: SpdpSecurityTokens::default(),
                discovered_peers: None,
                fragment_buffer: Arc::new(Mutex::new(FragmentBuffer::new(16, 5_000))),
                type_lookup,
                liveliness: Some(crate::dds::liveliness::Shared::new(Arc::new(
                    crate::dds::liveliness::MonotonicClock::new(),
                ))),
                #[cfg(feature = "security")]
                secure_builtins: None,
                #[cfg(feature = "security")]
                control_tx: Mutex::new(None),
            },
            _domain: domain,
        }
    }

    /// Deliver one datagram the way the listener does.
    ///
    /// The source address is deliberately NOT the announced locator: when
    /// the parameter list is lost, the SPDP handler infers a metatraffic
    /// locator from the source, and a fixture whose source matches its
    /// announcement cannot tell a wire read from that inference.
    pub(super) fn feed(
        &self,
        kind: PacketKind,
        datagram: &[u8],
        at: usize,
        meta: Option<FragmentMetadata>,
    ) {
        self.feed_from(
            kind,
            datagram,
            at,
            meta,
            "198.51.100.9:7410".parse().unwrap(),
        );
    }

    /// Same, from an address a reply can actually reach.
    pub(super) fn feed_from(
        &self,
        kind: PacketKind,
        datagram: &[u8],
        at: usize,
        meta: Option<FragmentMetadata>,
        src_addr: SocketAddr,
    ) {
        self.feed_with_origin(kind, datagram, at, meta, Origin::direct(src_addr));
    }

    /// Same, as if `forwarder` only relayed the datagram (behind an
    /// INFO_SRC, RTPS 2.5 8.3.8.10): no reply locator survives.
    pub(super) fn feed_relayed_from(
        &self,
        kind: PacketKind,
        datagram: &[u8],
        at: usize,
        meta: Option<FragmentMetadata>,
        forwarder: SocketAddr,
    ) {
        self.feed_with_origin(kind, datagram, at, meta, Origin::relayed(forwarder));
    }

    /// The one door every `feed*` helper above goes through.
    pub(super) fn feed_with_origin(
        &self,
        kind: PacketKind,
        datagram: &[u8],
        at: usize,
        meta: Option<FragmentMetadata>,
        origin: Origin,
    ) {
        self.dispatch.dispatch(kind, datagram, at, meta, origin);
    }
}

/// An empty COMPLETE struct named `fqn`.
///
/// Its only job is to have a REAL equivalence hash: the reply path refuses a
/// TypeObject that does not hash to the identifier it was requested under, so
/// a fixture cannot invent that hash - it has to compute it from the object it
/// actually ships.
#[cfg(feature = "xtypes-structural-assignability")]
pub(super) fn a_complete_type_object(fqn: &str) -> crate::xtypes::CompleteTypeObject {
    use crate::xtypes::{
        CompleteStructHeader, CompleteStructType, CompleteTypeDetail, CompleteTypeObject,
        StructTypeFlag,
    };
    CompleteTypeObject::Struct(CompleteStructType {
        struct_flags: StructTypeFlag::IS_FINAL,
        header: CompleteStructHeader {
            base_type: None,
            detail: CompleteTypeDetail::new(fqn),
        },
        member_seq: Vec::new(),
    })
}

/// A registered type whose identity is whatever `identity` says it is.
///
/// Everything else about the handle is a placeholder. The identifier is what
/// `lookup_type_object` matches on, and matching is the whole precondition of
/// a reply: with no match the service logs "no matching TypeObjects found" and
/// stays silent, which is indistinguishable from a dispatch that never
/// delivered anything.
#[cfg(feature = "xtypes-structural-assignability")]
pub(super) fn a_type_known_as(
    identity: crate::xtypes::TypeIdentifier,
    complete: crate::xtypes::CompleteTypeObject,
) -> crate::core::types::TypeObjectHandle {
    use crate::core::types::{Distro, ROS_HASH_SIZE};
    use crate::xtypes::{
        MinimalStructHeader, MinimalStructType, MinimalTypeDetail, MinimalTypeObject,
        StructTypeFlag, TypeIdentifier, TypeKind,
    };

    let minimal = MinimalTypeObject::Struct(MinimalStructType {
        struct_flags: StructTypeFlag::IS_FINAL,
        header: MinimalStructHeader {
            base_type: None,
            detail: MinimalTypeDetail::new(),
        },
        member_seq: Vec::new(),
    });
    let placeholder = TypeIdentifier::primitive(TypeKind::TK_INT32);
    let (complete_id, minimal_id) = match identity {
        id @ TypeIdentifier::Minimal(_) => (placeholder, id),
        id => (id, placeholder),
    };
    crate::core::types::TypeObjectHandle::new(
        Distro::Humble,
        Arc::<str>::from("wire_fixtures::ServedType"),
        1,
        Arc::new([0u8; ROS_HASH_SIZE]),
        complete,
        minimal,
        complete_id,
        minimal_id,
    )
}

/// The handle the getTypes request below asks for: known by its MINIMAL hash.
#[cfg(feature = "xtypes-structural-assignability")]
pub(super) fn a_type_known_by_its_minimal_hash(
    hash: [u8; 14],
) -> crate::core::types::TypeObjectHandle {
    use crate::xtypes::{EquivalenceHash, TypeIdentifier};
    a_type_known_as(
        TypeIdentifier::Minimal(EquivalenceHash::from_bytes(hash)),
        a_complete_type_object("wire_fixtures::ServedType"),
    )
}

#[cfg(feature = "xtypes-structural-assignability")]
impl Harness {
    /// A dispatch whose TypeLookup service can answer
    /// [`get_types_request`].
    pub(super) fn serving_the_get_types_request() -> Self {
        Self::serving_the_get_types_request_on(|_| {})
    }

    /// `serving_the_get_types_request`, the FSM configured by `configure`.
    pub(super) fn serving_the_get_types_request_on(
        configure: impl FnOnce(&mut DiscoveryFsm),
    ) -> Self {
        use super::type_lookup_handler::{TypeLookupConfig, TypeLookupService};
        use std::collections::HashMap;

        let mut registered = HashMap::new();
        registered.insert(
            "wire_fixtures::ServedType".to_string(),
            Arc::new(a_type_known_by_its_minimal_hash(
                GET_TYPES_FIRST_MINIMAL_HASH,
            )),
        );
        let registered = Arc::new(parking_lot::RwLock::new(registered));

        Self::with_configured_fsm(configure, move |fsm, transport| {
            Some(Arc::new(TypeLookupService::new(
                fsm.clone(),
                transport.clone(),
                OUR_PREFIX,
                TypeLookupConfig {
                    registered_types: registered,
                    served_types: Arc::new(parking_lot::RwLock::new(HashMap::new())),
                    #[cfg(feature = "type-lookup")]
                    dialect_detector: Arc::new(std::sync::Mutex::new(DialectDetector::new())),
                },
            )))
        })
    }
}

/// The datagram that came back is a getTypes REPLY, from us, addressed to
/// the participant that asked.
///
/// The entity id is asserted because it is the field the peer's own
/// dispatch reads to tell a reply from a request: a packet carrying the
/// request writer id would be routed back to the serve path and answered
/// forever.
///
/// The INFO_DST is asserted because arriving at the right SOCKET is not
/// the same as being addressed to the right PARTICIPANT - the send
/// address falls back to wherever the request came from, so a reply built
/// with the wrong peer prefix still reaches this socket and is then
/// discarded by the real receiver. Without this the test passed with the
/// peer prefix replaced by twelve zero octets.
#[cfg(feature = "xtypes-structural-assignability")]
pub(super) fn assert_is_a_get_types_reply_for(datagram: &[u8], peer: [u8; 12]) {
    let guid = crate::protocol::builder::extract_writer_guid(datagram)
        .expect("the reply must carry a DATA submessage with a writer GUID");
    assert_eq!(
        guid[12..],
        [0x00, 0x03, 0x01, 0xC3],
        "a getTypes answer comes from the TypeLookup REPLY writer \
         (DDS-XTypes v1.3 Sec.7.6.3.3.3 Table 61)"
    );
    assert_eq!(
        guid[..12],
        OUR_PREFIX,
        "and it is ours, not an echo of the request"
    );

    use crate::core::discovery::multicast::classifier::walk;
    let mut addressed_to = None;
    walk::for_each_submessage(datagram, |submsg| {
        if submsg.id != 0x0e {
            return walk::Step::Continue;
        }
        addressed_to = datagram
            .get(submsg.offset + 4..submsg.offset + 16)
            .map(|p| <[u8; 12]>::try_from(p).expect("twelve octets"));
        walk::Step::Stop
    });
    assert_eq!(
        addressed_to,
        Some(peer),
        "the reply must carry an INFO_DST naming the participant that asked \
         (RTPS v2.5 Sec.8.3.8.8)"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The request and the hash constant beside it must name the same type.
    ///
    /// A test that registers `GET_TYPES_FIRST_MINIMAL_HASH` and feeds
    /// `get_types_request()` proves nothing if the two ever drift apart:
    /// the service would find no match, send no reply, and the test would
    /// report a dispatch failure that is really a fixture failure.
    #[test]
    fn the_request_really_asks_for_the_hash_we_serve() {
        let request = get_types_request();
        let at = request
            .windows(GET_TYPES_FIRST_MINIMAL_HASH.len())
            .position(|w| w == GET_TYPES_FIRST_MINIMAL_HASH)
            .expect("the request must ask for the hash the fixtures serve");
        assert!(
            at >= fragment_cut(request.len()),
            "the requested hash sits at {at}, before the cut at {}: a fragmented \
             fixture built on it would be served from fragment 1 alone",
            fragment_cut(request.len())
        );
    }

    /// The builder puts each RequestHeader field where 7.6.3.3.2 says, and
    /// the DHEADERs it patches agree with the bytes that follow them.
    #[test]
    fn the_request_carries_the_header_it_was_built_with() {
        let request = get_types_request();
        assert_eq!(&request[..4], &[0x00, 0x07, 0x00, 0x02], "CDR2_LE, 2 pad");
        assert_eq!(&request[4..20], &GET_TYPES_REQUESTER_GUID);
        assert_eq!(&request[20..24], &GET_TYPES_REQUEST_SN.0.to_le_bytes());
        assert_eq!(&request[24..28], &GET_TYPES_REQUEST_SN.1.to_le_bytes());
        let name = get_types_instance_name();
        assert_eq!(name.len(), 48);
        assert_eq!(&request[28..32], &49u32.to_le_bytes());
        assert_eq!(&request[32..80], name.as_bytes());
        // NUL, 3 octets of padding, Call DHEADER (disc 4 + In DHEADER 4 +
        // EMHEADER 4 + NEXTINT 4 + length 4 + 2 * 15 = 50).
        assert_eq!(&request[80..84], &[0, 0, 0, 0]);
        assert_eq!(&request[84..88], &50u32.to_le_bytes());
        assert_eq!(request.len(), 4 + 134 + 2);
    }
}
