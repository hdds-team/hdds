// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! The type verdict on a foreign ShapeType: the one decision that says
//! whether a remote writer's type is assignable to a local reader's
//! (DDS-XTypes v1.3 Sec.7.6.3.4.2).
//!
//! The case under test is a remote writer announced with
//! `PID_TYPE_INFORMATION` only, whose COMPLETE TypeObject reaches HDDS later,
//! as the answer to a TypeLookup getTypes request. The fixtures below build
//! two such peers by hand, field by field: the PL_CDR_LE parameter list of
//! each peer's SEDP DATA(w) (DDSI-RTPS v2.5 Sec.9.6.2.2), and the
//! CompleteTypeObject each would answer getTypes with (DDS-XTypes v1.3
//! Annex B). Both are the IDL of shape_main's ShapeType, and differ from
//! shape_main's own TypeObject, and from each other, in member flags, element
//! flags and the key's string bound:
//!
//! - peer A: key member flags IS_KEY | IS_MUST_UNDERSTAND | TRY_CONSTRUCT1
//!   (0x31), other members TRY_CONSTRUCT1 (0x01); `color` a TI_STRING8_SMALL
//!   of bound 0 (no bound); the octet sequence's element flags TRY_CONSTRUCT1;
//! - peer B: key member flags IS_KEY | TRY_CONSTRUCT1 (0x21), other members
//!   0x01; `color` a TI_STRING8_SMALL of bound 128; the octet sequence's
//!   element flags 0.
//!
//! Every hash a fixture announces is computed here from the bytes built here
//! (MD5, first 14 bytes, Sec.7.3.4.8), never copied from anywhere.

use crate::core::discovery::Matcher;
use crate::protocol::discovery::types::TypeConsistencyEnforcement;
use crate::protocol::discovery::SedpData;
use crate::xtypes::CompleteTypeObject;
use crate::Cdr2Decode;

/// The ShapeType TypeObject `shape_main` announces, from the one file that
/// defines it for the application too.
mod shape_main {
    use crate::xtypes::*;
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/examples/shape_common/shape_type_object.rs"
    ));
}

// ---------------------------------------------------------------------------
// Hand-built peer announcements
// ---------------------------------------------------------------------------

/// A little-endian XCDR2 stream (DDS-XTypes v1.3 Sec.7.4.3): each primitive
/// is aligned to its size, capped at 4, from the start of the buffer.
#[derive(Default)]
struct Xcdr2Le(Vec<u8>);

impl Xcdr2Le {
    fn align(&mut self, n: usize) {
        while !self.0.len().is_multiple_of(n) {
            self.0.push(0);
        }
    }

    fn u8(&mut self, v: u8) {
        self.0.push(v);
    }

    fn u16(&mut self, v: u16) {
        self.align(2);
        self.0.extend_from_slice(&v.to_le_bytes());
    }

    fn u32(&mut self, v: u32) {
        self.align(4);
        self.0.extend_from_slice(&v.to_le_bytes());
    }

    fn octets(&mut self, v: &[u8]) {
        self.0.extend_from_slice(v);
    }

    /// A string: u32 length counting the terminating NUL, the octets, NUL.
    fn string(&mut self, s: &str) {
        self.u32(u32::try_from(s.len() + 1).expect("short"));
        self.octets(s.as_bytes());
        self.u8(0);
    }

    /// A u32 byte count of what `body` writes, then that body: the DHEADER
    /// of an appendable or mutable type and of a sequence of non-primitive
    /// elements (Sec.7.4.3.5.2), and the NEXTINT of an EMHEADER with LC=4
    /// (Sec.7.4.3.5.3).
    fn delimited(&mut self, body: impl FnOnce(&mut Self)) {
        self.align(4);
        let at = self.0.len();
        self.u32(0);
        body(self);
        let len = u32::try_from(self.0.len() - at - 4).expect("short");
        self.0[at..at + 4].copy_from_slice(&len.to_le_bytes());
    }
}

fn md5(bytes: &[u8]) -> [u8; 16] {
    use md5::{Digest, Md5};
    Md5::digest(bytes).into()
}

/// The EquivalenceHash of a serialized TypeObject: the first 14 bytes of its
/// MD5 (Sec.7.3.4.8).
fn equivalence_hash(type_object: &[u8]) -> crate::xtypes::EquivalenceHash {
    let mut hash = [0u8; 14];
    hash.copy_from_slice(&md5(type_object)[..14]);
    crate::xtypes::EquivalenceHash::from_bytes(hash)
}

/// The choices one peer's ShapeType TypeObject makes (see the module doc).
#[derive(Clone, Copy)]
struct PeerShape {
    /// The GUID prefix of the peer's participant (RTPS v2.5 Sec.8.2.4.1),
    /// chosen for the test.
    prefix: [u8; 12],
    /// MemberFlag of the key member `color`.
    key_flags: u16,
    /// SBound of `color`'s TI_STRING8_SMALL.
    color_bound: u8,
    /// CollectionElementFlag of `additional_payload_size`'s elements.
    element_flags: u16,
}

const PEER_A: PeerShape = PeerShape {
    prefix: [0xA0, 0x0A, 0x7E, 0x57, 0, 0, 0, 0, 0, 0, 0, 0x0A],
    key_flags: 0x0031,
    color_bound: 0,
    element_flags: 0x0001,
};

const PEER_B: PeerShape = PeerShape {
    prefix: [0xB0, 0x0B, 0x7E, 0x57, 0, 0, 0, 0, 0, 0, 0, 0x0B],
    key_flags: 0x0021,
    color_bound: 128,
    element_flags: 0x0000,
};

/// ShapeType's members in declaration order; member ids are their indices.
const SHAPE_MEMBERS: [&str; 5] = ["color", "x", "y", "shapesize", "additional_payload_size"];

/// MemberFlag of member `index`: the peer's key flags for `color`,
/// TRY_CONSTRUCT1 (DISCARD, Sec.7.2.2.7) for the others.
fn member_flags(shape: PeerShape, index: usize) -> u16 {
    if index == 0 {
        shape.key_flags
    } else {
        0x0001
    }
}

/// The TypeIdentifier of member `index` (Annex B). Every one is fully
/// descriptive, so the minimal and complete objects carry the same bytes.
fn write_member_type(w: &mut Xcdr2Le, shape: PeerShape, index: usize) {
    match index {
        // TI_STRING8_SMALL, then StringSTypeDefn { SBound bound }.
        0 => {
            w.u8(0x70);
            w.u8(shape.color_bound);
        }
        // `x`, `y`, `shapesize`: TK_INT32.
        1..=3 => w.u8(0x04),
        // TI_PLAIN_SEQUENCE_SMALL, then PlainSequenceSElemDefn:
        // PlainCollectionHeader { EquivalenceKind equiv_kind = EK_BOTH (a
        // primitive element), CollectionElementFlag element_flags },
        // SBound bound = 0 (unbounded), element_identifier = TK_UINT8.
        _ => {
            w.u8(0x80);
            w.u8(0xF3);
            w.u16(shape.element_flags);
            w.u8(0);
            w.u8(0x0D);
        }
    }
}

/// The serialized TypeObject (EK_COMPLETE) of the peer's ShapeType, from
/// its DHEADER: the bytes a getTypes reply carries, and the preimage of the
/// COMPLETE EquivalenceHash.
fn complete_type_object_bytes(shape: PeerShape) -> Vec<u8> {
    let mut w = Xcdr2Le::default();
    // TypeObject: @appendable union, so a DHEADER, then the discriminator.
    w.delimited(|w| {
        w.u8(0xF2); // EK_COMPLETE
        w.u8(0x51); // CompleteTypeObject (@final union): TK_STRUCTURE
        w.u16(0x0002); // CompleteStructType.struct_flags: IS_APPENDABLE
                       // CompleteStructHeader (@appendable).
        w.delimited(|w| {
            w.u8(0x00); // base_type: TK_NONE
                        // CompleteTypeDetail (@final): ann_builtin, ann_custom absent
                        // (an @optional member of a final struct is a presence flag),
                        // then type_name.
            w.u8(0);
            w.u8(0);
            w.string("ShapeType");
        });
        // CompleteStructMemberSeq: a sequence of an @appendable element.
        w.delimited(|w| {
            w.u32(5);
            for (index, name) in SHAPE_MEMBERS.iter().enumerate() {
                // CompleteStructMember (@appendable).
                w.delimited(|w| {
                    // CommonStructMember (@final): member_id, member_flags,
                    // member_type_id.
                    w.u32(u32::try_from(index).expect("small"));
                    w.u16(member_flags(shape, index));
                    write_member_type(w, shape, index);
                    // CompleteMemberDetail (@final): name, ann_builtin and
                    // ann_custom absent.
                    w.string(name);
                    w.u8(0);
                    w.u8(0);
                });
            }
        });
    });
    w.0
}

/// The serialized TypeObject (EK_MINIMAL) of the same ShapeType: the
/// preimage of the MINIMAL EquivalenceHash.
fn minimal_type_object_bytes(shape: PeerShape) -> Vec<u8> {
    let mut w = Xcdr2Le::default();
    w.delimited(|w| {
        w.u8(0xF1); // EK_MINIMAL
        w.u8(0x51); // MinimalTypeObject (@final union): TK_STRUCTURE
        w.u16(0x0002); // MinimalStructType.struct_flags: IS_APPENDABLE
                       // MinimalStructHeader (@appendable): base_type TK_NONE, then an
                       // empty MinimalTypeDetail.
        w.delimited(|w| w.u8(0x00));
        // MinimalStructMemberSeq.
        w.delimited(|w| {
            w.u32(5);
            for (index, name) in SHAPE_MEMBERS.iter().enumerate() {
                // MinimalStructMember (@appendable).
                w.delimited(|w| {
                    w.u32(u32::try_from(index).expect("small"));
                    w.u16(member_flags(shape, index));
                    write_member_type(w, shape, index);
                    // MinimalMemberDetail (@final): NameHash, the first four
                    // octets of the MD5 of the member name.
                    w.octets(&md5(name.as_bytes())[..4]);
                });
            }
        });
    });
    w.0
}

/// The value of PID_TYPE_INFORMATION (DDS-XTypes v1.3 Sec.7.6.3.2.2) naming
/// the two TypeObjects by their hashes and serialized sizes, with no
/// dependencies (every member type is fully descriptive).
fn type_information_value(minimal: &[u8], complete: &[u8]) -> Vec<u8> {
    let mut w = Xcdr2Le::default();
    // TypeInformation (@mutable): DHEADER, then one EMHEADER per member.
    w.delimited(|w| {
        for (member_id, ek, object) in [(0x1001u32, 0xF1u8, minimal), (0x1002, 0xF2, complete)] {
            // EMHEADER1: M=0, LC=4 (the length is in NEXTINT), member id.
            w.u32(0x4000_0000 | member_id);
            // NEXTINT, then TypeIdentifierWithDependencies (@appendable).
            w.delimited(|w| {
                w.delimited(|w| {
                    // typeid_with_size: TypeIdentifierWithSize (@appendable).
                    w.delimited(|w| {
                        w.u8(ek);
                        w.octets(equivalence_hash(object).as_bytes());
                        w.u32(u32::try_from(object.len()).expect("small"));
                    });
                    w.u32(0); // dependent_typeid_count
                    w.delimited(|w| w.u32(0)); // dependent_typeids: empty
                });
            });
        }
    });
    w.0
}

/// The peer's writer: entity key 0x000001, kind 0x02, a user writer with key
/// (RTPS v2.5 Sec.9.3.1.2).
const PEER_WRITER_ENTITY: [u8; 4] = [0x00, 0x00, 0x01, 0x02];

/// The serialized payload of the peer's SEDP DATA(w) for its writer of
/// Square/ShapeType: PL_CDR_LE, the parameters a remote writer needs to be
/// discovered and typed, and no PID_TYPE_OBJECT, so that its type is only
/// known once TypeLookup resolves the hash its TypeInformation names.
fn sedp_payload(shape: PeerShape) -> Vec<u8> {
    fn parameter(out: &mut Vec<u8>, pid: u16, value: &[u8]) {
        let padded = value.len().next_multiple_of(4);
        out.extend_from_slice(&pid.to_le_bytes());
        out.extend_from_slice(&u16::try_from(padded).expect("short").to_le_bytes());
        out.extend_from_slice(value);
        out.resize(out.len() + padded - value.len(), 0);
    }
    fn string(s: &str) -> Vec<u8> {
        let mut w = Xcdr2Le::default();
        w.string(s);
        w.0
    }
    let guid = |entity: [u8; 4]| [&shape.prefix[..], &entity[..]].concat();
    // Encapsulation PL_CDR_LE (0x0003), options 0 (RTPS v2.5 Sec.10.2).
    let mut out = vec![0x00, 0x03, 0x00, 0x00];
    parameter(&mut out, 0x005A, &guid(PEER_WRITER_ENTITY)); // PID_ENDPOINT_GUID
    parameter(&mut out, 0x0050, &guid([0x00, 0x00, 0x01, 0xC1])); // PID_PARTICIPANT_GUID
    parameter(&mut out, 0x0005, &string("Square")); // PID_TOPIC_NAME
    parameter(&mut out, 0x0007, &string("ShapeType")); // PID_TYPE_NAME
                                                       // PID_DATA_REPRESENTATION (DDS-XTypes v1.3 Sec.7.6.3.1.1): a sequence of
                                                       // one short, XCDR2_DATA_REPRESENTATION (2), what the readers here use.
    parameter(&mut out, 0x0073, &[1, 0, 0, 0, 2, 0]);
    parameter(
        &mut out,
        0x0075, // PID_TYPE_INFORMATION
        &type_information_value(
            &minimal_type_object_bytes(shape),
            &complete_type_object_bytes(shape),
        ),
    );
    out.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]); // PID_SENTINEL
    out
}

/// A foreign ShapeType announcement: what SEDP said, and what TypeLookup
/// answered for it.
pub(super) struct ForeignShape {
    pub sedp: SedpData,
    pub type_object: CompleteTypeObject,
}

/// Parse and decode one peer's fixtures, asserting the invariants the tests
/// rely on: the SEDP announces the writer of Square/ShapeType by
/// TypeInformation alone, naming the hashes of the bytes built above, and
/// HDDS decodes the COMPLETE TypeObject to its own delimiter and hashes it,
/// re-encoded, to the hash the SEDP names.
fn foreign_shape(shape: PeerShape) -> ForeignShape {
    let sedp = crate::protocol::discovery::parse_sedp(&sedp_payload(shape)).expect("fixture: SEDP");
    assert_eq!(sedp.topic_name, "Square", "fixture: topic");
    assert_eq!(sedp.type_name, "ShapeType", "fixture: type name");
    assert_eq!(
        sedp.endpoint_guid.entity_id[3], 0x02,
        "fixture: a user writer with key"
    );
    assert!(
        sedp.type_object.is_none(),
        "fixture: no inline TypeObject - TypeLookup is what resolves it"
    );
    let raw = complete_type_object_bytes(shape);
    assert_eq!(raw[4], 0xF2, "fixture: EK_COMPLETE");
    let mut cursor = 5;
    let type_object =
        CompleteTypeObject::decode_cdr2_le_at(&raw, &mut cursor).expect("fixture: TypeObject");
    assert_eq!(cursor, raw.len(), "fixture: decoded to its delimiter");
    let info = sedp
        .type_information
        .as_ref()
        .expect("fixture: the SEDP carries TypeInformation");
    let complete = info
        .complete
        .as_ref()
        .expect("fixture: the SEDP announces a COMPLETE TypeIdentifier");
    assert_eq!(
        complete.hash,
        equivalence_hash(&raw),
        "fixture: the SEDP names the COMPLETE object built here"
    );
    assert_eq!(
        type_object.compute_equivalence_hash().ok(),
        Some(complete.hash),
        "fixture: HDDS re-encodes the object to the bytes built here"
    );
    let minimal = info
        .minimal
        .as_ref()
        .expect("fixture: the SEDP announces a MINIMAL TypeIdentifier");
    assert_eq!(
        minimal.hash,
        equivalence_hash(&minimal_type_object_bytes(shape)),
        "fixture: the SEDP names the MINIMAL object built here"
    );
    ForeignShape { sedp, type_object }
}

pub(in crate::dds::participant) fn peer_a() -> ForeignShape {
    foreign_shape(PEER_A)
}

pub(super) fn peer_b() -> ForeignShape {
    foreign_shape(PEER_B)
}

pub(super) fn shape_main_type_object() -> CompleteTypeObject {
    shape_main::shape_type_object()
}

/// Both directions of the pairing: the peer's writer with our reader, whose
/// TypeConsistencyEnforcement shape_main leaves unset; our writer with the
/// peer's reader, which announces none, so the spec default applies
/// (Sec.7.6.3.4.1).
fn assert_assignable_both_ways(peer: &ForeignShape, who: &str) {
    let ours = shape_main_type_object();
    assert!(
        Matcher::is_type_compatible_with_policy(
            Some(&peer.type_object),
            Some(&ours),
            &peer.sedp.type_name,
            "ShapeType",
            None,
        ),
        "{who}'s ShapeType writer is assignable to shape_main's reader"
    );
    assert!(
        Matcher::is_type_compatible_with_policy(
            Some(&ours),
            Some(&peer.type_object),
            "ShapeType",
            &peer.sedp.type_name,
            Some(&TypeConsistencyEnforcement::default()),
        ),
        "shape_main's ShapeType writer is assignable to {who}'s reader"
    );
}

/// The TypeIdentifier of member `name` in a struct TypeObject.
fn member_type(type_object: &CompleteTypeObject, name: &str) -> crate::xtypes::TypeIdentifier {
    let CompleteTypeObject::Struct(shape) = type_object else {
        panic!("fixture: ShapeType is a struct");
    };
    shape
        .member_seq
        .iter()
        .find(|m| m.detail.name == name)
        .expect("fixture: the member")
        .common
        .member_type_id
        .clone()
}

/// shape_main's `additional_payload_size` is, to the byte, the
/// TypeIdentifier peer A's object carries for it: TI_PLAIN_SEQUENCE_SMALL
/// (0x80), a PlainCollectionHeader of EK_BOTH (0xF3, a primitive element is
/// fully descriptive) and TRY_CONSTRUCT1 (DISCARD, the default), unbounded,
/// of uint8 (0x0D). Peer B's is the same but for its element flags (0).
#[test]
fn shape_main_s_payload_sequence_is_the_identifier_the_peers_announce() {
    use crate::Cdr2Encode;
    let ours = member_type(&shape_main_type_object(), "additional_payload_size");
    let mut buf = [0u8; 16];
    let len = ours.encode_cdr2_le(&mut buf).expect("encodes");
    assert_eq!(
        &buf[..len],
        &[0x80, 0xF3, 0x01, 0x00, 0x00, 0x0D],
        "shape_main's bytes for the member"
    );
    assert_eq!(
        member_type(&peer_a().type_object, "additional_payload_size"),
        ours,
        "peer A's identifier for the member, decoded from its getTypes answer"
    );
    let theirs = member_type(&peer_b().type_object, "additional_payload_size");
    let crate::xtypes::TypeIdentifier::PlainSequenceSmall(ref seq) = theirs else {
        panic!("peer B announces a small plain sequence: {theirs:?}");
    };
    assert_eq!(seq.header.equiv_kind, crate::xtypes::EquivalenceKind::Both);
    assert_eq!(seq.header.element_flags.0, 0, "peer B's element flags");
}

/// Peer A's key carries IS_MUST_UNDERSTAND and no bound, shape_main's bound
/// 128 and no such flag: assignable both ways.
#[test]
fn peer_a_s_shapetype_and_shape_main_s_are_assignable_both_ways() {
    assert_assignable_both_ways(&peer_a(), "peer A");
}

/// Peer B's key carries the bound 128, shape_main's the same: assignable
/// both ways.
#[test]
fn peer_b_s_shapetype_and_shape_main_s_are_assignable_both_ways() {
    assert_assignable_both_ways(&peer_b(), "peer B");
}

// ---------------------------------------------------------------------------
// The verdict does not depend on the order things arrive in
// ---------------------------------------------------------------------------
//
// Three things arrive in an order nobody controls: the remote writer's SEDP
// (TypeInformation only), the TypeLookup reply that resolves its TypeObject
// (`DiscoveryFsm::update_type_object_for_type`, what the getTypes reply path
// calls), and the local reader. The verdict must not depend on whether the
// reply lands before or after the reader registers: each order below must
// end in the same match state and deliver the same samples.

use super::{Participant, TransportMode};
use crate::core::discovery::multicast::DiscoveryFsm;
use crate::core::discovery::GUID;
use crate::core::rtps_constants::RTPS_ENTITYID_PARTICIPANT;
use crate::dds::listener::{
    DataReaderListener, InconsistentTopicStatus, SubscriptionMatchedStatus,
};
use crate::dds::{QoS, DDS};
use crate::protocol::discovery::SpdpData;
use crate::test_support::domains::{unique_domain, DomainLease};
use crate::xtypes::TypeIdentifier;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq, crate::DDS)]
struct ShapeWire {
    color: String,
    x: i32,
    y: i32,
    shapesize: i32,
    additional_payload_size: Vec<u8>,
}

/// A reader-side ShapeType that announces shape_main's TypeObject.
#[derive(Debug, Clone, PartialEq)]
struct Shape(ShapeWire);

impl DDS for Shape {
    fn type_descriptor() -> &'static crate::core::types::TypeDescriptor {
        ShapeWire::type_descriptor()
    }

    fn encode(&self, buf: &mut [u8], version: crate::dds::CdrVersion) -> crate::dds::Result<usize> {
        self.0.encode(buf, version)
    }

    fn decode(buf: &[u8], version: crate::dds::CdrVersion) -> crate::dds::Result<Self> {
        ShapeWire::decode(buf, version).map(Shape)
    }

    fn get_type_object() -> Option<CompleteTypeObject> {
        Some(shape_main_type_object())
    }
}

fn sample(x: i32) -> Shape {
    Shape(ShapeWire {
        color: "BLUE".to_string(),
        x,
        y: 2 * x,
        shapesize: 30,
        additional_payload_size: Vec::new(),
    })
}

fn encoded(shape: &Shape) -> Vec<u8> {
    let mut buf = vec![0u8; 256];
    let len = shape
        .encode(&mut buf, crate::dds::CdrVersion::Xcdr2)
        .expect("encode");
    buf.truncate(len);
    buf
}

/// What the reader's listener heard: its subscription-matched current count
/// and its inconsistent-topic total.
#[derive(Default)]
struct Heard {
    matched: AtomicU32,
    inconsistent: AtomicU32,
}

impl DataReaderListener<Shape> for Heard {
    fn on_subscription_matched(&self, status: SubscriptionMatchedStatus) {
        self.matched.store(status.current_count, Ordering::SeqCst);
    }

    fn on_inconsistent_topic(&self, status: InconsistentTopicStatus) {
        self.inconsistent
            .store(status.total_count, Ordering::SeqCst);
    }
}

/// The order in which the remote writer's SEDP, the TypeLookup reply that
/// resolves its type, and the local reader arrive.
#[derive(Debug, Clone, Copy)]
enum Order {
    /// Reader, then SEDP, then reply.
    ReaderFirst,
    /// Reader, then a SEDP whose type is known as it arrives (carried
    /// inline, as an HDDS peer sends it): no reply to wait for.
    ReaderFirstTypeKnownAtSedp,
    /// SEDP, reply, then reader: the type is known before any reader is
    /// there to judge it.
    WriterFirst,
    /// The SEDP lands during our startup probation and is deferred, the
    /// reply and the reader follow, and the writer's participant is
    /// confirmed after the probation: the deferred discovery is replayed
    /// from the copy taken when the SEDP arrived, before its type was known.
    WriterDeferredInProbation,
}

const ORDERS: [Order; 4] = [
    Order::ReaderFirst,
    Order::ReaderFirstTypeKnownAtSedp,
    Order::WriterFirst,
    Order::WriterDeferredInProbation,
];

fn peer_spdp(prefix: [u8; 12]) -> SpdpData {
    let locator: std::net::SocketAddr = "127.0.0.1:9".parse().expect("address");
    SpdpData {
        participant_guid: GUID::new(prefix, RTPS_ENTITYID_PARTICIPANT),
        lease_duration_ms: 30_000,
        domain_id: 0,
        metatraffic_unicast_locators: vec![locator],
        default_unicast_locators: vec![locator],
        default_multicast_locators: vec![],
        metatraffic_multicast_locators: vec![],
        identity_token: None,
        permissions_token: None,
        participant_security_info: None,
        vendor_id: None,
        hdds_capabilities: None,
        builtin_endpoint_set: None,
    }
}

fn fsm(p: &Participant) -> &Arc<DiscoveryFsm> {
    p.discovery_fsm
        .as_ref()
        .expect("a UDP participant runs discovery")
}

fn sleep_until_uptime(p: &Participant, uptime: Duration) {
    if let Some(rest) = uptime.checked_sub(fsm(p).uptime()) {
        std::thread::sleep(rest);
    }
}

/// `sedp` as its peer announces it when the type behind it is `type_object`:
/// its TypeInformation names that type's COMPLETE hash.
fn announcing(sedp: &SedpData, type_object: &CompleteTypeObject) -> SedpData {
    let mut announced = sedp.clone();
    let complete = announced
        .type_information
        .as_mut()
        .and_then(|ti| ti.complete.as_mut())
        .expect("fixture: the SEDP announces a COMPLETE TypeIdentifier");
    complete.hash = type_object.compute_equivalence_hash().expect("hashable");
    announced
}

/// What a run ends in: the reader's matched count, its inconsistent-topic
/// total, and the samples it took.
#[derive(Debug, PartialEq)]
struct Outcome {
    matched: u32,
    inconsistent: u32,
    taken: Vec<i32>,
}

/// Wait for the matched count to reach `expected`, then hold it for a while:
/// the count is read once it has settled, never in a transient.
fn settled_matched(heard: &Heard, expected: u32) -> u32 {
    let deadline = Instant::now() + Duration::from_secs(3);
    while heard.matched.load(Ordering::SeqCst) != expected && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    std::thread::sleep(Duration::from_millis(150));
    heard.matched.load(Ordering::SeqCst)
}

/// Run one order against `writer_type` (the TypeObject the TypeLookup reply
/// resolves for the remote writer) and report the outcome. `expected_matched`
/// only tells the wait what to wait for; the caller asserts the outcome.
fn run(
    order: Order,
    peer: &ForeignShape,
    writer_type: Option<&CompleteTypeObject>,
    reader_policy: Option<&TypeConsistencyEnforcement>,
    expected_matched: u32,
) -> Outcome {
    let domain: DomainLease = unique_domain();
    let p = Participant::builder(&format!("type_verdict_{order:?}"))
        .domain_id(domain.id())
        .with_transport(TransportMode::UdpMulticast)
        .build()
        .expect("participant");
    let peer_prefix = peer.sedp.participant_guid.prefix;
    let writer = peer.sedp.endpoint_guid;
    // The peer announces the hash of the type it will answer TypeLookup
    // with, as a conforming peer does; the reply resolves that hash.
    let announced = writer_type.map(|t| announcing(&peer.sedp, t));
    let sedp = announced.clone().unwrap_or_else(|| peer.sedp.clone());
    let heard = Arc::new(Heard::default());
    let build_reader = || {
        p.topic::<Shape>("Square")
            .expect("topic")
            .reader()
            .qos(QoS {
                type_consistency: reader_policy.cloned(),
                ..QoS::best_effort().keep_last(16).data_representation_xcdr2()
            })
            .with_listener(heard.clone())
            .build()
            .expect("reader")
    };
    // What the getTypes reply path does with the answer. No reply when the
    // writer's type stays unknown.
    let resolve_writer_type = || {
        if let Some(writer_type) = writer_type {
            let hash = writer_type.compute_equivalence_hash().expect("hashable");
            fsm(&p).update_type_object_for_hash(&hash, writer_type.clone());
        }
    };

    let reader = match order {
        Order::ReaderFirst | Order::ReaderFirstTypeKnownAtSedp | Order::WriterFirst => {
            // The peer is confirmed past our probation: its endpoints
            // surface as soon as they are announced.
            sleep_until_uptime(&p, Duration::from_millis(300));
            fsm(&p).handle_spdp(peer_spdp(peer_prefix));
            std::thread::sleep(Duration::from_millis(150));
            fsm(&p).handle_spdp(peer_spdp(peer_prefix));
            assert!(fsm(&p).is_participant_confirmed(&peer_prefix), "fixture");
            if let Order::ReaderFirst = order {
                let reader = build_reader();
                fsm(&p).handle_sedp(sedp.clone());
                resolve_writer_type();
                reader
            } else if let Order::ReaderFirstTypeKnownAtSedp = order {
                let reader = build_reader();
                let mut inline = sedp.clone();
                inline.type_object = writer_type.cloned();
                fsm(&p).handle_sedp(inline);
                reader
            } else {
                fsm(&p).handle_sedp(sedp.clone());
                resolve_writer_type();
                build_reader()
            }
        }
        Order::WriterDeferredInProbation => {
            fsm(&p).handle_spdp(peer_spdp(peer_prefix));
            fsm(&p).handle_sedp(sedp.clone());
            assert!(
                fsm(&p).uptime() < Duration::from_millis(250),
                "fixture: the SEDP lands during our probation"
            );
            resolve_writer_type();
            let reader = build_reader();
            // Heard again more than 100 ms after its first announcement: the
            // probation keeps it. Heard after the boundary: it surfaces, and
            // its deferred SEDP is replayed.
            std::thread::sleep(Duration::from_millis(120));
            fsm(&p).handle_spdp(peer_spdp(peer_prefix));
            sleep_until_uptime(&p, Duration::from_millis(320));
            fsm(&p).handle_spdp(peer_spdp(peer_prefix));
            assert!(fsm(&p).is_participant_known(&peer_prefix), "fixture");
            reader
        }
    };

    // What the SEDP handler records for a remote writer before its DATA is
    // admitted (sedp_handler.rs): its topic and its OWNERSHIP kind.
    let registry = p.registry.as_ref().expect("registry");
    registry.register_writer_guid(writer.as_bytes(), "Square".to_string());
    registry.register_writer_ownership_kind(
        writer.as_bytes(),
        crate::qos::ownership::OwnershipKind::Shared,
    );
    let matched_now = settled_matched(&heard, expected_matched);
    let route = registry.get_topic("Square").expect("the reader's topic");
    for seq in 1..=3u64 {
        let x = i32::try_from(seq).expect("small");
        route.deliver_with_writer(
            writer.as_bytes(),
            seq,
            &encoded(&sample(x)),
            crate::dds::CdrVersion::Xcdr2,
        );
    }
    let mut taken = Vec::new();
    while let Ok(Some(shape)) = reader.take() {
        taken.push(shape.0.x);
    }
    Outcome {
        matched: matched_now,
        inconsistent: heard.inconsistent.load(Ordering::SeqCst),
        taken,
    }
}

/// Run every order and compare all of them with `expected`, so a failure
/// shows every order's outcome, not the first one that differs.
fn assert_every_order_ends_in(
    peer: &ForeignShape,
    writer_type: Option<&CompleteTypeObject>,
    reader_policy: Option<&TypeConsistencyEnforcement>,
    expected: Outcome,
) {
    let outcomes: Vec<(Order, Outcome)> = ORDERS
        .iter()
        .map(|&order| {
            let outcome = run(order, peer, writer_type, reader_policy, expected.matched);
            (order, outcome)
        })
        .collect();
    assert!(
        outcomes.iter().all(|(_, outcome)| *outcome == expected),
        "expected {expected:?} in every order, got {outcomes:?}"
    );
}

/// A ShapeType whose `x` is a float64: not assignable to shape_main's, whose
/// `x` is an int32, in either direction (DDS-XTypes v1.3 Sec.7.2.4.4.4
/// Table 15; int32 and float64 are on no common widening chain).
fn incompatible_variant_of(peer: &ForeignShape) -> CompleteTypeObject {
    let mut changed = peer.type_object.clone();
    let CompleteTypeObject::Struct(ref mut shape) = changed else {
        panic!("fixture: ShapeType is a struct");
    };
    let x = shape
        .member_seq
        .iter_mut()
        .find(|m| m.detail.name == "x")
        .expect("fixture: x");
    x.common.member_type_id = TypeIdentifier::TK_FLOAT64;
    changed
}

/// Peer A's ShapeType writer is matched by shape_main's reader and its samples
/// are delivered, whichever of the SEDP, the TypeLookup reply and the reader
/// comes first.
#[test]
fn a_compatible_foreign_writer_is_matched_and_delivered_in_every_order() {
    let peer = peer_a();
    assert_every_order_ends_in(
        &peer,
        Some(&peer.type_object),
        None,
        Outcome {
            matched: 1,
            inconsistent: 0,
            taken: vec![1, 2, 3],
        },
    );
}

/// A writer whose type is not assignable to the reader's is refused in every
/// order: not matched, reported once as an inconsistent topic
/// (Sec.7.6.3.4.2), and none of its samples delivered. Before the verdict
/// was one, the reader-first order matched it and delivered its samples (the
/// type was learned after the match and nothing judged it again), and the
/// deferred order reported it matched while dropping every sample.
#[test]
fn an_incompatible_foreign_writer_is_refused_in_every_order() {
    let peer = peer_a();
    let incompatible = incompatible_variant_of(&peer);
    assert!(
        !Matcher::is_type_compatible_with_policy(
            Some(&incompatible),
            Some(&shape_main_type_object()),
            "ShapeType",
            "ShapeType",
            None,
        ),
        "fixture: the variant is not assignable to shape_main's ShapeType"
    );
    assert_every_order_ends_in(
        &peer,
        Some(&incompatible),
        None,
        Outcome {
            matched: 0,
            inconsistent: 1,
            taken: vec![],
        },
    );
}

/// A reader that forces type validation refuses a writer whose type it never
/// learns, in every order (Sec.7.6.3.4.2 Step 2: the step fails when
/// force_type_validation is true, regardless of the type names).
#[test]
fn a_writer_of_unknown_type_is_refused_by_a_reader_forcing_type_validation() {
    let peer = peer_a();
    let forced = TypeConsistencyEnforcement {
        force_type_validation: true,
        ..TypeConsistencyEnforcement::default()
    };
    assert_every_order_ends_in(
        &peer,
        None,
        Some(&forced),
        Outcome {
            matched: 0,
            inconsistent: 1,
            taken: vec![],
        },
    );
}

/// A TypeLookup reply gives the type it resolved to the remote endpoints of
/// that type name and to no local one: a local endpoint's type is the one
/// its code declares, even when it declares none.
#[test]
fn a_type_lookup_reply_gives_its_type_to_remote_endpoints_only() {
    let peer = peer_a();
    let local_prefix = [0x01, 0x1a, 0x7e, 0x57, 0, 0, 0, 0, 0, 0, 0, 1];
    let fsm = DiscoveryFsm::new(GUID::new(local_prefix, RTPS_ENTITYID_PARTICIPANT), 30_000);
    fsm.handle_spdp(peer_spdp(peer.sedp.participant_guid.prefix));
    fsm.handle_sedp(peer.sedp.clone());
    // A local reader of a type named the same that declares no TypeObject.
    let local_reader = GUID::new(local_prefix, [0x00, 0x00, 0x01, 0x07]);
    let mut local = peer.sedp.clone();
    local.endpoint_guid = local_reader;
    local.participant_guid = GUID::new(local_prefix, RTPS_ENTITYID_PARTICIPANT);
    local.type_information = None;
    fsm.handle_sedp(local);

    assert_eq!(
        fsm.update_type_object_for_type("ShapeType", peer.type_object.clone()),
        1,
        "one endpoint updated: the remote writer"
    );
    let remote_now = fsm
        .find_writers_for_topic("Square")
        .into_iter()
        .find(|w| w.endpoint_guid == peer.sedp.endpoint_guid)
        .expect("the remote writer is known");
    assert_eq!(remote_now.type_object.as_ref(), Some(&peer.type_object));
    let local_now = fsm
        .find_readers_for_topic("Square")
        .into_iter()
        .find(|r| r.endpoint_guid == local_reader)
        .expect("the local reader is known");
    assert!(
        local_now.type_object.is_none(),
        "the local reader keeps the type it declared: none"
    );
}

/// Two peers publish under the one type name `ShapeType`, with different
/// types: peer A's, and a variant whose `x` is a float64. A TypeLookup answer
/// resolves the endpoints that announced its hash, and no other one: the
/// variant's writer is never judged on peer A's type, nor peer A's on the
/// variant's, whichever reply comes first. The name-keyed path (HTLK) holds
/// to the same rule for an endpoint that announced a hash.
#[test]
fn a_type_lookup_answer_resolves_only_the_endpoints_that_announced_its_hash() {
    let peer = peer_a();
    let variant = incompatible_variant_of(&peer);
    let variant_hash = variant.compute_equivalence_hash().expect("hashable");
    let peer_hash = peer
        .type_object
        .compute_equivalence_hash()
        .expect("hashable");
    let local_prefix = [0x01, 0x1a, 0x7e, 0x57, 0, 0, 0, 0, 0, 0, 0, 2];
    let other_prefix = [0x01, 0x0f, 0x7e, 0x57, 0, 0, 0, 0, 0, 0, 0, 3];
    let fsm = DiscoveryFsm::new(GUID::new(local_prefix, RTPS_ENTITYID_PARTICIPANT), 30_000);
    fsm.handle_spdp(peer_spdp(peer.sedp.participant_guid.prefix));
    fsm.handle_spdp(peer_spdp(other_prefix));
    fsm.handle_sedp(peer.sedp.clone());
    let mut other = announcing(&peer.sedp, &variant);
    other.participant_guid = GUID::new(other_prefix, RTPS_ENTITYID_PARTICIPANT);
    other.endpoint_guid = GUID::new(other_prefix, [0x00, 0x00, 0x01, 0x02]);
    fsm.handle_sedp(other.clone());
    let type_of = |guid: GUID| {
        fsm.find_writers_for_topic("Square")
            .into_iter()
            .find(|w| w.endpoint_guid == guid)
            .expect("the writer is known")
            .type_object
    };

    assert_eq!(
        fsm.update_type_object_for_hash(&variant_hash, variant.clone()),
        1,
        "the variant's answer resolves the variant's writer"
    );
    assert_eq!(type_of(other.endpoint_guid), Some(variant.clone()));
    assert_eq!(
        type_of(peer.sedp.endpoint_guid),
        None,
        "and not peer A's, which shares its type name"
    );
    assert_eq!(
        fsm.update_type_object_for_type("ShapeType", variant.clone()),
        0,
        "by name, peer A's writer is not given a type whose hash it did not announce"
    );
    assert_eq!(type_of(peer.sedp.endpoint_guid), None);
    assert_eq!(
        fsm.update_type_object_for_hash(&peer_hash, peer.type_object.clone()),
        1,
        "peer A's answer resolves peer A's writer"
    );
    assert_eq!(
        type_of(peer.sedp.endpoint_guid),
        Some(peer.type_object.clone())
    );
    assert_eq!(type_of(other.endpoint_guid), Some(variant));
}

/// A reader forcing type validation refuses a writer while its type is
/// unknown, and matches it and takes its samples once a TypeLookup answer
/// makes the type known and acceptable - whichever came first. Matched and
/// delivered in every order; the INCONSISTENT_TOPIC reported while the type
/// was unknown (the reader-first orders) is a fact of that moment and is not
/// compared.
#[test]
fn a_refusal_for_an_unknown_type_is_lifted_once_the_type_is_known_and_accepted() {
    let peer = peer_a();
    let forced = TypeConsistencyEnforcement {
        force_type_validation: true,
        ..TypeConsistencyEnforcement::default()
    };
    let outcomes: Vec<(Order, u32, Vec<i32>)> = ORDERS
        .iter()
        .map(|&order| {
            let outcome = run(order, &peer, Some(&peer.type_object), Some(&forced), 1);
            (order, outcome.matched, outcome.taken)
        })
        .collect();
    assert!(
        outcomes
            .iter()
            .all(|(_, matched, taken)| *matched == 1 && *taken == vec![1, 2, 3]),
        "matched and delivered in every order, got {outcomes:?}"
    );
}

/// Peer A's SEDP DATA(w) as a whole RTPS datagram, built for the test: an
/// RTPS header of peer A's participant (RTPS v2.5 Sec.8.3.3.1) and one DATA
/// submessage (Sec.9.4.5.3) from the SEDP publications writer carrying
/// `sedp_payload(PEER_A)`. The payload starts at
/// `crate::...::wire_fixtures::SAMPLE_AT` (44).
#[cfg(feature = "xtypes-structural-assignability")]
pub(in crate::dds::participant) fn peer_sedp_datagram() -> Vec<u8> {
    let payload = sedp_payload(PEER_A);
    let mut packet = Vec::with_capacity(44 + payload.len());
    packet.extend_from_slice(b"RTPS");
    // Protocol version 2.5, VENDORID_UNKNOWN (Sec.9.3.1.5): nothing on this
    // path depends on the sender's vendor.
    packet.extend_from_slice(&[0x02, 0x05, 0x00, 0x00]);
    packet.extend_from_slice(&PEER_A.prefix);
    let octets_to_next_header = u16::try_from(20 + payload.len()).expect("one datagram");
    packet.extend_from_slice(&[0x15, 0x05]); // DATA, little-endian, data present
    packet.extend_from_slice(&octets_to_next_header.to_le_bytes());
    packet.extend_from_slice(&[0x00, 0x00, 0x10, 0x00]); // extraFlags, octetsToInlineQos
    packet.extend_from_slice(&[0x00, 0x00, 0x03, 0xC7]); // SEDP publications reader
    packet.extend_from_slice(&[0x00, 0x00, 0x03, 0xC2]); // SEDP publications writer
    packet.extend_from_slice(&0i32.to_le_bytes()); // writerSN high
    packet.extend_from_slice(&1u32.to_le_bytes()); // writerSN low
    assert_eq!(packet.len(), 44, "fixture: the payload starts at 44");
    packet.extend_from_slice(&payload);
    packet
}

// ---------------------------------------------------------------------------
// The data-plane gate is per (writer, reader) pair
// ---------------------------------------------------------------------------

/// A participant past its probation with the remote peer `peer_prefix`
/// confirmed: the peer's endpoints surface as soon as they are announced.
fn participant_with_confirmed_peer(
    name: &str,
    peer_prefix: [u8; 12],
) -> (DomainLease, Arc<Participant>) {
    let domain: DomainLease = unique_domain();
    let p = Participant::builder(name)
        .domain_id(domain.id())
        .with_transport(TransportMode::UdpMulticast)
        .build()
        .expect("participant");
    sleep_until_uptime(&p, Duration::from_millis(300));
    fsm(&p).handle_spdp(peer_spdp(peer_prefix));
    std::thread::sleep(Duration::from_millis(150));
    fsm(&p).handle_spdp(peer_spdp(peer_prefix));
    assert!(fsm(&p).is_participant_confirmed(&peer_prefix), "fixture");
    (domain, p)
}

/// Deliver samples x = 1, 2, 3 from `writer` on Square, as the receive path
/// does once the SEDP handler has recorded the writer.
fn deliver_three(p: &Participant, writer: GUID) {
    let registry = p.registry.as_ref().expect("registry");
    registry.register_writer_guid(writer.as_bytes(), "Square".to_string());
    registry.register_writer_ownership_kind(
        writer.as_bytes(),
        crate::qos::ownership::OwnershipKind::Shared,
    );
    let route = registry.get_topic("Square").expect("the readers' topic");
    for seq in 1..=3u64 {
        let x = i32::try_from(seq).expect("small");
        route.deliver_with_writer(
            writer.as_bytes(),
            seq,
            &encoded(&sample(x)),
            crate::dds::CdrVersion::Xcdr2,
        );
    }
}

fn take_xs<T: DDS>(reader: &crate::dds::DataReader<T>, x_of: impl Fn(T) -> i32) -> Vec<i32> {
    let mut taken = Vec::new();
    while let Ok(Some(sample)) = reader.take() {
        taken.push(x_of(sample));
    }
    taken
}

fn shape_reader(
    p: &Arc<Participant>,
    policy: Option<TypeConsistencyEnforcement>,
    heard: &Arc<Heard>,
) -> crate::dds::DataReader<Shape> {
    p.topic::<Shape>("Square")
        .expect("topic")
        .reader()
        .qos(QoS {
            type_consistency: policy,
            ..QoS::best_effort().keep_last(16).data_representation_xcdr2()
        })
        .with_listener(heard.clone())
        .build()
        .expect("reader")
}

/// Two local readers of Square: A with the default policy, B forcing type
/// validation. The writer's type is unknown. A matches it (Sec.7.6.3.4.2
/// Step 2 passes without force_type_validation), B refuses it - and A takes
/// the samples it is matched for. The gate was per writer, participant-wide:
/// B's refusal starved A, matched and receiving nothing.
#[test]
fn a_reader_s_refusal_does_not_gate_another_reader_that_matched_the_writer() {
    let peer = peer_a();
    let forced = TypeConsistencyEnforcement {
        force_type_validation: true,
        ..TypeConsistencyEnforcement::default()
    };
    let (_domain, p) =
        participant_with_confirmed_peer("two_readers_policy", peer.sedp.participant_guid.prefix);
    let heard_a = Arc::new(Heard::default());
    let reader_a = shape_reader(&p, None, &heard_a);
    let heard_b = Arc::new(Heard::default());
    let reader_b = shape_reader(&p, Some(forced), &heard_b);
    fsm(&p).handle_sedp(peer.sedp.clone());
    let matched_a = settled_matched(&heard_a, 1);
    deliver_three(&p, peer.sedp.endpoint_guid);
    assert_eq!(
        (
            matched_a,
            take_xs(&reader_a, |s| s.0.x),
            heard_b.matched.load(Ordering::SeqCst),
            heard_b.inconsistent.load(Ordering::SeqCst),
            take_xs(&reader_b, |s| s.0.x),
        ),
        (1, vec![1, 2, 3], 0, 1, vec![]),
        "(A matched, A took, B matched, B inconsistent, B took)"
    );
}

/// A reader-side ShapeType whose `x` is a float64: not assignable from
/// peer A's ShapeType (int32 `x`, Table 15).
#[derive(Debug, Clone, PartialEq)]
struct ShapeX64(ShapeWire);

impl DDS for ShapeX64 {
    fn type_descriptor() -> &'static crate::core::types::TypeDescriptor {
        ShapeWire::type_descriptor()
    }

    fn encode(&self, buf: &mut [u8], version: crate::dds::CdrVersion) -> crate::dds::Result<usize> {
        self.0.encode(buf, version)
    }

    fn decode(buf: &[u8], version: crate::dds::CdrVersion) -> crate::dds::Result<Self> {
        ShapeWire::decode(buf, version).map(ShapeX64)
    }

    fn get_type_object() -> Option<CompleteTypeObject> {
        let mut x64 = shape_main_type_object();
        let CompleteTypeObject::Struct(ref mut shape) = x64 else {
            panic!("fixture: ShapeType is a struct");
        };
        let x = shape
            .member_seq
            .iter_mut()
            .find(|m| m.detail.name == "x")
            .expect("fixture: x");
        x.common.member_type_id = TypeIdentifier::TK_FLOAT64;
        Some(x64)
    }
}

/// Two local readers of Square with different types, the writer's type
/// known: shape_main's ShapeType accepts peer A's, the float64-`x` variant
/// refuses it. Each reader gets what its own verdict says: A matched and
/// delivered, B refused and delivered nothing.
#[test]
fn two_readers_of_different_types_on_one_topic_each_get_their_own_verdict() {
    let peer = peer_a();
    let (_domain, p) =
        participant_with_confirmed_peer("two_readers_types", peer.sedp.participant_guid.prefix);
    let heard_a = Arc::new(Heard::default());
    let reader_a = shape_reader(&p, None, &heard_a);
    let reader_b = p
        .topic::<ShapeX64>("Square")
        .expect("topic")
        .reader()
        .qos(QoS::best_effort().keep_last(16).data_representation_xcdr2())
        .build()
        .expect("reader B");
    let mut sedp = peer.sedp.clone();
    sedp.type_object = Some(peer.type_object.clone());
    fsm(&p).handle_sedp(sedp);
    let matched_a = settled_matched(&heard_a, 1);
    deliver_three(&p, peer.sedp.endpoint_guid);
    let reg = p.match_registry.as_ref().expect("match registry");
    assert!(
        reg.is_writer_refused_by_any(&peer.sedp.endpoint_guid.as_bytes()),
        "fixture: B refuses the writer"
    );
    assert_eq!(
        (
            matched_a,
            take_xs(&reader_a, |s| s.0.x),
            take_xs(&reader_b, |s| s.0.x)
        ),
        (1, vec![1, 2, 3], vec![]),
        "(A matched, A took, B took)"
    );
}

// ---------------------------------------------------------------------------
// A re-announcement keeps the type learned for the hash it announces again
// ---------------------------------------------------------------------------

/// A reader forcing type validation matches peer A's writer once a TypeLookup
/// answer resolves its type; the peer then announces the same writer again
/// (TypeInformation only, the same hash). The learned type is kept, the
/// writer stays matched and gated on, and its samples are taken. The
/// re-announcement must not overwrite the record: forgetting the type would
/// judge the writer again as of unknown type and gate it off while it is
/// still reported matched.
#[test]
fn a_reannounced_sedp_keeps_the_type_learned_for_its_hash() {
    let peer = peer_a();
    let forced = TypeConsistencyEnforcement {
        force_type_validation: true,
        ..TypeConsistencyEnforcement::default()
    };
    let (_domain, p) =
        participant_with_confirmed_peer("reannounce_same", peer.sedp.participant_guid.prefix);
    let heard = Arc::new(Heard::default());
    let reader = shape_reader(&p, Some(forced), &heard);
    let sedp = announcing(&peer.sedp, &peer.type_object);
    fsm(&p).handle_sedp(sedp.clone());
    let hash = peer
        .type_object
        .compute_equivalence_hash()
        .expect("hashable");
    fsm(&p).update_type_object_for_hash(&hash, peer.type_object.clone());
    assert_eq!(
        settled_matched(&heard, 1),
        1,
        "fixture: matched once the type is known"
    );

    fsm(&p).handle_sedp(sedp);

    let writer = peer.sedp.endpoint_guid;
    let kept = fsm(&p)
        .find_writers_for_topic("Square")
        .into_iter()
        .find(|w| w.endpoint_guid == writer)
        .expect("known")
        .type_object;
    let reg = p.match_registry.as_ref().expect("match registry");
    let gated = reg.is_writer_refused_by_any(&writer.as_bytes());
    let matched = settled_matched(&heard, 1);
    deliver_three(&p, writer);
    assert_eq!(
        (
            kept == Some(peer.type_object),
            gated,
            matched,
            take_xs(&reader, |s| s.0.x)
        ),
        (true, false, 1, vec![1, 2, 3]),
        "(type kept, gated, matched, taken)"
    );
}

/// A re-announcement naming ANOTHER hash is another type: the type learned
/// for the first hash is not carried over to it.
#[test]
fn a_reannounced_sedp_with_another_hash_starts_unresolved() {
    let peer = peer_a();
    let local_prefix = [0x01, 0x1a, 0x7e, 0x57, 0, 0, 0, 0, 0, 0, 0, 4];
    let fsm = DiscoveryFsm::new(GUID::new(local_prefix, RTPS_ENTITYID_PARTICIPANT), 30_000);
    fsm.handle_spdp(peer_spdp(peer.sedp.participant_guid.prefix));
    let sedp = announcing(&peer.sedp, &peer.type_object);
    fsm.handle_sedp(sedp.clone());
    let hash = peer
        .type_object
        .compute_equivalence_hash()
        .expect("hashable");
    assert_eq!(
        fsm.update_type_object_for_hash(&hash, peer.type_object.clone()),
        1
    );
    let type_now = |fsm: &DiscoveryFsm| {
        fsm.find_writers_for_topic("Square")
            .into_iter()
            .find(|w| w.endpoint_guid == peer.sedp.endpoint_guid)
            .expect("known")
            .type_object
    };

    fsm.handle_sedp(sedp);
    assert_eq!(
        type_now(&fsm),
        Some(peer.type_object.clone()),
        "same hash: kept"
    );

    fsm.handle_sedp(announcing(&peer.sedp, &incompatible_variant_of(&peer)));
    assert_eq!(
        type_now(&fsm),
        None,
        "another hash: not the first one's type"
    );
}

// ---------------------------------------------------------------------------
// A type learned is not a second discovery
// ---------------------------------------------------------------------------

/// Counts the discoveries of the remote writer `of` a listener hears.
struct DiscoveriesOf {
    of: GUID,
    heard: AtomicU32,
}

impl crate::core::discovery::multicast::DiscoveryListener for DiscoveriesOf {
    fn on_endpoint_discovered(&self, endpoint: crate::core::discovery::multicast::EndpointInfo) {
        if endpoint.endpoint_guid == self.of {
            self.heard.fetch_add(1, Ordering::SeqCst);
        }
    }
}

/// A remote writer whose type a TypeLookup answer resolves after its SEDP
/// surfaced is heard of ONCE by a discovery listener, whether the learned
/// type changes nothing for the local reader (default policy: matched at
/// discovery, still matched) or lifts its refusal (force_type_validation:
/// matched once the type is known). The answer must not surface the endpoint
/// again to listeners: that would report on_subscription_matched twice for
/// every foreign writer typed by TypeLookup, and a persistence bridge would
/// hear of the writer twice.
#[test]
fn a_type_lookup_answer_does_not_surface_the_endpoint_again() {
    let peer = peer_a();
    let forced = TypeConsistencyEnforcement {
        force_type_validation: true,
        ..TypeConsistencyEnforcement::default()
    };
    let mut outcomes = Vec::new();
    for policy in [None, Some(forced)] {
        let (_domain, p) =
            participant_with_confirmed_peer("surface_once", peer.sedp.participant_guid.prefix);
        let listener = Arc::new(DiscoveriesOf {
            of: peer.sedp.endpoint_guid,
            heard: AtomicU32::new(0),
        });
        fsm(&p).register_listener(listener.clone());
        let heard = Arc::new(Heard::default());
        let _reader = shape_reader(&p, policy.clone(), &heard);
        fsm(&p).handle_sedp(announcing(&peer.sedp, &peer.type_object));
        let after_sedp = listener.heard.load(Ordering::SeqCst);
        let hash = peer
            .type_object
            .compute_equivalence_hash()
            .expect("hashable");
        fsm(&p).update_type_object_for_hash(&hash, peer.type_object.clone());
        let matched = settled_matched(&heard, 1);
        outcomes.push((
            policy.is_some(),
            after_sedp,
            listener.heard.load(Ordering::SeqCst),
            matched,
        ));
    }
    assert_eq!(
        outcomes,
        vec![(false, 1, 1, 1), (true, 1, 1, 1)],
        "(forced, heard after SEDP, heard after the answer, matched)"
    );
}

// ---------------------------------------------------------------------------
// A Connext 7.7 writer announcing its type as a legacy v1 TypeObject
// ---------------------------------------------------------------------------

/// The real SEDP DATA(w) of a Connext 7.7 ShapeType writer (legacy v1
/// TypeObject only) and one of its real DATA payloads. A shape_main reader
/// matches that writer and takes the sample: the matched count and the
/// data-plane gate come from the same type verdict.
#[cfg(feature = "xtypes-structural-assignability")]
#[test]
fn a_connext_v1_shapetype_writer_is_matched_and_its_sample_is_taken() {
    use crate::xtypes::legacy_v1_test_vectors::{CONNEXT_SHAPETYPE_DATA, CONNEXT_SHAPETYPE_SEDP};
    let sedp =
        crate::protocol::discovery::parse_sedp_with_vendor(&CONNEXT_SHAPETYPE_SEDP, Some([1, 1]))
            .expect("fixture: the captured SEDP parses");
    assert!(
        sedp.type_object_legacy_v1 && sedp.type_information.is_none(),
        "fixture: the type arrives as a legacy v1 TypeObject only"
    );
    let writer = sedp.endpoint_guid;
    let (_domain, p) = participant_with_confirmed_peer("connext_v1_shape", writer.prefix);
    let heard = Arc::new(Heard::default());
    let reader = shape_reader(&p, None, &heard);
    fsm(&p).handle_sedp(sedp);
    let matched = settled_matched(&heard, 1);

    let registry = p.registry.as_ref().expect("registry");
    registry.register_writer_guid(writer.as_bytes(), "Square".to_string());
    registry.register_writer_ownership_kind(
        writer.as_bytes(),
        crate::qos::ownership::OwnershipKind::Shared,
    );
    // The router hands the reader the payload behind its encapsulation
    // header (D_CDR2_LE).
    registry
        .get_topic("Square")
        .expect("the reader's topic")
        .deliver_with_writer(
            writer.as_bytes(),
            31,
            &CONNEXT_SHAPETYPE_DATA[4..],
            crate::dds::CdrVersion::Xcdr2,
        );
    assert_eq!(
        (
            matched,
            heard.inconsistent.load(Ordering::SeqCst),
            take_xs(&reader, |s| s.0.x),
        ),
        (1, 0, vec![79]),
        "(matched, inconsistent, taken x)"
    );
}
