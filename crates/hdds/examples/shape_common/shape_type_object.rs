// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

// The TypeObject `shape_main` announces for its ShapeType, written ONCE.
//
// Included verbatim by `examples/shape_main.rs` (`ShapeType::get_type_object`)
// and by the library's type-verdict tests, so the type those tests judge
// against a peer's announcement is the type the application announces, not a
// copy that can drift from it. Written with unqualified names: each includer
// brings the `xtypes` items into scope (`hdds::xtypes::*` in the example,
// `crate::xtypes::*` in the library). Plain comments only - an included
// fragment cannot carry inner doc comments.
//
//   @appendable
//   struct ShapeType {
//     @key string<128> color;
//     int32 x;
//     int32 y;
//     int32 shapesize;
//     sequence<uint8> additional_payload_size;
//   };
//
// `color` is `TypeIdentifier::string(128)`, TI_STRING8_SMALL with the IDL
// bound (DDS-XTypes 1.3 7.3.4.4). An earlier form wrote
// it with the inert `TypeIdentifier::TK_STRING8`, a bare 0x20 that is a
// TypeKind and not a TypeIdentifier discriminator: HDDS's own decoder refused
// it, so every SEDP announcement of ShapeType went out without
// PID_TYPE_OBJECT and PID_TYPE_INFORMATION, HDDS to HDDS included, with an
// `[SEDP] TypeObject decode failed` error on every run. That form is gone
// rather than kept behind a switch: an object the specification's decoder
// refuses must not be one this tree can build.
//
// `additional_payload_size` is a `sequence<uint8>`, which is what the encoder
// writes (a u32 length and the octets). It was announced as a bare `uint8`
// in an earlier form: a peer that resolved this type through TypeLookup, or an
// HDDS reader resolving a peer's, compared a sequence with a primitive, which
// DDS-XTypes v1.3 Sec.7.2.4.4.4 Table 15 makes not assignable, and refused a
// type that is the same IDL on both sides.

// The specification's TypeObject for the IDL above (DDS-XTypes 1.3):
// - `color` is `TypeIdentifier::string(128)`, TI_STRING8_SMALL with its bound
//   (7.3.4.4), not the inert bare TK_STRING8;
// - every member carries TRY_CONSTRUCT1, the default TryConstruct behavior
//   DISCARD (7.2.2.7; Annex B MemberFlag: "00 = INVALID, 01 = DISCARD", spec
//   text line 12325), and the key member also carries IS_MUST_UNDERSTAND:
//   "Key members shall never be optional, and they shall always have their
//   'must understand' attribute set to true" (7.2.2.4.4.4.8, spec text line
//   2367).
// `tests/typeobject_oracle.rs` pins this object byte for byte, and its two
// hashes, against the Complete and Minimal objects written there by hand
// from Annex B, pins the variant whose `color` carries no bound the same
// way, and round-trips the object through the encoder and the decoder.
pub(crate) fn shape_type_object() -> CompleteTypeObject {
    let member = |member_id, member_flags, member_type_id, name: &str| CompleteStructMember {
        common: CommonStructMember {
            member_id,
            member_flags,
            member_type_id,
        },
        detail: CompleteMemberDetail::new(name),
    };
    let discard = MemberFlag::TRY_CONSTRUCT1;
    let key = MemberFlag(
        MemberFlag::IS_KEY.0 | MemberFlag::IS_MUST_UNDERSTAND.0 | MemberFlag::TRY_CONSTRUCT1.0,
    );
    let octets = TypeIdentifier::PlainSequenceSmall(PlainSequenceSElemDefn {
        header: PlainCollectionHeader {
            equiv_kind: EquivalenceKind::Both,
            element_flags: CollectionElementFlag::TRY_CONSTRUCT1,
        },
        bound: 0,
        element_identifier: Box::new(TypeIdentifier::TK_UINT8),
    });
    CompleteTypeObject::Struct(CompleteStructType {
        struct_flags: StructTypeFlag::IS_APPENDABLE,
        header: CompleteStructHeader {
            base_type: None,
            detail: CompleteTypeDetail::new("ShapeType"),
        },
        member_seq: vec![
            member(0, key, TypeIdentifier::string(128), "color"),
            member(1, discard, TypeIdentifier::TK_INT32, "x"),
            member(2, discard, TypeIdentifier::TK_INT32, "y"),
            member(3, discard, TypeIdentifier::TK_INT32, "shapesize"),
            member(4, discard, octets, "additional_payload_size"),
        ],
    })
}
