// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! DDS-XTypes v1.3 7.3.4: a Complete TypeObject references a nested type by
//! its `EK_COMPLETE` TypeIdentifier, a Minimal one by its `EK_MINIMAL`
//! TypeIdentifier, and a member's flags (here: `@key`) are carried on both
//! representations. The ROS 2 TypeObject builder (`xtypes/builder/ros.rs`)
//! must not pick the Minimal identifier for a nested member inside the
//! Complete TypeObject, nor share one `CommonStructMember` (hence one
//! `TypeIdentifier`) between both representations, and it reads `@key`
//! off the introspection object.
//!
//! This is the real wire path for a ROS 2 type registered through
//! `rmw_hdds`: nothing rewrites a ROS `TypeObjectHandle`'s `complete` field
//! into a separate spec-correct `complete_wire` form the way the native
//! HDDS-generated-type registration path does
//! (`dds/participant/xtypes.rs::build_served_handle`), so whatever
//! `TypeObjectBuilder::from_ros_type_support` puts in `complete` is exactly
//! what a peer's TypeLookup request receives.
//!
//! Fixtures use the Jazzy-shaped introspection structs (the layout that can
//! express `@key`), laid out byte-for-byte like
//! `ros_introspection_layout.rs`'s mirrors: `is_key_` then `is_array_` then
//! `array_size_`, so the crate's own (pre-Jazzy-shaped) struct definitions
//! read them correctly only through `RosIntrospectionLayout::WithKeyFields`.

#![cfg(feature = "xtypes")]

use hdds::core::types::Distro;
use hdds::xtypes::{
    rosidl_message_type_support_t, rosidl_typesupport_introspection_c__MessageMember,
    rosidl_typesupport_introspection_c__MessageMembers, CompleteTypeObject, MemberFlag,
    MinimalTypeObject, TypeObjectBuilder,
};
use std::ffi::{c_void, CString};

#[repr(C)]
struct JazzyMessageMember {
    name_: *const std::os::raw::c_char,
    type_id_: u8,
    string_upper_bound_: usize,
    members_: *const rosidl_message_type_support_t,
    is_key_: bool,
    is_array_: bool,
    array_size_: usize,
    is_upper_bound_: bool,
    offset_: u32,
    default_value_: *const c_void,
    size_function: Option<unsafe extern "C" fn(*const c_void) -> usize>,
    get_const_function: Option<unsafe extern "C" fn(*const c_void, usize) -> *const c_void>,
    get_function: Option<unsafe extern "C" fn(*mut c_void, usize) -> *mut c_void>,
    fetch_function: Option<unsafe extern "C" fn(*const c_void, usize, *mut c_void)>,
    assign_function: Option<unsafe extern "C" fn(*mut c_void, usize, *const c_void)>,
    resize_function: Option<unsafe extern "C" fn(*mut c_void, usize) -> bool>,
}

#[repr(C)]
struct JazzyMessageMembers {
    message_namespace_: *const std::os::raw::c_char,
    message_name_: *const std::os::raw::c_char,
    member_count_: u32,
    size_of_: usize,
    has_any_key_member_: bool,
    _pad: [u8; std::mem::align_of::<*const c_void>() - 1],
    members_: *const JazzyMessageMember,
    init_function: Option<unsafe extern "C" fn(*mut c_void, i32)>,
    fini_function: Option<unsafe extern "C" fn(*mut c_void)>,
}

const ROS_TYPE_INT32: u8 = 13;
const ROS_TYPE_MESSAGE: u8 = 18;

fn leaf_member(type_id: u8, is_key: bool) -> JazzyMessageMember {
    JazzyMessageMember {
        name_: std::ptr::null(),
        type_id_: type_id,
        string_upper_bound_: 0,
        members_: std::ptr::null(),
        is_key_: is_key,
        is_array_: false,
        array_size_: 0,
        is_upper_bound_: false,
        offset_: 0,
        default_value_: std::ptr::null(),
        size_function: None,
        get_const_function: None,
        get_function: None,
        fetch_function: None,
        assign_function: None,
        resize_function: None,
    }
}

fn members_of(
    member: &JazzyMessageMember,
    namespace: &CString,
    name: &CString,
) -> JazzyMessageMembers {
    JazzyMessageMembers {
        message_namespace_: namespace.as_ptr(),
        message_name_: name.as_ptr(),
        member_count_: 1,
        size_of_: 8,
        has_any_key_member_: true,
        _pad: [0u8; std::mem::align_of::<*const c_void>() - 1],
        members_: std::ptr::from_ref(member),
        init_function: None,
        fini_function: None,
    }
}

fn type_support_for(members: &JazzyMessageMembers) -> rosidl_message_type_support_t {
    rosidl_message_type_support_t {
        typesupport_identifier: std::ptr::null(),
        data: std::ptr::from_ref(members).cast(),
        func: None,
        get_type_hash_func: None,
        get_type_description_func: None,
        get_type_description_sources_func: None,
    }
}

/// Sanity check: the crate's own (pre-Jazzy-shaped) struct must read these
/// Jazzy-shaped fixtures as `@key`-capable, exactly the precondition
/// `ros_introspection_layout.rs` establishes for the layout-detection code.
/// Restated here so a change to either fixture shape is caught locally
/// instead of only failing a distant assertion below.
#[test]
fn fixture_member_is_byte_compatible_with_the_crate_struct() {
    assert_eq!(
        std::mem::offset_of!(JazzyMessageMember, is_key_),
        std::mem::offset_of!(rosidl_typesupport_introspection_c__MessageMember, is_array_),
    );
    assert_eq!(
        std::mem::offset_of!(JazzyMessageMember, array_size_),
        std::mem::offset_of!(
            rosidl_typesupport_introspection_c__MessageMember,
            array_size_
        ),
    );
    assert_eq!(
        std::mem::offset_of!(JazzyMessageMembers, members_),
        std::mem::offset_of!(rosidl_typesupport_introspection_c__MessageMembers, members_)
            + std::mem::align_of::<*const c_void>(),
    );
}

/// DDS-XTypes v1.3 7.3.4: a struct's Complete TypeObject references a
/// nested type's EK_COMPLETE identifier; its Minimal TypeObject references
/// the SAME nested type's EK_MINIMAL identifier. The two member identifiers
/// must therefore differ from each other, and each must match the nested
/// type's own identifier of the matching kind.
///
/// Mutant: revert `ros.rs`'s `ensure_ros_struct_ids` call to take only the
/// minimal half of the pair for both representations (the bug this test
/// pins) and this test fails on the first assertion, because the Complete
/// member would then carry the EK_MINIMAL identifier.
#[test]
fn complete_struct_references_nested_member_by_its_complete_identifier() {
    let inner_ns = CString::new("geometry_msgs__msg").expect("no NUL");
    let inner_name = CString::new("Point32").expect("no NUL");
    let inner_member = leaf_member(ROS_TYPE_INT32, false);
    let inner_members = members_of(&inner_member, &inner_ns, &inner_name);
    let inner_ts = type_support_for(&inner_members);

    let mut outer_member = leaf_member(ROS_TYPE_MESSAGE, false);
    outer_member.members_ = std::ptr::from_ref(&inner_ts);
    let outer_ns = CString::new("geometry_msgs__msg").expect("no NUL");
    let outer_name = CString::new("PointStamped").expect("no NUL");
    let outer_members = members_of(&outer_member, &outer_ns, &outer_name);
    let outer_ts = type_support_for(&outer_members);

    // SAFETY: both type supports point at live, Jazzy-shaped introspection
    // objects for the whole call, and `inner_ts` outlives the call that
    // reads it through `outer_member.members_`.
    let outer_handle =
        unsafe { TypeObjectBuilder::from_ros_type_support(Distro::Jazzy, &outer_ts) }
            .expect("outer struct builds");

    // Build the inner type again, from an independent builder instance, to
    // get its ground-truth (complete, minimal) identifiers: determinism of
    // `compute_equivalence_hash` over the same structural content is exactly
    // what a receiver relies on to recognize the same type from two
    // different peers, so this is a legitimate oracle, not a tautology.
    let inner_handle =
        unsafe { TypeObjectBuilder::from_ros_type_support(Distro::Jazzy, &inner_ts) }
            .expect("inner struct builds");

    let CompleteTypeObject::Struct(outer_complete) = &outer_handle.complete else {
        panic!("expected a Complete struct TypeObject");
    };
    let MinimalTypeObject::Struct(outer_minimal) = &outer_handle.minimal else {
        panic!("expected a Minimal struct TypeObject");
    };
    assert_eq!(outer_complete.member_seq.len(), 1);
    assert_eq!(outer_minimal.member_seq.len(), 1);

    let complete_member_type = &outer_complete.member_seq[0].common.member_type_id;
    let minimal_member_type = &outer_minimal.member_seq[0].common.member_type_id;

    assert_eq!(
        complete_member_type, &inner_handle.type_id_complete,
        "Complete TypeObject must reference the nested member by its EK_COMPLETE identifier"
    );
    assert_eq!(
        minimal_member_type, &inner_handle.type_id_minimal,
        "Minimal TypeObject must reference the nested member by its EK_MINIMAL identifier"
    );
    assert_ne!(
        complete_member_type, minimal_member_type,
        "Complete and Minimal must not reference the nested member with the same identifier"
    );
    assert_ne!(
        &outer_handle.type_id_complete, &outer_handle.type_id_minimal,
        "the outer struct's own Complete/Minimal identifiers must differ now that their \
         member_seq content differs"
    );
}

/// DDS-XTypes v1.3 7.3.4 / rosidl: ROS 2 Jazzy's only member property is
/// `@key`; it must reach `MemberFlag::IS_KEY` on both the Complete and the
/// Minimal member, never only one side and never silently dropped.
///
/// Mutant: delete the `layout.member_is_key(..)` call this test exists for
/// (restoring `MemberFlag::empty()` always) and this test fails.
#[test]
fn ros_key_member_sets_is_key_on_both_representations() {
    let ns = CString::new("sensor_msgs__msg").expect("no NUL");
    let name = CString::new("BatteryCell").expect("no NUL");
    let member = leaf_member(ROS_TYPE_INT32, true); // @key
    let members = members_of(&member, &ns, &name);
    let ts = type_support_for(&members);

    let handle = unsafe { TypeObjectBuilder::from_ros_type_support(Distro::Jazzy, &ts) }
        .expect("struct builds");

    let CompleteTypeObject::Struct(complete) = &handle.complete else {
        panic!("expected a Complete struct TypeObject");
    };
    let MinimalTypeObject::Struct(minimal) = &handle.minimal else {
        panic!("expected a Minimal struct TypeObject");
    };

    assert_eq!(complete.member_seq[0].common.member_flags.0, 0x0031);
    assert_eq!(minimal.member_seq[0].common.member_flags.0, 0x0031);
}

/// XTypes 1.3 7.2.2.7: the implicit TryConstruct is DISCARD (01),
/// including on a non-key member.
#[test]
fn ros_non_key_member_uses_default_discard() {
    let ns = CString::new("sensor_msgs__msg").expect("no NUL");
    let name = CString::new("Temperature").expect("no NUL");
    let member = leaf_member(ROS_TYPE_INT32, false);
    let members = members_of(&member, &ns, &name);
    let ts = type_support_for(&members);

    let handle = unsafe { TypeObjectBuilder::from_ros_type_support(Distro::Jazzy, &ts) }
        .expect("struct builds");

    let CompleteTypeObject::Struct(complete) = &handle.complete else {
        panic!("expected a Complete struct TypeObject");
    };
    let MinimalTypeObject::Struct(minimal) = &handle.minimal else {
        panic!("expected a Minimal struct TypeObject");
    };
    assert_eq!(minimal.member_seq[0].common.member_flags.0, 0x0001);
    assert_eq!(
        complete.member_seq[0].common.member_flags,
        MemberFlag::TRY_CONSTRUCT1,
        "the default TryConstruct is DISCARD"
    );
}

/// XTypes 1.3 7.3.4.1 / 7.3.4.6: an anonymous collection carries its
/// bound and element identifier directly, with the element's equivalence.
#[test]
fn ros_nested_collections_preserve_both_dependency_kinds() {
    use hdds::xtypes::{
        CollectionElementFlag, EquivalenceKind, PlainArrayLElemDefn, PlainArraySElemDefn,
        PlainCollectionHeader, PlainSequenceLElemDefn, PlainSequenceSElemDefn, TypeIdentifier,
    };
    let ns = CString::new("test_msgs__msg").expect("namespace");
    let inner_name = CString::new("Inner").expect("name");
    let outer_name = CString::new("Outer").expect("name");
    let inner_member = leaf_member(ROS_TYPE_INT32, false);
    let inner_members = members_of(&inner_member, &ns, &inner_name);
    let inner_ts = type_support_for(&inner_members);
    let inner = unsafe { TypeObjectBuilder::from_ros_type_support(Distro::Jazzy, &inner_ts) }
        .expect("inner");
    for (size, upper_bound) in [
        (3, false),
        (256, false),
        (255, true),
        (256, true),
        (0, false),
    ] {
        let mut member = leaf_member(ROS_TYPE_MESSAGE, false);
        member.members_ = &inner_ts;
        member.is_array_ = true;
        member.array_size_ = size;
        member.is_upper_bound_ = upper_bound;
        let members = members_of(&member, &ns, &outer_name);
        let ts = type_support_for(&members);
        let handle =
            unsafe { TypeObjectBuilder::from_ros_type_support(Distro::Jazzy, &ts) }.expect("outer");
        let CompleteTypeObject::Struct(c) = &handle.complete else {
            panic!("struct");
        };
        let MinimalTypeObject::Struct(m) = &handle.minimal else {
            panic!("struct");
        };
        for (actual, element, kind) in [
            (
                &c.member_seq[0].common.member_type_id,
                &inner.type_id_complete,
                EquivalenceKind::Complete,
            ),
            (
                &m.member_seq[0].common.member_type_id,
                &inner.type_id_minimal,
                EquivalenceKind::Minimal,
            ),
        ] {
            let header = PlainCollectionHeader {
                equiv_kind: kind,
                element_flags: CollectionElementFlag::TRY_CONSTRUCT1,
            };
            let expected = if size > 0 && !upper_bound {
                if let Ok(bound) = u8::try_from(size) {
                    TypeIdentifier::PlainArraySmall(PlainArraySElemDefn {
                        header,
                        array_bound_seq: vec![bound],
                        element_identifier: Box::new(element.clone()),
                    })
                } else {
                    TypeIdentifier::PlainArrayLarge(PlainArrayLElemDefn {
                        header,
                        array_bound_seq: vec![u32::try_from(size).expect("bound")],
                        element_identifier: Box::new(element.clone()),
                    })
                }
            } else if let Ok(bound) = u8::try_from(size) {
                TypeIdentifier::PlainSequenceSmall(PlainSequenceSElemDefn {
                    header,
                    bound,
                    element_identifier: Box::new(element.clone()),
                })
            } else {
                TypeIdentifier::PlainSequenceLarge(PlainSequenceLElemDefn {
                    header,
                    bound: u32::try_from(size).expect("bound"),
                    element_identifier: Box::new(element.clone()),
                })
            };
            assert_eq!(*actual, expected);
        }
    }
}

/// Independent hash oracle from XTypes 1.3 Annex B and 7.3.4.5:
/// Minimal struct { int32 x; }, no base, FINAL, default DISCARD.
/// Offsets in the hand-serialized outer TypeObject (no encapsulation):
/// 0: DHEADER=35; 4: EK_MINIMAL=f1; 5: TK_STRUCTURE=51; 6: FINAL=1;
/// 8: MinimalStructHeader DHEADER=1; 12: TK_NONE; 13..16: padding;
/// 16: member sequence DHEADER=19; 20: count=1; 24: member DHEADER=11;
/// 28: id=0; 32: flags=1; 34: TK_INT32=04;
/// 35: NameHash=MD5("x")[0..4]=9d d4 e4 61.
/// Python hashlib (independent of HDDS) gives the fixed digest below:
/// hashlib.md5(bytes.fromhex("23000000f1510100010000000000000013000000010000000b000000000000000100049dd4e461")).hexdigest()
#[test]
fn ros_minimal_identifier_matches_hand_serialized_xcdr2_hash() {
    use hdds::xtypes::{EquivalenceHash, TypeIdentifier};
    let ns = CString::new("test_msgs__msg").expect("namespace");
    let name = CString::new("Tiny").expect("name");
    let mut member = leaf_member(ROS_TYPE_INT32, false);
    member.name_ = c"x".as_ptr();
    let members = members_of(&member, &ns, &name);
    let ts = type_support_for(&members);
    let handle =
        unsafe { TypeObjectBuilder::from_ros_type_support(Distro::Jazzy, &ts) }.expect("struct");
    assert_eq!(
        handle.type_id_minimal,
        TypeIdentifier::minimal(EquivalenceHash::from_bytes([
            0xc7, 0x3b, 0x47, 0x0c, 0xaa, 0xfd, 0xb6, 0x05, 0xb2, 0x96, 0x42, 0x58, 0x93, 0xc0
        ]))
    );
}

/// RIHS01 is rosidl's SHA-256 type-description hash, independent of the
/// XTypes TypeObject hashes (ROS REP-2011). Copy it without reinterpretation.
#[test]
fn ros_rihs01_is_preserved_for_keys_and_nested_collections() {
    use hdds::xtypes::rosidl_type_hash_t;
    static RIHS01: rosidl_type_hash_t = rosidl_type_hash_t {
        version: 1,
        value: [0xa5; 32],
    };
    unsafe extern "C" fn hash(
        _: *const rosidl_message_type_support_t,
    ) -> *const rosidl_type_hash_t {
        &RIHS01
    }
    let ns = CString::new("test_msgs__msg").expect("namespace");
    let name = CString::new("Inner").expect("name");
    let inner_member = leaf_member(ROS_TYPE_INT32, true);
    let inner_members = members_of(&inner_member, &ns, &name);
    let mut inner_ts = type_support_for(&inner_members);
    inner_ts.get_type_hash_func = Some(hash);
    let mut member = leaf_member(ROS_TYPE_MESSAGE, true);
    member.members_ = &inner_ts;
    member.is_array_ = true;
    let outer_name = CString::new("Outer").expect("name");
    let members = members_of(&member, &ns, &outer_name);
    let mut ts = type_support_for(&members);
    ts.get_type_hash_func = Some(hash);
    for ts in [&inner_ts, &ts] {
        let handle =
            unsafe { TypeObjectBuilder::from_ros_type_support(Distro::Jazzy, ts) }.expect("type");
        assert_eq!(handle.ros_hash_version, 1);
        assert_eq!(*handle.ros_hash, RIHS01.value);
    }
}

/// The foreign corpus declares @final struct InnerL { long x; }. Feeding
/// the same declaration through ROS introspection must reproduce both of
/// Cyclone DDS 0.11 idlc's TypeObjects, including their independent hashes.
#[test]
fn ros_builder_matches_cyclone_complete_and_minimal_oracle() {
    use hdds::xtypes::{EquivalenceHash, TypeIdentifier};
    use hdds::Cdr2Encode;

    fn wire(ek: u8, object: &impl Cdr2Encode) -> Vec<u8> {
        let mut bytes = vec![0; 5 + object.max_cdr2_size()];
        bytes[4] = ek;
        let mut offset = 5;
        object
            .encode_cdr2_le_at(&mut bytes, &mut offset)
            .expect("encode");
        bytes[..4].copy_from_slice(&u32::try_from(offset - 4).expect("size").to_le_bytes());
        bytes.truncate(offset);
        bytes
    }
    fn unhex(value: &str) -> Vec<u8> {
        (0..value.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&value[i..i + 2], 16).expect("fixture hex"))
            .collect()
    }
    let ns = CString::new("").expect("namespace");
    let name = CString::new("InnerL").expect("name");
    let mut member = leaf_member(ROS_TYPE_INT32, false);
    member.name_ = c"x".as_ptr();
    let members = members_of(&member, &ns, &name);
    let ts = type_support_for(&members);
    let handle =
        unsafe { TypeObjectBuilder::from_ros_type_support(Distro::Jazzy, &ts) }.expect("type");
    let oracle = include_str!("golden/typeobject/cyclone-0.11-typeobjects.txt");
    for (kind, actual_id, actual_wire) in [
        ("C", &handle.type_id_complete, wire(0xf2, &handle.complete)),
        ("M", &handle.type_id_minimal, wire(0xf1, &handle.minimal)),
    ] {
        let prefix = format!("InnerL {kind} ");
        let row: Vec<_> = oracle
            .lines()
            .find(|row| row.starts_with(&prefix))
            .expect("Cyclone InnerL fixture")
            .split_whitespace()
            .collect();
        assert_eq!(actual_wire, unhex(row[3]), "{kind} XCDR2 bytes");
        let hash = EquivalenceHash::from_bytes(unhex(row[2]).try_into().expect("14 bytes"));
        let expected = if kind == "C" {
            TypeIdentifier::complete(hash)
        } else {
            TypeIdentifier::minimal(hash)
        };
        assert_eq!(*actual_id, expected, "{kind} independent TypeIdentifier");
    }
}
