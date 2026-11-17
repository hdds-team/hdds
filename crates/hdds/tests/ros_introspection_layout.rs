// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! ROS 2 Jazzy moved the introspection struct fields; the walker must follow.
//!
//! Jazzy added `@key` support to `rosidl_typesupport_introspection_c` and
//! inserted two `bool` members into the C structs:
//!
//! ```text
//! MessageMember   ... members_, [is_key_,] is_array_, array_size_, ...
//! MessageMembers  ... size_of_, [has_any_key_member_,] members_, init_, fini_
//! ```
//!
//! Reading a Jazzy struct with the pre-Jazzy layout walks a garbage `members_`
//! pointer: every ROS 2 node on Jazzy would segfault in
//! `build_struct_members_from_ros` while registering the `/rosout` publisher's
//! type.
//!
//! The layout is DETECTED from the object, never guessed from a distro name:
//! the slot the pre-Jazzy layout calls `members_` holds `has_any_key_member_`
//! plus padding on Jazzy, which reads back as a value no member array pointer
//! can have. That is what makes an ungated distro (Kilted, Rolling, whatever
//! comes next) safe instead of a jump through an out-of-bounds pointer read.

#![cfg(feature = "xtypes")]

use hdds::core::types::Distro;
use hdds::xtypes::builder::{
    resolve_ros_introspection_layout_from_env, rosidl_typesupport_introspection_c__MessageMember,
    rosidl_typesupport_introspection_c__MessageMembers, RosIntrospectionLayout,
};
use std::mem::offset_of;

/// The Jazzy-shaped C structs, written out by hand exactly as
/// `message_introspection.h` declares them on Jazzy. The accessors under test
/// have to read THESE correctly while the crate declares the pre-Jazzy shape.
#[repr(C)]
struct JazzyMessageMember {
    name_: *const std::os::raw::c_char,
    type_id_: u8,
    string_upper_bound_: usize,
    members_: *const std::ffi::c_void,
    is_key_: bool,
    is_array_: bool,
    array_size_: usize,
    is_upper_bound_: bool,
    offset_: u32,
    default_value_: *const std::ffi::c_void,
    size_function: Option<unsafe extern "C" fn(*const std::ffi::c_void) -> usize>,
    get_const_function:
        Option<unsafe extern "C" fn(*const std::ffi::c_void, usize) -> *const std::ffi::c_void>,
    get_function:
        Option<unsafe extern "C" fn(*mut std::ffi::c_void, usize) -> *mut std::ffi::c_void>,
    fetch_function:
        Option<unsafe extern "C" fn(*const std::ffi::c_void, usize, *mut std::ffi::c_void)>,
    assign_function:
        Option<unsafe extern "C" fn(*mut std::ffi::c_void, usize, *const std::ffi::c_void)>,
    resize_function: Option<unsafe extern "C" fn(*mut std::ffi::c_void, usize) -> bool>,
}

#[repr(C)]
struct JazzyMessageMembers {
    message_namespace_: *const std::os::raw::c_char,
    message_name_: *const std::os::raw::c_char,
    member_count_: u32,
    size_of_: usize,
    has_any_key_member_: bool,
    /// The padding between `has_any_key_member_` and the pointer-aligned
    /// `members_`, made EXPLICIT so the fixture can zero it.
    ///
    /// It is not cosmetic. `RosIntrospectionLayout::detect` reads this whole
    /// slot as one `usize` and decides the layout from the value, so those
    /// bytes are load-bearing input, not slack. A Rust struct literal leaves
    /// implicit padding uninitialised: MemorySanitizer reports the read as
    /// use-of-uninitialised-value, and the assertion below rides on whatever
    /// the stack happened to hold - it passes only while the garbage stays
    /// small. A real Jazzy typesupport object is a C `static`, whose padding
    /// every mainstream toolchain emits as zero, so zeroing here models the
    /// object under test instead of the stack under the test.
    _pad: [u8; std::mem::align_of::<*const std::ffi::c_void>() - 1],
    members_: *const JazzyMessageMember,
    init_function: Option<unsafe extern "C" fn(*mut std::ffi::c_void, i32)>,
    fini_function: Option<unsafe extern "C" fn(*mut std::ffi::c_void)>,
}

unsafe extern "C" fn dummy_fini(_: *mut std::ffi::c_void) {}
unsafe extern "C" fn dummy_init(_: *mut std::ffi::c_void, _: i32) {}

/// A single-member Jazzy message: `is_key_` SET and `is_array_` CLEAR, so a
/// reader that forgets the one-byte shift answers the opposite of the truth
/// for both flags. A fixture with both flags set would pass either way.
fn jazzy_member() -> JazzyMessageMember {
    JazzyMessageMember {
        name_: std::ptr::null(),
        type_id_: 4,
        string_upper_bound_: 0,
        members_: std::ptr::null(),
        is_key_: true,    // set, and it must NOT be mistaken for is_array_
        is_array_: false, // clear, and the pre-Jazzy offset must not be read for it
        array_size_: 7,
        is_upper_bound_: false,
        offset_: 16,
        default_value_: std::ptr::null(),
        size_function: None,
        get_const_function: None,
        get_function: None,
        fetch_function: None,
        assign_function: None,
        resize_function: None,
    }
}

fn jazzy_members(member: &JazzyMessageMember) -> JazzyMessageMembers {
    JazzyMessageMembers {
        message_namespace_: std::ptr::null(),
        message_name_: std::ptr::null(),
        member_count_: 1,
        size_of_: 32,
        has_any_key_member_: true,
        _pad: [0u8; std::mem::align_of::<*const std::ffi::c_void>() - 1],
        members_: std::ptr::from_ref(member),
        init_function: None,
        fini_function: Some(dummy_fini),
    }
}

fn as_mirror(
    members: &JazzyMessageMembers,
) -> *const rosidl_typesupport_introspection_c__MessageMembers {
    std::ptr::from_ref(members).cast()
}

#[test]
fn the_offsets_the_layout_rests_on() {
    // is_key_ lands exactly where the pre-Jazzy layout put is_array_, and
    // everything from array_size_ on is unmoved.
    assert_eq!(
        offset_of!(JazzyMessageMember, is_key_),
        offset_of!(rosidl_typesupport_introspection_c__MessageMember, is_array_),
        "is_key_ must occupy the byte the pre-Jazzy layout used for is_array_"
    );
    assert_eq!(
        offset_of!(JazzyMessageMember, array_size_),
        offset_of!(
            rosidl_typesupport_introspection_c__MessageMember,
            array_size_
        ),
        "array_size_ and everything after it must be unmoved"
    );
    // The tail shift is ONE POINTER ALIGNMENT, not the literal 8: on a 32-bit
    // target `bool has_any_key_member_` plus padding is 4 bytes, not 8.
    assert_eq!(
        offset_of!(JazzyMessageMembers, members_),
        offset_of!(rosidl_typesupport_introspection_c__MessageMembers, members_)
            + std::mem::align_of::<*const std::ffi::c_void>(),
        "MessageMembers.members_ shifts by exactly one pointer alignment on Jazzy"
    );
}

#[test]
fn jazzy_layout_is_read_at_the_right_offsets() {
    let member = jazzy_member();
    let members = jazzy_members(&member);
    let mirror = as_mirror(&members);
    let layout = RosIntrospectionLayout::WithKeyFields;

    // Read the Jazzy objects THROUGH the crate's pre-Jazzy-shaped mirror.
    assert_eq!(unsafe { (*mirror).member_count_ }, 1);
    assert_eq!(unsafe { (*mirror).size_of_ }, 32);
    assert_eq!(
        unsafe { layout.members(mirror) }.cast::<JazzyMessageMember>(),
        std::ptr::from_ref(&member),
        "members() must skip has_any_key_member_; the declared field holds padding"
    );
    assert!(
        unsafe { layout.fini_fn(mirror) }.is_some(),
        "fini_fn() must skip has_any_key_member_ too"
    );
    assert!(unsafe { layout.init_fn(mirror) }.is_none());

    let member_mirror = unsafe { layout.members(mirror) };
    assert_eq!(unsafe { (*member_mirror).type_id_ }, 4);
    assert_eq!(unsafe { (*member_mirror).array_size_ }, 7);
    assert_eq!(unsafe { (*member_mirror).offset_ }, 16);
    assert!(
        !unsafe { layout.member_is_array(member_mirror) },
        "is_array is CLEAR on this member: reading the pre-Jazzy offset returns is_key_ = true"
    );
    assert!(
        unsafe { layout.member_is_key(member_mirror) },
        "is_key is SET on this member and lives at the pre-Jazzy is_array_ offset"
    );

    // The discrimination this fixture exists for: a layout-blind read - the
    // pre-Jazzy offsets, which a walker that guessed the layout would use -
    // answers the OPPOSITE for both flags on the same bytes. A fixture with
    // is_key_ and is_array_ both set would pass either way and prove nothing.
    let blind = RosIntrospectionLayout::PreJazzy;
    assert!(
        unsafe { blind.member_is_array(member_mirror) },
        "the pre-Jazzy offset holds is_key_ on a Jazzy member: reading it as is_array_ inverts it"
    );
    assert!(!unsafe { blind.member_is_key(member_mirror) });
}

/// The layout must come out of the object, with no distro name, no
/// environment variable and no process-global involved. This is what makes an
/// ungated distro safe.
#[test]
fn the_layout_is_detected_from_the_object_not_from_a_distro_name() {
    let member = jazzy_member();
    let members = jazzy_members(&member);

    assert_eq!(
        unsafe { RosIntrospectionLayout::detect(as_mirror(&members)) },
        Some(RosIntrospectionLayout::WithKeyFields),
        "a Jazzy object holds has_any_key_member_ where the pre-Jazzy layout holds members_"
    );
    // Even told the wrong thing, the object wins.
    assert_eq!(
        unsafe {
            RosIntrospectionLayout::resolve_for(
                as_mirror(&members),
                RosIntrospectionLayout::PreJazzy,
            )
        },
        RosIntrospectionLayout::WithKeyFields,
        "a PreJazzy hint must not override what the object says"
    );

    // And the other direction: a pre-Jazzy object is never mistaken for a
    // Jazzy one, even when the hint says Jazzy.
    let pre_member = rosidl_typesupport_introspection_c__MessageMember {
        name_: std::ptr::null(),
        type_id_: 4,
        string_upper_bound_: 0,
        members_: std::ptr::null(),
        is_array_: true,
        array_size_: 7,
        is_upper_bound_: false,
        offset_: 16,
        default_value_: std::ptr::null(),
        size_function: None,
        get_const_function: None,
        get_function: None,
        fetch_function: None,
        assign_function: None,
        resize_function: None,
    };
    let pre_members = rosidl_typesupport_introspection_c__MessageMembers {
        message_namespace_: std::ptr::null(),
        message_name_: std::ptr::null(),
        member_count_: 1,
        size_of_: 32,
        members_: std::ptr::from_ref(&pre_member),
        init_function: Some(dummy_init),
        fini_function: Some(dummy_fini),
    };
    let pre_ptr = std::ptr::from_ref(&pre_members);
    assert_eq!(
        unsafe { RosIntrospectionLayout::detect(pre_ptr) },
        Some(RosIntrospectionLayout::PreJazzy)
    );
    assert_eq!(
        unsafe {
            RosIntrospectionLayout::resolve_for(pre_ptr, RosIntrospectionLayout::WithKeyFields)
        },
        RosIntrospectionLayout::PreJazzy,
        "a WithKeyFields hint must not override what the object says"
    );
    let pre = RosIntrospectionLayout::PreJazzy;
    assert_eq!(
        unsafe { pre.members(pre_ptr) },
        std::ptr::from_ref(&pre_member)
    );
    assert!(unsafe { pre.member_is_array(std::ptr::from_ref(&pre_member)) });
    assert!(
        !unsafe { pre.member_is_key(std::ptr::from_ref(&pre_member)) },
        "@key did not exist before Jazzy"
    );
}

/// An empty message cannot settle the question, so the hint has to survive.
#[test]
fn an_undetectable_object_falls_back_to_the_hint() {
    let empty = rosidl_typesupport_introspection_c__MessageMembers {
        message_namespace_: std::ptr::null(),
        message_name_: std::ptr::null(),
        member_count_: 0,
        size_of_: 0,
        members_: std::ptr::null(),
        init_function: None,
        fini_function: None,
    };
    let ptr = std::ptr::from_ref(&empty);
    assert_eq!(unsafe { RosIntrospectionLayout::detect(ptr) }, None);
    assert_eq!(
        unsafe { RosIntrospectionLayout::resolve_for(ptr, RosIntrospectionLayout::WithKeyFields) },
        RosIntrospectionLayout::WithKeyFields
    );
    assert_eq!(
        unsafe { RosIntrospectionLayout::detect(std::ptr::null()) },
        None
    );
}

#[test]
fn the_distro_hint_maps_the_three_gated_distros() {
    assert_eq!(
        RosIntrospectionLayout::for_distro(Distro::Humble),
        RosIntrospectionLayout::PreJazzy
    );
    assert_eq!(
        RosIntrospectionLayout::for_distro(Distro::Iron),
        RosIntrospectionLayout::PreJazzy
    );
    assert_eq!(
        RosIntrospectionLayout::for_distro(Distro::Jazzy),
        RosIntrospectionLayout::WithKeyFields
    );
}

/// The environment is read ONCE, on the rmw entry path, and only ever seeds
/// the fallback. This test owns the process-global for the whole binary, so it
/// is the only one here that touches it.
#[test]
fn the_env_override_seeds_the_fallback() {
    std::env::set_var("HDDS_ROS_INTROSPECTION_LAYOUT", "key");
    assert_eq!(
        resolve_ros_introspection_layout_from_env(),
        RosIntrospectionLayout::WithKeyFields
    );
}
