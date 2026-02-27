// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com
//! Tests for TypeCache.

use super::*;
use crate::xtypes::{
    rosidl_message_type_support_t, rosidl_type_hash_t,
    rosidl_typesupport_introspection_c__MessageMember,
    rosidl_typesupport_introspection_c__MessageMembers, CompleteStructHeader, CompleteStructType,
    CompleteTypeDetail, CompleteTypeObject, FieldType, MemberFlag, MessageDescriptor,
    MessageMember, MinimalStructHeader, MinimalStructType, MinimalTypeDetail, MinimalTypeObject,
    PrimitiveType, StructTypeFlag, TypeIdentifier, TypeKind,
};
use std::convert::TryFrom;
use std::os::raw::c_void;
use std::ptr::{self, NonNull};
use std::sync::atomic::{AtomicBool, AtomicPtr, Ordering};
use std::sync::Arc;
use std::sync::Barrier;
use std::thread;

static HASH_PTR: AtomicPtr<rosidl_type_hash_t> = AtomicPtr::new(ptr::null_mut());

unsafe extern "C" fn stub_get_hash(
    _: *const rosidl_message_type_support_t,
) -> *const rosidl_type_hash_t {
    let ptr = HASH_PTR.load(Ordering::SeqCst);
    let const_ptr: *const rosidl_type_hash_t = ptr;
    const_ptr
}

struct TypeSupportFixture {
    hash: Box<rosidl_type_hash_t>,
    _members: Box<[rosidl_typesupport_introspection_c__MessageMember]>,
    _descriptor: Box<rosidl_typesupport_introspection_c__MessageMembers>,
    type_support: Box<rosidl_message_type_support_t>,
}

impl TypeSupportFixture {
    fn new() -> Self {
        let hash = Box::new(Self::build_hash());
        let members = Self::make_members();
        let descriptor = Box::new(Self::build_descriptor(members.as_ptr(), members.len()));
        let descriptor_ptr = ptr::from_ref(descriptor.as_ref()).cast::<c_void>();
        let type_support = Box::new(Self::build_type_support(descriptor_ptr));

        Self {
            hash,
            _members: members,
            _descriptor: descriptor,
            type_support,
        }
    }

    fn register_hash(&self) {
        let ptr = NonNull::from(self.hash.as_ref()).as_ptr();
        HASH_PTR.store(ptr, Ordering::SeqCst);
    }

    fn type_support_ptr(&self) -> *const rosidl_message_type_support_t {
        self.type_support.as_ref()
    }

    fn hash_value_mut(&mut self) -> &mut [u8; ROS_HASH_SIZE] {
        &mut self.hash.value
    }

    fn build_hash() -> rosidl_type_hash_t {
        rosidl_type_hash_t {
            version: 1,
            value: [0u8; ROS_HASH_SIZE],
        }
    }

    fn make_members() -> Box<[rosidl_typesupport_introspection_c__MessageMember]> {
        vec![
            rosidl_typesupport_introspection_c__MessageMember {
                name_: c"x".as_ptr().cast(),
                type_id_: 1,
                string_upper_bound_: 0,
                members_: ptr::null(),
                is_array_: false,
                array_size_: 0,
                is_upper_bound_: false,
                offset_: 0,
                default_value_: ptr::null(),
                size_function: None,
                get_const_function: None,
                get_function: None,
                fetch_function: None,
                assign_function: None,
                resize_function: None,
            },
            rosidl_typesupport_introspection_c__MessageMember {
                name_: c"labels".as_ptr().cast(),
                type_id_: 16,
                string_upper_bound_: 0,
                members_: ptr::null(),
                is_array_: true,
                array_size_: 0,
                is_upper_bound_: true,
                offset_: 0,
                default_value_: ptr::null(),
                size_function: None,
                get_const_function: None,
                get_function: None,
                fetch_function: None,
                assign_function: None,
                resize_function: None,
            },
        ]
        .into_boxed_slice()
    }

    fn build_descriptor(
        members_ptr: *const rosidl_typesupport_introspection_c__MessageMember,
        member_count: usize,
    ) -> rosidl_typesupport_introspection_c__MessageMembers {
        let mut descriptor = rosidl_typesupport_introspection_c__MessageMembers {
            message_namespace_: c"test_pkg__msg".as_ptr().cast(),
            message_name_: c"TaggedPoint".as_ptr().cast(),
            member_count_: u32::try_from(member_count).expect("test member count fits in u32"),
            size_of_: 0,
            members_: ptr::null(),
            init_function: None,
            fini_function: None,
        };
        descriptor.members_ = members_ptr;
        descriptor
    }

    fn build_type_support(data: *const c_void) -> rosidl_message_type_support_t {
        rosidl_message_type_support_t {
            typesupport_identifier: c"rosidl_typesupport_introspection_c".as_ptr().cast(),
            data,
            func: None,
            get_type_hash_func: Some(stub_get_hash),
            get_type_description_func: None,
            get_type_description_sources_func: None,
        }
    }
}

impl Drop for TypeSupportFixture {
    fn drop(&mut self) {
        HASH_PTR.store(ptr::null_mut(), Ordering::SeqCst);
    }
}

fn sample_hash(seed: u8) -> [u8; ROS_HASH_SIZE] {
    let mut bytes = [0u8; ROS_HASH_SIZE];
    for (idx, byte) in bytes.iter_mut().enumerate() {
        let idx_u8 = u8::try_from(idx).expect("ROS hash length fits in u8");
        *byte = seed.wrapping_add(idx_u8);
    }
    bytes
}

fn dummy_handle(distro: Distro, fqn: &str, hash: [u8; ROS_HASH_SIZE]) -> TypeObjectHandle {
    let complete = CompleteTypeObject::Struct(CompleteStructType {
        struct_flags: StructTypeFlag::IS_FINAL,
        header: CompleteStructHeader {
            base_type: None,
            detail: CompleteTypeDetail::new(fqn),
        },
        member_seq: Vec::new(),
    });

    let minimal = MinimalTypeObject::Struct(MinimalStructType {
        struct_flags: StructTypeFlag::IS_FINAL,
        header: MinimalStructHeader {
            base_type: None,
            detail: MinimalTypeDetail::new(),
        },
        member_seq: Vec::new(),
    });

    TypeObjectHandle::new(
        distro,
        Arc::<str>::from(fqn),
        1,
        Arc::new(hash),
        complete,
        minimal,
        TypeIdentifier::primitive(TypeKind::TK_INT32),
        TypeIdentifier::primitive(TypeKind::TK_INT32),
    )
}

#[test]
fn cache_hit_and_miss_paths() {
    let cache = TypeCache::new(4);
    let hash = sample_hash(1);
    let type_obj = cache.get_or_build(Distro::Humble, "pkg/Type", &hash, || {
        dummy_handle(Distro::Humble, "pkg/Type", hash)
    });

    let stats = cache.stats();
    assert_eq!(stats.misses, 1);
    assert_eq!(stats.hits, 0);

    let build_called = AtomicBool::new(false);
    let hash = sample_hash(1);
    let same = cache.get_or_build(Distro::Humble, "pkg/Type", &hash, || {
        build_called.store(true, Ordering::Relaxed);
        dummy_handle(Distro::Humble, "pkg/Type", hash)
    });
    assert!(!build_called.load(Ordering::Relaxed));
    assert_eq!(Arc::as_ptr(&type_obj), Arc::as_ptr(&same));

    let stats = cache.stats();
    assert_eq!(stats.misses, 1);
    assert_eq!(stats.hits, 1);
}

#[test]
fn eviction_respects_capacity() {
    let cache = TypeCache::new(2);
    let builds = [("pkg/One", 1), ("pkg/Two", 2), ("pkg/Three", 3)];

    for (name, seed) in builds {
        let hash = sample_hash(seed);
        let _ = cache.get_or_build(Distro::Humble, name, &hash, || {
            dummy_handle(Distro::Humble, name, hash)
        });
    }

    let stats = cache.stats();
    assert_eq!(stats.misses, 3);
    assert_eq!(stats.hits, 0);

    let misses = cache.stats().misses;
    assert!(misses >= 3);
}

#[test]
fn pin_prevents_eviction() {
    let cache = TypeCache::new(2);
    let pinned_hash = sample_hash(42);
    cache.pin(Distro::Humble, "std_msgs/String", &pinned_hash);
    let _ = cache.get_or_build(Distro::Humble, "std_msgs/String", &pinned_hash, || {
        dummy_handle(Distro::Humble, "std_msgs/String", pinned_hash)
    });

    let hash_a = sample_hash(1);
    let _ = cache.get_or_build(Distro::Humble, "pkg/A", &hash_a, || {
        dummy_handle(Distro::Humble, "pkg/A", hash_a)
    });
    let hash_b = sample_hash(2);
    let _ = cache.get_or_build(Distro::Humble, "pkg/B", &hash_b, || {
        dummy_handle(Distro::Humble, "pkg/B", hash_b)
    });

    let build_called = AtomicBool::new(false);
    let pinned_hash2 = sample_hash(42);
    let value = cache.get_or_build(Distro::Humble, "std_msgs/String", &pinned_hash2, || {
        build_called.store(true, Ordering::Relaxed);
        dummy_handle(Distro::Humble, "std_msgs/String", pinned_hash2)
    });
    assert!(!build_called.load(Ordering::Relaxed));
    assert!(Arc::strong_count(&value) >= 1);
}

#[test]
fn concurrent_hits_are_cheap() {
    let cache = Arc::new(TypeCache::new(128));
    let pinned = sample_hash(77);
    cache.pin(Distro::Humble, "core/Pinned", &pinned);
    let _ = cache.get_or_build(Distro::Humble, "core/Pinned", &pinned, || {
        dummy_handle(Distro::Humble, "core/Pinned", pinned)
    });

    let barrier = Arc::new(Barrier::new(8));
    let mut handles = Vec::new();

    for _ in 0..8 {
        let cache = Arc::clone(&cache);
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            barrier.wait();
            for _ in 0..1_000 {
                let idx = fastrand::usize(..4);
                let name = match idx {
                    0 => "core/Pinned",
                    1 => "pkg/A",
                    2 => "pkg/B",
                    _ => "pkg/C",
                };
                let idx_u8 = u8::try_from(idx).expect("idx fits in u8");
                let hash = sample_hash(idx_u8);
                let _ = cache.get_or_build(Distro::Humble, name, &hash, || {
                    dummy_handle(Distro::Humble, name, hash)
                });
            }
        }));
    }

    for handle in handles {
        handle.join().expect("thread should succeed");
    }

    let stats = cache.stats();
    assert!(stats.hits > stats.misses);
}

#[test]
fn builds_from_type_support() {
    let mut fixture = TypeSupportFixture::new();
    for (idx, byte) in fixture.hash_value_mut().iter_mut().enumerate() {
        let idx_u8 = u8::try_from(idx).expect("ROS hash length fits in u8");
        *byte = idx_u8;
    }

    fixture.register_hash();

    let cache = TypeCache::new(4);
    // SAFETY: The type support pointer references data owned by `fixture` for the
    // duration of this call, matching the expectations of `get_or_build_from_type_support`.
    let handle = unsafe {
        cache
            .get_or_build_from_type_support(Distro::Humble, fixture.type_support_ptr())
            .expect("build from type support")
    };

    let struct_complete = match &handle.complete {
        CompleteTypeObject::Struct(s) => Some(s),
        _ => None,
    }
    .expect("expected struct TypeObject");

    assert_eq!(struct_complete.member_seq.len(), 2);
    assert_eq!(handle.ros_hash_version, 1);
    assert_eq!(handle.ros_hash.as_ref(), &fixture.hash.value);
}

#[test]
fn cache_builds_from_descriptor() {
    let cache = TypeCache::new(8);

    let first = build_tagged_point(&cache);
    let struct_complete = match &first.complete {
        CompleteTypeObject::Struct(s) => Some(s),
        _ => None,
    }
    .expect("expected struct TypeObject");
    assert_eq!(struct_complete.member_seq.len(), 2);
    assert!(matches!(
        struct_complete.member_seq[0].common.member_flags,
        flags if flags.contains(MemberFlag::IS_KEY)
    ));

    let second = build_tagged_point(&cache);
    assert!(Arc::ptr_eq(&first, &second));
}

fn build_tagged_point(cache: &TypeCache) -> Arc<TypeObjectHandle> {
    let nested_members = [
        MessageMember {
            name: "x",
            field_type: FieldType::Primitive(PrimitiveType::Float32),
            is_key: false,
        },
        MessageMember {
            name: "y",
            field_type: FieldType::Primitive(PrimitiveType::Float32),
            is_key: false,
        },
    ];
    let nested_hash = sample_hash(90);
    let nested_descriptor = MessageDescriptor {
        namespace: "geometry_msgs::msg",
        name: "Point2D",
        members: &nested_members,
        ros_hash_version: 1,
        ros_hash: &nested_hash,
    };

    let top_members = [
        MessageMember {
            name: "position",
            field_type: FieldType::Nested(&nested_descriptor),
            is_key: true,
        },
        MessageMember {
            name: "labels",
            field_type: FieldType::Sequence {
                element: Box::new(FieldType::String { bound: Some(8) }),
                bound: Some(4),
            },
            is_key: false,
        },
    ];
    let top_hash = sample_hash(91);
    let top_descriptor = MessageDescriptor {
        namespace: "vision_msgs::msg",
        name: "TaggedPoint",
        members: &top_members,
        ros_hash_version: 1,
        ros_hash: &top_hash,
    };

    cache
        .get_or_build_from_descriptor(Distro::Humble, &top_descriptor)
        .expect("tagged point build")
}
