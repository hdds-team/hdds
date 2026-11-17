// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

use super::Participant;
use crate::core::discovery::matcher::{Matcher, TypeObjectResolver};
use crate::core::types::{Distro, TypeObjectHandle};
use crate::protocol::discovery::types::TypeConsistencyEnforcement;
use crate::test_support::domains::unique_domain;
use crate::xtypes::{
    rosidl_message_type_support_t, rosidl_typesupport_introspection_c__MessageMember,
    rosidl_typesupport_introspection_c__MessageMembers, TypeIdentifier,
};
use std::ffi::CString;
use std::sync::Arc;

fn member(type_id: u8) -> rosidl_typesupport_introspection_c__MessageMember {
    rosidl_typesupport_introspection_c__MessageMember {
        name_: c"value".as_ptr(),
        type_id_: type_id,
        string_upper_bound_: 0,
        members_: std::ptr::null(),
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

fn members(
    name: &CString,
    member: &rosidl_typesupport_introspection_c__MessageMember,
) -> rosidl_typesupport_introspection_c__MessageMembers {
    rosidl_typesupport_introspection_c__MessageMembers {
        message_namespace_: c"ros_graph__msg".as_ptr(),
        message_name_: name.as_ptr(),
        member_count_: 1,
        size_of_: 8,
        members_: member,
        init_function: None,
        fini_function: None,
    }
}

fn support(
    members: &rosidl_typesupport_introspection_c__MessageMembers,
) -> rosidl_message_type_support_t {
    rosidl_message_type_support_t {
        typesupport_identifier: std::ptr::null(),
        data: std::ptr::from_ref(members).cast(),
        func: None,
        get_type_hash_func: None,
        get_type_description_func: None,
        get_type_description_sources_func: None,
    }
}

// All raw introspection pointers remain live until registration has copied
// the entire graph. Every fixture is pre-Jazzy and detected from its object.
fn register_graph(
    p: &Participant,
    name: &str,
    leaf_type: u8,
    sequence: bool,
) -> Arc<TypeObjectHandle> {
    let leaf_name = CString::new(format!("{name}Leaf")).expect("name");
    let leaf = member(leaf_type);
    let leaf_members = members(&leaf_name, &leaf);
    let leaf_ts = support(&leaf_members);
    let middle_name = CString::new(format!("{name}Middle")).expect("name");
    let mut middle = member(18);
    middle.members_ = &leaf_ts;
    let middle_members = members(&middle_name, &middle);
    let middle_ts = support(&middle_members);
    let root_name = CString::new(format!("{name}Root")).expect("name");
    let mut root = member(18);
    root.members_ = &middle_ts;
    root.is_array_ = sequence;
    let root_members = members(&root_name, &root);
    let root_ts = support(&root_members);
    let handle = unsafe { p.register_type_from_type_support(Distro::Humble, &root_ts) }
        .expect("ROS registration");
    let again = unsafe { p.register_type_from_type_support(Distro::Humble, &root_ts) }
        .expect("cached ROS registration");
    assert!(Arc::ptr_eq(&handle, &again));
    handle
}

/// XTypes 1.3 7.3.4 and 7.6.3: every reachable hash identifier must
/// resolve to its corresponding TypeObject, for both representation kinds.
#[test]
fn ros_registration_retains_and_publishes_transitive_dependencies() {
    let domain = unique_domain();
    let mut p = Participant::builder("ros_dependencies")
        .domain_id(domain.id())
        .with_transport(crate::TransportMode::IntraProcess)
        .build()
        .expect("participant");
    // IntraProcess has no discovery services. Attach the production registry
    // in memory so registration and matching need no sockets.
    let fsm = Arc::new(crate::core::discovery::multicast::DiscoveryFsm::new(
        p.guid(),
        30_000,
    ));
    let registry = Arc::new(
        crate::dds::match_notification::MatchNotificationRegistry::new(&fsm, p.guid().prefix),
    );
    Arc::get_mut(&mut p)
        .expect("fresh participant has one owner")
        .match_registry = Some(registry);
    let root = register_graph(&p, "Closure", 13, true);
    assert_eq!(root.dependencies.len(), 2);
    let registry = p.match_registry.as_ref().expect("match registry");
    let resolver = registry.snapshot_resolver();
    assert!(registry.unresolved_type_refs(&root.complete).is_empty());
    let registered = p.registered_types.read();
    for dependency in &root.dependencies {
        let TypeIdentifier::Complete(c) = dependency.type_id_complete else {
            panic!("complete id");
        };
        let TypeIdentifier::Minimal(m) = dependency.type_id_minimal else {
            panic!("minimal id");
        };
        assert_eq!(resolver.resolve_complete(&c), Some(&dependency.complete));
        assert!(resolver.resolve_minimal(&m).is_some());
        // These are the exact handle maps scanned by the getTypes responder.
        let served_complete = registered
            .values()
            .find(|h| h.type_id_complete == dependency.type_id_complete)
            .expect("TypeLookup can find Complete dependency");
        let served_minimal = registered
            .values()
            .find(|h| h.type_id_minimal == dependency.type_id_minimal)
            .expect("TypeLookup can find Minimal dependency");
        assert_eq!(
            served_complete
                .complete
                .compute_equivalence_hash()
                .expect("hash"),
            c
        );
        assert_eq!(
            served_minimal
                .minimal
                .compute_equivalence_hash()
                .expect("hash"),
            m
        );
    }
}

/// XTypes 1.3 7.5.2.7 / 7.6.3.4: nested type names alone do not prevent
/// assignability with ALLOW_TYPE_COERCION, while distinct FINAL member types
/// do. Exercise the production matcher with both registered graphs present.
#[test]
fn ros_registration_resolves_distinct_complete_names_for_matching() {
    let domain = unique_domain();
    let mut p = Participant::builder("ros_nested_matching")
        .domain_id(domain.id())
        .with_transport(crate::TransportMode::IntraProcess)
        .build()
        .expect("participant");
    // IntraProcess has no discovery services. Attach the production registry
    // in memory so registration and matching need no sockets.
    let fsm = Arc::new(crate::core::discovery::multicast::DiscoveryFsm::new(
        p.guid(),
        30_000,
    ));
    let registry = Arc::new(
        crate::dds::match_notification::MatchNotificationRegistry::new(&fsm, p.guid().prefix),
    );
    Arc::get_mut(&mut p)
        .expect("fresh participant has one owner")
        .match_registry = Some(registry);
    for sequence in [false, true] {
        let suffix = if sequence { "Seq" } else { "Scalar" };
        let a = register_graph(&p, &format!("A{suffix}"), 13, sequence);
        let b = register_graph(&p, &format!("B{suffix}"), 13, sequence);
        let c = register_graph(&p, &format!("C{suffix}"), 6, sequence); // boolean, not int32
        assert_eq!(a.type_id_minimal, b.type_id_minimal);
        assert_ne!(a.type_id_complete, b.type_id_complete);
        let registry = p.match_registry.as_ref().expect("registry");
        let resolver = registry.snapshot_resolver();
        {
            let registered = p.registered_types.read();
            for root in [&a, &b, &c] {
                for dependency in &root.dependencies {
                    assert!(
                        registered
                            .values()
                            .any(|h| h.type_id_complete == dependency.type_id_complete),
                        "every Complete object survives shared Minimal identities"
                    );
                }
            }
        }
        for (left, right) in [(&a, &b), (&b, &a)] {
            assert!(Matcher::is_type_compatible_with_resolver(
                Some(&left.complete),
                Some(&right.complete),
                &left.fqn,
                &right.fqn,
                Some(&TypeConsistencyEnforcement::default()),
                Some(&resolver)
            ));
        }
        assert!(!Matcher::is_type_compatible_with_resolver(
            Some(&a.complete),
            Some(&c.complete),
            &a.fqn,
            &c.fqn,
            Some(&TypeConsistencyEnforcement::default()),
            Some(&resolver)
        ));
    }
}
