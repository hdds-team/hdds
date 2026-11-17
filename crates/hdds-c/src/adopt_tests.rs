// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! XTypes 1.3 Sec.7.6.3.4.2 Step 2: an endpoint the C ABI creates without a
//! type name announces the name its topic's opposite endpoints announce, so
//! a typed peer does not refuse it for the placeholder `RawBytes`.

use super::*;
use hdds::test_support::domains::{unique_domain, DomainLease};
use std::ffi::CString;

type NamedCtor<'a, T> = (&'a str, Box<dyn Fn(*const c_char) -> *mut T + 'a>);

fn domain() -> DomainLease {
    let mut other = Vec::new();
    loop {
        let lease = unique_domain();
        if (200..=230).contains(&lease.id()) {
            return lease;
        }
        other.push(lease);
    }
}

unsafe fn participant(domain: u32) -> *mut HddsParticipant {
    let name = CString::new("adopt_names").unwrap();
    let config = transport_config::hdds_config_create(name.as_ptr());
    assert_eq!(
        transport_config::hdds_config_set_domain_id(config, domain),
        HddsError::HddsOk
    );
    let p = transport_config::hdds_config_build(config);
    assert!(!p.is_null());
    p
}

/// The type names the participant's own endpoints of `topic` announce.
unsafe fn names(p: *mut HddsParticipant, topic: &str) -> (Vec<String>, Vec<String>) {
    let participant = &*p.cast::<Arc<Participant>>();
    let fsm = participant.discovery().unwrap();
    let take = |endpoints: Vec<hdds::core::discovery::multicast::fsm::EndpointInfo>| {
        endpoints.into_iter().map(|e| e.type_name).collect()
    };
    (
        take(fsm.find_writers_for_topic(topic)),
        take(fsm.find_readers_for_topic(topic)),
    )
}

/// A content filtered topic on `topic` over a `{ int32 id; }` type.
unsafe fn filtered_topic(
    p: *mut HddsParticipant,
    topic: *const c_char,
    desc: *const HddsTypeDescriptor,
) -> *mut HddsContentFilteredTopic {
    let name = CString::new("adopt_cft").unwrap();
    let expr = CString::new("id > 0").unwrap();
    let cft = condition_ffi::hdds_create_content_filtered_topic(
        p,
        name.as_ptr(),
        topic,
        desc,
        expr.as_ptr(),
        ptr::null(),
        0,
    );
    assert!(!cft.is_null());
    cft
}

unsafe fn id_type() -> *mut HddsTypeDescriptor {
    let name = CString::new("AdoptId").unwrap();
    let builder = hdds_type_builder_new(name.as_ptr());
    let field = CString::new("id").unwrap();
    assert_eq!(
        hdds_type_builder_add_field(
            builder,
            field.as_ptr(),
            HddsPrimitiveKind::HddsPrimI32 as u32
        ),
        HddsError::HddsOk
    );
    hdds_type_builder_build(builder)
}

/// Every reader constructor of the ABI that takes no type name.
#[test]
fn nameless_c_readers_adopt_the_typed_writers_name() {
    let lease = domain();
    unsafe {
        let p = participant(lease.id());
        let subscriber = pubsub::hdds_subscriber_create(p);
        assert!(!subscriber.is_null());
        let typed = CString::new("X::Y").unwrap();
        let desc = id_type();
        let filtered = |t: *const c_char, type_name: Option<&str>| {
            let cft = filtered_topic(p, t, desc);
            let type_name = type_name.map(|n| CString::new(n).unwrap());
            let reader = condition_ffi::hdds_create_reader_filtered_with_type(
                p,
                cft,
                type_name.as_ref().map_or(ptr::null(), |n| n.as_ptr()),
                ptr::null(),
            );
            condition_ffi::hdds_content_filtered_topic_delete(cft);
            reader
        };
        let constructors: Vec<NamedCtor<'_, HddsDataReader>> = vec![
            ("hdds_reader_create", Box::new(|t| hdds_reader_create(p, t))),
            (
                "hdds_reader_create_with_type(\"\")",
                Box::new(|t| {
                    let empty = CString::new("").unwrap();
                    hdds_reader_create_with_type(p, t, empty.as_ptr(), ptr::null())
                }),
            ),
            (
                "hdds_create_reader_filtered",
                Box::new(move |t| {
                    let cft = filtered_topic(p, t, desc);
                    let reader = condition_ffi::hdds_create_reader_filtered(p, cft, ptr::null());
                    condition_ffi::hdds_content_filtered_topic_delete(cft);
                    reader
                }),
            ),
            (
                "hdds_create_reader_filtered_with_type(NULL)",
                Box::new(move |t| filtered(t, None)),
            ),
            (
                "hdds_create_reader_filtered_with_type(\"\")",
                Box::new(move |t| filtered(t, Some(""))),
            ),
            (
                "hdds_reader_create_with_qos",
                Box::new(|t| hdds_reader_create_with_qos(p, t, ptr::null())),
            ),
            (
                "hdds_reader_create_with_type(NULL)",
                Box::new(|t| hdds_reader_create_with_type(p, t, ptr::null(), ptr::null())),
            ),
            (
                "hdds_subscriber_create_reader",
                Box::new(|t| pubsub::hdds_subscriber_create_reader(subscriber, t)),
            ),
            (
                "hdds_subscriber_create_reader_with_qos",
                Box::new(|t| {
                    pubsub::hdds_subscriber_create_reader_with_qos(subscriber, t, ptr::null())
                }),
            ),
        ];
        for (index, (label, create)) in constructors.iter().enumerate() {
            let topic = CString::new(format!("adopt_reader_{index}")).unwrap();
            let writer =
                hdds_writer_create_with_type(p, topic.as_ptr(), typed.as_ptr(), ptr::null());
            assert!(!writer.is_null());
            let reader = create(topic.as_ptr());
            assert!(!reader.is_null(), "{label}");
            let (writers, readers) = names(p, topic.to_str().unwrap());
            assert_eq!(writers, ["X::Y"], "{label}: the typed writer is unchanged");
            assert_eq!(readers, ["X::Y"], "{label}: the reader adopts the name");
            hdds_reader_destroy(reader);
            hdds_writer_destroy(writer);
        }
        pubsub::hdds_subscriber_destroy(subscriber);
        hdds_type_descriptor_destroy(desc);
        hdds_participant_destroy(p);
    }
}

/// Every writer constructor of the ABI that takes no type name.
#[test]
fn nameless_c_writers_adopt_the_typed_readers_name() {
    let lease = domain();
    unsafe {
        let p = participant(lease.id());
        let publisher = pubsub::hdds_publisher_create(p);
        assert!(!publisher.is_null());
        let typed = CString::new("X::Y").unwrap();
        let constructors: Vec<NamedCtor<'_, HddsDataWriter>> = vec![
            ("hdds_writer_create", Box::new(|t| hdds_writer_create(p, t))),
            (
                "hdds_writer_create_with_qos",
                Box::new(|t| hdds_writer_create_with_qos(p, t, ptr::null())),
            ),
            (
                "hdds_writer_create_with_type(NULL)",
                Box::new(|t| hdds_writer_create_with_type(p, t, ptr::null(), ptr::null())),
            ),
            (
                "hdds_writer_create_with_type(\"\")",
                Box::new(|t| {
                    let empty = CString::new("").unwrap();
                    hdds_writer_create_with_type(p, t, empty.as_ptr(), ptr::null())
                }),
            ),
            (
                "hdds_writer_create_with_extensibility(NULL)",
                Box::new(|t| {
                    hdds_writer_create_with_extensibility(
                        p,
                        t,
                        ptr::null(),
                        ptr::null(),
                        HDDS_EXTENSIBILITY_FINAL,
                    )
                }),
            ),
            (
                "hdds_publisher_create_writer",
                Box::new(|t| pubsub::hdds_publisher_create_writer(publisher, t)),
            ),
            (
                "hdds_publisher_create_writer_with_qos",
                Box::new(|t| {
                    pubsub::hdds_publisher_create_writer_with_qos(publisher, t, ptr::null())
                }),
            ),
            (
                "hdds_publisher_create_writer_with_extensibility",
                Box::new(|t| {
                    pubsub::hdds_publisher_create_writer_with_extensibility(
                        publisher,
                        t,
                        ptr::null(),
                        HDDS_EXTENSIBILITY_APPENDABLE,
                    )
                }),
            ),
            (
                "hdds_writer_create_with_extensibility(\"\")",
                Box::new(|t| {
                    let empty = CString::new("").unwrap();
                    hdds_writer_create_with_extensibility(
                        p,
                        t,
                        empty.as_ptr(),
                        ptr::null(),
                        HDDS_EXTENSIBILITY_FINAL,
                    )
                }),
            ),
            (
                "hdds_writer_create_keyed(NULL)",
                Box::new(|t| {
                    key_ffi::hdds_writer_create_keyed(
                        p,
                        t,
                        ptr::null(),
                        ptr::null(),
                        HDDS_EXTENSIBILITY_FINAL,
                    )
                }),
            ),
            (
                "hdds_writer_create_keyed(\"\")",
                Box::new(|t| {
                    let empty = CString::new("").unwrap();
                    key_ffi::hdds_writer_create_keyed(
                        p,
                        t,
                        empty.as_ptr(),
                        ptr::null(),
                        HDDS_EXTENSIBILITY_FINAL,
                    )
                }),
            ),
            (
                "hdds_publisher_create_writer_keyed(NULL)",
                Box::new(|t| {
                    key_ffi::hdds_publisher_create_writer_keyed(
                        publisher,
                        t,
                        ptr::null(),
                        ptr::null(),
                        HDDS_EXTENSIBILITY_FINAL,
                    )
                }),
            ),
            (
                "hdds_publisher_create_writer_keyed(\"\")",
                Box::new(|t| {
                    let empty = CString::new("").unwrap();
                    key_ffi::hdds_publisher_create_writer_keyed(
                        publisher,
                        t,
                        empty.as_ptr(),
                        ptr::null(),
                        HDDS_EXTENSIBILITY_APPENDABLE,
                    )
                }),
            ),
        ];
        for (index, (label, create)) in constructors.iter().enumerate() {
            let topic = CString::new(format!("adopt_writer_{index}")).unwrap();
            let reader =
                hdds_reader_create_with_type(p, topic.as_ptr(), typed.as_ptr(), ptr::null());
            assert!(!reader.is_null());
            let writer = create(topic.as_ptr());
            assert!(!writer.is_null(), "{label}");
            let (writers, readers) = names(p, topic.to_str().unwrap());
            assert_eq!(readers, ["X::Y"], "{label}: the typed reader is unchanged");
            assert_eq!(writers, ["X::Y"], "{label}: the writer adopts the name");
            hdds_writer_destroy(writer);
            hdds_reader_destroy(reader);
        }
        pubsub::hdds_publisher_destroy(publisher);
        hdds_participant_destroy(p);
    }
}

/// With no typed peer the placeholder stays, so two nameless endpoints still
/// match; an explicit name is never replaced.
#[test]
fn placeholder_and_explicit_names_are_unchanged() {
    let lease = domain();
    unsafe {
        let p = participant(lease.id());
        let alone = CString::new("adopt_alone").unwrap();
        let writer = hdds_writer_create(p, alone.as_ptr());
        let reader = hdds_reader_create(p, alone.as_ptr());
        assert!(!writer.is_null() && !reader.is_null());
        let (writers, readers) = names(p, "adopt_alone");
        assert_eq!(writers, ["RawBytes"]);
        assert_eq!(readers, ["RawBytes"]);

        let topic = CString::new("adopt_explicit").unwrap();
        let (typed, other) = (CString::new("X::Y").unwrap(), CString::new("Z::W").unwrap());
        let w = hdds_writer_create_with_type(p, topic.as_ptr(), typed.as_ptr(), ptr::null());
        let r = hdds_reader_create_with_type(p, topic.as_ptr(), other.as_ptr(), ptr::null());
        assert!(!w.is_null() && !r.is_null());
        let (writers, readers) = names(p, "adopt_explicit");
        assert_eq!(writers, ["X::Y"]);
        assert_eq!(readers, ["Z::W"]);

        // The Publisher/Subscriber entries for a type announce the type's name
        // and never a peer's.
        let topic = CString::new("adopt_explicit_pubsub").unwrap();
        let peer = hdds_writer_create_with_type(p, topic.as_ptr(), other.as_ptr(), ptr::null());
        let subscriber = pubsub::hdds_subscriber_create(p);
        let publisher = pubsub::hdds_publisher_create(p);
        let typed_reader = pubsub::hdds_subscriber_create_reader_with_type(
            subscriber,
            topic.as_ptr(),
            typed.as_ptr(),
            ptr::null(),
        );
        let typed_writer = pubsub::hdds_publisher_create_writer_with_type(
            publisher,
            topic.as_ptr(),
            typed.as_ptr(),
            ptr::null(),
            HDDS_EXTENSIBILITY_FINAL,
        );
        assert!(!peer.is_null() && !typed_reader.is_null() && !typed_writer.is_null());
        let (mut writers, readers) = names(p, "adopt_explicit_pubsub");
        writers.sort();
        assert_eq!(writers, ["X::Y", "Z::W"]);
        assert_eq!(readers, ["X::Y"]);
        hdds_writer_destroy(typed_writer);
        hdds_reader_destroy(typed_reader);
        pubsub::hdds_publisher_destroy(publisher);
        pubsub::hdds_subscriber_destroy(subscriber);
        hdds_writer_destroy(peer);

        hdds_reader_destroy(r);
        hdds_writer_destroy(w);
        hdds_reader_destroy(reader);
        hdds_writer_destroy(writer);
        hdds_participant_destroy(p);
    }
}

/// A raw writer, a typed peer writer, then a new nameless reader: the live
/// placeholder counts as a name, so the topic is ambiguous and the reader
/// stays raw (paired with the raw writer) instead of leaving it.
#[test]
fn a_raw_writer_beside_a_typed_peer_keeps_the_new_reader_raw() {
    let lease = domain();
    unsafe {
        let p = participant(lease.id());
        let topic = CString::new("adopt_raw_pair").unwrap();
        let typed = CString::new("X::Y").unwrap();
        let raw_writer = hdds_writer_create(p, topic.as_ptr());
        let typed_writer =
            hdds_writer_create_with_type(p, topic.as_ptr(), typed.as_ptr(), ptr::null());
        assert!(!raw_writer.is_null() && !typed_writer.is_null());
        let reader = hdds_reader_create(p, topic.as_ptr());
        assert!(!reader.is_null());
        let (mut writers, readers) = names(p, "adopt_raw_pair");
        writers.sort();
        assert_eq!(writers, ["RawBytes", "X::Y"]);
        assert_eq!(readers, ["RawBytes"], "the reader keeps the placeholder");
        hdds_reader_destroy(reader);
        hdds_writer_destroy(typed_writer);
        hdds_writer_destroy(raw_writer);
        hdds_participant_destroy(p);
    }
}

/// A type name that is not UTF-8 is an error (NULL), never a nameless
/// endpoint that adopts a peer's name.
#[test]
fn an_invalid_utf8_type_name_creates_nothing() {
    let lease = domain();
    unsafe {
        let p = participant(lease.id());
        let topic = CString::new("adopt_bad_utf8").unwrap();
        let typed = CString::new("X::Y").unwrap();
        let peer = hdds_writer_create_with_type(p, topic.as_ptr(), typed.as_ptr(), ptr::null());
        assert!(!peer.is_null());
        let bad = CString::new(vec![0xff, 0xfe, b'x']).unwrap();
        assert!(
            hdds_writer_create_with_type(p, topic.as_ptr(), bad.as_ptr(), ptr::null()).is_null()
        );
        assert!(
            hdds_reader_create_with_type(p, topic.as_ptr(), bad.as_ptr(), ptr::null()).is_null()
        );
        assert!(hdds_writer_create_with_extensibility(
            p,
            topic.as_ptr(),
            bad.as_ptr(),
            ptr::null(),
            HDDS_EXTENSIBILITY_FINAL
        )
        .is_null());
        assert!(key_ffi::hdds_writer_create_keyed(
            p,
            topic.as_ptr(),
            bad.as_ptr(),
            ptr::null(),
            HDDS_EXTENSIBILITY_FINAL
        )
        .is_null());
        let publisher = pubsub::hdds_publisher_create(p);
        let subscriber = pubsub::hdds_subscriber_create(p);
        assert!(pubsub::hdds_publisher_create_writer_with_type(
            publisher,
            topic.as_ptr(),
            bad.as_ptr(),
            ptr::null(),
            HDDS_EXTENSIBILITY_FINAL
        )
        .is_null());
        assert!(key_ffi::hdds_publisher_create_writer_keyed(
            publisher,
            topic.as_ptr(),
            bad.as_ptr(),
            ptr::null(),
            HDDS_EXTENSIBILITY_FINAL
        )
        .is_null());
        assert!(pubsub::hdds_subscriber_create_reader_with_type(
            subscriber,
            topic.as_ptr(),
            bad.as_ptr(),
            ptr::null()
        )
        .is_null());
        pubsub::hdds_publisher_destroy(publisher);
        pubsub::hdds_subscriber_destroy(subscriber);
        let desc = id_type();
        let cft = filtered_topic(p, topic.as_ptr(), desc);
        assert!(condition_ffi::hdds_create_reader_filtered_with_type(
            p,
            cft,
            bad.as_ptr(),
            ptr::null()
        )
        .is_null());
        condition_ffi::hdds_content_filtered_topic_delete(cft);
        hdds_type_descriptor_destroy(desc);
        let (writers, readers) = names(p, "adopt_bad_utf8");
        assert_eq!(writers, ["X::Y"]);
        assert!(readers.is_empty(), "no reader was created: {readers:?}");
        hdds_writer_destroy(peer);
        hdds_participant_destroy(p);
    }
}
