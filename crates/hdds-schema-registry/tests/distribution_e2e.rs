// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Automatic distribution over a real DDS domain: one process registers a
//! schema, another one's registry has it without ever being told.
//!
//! Two participants, UDP multicast, a domain id nobody else in the suite
//! uses. This test needs a multicast-capable interface (HDDS refuses
//! loopback as the primary interface), so it is a local/CI-host test, not a
//! sandbox test.

#![cfg(feature = "dds")]

use std::thread::sleep;
use std::time::{Duration, Instant};

use hdds_schema_registry::distribution::{
    decode_announcement, encode_announcement, SchemaAnnouncer, SchemaSubscriber, SCHEMA_TOPIC,
};
use hdds_schema_registry::registry::{SchemaFormat, SchemaRegistry};

/// Domain 39 is HDDS's own project domain; the registry tests sit on 139 so a
/// concurrently running engine test never sees these announcements.
const DOMAIN: u32 = 139;

fn wait_for<F: FnMut() -> bool>(timeout: Duration, mut done: F) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if done() {
            return true;
        }
        sleep(Duration::from_millis(50));
    }
    done()
}

#[test]
fn a_registered_schema_reaches_a_remote_registry() {
    let mut subscriber =
        SchemaSubscriber::new(DOMAIN, "schema-registry-sub").expect("subscriber participant");
    let mut announcer =
        SchemaAnnouncer::new(DOMAIN, "schema-registry-pub").expect("announcer participant");

    // Discovery.
    sleep(Duration::from_millis(600));

    let mut local = SchemaRegistry::new();
    local
        .register(
            "Sensor",
            "struct Sensor { @key long id; double value; };",
            SchemaFormat::Idl4,
        )
        .expect("register v1");
    local
        .register(
            "Sensor",
            "struct Sensor { @key long id; double value; string unit; };",
            SchemaFormat::Idl4,
        )
        .expect("register v2");

    let announced = announcer.announce_all(&local).expect("announce");
    assert_eq!(announced, 2);

    let arrived = wait_for(Duration::from_secs(10), || {
        subscriber.poll().expect("poll") > 0
            || subscriber.registry().list_versions("Sensor").len() == 2
    });
    assert!(arrived, "no announcement arrived on {}", SCHEMA_TOPIC);

    // Drain whatever is left.
    wait_for(Duration::from_secs(5), || {
        let _ = subscriber.poll().expect("poll");
        subscriber.registry().list_versions("Sensor").len() == 2
    });

    let remote = subscriber.registry();
    assert_eq!(remote.list_schemas(), vec!["Sensor".to_string()]);
    assert_eq!(remote.list_versions("Sensor"), vec![1, 2]);
    let latest = remote.get_latest("Sensor").expect("latest");
    assert!(latest.content.contains("string unit"));
    assert_eq!(
        latest.hash,
        local.get_latest("Sensor").expect("local latest").hash,
        "the content hash must survive the wire"
    );
}

#[test]
fn the_announcement_encoding_is_stable() {
    // Not a DDS test: the wire shape other implementations would have to
    // follow, pinned here rather than left to drift.
    let mut registry = SchemaRegistry::new();
    registry
        .register("S", "struct S {};", SchemaFormat::Idl4)
        .expect("register");
    let entry = registry.get_latest("S").expect("entry");
    let bytes = encode_announcement(entry);

    assert_eq!(&bytes[0..4], &1u32.to_le_bytes());
    assert_eq!(bytes[4], b'S');
    assert_eq!(&bytes[5..9], &1u32.to_le_bytes());
    assert_eq!(bytes[9], 0, "Idl4 is format code 0");
    assert_eq!(&bytes[10..18], &entry.hash.to_le_bytes());
    assert_eq!(&bytes[18..22], &(entry.content.len() as u32).to_le_bytes());
    assert_eq!(&bytes[22..], entry.content.as_bytes());

    let decoded = decode_announcement(&bytes).expect("decode");
    assert_eq!(decoded.content, entry.content);
}
