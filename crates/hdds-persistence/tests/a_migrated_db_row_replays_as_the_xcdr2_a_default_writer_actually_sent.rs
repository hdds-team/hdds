// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Item 2 (datarep-default upgrade path): a sqlite row saved by a
//! persistence service build before the `representation` column existed
//! (migrated with `ALTER TABLE ... ADD COLUMN representation ... DEFAULT`)
//! was saved by a DEFAULT writer of the 1.4.x line, whose
//! default writers resolved and encoded XCDR2 at run time. The DEFAULT
//! writer is now XCDR1
//! (`hdds::dds::cdr_negotiation::resolve_writer_data_representation`), but
//! a migrated row's MEANING must never move with it: it was written under
//! the OLD default (XCDR2).
//!
//! The migration's `DEFAULT 0` (XCDR1) would map a
//! pre-migration row to the DDS-XTypes spec's unrelated "empty list"
//! default, which matched the old default writer by luck but no longer
//! does. Replaying such a row through
//! `HddsDdsInterface::create_writer` + `write_sample` (exactly as the
//! persistence service's own replay path does) then creates a writer
//! that OFFERS and stamps XCDR1 on bytes that are genuinely
//! XCDR2-encoded: the wire label disagrees with the wire bytes, and a
//! default reader on the other end misdecodes the trailing field.
//!
//! This test hand-builds a pre-migration database (the ORIGINAL schema,
//! no `representation` column) whose one row's payload is V3Rec encoded
//! for real as XCDR2 -- the only thing the 1.4.x default writer could have
//! produced -- opens it through `SqliteStore::new` (which must migrate it
//! in place), then replays the migrated row through the REAL
//! `HddsDdsInterface` into a real default reader over UDP, and checks the
//! DECODED VALUE, not just the representation code the migration wrote.

use hdds::api::DDS as DdsTrait;
use hdds::test_support::domains::unique_domain;
use hdds::{Participant, QoS, TransportMode};
use hdds_persistence::dds_interface::{DdsInterface, DurabilityKind};
use hdds_persistence::sqlite::SqliteStore;
use hdds_persistence::store::PersistenceStore;
use hdds_persistence::HddsDdsInterface;
use rusqlite::Connection;
use std::time::{Duration, Instant};

#[derive(hdds::DDS, Debug, Clone, PartialEq)]
struct V3Rec {
    a: u32,
    b: f64,
    c: u32,
}

fn wait_for(timeout: Duration, mut done: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if done() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    done()
}

#[test]
fn a_migrated_row_of_a_default_writer_replays_without_corruption() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("premigration.sqlite");
    let path_str = path.to_str().unwrap();

    let type_name = <V3Rec as DdsTrait>::type_descriptor().type_name;
    let topic_name = "db_upgrade_replay";
    let original = V3Rec {
        a: 0x11,
        b: 1234.5,
        c: 0x22,
    };
    let mut payload = vec![0u8; 256];
    let n = original
        .encode(&mut payload, hdds::CdrVersion::Xcdr2)
        .expect("encode V3Rec as XCDR2");
    payload.truncate(n);

    // Hand-build a pre-migration database: the ORIGINAL schema, no
    // representation column, one row already in it (the 1.4.x default
    // writer, XCDR2-encoded).
    {
        let conn = Connection::open(path_str).unwrap();
        conn.execute(
            "CREATE TABLE samples (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                topic TEXT NOT NULL,
                type_name TEXT NOT NULL,
                payload BLOB NOT NULL,
                timestamp_ns INTEGER NOT NULL,
                sequence INTEGER NOT NULL,
                source_guid BLOB NOT NULL
            )",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO samples (topic, type_name, payload, timestamp_ns, sequence, source_guid)
             VALUES (?1, ?2, ?3, 500, 1, X'00000000000000000000000000000000')",
            rusqlite::params![topic_name, type_name, payload],
        )
        .unwrap();
    }

    // Opening through SqliteStore::new runs init_schema, which must
    // migrate this file in place.
    let store = SqliteStore::new(path_str).expect("a pre-existing database must still open");
    let rows = store.load(topic_name).expect("load after migration");
    assert_eq!(rows.len(), 1);
    assert_eq!(
        rows[0].representation,
        hdds::CdrVersion::Xcdr2.representation_code(),
        "a migrated row with no stored representation must default to XCDR2, \
         the representation the 1.4.x default writer actually sent"
    );

    let domain = unique_domain();
    let replay_participant = Participant::builder("db_replay_writer_side")
        .domain_id(domain.id())
        .with_transport(TransportMode::UdpMulticast)
        .build()
        .unwrap();
    let sink = Participant::builder("db_replay_reader_side")
        .domain_id(domain.id())
        .with_transport(TransportMode::UdpMulticast)
        .build()
        .unwrap();
    std::mem::forget(domain);

    let iface = HddsDdsInterface::new(replay_participant).unwrap();
    let writer = iface
        .create_writer(topic_name, &rows[0].type_name, DurabilityKind::Volatile)
        .unwrap();
    let sink_reader = sink
        .topic::<V3Rec>(topic_name)
        .unwrap()
        .reader()
        .qos(QoS::reliable())
        .build()
        .unwrap();

    std::thread::sleep(Duration::from_millis(1500));
    writer
        .write_sample(
            &rows[0].payload,
            rows[0].timestamp_ns,
            rows[0].representation,
        )
        .unwrap();

    let mut got = Vec::new();
    wait_for(Duration::from_secs(5), || {
        while let Ok(Some(x)) = sink_reader.take() {
            got.push(x);
        }
        !got.is_empty()
    });

    assert_eq!(
        got,
        vec![original],
        "a migrated row of a default writer must replay without corruption"
    );
}
