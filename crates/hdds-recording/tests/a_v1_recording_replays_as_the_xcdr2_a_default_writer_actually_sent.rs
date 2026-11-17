// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Item 1 (datarep-default upgrade path): a FORMAT_VERSION 1 `.hdds` file
//! carries no per-message DATA_REPRESENTATION field at all -- it was
//! recorded by hdds-record on the 1.4.x line, whose
//! DEFAULT writers resolved and encoded XCDR2 at run time. The DEFAULT
//! writer is now XCDR1 (`resolve_writer_data_representation`),
//! but that change must never reach backward in time: a v1 file's bytes
//! were produced under the OLD default (XCDR2), so replaying it must
//! label those bytes XCDR2 too, never guess the NEW default.
//!
//! Filling in XCDR1 for every v1 message (the DDS-XTypes spec's "empty
//! list" default) would match the old default writer by luck but no
//! longer does. Replaying a v1 recording of a default writer through
//! `RawRelayWriter` (exactly as `hdds-replay`'s `bin/replay.rs` does, and
//! exactly as `HddsDdsInterface`'s persistence replay does) then creates a
//! writer that OFFERS and stamps XCDR1 on bytes that are genuinely
//! XCDR2-encoded: the wire label disagrees with the wire bytes, and a
//! default reader on the other end misdecodes the trailing field (`a: 16`
//! instead of `17`).
//!
//! This test hand-builds a v1-format file (no representation field in the
//! on-disk message layout) whose payload is V3Rec encoded for real as
//! XCDR2 -- the only thing the 1.4.x default writer could have produced --
//! then replays it through the real `RawRelayWriter` path into a real
//! default reader over UDP, and checks the DECODED VALUE, not just the
//! representation code HddsReader reports.

use byteorder::{LittleEndian, WriteBytesExt};
use hdds::api::DDS as DdsTrait;
use hdds::test_support::domains::unique_domain;
use hdds::{Participant, QoS, RawRelayWriter, TransportMode};
use hdds_recording::format::hdds::{FileHeader, HddsReader, SegmentHeader};
use hdds_recording::format::RecordingMetadata;
use std::io::Write as _;
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(hdds::DDS, Debug, Clone, PartialEq)]
struct V3Rec {
    a: u32,
    b: f64,
    c: u32,
}

/// Hand-build a minimal, valid FORMAT_VERSION 1 `.hdds` file: one segment,
/// one message, in the pre-FORMAT_VERSION_WITH_REPRESENTATION on-disk
/// layout (no representation u16 between qos_hash and payload_len), whose
/// payload is `sample` encoded for real as XCDR2 -- what a default writer
/// on 1.4.x actually put on the wire.
fn build_v1_file(path: &std::path::Path, topic_name: &str, type_name: &str, sample: &V3Rec) {
    let mut payload = vec![0u8; 256];
    let n = sample
        .encode(&mut payload, hdds::CdrVersion::Xcdr2)
        .expect("encode V3Rec as XCDR2");
    payload.truncate(n);

    let mut body = Vec::new();
    body.write_u64::<LittleEndian>(0).unwrap(); // timestamp_nanos
    body.write_u16::<LittleEndian>(topic_name.len() as u16)
        .unwrap();
    body.write_u16::<LittleEndian>(type_name.len() as u16)
        .unwrap();
    body.write_all(&[0u8; 16]).unwrap(); // writer_guid
    body.write_u64::<LittleEndian>(1).unwrap(); // sequence_number
    body.write_u32::<LittleEndian>(0).unwrap(); // qos_hash
                                                // NOTE: no representation field here -- this IS the v1 layout.
    body.write_u32::<LittleEndian>(payload.len() as u32)
        .unwrap();
    body.write_all(topic_name.as_bytes()).unwrap();
    body.write_all(type_name.as_bytes()).unwrap();
    body.write_all(&payload).unwrap();

    let mut segment = Vec::new();
    let seg_header = SegmentHeader {
        segment_id: 0,
        message_count: 1,
        data_size: body.len() as u32,
        first_timestamp: 0,
        last_timestamp: 0,
        reserved: 0,
    };
    seg_header.write(&mut segment).unwrap();
    segment.write_all(&body).unwrap();
    segment.write_u32::<LittleEndian>(0).unwrap(); // CRC (unchecked by this reader path)

    let metadata = RecordingMetadata::default();
    let metadata_json = serde_json::to_vec(&metadata).unwrap();

    let mut file = Vec::new();
    let mut header = FileHeader::new();
    header.version = 1;
    header.write(&mut file).unwrap();
    file.write_all(&segment).unwrap();
    let index_offset = file.len() as u64;
    let metadata_offset = file.len() as u64;
    file.write_all(&metadata_json).unwrap();

    header.metadata_offset = metadata_offset;
    header.metadata_size = metadata_json.len() as u32;
    header.index_offset = index_offset;
    header.index_count = 0;
    header.message_count = 1;
    header.duration_nanos = 0;
    let mut final_header = Vec::new();
    header.write(&mut final_header).unwrap();
    file[..FileHeader::SIZE].copy_from_slice(&final_header);

    std::fs::write(path, &file).unwrap();
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
fn a_v1_recording_of_a_default_writer_replays_without_corruption() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("v1.hdds");

    let type_name = <V3Rec as DdsTrait>::type_descriptor().type_name;
    let topic_name = "v1_upgrade_replay";
    let original = V3Rec {
        a: 0x11,
        b: 1234.5,
        c: 0x22,
    };
    build_v1_file(&path, topic_name, type_name, &original);

    let reader = HddsReader::open(&path).expect("open v1");
    let msgs: Vec<_> = reader.messages().map(|m| m.unwrap()).collect();
    assert_eq!(msgs.len(), 1);
    let m = &msgs[0];

    // The documented default for a v1 message's representation must now
    // be XCDR2: the one the 1.4.x default writer actually encoded, not the
    // DDS-XTypes spec's unrelated "empty list" default.
    assert_eq!(
        m.representation,
        hdds::CdrVersion::Xcdr2.representation_code(),
        "a v1 file's undocumented representation must default to XCDR2, \
         the representation the 1.4.x default writer actually sent"
    );

    let domain = unique_domain();
    let relay = Participant::builder("v1_replay_relay")
        .domain_id(domain.id())
        .with_transport(TransportMode::UdpMulticast)
        .build()
        .unwrap();
    let sink = Participant::builder("v1_replay_sink")
        .domain_id(domain.id())
        .with_transport(TransportMode::UdpMulticast)
        .build()
        .unwrap();
    std::mem::forget(domain);

    let version = hdds::CdrVersion::from_representation_code(m.representation).unwrap();
    let relay_writer = RawRelayWriter::new(
        Arc::clone(&relay),
        topic_name,
        &m.type_name,
        Some(QoS::reliable()),
        None,
        Some(version),
    )
    .unwrap();
    let sink_reader = sink
        .topic::<V3Rec>(topic_name)
        .unwrap()
        .reader()
        .qos(QoS::reliable())
        .build()
        .unwrap();

    std::thread::sleep(Duration::from_millis(1500));
    relay_writer.relay_write(&m.payload, version).unwrap();

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
        "a v1 recording of a default writer must replay without corruption"
    );
}
