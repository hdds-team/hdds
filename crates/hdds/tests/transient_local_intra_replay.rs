// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! TRANSIENT_LOCAL history replay on the intra-process path.
//!
//! A late joiner is owed every retained sample, decoded the way it was
//! encoded. `Tagged` below makes a CDR version mismatch deterministic
//! instead of garbage: it stores the version it was encoded with and
//! refuses to decode under any other, which is what a type whose decoder
//! honours the version (every hdds_gen-generated type does; the derive
//! ignores the parameter) suffers as misread fields.

use hdds::{DdsTrait, Participant, QoS, TransportMode};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq)]
struct Tagged {
    value: u32,
}

/// Derived twin with the same layout, only there to supply a type
/// descriptor. Both fields are `u32`: a `u8` field makes the derive emit an
/// `offset % 1` that clippy's `modulo_one` refuses in this crate's lints.
#[derive(hdds::DDS)]
struct TaggedWire {
    value: u32,
    tag: u32,
}

fn tag(version: hdds::dds::CdrVersion) -> u32 {
    match version {
        hdds::dds::CdrVersion::Xcdr1 => 1,
        hdds::dds::CdrVersion::Xcdr2 => 2,
    }
}

impl DdsTrait for Tagged {
    fn type_descriptor() -> &'static hdds::core::types::TypeDescriptor {
        TaggedWire::type_descriptor()
    }

    fn encode(&self, buf: &mut [u8], version: hdds::dds::CdrVersion) -> hdds::Result<usize> {
        if buf.len() < 8 {
            return Err(hdds::Error::BufferTooSmall);
        }
        buf[..4].copy_from_slice(&self.value.to_le_bytes());
        buf[4..8].copy_from_slice(&tag(version).to_le_bytes());
        Ok(8)
    }

    fn decode(buf: &[u8], version: hdds::dds::CdrVersion) -> hdds::Result<Self> {
        if buf.len() < 8 {
            return Err(hdds::Error::InvalidState(
                "Tagged: payload shorter than 8 bytes".to_string(),
            ));
        }
        let encoded_tag = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
        if encoded_tag != tag(version) {
            return Err(hdds::Error::InvalidState(format!(
                "Tagged: encoded with version tag {encoded_tag} but decoded as {version:?}"
            )));
        }
        Ok(Self {
            value: u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]),
        })
    }

    /// Two `u32`: the same body under XCDR1 and XCDR2, tagged by version.
    fn encodes_xcdr1_natively() -> bool {
        true
    }
}

fn drain(reader: &hdds::DataReader<Tagged>, expected: usize, timeout: Duration) -> Vec<u32> {
    let deadline = Instant::now() + timeout;
    let mut values = Vec::new();
    while values.len() < expected && Instant::now() < deadline {
        while let Some(sample) = reader.take().unwrap() {
            values.push(sample.value);
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    values
}

/// Write three samples, optionally with a reader already bound to the
/// writer while it writes, then bind a late joiner and return what its
/// replay delivers.
fn late_joiner_receives(name: &str, qos: QoS, with_live_reader: bool) -> Vec<u32> {
    let participant = Participant::builder(name)
        .domain_id(0)
        .with_transport(TransportMode::IntraProcess)
        .build()
        .unwrap();
    let topic = participant.topic::<Tagged>(name).unwrap();
    let writer = topic.writer().qos(qos.clone()).build().unwrap();
    let live = with_live_reader.then(|| topic.reader().qos(qos.clone()).build().unwrap());
    for value in [1, 2, 3] {
        writer.write(&Tagged { value }).unwrap();
    }
    if let Some(live) = &live {
        assert_eq!(
            drain(live, 3, Duration::from_secs(2)),
            vec![1, 2, 3],
            "live delivery must carry the writer's version"
        );
    }
    let late = topic.reader().qos(qos).build().unwrap();
    drain(&late, 3, Duration::from_secs(2))
}

fn transient_local() -> QoS {
    QoS::reliable().transient_local().keep_last(8)
}

#[test]
fn history_written_beside_a_live_reader_is_replayed_to_a_late_joiner() {
    // With a local reader already bound, the writer takes its intra-process
    // fast path, which must still feed the history cache: otherwise the late
    // joiner would replay an empty history although the writer is
    // TRANSIENT_LOCAL.
    assert_eq!(
        late_joiner_receives("replay_beside_live_reader", transient_local(), true),
        vec![1, 2, 3],
        "a durable writer must retain samples even when a reader was live"
    );
}

#[test]
fn xcdr1_history_written_beside_a_live_reader_is_replayed_and_decoded() {
    // Both defects at once: the fast path must journal, and the replay must
    // carry the XCDR1 version the journal recorded.
    assert_eq!(
        late_joiner_receives(
            "replay_xcdr1_beside_live_reader",
            transient_local().data_representation_xcdr1(),
            true,
        ),
        vec![1, 2, 3]
    );
}

#[test]
fn replay_decodes_with_the_writers_cdr_version() {
    // An XCDR1-only writer encodes every sample as XCDR1. The history cache
    // journals that version; the replayed ring entry must carry it too, or
    // the late joiner decodes the retained bytes under the default version
    // and gets nothing.
    assert_eq!(
        late_joiner_receives(
            "replay_cdr_version",
            transient_local().data_representation_xcdr1(),
            false,
        ),
        vec![1, 2, 3],
        "replayed history must carry the version it was encoded with"
    );
}
