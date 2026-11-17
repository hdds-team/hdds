// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! A reader in the same process as the writer sees its instances disposed
//! and unregistered (DDS 1.4 2.2.2.5.1 instance states), in order with the
//! samples around the change.
//!
//! A dispose or unregister must reach local readers too, not only remote
//! readers (as a key-only DATA on the wire): a local reader must not be left
//! with `[Alive]` and nothing else, intra-process or over UDP.

use hdds::dds::InstanceState;
use hdds::{DdsTrait, Participant, QoS, TransportMode};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq)]
struct Keyed {
    id: u32,
    value: u32,
}

#[derive(hdds::DDS)]
struct KeyedWire {
    id: u32,
    value: u32,
}

impl DdsTrait for Keyed {
    fn type_descriptor() -> &'static hdds::core::types::TypeDescriptor {
        KeyedWire::type_descriptor()
    }

    fn encode(&self, buf: &mut [u8], _version: hdds::dds::CdrVersion) -> hdds::Result<usize> {
        if buf.len() < 8 {
            return Err(hdds::Error::BufferTooSmall);
        }
        buf[..4].copy_from_slice(&self.id.to_le_bytes());
        buf[4..8].copy_from_slice(&self.value.to_le_bytes());
        Ok(8)
    }

    fn decode(buf: &[u8], _version: hdds::dds::CdrVersion) -> hdds::Result<Self> {
        if buf.len() < 8 {
            return Err(hdds::Error::InvalidState("short".to_string()));
        }
        Ok(Self {
            id: u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]),
            value: u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]),
        })
    }

    fn has_key() -> bool {
        true
    }

    fn compute_key(&self) -> [u8; 16] {
        let mut key = [0u8; 16];
        key[..4].copy_from_slice(&self.id.to_be_bytes());
        key
    }
}

fn states(
    reader: &hdds::DataReader<Keyed>,
    timeout: Duration,
) -> Vec<(Option<(u32, u32)>, InstanceState)> {
    let deadline = Instant::now() + timeout;
    let mut out = Vec::new();
    while Instant::now() < deadline {
        while let Some((sample, info)) = reader.take_with_info().unwrap() {
            out.push((sample.map(|s| (s.id, s.value)), info.instance_state));
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    out
}

/// What a reader saw, in order: `D(id,value)` for a sample, the instance
/// state for a transition. The state reported WITH a sample is left out:
/// DDS 1.4 2.2.2.5.1.3 makes it a snapshot taken at read/take time, so a
/// sample taken after its instance's dispose was received rightly reports
/// the instance disposed.
fn shape(seen: Vec<(Option<(u32, u32)>, InstanceState)>) -> Vec<String> {
    seen.into_iter()
        .map(|(data, state)| match data {
            Some((id, value)) => format!("D({id},{value})"),
            None => format!("{state:?}"),
        })
        .collect()
}

fn local_pair(
    name: &str,
    transport: TransportMode,
    writer_qos: QoS,
) -> (
    std::sync::Arc<Participant>,
    hdds::DataWriter<Keyed>,
    hdds::DataReader<Keyed>,
    Option<hdds::test_support::domains::DomainLease>,
) {
    let lease = matches!(transport, TransportMode::UdpMulticast)
        .then(hdds::test_support::domains::unique_domain);
    let participant = Participant::builder(name)
        .domain_id(lease.as_ref().map_or(0, |l| l.id()))
        .with_transport(transport)
        .build()
        .unwrap();
    let topic = participant.topic::<Keyed>(name).unwrap();
    let writer = topic.writer().qos(writer_qos).build().unwrap();
    let reader = topic
        .reader()
        .qos(QoS::reliable().keep_all())
        .build()
        .unwrap();
    std::thread::sleep(Duration::from_millis(100));
    (participant, writer, reader, lease)
}

#[test]
fn an_intra_process_reader_sees_the_instance_disposed() {
    let (_p, writer, reader, _lease) =
        local_pair("life_intra", TransportMode::IntraProcess, QoS::reliable());
    writer.write(&Keyed { id: 1, value: 10 }).unwrap();
    writer.dispose(&Keyed { id: 1, value: 10 }).unwrap();
    assert_eq!(
        shape(states(&reader, Duration::from_millis(500))),
        ["D(1,10)", "NotAliveDisposed"]
    );
}

#[test]
fn a_reader_of_the_same_participant_on_udp_sees_the_instance_disposed() {
    let (_p, writer, reader, _lease) =
        local_pair("life_udp", TransportMode::UdpMulticast, QoS::reliable());
    writer.write(&Keyed { id: 1, value: 10 }).unwrap();
    writer.dispose(&Keyed { id: 1, value: 10 }).unwrap();
    assert_eq!(
        shape(states(&reader, Duration::from_millis(1000))),
        ["D(1,10)", "NotAliveDisposed"]
    );
}

#[test]
fn a_dispose_is_seen_between_the_samples_around_it() {
    // Written, disposed, written again (the instance comes back alive): the
    // transition sits between the two samples, never ahead of the first nor
    // behind the second.
    let (_p, writer, reader, _lease) =
        local_pair("life_order", TransportMode::IntraProcess, QoS::reliable());
    writer.write(&Keyed { id: 1, value: 10 }).unwrap();
    writer.dispose(&Keyed { id: 1, value: 10 }).unwrap();
    writer.write(&Keyed { id: 1, value: 11 }).unwrap();
    assert_eq!(
        shape(states(&reader, Duration::from_millis(500))),
        ["D(1,10)", "NotAliveDisposed", "D(1,11)"]
    );
}

#[test]
fn an_unregister_without_autodispose_leaves_the_instance_with_no_writers() {
    let (_p, writer, reader, _lease) = local_pair(
        "life_unreg",
        TransportMode::IntraProcess,
        QoS::reliable().writer_data_lifecycle_manual_dispose(),
    );
    writer.write(&Keyed { id: 1, value: 10 }).unwrap();
    writer
        .unregister_instance(&Keyed { id: 1, value: 10 })
        .unwrap();
    assert_eq!(
        shape(states(&reader, Duration::from_millis(500))),
        ["D(1,10)", "NotAliveNoWriters"]
    );
}

/// Deleting a DataWriter unregisters its instances, and WRITER_DATA_LIFECYCLE
/// decides whether that disposes them (DDS 1.4 2.2.2.4.1.6, 2.2.3.21). With
/// the default (autodispose TRUE) a reader in the same participant sees the
/// instance NOT_ALIVE_DISPOSED once the writer is dropped.
#[test]
fn dropping_a_writer_with_autodispose_disposes_its_instances() {
    let (_p, writer, reader, _lease) = local_pair(
        "life_drop_auto",
        TransportMode::IntraProcess,
        QoS::reliable().writer_data_lifecycle_auto_dispose(),
    );
    writer.write(&Keyed { id: 1, value: 10 }).unwrap();
    drop(writer);
    assert_eq!(
        shape(states(&reader, Duration::from_millis(500))),
        ["D(1,10)", "NotAliveDisposed"]
    );
}

/// The same on UDP, where the local reader is reached through the merger
/// while remote readers get the key-only DATA.
#[test]
fn dropping_a_writer_with_autodispose_disposes_its_instances_on_udp() {
    let (_p, writer, reader, _lease) = local_pair(
        "life_drop_auto_udp",
        TransportMode::UdpMulticast,
        QoS::reliable(),
    );
    writer.write(&Keyed { id: 1, value: 10 }).unwrap();
    drop(writer);
    assert_eq!(
        shape(states(&reader, Duration::from_millis(1000))),
        ["D(1,10)", "NotAliveDisposed"]
    );
}

/// With autodispose FALSE the deletion unregisters only: the instance is
/// left NOT_ALIVE_NO_WRITERS.
#[test]
fn dropping_a_writer_without_autodispose_leaves_its_instances_with_no_writers() {
    let (_p, writer, reader, _lease) = local_pair(
        "life_drop_manual",
        TransportMode::IntraProcess,
        QoS::reliable().writer_data_lifecycle_manual_dispose(),
    );
    writer.write(&Keyed { id: 1, value: 10 }).unwrap();
    drop(writer);
    assert_eq!(
        shape(states(&reader, Duration::from_millis(500))),
        ["D(1,10)", "NotAliveNoWriters"]
    );
}

/// An instance the application disposed is not unregistered again by the
/// deletion, whatever the policy: the reader keeps it NOT_ALIVE_DISPOSED and
/// sees that transition once.
#[test]
fn dropping_a_writer_does_not_repeat_the_dispose_the_application_made() {
    for (name, qos) in [
        ("life_drop_disp_auto", QoS::reliable()),
        (
            "life_drop_disp_manual",
            QoS::reliable().writer_data_lifecycle_manual_dispose(),
        ),
    ] {
        let (_p, writer, reader, _lease) = local_pair(name, TransportMode::IntraProcess, qos);
        writer.write(&Keyed { id: 1, value: 10 }).unwrap();
        writer.dispose(&Keyed { id: 1, value: 10 }).unwrap();
        drop(writer);
        assert_eq!(
            shape(states(&reader, Duration::from_millis(500))),
            ["D(1,10)", "NotAliveDisposed"],
            "{name}"
        );
    }
}

#[test]
fn a_dispose_at_the_head_of_the_ring_is_not_overtaken_by_the_next_sample() {
    // The first sample is taken before the dispose is written, so the dispose
    // is the FIRST entry the next take pops, with a later sample behind it.
    let (_p, writer, reader, _lease) =
        local_pair("life_head", TransportMode::IntraProcess, QoS::reliable());
    writer.write(&Keyed { id: 1, value: 10 }).unwrap();
    assert_eq!(
        shape(states(&reader, Duration::from_millis(300))),
        ["D(1,10)"]
    );
    writer.dispose(&Keyed { id: 1, value: 10 }).unwrap();
    writer.write(&Keyed { id: 1, value: 11 }).unwrap();
    assert_eq!(
        shape(states(&reader, Duration::from_millis(500))),
        ["NotAliveDisposed", "D(1,11)"]
    );
}

#[test]
fn transitions_of_interleaved_instances_keep_their_places() {
    // A transition already waiting makes the next take pump the ring into
    // the cache: the second instance's dispose must still wait behind that
    // instance's own sample.
    let (_p, writer, reader, _lease) =
        local_pair("life_two", TransportMode::IntraProcess, QoS::reliable());
    writer.write(&Keyed { id: 1, value: 10 }).unwrap();
    writer.dispose(&Keyed { id: 1, value: 10 }).unwrap();
    writer.write(&Keyed { id: 2, value: 20 }).unwrap();
    writer.dispose(&Keyed { id: 2, value: 20 }).unwrap();
    writer.write(&Keyed { id: 1, value: 11 }).unwrap();
    assert_eq!(
        shape(states(&reader, Duration::from_millis(500))),
        [
            "D(1,10)",
            "NotAliveDisposed",
            "D(2,20)",
            "NotAliveDisposed",
            "D(1,11)"
        ]
    );
}

#[test]
fn with_two_local_writers_a_dispose_still_precedes_what_its_writer_wrote_next() {
    // A second local writer gives the reader a second ring, and the rings
    // are merged by pumping them all before taking. DDS orders nothing
    // across writers, but within one writer the dispose must come before
    // the sample written after it.
    let participant = Participant::builder("life_k2")
        .domain_id(0)
        .with_transport(TransportMode::IntraProcess)
        .build()
        .unwrap();
    let topic = participant.topic::<Keyed>("life_k2").unwrap();
    let first = topic.writer().qos(QoS::reliable()).build().unwrap();
    let second = topic.writer().qos(QoS::reliable()).build().unwrap();
    let reader = topic
        .reader()
        .qos(QoS::reliable().keep_all())
        .build()
        .unwrap();
    std::thread::sleep(Duration::from_millis(100));
    first.write(&Keyed { id: 1, value: 10 }).unwrap();
    assert_eq!(
        shape(states(&reader, Duration::from_millis(300))),
        ["D(1,10)"]
    );
    first.dispose(&Keyed { id: 1, value: 10 }).unwrap();
    first.write(&Keyed { id: 1, value: 11 }).unwrap();
    second.write(&Keyed { id: 2, value: 20 }).unwrap();
    let seen = shape(states(&reader, Duration::from_millis(500)));
    let at = |what: &str| seen.iter().position(|s| s == what);
    assert!(
        matches!((at("NotAliveDisposed"), at("D(1,11)")), (Some(d), Some(s)) if d < s),
        "the dispose must precede the sample its writer wrote after it: {seen:?}"
    );
    assert!(at("D(2,20)").is_some(), "{seen:?}");
}

#[test]
#[allow(deprecated)] // try_take is the legacy accessor under test here
fn the_legacy_try_take_skips_a_lifecycle_change_instead_of_decoding_it() {
    // try_take returns bare samples and cannot report a transition; the
    // lifecycle entry must not come out of it as a sample decoded from the
    // key hash bytes.
    let (_p, writer, reader, _lease) =
        local_pair("life_legacy", TransportMode::IntraProcess, QoS::reliable());
    writer.write(&Keyed { id: 1, value: 10 }).unwrap();
    writer.dispose(&Keyed { id: 1, value: 10 }).unwrap();
    writer.write(&Keyed { id: 1, value: 11 }).unwrap();
    std::thread::sleep(Duration::from_millis(100));
    let mut seen = Vec::new();
    while let Some(sample) = reader.try_take().unwrap() {
        seen.push((sample.id, sample.value));
    }
    assert_eq!(seen, vec![(1, 10), (1, 11)]);
}

#[derive(hdds::DDS, Debug, Clone)]
struct Reading {
    value: i64,
}

#[test]
fn a_content_filtered_reader_sees_the_dispose_of_what_it_received() {
    // A content filter selects DATA; a dispose carries no sample to test.
    // The network path hands transitions to the reader unfiltered, and so
    // must the local one: running the filter over the key hash bytes as if
    // they were a sample would drop the dispose.
    let participant = Participant::builder("life_cft")
        .domain_id(0)
        .with_transport(TransportMode::IntraProcess)
        .build()
        .unwrap();
    let cft = participant
        .create_content_filtered_topic::<Reading>(
            "life_cft_filtered",
            "life_cft",
            "value > %0",
            vec!["40".into()],
        )
        .unwrap();
    let reader = cft
        .reader()
        .qos(QoS::reliable().keep_all())
        .build()
        .unwrap();
    let writer = participant
        .topic::<Reading>("life_cft")
        .unwrap()
        .writer()
        .qos(QoS::reliable())
        .build()
        .unwrap();
    std::thread::sleep(Duration::from_millis(100));
    writer.write(&Reading { value: 50 }).unwrap();
    writer.dispose(&Reading { value: 50 }).unwrap();
    let deadline = Instant::now() + Duration::from_millis(500);
    let mut seen = Vec::new();
    while Instant::now() < deadline {
        while let Some((sample, info)) = reader.take_with_info().unwrap() {
            seen.push(match sample {
                Some(r) => format!("D({})", r.value),
                None => format!("{:?}", info.instance_state),
            });
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(seen, ["D(50)", "NotAliveDisposed"]);
}

/// A late joiner of a TRANSIENT_LOCAL writer is owed its history PER
/// INSTANCE, and a dispose is a change of that history (RTPS 2.5 8.2.3).
/// It must be part of it: the late joiner must not be handed the instance
/// ALIVE when the writer has disposed it.
fn late_joiner_shape(
    name: &str,
    transport: TransportMode,
    depth: u32,
    script: &[(bool, u32)],
) -> Vec<String> {
    let lease = matches!(transport, TransportMode::UdpMulticast)
        .then(hdds::test_support::domains::unique_domain);
    let participant = Participant::builder(name)
        .domain_id(lease.as_ref().map_or(0, |l| l.id()))
        .with_transport(transport)
        .build()
        .unwrap();
    let topic = participant.topic::<Keyed>(name).unwrap();
    let writer = topic
        .writer()
        .qos(QoS::reliable().transient_local().keep_last(depth))
        .build()
        .unwrap();
    for &(dispose, value) in script {
        let sample = Keyed { id: 1, value };
        if dispose {
            writer.dispose(&sample).unwrap();
        } else {
            writer.write(&sample).unwrap();
        }
    }
    let late = topic
        .reader()
        .qos(QoS::reliable().transient_local().keep_all())
        .build()
        .unwrap();
    shape(states(&late, Duration::from_millis(600)))
}

#[test]
fn a_late_joiner_of_depth_one_receives_the_dispose_that_replaced_the_sample() {
    assert_eq!(
        late_joiner_shape(
            "late_d1",
            TransportMode::IntraProcess,
            1,
            &[(false, 10), (true, 10)]
        ),
        ["NotAliveDisposed"]
    );
}

#[test]
fn a_late_joiner_of_depth_two_receives_the_sample_then_the_dispose() {
    assert_eq!(
        late_joiner_shape(
            "late_d2",
            TransportMode::IntraProcess,
            2,
            &[(false, 10), (true, 10)]
        ),
        ["D(1,10)", "NotAliveDisposed"]
    );
}

#[test]
fn a_late_joiner_after_a_resurrection_receives_the_instance_alive() {
    assert_eq!(
        late_joiner_shape(
            "late_res",
            TransportMode::IntraProcess,
            1,
            &[(false, 10), (true, 10), (false, 11)]
        ),
        ["D(1,11)"]
    );
}

#[test]
fn a_late_joiner_on_udp_receives_the_dispose_too() {
    assert_eq!(
        late_joiner_shape(
            "late_udp",
            TransportMode::UdpMulticast,
            1,
            &[(false, 10), (true, 10)]
        ),
        ["NotAliveDisposed"]
    );
}
