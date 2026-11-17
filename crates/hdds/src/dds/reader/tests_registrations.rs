// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! An instance written by two remote DataWriters, as a reader sees it when
//! one of them unregisters it, disposes it, or leaves (DDS v1.4
//! Sec.2.2.2.4.2.7, Sec.2.2.2.5.1.3, Sec.2.2.3.23.3).
//!
//! Every sample and every lifecycle change is classified and enters through
//! `route_data_packet`, as a datagram another implementation would send (an
//! RTPS 2.5 header with a foreign vendor id, little-endian DATA submessages);
//! a writer's departure enters through `TopicRegistry::notify_writer_dispose`,
//! what the SEDP endpoint dispose calls. What is asserted is what the
//! application takes.

use super::ReaderBuilder;
use crate::core::discovery::multicast::{classify_rtps, PacketKind};
use crate::core::rt;
use crate::dds::{DataReader, InstanceState, QoS, ViewState, DDS};
use crate::engine::subscriber::DisposeKind;
use crate::engine::{route_data_packet, RouteStatus, RouterMetrics, Subscriber, TopicRegistry};
use std::sync::Arc;

/// Wire twin of [`Instance`]: the derive has no key handling, so the keyed
/// type delegates its codec here and hand-writes the key.
#[derive(Debug, Clone, Copy, PartialEq, crate::DDS)]
struct InstanceWire {
    key: i64,
    value: i64,
}

#[derive(Debug, Clone, Copy, PartialEq)]
struct Instance {
    key: i64,
    value: i64,
}

impl DDS for Instance {
    fn type_descriptor() -> &'static crate::core::types::TypeDescriptor {
        InstanceWire::type_descriptor()
    }

    fn encode(&self, buf: &mut [u8], version: crate::dds::CdrVersion) -> crate::dds::Result<usize> {
        InstanceWire {
            key: self.key,
            value: self.value,
        }
        .encode(buf, version)
    }

    fn decode(buf: &[u8], version: crate::dds::CdrVersion) -> crate::dds::Result<Self> {
        let wire = InstanceWire::decode(buf, version)?;
        Ok(Self {
            key: wire.key,
            value: wire.value,
        })
    }

    fn compute_key(&self) -> [u8; 16] {
        let mut hash = [0u8; 16];
        hash[..8].copy_from_slice(&self.key.to_le_bytes());
        hash[8..].copy_from_slice(&(self.key ^ 0x5A5A_5A5A_5A5A_5A5A_i64).to_le_bytes());
        hash
    }
}

/// The instance every test writes.
const KEY: i64 = 7;

/// Writer A and writer B, each of its own participant.
const A: [u8; 16] = [
    0x01, 0x0f, 0xa1, 0xa1, 0x0e, 0x00, 0xad, 0xef, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x01, 0x02,
];
const B: [u8; 16] = [
    0x01, 0x0f, 0xb2, 0xb2, 0x0e, 0x00, 0xad, 0xef, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x01, 0x02,
];

/// StatusInfo flags (RTPS v2.5 Sec.9.6.4.9).
const DISPOSED: u8 = 0x01;
const UNREGISTERED: u8 = 0x02;

fn key_hash() -> [u8; 16] {
    Instance { key: KEY, value: 0 }.compute_key()
}

/// One DATA submessage of `writer` as change `sn`, little-endian
/// (RTPS v2.5 Sec.9.4.5.3): `flags` beyond E, an inline QoS of StatusInfo
/// `status` and the KeyHash (Sec.9.6.4.8) when `status` is `Some`, then
/// `payload`.
fn datagram(writer: [u8; 16], sn: u32, flags: u8, status: Option<u8>, payload: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&[0, 0]); // extraFlags
    body.extend_from_slice(&16u16.to_le_bytes()); // octetsToInlineQos
    body.extend_from_slice(&[0, 0, 0, 0]); // readerId: ENTITYID_UNKNOWN
    body.extend_from_slice(&writer[12..]);
    body.extend_from_slice(&0u32.to_le_bytes()); // writerSN high
    body.extend_from_slice(&sn.to_le_bytes()); // writerSN low
    if let Some(status) = status {
        body.extend_from_slice(&[0x71, 0x00, 0x04, 0x00, 0, 0, 0, status]);
        body.extend_from_slice(&[0x70, 0x00, 0x10, 0x00]);
        body.extend_from_slice(&key_hash());
        body.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]); // PID_SENTINEL
    }
    body.extend_from_slice(payload);
    assert_eq!(body.len() % 4, 0, "the next header stays aligned");
    let mut packet = Vec::new();
    packet.extend_from_slice(b"RTPS");
    packet.extend_from_slice(&[2, 5, 0x01, 0x0f]);
    packet.extend_from_slice(&writer[..12]);
    packet.extend_from_slice(&[0x15, 0x01 | flags]);
    packet.extend_from_slice(&u16::try_from(body.len()).expect("fits").to_le_bytes());
    packet.extend_from_slice(&body);
    packet
}

/// CDR2_LE encapsulation of the sample `(KEY, value)`.
fn serialized(value: i64) -> Vec<u8> {
    let mut buf = vec![0u8; 64];
    let len = Instance { key: KEY, value }
        .encode(&mut buf[4..], crate::dds::CdrVersion::Xcdr2)
        .expect("encode");
    buf[..4].copy_from_slice(&[0x00, 0x07, 0x00, 0x00]);
    buf.truncate(4 + len);
    buf
}

/// The reader, its subscriber registered on a topic registry that knows
/// both writers.
struct Fixture {
    reader: Arc<DataReader<Instance>>,
    registry: TopicRegistry,
}

impl Fixture {
    fn new(topic: &str) -> Self {
        let _ = rt::init_slab_pool();
        let reader = Arc::new(
            ReaderBuilder::<Instance>::new(topic.to_string())
                .qos(QoS::best_effort().keep_last(16))
                .network_ring_for_test()
                .build()
                .expect("reader build should succeed"),
        );
        let network_ring = Arc::clone(reader.network_ring_for_test().expect("network ring"));
        let sub = Arc::new(
            super::subscriber::ReaderSubscriber::<Instance>::new(
                topic.to_string(),
                network_ring,
                reader.get_status_condition(),
                None,
                None,
                None,
                Arc::clone(reader.dispose_queue_for_test()),
                Arc::new(std::sync::Mutex::new(super::reorder::ReorderGate::new(
                    false, false,
                ))),
            )
            .with_room(reader.network_room_for_test().cloned()),
        );
        let registry = TopicRegistry::new();
        registry
            .register_subscriber(sub as Arc<dyn Subscriber>)
            .expect("register subscriber");
        registry.register_writer_guid(A, topic.to_string());
        registry.register_writer_guid(B, topic.to_string());
        Self { reader, registry }
    }

    /// The datagram through the door a received one takes: classified,
    /// then routed at the offset the classifier names.
    fn route(&self, packet: &[u8]) {
        let (kind, offset, _, _) = classify_rtps(packet);
        assert_eq!(kind, PacketKind::Data);
        assert_eq!(
            route_data_packet(
                packet,
                packet.len(),
                offset,
                &self.registry,
                &RouterMetrics::new()
            ),
            RouteStatus::Delivered
        );
    }

    /// `writer` writes the instance as its change `sn`.
    fn write(&self, writer: [u8; 16], sn: u32, value: i64) {
        self.route(&datagram(writer, sn, 0x04, None, &serialized(value)));
    }

    /// `writer` sends a key-only lifecycle change (D=0 K=1 Q=1) as its
    /// change `sn`, the serialized key after the inline QoS.
    fn key_only(&self, writer: [u8; 16], sn: u32, status: u8) {
        let mut key = vec![0x00, 0x01, 0x00, 0x00];
        key.extend_from_slice(&KEY.to_le_bytes());
        self.route(&datagram(writer, sn, 0x0a, Some(status), &key));
    }

    /// `writer` writes the instance as its change `sn` and unregisters it in
    /// the same DATA (D=1 with StatusInfo, RTPS v2.5 Sec.9.6.4.9).
    fn write_and_unregister(&self, writer: [u8; 16], sn: u32, value: i64) {
        self.route(&datagram(
            writer,
            sn,
            0x06,
            Some(UNREGISTERED),
            &serialized(value),
        ));
    }

    /// `writer` left (its SEDP endpoint dispose).
    fn depart(&self, writer: [u8; 16]) {
        assert!(self
            .registry
            .notify_writer_dispose(writer, DisposeKind::Unregistered));
    }

    /// Everything the application can take now: the value (None for a
    /// transition), the instance state and the view state.
    fn take_all(&self) -> Vec<(Option<i64>, InstanceState, ViewState)> {
        let mut taken = Vec::new();
        while let Some((data, info)) = self.reader.take_with_info().expect("take_with_info") {
            assert_eq!(info.instance_handle.0, key_hash(), "one instance");
            taken.push((
                data.map(|sample| sample.value),
                info.instance_state,
                info.view_state,
            ));
        }
        taken
    }
}

/// A writer that unregistered an instance no longer writes it, and does not
/// keep it alive past the departure of the writer that wrote it after:
/// DDS v1.4 Sec.2.2.2.4.2.7, an instance loses its writers "if no other
/// DataWriter entities are writing the instance", and Sec.2.2.3.23.3,
/// "Deleting a DataWriter is equivalent to unregistering all the instances
/// it was writing".
#[test]
fn a_writer_that_unregistered_does_not_keep_the_instance_past_the_last_writers_departure() {
    let f = Fixture::new("registrations-unregistered-then-departed");
    f.write(A, 1, 10);
    f.key_only(A, 2, UNREGISTERED);
    assert_eq!(
        f.take_all(),
        vec![
            (Some(10), InstanceState::NotAliveNoWriters, ViewState::New),
            (None, InstanceState::NotAliveNoWriters, ViewState::NotNew),
        ],
        "A was its only writer"
    );

    f.write(B, 3, 30);
    assert_eq!(
        f.take_all(),
        vec![(Some(30), InstanceState::Alive, ViewState::New)],
        "B brings it back, a new generation"
    );

    f.depart(B);
    assert_eq!(
        f.take_all(),
        vec![(None, InstanceState::NotAliveNoWriters, ViewState::NotNew)],
        "B was its last writer: A had let it go"
    );

    f.depart(A);
    assert_eq!(
        f.take_all(),
        vec![],
        "A's departure releases nothing it had not already let go"
    );
}

/// An unregister from one of two writers leaves the instance ALIVE, with no
/// transition for the application, and the other writer's next sample
/// continues the same generation: NOT_NEW.
#[test]
fn an_unregister_from_one_of_two_writers_keeps_the_instance_alive_and_not_new() {
    let f = Fixture::new("registrations-one-of-two-unregisters");
    f.write(A, 1, 10);
    f.write(B, 1, 20);
    assert_eq!(
        f.take_all(),
        vec![
            (Some(10), InstanceState::Alive, ViewState::New),
            (Some(20), InstanceState::Alive, ViewState::NotNew),
        ]
    );

    f.key_only(A, 2, UNREGISTERED);
    assert_eq!(f.take_all(), vec![], "B still writes the instance");

    f.write(B, 2, 21);
    assert_eq!(
        f.take_all(),
        vec![(Some(21), InstanceState::Alive, ViewState::NotNew)],
        "the same generation, already viewed"
    );
}

/// The last of two writers to unregister leaves the instance with no
/// writers. B's unregister rides its final sample (D=1 with StatusInfo).
#[test]
fn the_last_of_two_writers_to_unregister_leaves_the_instance_without_writers() {
    let f = Fixture::new("registrations-last-of-two-unregisters");
    f.write(A, 1, 10);
    f.write(B, 1, 20);
    assert_eq!(f.take_all().len(), 2);

    f.key_only(A, 2, UNREGISTERED);
    assert_eq!(f.take_all(), vec![], "B still writes the instance");

    f.write_and_unregister(B, 2, 21);
    assert_eq!(
        f.take_all(),
        vec![
            (
                Some(21),
                InstanceState::NotAliveNoWriters,
                ViewState::NotNew
            ),
            (None, InstanceState::NotAliveNoWriters, ViewState::NotNew),
        ],
        "no writer is left"
    );
}

/// A dispose applies whichever of the writers sends it (SHARED ownership,
/// DDS v1.4 Sec.2.2.2.5.1.3: NOT_ALIVE_DISPOSED "if any DataWriter
/// explicitly disposes the instance").
#[test]
fn a_dispose_from_either_writer_disposes_the_instance() {
    let f = Fixture::new("registrations-dispose-from-either");
    f.write(A, 1, 10);
    f.write(B, 1, 20);
    assert_eq!(f.take_all().len(), 2);

    f.key_only(A, 2, DISPOSED);
    assert_eq!(
        f.take_all(),
        vec![(None, InstanceState::NotAliveDisposed, ViewState::NotNew)],
        "A disposed it"
    );

    f.write(B, 2, 21);
    assert_eq!(
        f.take_all(),
        vec![(Some(21), InstanceState::Alive, ViewState::New)],
        "written again: alive, a new generation"
    );

    f.key_only(B, 3, DISPOSED);
    assert_eq!(
        f.take_all(),
        vec![(None, InstanceState::NotAliveDisposed, ViewState::NotNew)],
        "B disposed it"
    );
}

/// A dispose is not an unregister (DDS v1.4 Sec.2.2.3.23.3): the writer
/// that disposed the instance still holds it, so another writer's
/// unregister leaves it ALIVE, and the instance loses its writers when the
/// disposing writer leaves too.
#[test]
fn a_dispose_leaves_its_writer_holding_the_instance() {
    let f = Fixture::new("registrations-dispose-keeps-registration");
    f.write(A, 1, 10);
    f.key_only(A, 2, DISPOSED);
    assert_eq!(
        f.take_all(),
        vec![
            (Some(10), InstanceState::NotAliveDisposed, ViewState::New),
            (None, InstanceState::NotAliveDisposed, ViewState::NotNew),
        ]
    );
    f.write(B, 1, 20);
    assert_eq!(
        f.take_all(),
        vec![(Some(20), InstanceState::Alive, ViewState::New)],
        "B writes it again: alive, a new generation"
    );

    f.key_only(B, 2, UNREGISTERED);
    assert_eq!(f.take_all(), vec![], "A disposed it but still writes it");

    f.depart(A);
    assert_eq!(
        f.take_all(),
        vec![(None, InstanceState::NotAliveNoWriters, ViewState::NotNew)],
        "A, its last writer, left"
    );
}
