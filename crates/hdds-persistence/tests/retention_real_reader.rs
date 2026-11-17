// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

use hdds::api::DDS as DdsTrait;
use hdds::{Participant, QoS, TransportMode};
use hdds_persistence::dds_interface::{DdsInterface, DurabilityKind};
use hdds_persistence::{HddsDdsInterface, PersistenceStore, SqliteStore};

#[derive(hdds::DDS, Debug, Clone, PartialEq)]
struct KeyedState {
    #[key]
    key: u32,
    value: u32,
}

// DDS v1.4 Sec.2.2.3.5 and Sec.2.2.3.18: a durability service's depth
// applies to each instance. Exercise capture and SampleInfo, not fabricated
// store handles, on live delivery and the writer's local history replay.
#[test]
fn real_raw_reader_retains_two_instances_at_depth_one() {
    let domain = loop {
        let lease = hdds::test_support::domains::unique_domain();
        if (200..=230).contains(&lease.id()) {
            break lease;
        }
    };
    let participant = Participant::builder("raw_key_retention")
        .domain_id(domain.id())
        .with_transport(TransportMode::UdpMulticast)
        .build()
        .unwrap();
    let dds = HddsDdsInterface::new(participant.clone()).unwrap();
    for capture_first in [true, false] {
        let name = format!("raw_key_retention_{capture_first}");
        let topic = participant.topic::<KeyedState>(&name).unwrap();
        let writer = topic
            .writer()
            .qos(QoS::reliable().persistent().keep_last(1))
            .build()
            .unwrap();
        let create_capture = || {
            dds.create_reader(
                &name,
                KeyedState::type_descriptor().type_name,
                DurabilityKind::Persistent,
            )
            .unwrap()
        };
        let capture = capture_first.then(create_capture);
        let a1 = KeyedState { key: 1, value: 10 };
        let b = KeyedState { key: 2, value: 20 };
        let a2 = KeyedState { key: 1, value: 30 };
        for value in [&a1, &b, &a2] {
            writer.write(value).unwrap();
        }
        let capture = capture.unwrap_or_else(create_capture);
        let received = capture.take().unwrap();
        assert_eq!(received.len(), if capture_first { 3 } else { 2 });
        let store = SqliteStore::new_in_memory().unwrap();
        for sample in received {
            store.save(&sample.into()).unwrap();
        }
        store.apply_retention(&name, 1).unwrap();
        let kept = store.load(&name).unwrap();
        assert_eq!(kept.len(), 2, "each key has its own depth budget");
        for expected in [&b, &a2] {
            let sample = kept
                .iter()
                .find(|s| s.instance_handle == expected.compute_key())
                .unwrap();
            let version =
                hdds::CdrVersion::from_representation_code(sample.representation).unwrap();
            assert_eq!(
                KeyedState::decode(&sample.payload, version).unwrap(),
                *expected
            );
        }
    }
}
