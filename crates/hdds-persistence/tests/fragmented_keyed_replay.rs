// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

use hdds::api::DDS as DdsTrait;
use hdds::dds::listener::DataReaderListener;
use hdds::{CdrVersion, Participant, QoS, TransportMode};
use hdds_persistence::dds_interface::{DdsInterface, DurabilityKind};
use hdds_persistence::hdds_interface::HddsDdsInterface;
use std::collections::HashSet;
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

#[derive(Clone, Debug, PartialEq, hdds::DDS)]
struct Blob {
    #[key]
    key: u32,
    bytes: Vec<u8>,
}

struct Arrivals(mpsc::Sender<Vec<u8>>);
impl<T: DdsTrait + hdds::core::ser::Cdr2Encode> DataReaderListener<T> for Arrivals {
    fn on_data_available(&self, value: &T) {
        let mut bytes = vec![0; value.max_cdr2_size()];
        let len = value.encode(&mut bytes, CdrVersion::Xcdr1).unwrap();
        bytes.truncate(len);
        self.0.send(bytes).unwrap();
    }
}

// RTPS 2.5 Sec.9.4.5.4/9.6.4.8: the first DATA_FRAG carries the
// sample's KeyHash, so an opaque reader keeps a depth budget per key.
fn fragmented_instances(replay: bool) {
    let domain = loop {
        let lease = hdds::test_support::domains::unique_domain();
        if (200..=230).contains(&lease.id()) {
            break lease;
        }
    };
    let sender = Participant::builder("fragmented_keys_sender")
        .domain_id(domain.id())
        .with_transport(TransportMode::UdpMulticast)
        .build()
        .unwrap();
    let receiver = Participant::builder("fragmented_keys_receiver")
        .domain_id(domain.id())
        .with_transport(TransportMode::UdpMulticast)
        .build()
        .unwrap();
    let values = [
        Blob {
            key: 1,
            bytes: vec![0xA1; 10_000],
        },
        Blob {
            key: 2,
            bytes: vec![0xB2; 10_000],
        },
    ];
    {
        let name = if replay {
            "fragmented_replay_keys"
        } else {
            "fragmented_native_keys"
        };
        let (tx, rx) = mpsc::channel();
        let raw = receiver
            .create_raw_reader_with_type(
                name,
                Blob::type_descriptor().type_name,
                Some(QoS::reliable().transient_local().keep_last(1)),
                None,
                Some(Arc::new(Arrivals(tx))),
            )
            .unwrap();
        let dds = HddsDdsInterface::new(sender.clone()).unwrap();
        let native;
        let relay;
        if replay {
            relay = Some(
                dds.create_writer(
                    name,
                    Blob::type_descriptor().type_name,
                    DurabilityKind::TransientLocal,
                )
                .unwrap(),
            );
            native = None;
        } else {
            native = Some(
                sender
                    .topic::<Blob>(name)
                    .unwrap()
                    .writer()
                    .qos(QoS::reliable().transient_local().keep_all())
                    .build()
                    .unwrap(),
            );
            relay = None;
        }
        for value in &values {
            if let Some(writer) = native.as_ref() {
                writer.write(value).unwrap();
            } else {
                let mut payload = vec![0; 11_000];
                let len = value.encode(&mut payload, CdrVersion::Xcdr1).unwrap();
                relay
                    .as_ref()
                    .unwrap()
                    .write_sample_with_key(&payload[..len], 1_000_000_000, 0, value.compute_key())
                    .unwrap();
            }
        }
        // A callback barrier waits for both distinct payloads to be admitted,
        // without taking either out of the KEEP_LAST reader prematurely.
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut arrived = HashSet::new();
        while arrived.len() < 2 {
            let bytes = rx
                .recv_timeout(deadline.saturating_duration_since(Instant::now()))
                .expect("both fragmented payloads arrive over UDP");
            arrived.insert(Blob::decode(&bytes, CdrVersion::Xcdr1).unwrap().key);
        }
        let samples = raw.try_take_raw_with_info_and_encoding().unwrap();
        assert_eq!(
            samples.len(),
            2,
            "depth one retains A and B (replay={replay})"
        );
        for value in &values {
            assert!(samples
                .iter()
                .any(
                    |(bytes, info, version)| info.instance_handle.0 == value.compute_key()
                        && Blob::decode(bytes, *version).unwrap() == *value
                ));
        }
    }
}

#[test]
fn fragmented_native_samples_keep_both_instances() {
    fragmented_instances(false);
}

#[test]
fn fragmented_replayed_samples_keep_both_instances() {
    fragmented_instances(true);
}
