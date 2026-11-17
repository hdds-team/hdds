// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! The request/offered rules of DDS v1.4 Sec.2.2.3 between a writer and a
//! reader of two UDP participants: each end judges the other on what the
//! other ANNOUNCED in SEDP, so both ends must reach the same verdict, report
//! it on their own status (OFFERED_INCOMPATIBLE_QOS at the writer,
//! REQUESTED_INCOMPATIBLE_QOS at the reader) and report the policy by its
//! QosPolicyId_t (DDS v1.4 Sec.2.3.3).
//!
//! The rules pinned here, as the specification states them:
//! - LIVELINESS (Sec.2.2.3.11): "offered kind >= requested kind", "AUTOMATIC
//!   < MANUAL_BY_PARTICIPANT < MANUAL_BY_TOPIC", and "offered
//!   lease_duration <= requested lease_duration".
//! - LATENCY_BUDGET (Sec.2.2.3.8): "offered duration <= requested duration".
//! - DESTINATION_ORDER (Sec.2.2.3.17): "offered kind >= requested kind",
//!   "BY_RECEPTION_TIMESTAMP < BY_SOURCE_TIMESTAMP".
//! - DEADLINE (Sec.2.2.3.7), DURABILITY (Sec.2.2.3.4), RELIABILITY
//!   (Sec.2.2.3.14), PRESENTATION (Sec.2.2.3.6), OWNERSHIP (Sec.2.2.3.9).

use hdds::api::DDS;
use hdds::core::types::TypeDescriptor;
use hdds::dds::qos::policy_id;
use hdds::dds::qos::{Liveliness, QoS};
use hdds::dds::{DataReaderListener, DataWriterListener, PublicationMatchedStatus};
use hdds::dds::{RequestedIncompatibleQosStatus, SubscriptionMatchedStatus};
use hdds::test_support::domains::unique_domain;
use hdds::{CdrVersion, Participant, TransportMode};
use std::sync::atomic::{AtomicI32, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
struct Value(i64);

impl DDS for Value {
    fn type_descriptor() -> &'static TypeDescriptor {
        static DESCRIPTOR: TypeDescriptor = TypeDescriptor {
            type_id: 0x5EC0_0A01,
            type_name: "RxoRulesValue",
            size_bytes: 8,
            alignment: 8,
            is_variable_size: false,
            fields: &[],
        };
        &DESCRIPTOR
    }
    fn encode(&self, buf: &mut [u8], _version: CdrVersion) -> hdds::api::Result<usize> {
        let dst = buf.get_mut(..8).ok_or(hdds::api::Error::BufferTooSmall)?;
        dst.copy_from_slice(&self.0.to_le_bytes());
        Ok(8)
    }
    fn decode(buf: &[u8], _version: CdrVersion) -> hdds::api::Result<Self> {
        let bytes: [u8; 8] = buf
            .get(..8)
            .and_then(|b| b.try_into().ok())
            .ok_or(hdds::api::Error::BufferTooSmall)?;
        Ok(Self(i64::from_le_bytes(bytes)))
    }
    fn encodes_xcdr1_natively() -> bool {
        true
    }
}

/// What one end reported.
#[derive(Default)]
struct Seen {
    current: AtomicI32,
    incompat: AtomicU32,
    last_policy: AtomicU32,
    names: Mutex<Vec<String>>,
}

impl DataWriterListener<Value> for Seen {
    fn on_publication_matched(&self, status: PublicationMatchedStatus) {
        self.current
            .store(status.current_count as i32, Ordering::SeqCst);
    }
    fn on_offered_incompatible_qos(&self, policy_id: u32, policy_name: &str) {
        self.last_policy.store(policy_id, Ordering::SeqCst);
        self.names.lock().unwrap().push(policy_name.to_string());
        self.incompat.fetch_add(1, Ordering::SeqCst);
    }
}

impl DataReaderListener<Value> for Seen {
    fn on_subscription_matched(&self, status: SubscriptionMatchedStatus) {
        self.current
            .store(status.current_count as i32, Ordering::SeqCst);
    }
    fn on_requested_incompatible_qos(&self, status: RequestedIncompatibleQosStatus) {
        self.last_policy
            .store(status.last_policy_id, Ordering::SeqCst);
        self.incompat.fetch_add(1, Ordering::SeqCst);
    }
}

fn wait_for(timeout: Duration, mut done: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if done() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    done()
}

fn participant(name: &str, domain: u32) -> Arc<Participant> {
    Participant::builder(name)
        .domain_id(domain)
        .with_transport(TransportMode::UdpMulticast)
        .build()
        .expect("participant")
}

/// A writer of `writer_qos` and a reader of `reader_qos`, of two
/// participants, until both ends reported a verdict; what each reported.
fn judge(
    name: &str,
    writer_qos: QoS,
    reader_qos: QoS,
    expect_match: bool,
) -> (Arc<Seen>, Arc<Seen>) {
    let domain = unique_domain();
    let publisher = participant(&format!("{name}_pub"), domain.id());
    let subscriber = participant(&format!("{name}_sub"), domain.id());
    let writer_seen = Arc::new(Seen::default());
    let reader_seen = Arc::new(Seen::default());
    let writer = publisher
        .topic::<Value>(name)
        .unwrap()
        .writer()
        .qos(writer_qos)
        .with_listener(Arc::clone(&writer_seen) as Arc<dyn DataWriterListener<Value>>)
        .build()
        .unwrap();
    let reader = subscriber
        .topic::<Value>(name)
        .unwrap()
        .reader()
        .qos(reader_qos)
        .with_listener(Arc::clone(&reader_seen) as Arc<dyn DataReaderListener<Value>>)
        .build()
        .unwrap();
    if expect_match {
        assert!(
            wait_for(Duration::from_secs(5), || {
                writer_seen.current.load(Ordering::SeqCst) == 1
                    && reader_seen.current.load(Ordering::SeqCst) == 1
            }),
            "{name}: both ends match"
        );
        // And the data flows.
        let mut delivered = false;
        for _ in 0..50 {
            writer.write(&Value(7)).unwrap();
            if wait_for(Duration::from_millis(100), || {
                reader.take().unwrap().is_some_and(|v| v.0 == 7)
            }) {
                delivered = true;
                break;
            }
        }
        assert!(delivered, "{name}: the sample is delivered");
    } else {
        assert!(
            wait_for(Duration::from_secs(5), || {
                writer_seen.incompat.load(Ordering::SeqCst) >= 1
                    && reader_seen.incompat.load(Ordering::SeqCst) >= 1
            }),
            "{name}: both ends report incompatible QoS (writer {}, reader {})",
            writer_seen.incompat.load(Ordering::SeqCst),
            reader_seen.incompat.load(Ordering::SeqCst)
        );
        assert_eq!(writer_seen.current.load(Ordering::SeqCst), 0, "{name}");
        assert_eq!(reader_seen.current.load(Ordering::SeqCst), 0, "{name}");
    }
    drop((writer, reader));
    drop(domain);
    (writer_seen, reader_seen)
}

fn secs(s: u64) -> Duration {
    Duration::from_secs(s)
}

/// Each refused pair is refused at BOTH ends, each reporting the policy's
/// QosPolicyId_t (the writer's listener also its name).
#[test]
fn both_ends_refuse_and_report_the_psm_policy_id() {
    let cases: Vec<(&str, QoS, QoS, u32)> = vec![
        (
            "liveliness_kind",
            QoS::reliable().liveliness(Liveliness::automatic(secs(10))),
            QoS::reliable().liveliness(Liveliness::manual_by_participant(secs(10))),
            policy_id::LIVELINESS,
        ),
        (
            "liveliness_topic_over_participant",
            QoS::reliable().liveliness(Liveliness::manual_by_participant(secs(10))),
            QoS::reliable().liveliness(Liveliness::manual_by_topic(secs(10))),
            policy_id::LIVELINESS,
        ),
        (
            "liveliness_lease",
            QoS::reliable().liveliness(Liveliness::automatic(secs(10))),
            QoS::reliable().liveliness(Liveliness::automatic(secs(5))),
            policy_id::LIVELINESS,
        ),
        (
            "latency_budget",
            QoS::reliable().latency_budget_millis(100),
            QoS::reliable().latency_budget_millis(10),
            policy_id::LATENCY_BUDGET,
        ),
        (
            "destination_order",
            QoS::reliable().destination_order_by_reception(),
            QoS::reliable().destination_order_by_source(),
            policy_id::DESTINATION_ORDER,
        ),
        (
            "deadline",
            QoS::reliable().deadline_millis(200),
            QoS::reliable().deadline_millis(100),
            policy_id::DEADLINE,
        ),
        (
            "durability",
            QoS::reliable(),
            QoS::reliable().transient_local(),
            policy_id::DURABILITY,
        ),
        (
            "reliability",
            QoS::best_effort(),
            QoS::reliable(),
            policy_id::RELIABILITY,
        ),
        (
            "presentation",
            QoS::reliable().presentation_instance(),
            QoS::reliable().presentation_topic_coherent(),
            policy_id::PRESENTATION,
        ),
        (
            "ownership",
            QoS::reliable().ownership_exclusive(),
            QoS::reliable(),
            policy_id::OWNERSHIP,
        ),
    ];
    for (name, writer_qos, reader_qos, id) in cases {
        let topic = format!("rxo_refused_{name}");
        let (writer_seen, reader_seen) = judge(&topic, writer_qos, reader_qos, false);
        assert_eq!(
            writer_seen.last_policy.load(Ordering::SeqCst),
            id,
            "{name}: the writer reports {}",
            policy_id::name(id)
        );
        assert_eq!(
            reader_seen.last_policy.load(Ordering::SeqCst),
            id,
            "{name}: the reader reports {}",
            policy_id::name(id)
        );
        assert!(
            writer_seen
                .names
                .lock()
                .unwrap()
                .iter()
                .all(|n| n == policy_id::name(id)),
            "{name}: {:?}",
            writer_seen.names.lock().unwrap()
        );
    }
}

/// A writer offering more than the reader requests matches at both ends and
/// delivers: a stronger LIVELINESS kind with a shorter lease, a smaller
/// LATENCY_BUDGET, BY_SOURCE_TIMESTAMP to a BY_RECEPTION_TIMESTAMP reader.
#[test]
fn a_stronger_offer_matches_at_both_ends() {
    let cases: Vec<(&str, QoS, QoS)> = vec![
        (
            "liveliness_topic_to_automatic",
            QoS::reliable().liveliness(Liveliness::manual_by_topic(secs(5))),
            QoS::reliable().liveliness(Liveliness::automatic(secs(10))),
        ),
        (
            "liveliness_participant_to_automatic",
            QoS::reliable().liveliness(Liveliness::manual_by_participant(secs(5))),
            QoS::reliable(),
        ),
        (
            "latency_budget",
            QoS::reliable().latency_budget_millis(10),
            QoS::reliable().latency_budget_millis(100),
        ),
        (
            "destination_order",
            QoS::reliable().destination_order_by_source(),
            QoS::reliable().destination_order_by_reception(),
        ),
    ];
    for (name, writer_qos, reader_qos) in cases {
        let topic = format!("rxo_matched_{name}");
        let (writer_seen, reader_seen) = judge(&topic, writer_qos, reader_qos, true);
        assert_eq!(writer_seen.incompat.load(Ordering::SeqCst), 0, "{name}");
        assert_eq!(reader_seen.incompat.load(Ordering::SeqCst), 0, "{name}");
    }
}
