// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! A remote writer's samples reach a local reader only when that (writer,
//! reader) pair is matched, whatever the other readers of the topic in the
//! same participant are.
//!
//! DDS v1.4 Sec.2.2.3: "for the Subscriber to receive data the DataReader's
//! requested value must be compatible with the DataWriter's offered value",
//! and an incompatible pair is recorded as OFFERED_INCOMPATIBLE_QOS on the
//! publisher end and REQUESTED_INCOMPATIBLE_QOS on the subscriber end.
//!
//! The defect this pins: the data plane blocked a remote writer only when it
//! was incompatible with EVERY local reader of its topic. With one
//! compatible sibling, a reader told REQUESTED_INCOMPATIBLE received every
//! sample all the same.
//!
//! Each test builds two UDP participants (writer in one, readers in the
//! other), waits for both ends to report, writes, and compares what each
//! reader took with what its status says.

use hdds::dds::{
    DataReaderListener, DataWriterListener, PublicationMatchedStatus,
    RequestedIncompatibleQosStatus, SubscriptionMatchedStatus,
};
use hdds::{DataReader, DataWriter, Participant, QoS, TransportMode};
use std::sync::atomic::{AtomicI32, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(hdds::DDS, Debug, Clone)]
struct Probe {
    value: i64,
}

const SAMPLES: i64 = 20;

#[derive(Default)]
struct Seen {
    current: AtomicI32,
    incompat: AtomicU32,
}

impl DataWriterListener<Probe> for Seen {
    fn on_publication_matched(&self, status: PublicationMatchedStatus) {
        self.current
            .store(status.current_count as i32, Ordering::SeqCst);
    }
    fn on_offered_incompatible_qos(&self, _policy_id: u32, _policy_name: &str) {
        self.incompat.fetch_add(1, Ordering::SeqCst);
    }
}

impl DataReaderListener<Probe> for Seen {
    fn on_subscription_matched(&self, status: SubscriptionMatchedStatus) {
        self.current
            .store(status.current_count as i32, Ordering::SeqCst);
    }
    fn on_requested_incompatible_qos(&self, _status: RequestedIncompatibleQosStatus) {
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

struct Reader {
    reader: DataReader<Probe>,
    seen: Arc<Seen>,
    got: usize,
}

impl Reader {
    fn new(participant: &Arc<Participant>, topic: &str, qos: QoS) -> Self {
        let seen = Arc::new(Seen::default());
        let reader = participant
            .topic::<Probe>(topic)
            .expect("topic")
            .reader()
            .qos(qos)
            .with_listener(Arc::clone(&seen) as Arc<dyn DataReaderListener<Probe>>)
            .build()
            .expect("reader");
        Self {
            reader,
            seen,
            got: 0,
        }
    }

    fn drain(&mut self) -> usize {
        while self.reader.take().expect("take").is_some() {
            self.got += 1;
        }
        self.got
    }

    fn matched(&self) -> i32 {
        self.seen.current.load(Ordering::SeqCst)
    }

    fn incompatible(&self) -> bool {
        self.seen.incompat.load(Ordering::SeqCst) > 0
    }
}

struct Writer {
    writer: DataWriter<Probe>,
    seen: Arc<Seen>,
}

impl Writer {
    fn new(participant: &Arc<Participant>, topic: &str, qos: QoS) -> Self {
        let seen = Arc::new(Seen::default());
        let writer = participant
            .topic::<Probe>(topic)
            .expect("topic")
            .writer()
            .qos(qos)
            .with_listener(Arc::clone(&seen) as Arc<dyn DataWriterListener<Probe>>)
            .build()
            .expect("writer");
        Self { writer, seen }
    }

    fn write_all(&self) {
        for value in 0..SAMPLES {
            self.writer.write(&Probe { value }).expect("write");
            std::thread::sleep(Duration::from_millis(2));
        }
    }
}

/// How the incompatible pair is reported.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Refusal {
    /// REQUESTED_INCOMPATIBLE at the reader, OFFERED_INCOMPATIBLE at the
    /// writer (an RxO policy).
    Reported,
    /// Not matched and told nothing (a PARTITION mismatch).
    Silent,
}

/// Write once both ends decided, and wait for the compatible reader to have
/// taken every sample; then leave the incompatible one room to receive a
/// straggler.
fn write_and_settle(writer: &Writer, compatible: &mut Reader, incompatible: &mut Reader) {
    // Room for a late, contradicting report.
    std::thread::sleep(Duration::from_millis(300));
    writer.write_all();
    wait_for(Duration::from_secs(5), || {
        compatible.drain() == SAMPLES as usize
    });
    std::thread::sleep(Duration::from_millis(300));
    compatible.drain();
    incompatible.drain();
}

fn assert_outcome(
    case: &str,
    writer: &Writer,
    compatible: &Reader,
    incompatible: &Reader,
    refusal: Refusal,
) {
    assert_eq!(
        compatible.got, SAMPLES as usize,
        "{case}: the compatible reader takes every sample"
    );
    assert_eq!(compatible.matched(), 1, "{case}: compatible reader matched");
    assert!(
        !compatible.incompatible(),
        "{case}: compatible reader told nothing incompatible"
    );
    assert_eq!(
        incompatible.matched(),
        0,
        "{case}: incompatible reader not matched"
    );
    assert_eq!(
        incompatible.incompatible(),
        refusal == Refusal::Reported,
        "{case}: incompatible reader's REQUESTED_INCOMPATIBLE_QOS"
    );
    assert_eq!(
        writer.seen.current.load(Ordering::SeqCst),
        1,
        "{case}: the writer is matched with the compatible reader only"
    );
    assert_eq!(
        writer.seen.incompat.load(Ordering::SeqCst) > 0,
        refusal == Refusal::Reported,
        "{case}: the writer's OFFERED_INCOMPATIBLE_QOS"
    );
    assert_eq!(
        incompatible.got, 0,
        "{case}: a reader not matched with the writer received its samples"
    );
}

/// Two readers of one topic in one participant, one compatible with the
/// remote writer and one not: the incompatible one takes nothing, the
/// compatible one everything, and both ends say so.
fn siblings(case: &str, writer_qos: QoS, compatible: QoS, incompatible: QoS, refusal: Refusal) {
    let lease = hdds::test_support::domains::unique_domain();
    let pa = participant(&format!("{case}_pub"), lease.id());
    let pb = participant(&format!("{case}_sub"), lease.id());
    let topic = format!("rxo_sib_{case}");
    let mut incompatible = Reader::new(&pb, &topic, incompatible);
    let mut compatible = Reader::new(&pb, &topic, compatible);
    let writer = Writer::new(&pa, &topic, writer_qos);
    wait_for(Duration::from_secs(5), || {
        compatible.matched() == 1
            && writer.seen.current.load(Ordering::SeqCst) == 1
            && (refusal == Refusal::Silent
                || (incompatible.incompatible() && writer.seen.incompat.load(Ordering::SeqCst) > 0))
    });
    write_and_settle(&writer, &mut compatible, &mut incompatible);
    assert_outcome(case, &writer, &compatible, &incompatible, refusal);
}

#[test]
fn reliability_best_effort_writer_reliable_sibling() {
    siblings(
        "reliability",
        QoS::best_effort(),
        QoS::best_effort(),
        QoS::reliable(),
        Refusal::Reported,
    );
}

#[test]
fn durability_volatile_writer_transient_local_sibling() {
    siblings(
        "durability",
        QoS::reliable(),
        QoS::reliable(),
        QoS::reliable().transient_local(),
        Refusal::Reported,
    );
}

#[test]
fn deadline_slower_writer_than_one_sibling_requests() {
    siblings(
        "deadline",
        QoS::reliable().deadline_millis(200),
        QoS::reliable().deadline_millis(500),
        QoS::reliable().deadline_millis(100),
        Refusal::Reported,
    );
}

/// The writer refuses the MANUAL_BY_PARTICIPANT reader on RxO (offered
/// AUTOMATIC < requested MANUAL_BY_PARTICIPANT, DDS v1.4 Sec.2.2.3.11) and
/// matches the AUTOMATIC one, same as every other QoS pinned in this
/// file.
#[test]
fn liveliness_automatic_writer_manual_sibling() {
    let lease = hdds::test_support::domains::unique_domain();
    let pa = participant("liveliness_pub", lease.id());
    let pb = participant("liveliness_sub", lease.id());
    let topic = "rxo_sib_liveliness";
    let mut incompatible = Reader::new(
        &pb,
        topic,
        QoS::reliable().liveliness_manual_participant_secs(10),
    );
    let mut compatible = Reader::new(&pb, topic, QoS::reliable());
    let writer = Writer::new(&pa, topic, QoS::reliable());
    wait_for(Duration::from_secs(5), || {
        compatible.matched() == 1 && incompatible.incompatible()
    });
    write_and_settle(&writer, &mut compatible, &mut incompatible);
    assert_eq!(compatible.got, SAMPLES as usize);
    assert_eq!(compatible.matched(), 1);
    assert_eq!(incompatible.matched(), 0);
    assert!(incompatible.incompatible());
    assert_eq!(
        incompatible.got, 0,
        "liveliness: a reader not matched with the writer received its samples"
    );
}

#[test]
fn presentation_instance_writer_topic_coherent_sibling() {
    siblings(
        "presentation",
        QoS::reliable(),
        QoS::reliable(),
        QoS::reliable().presentation_topic_coherent(),
        Refusal::Reported,
    );
}

#[test]
fn ownership_exclusive_writer_shared_sibling() {
    siblings(
        "ownership",
        QoS::reliable().ownership_exclusive().ownership_strength(5),
        QoS::reliable().ownership_exclusive(),
        QoS::reliable(),
        Refusal::Reported,
    );
}

#[test]
fn data_representation_default_writer_xcdr2_sibling() {
    siblings(
        "datarep",
        QoS::reliable(),
        QoS::reliable(),
        QoS::reliable().data_representation_xcdr2(),
        Refusal::Reported,
    );
}

#[test]
fn partition_disjoint_sibling() {
    siblings(
        "partition",
        QoS::reliable().partition_single("A"),
        QoS::reliable().partition_single("A"),
        QoS::reliable().partition_single("B"),
        Refusal::Silent,
    );
}

/// The incompatible reader is created after the writer matched its
/// compatible sibling: it is judged when it registers, and takes nothing.
#[test]
fn an_incompatible_reader_created_later_takes_nothing() {
    let lease = hdds::test_support::domains::unique_domain();
    let pa = participant("later_incompat_pub", lease.id());
    let pb = participant("later_incompat_sub", lease.id());
    let topic = "rxo_later_incompat";
    let mut compatible = Reader::new(&pb, topic, QoS::best_effort());
    let writer = Writer::new(&pa, topic, QoS::best_effort());
    assert!(wait_for(Duration::from_secs(5), || {
        compatible.matched() == 1 && writer.seen.current.load(Ordering::SeqCst) == 1
    }));
    let mut incompatible = Reader::new(&pb, topic, QoS::reliable());
    wait_for(Duration::from_secs(5), || {
        incompatible.incompatible() && writer.seen.incompat.load(Ordering::SeqCst) > 0
    });
    write_and_settle(&writer, &mut compatible, &mut incompatible);
    assert_outcome(
        "incompatible reader created later",
        &writer,
        &compatible,
        &incompatible,
        Refusal::Reported,
    );
}

/// The compatible reader is created after the writer was refused by the
/// only reader there was: it is matched, and takes every sample, while its
/// incompatible sibling still takes nothing.
#[test]
fn a_compatible_reader_created_later_takes_everything() {
    let lease = hdds::test_support::domains::unique_domain();
    let pa = participant("later_compat_pub", lease.id());
    let pb = participant("later_compat_sub", lease.id());
    let topic = "rxo_later_compat";
    let mut incompatible = Reader::new(&pb, topic, QoS::reliable());
    let writer = Writer::new(&pa, topic, QoS::best_effort());
    assert!(wait_for(Duration::from_secs(5), || {
        incompatible.incompatible() && writer.seen.incompat.load(Ordering::SeqCst) > 0
    }));
    let mut compatible = Reader::new(&pb, topic, QoS::best_effort());
    wait_for(Duration::from_secs(5), || {
        compatible.matched() == 1 && writer.seen.current.load(Ordering::SeqCst) == 1
    });
    write_and_settle(&writer, &mut compatible, &mut incompatible);
    assert_outcome(
        "compatible reader created later",
        &writer,
        &compatible,
        &incompatible,
        Refusal::Reported,
    );
}

/// The compatible reader is deleted: its incompatible sibling still takes
/// nothing, and a compatible reader created afterwards takes everything.
#[test]
fn deleting_the_compatible_reader_opens_nothing_to_its_sibling() {
    let lease = hdds::test_support::domains::unique_domain();
    let pa = participant("deleted_pub", lease.id());
    let pb = participant("deleted_sub", lease.id());
    let topic = "rxo_deleted";
    let mut incompatible = Reader::new(&pb, topic, QoS::reliable());
    let compatible = Reader::new(&pb, topic, QoS::best_effort());
    let writer = Writer::new(&pa, topic, QoS::best_effort());
    assert!(wait_for(Duration::from_secs(5), || {
        compatible.matched() == 1
            && writer.seen.current.load(Ordering::SeqCst) == 1
            && incompatible.incompatible()
    }));
    drop(compatible);
    assert!(
        wait_for(Duration::from_secs(5), || writer
            .seen
            .current
            .load(Ordering::SeqCst)
            == 0),
        "the writer sees the deleted reader leave"
    );
    std::thread::sleep(Duration::from_millis(200));
    writer.write_all();
    std::thread::sleep(Duration::from_millis(500));
    assert_eq!(
        incompatible.drain(),
        0,
        "with no compatible sibling left, the incompatible reader takes nothing"
    );
    let mut successor = Reader::new(&pb, topic, QoS::best_effort());
    assert!(wait_for(Duration::from_secs(5), || {
        successor.matched() == 1 && writer.seen.current.load(Ordering::SeqCst) == 1
    }));
    write_and_settle(&writer, &mut successor, &mut incompatible);
    assert_outcome(
        "compatible reader created after a deletion",
        &writer,
        &successor,
        &incompatible,
        Refusal::Reported,
    );
}
