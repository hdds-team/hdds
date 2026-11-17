// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! A C ABI reader listener on a reader that delivers through
//! `on_data_available_notification` (BY_SOURCE_TIMESTAMP, TIME_BASED_FILTER,
//! DDS v1.4 Sec.2.2.4.3.2). Without a notify callback, the bridge's adapter
//! reads the accepted samples and feeds the payload callback; with
//! `hdds_reader_set_listener_notify`, the notification itself reaches C.

use super::*;
use crate::listener::{
    hdds_reader_clear_listener, hdds_reader_set_listener, hdds_reader_set_listener_notify,
    HddsOnDataAvailableNotify, HddsReaderListener,
};
use std::ffi::CString;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

const SEPARATION_MS: u64 = 300;

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

/// What the C callbacks of one reader listener saw.
#[derive(Default)]
struct Seen {
    /// Each payload callback: the bytes and the instant it ran.
    payloads: Mutex<Vec<(Vec<u8>, Instant)>>,
    data_calls: AtomicUsize,
    notifications: AtomicUsize,
}

impl Seen {
    fn payload_count(&self) -> usize {
        self.payloads.lock().unwrap().len()
    }
}

unsafe extern "C" fn on_data(data: *const u8, len: usize, user: *mut c_void) {
    let seen = &*user.cast::<Seen>();
    seen.data_calls.fetch_add(1, Ordering::SeqCst);
    let bytes = std::slice::from_raw_parts(data, len).to_vec();
    seen.payloads.lock().unwrap().push((bytes, Instant::now()));
}

unsafe extern "C" fn on_notify(user: *mut c_void) {
    let seen = &*user.cast::<Seen>();
    seen.notifications.fetch_add(1, Ordering::SeqCst);
}

/// A listener with the payload callback only (no status callbacks).
fn payload_listener(seen: &Seen) -> HddsReaderListener {
    HddsReaderListener {
        on_data_available: Some(on_data),
        on_subscription_matched: None,
        on_liveliness_changed: None,
        on_sample_lost: None,
        on_sample_rejected: None,
        on_deadline_missed: None,
        on_incompatible_qos: None,
        user_data: (seen as *const Seen).cast_mut().cast::<c_void>(),
    }
}

/// The DDS domain of this file's participants: a test runs on 200-230, never
/// 0. The C ABI takes its domain from the process environment, which the
/// parallel tests share, so the participant is built here with its domain and
/// handed over in the C handle form (the same `Arc<Participant>` box
/// `hdds_participant_create_with_transport` makes).
const TEST_DOMAIN: u32 = 210;

unsafe fn intra_participant(name: &str) -> *mut HddsParticipant {
    let participant = hdds::Participant::builder(name)
        .domain_id(TEST_DOMAIN)
        .with_transport(hdds::TransportMode::IntraProcess)
        .build()
        .expect("intra-process participant");
    Box::into_raw(Box::new(participant)).cast::<HddsParticipant>()
}

/// A C ABI writer with `qos`, offering XCDR2, the representation the reader
/// requests. A BY_SOURCE_TIMESTAMP reader matches only a writer that offers
/// BY_SOURCE_TIMESTAMP too (DESTINATION_ORDER is request-versus-offer).
unsafe fn writer(participant: *mut HddsParticipant, topic: &str, qos: QoS) -> *mut HddsDataWriter {
    let topic = CString::new(topic).unwrap();
    let qos = Box::into_raw(Box::new(qos.data_representation_xcdr2()));
    let writer = hdds_writer_create_with_qos(participant, topic.as_ptr(), qos.cast::<HddsQoS>());
    drop(Box::from_raw(qos));
    assert!(!writer.is_null());
    writer
}

/// A C ABI reader with `qos`; the C side copies the QoS it is given.
unsafe fn reader(participant: *mut HddsParticipant, topic: &str, qos: QoS) -> *mut HddsDataReader {
    let topic = CString::new(topic).unwrap();
    let qos = Box::into_raw(Box::new(qos.data_representation_xcdr2()));
    let reader = hdds_reader_create_with_qos(participant, topic.as_ptr(), qos.cast::<HddsQoS>());
    drop(Box::from_raw(qos));
    assert!(!reader.is_null());
    reader
}

unsafe fn write(writer: *mut HddsDataWriter, bytes: &[u8]) {
    assert_eq!(
        hdds_writer_write(writer, bytes.as_ptr().cast(), bytes.len()),
        HddsError::HddsOk
    );
}

unsafe fn teardown(
    participant: *mut HddsParticipant,
    writer: *mut HddsDataWriter,
    reader: *mut HddsDataReader,
) {
    let _ = hdds_reader_clear_listener(reader);
    hdds_reader_destroy(reader);
    hdds_writer_destroy(writer);
    hdds_participant_destroy(participant);
}

/// The payload callback of a TIME_BASED_FILTER reader (no notify callback) is
/// fed by the adapter: the shown sample arrives at once, the held one when its
/// window ends. The adapter is non-consuming: the sample stays takeable.
#[test]
fn a_payload_listener_on_a_time_based_filter_reader_gets_the_accepted_samples() {
    unsafe {
        let participant = intra_participant("notify-tbf-payload");
        let writer = writer(participant, "notify-tbf-payload-topic", QoS::reliable());
        let reader = reader(
            participant,
            "notify-tbf-payload-topic",
            QoS::reliable()
                .keep_last(8)
                .time_based_filter_millis(SEPARATION_MS),
        );
        let seen = Box::new(Seen::default());
        let listener = payload_listener(&seen);
        assert_eq!(
            hdds_reader_set_listener(reader, &listener),
            HddsError::HddsOk
        );

        let first = [1u8, 2, 3, 4];
        let before_first = Instant::now();
        write(writer, &first);
        assert!(
            wait_for(Duration::from_secs(2), || seen.payload_count() >= 1),
            "the first sample reaches the payload callback"
        );
        assert_eq!(seen.payloads.lock().unwrap()[0].0, first);

        // The adapter does not consume: the sample is still in the cache.
        let rd = &*reader.cast::<DataReader<BytePayload>>();
        let taken = rd
            .take()
            .expect("take succeeds")
            .expect("the accepted sample is still takeable");
        assert_eq!(taken.data, first);

        // Inside the window: held, then delivered when the window ends.
        let second = [9u8, 9, 9, 9];
        write(writer, &second);
        assert!(
            wait_for(Duration::from_secs(3), || seen.payload_count() >= 2),
            "the held sample reaches the payload callback when its window ends"
        );
        let (bytes, at) = seen.payloads.lock().unwrap()[1].clone();
        assert_eq!(bytes, second);
        assert!(
            at.duration_since(before_first) >= Duration::from_millis(SEPARATION_MS),
            "never before the window of the shown sample ends"
        );

        teardown(participant, writer, reader);
    }
}

/// The same on a BY_SOURCE_TIMESTAMP reader: the accepted samples reach the
/// payload callback, in order, once each.
#[test]
fn a_payload_listener_on_a_by_source_timestamp_reader_gets_the_accepted_samples() {
    unsafe {
        let participant = intra_participant("notify-bst-payload");
        let writer = writer(
            participant,
            "notify-bst-payload-topic",
            QoS::reliable().keep_last(8).destination_order_by_source(),
        );
        let reader = reader(
            participant,
            "notify-bst-payload-topic",
            QoS::reliable().keep_last(8).destination_order_by_source(),
        );
        let seen = Box::new(Seen::default());
        let listener = payload_listener(&seen);
        assert_eq!(
            hdds_reader_set_listener(reader, &listener),
            HddsError::HddsOk
        );

        let first = [0xAAu8, 0x01];
        let second = [0xBBu8, 0x02];
        write(writer, &first);
        write(writer, &second);
        let delivered = wait_for(Duration::from_secs(3), || seen.payload_count() >= 2);
        assert!(
            delivered,
            "both accepted samples reach the payload callback: payloads {}, notifications {}",
            seen.payload_count(),
            seen.notifications.load(Ordering::SeqCst)
        );
        let payloads = seen.payloads.lock().unwrap();
        assert_eq!(payloads[0].0, first);
        assert_eq!(payloads[1].0, second);
        drop(payloads);
        assert_eq!(seen.data_calls.load(Ordering::SeqCst), 2, "each once");

        teardown(participant, writer, reader);
    }
}

/// With `hdds_reader_set_listener_notify`, the notification reaches C and the
/// payload callback is not called on that reader. The application reads the
/// samples itself, from the notification or later.
#[test]
fn a_notify_callback_is_called_and_the_payload_callback_is_not() {
    unsafe {
        let participant = intra_participant("notify-tbf-notify");
        let writer = writer(participant, "notify-tbf-notify-topic", QoS::reliable());
        let reader = reader(
            participant,
            "notify-tbf-notify-topic",
            QoS::reliable()
                .keep_last(8)
                .time_based_filter_millis(SEPARATION_MS),
        );
        let seen = Box::new(Seen::default());
        let listener = payload_listener(&seen);
        let notify: HddsOnDataAvailableNotify = Some(on_notify);
        assert_eq!(
            hdds_reader_set_listener_notify(reader, &listener, notify),
            HddsError::HddsOk
        );

        let first = [5u8, 6];
        let second = [7u8, 8];
        let before_first = Instant::now();
        write(writer, &first);
        assert!(
            wait_for(Duration::from_secs(2), || seen
                .notifications
                .load(Ordering::SeqCst)
                >= 1),
            "the notify callback runs when the first sample arrives"
        );
        // Inside the window of the first: a further notification, nothing shown yet.
        write(writer, &second);
        assert!(
            wait_for(Duration::from_secs(2), || seen
                .notifications
                .load(Ordering::SeqCst)
                >= 2),
            "the notify callback runs for the held sample's arrival too"
        );
        assert_eq!(
            seen.data_calls.load(Ordering::SeqCst),
            0,
            "the payload callback is not called when a notify callback is set"
        );

        // The application reads: the first sample is shown when its window ends,
        // the second one when its own window (opened by that read) ends.
        let rd = &*reader.cast::<DataReader<BytePayload>>();
        let mut shown = Vec::new();
        let got = wait_for(Duration::from_secs(3), || {
            while let Ok(Some(sample)) = rd.take() {
                shown.push(sample.data);
            }
            shown.len() >= 2
        });
        assert!(
            got,
            "both samples are shown as their windows end: {shown:?}"
        );
        assert_eq!(shown[0], first, "the first sample is shown first");
        assert_eq!(shown[1], second, "then the held one");
        assert!(
            before_first.elapsed() >= Duration::from_millis(SEPARATION_MS),
            "not shown before the window of the first sample ends"
        );

        teardown(participant, writer, reader);
    }
}

/// The same by-source intra-process reader through the Rust API, with plain
/// `DataWriter::write` (source timestamp stamped from the clock): the writer
/// offers BY_SOURCE_TIMESTAMP, so the pair matches and both samples arrive in
/// order. A BY_RECEPTION_TIMESTAMP writer is refused by the reader's request
/// (DESTINATION_ORDER is request-versus-offer) and delivers nothing.
#[derive(Debug, Clone, PartialEq, hdds::DDS)]
struct RustValue {
    value: i32,
}

#[derive(Default)]
struct NotifyCount(AtomicUsize);

impl hdds::dds::listener::DataReaderListener<RustValue> for NotifyCount {
    fn on_data_available_notification(&self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn a_plain_write_reaches_a_by_source_reader_in_process() {
    let participant = hdds::Participant::builder("rust-bst-intra")
        .domain_id(210)
        .with_transport(hdds::TransportMode::IntraProcess)
        .build()
        .unwrap();
    let topic = participant
        .topic::<RustValue>("rust-bst-intra-topic")
        .unwrap();
    let writer = topic
        .writer()
        .qos(
            hdds::QoS::reliable()
                .keep_last(8)
                .destination_order_by_source(),
        )
        .build()
        .unwrap();
    let reader = topic
        .reader()
        .qos(
            hdds::QoS::reliable()
                .keep_last(8)
                .destination_order_by_source(),
        )
        .build()
        .unwrap();
    let counter = Arc::new(NotifyCount::default());
    reader.set_listener(
        Some(counter.clone() as Arc<dyn hdds::dds::listener::DataReaderListener<RustValue>>),
        hdds::dds::StatusMask::DATA_AVAILABLE,
    );
    writer.write(&RustValue { value: 1 }).unwrap();
    writer.write(&RustValue { value: 2 }).unwrap();
    let mut got = Vec::new();
    wait_for(Duration::from_secs(3), || {
        while let Ok(Some(sample)) = reader.take() {
            got.push(sample.value);
        }
        got.len() >= 2
    });
    assert_eq!(
        got,
        vec![1, 2],
        "notifications {}",
        counter.0.load(Ordering::SeqCst)
    );
}

/// The sender a probe reports its first call's entry on, and the receiver it
/// then waits on for the release.
type ProbeGate = (
    Mutex<std::sync::mpsc::Sender<()>>,
    Mutex<std::sync::mpsc::Receiver<()>>,
);

/// What the payload callback of an ordering test saw, and what its first call
/// does before it returns.
#[derive(Default)]
struct Probe {
    /// The first byte of each payload, in the order the callbacks returned.
    seen: Mutex<Vec<u8>>,
    calls: AtomicUsize,
    /// First call: report entry on the sender, then wait for the receiver.
    gate: Option<ProbeGate>,
    /// First call: write these values to `writer`, from inside the callback.
    writes: Vec<u8>,
    writer: usize,
    /// First call, after the writes: remove the listener of this reader (0 =
    /// none), from inside the callback.
    clear_reader: usize,
}

unsafe extern "C" fn on_probe(data: *const u8, len: usize, user: *mut c_void) {
    let probe = &*user.cast::<Probe>();
    let value = std::slice::from_raw_parts(data, len)
        .first()
        .copied()
        .unwrap_or(0);
    if probe.calls.fetch_add(1, Ordering::SeqCst) == 0 {
        if let Some((entered, release)) = &probe.gate {
            entered.lock().unwrap().send(()).unwrap();
            release.lock().unwrap().recv().unwrap();
        }
        for &v in &probe.writes {
            write(probe.writer as *mut HddsDataWriter, &[v]);
        }
        if probe.clear_reader != 0 {
            let _ = hdds_reader_clear_listener(probe.clear_reader as *mut HddsDataReader);
        }
    }
    probe.seen.lock().unwrap().push(value);
}

/// A payload listener that records through `on_probe`.
fn probe_listener(probe: &Probe) -> HddsReaderListener {
    HddsReaderListener {
        on_data_available: Some(on_probe),
        on_subscription_matched: None,
        on_liveliness_changed: None,
        on_sample_lost: None,
        on_sample_rejected: None,
        on_deadline_missed: None,
        on_incompatible_qos: None,
        user_data: (probe as *const Probe).cast_mut().cast::<c_void>(),
    }
}

/// Two writes from two threads. The first sample's callback is held inside the
/// holder's delivery while the second sample is accepted: the second callback
/// must wait for the holder, so the callbacks see 1 then 2. Without the
/// forwarding role, sample 2 reaches its callback on the second thread while
/// sample 1 is still inside its own.
#[test]
fn accepted_samples_reach_the_payload_callback_in_read_order_across_threads() {
    unsafe {
        let participant = intra_participant("notify-order-threads");
        let by_source = || QoS::reliable().keep_last(8).destination_order_by_source();
        let writer = writer(participant, "notify-order-threads-topic", by_source());
        let reader = reader(participant, "notify-order-threads-topic", by_source());
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let probe = Box::new(Probe {
            gate: Some((Mutex::new(entered_tx), Mutex::new(release_rx))),
            ..Probe::default()
        });
        let listener = probe_listener(&probe);
        assert_eq!(
            hdds_reader_set_listener(reader, &listener),
            HddsError::HddsOk
        );

        let writer_addr = writer as usize;
        let first = std::thread::spawn(move || {
            write(writer_addr as *mut HddsDataWriter, &[1]);
        });
        entered_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("sample 1 reaches its callback");
        write(writer, &[2]);
        assert!(
            probe.seen.lock().unwrap().is_empty(),
            "sample 2 waits for the holder of sample 1's delivery"
        );
        release_tx.send(()).unwrap();
        first.join().unwrap();
        assert_eq!(*probe.seen.lock().unwrap(), vec![1, 2]);

        teardown(participant, writer, reader);
    }
}

/// A callback that writes from inside itself: the samples it wrote are
/// delivered once each, in write order, by the holder's next pass, before the
/// write that started the delivery returns.
#[test]
fn a_payload_callback_that_writes_gets_its_samples_once_and_in_order() {
    unsafe {
        let participant = intra_participant("notify-order-reentrant");
        let by_source = || QoS::reliable().keep_last(8).destination_order_by_source();
        let writer = writer(participant, "notify-order-reentrant-topic", by_source());
        let reader = reader(participant, "notify-order-reentrant-topic", by_source());
        let probe = Box::new(Probe {
            writes: vec![2, 3],
            writer: writer as usize,
            ..Probe::default()
        });
        let listener = probe_listener(&probe);
        assert_eq!(
            hdds_reader_set_listener(reader, &listener),
            HddsError::HddsOk
        );

        write(writer, &[1]);
        assert_eq!(*probe.seen.lock().unwrap(), vec![1, 2, 3]);
        assert_eq!(probe.calls.load(Ordering::SeqCst), 3, "each sample once");

        teardown(participant, writer, reader);
    }
}

/// The listener is removed from inside its own callback while the second
/// sample is accepted and still to be read: the adapter stops before it reads,
/// so the sample stays NOT_READ for the application and no callback runs for
/// it.
#[test]
fn a_listener_removed_mid_pass_leaves_the_pending_sample_unread() {
    unsafe {
        let participant = intra_participant("notify-remove-mid-pass");
        let by_source = || QoS::reliable().keep_last(8).destination_order_by_source();
        let writer = writer(participant, "notify-remove-mid-pass-topic", by_source());
        let reader = reader(participant, "notify-remove-mid-pass-topic", by_source());
        let probe = Box::new(Probe {
            writes: vec![2],
            writer: writer as usize,
            clear_reader: reader as usize,
            ..Probe::default()
        });
        let listener = probe_listener(&probe);
        assert_eq!(
            hdds_reader_set_listener(reader, &listener),
            HddsError::HddsOk
        );

        write(writer, &[1]);
        assert_eq!(
            *probe.seen.lock().unwrap(),
            vec![1],
            "no callback after removal"
        );

        let rd = reader_arc_from_handle(reader);
        let condition = rd
            .create_readcondition(
                hdds::dds::SampleStateMask::NOT_READ,
                hdds::dds::ViewStateMask::ANY,
                hdds::dds::InstanceStateMask::ANY,
            )
            .expect("NOT_READ condition");
        let pending = rd.read_w_condition(&condition, 8).expect("read");
        assert_eq!(
            pending.len(),
            1,
            "sample 2 is still NOT_READ: the removed adapter did not mark it READ"
        );

        teardown(participant, writer, reader);
    }
}

/// A reader of a GROUP-presentation Subscriber is read only inside the
/// Subscriber's access bracket, so the adapter cannot read its samples: the
/// payload callback gets nothing, every refusal is counted (the warning is
/// logged on the first), and nothing panics.
#[test]
fn a_group_scope_subscriber_reader_refuses_the_adapter_without_a_panic() {
    unsafe {
        let participant = hdds::Participant::builder("notify-group-scope")
            .domain_id(210)
            .with_transport(hdds::TransportMode::IntraProcess)
            .build()
            .unwrap();
        let topic = participant
            .topic::<BytePayload>("notify-group-scope-topic")
            .unwrap();
        let subscriber = participant
            .create_subscriber(hdds::QoS::default().presentation(
                hdds::dds::qos::Presentation::new(
                    hdds::dds::qos::PresentationAccessScope::Group,
                    false,
                    false,
                ),
            ))
            .unwrap();
        let reader = topic
            .reader()
            .subscriber(&subscriber)
            .qos(QoS::reliable().keep_last(8).destination_order_by_source())
            .build()
            .unwrap();
        let writer = topic
            .writer()
            .qos(QoS::reliable().keep_last(8).destination_order_by_source())
            .build()
            .unwrap();
        let handle = reader_into_handle(reader);
        let probe = Box::new(Probe::default());
        let listener = probe_listener(&probe);
        assert_eq!(
            hdds_reader_set_listener(handle, &listener),
            HddsError::HddsOk
        );

        writer.write(&BytePayload::to_write(vec![1])).unwrap();
        writer.write(&BytePayload::to_write(vec![2])).unwrap();
        assert!(
            wait_for(Duration::from_secs(3), || group_scope_refusals(handle) >= 2),
            "each notification is refused: {}",
            group_scope_refusals(handle)
        );
        assert_eq!(group_scope_refusals(handle), 2);
        assert!(
            probe.seen.lock().unwrap().is_empty(),
            "the payload callback gets nothing outside the bracket"
        );

        assert_eq!(hdds_reader_clear_listener(handle), HddsError::HddsOk);
        hdds_reader_destroy(handle);
    }
}
