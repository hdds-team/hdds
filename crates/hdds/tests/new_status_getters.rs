// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! DDS v1.4 Sec.2.2.4 status getters: SUBSCRIPTION_MATCHED /
//! PUBLICATION_MATCHED and REQUESTED/OFFERED_INCOMPATIBLE_QOS, read-and-reset
//! like the existing SAMPLE_REJECTED/SAMPLE_LOST getters (Sec.2.2.4.2.1), and
//! raising/clearing a bit on the StatusCondition (DataReader's and
//! DataWriter's). No listener is installed anywhere here on purpose: these
//! getters/conditions exist for the application that polls instead of listening.
//!
//! One pairing mixes `IntraProcess` and `UdpMulticast` (same pattern as
//! `mixed_transport_match_status.rs`) so the match callback's two sources --
//! the SEDP `MatchNotificationRegistry` and `domain_registry::
//! LocalMatchStatus` -- are both exercised by the SAME test, one per side.

use hdds::dds::{
    Condition, DataReaderListener, DataWriterListener, PublicationMatchedStatus,
    RequestedIncompatibleQosStatus, StatusMask, SubscriptionMatchedStatus, WaitSet,
};
use hdds::{Participant, QoS, TransportMode};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(hdds::DDS, Debug, Clone)]
struct Probe {
    value: i64,
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

/// IntraProcess writer, UdpMulticast reader (distinct participants, same
/// process/domain): the writer's PUBLICATION_MATCHED comes only from
/// `domain_registry::LocalMatchStatus` (no wire path at all), the reader's
/// SUBSCRIPTION_MATCHED only from the SEDP `MatchNotificationRegistry`
/// (its participant has one; the writer is never announced over SEDP).
#[test]
fn subscription_and_publication_matched_status_and_matched_guids_and_waitset() {
    let lease = hdds::test_support::domains::unique_domain();
    let domain_id = lease.id();
    let name = "new_status_getters_match";

    let pub_participant = Participant::builder(&format!("{name}_pub"))
        .domain_id(domain_id)
        .with_transport(TransportMode::IntraProcess)
        .build()
        .unwrap();
    let sub_participant = Participant::builder(&format!("{name}_sub"))
        .domain_id(domain_id)
        .with_transport(TransportMode::UdpMulticast)
        .build()
        .unwrap();

    let writer = pub_participant
        .topic::<Probe>(name)
        .unwrap()
        .writer()
        .qos(QoS::reliable().keep_last(8))
        .build()
        .unwrap();
    let reader = sub_participant
        .topic::<Probe>(name)
        .unwrap()
        .reader()
        .qos(QoS::reliable().keep_last(8))
        .build()
        .unwrap();

    // No listener on either side: PUBLICATION_MATCHED / SUBSCRIPTION_MATCHED
    // must still raise the StatusCondition and wake an attached WaitSet.
    let writer_condition = writer.get_status_condition();
    writer_condition.set_enabled_statuses(StatusMask::PUBLICATION_MATCHED);
    let writer_waitset = WaitSet::new();
    writer_waitset
        .attach_condition(Arc::clone(&writer_condition) as Arc<dyn Condition>)
        .expect("attach writer condition");

    let reader_condition = reader.get_status_condition();
    reader_condition.set_enabled_statuses(StatusMask::SUBSCRIPTION_MATCHED);
    let reader_waitset = WaitSet::new();
    reader_waitset
        .attach_condition(Arc::clone(&reader_condition) as Arc<dyn Condition>)
        .expect("attach reader condition");

    assert!(
        writer_waitset.wait(Some(Duration::from_secs(5))).is_ok(),
        "the writer's WaitSet never woke on PUBLICATION_MATCHED"
    );
    assert!(
        reader_waitset.wait(Some(Duration::from_secs(5))).is_ok(),
        "the reader's WaitSet never woke on SUBSCRIPTION_MATCHED"
    );

    let pub_status = writer.get_publication_matched_status();
    assert_eq!(pub_status.total_count, 1);
    assert_eq!(pub_status.total_count_change, 1);
    assert_eq!(pub_status.current_count, 1);
    assert_eq!(pub_status.current_count_change, 1);
    assert!(pub_status.last_subscription_handle.is_some());
    assert!(
        !writer_condition
            .get_active_statuses()
            .contains(StatusMask::PUBLICATION_MATCHED),
        "the getter must clear the bit it just read"
    );
    let pub_status_again = writer.get_publication_matched_status();
    assert_eq!(pub_status_again.total_count, 1, "cumulative, unaffected");
    assert_eq!(pub_status_again.total_count_change, 0, "reset on read");
    assert_eq!(pub_status_again.current_count_change, 0, "reset on read");

    let sub_status = reader.get_subscription_matched_status();
    assert_eq!(sub_status.total_count, 1);
    assert_eq!(sub_status.total_count_change, 1);
    assert_eq!(sub_status.current_count, 1);
    assert_eq!(sub_status.current_count_change, 1);
    assert!(sub_status.last_publication_handle.is_some());
    assert!(
        !reader_condition
            .get_active_statuses()
            .contains(StatusMask::SUBSCRIPTION_MATCHED),
        "the getter must clear the bit it just read"
    );
    let sub_status_again = reader.get_subscription_matched_status();
    assert_eq!(sub_status_again.total_count_change, 0, "reset on read");
    assert_eq!(sub_status_again.current_count_change, 0, "reset on read");

    // get_matched_subscriptions / get_matched_publications: a live GUID
    // snapshot, no read-and-reset, backed by the SEDP registry's
    // `matched_remotes` (reader side here) and `LocalMatchStatus::
    // matched_peers` (writer side here) -- the two sources this pairing
    // exercises one each.
    let matched_subs = writer.get_matched_subscriptions();
    assert_eq!(matched_subs.len(), 1, "exactly the one matched reader");
    assert_eq!(Some(matched_subs[0]), pub_status.last_subscription_handle);

    let matched_pubs = reader.get_matched_publications();
    assert_eq!(matched_pubs.len(), 1, "exactly the one matched writer");
    assert_eq!(Some(matched_pubs[0]), sub_status.last_publication_handle);

    // Deliver a sample so the pairing is proven live, not just counted.
    writer.write(&Probe { value: 99 }).unwrap();
    let delivered = wait_for(
        Duration::from_secs(5),
        || matches!(reader.take(), Ok(Some(ref p)) if p.value == 99),
    );
    assert!(delivered, "the sample never reached the matched reader");

    // Unmatch: dropping the reader must empty both matched-GUID views and
    // bring PUBLICATION_MATCHED's current_count back to 0 (total_count
    // stays cumulative, DDS v1.4 Sec.2.2.4.1).
    drop(reader);
    assert!(
        wait_for(Duration::from_secs(5), || writer
            .get_matched_subscriptions()
            .is_empty()),
        "the writer still reports the dropped reader as matched"
    );
    let after_unmatch = writer.get_publication_matched_status();
    assert_eq!(after_unmatch.total_count, 1, "cumulative: never decreases");
    assert_eq!(after_unmatch.current_count, 0);
    assert_eq!(after_unmatch.current_count_change, -1);
}

/// A writer offering BEST_EFFORT and a reader requesting RELIABLE are QoS-
/// incompatible (DDS v1.4 Sec.2.2.3.14, RELIABLE > BEST_EFFORT): both ends
/// report REQUESTED_INCOMPATIBLE_QOS / OFFERED_INCOMPATIBLE_QOS and never
/// match. One IntraProcess participant for both endpoints, so the only
/// source is `domain_registry::LocalMatchStatus` (no `discovery_fsm`, hence
/// no `MatchNotificationRegistry`, for an IntraProcess participant).
#[test]
fn incompatible_qos_status_getters_read_and_reset_and_raise_condition() {
    let participant = Participant::builder("new_status_getters_incompat")
        .domain_id(0)
        .with_transport(TransportMode::IntraProcess)
        .build()
        .unwrap();
    let topic = participant
        .topic::<Probe>("new_status_getters_incompat")
        .unwrap();

    let writer = topic.writer().qos(QoS::best_effort()).build().unwrap();
    let reader = topic.reader().qos(QoS::reliable()).build().unwrap();

    let writer_condition = writer.get_status_condition();
    writer_condition.set_enabled_statuses(StatusMask::OFFERED_INCOMPATIBLE_QOS);
    let reader_condition = reader.get_status_condition();
    reader_condition.set_enabled_statuses(StatusMask::REQUESTED_INCOMPATIBLE_QOS);

    assert!(
        wait_for(Duration::from_secs(5), || writer_condition
            .get_active_statuses()
            .contains(StatusMask::OFFERED_INCOMPATIBLE_QOS)),
        "the writer never reported OFFERED_INCOMPATIBLE_QOS"
    );
    assert!(
        wait_for(Duration::from_secs(5), || reader_condition
            .get_active_statuses()
            .contains(StatusMask::REQUESTED_INCOMPATIBLE_QOS)),
        "the reader never reported REQUESTED_INCOMPATIBLE_QOS"
    );

    let writer_status = writer.get_offered_incompatible_qos_status();
    assert_eq!(writer_status.total_count, 1);
    assert_eq!(writer_status.total_count_change, 1);
    assert_ne!(writer_status.last_policy_id, 0);
    assert!(
        !writer_condition
            .get_active_statuses()
            .contains(StatusMask::OFFERED_INCOMPATIBLE_QOS),
        "the getter must clear the bit it just read"
    );
    let writer_status_again = writer.get_offered_incompatible_qos_status();
    assert_eq!(writer_status_again.total_count_change, 0, "reset on read");

    let reader_status = reader.get_requested_incompatible_qos_status();
    assert_eq!(reader_status.total_count, 1);
    assert_eq!(reader_status.total_count_change, 1);
    assert_ne!(reader_status.last_policy_id, 0);
    assert!(
        !reader_condition
            .get_active_statuses()
            .contains(StatusMask::REQUESTED_INCOMPATIBLE_QOS),
        "the getter must clear the bit it just read"
    );
    let reader_status_again = reader.get_requested_incompatible_qos_status();
    assert_eq!(reader_status_again.total_count_change, 0, "reset on read");

    // Never matched: no readers/writers counted either way.
    assert_eq!(writer.get_matched_subscriptions().len(), 0);
    assert_eq!(reader.get_matched_publications().len(), 0);
}

/// Sanity: a listener installed for PUBLICATION_MATCHED / SUBSCRIPTION_MATCHED
/// consumes the event (reset change, cleared condition) itself, so an
/// application that ALSO polls the getter afterwards sees the already-reset
/// state -- DDS v1.4 Sec.2.2.4.2.1, "the status is reset prior to calling
/// the listener".
#[test]
fn a_listener_resets_the_status_before_the_getter_is_called() {
    let participant = Participant::builder("new_status_getters_listener_reset")
        .domain_id(0)
        .with_transport(TransportMode::IntraProcess)
        .build()
        .unwrap();
    let topic = participant
        .topic::<Probe>("new_status_getters_listener_reset")
        .unwrap();

    #[derive(Default)]
    struct NullListener;
    impl DataWriterListener<Probe> for NullListener {}
    impl DataReaderListener<Probe> for NullListener {}

    let writer = topic
        .writer()
        .qos(QoS::reliable())
        .with_listener(Arc::new(NullListener) as Arc<dyn DataWriterListener<Probe>>)
        .build()
        .unwrap();
    let reader = topic
        .reader()
        .qos(QoS::reliable())
        .with_listener(Arc::new(NullListener) as Arc<dyn DataReaderListener<Probe>>)
        .build()
        .unwrap();

    assert!(wait_for(Duration::from_secs(5), || writer
        .matched_reader_count()
        == 1));

    let pub_status = writer.get_publication_matched_status();
    assert_eq!(
        pub_status.total_count_change, 0,
        "the installed listener already consumed the event"
    );
    let sub_status = reader.get_subscription_matched_status();
    assert_eq!(
        sub_status.total_count_change, 0,
        "the installed listener already consumed the event"
    );
}

/// A listener installed AFTER a status was raised with no listener must
/// still clear the StatusCondition bit on the NEXT event (DDS v1.4
/// Sec.2.2.4.2.1: the status is reset / the bit cleared on EVERY delivery
/// to the listener, not only the first one after installation). Pins
/// PUBLICATION_MATCHED (one writer, two readers) and SUBSCRIPTION_MATCHED
/// (one reader, two writers): the first match raises the bit with no
/// listener, a listener is installed, then a second peer's match must
/// reach the listener AND clear the bit.
#[test]
fn a_listener_installed_after_a_raised_match_bit_clears_it_on_the_next_match() {
    // PUBLICATION_MATCHED: one writer, two readers.
    {
        let domain = hdds::test_support::domains::unique_domain();
        let participant = Participant::builder("listener_after_raise_pub")
            .domain_id(domain.id())
            .with_transport(TransportMode::IntraProcess)
            .build()
            .unwrap();
        let topic = participant
            .topic::<Probe>("listener_after_raise_pub")
            .unwrap();
        let writer = topic.writer().qos(QoS::reliable()).build().unwrap();
        let _reader_1 = topic.reader().qos(QoS::reliable()).build().unwrap();
        let condition = writer.get_status_condition();
        condition.set_enabled_statuses(StatusMask::PUBLICATION_MATCHED);
        assert!(
            wait_for(Duration::from_secs(5), || condition
                .get_active_statuses()
                .contains(StatusMask::PUBLICATION_MATCHED)),
            "the first match (no listener) must raise the bit"
        );

        #[derive(Default)]
        struct Seen(AtomicU32);
        impl DataWriterListener<Probe> for Seen {
            fn on_publication_matched(&self, _status: PublicationMatchedStatus) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }
        let seen = Arc::new(Seen::default());
        writer.set_listener(
            Some(Arc::clone(&seen) as Arc<dyn DataWriterListener<Probe>>),
            StatusMask::PUBLICATION_MATCHED,
        );

        let _reader_2 = topic.reader().qos(QoS::reliable()).build().unwrap();
        assert!(
            wait_for(Duration::from_secs(5), || seen.0.load(Ordering::SeqCst) > 0),
            "the listener installed after the raise was never called on the next match"
        );
        assert!(
            !condition
                .get_active_statuses()
                .contains(StatusMask::PUBLICATION_MATCHED),
            "the listener's clear_active_status must run on the next event too, \
             not only on an event that follows the listener's own installation \
             with no bit already raised"
        );
    }

    // SUBSCRIPTION_MATCHED: one reader, two writers.
    {
        let domain = hdds::test_support::domains::unique_domain();
        let participant = Participant::builder("listener_after_raise_sub")
            .domain_id(domain.id())
            .with_transport(TransportMode::IntraProcess)
            .build()
            .unwrap();
        let topic = participant
            .topic::<Probe>("listener_after_raise_sub")
            .unwrap();
        let reader = topic.reader().qos(QoS::reliable()).build().unwrap();
        let _writer_1 = topic.writer().qos(QoS::reliable()).build().unwrap();
        let condition = reader.get_status_condition();
        condition.set_enabled_statuses(StatusMask::SUBSCRIPTION_MATCHED);
        assert!(
            wait_for(Duration::from_secs(5), || condition
                .get_active_statuses()
                .contains(StatusMask::SUBSCRIPTION_MATCHED)),
            "the first match (no listener) must raise the bit"
        );

        #[derive(Default)]
        struct Seen(AtomicU32);
        impl DataReaderListener<Probe> for Seen {
            fn on_subscription_matched(&self, _status: SubscriptionMatchedStatus) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }
        let seen = Arc::new(Seen::default());
        reader.set_listener(
            Some(Arc::clone(&seen) as Arc<dyn DataReaderListener<Probe>>),
            StatusMask::SUBSCRIPTION_MATCHED,
        );

        let _writer_2 = topic.writer().qos(QoS::reliable()).build().unwrap();
        assert!(
            wait_for(Duration::from_secs(5), || seen.0.load(Ordering::SeqCst) > 0),
            "the listener installed after the raise was never called on the next match"
        );
        assert!(
            !condition
                .get_active_statuses()
                .contains(StatusMask::SUBSCRIPTION_MATCHED),
            "the listener's clear_active_status must run on the next event too"
        );
    }
}

/// Same pin as `a_listener_installed_after_a_raised_match_bit_clears_it_on_the_next_match`,
/// for OFFERED_INCOMPATIBLE_QOS (writer) and REQUESTED_INCOMPATIBLE_QOS
/// (reader). The second incompatible peer is a DIFFERENT GUID so it is a
/// fresh event rather than a dedup no-op (the per-entry/per-pair dedup
/// keys on the remote's identity, not on the policy alone).
#[test]
fn a_listener_installed_after_a_raised_incompatible_qos_bit_clears_it_on_the_next_event() {
    // OFFERED_INCOMPATIBLE_QOS: one writer, two incompatible readers.
    {
        let domain = hdds::test_support::domains::unique_domain();
        let participant = Participant::builder("listener_after_raise_offered_incompat")
            .domain_id(domain.id())
            .with_transport(TransportMode::IntraProcess)
            .build()
            .unwrap();
        let topic = participant
            .topic::<Probe>("listener_after_raise_offered_incompat")
            .unwrap();
        let writer = topic.writer().qos(QoS::best_effort()).build().unwrap();
        let _reader_1 = topic.reader().qos(QoS::reliable()).build().unwrap();
        let condition = writer.get_status_condition();
        condition.set_enabled_statuses(StatusMask::OFFERED_INCOMPATIBLE_QOS);
        assert!(
            wait_for(Duration::from_secs(5), || condition
                .get_active_statuses()
                .contains(StatusMask::OFFERED_INCOMPATIBLE_QOS)),
            "the first incompatible match (no listener) must raise the bit"
        );

        #[derive(Default)]
        struct Seen(AtomicU32);
        impl DataWriterListener<Probe> for Seen {
            fn on_offered_incompatible_qos(&self, _policy_id: u32, _policy_name: &str) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }
        let seen = Arc::new(Seen::default());
        writer.set_listener(
            Some(Arc::clone(&seen) as Arc<dyn DataWriterListener<Probe>>),
            StatusMask::OFFERED_INCOMPATIBLE_QOS,
        );

        let _reader_2 = topic.reader().qos(QoS::reliable()).build().unwrap();
        assert!(
            wait_for(Duration::from_secs(5), || seen.0.load(Ordering::SeqCst) > 0),
            "the listener installed after the raise was never called on the \
             next incompatible match"
        );
        assert!(
            !condition
                .get_active_statuses()
                .contains(StatusMask::OFFERED_INCOMPATIBLE_QOS),
            "the listener's clear_active_status must run on the next event too"
        );
    }

    // REQUESTED_INCOMPATIBLE_QOS: one reader, two incompatible writers.
    {
        let domain = hdds::test_support::domains::unique_domain();
        let participant = Participant::builder("listener_after_raise_requested_incompat")
            .domain_id(domain.id())
            .with_transport(TransportMode::IntraProcess)
            .build()
            .unwrap();
        let topic = participant
            .topic::<Probe>("listener_after_raise_requested_incompat")
            .unwrap();
        let reader = topic.reader().qos(QoS::reliable()).build().unwrap();
        let _writer_1 = topic.writer().qos(QoS::best_effort()).build().unwrap();
        let condition = reader.get_status_condition();
        condition.set_enabled_statuses(StatusMask::REQUESTED_INCOMPATIBLE_QOS);
        assert!(
            wait_for(Duration::from_secs(5), || condition
                .get_active_statuses()
                .contains(StatusMask::REQUESTED_INCOMPATIBLE_QOS)),
            "the first incompatible match (no listener) must raise the bit"
        );

        #[derive(Default)]
        struct Seen(AtomicU32);
        impl DataReaderListener<Probe> for Seen {
            fn on_requested_incompatible_qos(&self, _status: RequestedIncompatibleQosStatus) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }
        let seen = Arc::new(Seen::default());
        reader.set_listener(
            Some(Arc::clone(&seen) as Arc<dyn DataReaderListener<Probe>>),
            StatusMask::REQUESTED_INCOMPATIBLE_QOS,
        );

        let _writer_2 = topic.writer().qos(QoS::best_effort()).build().unwrap();
        assert!(
            wait_for(Duration::from_secs(5), || seen.0.load(Ordering::SeqCst) > 0),
            "the listener installed after the raise was never called on the \
             next incompatible match"
        );
        assert!(
            !condition
                .get_active_statuses()
                .contains(StatusMask::REQUESTED_INCOMPATIBLE_QOS),
            "the listener's clear_active_status must run on the next event too"
        );
    }
}
