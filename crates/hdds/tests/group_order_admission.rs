// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! An ordered later change cannot consume the only reader slot needed by
//! its earlier pending predecessor (DDS 1.4 2.2.3.6/2.2.3.14/2.2.3.19).

use hdds::{Participant, QoS, TransportMode};
use std::sync::{mpsc, Arc};
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, hdds::DDS)]
struct WireValue {
    value: i32,
}

#[derive(Debug, Clone, PartialEq)]
struct Value {
    value: i32,
    refuse: bool,
}

impl hdds::dds::DDS for Value {
    fn type_descriptor() -> &'static hdds::core::types::TypeDescriptor {
        <WireValue as hdds::dds::DDS>::type_descriptor()
    }
    fn encode(&self, bytes: &mut [u8], version: hdds::dds::CdrVersion) -> hdds::dds::Result<usize> {
        if self.refuse {
            return Err(hdds::Error::Config(
                "intentional encoding refusal".to_string(),
            ));
        }
        <WireValue as hdds::dds::DDS>::encode(&WireValue { value: self.value }, bytes, version)
    }
    fn decode(bytes: &[u8], version: hdds::dds::CdrVersion) -> hdds::dds::Result<Self> {
        <WireValue as hdds::dds::DDS>::decode(bytes, version).map(|value| Self {
            value: value.value,
            refuse: false,
        })
    }
}

#[derive(Debug)]
enum LaterEvent {
    Blocked,
    Finished(bool),
}

fn one_slot_history(refuse_first: bool, coherent_later: bool) {
    let name = if refuse_first {
        "ordered-slot-cancel"
    } else if coherent_later {
        "ordered-slot-coherent"
    } else {
        "ordered-slot-publish"
    };
    let participant = Participant::builder(name)
        .domain_id(0)
        .with_transport(TransportMode::IntraProcess)
        .build()
        .unwrap();
    let mut qos = QoS::reliable()
        .keep_all()
        .presentation_group_coherent_ordered();
    qos.reliability_max_blocking_time = Duration::from_secs(5);
    let publisher = Arc::new(participant.create_publisher(qos.clone()).unwrap());
    let subscriber = Arc::new(participant.create_subscriber(qos.clone()).unwrap());
    let topic = participant.topic::<Value>(name).unwrap();
    let a = topic
        .writer()
        .qos(qos.clone())
        .publisher(&publisher)
        .build()
        .unwrap();
    let b = topic
        .writer()
        .qos(qos.clone())
        .publisher(&publisher)
        .build()
        .unwrap();
    qos.resource_limits.max_samples = 1;
    let reader = topic
        .reader()
        .qos(qos)
        .subscriber(&subscriber)
        .build()
        .unwrap();
    let (reserved, first_reserved) = mpsc::channel();
    let (resume, resumed) = mpsc::channel();
    let (first_done, first_finished) = mpsc::channel();
    let first = std::thread::spawn(move || {
        hdds::test_support::coherent_race::before_next_ordered_write(move || {
            reserved.send(()).unwrap();
            resumed.recv().unwrap();
        });
        let result = a.write(&Value {
            value: 1,
            refuse: refuse_first,
        });
        first_done.send(result.is_ok()).unwrap();
        result
    });
    first_reserved
        .recv_timeout(Duration::from_secs(2))
        .expect("GSN 1 reserved before admission");
    let (later_event, events) = mpsc::channel();
    let later_publisher = publisher.clone();
    let later = std::thread::spawn(move || {
        let blocked = later_event.clone();
        hdds::test_support::coherent_race::before_next_room_wait(move || {
            blocked.send(LaterEvent::Blocked).unwrap()
        });
        let result = if coherent_later {
            later_publisher.begin_coherent_changes().unwrap();
            b.write(&Value {
                value: 2,
                refuse: false,
            })
            .and_then(|_| later_publisher.end_coherent_changes())
        } else {
            b.write(&Value {
                value: 2,
                refuse: false,
            })
        };
        later_event
            .send(LaterEvent::Finished(result.is_ok()))
            .unwrap();
        result
    });
    let event = events
        .recv_timeout(Duration::from_secs(2))
        .expect("later admission decision");
    if !matches!(event, LaterEvent::Blocked) {
        // Close the reader to release the paused producer on a broken rule,
        // so even the deliberately failing test leaves no blocked worker.
        resume.send(()).unwrap();
        drop(reader);
        let _ = first.join();
        let _ = later.join();
        panic!("GSN 2 consumed the predecessor's only place: {event:?}");
    }
    resume.send(()).unwrap();
    let admitted = first_finished.recv_timeout(Duration::from_secs(2));
    if admitted.is_err() {
        drop(reader);
        let _ = first.join();
        let _ = later.join();
        panic!("earlier write could not finish while the later writer waited: {admitted:?}");
    }
    assert_eq!(admitted.unwrap(), !refuse_first);
    subscriber.begin_access().unwrap();
    if !refuse_first {
        assert_eq!(
            reader.take().unwrap(),
            Some(Value {
                value: 1,
                refuse: false
            })
        );
    }
    subscriber.end_access().unwrap();
    match events
        .recv_timeout(Duration::from_secs(2))
        .expect("later writer released by take or cancellation")
    {
        LaterEvent::Finished(true) => {}
        event => panic!("later write did not succeed: {event:?}"),
    }
    assert_eq!(first.join().unwrap().is_ok(), !refuse_first);
    later.join().unwrap().unwrap();
    subscriber.begin_access().unwrap();
    assert_eq!(
        reader.take().unwrap(),
        Some(Value {
            value: 2,
            refuse: false
        })
    );
    subscriber.end_access().unwrap();
}

#[test]
fn later_writer_keeps_the_only_history_slot_for_its_pending_predecessor() {
    one_slot_history(false, false);
}

#[test]
fn cancelling_a_pending_predecessor_wakes_the_writer_waiting_for_its_slot() {
    one_slot_history(true, false);
}

#[test]
fn a_later_coherent_set_keeps_the_slot_for_an_earlier_pending_ordinary_change() {
    one_slot_history(false, true);
}

#[test]
fn coherent_admission_does_not_keep_slots_for_its_own_transaction_members() {
    let participant = Participant::builder("ordered-internal-headroom")
        .domain_id(0)
        .with_transport(TransportMode::IntraProcess)
        .build()
        .unwrap();
    let mut qos = QoS::reliable()
        .keep_all()
        .presentation_group_coherent_ordered();
    qos.reliability_max_blocking_time = Duration::from_millis(50);
    let publisher = Arc::new(participant.create_publisher(qos.clone()).unwrap());
    let subscriber = Arc::new(participant.create_subscriber(qos.clone()).unwrap());
    let topic = participant
        .topic::<Value>("ordered-internal-headroom")
        .unwrap();
    let a = topic
        .writer()
        .qos(qos.clone())
        .publisher(&publisher)
        .build()
        .unwrap();
    let b = topic
        .writer()
        .qos(qos.clone())
        .publisher(&publisher)
        .build()
        .unwrap();
    qos.resource_limits.max_samples = 2;
    let reader = topic
        .reader()
        .qos(qos)
        .subscriber(&subscriber)
        .build()
        .unwrap();
    publisher.begin_coherent_changes().unwrap();
    a.write(&Value {
        value: 1,
        refuse: false,
    })
    .unwrap();
    b.write(&Value {
        value: 2,
        refuse: false,
    })
    .unwrap();
    publisher.end_coherent_changes().unwrap();
    subscriber.begin_access().unwrap();
    assert_eq!(
        reader.take_all().unwrap(),
        vec![
            Value {
                value: 1,
                refuse: false
            },
            Value {
                value: 2,
                refuse: false
            }
        ]
    );
    subscriber.end_access().unwrap();
}

/// One Subscriber's rejection listener may release another Subscriber's
/// history. Rejection callbacks cannot wait behind the latter's admission.
#[test]
fn coherent_rejection_callback_runs_before_another_subscribers_capacity_wait() {
    use hdds::dds::{DataReaderListener, SampleRejectedStatus, StatusMask};
    use std::sync::atomic::{AtomicBool, Ordering};
    struct DrainPeer {
        reader: std::sync::Weak<hdds::DataReader<Value>>,
        subscriber: Arc<hdds::dds::Subscriber>,
        drained: Arc<AtomicBool>,
    }
    impl DataReaderListener<Value> for DrainPeer {
        fn on_sample_rejected(&self, _: SampleRejectedStatus) {
            if self.drained.swap(true, Ordering::SeqCst) {
                return;
            }
            let reader = self.reader.upgrade().unwrap();
            self.subscriber.begin_access().unwrap();
            assert_eq!(
                reader.take().unwrap(),
                Some(Value {
                    value: 0,
                    refuse: false
                })
            );
            self.subscriber.end_access().unwrap();
        }
    }
    let participant = Participant::builder("ordered-rejection-progress")
        .domain_id(0)
        .with_transport(TransportMode::IntraProcess)
        .build()
        .unwrap();
    let mut qos = QoS::reliable()
        .keep_all()
        .presentation_group_coherent_ordered();
    qos.reliability_max_blocking_time = Duration::from_millis(50);
    let publisher = Arc::new(participant.create_publisher(qos.clone()).unwrap());
    let subscriber_a = Arc::new(participant.create_subscriber(qos.clone()).unwrap());
    let subscriber_b = Arc::new(participant.create_subscriber(qos.clone()).unwrap());
    let topic = participant
        .topic::<Value>("ordered-rejection-progress")
        .unwrap();
    let writer_a = topic
        .writer()
        .qos(qos.clone())
        .publisher(&publisher)
        .build()
        .unwrap();
    let writer_b = topic
        .writer()
        .qos(qos.clone())
        .publisher(&publisher)
        .build()
        .unwrap();
    let mut small = qos.clone();
    small.resource_limits.max_samples = 1;
    let reader_a = topic
        .reader()
        .qos(small)
        .subscriber(&subscriber_a)
        .build()
        .unwrap();
    qos.resource_limits.max_samples = 2;
    let reader_b = Arc::new(
        topic
            .reader()
            .qos(qos)
            .subscriber(&subscriber_b)
            .build()
            .unwrap(),
    );
    writer_a
        .write(&Value {
            value: 0,
            refuse: false,
        })
        .unwrap();
    let drained = Arc::new(AtomicBool::new(false));
    reader_a.set_listener(
        Some(Arc::new(DrainPeer {
            reader: Arc::downgrade(&reader_b),
            subscriber: subscriber_b.clone(),
            drained: drained.clone(),
        })),
        StatusMask::SAMPLE_REJECTED,
    );
    publisher.begin_coherent_changes().unwrap();
    writer_a
        .write(&Value {
            value: 1,
            refuse: false,
        })
        .unwrap();
    writer_b
        .write(&Value {
            value: 2,
            refuse: false,
        })
        .unwrap();
    publisher.end_coherent_changes().unwrap();
    assert!(drained.load(Ordering::SeqCst));
    subscriber_b.begin_access().unwrap();
    assert_eq!(
        reader_b.take_all().unwrap(),
        vec![
            Value {
                value: 1,
                refuse: false
            },
            Value {
                value: 2,
                refuse: false
            }
        ]
    );
    subscriber_b.end_access().unwrap();
}

#[test]
fn publisher_order_is_independent_of_the_readers_binding_indices() {
    for coherent in [false, true] {
        let name = if coherent {
            "ordered-reverse-coherent"
        } else {
            "ordered-reverse-ordinary"
        };
        let participant = Participant::builder(name)
            .domain_id(0)
            .with_transport(TransportMode::IntraProcess)
            .build()
            .unwrap();
        let qos = QoS::reliable()
            .keep_all()
            .presentation_group_coherent_ordered();
        let publisher = Arc::new(participant.create_publisher(qos.clone()).unwrap());
        let subscriber = Arc::new(participant.create_subscriber(qos.clone()).unwrap());
        let topic = participant.topic::<Value>(name).unwrap();
        let a = topic
            .writer()
            .qos(qos.clone())
            .publisher(&publisher)
            .build()
            .unwrap();
        let b = topic
            .writer()
            .qos(qos.clone())
            .publisher(&publisher)
            .build()
            .unwrap();
        let reader = topic
            .reader()
            .qos(qos)
            .subscriber(&subscriber)
            .build()
            .unwrap();
        if coherent {
            publisher.begin_coherent_changes().unwrap();
        }
        b.write(&Value {
            value: 1,
            refuse: false,
        })
        .unwrap();
        a.write(&Value {
            value: 2,
            refuse: false,
        })
        .unwrap();
        if coherent {
            publisher.end_coherent_changes().unwrap();
        }
        subscriber.begin_access().unwrap();
        assert_eq!(
            reader.take_all().unwrap(),
            vec![
                Value {
                    value: 1,
                    refuse: false
                },
                Value {
                    value: 2,
                    refuse: false
                }
            ]
        );
        subscriber.end_access().unwrap();
    }
}
