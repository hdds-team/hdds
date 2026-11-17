// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! DDS 1.4 2.2.3.6 ordered access and 2.2.4.5 ReadConditions: making a
//! retained later sample accessible must wake a waiter without another arrival.

use hdds::dds::{Condition, InstanceStateMask, SampleStateMask, ViewStateMask};
use hdds::{Participant, QoS, TransportMode};
use std::sync::{mpsc, Arc};
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, hdds::DDS)]
struct Value {
    value: i32,
}

fn qos() -> QoS {
    QoS::reliable()
        .keep_all()
        .presentation_group_coherent_ordered()
}

fn condition(reader: &Arc<hdds::DataReader<Value>>) -> Arc<hdds::dds::ReadCondition> {
    reader
        .create_readcondition(
            SampleStateMask::ANY,
            ViewStateMask::ANY,
            InstanceStateMask::ANY,
        )
        .unwrap()
}

fn access_unblocks_peer(drop_first: bool) {
    let name = if drop_first {
        "group-order-delete-wake"
    } else {
        "group-order-access-wake"
    };
    let participant = Participant::builder(name)
        .domain_id(0)
        .with_transport(TransportMode::IntraProcess)
        .build()
        .unwrap();
    let publisher = Arc::new(participant.create_publisher(qos()).unwrap());
    let subscriber = Arc::new(participant.create_subscriber(qos()).unwrap());
    let a = participant.topic::<Value>(&format!("{name}-a")).unwrap();
    let b = participant.topic::<Value>(&format!("{name}-b")).unwrap();
    let writer_a = a.writer().qos(qos()).publisher(&publisher).build().unwrap();
    let writer_b = b.writer().qos(qos()).publisher(&publisher).build().unwrap();
    let reader_a = Arc::new(
        a.reader()
            .qos(qos())
            .subscriber(&subscriber)
            .build()
            .unwrap(),
    );
    let reader_b = Arc::new(
        b.reader()
            .qos(qos())
            .subscriber(&subscriber)
            .build()
            .unwrap(),
    );
    writer_a.write(&Value { value: 1 }).unwrap();
    writer_b.write(&Value { value: 2 }).unwrap();
    subscriber.begin_access().unwrap();
    let condition_b = condition(&reader_b);
    assert!(!condition_b.get_trigger_value(), "GSN 2 waits for GSN 1");
    let waitset = hdds::WaitSet::new();
    waitset.attach_condition(condition_b.clone()).unwrap();
    hdds::test_support::coherent_race::before_next_wait(&waitset, move || {
        if !drop_first {
            assert_eq!(reader_a.take().unwrap(), Some(Value { value: 1 }));
        }
        drop(reader_a);
    });
    assert!(
        waitset.wait(Some(Duration::from_secs(2))).is_ok(),
        "advancing the Subscriber order must signal its newly accessible peer"
    );
    assert_eq!(reader_b.take().unwrap(), Some(Value { value: 2 }));
    subscriber.end_access().unwrap();
}

#[test]
fn taking_an_earlier_reader_wakes_a_waiting_later_readcondition() {
    access_unblocks_peer(false);
}

#[test]
fn deleting_an_earlier_reader_wakes_a_waiting_later_readcondition() {
    access_unblocks_peer(true);
}

std::thread_local! {
    static FAILING_ENCODE: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
}

#[derive(Debug, Clone)]
struct FailableValue {
    value: i32,
    fail: bool,
}

impl hdds::dds::DDS for FailableValue {
    fn type_descriptor() -> &'static hdds::core::types::TypeDescriptor {
        <Value as hdds::dds::DDS>::type_descriptor()
    }
    fn encode(&self, bytes: &mut [u8], version: hdds::dds::CdrVersion) -> hdds::dds::Result<usize> {
        if self.fail {
            FAILING_ENCODE.with(|hook| {
                if let Some(hook) = hook.borrow_mut().take() {
                    hook();
                }
            });
            return Err(hdds::Error::Config(
                "intentional encoding refusal".to_string(),
            ));
        }
        <Value as hdds::dds::DDS>::encode(&Value { value: self.value }, bytes, version)
    }
    fn decode(bytes: &[u8], version: hdds::dds::CdrVersion) -> hdds::dds::Result<Self> {
        <Value as hdds::dds::DDS>::decode(bytes, version).map(|value| Self {
            value: value.value,
            fail: false,
        })
    }
}

#[test]
fn cancelling_an_unpublished_lower_gsn_wakes_a_waiting_later_readcondition() {
    let participant = Participant::builder("group-order-cancel-wake")
        .domain_id(0)
        .with_transport(TransportMode::IntraProcess)
        .build()
        .unwrap();
    let publisher = Arc::new(participant.create_publisher(qos()).unwrap());
    let subscriber = Arc::new(participant.create_subscriber(qos()).unwrap());
    let a = participant
        .topic::<FailableValue>("group-order-cancel-wake-a")
        .unwrap();
    let b = participant
        .topic::<Value>("group-order-cancel-wake-b")
        .unwrap();
    let writer_a = a.writer().qos(qos()).publisher(&publisher).build().unwrap();
    let writer_b = b.writer().qos(qos()).publisher(&publisher).build().unwrap();
    let _reader_a = a
        .reader()
        .qos(qos())
        .subscriber(&subscriber)
        .build()
        .unwrap();
    let reader_b = Arc::new(
        b.reader()
            .qos(qos())
            .subscriber(&subscriber)
            .build()
            .unwrap(),
    );
    let (encoding, entered) = mpsc::channel();
    let (resume, resumed) = mpsc::channel();
    let producer = std::thread::spawn(move || {
        FAILING_ENCODE.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                encoding.send(()).unwrap();
                resumed.recv().unwrap();
            }))
        });
        writer_a.write(&FailableValue {
            value: 1,
            fail: true,
        })
    });
    entered
        .recv_timeout(Duration::from_secs(2))
        .expect("lower GSN reserved before encoding");
    writer_b.write(&Value { value: 2 }).unwrap();
    subscriber.begin_access().unwrap();
    let condition_b = condition(&reader_b);
    assert!(!condition_b.get_trigger_value());
    let waitset = Arc::new(hdds::WaitSet::new());
    waitset.attach_condition(condition_b).unwrap();
    let (waiting, armed) = mpsc::channel();
    hdds::test_support::coherent_race::before_next_wait(&waitset, move || {
        waiting.send(()).unwrap()
    });
    let waiter = {
        let waitset = waitset.clone();
        std::thread::spawn(move || waitset.wait(Some(Duration::from_secs(2))))
    };
    armed
        .recv_timeout(Duration::from_secs(2))
        .expect("false condition scan completed");
    resume.send(()).unwrap();
    assert!(
        producer.join().unwrap().is_err(),
        "the first change was never published"
    );
    assert!(
        waiter.join().unwrap().is_ok(),
        "pending-token cancellation must wake GSN 2"
    );
    assert_eq!(reader_b.take().unwrap(), Some(Value { value: 2 }));
    subscriber.end_access().unwrap();
}
