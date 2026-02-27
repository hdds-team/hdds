// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

// Test intra-process delivery through RmwContext
// Simulates what rmw_hdds does: create context, writer, reader, publish, wait

use hdds::rmw::context::RmwContext;
use std::time::Duration;

#[derive(hdds::DDS, Debug)]
struct TestMsg {
    pub value: i32,
}

#[test]
fn test_rmw_context_intra_process_delivery() {
    // 1. Create an RmwContext (same as ForeignRmwContext::create does)
    let ctx = RmwContext::create("test_intra").unwrap();
    let participant = ctx.participant();

    // 2. Create reader
    let reader = participant
        .create_reader::<TestMsg>("test_topic", hdds::QoS::default())
        .expect("create reader");

    // 3. Create writer
    let writer = participant
        .create_writer::<TestMsg>("test_topic", hdds::QoS::default())
        .expect("create writer");

    // 4. Bind reader to writer (intra-process delivery)
    reader.bind_to_writer(writer.merger());

    // 5. Attach reader's status condition to the context waitset
    let handle = ctx.attach_reader(&reader).expect("attach reader");
    let key = handle.key();
    eprintln!("reader attached with key={}", key);

    // 6. Write a message
    let msg = TestMsg { value: 42 };
    writer.write(&msg).expect("write");
    eprintln!("message written");

    // 7. Wait - should trigger since data was delivered intra-process
    let triggered = ctx.wait(Some(Duration::from_secs(2))).expect("wait");

    eprintln!("triggered keys: {:?}", triggered);
    assert!(
        !triggered.is_empty(),
        "wait should return triggered conditions after intra-process delivery"
    );
    assert!(
        triggered.contains(&key),
        "triggered conditions should include our reader's key"
    );

    // 8. Take the message
    let sample = reader.take().expect("take");
    assert!(sample.is_some(), "should have a sample to take");
    let sample = sample.unwrap();
    assert_eq!(sample.value, 42);
    eprintln!("received message: value={}", sample.value);
}
