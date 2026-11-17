// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! The relay end to end: a browser-protocol client over a real WebSocket, a
//! real DDS domain, and a native HDDS participant on the other side.
//!
//! Needs a multicast-capable interface (HDDS refuses loopback as the primary
//! interface), so it is a host test, run by the service-crates gate.

#![cfg(feature = "relay")]

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use hdds::dds::{Participant, TransportMode};
use hdds::QoS;
use hdds_wasm::protocol::{self, RelayMessage};
use hdds_wasm::qos::WasmQos;
use hdds_wasm::relay_server::RelayServer;
use tokio_tungstenite::tungstenite::Message;

/// This crate's own DDS domain.
const DOMAIN: u32 = 145;
const TOPIC: &str = "WasmChatter";
const TYPE_NAME: &str = "std_msgs::String";

/// Start the relay on an ephemeral loopback port. Returns the relay and its
/// ws:// URL; the caller keeps the relay alive.
async fn start_relay_with(name: &str, max_topics: usize) -> (Arc<RelayServer>, String) {
    let relay = RelayServer::new(DOMAIN, name)
        .expect("relay participant")
        .with_max_topics(max_topics);
    let listener = tokio::net::TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .expect("bind relay");
    let addr = listener.local_addr().expect("relay addr");
    let router = relay.router();
    tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    (relay, format!("ws://{}/ws", addr))
}

async fn start_relay(name: &str) -> String {
    let (relay, url) = start_relay_with(name, 64).await;
    // Keep the participant alive for the whole test.
    Box::leak(Box::new(relay));
    url
}

type Socket =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

/// Next protocol message, or None once `within` has elapsed with nothing.
async fn next_message_within(socket: &mut Socket, within: Duration) -> Option<RelayMessage> {
    let deadline = tokio::time::Instant::now() + within;
    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_millis(200), socket.next()).await {
            Ok(Some(Ok(Message::Binary(bytes)))) => {
                return protocol::parse_message(&bytes).ok();
            }
            Ok(Some(Ok(_))) => continue,
            Ok(Some(Err(_))) | Ok(None) => return None,
            Err(_) => continue,
        }
    }
    None
}

async fn next_message(socket: &mut Socket) -> Option<RelayMessage> {
    next_message_within(socket, Duration::from_secs(10)).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_browser_client_publishes_onto_dds_and_receives_from_dds() {
    let url = start_relay("hdds-wasm-relay-test").await;

    let native = Participant::builder("wasm-relay-native-peer")
        .domain_id(DOMAIN)
        .with_transport(TransportMode::UdpMulticast)
        .build()
        .expect("native participant");
    // The browser asks for RELIABLE below, so the relay's reader is RELIABLE.
    // A BEST_EFFORT writer does not satisfy a RELIABLE reader (RxO), so the
    // native peer must be reliable too or the DDS -> browser leg never
    // matches. That asymmetry is itself the proof that the CREATE_TOPIC QoS
    // block reaches the wire: with the QoS dropped both ends would be
    // best-effort and this would match by accident.
    let native_reader = native
        .create_raw_reader_with_type(TOPIC, TYPE_NAME, None, None, None)
        .expect("native reader");
    // The browser decodes XCDR2 only (the WASM SDK's `cdr` module), so the
    // relay's reader requests XCDR2 alone (DDS-XTypes 1.3 7.6.3.1.1: a reader
    // requests what it can deserialize). A writer that sets no list offers
    // XCDR and is refused (see
    // a_default_native_writer_is_refused_by_the_xcdr2_only_relay); a peer
    // writing for browsers offers XCDR2.
    let native_writer = native
        .create_raw_writer_with_type(
            TOPIC,
            TYPE_NAME,
            Some(QoS::reliable().data_representation_xcdr2()),
            None,
            None,
        )
        .expect("native writer");

    let (mut socket, _) = tokio_tungstenite::connect_async(&url)
        .await
        .expect("connect to the relay");

    // CONNECT -> CONNECT_ACK
    socket
        .send(Message::Binary(protocol::build_connect(0, 0)))
        .await
        .expect("send CONNECT");
    match next_message(&mut socket).await {
        Some(RelayMessage::ConnectAck { participant_id }) => assert!(participant_id > 0),
        other => panic!("expected CONNECT_ACK, got {:?}", other),
    }

    // CREATE_TOPIC carrying QoS -> TOPIC_ACK
    let qos = WasmQos::reliable();
    socket
        .send(Message::Binary(protocol::build_create_topic_with_qos(
            TOPIC,
            TYPE_NAME,
            Some(&qos),
            1,
        )))
        .await
        .expect("send CREATE_TOPIC");
    let topic_id = match next_message(&mut socket).await {
        Some(RelayMessage::TopicAck {
            topic_id,
            topic_name,
        }) => {
            assert_eq!(topic_name, TOPIC);
            topic_id
        }
        other => panic!("expected TOPIC_ACK, got {:?}", other),
    };

    socket
        .send(Message::Binary(protocol::build_subscribe(topic_id, 2)))
        .await
        .expect("send SUBSCRIBE");

    // Give SEDP time to match the relay's endpoints with the native peer's.
    tokio::time::sleep(Duration::from_millis(1500)).await;

    // Browser -> DDS.
    let sample = vec![0x41u8, 0x42, 0x43, 0x44];
    let mut seen_by_native = None;
    for _ in 0..60 {
        socket
            .send(Message::Binary(protocol::build_publish(
                topic_id, 3, &sample,
            )))
            .await
            .expect("send PUBLISH");
        tokio::time::sleep(Duration::from_millis(50)).await;
        let batch = native_reader.try_take_raw().expect("take");
        if let Some(s) = batch.into_iter().find(|s| s.payload == sample) {
            seen_by_native = Some(s.payload);
            break;
        }
    }
    assert_eq!(
        seen_by_native.as_deref(),
        Some(&sample[..]),
        "the native DDS reader never saw the browser's sample"
    );

    // DDS -> browser. One continuous drain against a single total deadline:
    // the native peer rewrites every 200 ms and every frame the relay pushes
    // is read as it arrives, so a failure costs the deadline once and not
    // once per attempt.
    let answer = vec![0x51u8, 0x52, 0x53];
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let mut next_write = tokio::time::Instant::now();
    let mut got: Vec<Vec<u8>> = Vec::new();
    let mut found = false;
    while tokio::time::Instant::now() < deadline && !found {
        if tokio::time::Instant::now() >= next_write {
            native_writer.write_raw(&answer).expect("native write");
            next_write = tokio::time::Instant::now() + Duration::from_millis(200);
        }
        if let Some(RelayMessage::Data {
            topic_id: id,
            payload,
            ..
        }) = next_message_within(&mut socket, Duration::from_millis(200)).await
        {
            assert_eq!(id, topic_id);
            found = payload == answer;
            got.push(payload);
        }
    }
    assert!(
        found,
        "the browser never received the native peer's sample; it saw {:?}",
        got
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_text_frame_and_a_malformed_frame_are_answered_with_an_error() {
    let url = start_relay("hdds-wasm-relay-errors").await;
    let (mut socket, _) = tokio_tungstenite::connect_async(&url)
        .await
        .expect("connect to the relay");

    socket
        .send(Message::Text("hello".to_string()))
        .await
        .expect("send text");
    match next_message(&mut socket).await {
        Some(RelayMessage::Error { reason }) => assert!(reason.contains("binary"), "{}", reason),
        other => panic!("expected ERROR, got {:?}", other),
    }

    socket
        .send(Message::Binary(vec![0xEE, 0, 0, 0, 0, 0, 0, 0]))
        .await
        .expect("send garbage");
    match next_message(&mut socket).await {
        Some(RelayMessage::Error { .. }) => {}
        other => panic!("expected ERROR, got {:?}", other),
    }
}

/// Connect, ask for `topic`, and return the socket plus the acknowledged id.
async fn connect_and_create(url: &str, topic: &str) -> (Socket, Option<u16>) {
    let (mut socket, _) = tokio_tungstenite::connect_async(url)
        .await
        .expect("connect to the relay");
    socket
        .send(Message::Binary(protocol::build_connect(0, 0)))
        .await
        .expect("send CONNECT");
    next_message(&mut socket).await;
    socket
        .send(Message::Binary(protocol::build_create_topic(
            topic, TYPE_NAME, 1,
        )))
        .await
        .expect("send CREATE_TOPIC");
    let id = match next_message(&mut socket).await {
        Some(RelayMessage::TopicAck { topic_id, .. }) => Some(topic_id),
        _ => None,
    };
    (socket, id)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_departing_client_takes_its_dds_endpoints_with_it() {
    let (relay, url) = start_relay_with("hdds-wasm-relay-lifecycle", 64).await;

    let (socket_a, id_a) = connect_and_create(&url, "LifecycleTopic").await;
    assert!(id_a.is_some());
    assert_eq!(relay.topic_count().await, 1);

    // A second client on the SAME topic holds it too.
    let (socket_b, id_b) = connect_and_create(&url, "LifecycleTopic").await;
    assert_eq!(id_a, id_b);
    assert_eq!(relay.topic_count().await, 1);

    // The first client leaves: the topic stays, because B still holds it.
    drop(socket_a);
    for _ in 0..50 {
        if relay.topic_count().await == 1 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
    assert_eq!(relay.topic_count().await, 1, "B still holds the topic");

    // The last client leaves: the endpoints and the polling task go with it.
    drop(socket_b);
    let mut released = false;
    for _ in 0..100 {
        if relay.topic_count().await == 0 {
            released = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        released,
        "the relay kept a DDS writer, a reader and a 5 ms polling task for a topic nobody uses"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_relay_refuses_more_topics_than_its_cap() {
    let (relay, url) = start_relay_with("hdds-wasm-relay-cap", 1).await;

    let (_socket, id) = connect_and_create(&url, "CapTopicOne").await;
    assert!(id.is_some());
    assert_eq!(relay.topic_count().await, 1);

    let (mut socket, _) = tokio_tungstenite::connect_async(&url)
        .await
        .expect("connect to the relay");
    socket
        .send(Message::Binary(protocol::build_connect(0, 0)))
        .await
        .expect("send CONNECT");
    next_message(&mut socket).await;
    socket
        .send(Message::Binary(protocol::build_create_topic(
            "CapTopicTwo",
            TYPE_NAME,
            1,
        )))
        .await
        .expect("send CREATE_TOPIC");
    match next_message(&mut socket).await {
        Some(RelayMessage::Error { reason }) => {
            assert!(reason.contains("maximum"), "{}", reason)
        }
        other => panic!("expected an ERROR past the cap, got {:?}", other),
    }
    assert_eq!(relay.topic_count().await, 1);
}

/// Bodies Eclipse Cyclone DDS 0.11.0 serializes for `@final struct U8I64 {
/// octet a; int64 b; }` with a = 0x11, b = 0x0102030405060708, at encoding
/// version 2 (identifier `{0x00, 0x07}`) and version 1 (`{0x00, 0x01}`)
/// (captured with a probe program; same vectors as the
/// crate's CDR unit tests).
const CYCLONE_U8I64_XCDR2: [u8; 12] = [
    0x11, 0, 0, 0, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
];

/// What a browser sends reaches a DDS peer under an XCDR2 identifier, with
/// the XCDR2 layout Cyclone writes for the same type; and a peer that
/// accepts XCDR1 only is not matched, rather than handed XCDR2 bytes under
/// an XCDR1 identifier.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_relay_puts_xcdr2_bytes_on_dds_under_an_xcdr2_identifier() {
    let url = start_relay("hdds-wasm-relay-encoding").await;
    let native = Participant::builder("wasm-relay-encoding-peer")
        .domain_id(DOMAIN)
        .with_transport(TransportMode::UdpMulticast)
        .build()
        .expect("native participant");

    const ANY: &str = "WasmEncodingAny";
    const X1: &str = "WasmEncodingXcdr1Only";
    let reader_any = native
        .create_raw_reader_with_type(ANY, TYPE_NAME, None, None, None)
        .expect("native reader");
    let reader_x1 = native
        .create_raw_reader_with_type(
            X1,
            TYPE_NAME,
            Some(QoS::default().data_representation_xcdr1()),
            None,
            None,
        )
        .expect("native XCDR1 reader");

    let (mut socket_any, id_any) = connect_and_create(&url, ANY).await;
    let (mut socket_x1, id_x1) = connect_and_create(&url, X1).await;
    let (id_any, id_x1) = (id_any.expect("topic"), id_x1.expect("topic"));

    tokio::time::sleep(Duration::from_millis(1500)).await;

    let mut enc = hdds_wasm::CdrEncoder::new();
    enc.encode_u8(0x11);
    enc.encode_i64(0x0102_0304_0506_0708);
    let body = enc.finish();
    assert_eq!(body, CYCLONE_U8I64_XCDR2);

    let mut seen_any = None;
    let mut seen_x1 = Vec::new();
    for _ in 0..40 {
        for (socket, id) in [(&mut socket_any, id_any), (&mut socket_x1, id_x1)] {
            socket
                .send(Message::Binary(protocol::build_publish(id, 3, &body)))
                .await
                .expect("send PUBLISH");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        for (sample, version) in reader_any.try_take_raw_with_encoding().expect("take") {
            seen_any.get_or_insert((sample.payload, version));
        }
        for (sample, version) in reader_x1.try_take_raw_with_encoding().expect("take") {
            seen_x1.push((sample.payload, version));
        }
    }

    assert_eq!(
        seen_any,
        Some((body.clone(), hdds::CdrVersion::Xcdr2)),
        "the browser's sample must reach DDS as XCDR2 bytes labelled XCDR2"
    );
    assert!(
        seen_x1.is_empty(),
        "an XCDR1-only reader must not be matched with the relay; it received {:?}",
        &seen_x1[..seen_x1.len().min(1)]
    );
}

/// What a native writer reports about the relay's reader.
#[derive(Default)]
struct WriterSeen {
    matched: std::sync::atomic::AtomicI32,
    incompatible_policy: std::sync::atomic::AtomicU32,
}

impl<T: hdds::DdsTrait> hdds::dds::DataWriterListener<T> for WriterSeen {
    fn on_publication_matched(&self, status: hdds::dds::PublicationMatchedStatus) {
        self.matched.store(
            status.current_count as i32,
            std::sync::atomic::Ordering::SeqCst,
        );
    }
    fn on_offered_incompatible_qos(&self, policy_id: u32, _policy_name: &str) {
        self.incompatible_policy
            .store(policy_id, std::sync::atomic::Ordering::SeqCst);
    }
}

/// A native writer that sets no DATA_REPRESENTATION offers XCDR
/// (DDS-XTypes 1.3 7.6.3.1.1); the relay's reader, whose browsers decode
/// XCDR2 only, requests XCDR2: the writer reports OFFERED_INCOMPATIBLE_QOS
/// for DATA_REPRESENTATION (policy 23), is never matched, and no browser
/// receives its XCDR1 bytes. The same writer offering XCDR2 is matched.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_default_native_writer_is_refused_by_the_xcdr2_only_relay() {
    use std::sync::atomic::Ordering;
    const DATA_REPRESENTATION: u32 = 23;
    let url = start_relay("hdds-wasm-relay-default-writer").await;
    let native = Participant::builder("wasm-relay-default-writer-peer")
        .domain_id(DOMAIN)
        .with_transport(TransportMode::UdpMulticast)
        .build()
        .expect("native participant");

    let (mut socket, id) = connect_and_create(&url, "WasmDefaultWriter").await;
    let topic_id = id.expect("topic");
    socket
        .send(Message::Binary(protocol::build_subscribe(topic_id, 2)))
        .await
        .expect("send SUBSCRIBE");

    let seen = Arc::new(WriterSeen::default());
    let writer = native
        .create_raw_writer_with_type(
            "WasmDefaultWriter",
            TYPE_NAME,
            None,
            None,
            Some(Arc::clone(&seen) as _),
        )
        .expect("native writer");
    assert_eq!(
        writer.qos().data_representation,
        vec![0x0000],
        "offers XCDR"
    );

    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while tokio::time::Instant::now() < deadline
        && seen.incompatible_policy.load(Ordering::SeqCst) == 0
    {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(
        seen.incompatible_policy.load(Ordering::SeqCst),
        DATA_REPRESENTATION,
        "the writer reports the relay's reader incompatible for DATA_REPRESENTATION"
    );
    assert_eq!(seen.matched.load(Ordering::SeqCst), 0);
    let payload = vec![0x61u8, 0x62];
    let mut got = Vec::new();
    for _ in 0..10 {
        writer.write_raw(&payload).expect("native write");
        if let Some(RelayMessage::Data { payload, .. }) =
            next_message_within(&mut socket, Duration::from_millis(100)).await
        {
            got.push(payload);
        }
    }
    assert!(got.is_empty(), "the browser received XCDR1 bytes: {got:?}");
}

/// The cap can be set on a relay somebody else already holds a reference
/// to (the `Arc` is shared, not uniquely owned).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_cap_is_set_on_a_shared_relay() {
    let relay = RelayServer::new(DOMAIN, "hdds-wasm-relay-shared-cap").expect("relay participant");
    let other_holder = Arc::clone(&relay);
    let relay = relay.with_max_topics(0);
    assert!(Arc::ptr_eq(&relay, &other_holder));
    assert_eq!(relay.topic_count().await, 0);
}
