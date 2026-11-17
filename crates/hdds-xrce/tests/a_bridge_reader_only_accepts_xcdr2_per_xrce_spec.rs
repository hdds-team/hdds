// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! DDS-XRCE v1.0 Sec.7.7.1: "the XCDRSerializedBuffer represents the bytes
//! resulting from serializing the application-specific data type that is
//! being sent using the XCDR version 2 rules defined in clause 7.4 of
//! [DDS-XTYPES]". Every DataRepresentation value an agent forwards to a
//! client is XCDR version 2, period -- there is no negotiation, and this
//! bridge never re-encodes a payload (it passes bytes through untouched).
//!
//! So `HddsBridge::create_reader` must request XCDR2 only: a DDS writer
//! that offers XCDR1 (the default for an unconfigured raw writer, since
//! `RawBytes::encodes_xcdr1_natively()` is true) must simply not match,
//! rather than have its bytes forwarded to a client under the XCDR2 label
//! the spec promises. Calls `HddsBridge` through the same `ProxyBridge`
//! trait methods the wire-level agent uses, skipping only the XRCE wire
//! framing itself (covered by `hdds_bridge_e2e.rs`).

#![cfg(feature = "hdds")]

use std::thread::sleep;
use std::time::{Duration, Instant};

use hdds::dds::{Participant, QoS, TransportMode};
use hdds_xrce::proxy::ProxyBridge;
use hdds_xrce::HddsBridge;

const DOMAIN: u32 = 142;
const TOPIC_XCDR1: &str = "XrceSpecProbeXcdr1";
const TOPIC_XCDR2: &str = "XrceSpecProbeXcdr2";
const TYPE_NAME: &str = "std_msgs::String";

fn wait_for(timeout: Duration, mut done: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if done() {
            return true;
        }
        sleep(Duration::from_millis(10));
    }
    done()
}

/// Build a bridge reader (via the public ProxyBridge API, exactly what the
/// agent calls for a client's CREATE DataReader) and a native writer on
/// `topic`, offering `writer_qos`. Returns whatever the bridge's reader
/// took after both sides had time to match and the writer published once.
fn probe(topic: &str, writer_qos: QoS) -> Vec<u8> {
    let bridge = HddsBridge::with_domain("xrce-spec-probe-bridge", DOMAIN);
    let participant_id = bridge.create_participant(DOMAIN as u16).unwrap();
    let topic_id = bridge
        .create_topic(participant_id, topic, TYPE_NAME)
        .unwrap();
    let reader_id = bridge.create_reader(participant_id, topic_id).unwrap();

    let native = Participant::builder("xrce-spec-probe-native")
        .domain_id(DOMAIN)
        .with_transport(TransportMode::UdpMulticast)
        .build()
        .unwrap();
    let writer = native
        .create_raw_writer_with_type(topic, TYPE_NAME, Some(writer_qos), None, None)
        .unwrap();

    sleep(Duration::from_millis(1500));
    writer.write_raw(&[0xDE, 0xAD, 0xBE, 0xEF]).unwrap();

    let mut got = Vec::new();
    let _ = wait_for(Duration::from_secs(3), || {
        if let Ok(Some(payload)) = bridge.read_data(reader_id) {
            got = payload;
            true
        } else {
            false
        }
    });
    got
}

#[test]
fn a_native_xcdr2_writer_reaches_the_bridge_reader() {
    let got = probe(TOPIC_XCDR2, QoS::default().data_representation_xcdr2());
    assert_eq!(
        got,
        vec![0xDE, 0xAD, 0xBE, 0xEF],
        "an XCDR2 source must reach the bridge reader: the spec requires exactly this"
    );
}

#[test]
fn a_native_xcdr1_writer_never_reaches_the_bridge_reader() {
    let got = probe(TOPIC_XCDR1, QoS::default().data_representation_xcdr1());
    assert!(
        got.is_empty(),
        "an XCDR1 source must NOT reach the bridge reader: forwarding it would mislabel \
         XCDR1 bytes as the XCDR2 the DDS-XRCE spec guarantees a client; got {got:?}"
    );
}
