// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! The key-only DATA of a dispose is framed like the writer's DATA.
//!
//! RTPS 2.5 9.4.5.3: with K=1 the serializedPayload "contains the
//! serialized Key", and DDS-XTypes 1.3 7.2.2.4.7 defines the key as the
//! KeyHolder of the type, which keeps the type's extensibility (only the
//! KeyHash, 7.6.8, makes it FINAL). So the K payload carries the same
//! encapsulation identifier as a DATA of the same writer at the same CDR
//! version, and the body that identifier announces. A writer must not stamp
//! every K payload D_CDR2_LE, encoded at XCDR2 whatever it had negotiated.

use super::WriterBuilder;
use crate::core::discovery::GUID;
use crate::dds::{CdrVersion, QoS, DDS};
use crate::protocol::builder::RtpsEndpointContext;
use crate::transport::{PortMapping, UdpTransport};
use std::sync::Arc;
use std::time::Duration;

/// `@final struct { @key octet t; @key long long v; long x; }`.
#[derive(Debug, Clone, Copy, PartialEq, crate::DDS)]
struct Keyed {
    #[key]
    t: u8,
    #[key]
    v: i64,
    x: i32,
}

/// The encapsulation identifier and the bytes after the 4-byte
/// encapsulation header of the first DATA (RTPS header + INFO_TS + DATA)
/// whose flags have `flag` set.
fn payload_of(packets: &[Vec<u8>], flag: u8) -> Option<(u16, Vec<u8>)> {
    packets.iter().find_map(|pkt| {
        if pkt.len() < 40 || pkt[32] != 0x15 || pkt[33] & flag == 0 {
            return None;
        }
        let body = 36usize;
        let oti = usize::from(u16::from_le_bytes([pkt[body + 2], pkt[body + 3]]));
        let mut at = body + 4 + oti;
        loop {
            let pid = u16::from_le_bytes([pkt[at], pkt[at + 1]]);
            let len = usize::from(u16::from_le_bytes([pkt[at + 2], pkt[at + 3]]));
            at += 4 + len;
            if pid == 0x0001 {
                break;
            }
        }
        let kind = u16::from_be_bytes([pkt[at], pkt[at + 1]]);
        let submessage_end = 36 + usize::from(u16::from_le_bytes([pkt[34], pkt[35]]));
        Some((kind, pkt[at + 4..submessage_end].to_vec()))
    })
}

/// Write one sample, dispose its instance, and capture both packets.
fn data_and_dispose(representation: Vec<u16>, participant_id: u8) -> (Vec<Vec<u8>>, CdrVersion) {
    let lease = crate::test_support::domains::unique_domain();
    let mapping = PortMapping::calculate(lease.id(), participant_id).expect("port mapping");
    let transport =
        Arc::new(UdpTransport::new(lease.id(), participant_id, mapping).expect("transport"));
    let mut writer = WriterBuilder::<Keyed>::new("test/key_payload".to_string())
        .qos(QoS {
            data_representation: representation,
            ..QoS::reliable().transient_local().keep_all()
        })
        .with_transport(transport)
        .build()
        .expect("writer build");
    // The canonical kind the builder derives from the derived TypeObject
    // (IS_FINAL); set by hand because this writer has no participant.
    writer.rtps_endpoint = Some(RtpsEndpointContext {
        guid_prefix: [0x35; 12],
        reader_entity_id: [0; 4],
        writer_entity_id: [0x00, 0x00, 0x01, 0x03],
        encapsulation_kind: 0x0007,
        publisher_entity_id: [0x00, 0x00, 0x01, 0x08],
    });
    let capture = crate::test_support::ports::bind_capture_socket();
    capture
        .set_read_timeout(Some(Duration::from_millis(300)))
        .expect("timeout");
    let registry = crate::core::discovery::EndpointRegistry::new();
    registry.register(
        GUID::new([0x46; 12], [0x00, 0x00, 0x01, 0xC1]),
        capture.local_addr().expect("capture addr"),
    );
    writer.endpoint_registry = Some(registry);
    let version = writer.effective_cdr_version();

    let sample = Keyed { t: 1, v: 2, x: 3 };
    writer.write(&sample).expect("write");
    writer.dispose(&sample).expect("dispose");

    let mut packets = Vec::new();
    let mut buf = [0u8; 4096];
    while let Ok((n, _)) = capture.recv_from(&mut buf) {
        packets.push(buf[..n].to_vec());
    }
    (packets, version)
}

/// Including a writer that set no DATA_REPRESENTATION: it offers XCDR
/// (DDS-XTypes v1.3 Sec.7.6.3.1.1) and its DATA carries CDR_LE (0x0001) on
/// the wire. Before: with no reader known it encoded XCDR2 (0x0007).
#[test]
fn a_dispose_is_framed_like_the_writers_data_under_xcdr2_and_xcdr1() {
    for (representation, version, wire_kind, participant_id) in [
        (vec![0x0002], CdrVersion::Xcdr2, 0x0007u16, 11u8),
        (vec![0x0000], CdrVersion::Xcdr1, 0x0001u16, 12u8),
        (vec![], CdrVersion::Xcdr1, 0x0001u16, 14u8),
    ] {
        let (packets, negotiated) = data_and_dispose(representation, participant_id);
        assert_eq!(negotiated, version);
        let (data_kind, _) = payload_of(&packets, 0x04).expect("the DATA arrives");
        let (key_kind, key_body) = payload_of(&packets, 0x08).expect("the dispose arrives");
        assert_eq!(data_kind, wire_kind, "{version:?}: data encapsulation");
        assert_eq!(key_kind, data_kind, "{version:?}: K and D encapsulation");
        // The body that identifier announces: the key members, no DHEADER,
        // aligned as the version aligns them; then RTPS padding to 4.
        let key = Keyed { t: 1, v: 2, x: 3 }.encode_key(version);
        assert_eq!(&key_body[..key.len()], &key[..], "{version:?}: K body");
        assert!(key_body[key.len()..].iter().all(|b| *b == 0));
    }
}

/// A dispose journals the version its key was encoded with, so a repair or
/// a late joiner's replay frames it the same way.
#[test]
fn a_dispose_journals_the_cdr_version_of_its_key() {
    let lease = crate::test_support::domains::unique_domain();
    let mapping = PortMapping::calculate(lease.id(), 13).expect("port mapping");
    let transport = Arc::new(UdpTransport::new(lease.id(), 13, mapping).expect("transport"));
    let writer = WriterBuilder::<Keyed>::new("test/key_payload_journal".to_string())
        .qos(QoS {
            data_representation: vec![0x0000],
            ..QoS::reliable().transient_local().keep_all()
        })
        .with_transport(transport)
        .build()
        .expect("writer build");
    let cache = writer.history_cache.clone().expect("reliable writer cache");
    let sample = Keyed { t: 1, v: 2, x: 3 };
    let seq = writer.next_seq.load(std::sync::atomic::Ordering::Relaxed);
    writer.dispose(&sample).expect("dispose");
    let change = cache
        .get_change(seq)
        .expect("the dispose is in the history");
    assert_eq!(change.metadata.cdr_version, CdrVersion::Xcdr1);
    assert_eq!(change.payload, sample.encode_key(CdrVersion::Xcdr1));
}

/// A NACK repair or a late joiner's replay rebuilds a dispose from the
/// history with the CDR version journaled with it: an XCDR1 key is framed
/// CDR_LE again, not as XCDR2.
#[test]
fn a_rebuilt_dispose_keeps_the_version_it_was_journaled_with() {
    let ctx = RtpsEndpointContext {
        guid_prefix: [0x35; 12],
        reader_entity_id: [0; 4],
        writer_entity_id: [0x00, 0x00, 0x01, 0x03],
        encapsulation_kind: 0x0007,
        publisher_entity_id: [0x00, 0x00, 0x01, 0x08],
    };
    let key = Keyed { t: 1, v: 2, x: 3 };
    for version in [CdrVersion::Xcdr1, CdrVersion::Xcdr2] {
        let change = crate::reliability::CachedChange {
            seq: 4,
            payload: key.encode_key(version),
            metadata: crate::reliability::ChangeMetadata {
                key_hash: Some(key.compute_key()),
                cdr_version: version,
                source_ts: (1, 2),
                source_ts_known: true,
                status_info: Some(crate::protocol::builder::StatusInfoKind::Disposed),
                ..crate::reliability::ChangeMetadata::user_data()
            },
            group: None,
        };
        let packet =
            super::nack::lifecycle_change_packet(Some(ctx), "test/key_payload", &change, false)
                .expect("a lifecycle change");
        let (kind, body) = payload_of(&[packet], 0x08).expect("a key-only DATA");
        assert_eq!(
            kind,
            crate::dds::cdr_negotiation::encap_kind_for_version(0x0007, version),
            "{version:?}"
        );
        assert_eq!(&body[..change.payload.len()], &change.payload[..]);
    }
}
