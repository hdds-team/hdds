// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Integration tests for DDS-RPC module.

use super::*;

#[tokio::test]
async fn clients_on_same_service_keep_reply_correlation_distinct() {
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    let participant = crate::Participant::builder("rpc_two_clients")
        .domain_id(0)
        .with_transport(crate::TransportMode::IntraProcess)
        .build()
        .unwrap();
    let identities = Arc::new(Mutex::new(Vec::new()));
    let observed = identities.clone();
    let server = ServiceServer::new(&participant, "rpc_two_clients", move |id, bytes: &[u8]| {
        observed.lock().unwrap().push(id);
        Ok(bytes.to_vec())
    })
    .unwrap();
    let first = ServiceClient::new(&participant, "rpc_two_clients").unwrap();
    let second = ServiceClient::new(&participant, "rpc_two_clients").unwrap();
    tokio::select! {
        _ = server.spin() => panic!("server stopped before both replies"),
        _ = async {
            let (a, b) = tokio::join!(
                first.call_raw(b"first", Duration::from_secs(2)),
                second.call_raw(b"second", Duration::from_secs(2)),
            );
            assert_eq!(a.unwrap(), b"first");
            assert_eq!(b.unwrap(), b"second");
        } => {}
    }
    let identities = identities.lock().unwrap();
    assert_eq!(identities.len(), 2);
    assert_eq!(identities[0].sequence_number, identities[1].sequence_number);
    assert_ne!(identities[0].writer_guid, identities[1].writer_guid);
}

/// DDS-RPC 1.0 clause 7.4.2.3 lets topic names be specified at run
/// time, and 7.4.2 requires only that both ends of an exchange agree on
/// them -- not that they follow HDDS's `rq/`/`rr/` convention (7.4.1's own
/// default grammar is `<interface>_<service>_Request`/`_Reply`, which HDDS
/// does not use). `with_topic_names` is the escape hatch: point a client
/// and server at whatever names a peer expects.
#[tokio::test]
async fn service_client_and_server_agree_on_explicit_non_default_topic_names() {
    use std::time::Duration;

    let participant = crate::Participant::builder("rpc_explicit_topics")
        .domain_id(0)
        .with_transport(crate::TransportMode::IntraProcess)
        .build()
        .unwrap();

    // Deliberately NOT the `rq/{service}` / `rr/{service}` HDDS default --
    // the specification's own default grammar (7.4.1) for an interface
    // named "Calculator" with the default service name "Service".
    let request_topic = "Calculator_Service_Request";
    let reply_topic = "Calculator_Service_Reply";

    let server = ServiceServer::with_topic_names(
        &participant,
        "calculator",
        request_topic,
        reply_topic,
        |_id, bytes: &[u8]| Ok(bytes.to_vec()),
    )
    .unwrap();
    let client = ServiceClient::with_topic_names(
        &participant,
        "calculator",
        request_topic,
        reply_topic,
        Duration::from_secs(2),
    )
    .unwrap();

    tokio::select! {
        _ = server.spin() => panic!("server stopped before the reply"),
        result = client.call_raw(b"spec-topics", Duration::from_secs(2)) => {
            assert_eq!(result.unwrap(), b"spec-topics");
        }
    }
}

#[test]
fn wire_bodies_preserve_header_sizes_and_payload_offsets() {
    use super::client::RpcMessage;
    use crate::core::ser::{Cdr2Decode, Cdr2Encode};
    use crate::dds::{CdrVersion, DDS};

    // A DDS-RPC Basic Service Mapping request as a foreign peer lays it out
    // (layout pinned against fastddsgen 4.0.4 + Fast-CDR 2.3.3 vectors in
    // types.rs): RequestHeader with an empty instanceName, then the payload
    // at the next 4-byte boundary, where the `_Call` union would start.
    let mut request = vec![1u8; 12]; // writer_guid.guidPrefix
    request.extend_from_slice(&[0, 0, 1, 2]); // writer_guid.entityId
    request.extend_from_slice(&[0, 0, 0, 0]); // sequence_number.high
    request.extend_from_slice(&42u32.to_le_bytes()); // sequence_number.low
    request.extend_from_slice(&1u32.to_le_bytes()); // instanceName length, NUL included
    request.extend_from_slice(&[0, 0xee, 0xee, 0xee]); // "" + padding a peer never zeroes
    request.extend_from_slice(b"\0\xffrequest");
    let decoded = RpcMessage::decode(&request, CdrVersion::Xcdr2).unwrap();
    let (header, consumed) = RequestHeader::decode_cdr2_le(&decoded.bytes).unwrap();
    assert_eq!(consumed, 32);
    assert_eq!(header.request_id.sequence_number, 42);
    assert_eq!(header.request_id.writer_guid.prefix, [1; 12]);
    assert_eq!(header.request_id.writer_guid.entity_id, [0, 0, 1, 2]);
    assert_eq!(header.instance_name, "");
    assert_eq!(&decoded.bytes[consumed..], b"\0\xffrequest");
    let mut encoded = vec![0; request.len()];
    assert_eq!(
        decoded.encode(&mut encoded, CdrVersion::Xcdr2).unwrap(),
        request.len()
    );
    assert_eq!(encoded, request);
    // Re-encoding reproduces the peer's header; only the padding differs (ours is zero).
    assert_eq!(header.encode_cdr2_le(&mut encoded).unwrap(), consumed);
    assert_eq!(&encoded[..29], &request[..29]);
    assert_eq!(&encoded[29..32], &[0, 0, 0]);

    let mut reply = request[..24].to_vec();
    reply.extend_from_slice(&2i32.to_le_bytes()); // REMOTE_EX_INVALID_ARGUMENT
    reply.extend_from_slice(b"\xff\0reply");
    let decoded = RpcMessage::decode(&reply, CdrVersion::Xcdr2).unwrap();
    let (header, consumed) = ReplyHeader::decode_cdr2_le(&decoded.bytes).unwrap();
    assert_eq!(consumed, 28);
    assert_eq!(
        header.remote_exception_code,
        RemoteExceptionCode::InvalidArgument
    );
    assert_eq!(&decoded.bytes[consumed..], b"\xff\0reply");
    for len in 0..32 {
        assert!(RequestHeader::decode_cdr2_le(&request[..len]).is_err());
    }
    for len in 0..28 {
        assert!(ReplyHeader::decode_cdr2_le(&reply[..len]).is_err());
    }
}

#[tokio::test]
async fn server_timeout_replies_before_handler_finishes() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    let participant = crate::Participant::builder("rpc_handler_timeout")
        .domain_id(0)
        .with_transport(crate::TransportMode::IntraProcess)
        .build()
        .unwrap();
    let (release, receive) = std::sync::mpsc::channel::<()>();
    let receive = Mutex::new(receive);
    let completed = Arc::new(AtomicBool::new(false));
    let handler_completed = completed.clone();
    let server = ServiceServer::new(
        &participant,
        "rpc_handler_timeout",
        move |_id: SampleIdentity, _payload: &[u8]| {
            let _ = receive.lock().unwrap().recv();
            handler_completed.store(true, Ordering::Release);
            Ok(Vec::new())
        },
    )
    .unwrap()
    .with_request_timeout(Duration::from_millis(20));
    let client = ServiceClient::new(&participant, "rpc_handler_timeout").unwrap();
    tokio::select! {
        _ = server.spin() => panic!("server stopped before timeout reply"),
        _ = async {
            let result = tokio::time::timeout(
                Duration::from_secs(2),
                client.call_raw(b"wait", Duration::from_secs(30)),
            ).await.expect("server must reply before the client's own timeout");
            // DDS-RPC has no timeout code: the server reports its handler
            // timeout as REMOTE_EX_UNKNOWN_EXCEPTION, not as a local timeout.
            assert!(matches!(
                result,
                Err(RpcError::RemoteException {
                    code: RemoteExceptionCode::UnknownException,
                    ..
                })
            ));
            assert!(!completed.load(Ordering::Acquire));
            release.send(()).unwrap();
        } => {}
    }
    client.shutdown();
}

#[tokio::test]
async fn request_reply_preserves_binary_payload_and_reports_remote_error() {
    let participant = crate::Participant::builder("rpc_roundtrip")
        .domain_id(0)
        .with_transport(crate::TransportMode::IntraProcess)
        .build()
        .unwrap();
    let server = ServiceServer::new(
        &participant,
        "rpc_roundtrip",
        |_id: SampleIdentity, payload: &[u8]| {
            if payload == b"reject" {
                Err((RemoteExceptionCode::InvalidArgument, "rejected".into()))
            } else {
                Ok(payload.to_vec())
            }
        },
    )
    .unwrap();
    let client = ServiceClient::new(&participant, "rpc_roundtrip").unwrap();
    tokio::select! {
        _ = server.spin() => panic!("server stopped before the requests completed"),
        _ = async {
    for payload in [b"\0\xffbinary\0payload".as_slice(), b"".as_slice()] {
        let result = client
            .call_raw(payload, std::time::Duration::from_secs(2))
            .await;
        assert_eq!(result.unwrap(), payload);
    }
    assert!(matches!(
        client
            .call_raw(b"reject", std::time::Duration::from_secs(2))
            .await,
        Err(RpcError::RemoteException {
            code: RemoteExceptionCode::InvalidArgument,
            ..
        })
    ));
    client.shutdown();
        } => {}
    }
}

#[test]
fn test_rpc_qos_profile() {
    let qos = rpc_qos();

    // RPC should use reliable, keep-all, volatile
    assert!(matches!(qos.reliability, crate::dds::Reliability::Reliable));
    assert!(matches!(qos.history, crate::dds::History::KeepAll));
    assert!(matches!(qos.durability, crate::dds::Durability::Volatile));
}

/// DDS-RPC 1.0 (formal/17-04-01) clause 7.5.1.1 says the Basic
/// Service Mapping "maps interfaces to data-types that can be used by DDS
/// version 1.3 compliant implementations, which may lack support for the
/// [DDS-XTypes] specification" -- so an RPC writer must not offer the
/// XTypes-only XCDR2 representations. `rpc_qos()` pins `data_representation`
/// to XCDR1-only for exactly that reason.
#[test]
fn rpc_qos_offers_xcdr1_only_per_basic_mapping_clause_7_5_1_1() {
    assert_eq!(rpc_qos().data_representation, vec![0x0000]);
}

/// Chained through the SAME negotiation functions every other DDS
/// writer uses (`dds::cdr_negotiation`), pure and deterministic (no
/// discovery timing involved): an RPC writer's offered list is XCDR1-only,
/// so `resolve_writer_data_representation` resolves it to `Xcdr1` at
/// creation, whoever is matched, and RpcMessage carries no TypeObject (`get_type_object`
/// returns the trait default `None`), so its canonical (XCDR2) kind is the
/// `@final` fallback `0x0007` -- `encap_kind_for_version` then degrades that
/// to `0x0001` (`PLAIN_CDR_LE`), never the DDS-XTypes-only `0x0007`
/// (`PLAIN_CDR2_LE`) a Basic-mapping peer cannot be assumed to parse.
/// `see rpc_negotiates_plain_cdr_on_a_real_udp_wire` below for the same
/// claim proven on an actual wire capture, not just this function chain.
#[test]
fn rpc_qos_negotiates_to_plain_cdr_le_via_the_shared_cdr_negotiation_path() {
    use super::client::RpcMessage;
    use crate::dds::cdr_negotiation::{
        encap_kind_for_version, resolve_writer_data_representation, Xcdr1Encoding,
    };
    use crate::dds::{CdrVersion, DDS};

    let mut qos = rpc_qos();
    let version = resolve_writer_data_representation(&mut qos, Xcdr1Encoding::of::<RpcMessage>())
        .expect("XCDR1 is serializable");
    assert_eq!(version, CdrVersion::Xcdr1);
    assert_eq!(
        qos.data_representation,
        vec![0x0000],
        "an explicit list is kept"
    );

    // RpcMessage is untyped (get_type_object() == None), so its canonical
    // XCDR2 kind is the @final default 0x0007 -- the same value
    // `dds::writer::builder::canonical_encapsulation_kind` computes for it.
    assert!(RpcMessage::get_type_object().is_none());
    const CANONICAL_FINAL_XCDR2_KIND: u16 = 0x0007;
    assert_eq!(
        encap_kind_for_version(CANONICAL_FINAL_XCDR2_KIND, version),
        0x0001,
        "RPC must wind up on PLAIN_CDR_LE (0x0001), not PLAIN_CDR2_LE (0x0007)"
    );
}

/// Proven on the wire, not just in the negotiation functions above:
/// a real client and server over real UDP (not `TransportMode::IntraProcess`,
/// which never builds an RTPS DATA submessage or an encapsulation header at
/// all), with a third raw capture reader on the SAME request topic decoding
/// whatever representation id the writer actually put on the wire. HDDS's
/// own router (`cdr_version_from_representation_id`, used for every
/// cross-vendor topic, not just RPC) is what turns that representation id
/// into the `CdrVersion` this test asserts on -- the same decoder a foreign
/// peer's representation-id byte would be checked against, run against our
/// own writer's real output.
///
/// Ignored by default: it needs a host where UDP multicast actually
/// delivers SPDP (sandboxed or containerised environments often do not;
/// plain-UDP tests such as `frag_user_data_e2e::test_100kb_sample_udp_roundtrip`
/// fail there too). Run with `--ignored` on a host with working multicast.
#[tokio::test]
#[ignore = "needs a host where UDP multicast delivers SPDP; run with --ignored"]
async fn rpc_negotiates_plain_cdr_on_a_real_udp_wire() {
    use crate::dds::CdrVersion;
    use crate::test_support::domains::unique_domain;
    use crate::{Participant, TransportMode};
    use std::time::Duration;

    let domain = unique_domain();
    let service = "rpc_r88c_wire_probe";
    let request_topic = format!("rq/{}", service);

    let server_part = Participant::builder("rpc_r88c_server")
        .domain_id(domain.id())
        .with_transport(TransportMode::UdpMulticast)
        .build()
        .expect("server participant");

    // A second reader on the exact request topic/type/QoS the server's own
    // request_reader uses, purely to observe the wire encoding: RawBytes
    // preserves the CdrVersion the router decoded from the sample's actual
    // representation id (see `RawDataReader::try_take_raw_with_encoding`).
    let capture = server_part
        .create_raw_reader_with_type(&request_topic, "RpcMessage", Some(rpc_qos()), None, None)
        .expect("raw capture reader");

    let server = ServiceServer::new(
        &server_part,
        service,
        |_id, bytes: &[u8]| Ok(bytes.to_vec()),
    )
    .expect("server");

    let client_part = Participant::builder("rpc_r88c_client")
        .domain_id(domain.id())
        .with_transport(TransportMode::UdpMulticast)
        .build()
        .expect("client participant");
    let client = ServiceClient::new(&client_part, service).expect("client");

    tokio::select! {
        _ = server.spin() => panic!("server stopped before the reply"),
        result = async {
            // Retry the call: RELIABLE + KEEP_ALL survives the discovery
            // window, but the client's own writer/reader must still have
            // matched the server's before the first write is admitted.
            let mut last_err = None;
            for _ in 0..50 {
                match client.call_raw(b"ping", Duration::from_millis(500)).await {
                    Ok(reply) => {
                        assert_eq!(reply, b"ping");
                        last_err = None;
                        break;
                    }
                    Err(e) => {
                        last_err = Some(e);
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
            }
            if let Some(e) = last_err {
                panic!("RPC call never succeeded: {:?}", e);
            }

            // Drain the raw capture reader for the request the server just
            // handled, retrying briefly in case delivery to this SECOND
            // reader lags behind the server's own.
            for _ in 0..50 {
                let captured = capture.try_take_raw_with_encoding().expect("raw take");
                if let Some((_, version)) = captured.into_iter().next() {
                    assert_eq!(
                        version,
                        CdrVersion::Xcdr1,
                        "RPC request must be encoded XCDR1 (PLAIN_CDR), not XCDR2"
                    );
                    return;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            panic!("raw capture reader never observed the request");
        } => result,
    }

    client.shutdown();
}

#[test]
fn test_sample_identity_hash() {
    use std::collections::HashSet;

    let id1 = SampleIdentity::new(crate::core::discovery::GUID::zero(), 1);
    let id2 = SampleIdentity::new(crate::core::discovery::GUID::zero(), 2);
    let id1_clone = SampleIdentity::new(crate::core::discovery::GUID::zero(), 1);

    let mut set = HashSet::new();
    set.insert(id1);
    set.insert(id2);

    assert_eq!(set.len(), 2);
    assert!(set.contains(&id1_clone));
}

#[test]
fn test_request_header_creation() {
    let id = SampleIdentity::new(crate::core::discovery::GUID::zero(), 42);
    let header = RequestHeader::new(id);

    assert_eq!(header.request_id.sequence_number, 42);
    assert_eq!(header.instance_name, "");
}

#[test]
fn test_reply_header_success() {
    let id = SampleIdentity::new(crate::core::discovery::GUID::zero(), 42);
    let header = ReplyHeader::success(id);

    assert!(header.is_success());
    assert_eq!(header.remote_exception_code, RemoteExceptionCode::Ok);
}

#[test]
fn test_reply_header_error() {
    let id = SampleIdentity::new(crate::core::discovery::GUID::zero(), 42);
    let header = ReplyHeader::error(id, RemoteExceptionCode::UnknownException);

    assert!(!header.is_success());
    assert_eq!(
        header.remote_exception_code,
        RemoteExceptionCode::UnknownException
    );
}

#[test]
fn test_rpc_error_display() {
    let err = RpcError::Timeout;
    assert!(err.to_string().contains("timed out"));

    let err = RpcError::ServiceNotFound("calc".to_string());
    assert!(err.to_string().contains("calc"));

    let err = RpcError::remote(RemoteExceptionCode::InvalidArgument);
    assert!(err.to_string().contains("InvalidArgument"));
}

#[test]
fn test_rpc_error_from_code() {
    // No remote code maps to the local Timeout: that one is the client's own deadline.
    let err = RpcError::from_code(RemoteExceptionCode::UnknownException);
    assert!(matches!(
        err,
        RpcError::RemoteException {
            code: RemoteExceptionCode::UnknownException,
            ..
        }
    ));

    let err = RpcError::from_code(RemoteExceptionCode::InvalidArgument);
    assert!(matches!(
        err,
        RpcError::RemoteException {
            code: RemoteExceptionCode::InvalidArgument,
            ..
        }
    ));
}
