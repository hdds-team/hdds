// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! RTPS 2.5 9.6.4.8 and 9.4.5.3: keyed DATA carries the instance
//! hash, lifecycle DATA carries the serialized key, and the endpoint's
//! entity kind announces WITH_KEY. DDS 1.4 2.2.2.4.2: registration emits
//! nothing, and dispose/unregister address that same instance.

use super::*;
use hdds::test_support::domains::{unique_domain, DomainLease};
use hdds::test_support::wire::{capture_data, drain};
use std::ffi::CString;

fn domain() -> DomainLease {
    let mut other = Vec::new();
    loop {
        let lease = unique_domain();
        if (200..=230).contains(&lease.id()) {
            return lease;
        }
        other.push(lease);
    }
}

unsafe fn participant(domain: u32) -> *mut HddsParticipant {
    let name = CString::new("serialized_keys").unwrap();
    let config = transport_config::hdds_config_create(name.as_ptr());
    assert_eq!(
        transport_config::hdds_config_set_domain_id(config, domain),
        HddsError::HddsOk
    );
    let p = transport_config::hdds_config_build(config);
    assert!(!p.is_null());
    p
}

fn key(id: u32, payload: &[u8]) -> HddsSerializedKey {
    let mut hash = [0; 16];
    hash[..4].copy_from_slice(&id.to_be_bytes());
    HddsSerializedKey {
        hash,
        protected_hash: {
            let mut holder = hdds::core::key_hash::KeyHolderWriter::for_security();
            holder.write_u32(id);
            holder.finish(hdds::core::key_hash::KeyMaxSize::Unbounded)
        },
        payload: payload.as_ptr(),
        payload_len: payload.len(),
        representation: 2,
    }
}

#[derive(Debug)]
struct Change {
    writer_kind: u8,
    timestamp: Option<(u32, u32)>,
    flags: u8,
    hash: Option<[u8; 16]>,
    status: Option<[u8; 4]>,
    payload: Vec<u8>,
}

fn changes(packets: Vec<Vec<u8>>) -> Vec<Change> {
    let mut out = Vec::new();
    for packet in packets {
        let mut at = 20;
        let mut timestamp = None;
        while at + 4 <= packet.len() {
            let len = usize::from(u16::from_le_bytes([packet[at + 2], packet[at + 3]]));
            let end = if len == 0 { packet.len() } else { at + 4 + len };
            assert!(end <= packet.len());
            if packet[at] == 0x09 && packet[at + 1] & 2 == 0 && len == 8 {
                timestamp = Some((
                    u32::from_le_bytes(packet[at + 4..at + 8].try_into().unwrap()),
                    u32::from_le_bytes(packet[at + 8..at + 12].try_into().unwrap()),
                ));
            }
            if packet[at] == 0x15 {
                let body = at + 4;
                let flags = packet[at + 1];
                let oti = usize::from(u16::from_le_bytes([packet[body + 2], packet[body + 3]]));
                let mut p = body + 4 + oti;
                let mut hash = None;
                let mut status = None;
                if flags & 2 != 0 {
                    loop {
                        let pid = u16::from_le_bytes([packet[p], packet[p + 1]]);
                        let n = usize::from(u16::from_le_bytes([packet[p + 2], packet[p + 3]]));
                        p += 4;
                        if pid == 0x70 {
                            hash = Some(packet[p..p + 16].try_into().unwrap());
                        }
                        if pid == 0x71 {
                            status = Some(packet[p..p + 4].try_into().unwrap());
                        }
                        p += n;
                        if pid == 1 {
                            break;
                        }
                    }
                }
                out.push(Change {
                    writer_kind: packet[body + 11],
                    timestamp,
                    flags,
                    hash,
                    status,
                    payload: packet[p..end].to_vec(),
                });
            }
            if len == 0 {
                break;
            }
            at = end;
        }
    }
    out
}

#[test]
fn keyed_abi_preserves_hashes_and_key_payloads_for_every_operation() {
    let lease = domain();
    unsafe {
        let p = participant(lease.id());
        let topic = CString::new("keys_wire").unwrap();
        let qos = qos::hdds_qos_reliable();
        let w = hdds_writer_create_keyed(p, topic.as_ptr(), ptr::null(), qos, 0);
        assert!(!w.is_null());
        let socket = capture_data(&mut *w.cast::<DataWriter<BytePayload>>());
        for id in 1u32..=3 {
            let bytes = id.to_le_bytes();
            let identity = key(id, &bytes);
            let mut handle = HddsInstanceHandle::default();
            assert_eq!(
                hdds_writer_register_instance_keyed(w, ptr::null(), 0, &identity, &mut handle),
                HddsError::HddsOk
            );
            assert_eq!(handle.value, identity.hash);
            assert_eq!(
                hdds_writer_register_instance_w_timestamp_keyed(
                    w,
                    ptr::null(),
                    0,
                    &identity,
                    123,
                    &mut handle
                ),
                HddsError::HddsOk
            );
            assert_eq!(handle.value, identity.hash);
        }
        assert!(
            changes(drain(&socket)).is_empty(),
            "registration emits no DATA"
        );
        for id in 1u32..=3 {
            let bytes = id.to_le_bytes();
            let identity = key(id, &bytes);
            assert_eq!(
                hdds_writer_write_keyed(w, bytes.as_ptr().cast(), bytes.len(), &identity),
                HddsError::HddsOk
            );
            assert_eq!(
                hdds_writer_write_w_timestamp_keyed(
                    w,
                    bytes.as_ptr().cast(),
                    bytes.len(),
                    &identity,
                    123
                ),
                HddsError::HddsOk
            );
        }
        let bytes = 2u32.to_le_bytes();
        let identity = key(2, &bytes);
        assert_eq!(
            hdds_writer_dispose_keyed(w, ptr::null(), 0, &identity),
            HddsError::HddsOk
        );
        assert_eq!(
            hdds_writer_dispose_w_timestamp_keyed(w, ptr::null(), 0, &identity, 123),
            HddsError::HddsOk
        );
        let bytes3 = 3u32.to_le_bytes();
        let identity3 = key(3, &bytes3);
        assert_eq!(
            hdds_writer_unregister_instance_keyed(w, ptr::null(), 0, &identity3),
            HddsError::HddsOk
        );
        assert_eq!(
            hdds_writer_unregister_instance_w_timestamp_keyed(w, ptr::null(), 0, &identity3, 123),
            HddsError::HddsOk
        );
        let seen = changes(drain(&socket));
        assert_eq!(seen.len(), 10);
        for (i, change) in seen.iter().enumerate() {
            assert_eq!(change.writer_kind, 0x02, "WITH_KEY, RTPS Table 9.1");
            if i % 2 == 1 {
                assert_eq!(
                    change.timestamp,
                    Some((0, ((123u64 << 32) / 1_000_000_000) as u32)),
                    "explicit nanosecond timestamp is preserved by each keyed variant"
                );
            }
            let id = if i < 6 {
                i as u32 / 2 + 1
            } else if i < 8 {
                2
            } else {
                3
            };
            let bytes = id.to_le_bytes();
            assert_eq!(change.hash, Some(key(id, &bytes).hash));
            assert_eq!(change.flags & 0x0c, if i < 6 { 4 } else { 8 });
            assert_eq!(&change.payload[..4], &[0, 7, 0, 0]);
            assert_eq!(&change.payload[4..8], &bytes);
            assert_eq!(
                change.status,
                if i < 6 {
                    None
                } else {
                    Some([0, 0, 0, if i < 8 { 1 } else { 3 }])
                }
            );
        }
        hdds_writer_destroy(w);
        qos::hdds_qos_destroy(qos);
        hdds_participant_destroy(p);
    }
}

#[test]
fn keyed_abi_refuses_missing_metadata_wrong_encoding_and_legacy_handles() {
    unsafe {
        let name = CString::new("keys_arguments").unwrap();
        let p = hdds_participant_create_with_transport(
            name.as_ptr(),
            HddsTransportMode::HddsTransportIntraProcess,
        );
        let topic = CString::new("keys_arguments").unwrap();
        let w = hdds_writer_create_keyed(p, topic.as_ptr(), ptr::null(), ptr::null(), 0);
        assert!(!w.is_null());
        let bytes = [0u8; 4];
        let mut identity = key(0, &bytes);
        assert_eq!(
            hdds_writer_write_keyed(w, bytes.as_ptr().cast(), 4, ptr::null()),
            HddsError::HddsInvalidArgument
        );
        assert_eq!(
            hdds_writer_write_keyed(w, ptr::null(), 4, &identity),
            HddsError::HddsInvalidArgument
        );
        identity.payload = ptr::null();
        assert_eq!(
            hdds_writer_write_keyed(w, bytes.as_ptr().cast(), 4, &identity),
            HddsError::HddsInvalidArgument
        );
        identity.payload = bytes.as_ptr();
        for representation in [0, 1, 3, u16::MAX] {
            identity.representation = representation;
            assert_eq!(
                hdds_writer_write_keyed(w, bytes.as_ptr().cast(), 4, &identity),
                HddsError::HddsInvalidArgument
            );
        }
        identity.representation = 2;
        assert_eq!(
            hdds_writer_write(w, bytes.as_ptr().cast(), 4),
            HddsError::HddsOperationFailed
        );
        assert_eq!(
            hdds_writer_dispose(w, bytes.as_ptr().cast(), 4),
            HddsError::HddsOperationFailed
        );
        let mut handle = HddsInstanceHandle::default();
        assert_eq!(
            hdds_writer_register_instance(w, bytes.as_ptr().cast(), 4, &mut handle),
            HddsError::HddsOperationFailed
        );
        assert_eq!(
            hdds_writer_write_keyed(w, bytes.as_ptr().cast(), 4, &identity),
            HddsError::HddsOk,
            "the all-zero key remains a keyed instance"
        );
        hdds_writer_destroy(w);
        let raw = hdds_writer_create(p, topic.as_ptr());
        assert!(!raw.is_null());
        assert_eq!(
            hdds_writer_write(raw, bytes.as_ptr().cast(), 4),
            HddsError::HddsOk
        );
        assert_eq!(
            hdds_writer_register_instance(raw, bytes.as_ptr().cast(), 4, &mut handle),
            HddsError::HddsOk
        );
        assert_eq!(handle.value, [0; 16]);
        assert_eq!(
            hdds_writer_write_keyed(raw, bytes.as_ptr().cast(), 4, &identity),
            HddsError::HddsInvalidArgument
        );
        hdds_writer_destroy(raw);
        hdds_participant_destroy(p);
    }
}

#[cfg(feature = "security")]
#[test]
fn encrypted_abi_uses_the_protected_digest_for_data_and_lifecycle() {
    use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair, KeyUsagePurpose};
    let lease = domain();
    let dir = std::env::temp_dir().join(format!(
        "hdds-keyed-wire-{}-{}",
        std::process::id(),
        lease.id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let ca = ca_params.self_signed(&ca_key).unwrap();
    let id_key = KeyPair::generate().unwrap();
    let params = CertificateParams::new(Vec::<String>::new()).unwrap();
    let id = params.signed_by(&id_key, &ca, &ca_key).unwrap();
    std::fs::write(dir.join("ca.pem"), ca.pem()).unwrap();
    std::fs::write(dir.join("id.pem"), id.pem()).unwrap();
    std::fs::write(dir.join("key.pem"), id_key.serialize_pem()).unwrap();
    let security = hdds::SecurityConfig::builder()
        .identity_certificate(dir.join("id.pem"))
        .private_key(dir.join("key.pem"))
        .ca_certificates(dir.join("ca.pem"))
        .enable_encryption(true)
        .build()
        .unwrap();
    let participant = Participant::builder("keyed_encrypt_wire")
        .domain_id(lease.id())
        .with_security(security)
        .build()
        .unwrap();
    unsafe {
        let p = Box::into_raw(Box::new(participant)).cast::<HddsParticipant>();
        let topic = CString::new("keys_encrypt_wire").unwrap();
        let w = hdds_writer_create_keyed(p, topic.as_ptr(), ptr::null(), ptr::null(), 0);
        assert!(!w.is_null());
        let socket = capture_data(&mut *w.cast::<DataWriter<BytePayload>>());
        let bytes = 2u32.to_le_bytes();
        let mut identity = key(2, &bytes);
        // MD5 of 00000002, CDR big endian, even though the key fits in 16.
        identity.protected_hash = [
            0xf1, 0x11, 0x77, 0xd2, 0xec, 0x63, 0xd9, 0x95, 0xfb, 0x4a, 0xc6, 0x28, 0xe0, 0xd7,
            0x82, 0xdf,
        ];
        assert_eq!(
            hdds_writer_write_keyed(w, bytes.as_ptr().cast(), 4, &identity),
            HddsError::HddsOk
        );
        assert_eq!(
            hdds_writer_dispose_keyed(w, ptr::null(), 0, &identity),
            HddsError::HddsOk
        );
        assert_eq!(
            hdds_writer_unregister_instance_keyed(w, ptr::null(), 0, &identity),
            HddsError::HddsOk
        );
        let seen = changes(drain(&socket));
        assert_eq!(seen.len(), 3);
        for change in seen {
            assert_eq!(change.hash, Some(identity.protected_hash));
            assert_ne!(change.hash, Some(identity.hash));
            assert_eq!(
                &change.payload[..4],
                &[0, 0, 0, 4],
                "AES256_GCM CryptoHeader, including key-only lifecycle DATA"
            );
            assert!(change.payload.len() > 8);
        }
        hdds_writer_destroy(w);
        hdds_participant_destroy(p);
    }
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn keyed_lifecycle_keeps_the_selected_encoding_and_owned_key_after_write() {
    let lease = domain();
    unsafe {
        let p = participant(lease.id());
        for representation in [0i16, 2] {
            let topic = CString::new(format!("keys_encoding_{representation}")).unwrap();
            let qos = qos::hdds_qos_reliable();
            assert_eq!(
                qos::hdds_qos_set_data_representation(qos, &representation, 1),
                HddsError::HddsOk
            );
            let w = hdds_writer_create_keyed(p, topic.as_ptr(), ptr::null(), qos, 0);
            assert!(!w.is_null());
            let socket = capture_data(&mut *w.cast::<DataWriter<BytePayload>>());
            let expected;
            {
                // @key octet t = 1; @key long long v = 2. XCDR1 aligns v
                // at 8; XCDR2 at 4. The ABI copies the key before returning.
                let mut bytes = vec![1u8];
                bytes.resize(if representation == 0 { 8 } else { 4 }, 0);
                bytes.extend_from_slice(&2i64.to_le_bytes());
                expected = bytes.clone();
                let mut identity = key(1, &bytes);
                identity.representation = representation as u16;
                identity.hash = [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0];
                identity.protected_hash = [
                    0x85, 0x73, 0x0d, 0x43, 0xc2, 0x8a, 0xe5, 0x9c, 0xf2, 0xf1, 0x2d, 0xdf, 0x0e,
                    0xd4, 0xa9, 0x12,
                ];
                assert_eq!(
                    hdds_writer_write_keyed(w, bytes.as_ptr().cast(), bytes.len(), &identity),
                    HddsError::HddsOk
                );
            }
            hdds_writer_destroy(w);
            let seen = changes(drain(&socket));
            assert_eq!(seen.len(), 2, "one DATA and the implicit unregister");
            for change in &seen {
                assert_eq!(
                    &change.payload[..4],
                    &[0, if representation == 0 { 1 } else { 7 }, 0, 0]
                );
                assert_eq!(&change.payload[4..4 + expected.len()], &expected);
            }
            assert_eq!(seen[1].flags & 0x0c, 8);
            assert_eq!(seen[1].status, Some([0, 0, 0, 3]));
            assert_eq!(seen[1].hash, seen[0].hash);
            qos::hdds_qos_destroy(qos);
        }
        hdds_participant_destroy(p);
    }
}

#[test]
fn serialized_publisher_preserves_partition_and_group() {
    let lease = domain();
    unsafe {
        let p = participant(lease.id());
        let qos = QoS::reliable().partition_single("serialized_partition");
        let publisher = hdds_publisher_create_with_qos(p, (&qos as *const QoS).cast());
        assert!(!publisher.is_null());
        let topic = CString::new("publisher_keys").unwrap();
        let writer = hdds_publisher_create_writer_keyed(
            publisher,
            topic.as_ptr(),
            topic.as_ptr(),
            ptr::null(),
            0,
        );
        assert!(!writer.is_null());
        let typed = &*writer.cast::<DataWriter<BytePayload>>();
        assert_eq!(typed.qos().partition, qos.partition);
        let parent = &*publisher.cast::<hdds::dds::Publisher>();
        let participant = &*p.cast::<Arc<Participant>>();
        let endpoints = participant
            .discovery()
            .unwrap()
            .find_writers_for_topic("publisher_keys");
        assert_eq!(endpoints.len(), 1);
        assert_eq!(endpoints[0].type_name, "publisher_keys");
        assert_eq!(endpoints[0].group_entity_id, Some(parent.entity_id()));
        hdds_writer_destroy(writer);
        hdds_publisher_destroy(publisher);
        hdds_participant_destroy(p);
    }
}

#[test]
fn native_protected_key_uses_cdr_big_endian_and_natural_alignment() {
    #[derive(hdds::DDS)]
    #[dds(final)]
    struct Scalar {
        #[key]
        tag: u8,
        #[key]
        id: i64,
        value: i32,
    }
    #[derive(hdds::DDS)]
    #[dds(final)]
    struct Text {
        #[key]
        label: String,
        #[key]
        id: i64,
        value: i32,
    }
    let scalar = Scalar {
        tag: 1,
        id: 2,
        value: 0,
    };
    assert_eq!(
        scalar.protected_key(),
        Some([
            0x85, 0x73, 0x0d, 0x43, 0xc2, 0x8a, 0xe5, 0x9c, 0xf2, 0xf1, 0x2d, 0xdf, 0x0e, 0xd4,
            0xa9, 0x12,
        ])
    );
    let text = Text {
        label: "BLUE".into(),
        id: 2,
        value: 0,
    };
    assert_eq!(
        text.protected_key(),
        Some([
            0xa4, 0x9a, 0x08, 0x7b, 0xc2, 0xbb, 0x7c, 0xd4, 0xbc, 0xd8, 0xb8, 0xbf, 0xdf, 0x5e,
            0x87, 0x61,
        ])
    );
}

#[test]
fn legacy_publisher_constructors_preserve_partition_and_group() {
    let lease = domain();
    unsafe {
        let p = participant(lease.id());
        let qos = QoS::reliable().partition_single("legacy_partition");
        let publisher = hdds_publisher_create_with_qos(p, (&qos as *const QoS).cast());
        assert!(!publisher.is_null());
        let parent = &*publisher.cast::<hdds::dds::Publisher>();
        for constructor in 0..3 {
            let topic = CString::new(format!("legacy_publisher_{constructor}")).unwrap();
            let writer = match constructor {
                0 => hdds_publisher_create_writer(publisher, topic.as_ptr()),
                1 => hdds_publisher_create_writer_with_qos(publisher, topic.as_ptr(), ptr::null()),
                _ => hdds_publisher_create_writer_with_extensibility(
                    publisher,
                    topic.as_ptr(),
                    ptr::null(),
                    2,
                ),
            };
            assert!(!writer.is_null());
            let typed = &*writer.cast::<DataWriter<BytePayload>>();
            assert_eq!(typed.qos().partition, qos.partition);
            let participant = &*p.cast::<Arc<Participant>>();
            let endpoints = participant
                .discovery()
                .unwrap()
                .find_writers_for_topic(topic.to_str().unwrap());
            assert_eq!(endpoints.len(), 1);
            assert_eq!(endpoints[0].group_entity_id, Some(parent.entity_id()));
            assert_eq!(endpoints[0].type_name, "RawBytes");
            hdds_writer_destroy(writer);
        }
        hdds_publisher_destroy(publisher);
        hdds_participant_destroy(p);
    }
}
