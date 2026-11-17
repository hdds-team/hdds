// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! DDS Security v1.1 Sec.7.4.1.6 and DDSI-RTPS v2.5 Sec.9.6.4.9.
//! Wire fixtures use literal entity ids and parameter ids.

use super::discovery::sealed_departure_datagram;
use super::DiscoveryFsm;
use crate::core::discovery::GUID;
use crate::security::access::ProtectionKind;
use crate::security::crypto::data_keys::WriterKey;
use crate::security::crypto::secure_submessage::{
    decode_datawriter_submessage, encode_datawriter_submessage, Transformation, WriterKeyMaterial,
};

const PREFIX: [u8; 12] = [0x42; 12];
const PARTICIPANT: [u8; 4] = [0, 0, 1, 0xc1];

fn material(transformation: Transformation) -> WriterKeyMaterial {
    let (id, key) = WriterKey::mint().expect("mint");
    key.with_transformation(transformation)
        .submessage_material(id)
}

/// A DATA(p[UD]) or DATA(p[UD],K) with a positive writerSN. StatusInfo
/// is an octet array in both endiannesses; the key-only payload is PL_CDR.
fn fixture(le: bool, status: u8, serialized_key: bool) -> Vec<u8> {
    let u16_bytes = |n: u16| if le { n.to_le_bytes() } else { n.to_be_bytes() };
    let mut body = Vec::new();
    body.extend_from_slice(&u16_bytes(0));
    body.extend_from_slice(&u16_bytes(16));
    body.extend_from_slice(&[0xff, 1, 1, 0xc7]);
    body.extend_from_slice(&[0xff, 1, 1, 0xc2]);
    body.extend_from_slice(&[0; 4]);
    body.extend_from_slice(&if le {
        1u32.to_le_bytes()
    } else {
        1u32.to_be_bytes()
    });
    body.extend_from_slice(&u16_bytes(0x71));
    body.extend_from_slice(&u16_bytes(4));
    body.extend_from_slice(&[0, 0, 0, status]);
    if serialized_key {
        body.extend_from_slice(&u16_bytes(1));
        body.extend_from_slice(&[0, 0]);
        body.extend_from_slice(&[0, if le { 3 } else { 2 }, 0, 0]);
        body.extend_from_slice(&u16_bytes(0x50));
    } else {
        body.extend_from_slice(&u16_bytes(0x70));
    }
    body.extend_from_slice(&u16_bytes(16));
    body.extend_from_slice(&PREFIX);
    body.extend_from_slice(&PARTICIPANT);
    body.extend_from_slice(&u16_bytes(1));
    body.extend_from_slice(&[0, 0]);
    let mut out = b"RTPS\x02\x05\x01\x12".to_vec();
    out.extend_from_slice(&PREFIX);
    out.extend_from_slice(&[0x15, u8::from(le) | 2 | if serialized_key { 8 } else { 0 }]);
    out.extend_from_slice(&u16_bytes(
        u16::try_from(body.len()).expect("small fixture"),
    ));
    out.extend_from_slice(&body);
    out
}

#[test]
fn participant_departure_wire_matches_status_and_key_under_each_policy() {
    let guid = GUID::new(PREFIX, PARTICIPANT);
    for (kind, transformation) in [
        (ProtectionKind::None, Transformation::Aes256Gcm),
        (ProtectionKind::Sign, Transformation::Aes256Gmac),
        (ProtectionKind::Encrypt, Transformation::Aes256Gcm),
    ] {
        let key = material(transformation);
        let packet = sealed_departure_datagram(&key, guid, kind).expect("departure");
        let data = if kind.is_protected() {
            let decoded = decode_datawriter_submessage(&key, &packet, 20).expect("decode envelope");
            assert_eq!(decoded.transformation, transformation);
            decoded.submessage
        } else {
            packet[20..].to_vec()
        };
        // Independently written expected wire pins E|Q, D=K=0, the secure
        // participant ids, SN=1, status octets, key hash, sentinel and length.
        assert_eq!(data, fixture(true, 3, false)[20..]);
    }
}

#[test]
fn participant_departure_reads_independent_status_and_key_wire() {
    let key = material(Transformation::Aes256Gcm);
    for le in [false, true] {
        for status in [1, 2, 3] {
            for serialized_key in [false, true] {
                let wire = fixture(le, status, serialized_key);
                let mut packet = wire[..20].to_vec();
                packet.extend_from_slice(
                    &encode_datawriter_submessage(&key, &wire[20..]).expect("seal"),
                );
                assert_eq!(
                    DiscoveryFsm::open_sealed_departure(&packet, 20, &key, ProtectionKind::Encrypt),
                    Some(GUID::new(PREFIX, PARTICIPANT)),
                    "le={le} status={status} serialized_key={serialized_key}",
                );
            }
        }
    }
}

#[test]
fn participant_departure_rejects_wrong_status_key_writer_and_protection() {
    let key = material(Transformation::Aes256Gcm);
    let open = |wire: &[u8]| {
        let mut packet = wire[..20].to_vec();
        packet.extend_from_slice(&encode_datawriter_submessage(&key, &wire[20..]).expect("seal"));
        DiscoveryFsm::open_sealed_departure(&packet, 20, &key, ProtectionKind::Encrypt)
    };
    assert_eq!(open(&fixture(true, 0, false)), None, "no status change");
    for (at, value) in [
        (21, 7),
        (32, 0),
        (56, 0x43),
        (71, 0xc2),
        (40, 0),
        (39, 0x80),
    ] {
        let mut wire = fixture(true, 3, false);
        wire[at] = value;
        assert_eq!(open(&wire), None, "invalid field at {at}");
    }
    let sign_key = material(Transformation::Aes256Gmac);
    let packet = sealed_departure_datagram(
        &sign_key,
        GUID::new(PREFIX, PARTICIPANT),
        ProtectionKind::Sign,
    )
    .expect("signed");
    assert_eq!(
        DiscoveryFsm::open_sealed_departure(&packet, 20, &sign_key, ProtectionKind::Encrypt),
        None
    );
    assert_eq!(
        DiscoveryFsm::open_sealed_departure(&packet, 20, &sign_key, ProtectionKind::Sign),
        Some(GUID::new(PREFIX, PARTICIPANT))
    );
    assert!(sealed_departure_datagram(
        &sign_key,
        GUID::new(PREFIX, PARTICIPANT),
        ProtectionKind::Encrypt
    )
    .is_none());
}

#[test]
fn participant_writer_key_uses_discovery_protection_kind() {
    use crate::security::access::{DiscoveryGovernance, DomainRule};
    for kind in [ProtectionKind::Sign, ProtectionKind::Encrypt] {
        let mut fsm = DiscoveryFsm::new(GUID::new(PREFIX, PARTICIPANT), 30_000);
        fsm.set_discovery_governance(Some(DiscoveryGovernance::new(DomainRule {
            domains: vec![0],
            domain_ranges: vec![],
            allow_unauthenticated: false,
            enable_join_access_control: true,
            discovery_protection_kind: kind,
            liveliness_protection_kind: ProtectionKind::None,
            rtps_protection_kind: ProtectionKind::None,
            topic_rules: vec![],
        })));
        fsm.register_builtin_writer_keys_for_tests();
        let (_, key) = fsm.local_builtin_writer_key_for_tests([0xff, 1, 1, 0xc2]);
        assert_eq!(
            key.transformation,
            if kind.is_encrypted() {
                Transformation::Aes256Gcm
            } else {
                Transformation::Aes256Gmac
            }
        );
    }
}
