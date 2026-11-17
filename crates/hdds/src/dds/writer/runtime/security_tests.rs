// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Writer-side DDS-Security tests: the fail-closed legs and the sealed wire
//! path. Lives in its own file (declared from `runtime.rs`, so `super::*`
//! still reaches the writer runtime's private items) rather than inline, so
//! the extreme audit's panic!() scan - which excludes `*test*` files but not
//! inline `#[cfg(test)]` modules - does not misclassify test assertions as
//! production panics.

use super::*;

/// Encryption was never requested: nothing is refused. This is the branch
/// that keeps every non-secure deployment -- which is every deployment the
/// interop suite exercises -- on its existing path.
#[test]
fn without_a_crypto_plugin_no_leg_refuses() {
    assert!(refuse_cleartext_leg(false, "SomeTopic", "intra-process").is_ok());
    assert!(refuse_cleartext_leg(false, "SomeTopic", "history-cache").is_ok());
}

/// THE contract of the non-encrypting legs: encryption requested and no
/// cipher on the leg means the emission is REFUSED, never cleartext.
#[test]
fn encryption_requested_refuses_every_cipherless_leg() {
    for leg in ["intra-process", "history-cache"] {
        match refuse_cleartext_leg(true, "SecretTopic", leg) {
            Err(Error::EncryptionUnavailable(msg)) => {
                assert!(
                    msg.contains("SecretTopic"),
                    "the error must name the topic so an operator can act on it, got: {}",
                    msg
                );
            }
            other => panic!(
                "fail-open regression on the {} leg: expected EncryptionUnavailable, got {:?}",
                leg, other
            ),
        }
    }
}

/// The anti-drift tripwire, restated for the new shape: every cipherless
/// leg refuses through ONE predicate, so the errors differ only by the leg
/// label and nothing else. If a leg grows its own refusal logic again,
/// this is the test to extend first.
#[test]
fn cipherless_legs_share_one_refusal_shape() {
    let intra = match refuse_cleartext_leg(true, "SharedTopic", "leg-a") {
        Err(e) => format!("{:?}", e),
        Ok(()) => panic!("leg-a failed open"),
    };
    let cache = match refuse_cleartext_leg(true, "SharedTopic", "leg-a") {
        Err(e) => format!("{:?}", e),
        Ok(()) => panic!("leg-a (second call) failed open"),
    };
    assert_eq!(intra, cache, "the refusal must be deterministic");
}

/// A tiny keyless type: `seal_payload_for_wire` never looks at `T`, so
/// the simplest possible writer is the right harness for its contract.
#[derive(Debug, Clone, Copy, PartialEq, crate::DDS)]
struct SealProbe {
    x: i32,
}

/// A transportless writer straight from the builder: `security` is `None`
/// (no participant to inherit a suite from), which the tests below
/// override to steer the seal into each of its branches.
fn probe_writer() -> DataWriter<SealProbe> {
    let _ = crate::core::rt::init_slab_pool();
    crate::dds::writer::WriterBuilder::<SealProbe>::new("SealProbeTopic".to_string())
        .qos(QoS::best_effort())
        .build()
        .expect("a transportless writer must build")
}

/// A real suite with `enable_encryption(true)`, built from the shared
/// test PKI. Reading the PEMs happens inside `SecurityPluginSuite::new`,
/// so the temp files only need to live through this function.
fn encrypting_suite() -> Arc<crate::security::SecurityPluginSuite> {
    use crate::security::test_pki::{
        TEST_CA_CERT_PEM, TEST_IDENTITY_CERT_PEM, TEST_IDENTITY_KEY_PEM,
    };
    use std::io::Write as _;

    let write_pem = |contents: &[u8]| {
        let mut f = tempfile::NamedTempFile::new().expect("temp PEM file");
        f.write_all(contents).expect("write PEM");
        f.flush().expect("flush PEM");
        f
    };
    let cert = write_pem(TEST_IDENTITY_CERT_PEM);
    let key = write_pem(TEST_IDENTITY_KEY_PEM);
    let ca = write_pem(TEST_CA_CERT_PEM);

    let config = crate::security::SecurityConfig::builder()
        .identity_certificate(cert.path())
        .private_key(key.path())
        .ca_certificates(ca.path())
        .enable_encryption(true)
        .build()
        .expect("SecurityConfig from the shared test PKI must build");
    Arc::new(crate::security::SecurityPluginSuite::new(config, 0).expect("suite"))
}

/// Governance is authoritative even when the optional crypto plugin is absent.
#[cfg(feature = "qos-loaders")]
#[test]
fn governance_payload_protection_without_crypto_refuses_cleartext() {
    use crate::security::access::AccessControlPlugin;
    for protection in ["NONE", "ENCRYPT"] {
        let mut writer = probe_writer();
        let mut suite = encrypting_suite();
        let suite_mut = Arc::get_mut(&mut suite).unwrap();
        suite_mut.cryptographic = None;
        let governance = format!(
            "<dds><domain_access_rules><domain_rule><domains><id>0</id></domains>\
             <allow_unauthenticated_participants>false</allow_unauthenticated_participants>\
             <enable_join_access_control>true</enable_join_access_control>\
             <discovery_protection_kind>NONE</discovery_protection_kind>\
             <liveliness_protection_kind>NONE</liveliness_protection_kind>\
             <rtps_protection_kind>NONE</rtps_protection_kind>\
             <topic_access_rules><topic_rule><topic_expression>*</topic_expression>\
             <enable_discovery_protection>false</enable_discovery_protection>\
             <enable_liveliness_protection>false</enable_liveliness_protection>\
             <enable_read_access_control>false</enable_read_access_control>\
             <enable_write_access_control>false</enable_write_access_control>\
             <metadata_protection_kind>NONE</metadata_protection_kind>\
             <data_protection_kind>{protection}</data_protection_kind>\
             </topic_rule></topic_access_rules></domain_rule></domain_access_rules></dds>"
        );
        suite_mut.access_control = Some(
            AccessControlPlugin::from_xml(&governance, "<dds><permissions/></dds>", 0).unwrap(),
        );
        writer.security = Some(suite);
        let wire = writer.seal_payload_for_wire(&[1, 2, 3, 4], CdrVersion::Xcdr2);
        if protection == "NONE" {
            assert_eq!(wire.unwrap(), (vec![1, 2, 3, 4], false));
        } else {
            assert!(
                matches!(wire, Err(Error::EncryptionUnavailable(_))),
                "{protection}"
            );
        }
        for leg in ["intra-process", "history-cache"] {
            let local = writer.refuse_unkeyed_local_delivery(leg);
            if protection == "NONE" {
                assert!(local.is_ok());
            } else {
                assert!(
                    matches!(local, Err(Error::EncryptionUnavailable(_))),
                    "{protection} {leg}"
                );
            }
        }
    }
}

/// Lifecycle DATA goes through the sealer now, and the sealer is a
/// passthrough when encryption was never requested: the K-payload bytes
/// reach the packet builder untouched. This is the default build's
/// behaviour and the interop-tested one.
#[test]
fn a_lifecycle_payload_is_untouched_when_encryption_was_never_requested() {
    let writer = probe_writer();
    let key_bytes = [0x05u8, 0x00, 0x00, 0x00, b'B', b'L', b'U', 0x00];

    let (out, sealed) = writer
        .seal_payload_for_wire(&key_bytes, CdrVersion::Xcdr2)
        .expect("a participant that never asked for encryption must still dispose and unregister");
    assert!(!sealed, "no crypto requested, so nothing may be sealed");
    assert_eq!(
        out, key_bytes,
        "the passthrough must not rewrite the key bytes"
    );
}

/// The fail-closed tripwire, restated for the sealing shape: dispose and
/// unregister now seal on the same terms as `write()`, so a writer with
/// encryption requested and no data-plane key must REFUSE the lifecycle
/// emission -- from the seal itself, never by falling back to cleartext.
/// Covered in both key-less shapes: no RTPS endpoint at all, and an
/// endpoint whose key store holds nothing.
#[test]
fn a_lifecycle_payload_is_refused_when_encryption_has_no_key() {
    let mut writer = probe_writer();
    writer.security = Some(encrypting_suite());

    let expect_refusal = |result: Result<(Vec<u8>, bool)>, shape: &str| match result {
        Err(Error::EncryptionUnavailable(msg)) => {
            assert!(
                msg.contains("SealProbeTopic"),
                "the refusal must name the topic so an operator can act on it \
                 ({} shape), got: {}",
                shape,
                msg
            );
        }
        other => panic!(
            "fail-open regression ({} shape): a lifecycle DATA would have emitted \
             the instance key fields in cleartext, got {:?}",
            shape, other
        ),
    };

    // No RTPS endpoint: minting happens at writer build and requires one,
    // so there is no key to look up.
    expect_refusal(
        writer.seal_payload_for_wire(&[1, 2, 3, 4], CdrVersion::Xcdr2),
        "no-endpoint",
    );

    // Endpoint present but the store is empty: same refusal, from the
    // key lookup rather than the endpoint gate.
    writer.rtps_endpoint = Some(crate::protocol::builder::RtpsEndpointContext {
        guid_prefix: [0x11; 12],
        reader_entity_id: [0x00, 0x00, 0x01, 0x02],
        writer_entity_id: [0x00, 0x00, 0x01, 0x03],
        encapsulation_kind: 0x0007,
        publisher_entity_id: [0x00, 0x00, 0x01, 0x08],
    });
    expect_refusal(
        writer.seal_payload_for_wire(&[1, 2, 3, 4], CdrVersion::Xcdr2),
        "empty-store",
    );
}

fn context() -> builder::RtpsEndpointContext {
    builder::RtpsEndpointContext {
        guid_prefix: [0x31; 12],
        reader_entity_id: [0; 4],
        writer_entity_id: [0, 0, 1, 3],
        encapsulation_kind: 0x0007,
        publisher_entity_id: [0, 0, 1, 8],
    }
}

/// The writer uses the same announced salt as its matched receivers, and
/// replacement tokens define a new generation even when the id is reused.
#[test]
fn payload_session_keys_follow_the_announced_material_and_rekey() {
    use crate::security::crypto::data_keys::WriterKey;
    use crate::security::crypto::peer_keys::SecretKey;
    use crate::security::crypto::user_data::{
        decode_serialized_payload, secured_payload_key_id, serialized_body,
    };
    let mut writer = probe_writer();
    let suite = encrypting_suite();
    writer.security = Some(suite.clone());
    writer.rtps_endpoint = Some(context());
    let guid = GUID::new(context().guid_prefix, context().writer_entity_id);
    suite
        .data_keys
        .insert(
            guid,
            7,
            WriterKey::for_tests(SecretKey::from_bytes([0x11; 32])),
        )
        .unwrap();
    let (old, sealed) = writer
        .seal_payload_for_wire(&[1, 2, 3, 4, 5], CdrVersion::Xcdr1)
        .unwrap();
    assert!(sealed);
    assert_eq!(secured_payload_key_id(&old).unwrap(), 7);
    let old_material = suite.data_keys.get_material(&guid, 7).unwrap();
    let plain = decode_serialized_payload(7, &old_material, &old).unwrap();
    assert_eq!(&plain[..4], &[0, 1, 0, 3]);
    assert_eq!(
        serialized_body(&plain).unwrap(),
        (vec![1, 2, 3, 4, 5], CdrVersion::Xcdr1)
    );
    suite
        .data_keys
        .insert(
            guid,
            8,
            WriterKey::new(
                SecretKey::from_bytes([0x11; 32]),
                SecretKey::from_bytes([0x33; 32]),
            ),
        )
        .unwrap();
    assert!(suite.data_keys.get_material(&guid, 7).is_none());
    let current = suite.data_keys.get_material(&guid, 8).unwrap();
    assert!(decode_serialized_payload(8, &current, &old).is_err());
    let (new, _) = writer
        .seal_payload_for_wire(&[1, 2, 3, 4, 5], CdrVersion::Xcdr2)
        .unwrap();
    assert_eq!(secured_payload_key_id(&new).unwrap(), 8);
    assert!(decode_serialized_payload(8, &old_material, &new).is_err());
    assert_eq!(
        serialized_body(&decode_serialized_payload(8, &current, &new).unwrap())
            .unwrap()
            .1,
        CdrVersion::Xcdr2
    );
    suite
        .data_keys
        .insert(
            guid,
            8,
            WriterKey::new(
                SecretKey::from_bytes([0x44; 32]),
                SecretKey::from_bytes([0x33; 32]),
            ),
        )
        .unwrap();
    let replaced = suite.data_keys.get_material(&guid, 8).unwrap();
    assert!(
        decode_serialized_payload(8, &replaced, &new).is_err(),
        "same id, replacement master key"
    );
}

#[derive(Debug, Clone, Copy, PartialEq, crate::DDS)]
struct ProtectedKey {
    #[key]
    tag: u8,
    #[key]
    value: u64,
    payload: i32,
}

/// [`encrypting_suite`] plus a permissions overlay: the one document whose
/// generation moves while the participant runs, so it is what a cache keyed
/// on that generation must notice.
fn overlay_suite(overlay: &std::path::Path) -> Arc<crate::security::SecurityPluginSuite> {
    use crate::security::test_pki::{
        TEST_CA_CERT_PEM, TEST_IDENTITY_CERT_PEM, TEST_IDENTITY_KEY_PEM,
    };
    use std::io::Write as _;

    let write_pem = |contents: &[u8]| {
        let mut f = tempfile::NamedTempFile::new().expect("temp PEM file");
        f.write_all(contents).expect("write PEM");
        f.flush().expect("flush PEM");
        f
    };
    let cert = write_pem(TEST_IDENTITY_CERT_PEM);
    let key = write_pem(TEST_IDENTITY_KEY_PEM);
    let ca = write_pem(TEST_CA_CERT_PEM);

    let config = crate::security::SecurityConfig::builder()
        .identity_certificate(cert.path())
        .private_key(key.path())
        .ca_certificates(ca.path())
        .enable_encryption(true)
        .permissions_overlay(overlay)
        .build()
        .expect("SecurityConfig with an overlay must build");
    Arc::new(crate::security::SecurityPluginSuite::new(config, 0).expect("suite"))
}

/// The write path reads the topic's protection ONCE, not once per sample:
/// the answer is filed under the document generation. A reload replaces the
/// only document that can change under a running participant, and the next
/// sample must read the documents again rather than seal under a rule that
/// was replaced.
#[test]
fn the_topic_protection_is_read_once_and_again_after_a_document_reload() {
    use std::io::Write as _;

    let mut overlay = tempfile::NamedTempFile::new().expect("overlay file");
    overlay
        .write_all(b"[subject: CN=DDS Test Identity, O=HDDS Test]\ndefault: allow\n")
        .expect("write overlay");
    overlay.flush().expect("flush overlay");
    let suite = overlay_suite(overlay.path());

    let mut writer =
        crate::dds::writer::WriterBuilder::<ProtectedKey>::new("protection-cache".into())
            .qos(QoS::best_effort())
            .build()
            .expect("a transportless writer must build");
    writer.security = Some(Arc::clone(&suite));

    let msg = ProtectedKey {
        tag: 1,
        value: 2,
        payload: 3,
    };
    writer
        .protected_key_hash(&msg)
        .expect("key protection is announced")
        .expect("a keyed type announces a KeyHash");
    assert_eq!(
        writer.protection.resolutions(),
        1,
        "the first sample resolves the topic's protection"
    );
    writer.protected_key_hash(&msg).expect("second sample");
    assert_eq!(
        writer.protection.resolutions(),
        1,
        "the second sample must be served from the cache, not from the governance"
    );

    let before = suite.local_restriction_generation();
    // A reload that finds the same document changes nothing, so a reload
    // that MOVES the generation is one that found a new one.
    std::fs::write(
        overlay.path(),
        b"[subject: CN=DDS Test Identity, O=HDDS Test]\ndefault: allow\n\
          deny publish: nothing/*\n",
    )
    .expect("rewrite the overlay");
    suite
        .reload_permissions_overlay()
        .expect("the overlay reloads")
        .expect("an overlay is configured");
    assert_ne!(
        suite.local_restriction_generation(),
        before,
        "a reload moves the generation the cache is filed under"
    );
    writer.protected_key_hash(&msg).expect("third sample");
    assert_eq!(
        writer.protection.resolutions(),
        2,
        "the sample after a reload must read the documents again"
    );
}

/// DDS-Security v1.1 Sec.7.3.4 computes the KeyHash "for the Instance Key":
/// a type with no @key has none, and the digest of an empty KeyHolder is not
/// a key. The writer leaves the inline QoS KeyHash out rather than announce
/// one.
#[test]
fn a_keyless_type_announces_no_key_hash_under_key_protection() {
    let mut writer = probe_writer();
    let suite = encrypting_suite();
    // Key protection is announced from the explicit crypto configuration
    // (no governance document, so no topic rule to derive it from): the
    // KeyHash leg below is live, and only `has_key` switches it off.
    assert!(
        crate::security::crypto::user_data::endpoint_security_info(&suite, "SealProbeTopic")
            .expect("attributes")
            .is_key_protected(),
        "the harness must announce key protection"
    );
    writer.security = Some(suite);
    assert!(!SealProbe::has_key());
    assert_eq!(
        writer
            .protected_key_hash(&SealProbe { x: 7 })
            .expect("a keyless type has nothing to refuse"),
        None,
        "a keyless type must not announce a KeyHash"
    );
}

/// A keyed type that predates the KeyHolder hook: `has_key` says there is an
/// instance key, `write_key_holder` (the default) cannot serialize it. The
/// security KeyHash is defined over that serialization, so the write is
/// refused, never sent with an invented KeyHash or in clear.
#[derive(Debug, Clone, Copy, PartialEq)]
struct KeyedWithoutHolder {
    tag: u8,
}

impl crate::dds::DDS for KeyedWithoutHolder {
    fn type_descriptor() -> &'static crate::core::types::TypeDescriptor {
        static DESC: crate::core::types::TypeDescriptor = crate::core::types::TypeDescriptor {
            type_id: 0x4B57_4830,
            type_name: "KeyedWithoutHolder",
            size_bytes: 1,
            alignment: 1,
            is_variable_size: false,
            fields: &[],
        };
        &DESC
    }

    fn encode(&self, buf: &mut [u8], _version: CdrVersion) -> crate::dds::Result<usize> {
        let dst = buf.get_mut(..1).ok_or(crate::dds::Error::BufferTooSmall)?;
        dst[0] = self.tag;
        Ok(1)
    }

    fn decode(buf: &[u8], _version: CdrVersion) -> crate::dds::Result<Self> {
        buf.first()
            .map(|tag| Self { tag: *tag })
            .ok_or(crate::dds::Error::SerializationError)
    }

    fn has_key() -> bool {
        true
    }
}

#[test]
fn a_keyed_type_without_a_key_holder_refuses_the_protected_write() {
    let mut writer =
        crate::dds::writer::WriterBuilder::<KeyedWithoutHolder>::new("no-holder".into())
            .qos(QoS::best_effort())
            .build()
            .unwrap();
    writer.security = Some(encrypting_suite());
    match writer.protected_key_hash(&KeyedWithoutHolder { tag: 1 }) {
        Err(Error::EncryptionUnavailable(msg)) => assert!(
            msg.contains("no-holder"),
            "the refusal must name the topic so an operator can act on it, got: {msg}"
        ),
        other => panic!(
            "a keyed type with no KeyHolder must not emit a KeyHash it cannot \
             compute (Sec.7.3.4), got {other:?}"
        ),
    }
}

#[test]
fn encrypted_short_keys_use_md5_of_cdr_big_endian_fields() {
    let mut writer = crate::dds::writer::WriterBuilder::<ProtectedKey>::new("protected-key".into())
        .qos(QoS::best_effort())
        .build()
        .unwrap();
    writer.security = Some(encrypting_suite());
    let msg = ProtectedKey {
        tag: 1,
        value: 2,
        payload: 3,
    };
    // hashlib.md5(bytes.fromhex('01000000000000000000000000000002')).digest():
    // octet, seven CDR alignment zeros, uint64 BE. No short-key padded form.
    let expected = [
        0x85, 0x73, 0x0d, 0x43, 0xc2, 0x8a, 0xe5, 0x9c, 0xf2, 0xf1, 0x2d, 0xdf, 0x0e, 0xd4, 0xa9,
        0x12,
    ];
    assert_eq!(writer.protected_key_hash(&msg).unwrap(), Some(expected));
    assert_ne!(msg.compute_key(), expected);
}

/// Repair and TRANSIENT_LOCAL replay share these change builders. Both
/// ordinary and lifecycle changes retain the protected octets and set tags.
#[test]
fn protected_history_builders_preserve_crypto_elements_and_coherent_metadata() {
    use crate::dds::writer::nack::{
        change_frag_packets, lifecycle_change_packet, user_data_change_packet,
    };
    use crate::reliability::CachedChange;
    use crate::security::crypto::data_keys::WriterKey;
    use crate::security::crypto::peer_keys::SecretKey;
    use crate::security::crypto::user_data::{
        decode_serialized_payload, encode_serialized_payload,
    };
    let ctx = context();
    let material = WriterKey::for_tests(SecretKey::from_bytes([0x11; 32]));
    for len in [5, builder::DEFAULT_MAX_UNFRAGMENTED_SIZE + 1] {
        let plain = builder::encapsulate_serialized_payload(0x0001, &vec![0x51; len], false);
        let protected = encode_serialized_payload(7, &material, &plain).unwrap();
        let change = CachedChange {
            seq: 11,
            payload: protected.clone(),
            metadata: ChangeMetadata {
                coherent_sn: Some(9),
                key_hash: Some([0x55; 16]),
                cdr_version: CdrVersion::Xcdr1,
                key_epoch: 1,
                source_ts: (31, 41),
                source_ts_known: true,
                frag_size: builder::DEFAULT_FRAGMENT_SIZE as u16,
                ..ChangeMetadata::user_data()
            },
            group: None,
        };
        for replay in [false, true] {
            if len == 5 {
                let packet = user_data_change_packet(ctx, "history", &change, (31, 41), replay);
                let off = builder::helpers::find_data_submsg_offset(&packet).unwrap();
                let layout = builder::data_submessage_layout(&packet, off).unwrap();
                assert_eq!(&packet[layout.payload..layout.end], protected);
                let (iq, le) = builder::extract_inline_qos(&packet).unwrap();
                assert_eq!(builder::extract_coherent_set(iq, le), Some(9));
            } else {
                let packets = change_frag_packets(
                    &ctx,
                    "history",
                    change.seq,
                    &change.payload,
                    &change.metadata,
                    None,
                    builder::DEFAULT_FRAGMENT_SIZE,
                    (31, 41),
                    replay,
                );
                assert!(packets.len() > 1);
                let mut whole = Vec::new();
                for packet in &packets {
                    let (_, offset, _, _) =
                        crate::core::discovery::multicast::classifier::classify_rtps(packet);
                    whole.extend_from_slice(&packet[offset.unwrap()..]);
                }
                assert_eq!(whole, protected);
            }
        }
        if len == 5 {
            let mut lifecycle = change;
            lifecycle.metadata.status_info = Some(builder::StatusInfoKind::Disposed);
            let packet = lifecycle_change_packet(Some(ctx), "history", &lifecycle, false).unwrap();
            let off = builder::helpers::find_data_submsg_offset(&packet).unwrap();
            let layout = builder::data_submessage_layout(&packet, off).unwrap();
            assert!(builder::is_key_only_data(&packet));
            assert_eq!(
                decode_serialized_payload(7, &material, &packet[layout.payload..layout.end])
                    .unwrap(),
                plain
            );
        }
    }
}

/// A policy reload changes how lifecycle identifies an instance, even when
/// the protected digest of an earlier write remains cached (Sec.7.3.4).
#[cfg(feature = "qos-loaders")]
#[test]
fn lifecycle_hash_follows_the_current_policy_after_reload() {
    let value = ProtectedKey {
        tag: 1,
        value: 2,
        payload: 3,
    };
    check_lifecycle_policy(value);
    check_lifecycle_policy(PerSampleKey(value));
}

#[cfg(feature = "qos-loaders")]
fn check_lifecycle_policy<T: DDS>(value: T) {
    use crate::security::access::AccessControlPlugin;
    let governance = |protection| {
        format!(
            "<dds><domain_access_rules><domain_rule><domains><id>0</id></domains>\
         <allow_unauthenticated_participants>false</allow_unauthenticated_participants>\
         <enable_join_access_control>true</enable_join_access_control>\
         <discovery_protection_kind>NONE</discovery_protection_kind>\
         <liveliness_protection_kind>NONE</liveliness_protection_kind>\
         <rtps_protection_kind>NONE</rtps_protection_kind>\
         <topic_access_rules><topic_rule><topic_expression>*</topic_expression>\
         <enable_discovery_protection>false</enable_discovery_protection>\
         <enable_liveliness_protection>false</enable_liveliness_protection>\
         <enable_read_access_control>false</enable_read_access_control>\
         <enable_write_access_control>false</enable_write_access_control>\
         <metadata_protection_kind>NONE</metadata_protection_kind>\
         <data_protection_kind>{protection}</data_protection_kind>\
         </topic_rule></topic_access_rules></domain_rule></domain_access_rules></dds>"
        )
    };
    let _ = crate::core::rt::init_slab_pool();
    let overlay = tempfile::NamedTempFile::new().expect("overlay");
    std::fs::write(
        overlay.path(),
        b"[subject: CN=DDS Test Identity, O=HDDS Test]\ndefault: allow\n",
    )
    .unwrap();
    let mut writer = crate::dds::writer::WriterBuilder::<T>::new("lifecycle-policy".into())
        .qos(QoS::reliable().transient_local())
        .build()
        .unwrap();
    writer.security = Some(overlay_suite(overlay.path()));
    let normal = value.instance_key().unwrap();
    let protected = writer.protected_key_hash(&value).unwrap().unwrap();
    assert!(matches!(
        writer.lifecycle_wire_key_hash(&normal, true),
        Err(Error::EncryptionUnavailable(_))
    ));
    writer
        .protected_key_hashes
        .lock()
        .unwrap()
        .insert(normal, protected);
    assert_eq!(
        writer.lifecycle_wire_key_hash(&normal, true).unwrap(),
        protected
    );
    let suite = writer.security.as_mut().unwrap();
    let before = suite.local_restriction_generation();
    // Governance takes precedence over the still-installed crypto plugin.
    Arc::get_mut(suite).unwrap().access_control = Some(
        AccessControlPlugin::from_xml(&governance("NONE"), "<dds><permissions/></dds>", 0).unwrap(),
    );
    std::fs::write(
        overlay.path(),
        b"[subject: CN=DDS Test Identity, O=HDDS Test]\ndefault: allow\ndeny publish: nothing/*\n",
    )
    .unwrap();
    suite.reload_permissions_overlay().unwrap();
    assert_ne!(suite.local_restriction_generation(), before);
    assert_eq!(
        writer.lifecycle_wire_key_hash(&normal, true).unwrap(),
        normal
    );
    writer
        .emit_lifecycle_change(
            &normal,
            &value.encode_key(CdrVersion::Xcdr2),
            CdrVersion::Xcdr2,
            crate::protocol::builder::StatusInfoKind::Disposed,
            false,
            true,
        )
        .unwrap();
    let changes = writer.history_cache.as_ref().unwrap().snapshot_changes();
    assert_eq!(changes.len(), 1);
    assert_eq!(changes[0].metadata.key_hash, Some(normal));
    let suite = writer.security.as_mut().unwrap();
    Arc::get_mut(suite).unwrap().access_control = Some(
        AccessControlPlugin::from_xml(&governance("ENCRYPT"), "<dds><permissions/></dds>", 0)
            .unwrap(),
    );
    std::fs::write(
        overlay.path(),
        b"[subject: CN=DDS Test Identity, O=HDDS Test]\ndefault: allow\ndeny publish: other/*\n",
    )
    .unwrap();
    suite.reload_permissions_overlay().unwrap();
    assert_eq!(
        writer.lifecycle_wire_key_hash(&normal, true).unwrap(),
        protected
    );
    assert_eq!(
        writer.protected_key_hashes.lock().unwrap().get(&normal),
        Some(&protected)
    );
}

/// An opaque codec supplies keys per sample while its static DDS type is
/// keyless. A keyed TypeObject selects WITH_KEY on the normal constructor.
#[cfg(feature = "qos-loaders")]
#[derive(Debug, Clone, PartialEq)]
struct PerSampleKey(ProtectedKey);

#[cfg(feature = "qos-loaders")]
impl DDS for PerSampleKey {
    fn type_descriptor() -> &'static crate::core::types::TypeDescriptor {
        ProtectedKey::type_descriptor()
    }

    fn encode(&self, buf: &mut [u8], version: CdrVersion) -> Result<usize> {
        self.0.encode(buf, version)
    }

    fn decode(buf: &[u8], version: CdrVersion) -> Result<Self> {
        ProtectedKey::decode(buf, version).map(Self)
    }

    fn instance_key(&self) -> Option<[u8; 16]> {
        Some(self.0.compute_key())
    }

    fn protected_key(&self) -> Option<[u8; 16]> {
        self.0.protected_key()
    }

    fn encode_key(&self, version: CdrVersion) -> Vec<u8> {
        self.0.encode_key(version)
    }
}

/// Sec.7.3.4 applies to the sample's key, regardless of the codec's static
/// has_key(). With metadata NONE, a short normal KeyHash would expose the
/// clear key fields even though the data and key-only bodies are encrypted.
#[cfg(all(feature = "xtypes", feature = "qos-loaders"))]
#[test]
fn per_sample_key_write_and_lifecycle_share_protected_wire_identity() {
    use crate::security::crypto::user_data::{
        decode_serialized_payload, secured_payload_key_id, serialized_body,
    };
    use crate::security::test_pki::{
        TEST_CA_CERT_PEM, TEST_IDENTITY_CERT_PEM, TEST_IDENTITY_KEY_PEM,
    };
    use crate::test_support::{domains::unique_domain, wire};
    use std::io::Write as _;

    let mut other_domains = Vec::new();
    let domain = loop {
        let lease = unique_domain();
        if (200..=230).contains(&lease.id()) {
            break lease;
        }
        other_domains.push(lease);
    };
    let file = |bytes: &[u8]| {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(bytes).unwrap();
        f.flush().unwrap();
        f
    };
    let cert = file(TEST_IDENTITY_CERT_PEM);
    let key = file(TEST_IDENTITY_KEY_PEM);
    let ca = file(TEST_CA_CERT_PEM);
    let governance = file(
        b"<dds><domain_access_rules><domain_rule>\
        <domains><id_range><min>200</min><max>230</max></id_range></domains>\
        <allow_unauthenticated_participants>TRUE</allow_unauthenticated_participants>\
        <enable_join_access_control>FALSE</enable_join_access_control>\
        <discovery_protection_kind>NONE</discovery_protection_kind>\
        <liveliness_protection_kind>NONE</liveliness_protection_kind>\
        <rtps_protection_kind>NONE</rtps_protection_kind>\
        <topic_access_rules><topic_rule><topic_expression>*</topic_expression>\
        <enable_discovery_protection>FALSE</enable_discovery_protection>\
        <enable_liveliness_protection>FALSE</enable_liveliness_protection>\
        <enable_read_access_control>FALSE</enable_read_access_control>\
        <enable_write_access_control>FALSE</enable_write_access_control>\
        <metadata_protection_kind>NONE</metadata_protection_kind>\
        <data_protection_kind>ENCRYPT</data_protection_kind>\
        </topic_rule></topic_access_rules></domain_rule></domain_access_rules></dds>",
    );
    let permissions = file(
        b"<dds><permissions><grant name=\"adapter\">\
        <subject_name>CN=DDS Test Identity, O=HDDS Test</subject_name>\
        <validity><not_before>2020-01-01T00:00:00</not_before>\
        <not_after>2036-01-01T00:00:00</not_after></validity>\
        <allow_rule><domains><id_range><min>200</min><max>230</max></id_range></domains>\
        <publish><topics><topic>*</topic></topics></publish>\
        <subscribe><topics><topic>*</topic></topics></subscribe></allow_rule>\
        <default>DENY</default></grant></permissions></dds>",
    );
    let config = crate::security::SecurityConfig::builder()
        .identity_certificate(cert.path())
        .private_key(key.path())
        .ca_certificates(ca.path())
        .governance_xml(governance.path())
        .permissions_xml(permissions.path())
        .insecure_allow_unsigned_documents(true)
        .require_authentication(false)
        .enable_encryption(true)
        .build()
        .unwrap();
    let participant = crate::Participant::builder("per-sample-key")
        .domain_id(domain.id())
        .with_transport(crate::TransportMode::UdpMulticast)
        .with_security(config)
        .build()
        .unwrap();
    let mut writer = participant
        .create_writer_with_type::<PerSampleKey>(
            "per-sample-key",
            QoS::best_effort().data_representation_xcdr2(),
            "ProtectedKey",
            ProtectedKey::get_type_object(),
        )
        .unwrap();
    assert!(!PerSampleKey::has_key());
    assert!(!writer.serialized_keys);
    let ctx = writer.rtps_endpoint.unwrap();
    assert_eq!(ctx.writer_entity_id[3], 0x02, "WITH_KEY endpoint");
    let suite = writer.security.as_ref().unwrap();
    let protection = writer.endpoint_protection(suite).unwrap();
    assert!(protection.is_key_protected());
    assert!(protection.is_payload_protected());
    assert!(!protection.is_submessage_protected());
    let socket = wire::capture_data(&mut writer);
    let value = PerSampleKey(ProtectedKey {
        tag: 1,
        value: 2,
        payload: 3,
    });
    let normal = value.instance_key().unwrap();
    let protected = value.protected_key().unwrap();
    assert_ne!(normal, protected);
    writer.write(&value).unwrap();
    writer.dispose(&value).unwrap();
    let mut data = Vec::new();
    for packet in wire::drain(&socket) {
        if let Some(off) = builder::helpers::find_data_submsg_offset(&packet) {
            let layout = builder::data_submessage_layout(&packet, off).unwrap();
            let (iq, le) = builder::extract_inline_qos(&packet).unwrap();
            let hash = builder::extract_key_hash(iq, le).unwrap();
            assert_ne!(hash, normal, "metadata NONE must not expose the clear key");
            assert_eq!(hash, protected, "write and dispose use the same identity");
            let payload = &packet[layout.payload..layout.end];
            let key_id = secured_payload_key_id(payload).unwrap();
            let material = writer
                .security
                .as_ref()
                .unwrap()
                .data_keys
                .get_material(&GUID::new(ctx.guid_prefix, ctx.writer_entity_id), key_id)
                .unwrap();
            let plain = decode_serialized_payload(key_id, &material, payload).unwrap();
            let (body, version) = serialized_body(&plain).unwrap();
            assert_eq!(version, CdrVersion::Xcdr2);
            data.push((builder::is_key_only_data(&packet), body));
        }
    }
    let mut sample = [0; 64];
    let n = value.encode(&mut sample, CdrVersion::Xcdr2).unwrap();
    assert_eq!(
        data,
        vec![
            (false, sample[..n].to_vec()),
            (true, value.encode_key(CdrVersion::Xcdr2)),
        ]
    );

    // A fresh write revives the instance. Deletion unregisters it using
    // the same protected digest, after taking the written-instance table.
    writer.write(&value).unwrap();
    drop(writer);
    let changes: Vec<_> = wire::drain(&socket)
        .into_iter()
        .filter(|packet| builder::helpers::find_data_submsg_offset(packet).is_some())
        .collect();
    assert_eq!(changes.len(), 2, "write and Drop-time unregister");
    for packet in &changes {
        let (iq, le) = builder::extract_inline_qos(packet).unwrap();
        assert_eq!(builder::extract_key_hash(iq, le), Some(protected));
    }
    let (iq, le) = builder::extract_inline_qos(&changes[1]).unwrap();
    assert_eq!(builder::extract_status_info(iq, le).unwrap() & 2, 2);
}
