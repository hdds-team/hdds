// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! The ParticipantVolatileMessageSecure channel through the production
//! dispatch (`DiscoveryDispatch::dispatch`, the entry point the listener
//! uses): a datagram goes in as the listener hands it over, and what the
//! participant did with it is read back.

use super::secure_builtins::{setup_secure_builtins, SecureBuiltins};
use super::wire_fixtures::*;
use crate::core::discovery::multicast::PacketKind;
use crate::core::discovery::GUID;
use crate::core::rtps_constants::{
    HDDS_VENDOR_ID, RTPS_ENTITYID_BUILTIN_PARTICIPANT_VOLATILE_MESSAGE_SECURE_READER,
    RTPS_ENTITYID_BUILTIN_PARTICIPANT_VOLATILE_MESSAGE_SECURE_WRITER, RTPS_ENTITYID_PARTICIPANT,
    RTPS_ENTITYID_SPDP_SECURE_READER, RTPS_ENTITYID_SPDP_SECURE_WRITER, RTPS_VERSION_MAJOR,
    RTPS_VERSION_MINOR,
};
use crate::security::crypto::data_keys::WriterKey;
use crate::security::crypto::secure_submessage::WriterKeyMaterial;
use crate::security::crypto::volatile::WriterKeyAnnouncement;
use crate::security::SecurityPluginSuite;
use std::io::Write;
use std::sync::Arc;

/// A harness whose dispatch carries the secure builtins of a participant
/// that completed a real handshake with `SENDER_PREFIX`, the FSM and the
/// builtins sharing one handshake machine and one key store, as
/// `discovery_setup` wires them.
pub(super) struct VolatileHarness {
    pub(super) h: Harness,
    pub(super) suite: Arc<SecurityPluginSuite>,
    pub(super) builtins: SecureBuiltins,
    _files: [tempfile::NamedTempFile; 3],
}

impl VolatileHarness {
    pub(super) fn new() -> Self {
        let write_pem = |contents: &[u8]| {
            let mut f = tempfile::NamedTempFile::new().expect("temp file");
            f.write_all(contents).expect("write PEM");
            f.flush().expect("flush PEM");
            f
        };
        let cert = write_pem(crate::security::test_pki::TEST_IDENTITY_CERT_PEM);
        let key = write_pem(crate::security::test_pki::TEST_IDENTITY_KEY_PEM);
        let ca = write_pem(crate::security::test_pki::TEST_CA_CERT_PEM);
        let config = crate::security::SecurityConfig::builder()
            .identity_certificate(cert.path())
            .private_key(key.path())
            .ca_certificates(ca.path())
            .enable_encryption(true)
            .build()
            .expect("config");
        let mut suite = SecurityPluginSuite::new(config, 0).expect("suite");
        suite.handshakes = crate::security::test_pki::local_machine_with_completed_peer(
            OUR_PREFIX,
            SENDER_PREFIX,
            None,
        );
        let suite = Arc::new(suite);
        let mut h = Harness::new();
        {
            let fsm = Arc::get_mut(&mut h.dispatch.fsm).expect("the harness is the FSM's owner");
            fsm.set_handshake_machine(
                suite.handshakes.clone(),
                crate::security::test_pki::TEST_IDENTITY_CERT_PEM.to_vec(),
                crate::security::test_pki::TEST_IDENTITY_KEY_PEM.to_vec(),
            );
            fsm.register_builtin_writer_keys(Arc::clone(&suite.data_keys))
                .expect("builtin writer keys");
            fsm.register_builtin_reader_keys(Arc::clone(&suite.data_keys))
                .expect("builtin reader keys");
        }
        let builtins = setup_secure_builtins(OUR_PREFIX, &suite).expect("secure builtins");
        h.dispatch.secure_builtins = Some(builtins.clone());
        Self {
            h,
            suite,
            builtins,
            _files: [cert, key, ca],
        }
    }

    /// The KxKeys both sides of the pair derive (Table 67).
    pub(super) fn kx(&self) -> WriterKeyMaterial {
        self.suite
            .handshakes
            .volatile_key_material(&SENDER_PREFIX)
            .expect("the pair authenticated")
    }

    /// Deliver `datagram` as the listener does: at its first SEC_PREFIX
    /// as `SecureSEDP` when it carries one, as the classifier names it
    /// otherwise.
    pub(super) fn feed(&self, datagram: &[u8]) {
        if let Some(at) = crate::security::crypto::secure_submessage::first_secure_prefix(datagram)
        {
            self.h.feed(PacketKind::SecureSEDP, datagram, at, None);
            return;
        }
        let (kind, at, meta, _) =
            crate::core::discovery::multicast::classifier::classify_rtps(datagram);
        self.h.feed(kind, datagram, at.unwrap_or(SAMPLE_AT), meta);
    }
}

/// The RTPS header of a message from `source`, written out by hand.
pub(super) fn header_from(source: [u8; 12]) -> Vec<u8> {
    let mut out = b"RTPS".to_vec();
    out.extend_from_slice(&[RTPS_VERSION_MAJOR, RTPS_VERSION_MINOR]);
    out.extend_from_slice(&HDDS_VENDOR_ID);
    out.extend_from_slice(&source);
    out
}

/// INFO_DST naming `destination` (RTPS v2.5 Sec.9.4.5.10), little endian.
pub(super) fn info_dst(destination: [u8; 12]) -> Vec<u8> {
    let mut out = vec![0x0e, 0x01, 12, 0];
    out.extend_from_slice(&destination);
    out
}

/// A volatile message from `SENDER_PREFIX` to us: the header, INFO_DST,
/// then each protected submessage in its own place.
pub(super) fn volatile_datagram(protected: &[&[u8]]) -> Vec<u8> {
    let mut out = header_from(SENDER_PREFIX);
    out.extend_from_slice(&info_dst(OUR_PREFIX));
    for p in protected {
        out.extend_from_slice(p);
    }
    out
}

/// The sender's secure participant writer's key, announced to our secure
/// participant reader as change `sn` of its volatile writer, protected
/// under `kx`; with the key itself.
fn spdp_secure_writer_key(kx: &WriterKeyMaterial, sn: i64) -> (u32, WriterKey, Vec<u8>) {
    let (key_id, material) = WriterKey::mint().expect("mint");
    let wire = WriterKeyAnnouncement {
        writer_guid: GUID::new(SENDER_PREFIX, RTPS_ENTITYID_SPDP_SECURE_WRITER),
        key_id: u64::from(key_id),
        key: material.key.duplicate_for_store(),
        master_salt: material.salt.duplicate_for_store(),
        transformation: material.transformation,
    }
    .seal(
        kx,
        &GUID::new(
            SENDER_PREFIX,
            RTPS_ENTITYID_BUILTIN_PARTICIPANT_VOLATILE_MESSAGE_SECURE_WRITER,
        ),
        &GUID::new(OUR_PREFIX, RTPS_ENTITYID_PARTICIPANT),
        GUID::new(OUR_PREFIX, RTPS_ENTITYID_SPDP_SECURE_READER).as_bytes(),
        sn,
    )
    .expect("seal");
    (key_id, material, wire)
}

/// DDS Security v1.1 Sec.7.4.4.1 (Table 17) and Sec.8.5.1.9.2: the volatile
/// writer's DATA arrives as a SEC_PREFIX in the RTPS message itself, under
/// the pair's KxKeys -- no CryptoToken of any endpoint involved. The
/// production dispatch opens it with those keys and installs what it
/// carries.
///
/// Mutant: deleting the volatile routing from `handle_secure_sedp` (the
/// SEC_PREFIX then goes to the secure SEDP candidates, which hold nothing
/// for key id 0, and is held awaiting a key that never comes) fails the
/// install assertion.
#[test]
fn a_protected_volatile_data_in_the_rtps_message_installs_its_key() {
    let v = VolatileHarness::new();
    let (key_id, material, wire) = spdp_secure_writer_key(&v.kx(), 1);
    v.feed(&volatile_datagram(&[&wire]));
    let installed = v
        .suite
        .data_keys
        .get_material(
            &GUID::new(SENDER_PREFIX, RTPS_ENTITYID_SPDP_SECURE_WRITER),
            u64::from(key_id),
        )
        .expect("the key the protected DATA carries is installed");
    assert!(installed.same_material(&material));
    assert!(
        !v.h.dispatch.fsm.has_sedp_awaiting_key(&SENDER_PREFIX),
        "never held as a secure SEDP datagram waiting for a key"
    );
}

/// The key a held secure SEDP datagram waits for reaches it over the
/// volatile channel: the volatile datagram is not itself held behind the
/// one waiting (which would wait forever), and installing its key hands
/// the held one back.
///
/// Mutant: as above, the volatile datagram is then held awaiting a key
/// too and the departure stays held.
#[test]
fn a_volatile_datagram_is_not_held_behind_secure_sedp_waiting_for_its_key() {
    let v = VolatileHarness::new();
    let kx = v.kx();
    let (key_id, material, wire) = spdp_secure_writer_key(&kx, 1);
    let sealing = material.submessage_material(key_id);
    let departure = crate::core::discovery::multicast::fsm::sealed_departure_datagram(
        &sealing,
        GUID::new(SENDER_PREFIX, RTPS_ENTITYID_PARTICIPANT),
        crate::security::access::ProtectionKind::Encrypt,
    )
    .expect("sealed departure");
    v.feed(&departure);
    assert!(
        v.h.dispatch.fsm.has_sedp_awaiting_key(&SENDER_PREFIX),
        "fixture: the departure waits for its key"
    );
    v.feed(&volatile_datagram(&[&wire]));
    assert!(
        !v.h.dispatch.fsm.has_sedp_awaiting_key(&SENDER_PREFIX),
        "the installed key handed the held departure back"
    );
}

/// The topic is submessage-protected (Table 17): a CLEAR DATA of the
/// volatile endpoints -- the shape HDDS itself sent before, a DATA whose
/// payload is a protected envelope -- is refused and counted, never
/// opened.
///
/// Mutant: the `SecureVolatile` arm opening the clear DATA's payload as
/// if it were a protected envelope installs the key and fails both
/// assertions.
#[test]
fn a_clear_volatile_data_is_refused_and_counted() {
    let v = VolatileHarness::new();
    let (key_id, _, wire) = spdp_secure_writer_key(&v.kx(), 1);
    let clear_data = crate::protocol::rtps::encode_data(
        &RTPS_ENTITYID_BUILTIN_PARTICIPANT_VOLATILE_MESSAGE_SECURE_READER,
        &RTPS_ENTITYID_BUILTIN_PARTICIPANT_VOLATILE_MESSAGE_SECURE_WRITER,
        1,
        &wire,
    )
    .expect("DATA");
    let mut datagram = header_from(SENDER_PREFIX);
    datagram.extend_from_slice(&info_dst(OUR_PREFIX));
    datagram.extend_from_slice(&clear_data);
    // The classifier names it; no SEC_PREFIX at the RTPS level.
    let (kind, _, _, _) = crate::core::discovery::multicast::classifier::classify_rtps(&datagram);
    assert_eq!(kind, PacketKind::SecureVolatile, "fixture");
    v.feed(&datagram);
    assert!(v
        .suite
        .data_keys
        .get_material(
            &GUID::new(SENDER_PREFIX, RTPS_ENTITYID_SPDP_SECURE_WRITER),
            u64::from(key_id),
        )
        .is_none());
    assert_eq!(v.suite.volatile.stats.clear_refused(), 1);
}

/// Sec.7.4.4.4: a message whose destination_participant_guid is neither
/// GUID_UNKNOWN nor this participant is meant for another participant's
/// volatile reader, and is refused and counted.
///
/// Mutant: deleting the destination_participant_guid check installs it.
#[test]
fn a_message_for_another_participant_is_refused() {
    let v = VolatileHarness::new();
    let (key_id, material) = WriterKey::mint().expect("mint");
    let wire = WriterKeyAnnouncement {
        writer_guid: GUID::new(SENDER_PREFIX, RTPS_ENTITYID_SPDP_SECURE_WRITER),
        key_id: u64::from(key_id),
        key: material.key.duplicate_for_store(),
        master_salt: material.salt.duplicate_for_store(),
        transformation: material.transformation,
    }
    .seal(
        &v.kx(),
        &GUID::new(
            SENDER_PREFIX,
            RTPS_ENTITYID_BUILTIN_PARTICIPANT_VOLATILE_MESSAGE_SECURE_WRITER,
        ),
        &GUID::new([0x77; 12], RTPS_ENTITYID_PARTICIPANT),
        GUID::new(OUR_PREFIX, RTPS_ENTITYID_SPDP_SECURE_READER).as_bytes(),
        1,
    )
    .expect("seal");
    v.feed(&volatile_datagram(&[&wire]));
    assert!(v
        .suite
        .data_keys
        .get_material(
            &GUID::new(SENDER_PREFIX, RTPS_ENTITYID_SPDP_SECURE_WRITER),
            u64::from(key_id),
        )
        .is_none());
    assert_eq!(v.suite.volatile.stats.misaddressed_participant_refused(), 1);
}

/// What opens under the KxKeys and is not a submessage of the volatile
/// endpoints is refused and counted: the Kx material protects nothing
/// else (Sec.8.5.1.9.2). Here a DATA addressed to the volatile reader by
/// another writer.
///
/// Mutant: `parse_data` not checking the writerId takes this DATA as the
/// volatile writer's and decodes its payload (the counter stays 0).
#[test]
fn a_kx_protected_submessage_of_another_endpoint_is_refused() {
    let v = VolatileHarness::new();
    let foreign = crate::protocol::rtps::encode_data(
        &RTPS_ENTITYID_BUILTIN_PARTICIPANT_VOLATILE_MESSAGE_SECURE_READER,
        &RTPS_ENTITYID_SPDP_SECURE_WRITER,
        1,
        &[0x00, 0x01, 0x00, 0x00, 1, 2, 3, 4],
    )
    .expect("DATA");
    let protected =
        crate::security::crypto::secure_submessage::encode_datawriter_submessage(&v.kx(), &foreign)
            .expect("protect");
    v.feed(&volatile_datagram(&[&protected]));
    assert_eq!(v.suite.volatile.stats.foreign_submessage_refused(), 1);
}

/// `builtins` is the same value the dispatch holds.
#[test]
fn the_harness_dispatch_holds_the_builtins() {
    let v = VolatileHarness::new();
    assert!(v.h.dispatch.secure_builtins.is_some());
    assert_eq!(
        v.builtins.local_identity.guid,
        GUID::new(OUR_PREFIX, RTPS_ENTITYID_PARTICIPANT)
    );
}

/// A SEC_PREFIX naming the KxKeys' key id (0, Table 67) that does not
/// authenticate under them is refused and counted, and the datagram is
/// not held as a secure SEDP one waiting for a key: no secure builtin
/// endpoint of the sender announced key material under that id.
///
/// Mutant: `open_volatile_envelope` returning `None` for `Refused` (the
/// envelope then falls to secure SEDP and is held awaiting a key) fails
/// both assertions.
#[test]
fn a_volatile_key_id_envelope_that_does_not_open_is_refused_not_held() {
    let v = VolatileHarness::new();
    let not_the_kx = WriterKeyMaterial::new([0x5A; 32], [0xA5; 32], [0, 0, 0, 0]);
    let data = crate::protocol::rtps::encode_data(
        &RTPS_ENTITYID_BUILTIN_PARTICIPANT_VOLATILE_MESSAGE_SECURE_READER,
        &RTPS_ENTITYID_BUILTIN_PARTICIPANT_VOLATILE_MESSAGE_SECURE_WRITER,
        1,
        &[0x00, 0x01, 0x00, 0x00],
    )
    .expect("DATA");
    let protected = crate::security::crypto::secure_submessage::encode_datawriter_submessage(
        &not_the_kx,
        &data,
    )
    .expect("protect");
    v.feed(&volatile_datagram(&[&protected]));
    assert_eq!(v.suite.volatile.stats.undecodable(), 1);
    assert!(!v.h.dispatch.fsm.has_sedp_awaiting_key(&SENDER_PREFIX));
}

/// A probe socket standing for `SENDER_PREFIX`'s metatraffic unicast
/// locator: the sender's SPDP announcement names it.
fn sender_at_a_probe(v: &VolatileHarness) -> std::net::UdpSocket {
    let probe = std::net::UdpSocket::bind("127.0.0.1:0").expect("probe");
    probe
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .expect("timeout");
    let (mut data, _) = announcement_from(SENDER_PREFIX);
    data.metatraffic_unicast_locators = vec![probe.local_addr().expect("address")];
    let mut cdr = vec![0u8; 8192];
    let n = crate::protocol::discovery::build_spdp(&data, &mut cdr).expect("announcement");
    cdr.truncate(n);
    v.h.feed(
        PacketKind::SPDP,
        &data_datagram(SENDER_PREFIX, &SPDP, &cdr),
        SAMPLE_AT,
        None,
    );
    assert_eq!(
        v.h.dispatch.fsm.first_metatraffic_locator(&SENDER_PREFIX),
        Some(probe.local_addr().expect("address")),
        "fixture: the sender's locator is the probe"
    );
    probe
}

/// The next datagram the probe receives that carries submessages
/// protected under `kx` (the dispatch also answers the sender's SPDP),
/// with those submessages opened.
fn next_volatile(probe: &std::net::UdpSocket, kx: &WriterKeyMaterial) -> (Vec<u8>, Vec<Vec<u8>>) {
    use crate::security::crypto::secure_submessage::{
        decode_datawriter_submessage, first_secure_prefix,
    };
    let mut buf = [0u8; 65536];
    loop {
        let (n, _) = probe
            .recv_from(&mut buf)
            .expect("a volatile message reaches the peer");
        let datagram = buf[..n].to_vec();
        let opens = first_secure_prefix(&datagram)
            .is_some_and(|at| decode_datawriter_submessage(kx, &datagram, at).is_ok());
        if opens {
            let subs = opened_submessages(&datagram, kx);
            return (datagram, subs);
        }
    }
}

/// The submessages of `datagram` opened under `kx`, from its first
/// SEC_PREFIX on.
fn opened_submessages(datagram: &[u8], kx: &WriterKeyMaterial) -> Vec<Vec<u8>> {
    use crate::security::crypto::secure_submessage::{
        decode_datawriter_submessage, first_secure_prefix, first_secure_prefix_from,
    };
    let mut out = Vec::new();
    let mut at = first_secure_prefix(datagram);
    while let Some(prefix) = at {
        let decoded = decode_datawriter_submessage(kx, datagram, prefix).expect("opens");
        out.push(decoded.submessage);
        at = first_secure_prefix_from(datagram, decoded.end);
    }
    out
}

/// RTPS v2.5 Sec.8.4.12.2 through the production dispatch: the volatile
/// reader answers its peer writer's HEARTBEAT with an ACKNACK, protected
/// under the KxKeys (Table 17), addressed to the peer (INFO_DST) and sent
/// to its metatraffic locator, naming the change it has not received.
///
/// Mutant: the dispatch dropping the receipt's replies instead of sending
/// them leaves the probe silent.
#[test]
fn a_heartbeat_is_answered_with_a_protected_acknack_sent_to_the_peer() {
    let v = VolatileHarness::new();
    let probe = sender_at_a_probe(&v);
    let kx = v.kx();
    let heartbeat = crate::protocol::rtps::encode_heartbeat(
        &RTPS_ENTITYID_BUILTIN_PARTICIPANT_VOLATILE_MESSAGE_SECURE_READER,
        &RTPS_ENTITYID_BUILTIN_PARTICIPANT_VOLATILE_MESSAGE_SECURE_WRITER,
        1,
        1,
        1,
    )
    .expect("HEARTBEAT");
    let protected =
        crate::security::crypto::secure_submessage::encode_datawriter_submessage(&kx, &heartbeat)
            .expect("protect");
    v.feed(&volatile_datagram(&[&protected]));

    let (answer, subs) = next_volatile(&probe, &kx);
    assert_eq!(&answer[8..20], &OUR_PREFIX, "from us");
    assert_eq!(&answer[20..36], &info_dst(SENDER_PREFIX)[..], "to the peer");
    assert_eq!(subs.len(), 1);
    let acknack = &subs[0];
    assert_eq!(acknack[0], 0x06, "an ACKNACK");
    assert_eq!(acknack[1] & 0x02, 0, "Final clear: something is missing");
    assert_eq!(&acknack[4..8], &[0xff, 0x02, 0x02, 0xc4]);
    assert_eq!(&acknack[8..12], &[0xff, 0x02, 0x02, 0xc3]);
    assert_eq!(&acknack[12..20], &[0, 0, 0, 0, 1, 0, 0, 0], "bitmapBase 1");
    assert_eq!(&acknack[20..24], &1u32.to_le_bytes(), "one bit");
    assert_eq!(&acknack[24..28], &0x8000_0000u32.to_le_bytes(), "1 missing");
}

/// RTPS v2.5 Sec.8.4.9.2 through the production dispatch: an ACKNACK of
/// the peer's volatile reader asking for a change our writer holds for it
/// is answered with that change again, sent to the peer.
///
/// Mutant: as above.
#[test]
fn an_acknack_is_answered_with_the_change_it_asks_for() {
    let v = VolatileHarness::new();
    let probe = sender_at_a_probe(&v);
    let kx = v.kx();
    let (_, _, _first_send) = {
        let (key_id, material) = WriterKey::mint().expect("mint");
        let datagrams = v
            .suite
            .volatile
            .writer
            .lock()
            .write(
                &OUR_PREFIX,
                SENDER_PREFIX,
                &kx,
                std::time::Instant::now(),
                |sn| {
                    crate::security::crypto::volatile::protect_message(
                        &kx,
                        sn,
                        &[0x00, 0x01, 0x00, 0x00, 0xAB, 0xCD, 0xEF, 0x01],
                    )
                },
            )
            .expect("written");
        (key_id, material, datagrams)
    };
    let ask = crate::protocol::rtps::encode_acknack_with_final(
        &RTPS_ENTITYID_BUILTIN_PARTICIPANT_VOLATILE_MESSAGE_SECURE_READER,
        &RTPS_ENTITYID_BUILTIN_PARTICIPANT_VOLATILE_MESSAGE_SECURE_WRITER,
        1,
        1,
        &[0x8000_0000],
        1,
        false,
    )
    .expect("ACKNACK");
    let protected =
        crate::security::crypto::secure_submessage::encode_datareader_submessage(&kx, &ask)
            .expect("protect");
    v.feed(&volatile_datagram(&[&protected]));

    let (_, subs) = next_volatile(&probe, &kx);
    let data = subs
        .iter()
        .find_map(|s| crate::security::crypto::volatile::parse_data(s))
        .expect("the change is sent again");
    assert_eq!(data.sequence_number, 1);
    assert_eq!(
        data.payload,
        &[0x00, 0x01, 0x00, 0x00, 0xAB, 0xCD, 0xEF, 0x01]
    );
    assert_eq!(v.suite.volatile.stats.data_retransmitted(), 1);
}

/// NONE protects the topic by policy rather than by a SEC_PREFIX. The
/// departure is still accepted only after authentication; SIGN and ENCRYPT
/// require the corresponding submessage protection (DDS Security Table 59).
#[test]
fn a_clear_secure_participant_departure_follows_governance() {
    use crate::security::access::{DiscoveryGovernance, DomainRule, ProtectionKind};
    for kind in [
        ProtectionKind::None,
        ProtectionKind::Sign,
        ProtectionKind::Encrypt,
    ] {
        let mut v = VolatileHarness::new();
        let fsm = Arc::get_mut(&mut v.h.dispatch.fsm).expect("sole FSM owner");
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
        fsm.handle_spdp(announcement_from(SENDER_PREFIX).0);
        assert!(fsm
            .get_participants()
            .iter()
            .any(|p| p.guid.prefix == SENDER_PREFIX));
        // Independently written DATA(p[UD]), with status and participant key.
        let mut packet = header_from(SENDER_PREFIX);
        packet.extend_from_slice(&[
            0x15, 3, 52, 0, 0, 0, 16, 0, 0xff, 1, 1, 0xc7, 0xff, 1, 1, 0xc2, 0, 0, 0, 0, 1, 0, 0,
            0, 0x71, 0, 4, 0, 0, 0, 0, 3, 0x70, 0, 16, 0,
        ]);
        packet.extend_from_slice(&SENDER_PREFIX);
        packet.extend_from_slice(&[0, 0, 1, 0xc1, 1, 0, 0, 0]);
        v.feed(&packet);
        let known =
            v.h.dispatch
                .fsm
                .get_participants()
                .iter()
                .any(|p| p.guid.prefix == SENDER_PREFIX);
        assert_eq!(known, kind != ProtectionKind::None, "{kind:?}");
    }
}
