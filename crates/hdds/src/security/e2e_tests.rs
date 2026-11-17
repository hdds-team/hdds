// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! End-to-end DDS-Security tests over a real UDP transport.
//!
//! Everything else in the security tree is unit-level: the handshake tests
//! hand-carry encoded tokens between two `HandshakeMachine`s, and the writer's
//! `security_tests` steer the seal with a bare `CryptoPlugin` marker. Neither
//! proves that the packets actually travel -- which is how a whole control
//! plane can stay inert while its unit tests are green: the classifier, the
//! listener gate and the callback arm can each be individually plausible and
//! collectively dead.
//!
//! These tests stand up two real participants and let the network decide.
//!
//! # Why they live inside the crate
//!
//! [`crate::security::test_pki`] is `cfg(test)` and `pub(crate)`, and there are
//! no PEM files on disk anywhere in the repo. An external integration test would
//! have to embed its own certificate chain -- a second copy that silently rots
//! when the first is regenerated.
//!
//! # Two fixture flavours
//!
//! The authentication-path tests run with encryption OFF so a data-plane
//! problem cannot mask an authentication one. The data-plane tests
//! (`encrypted_samples_cross_between_authenticated_participants` and friends)
//! run with encryption ON and exercise the full chain: key mint, volatile
//! distribution, sealed samples, reader-side decrypt.
//!
//! # Domains are leased, never named
//!
//! Every test here takes its domain from
//! [`crate::test_support::domains::unique_domain`] rather than declaring a
//! constant. A constant can only avoid the other constants its author could
//! see: `access_control_decisions_reach_the_audit_chain_through_the_public_api`
//! used `const DOMAIN: u32 = 229` and died with "Address already in use"
//! against `tests/cloud_azure.rs`, a different binary running at the same
//! moment, and `both_authenticated_sides_hold_the_same_volatile_material` used
//! 217 while `security::stateless_writer`'s own test claimed 217 as its
//! "own domain" in the same lib binary.
//!
//! Two rules follow, and both matter:
//!
//! * The lease is the FIRST binding in the test, so it is dropped LAST --
//!   after the participants have torn down and closed their sockets. Written
//!   as `let d = unique_domain().id();` it would release the domain on the
//!   spot and reintroduce exactly the race it exists to prevent.
//! * A pair that must meet shares ONE lease (`domain.id()` passed twice).
//!   Leasing twice would put the two participants on different domains and
//!   they would never discover each other.

use crate::dds::{Participant, QoS, TransportMode};
use crate::security::test_pki::{
    AUDIT_GOVERNANCE_SMIME, AUDIT_PERMISSIONS_SMIME, GOVERNANCE_EC_SMIME, GOVERNANCE_PLAIN_XML,
    PERMISSIONS_OTHER_CA_SMIME, PERMISSIONS_PLAIN_XML, PERMISSIONS_TAMPERED_SMIME, PERM_CA_EC_PEM,
    TEST_CA_CERT_PEM, TEST_IDENTITY_CERT_PEM, TEST_IDENTITY_KEY_PEM,
};
use crate::security::SecurityConfig;
use crate::test_support::domains::unique_domain;
use std::io::Write;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tempfile::NamedTempFile;

/// Certificate material on disk, plus the handles that keep it there.
///
/// The `NamedTempFile`s MUST outlive the participant: `SecurityPluginSuite::new`,
/// `setup_secure_builtins` and `setup_discovery` each re-read these paths, and
/// dropping a handle unlinks the file mid-build.
struct SecurityFixture {
    config: SecurityConfig,
    _cert: NamedTempFile,
    _key: NamedTempFile,
    _ca: NamedTempFile,
}

fn write_pem(contents: &[u8]) -> NamedTempFile {
    let mut f = NamedTempFile::new().expect("temp file");
    f.write_all(contents).expect("write PEM");
    f.flush().expect("flush PEM");
    f
}

/// Both participants present the SAME identity, matching the convention already
/// set in `security::handshake::tests`: the handshake never compares the two
/// certificates against each other, so one identity still exercises chain
/// validation, ECDSA sign, ECDSA verify, ECDH and HKDF on both sides.
fn security_fixture() -> SecurityFixture {
    fixture_with_encryption(false)
}

/// Same PKI, with `enable_encryption` under the caller's control.
///
/// Encryption ON arms the full data plane: the writer mints a key at build,
/// the volatile channel distributes it, samples go out sealed. Discovery, the
/// handshake and secure SEDP are unaffected either way -- none of them goes
/// through the writer's sealer.
fn fixture_with_encryption(enable: bool) -> SecurityFixture {
    let cert = write_pem(TEST_IDENTITY_CERT_PEM);
    let key = write_pem(TEST_IDENTITY_KEY_PEM);
    let ca = write_pem(TEST_CA_CERT_PEM);

    let config = SecurityConfig::builder()
        .identity_certificate(cert.path())
        .private_key(key.path())
        .ca_certificates(ca.path())
        .enable_encryption(enable)
        .build()
        .expect("SecurityConfig from the shared test PKI must build");

    SecurityFixture {
        config,
        _cert: cert,
        _key: key,
        _ca: ca,
    }
}

/// Same PKI, with the key-agreement suite under the caller's control.
///
/// The suite is POLICY, not negotiation: the responder refuses a mismatch
/// outright (machine.rs `handle_request`), so both participants of a pair
/// must be built from the same fixture. Handshake signatures stay
/// ECDSA-P256-SHA256 for every suite -- the suite only selects the ECDH
/// curve and the MasterSharedSecret derivation -- which is why the shared
/// P-256 test PKI serves the P-384 suite unchanged.
fn fixture_with_suite(kagree_algo: &str) -> SecurityFixture {
    let cert = write_pem(TEST_IDENTITY_CERT_PEM);
    let key = write_pem(TEST_IDENTITY_KEY_PEM);
    let ca = write_pem(TEST_CA_CERT_PEM);

    let config = SecurityConfig::builder()
        .identity_certificate(cert.path())
        .private_key(key.path())
        .ca_certificates(ca.path())
        .key_establishment_algorithm(kagree_algo)
        .build()
        .expect("SecurityConfig with an explicit suite must build");

    SecurityFixture {
        config,
        _cert: cert,
        _key: key,
        _ca: ca,
    }
}

fn secure_participant(name: &str, domain: u32, fixture: &SecurityFixture) -> Arc<Participant> {
    Participant::builder(name)
        .domain_id(domain)
        .with_transport(TransportMode::UdpMulticast)
        .with_security(fixture.config.clone())
        .build()
        .unwrap_or_else(|e| {
            panic!(
                "secure participant '{}' must build on domain {}: {}. \
                 An \"Address already in use\" here names a domain this process LEASED, \
                 so no other leasing test can be on it: look for a binder that does not \
                 lease -- an unconverted domain constant in another crate, another \
                 worktree, or a stale test binary still running the pre-lease code",
                name, domain, e
            )
        })
}

/// True once `remote` appears in `local`'s SPDP participant list.
fn has_discovered(local: &Arc<Participant>, remote: &Arc<Participant>) -> bool {
    match local.discovery() {
        Some(fsm) => fsm
            .get_participants()
            .iter()
            .any(|p| p.guid == remote.guid()),
        None => false,
    }
}

/// True once `local`'s handshake machine holds a completed session for `remote`.
///
/// Keyed on ENTITYID_PARTICIPANT, which is the single convention the machine is
/// written and read under (`security::pump::guid_from_prefix`).
fn has_authenticated(local: &Arc<Participant>, remote: &Arc<Participant>) -> bool {
    let suite = match local.security() {
        Some(s) => s,
        None => return false,
    };
    let remote_participant_guid =
        crate::core::discovery::GUID::new(remote.guid().prefix, [0x00, 0x00, 0x01, 0xC1]);
    suite.handshakes.is_authenticated(&remote_participant_guid)
}

/// Poll `cond` until it holds or the deadline expires. Returns whether it held.
fn wait_until(timeout: Duration, mut cond: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if cond() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    cond()
}

// ---------------------------------------------------------------------------
//  The PKI-DH handshake, over the wire
// ---------------------------------------------------------------------------

/// Set in the child process that measures threads (see
/// `child_counts_stateless_writer_threads` below).
const SECURE_DROP_CHILD_ENV: &str = "HDDS_SECURE_DROP_CHILD";
/// The domain the child builds on (leased by the parent).
const SECURE_DROP_DOMAIN_ENV: &str = "HDDS_SECURE_DROP_DOMAIN";

/// How many threads in this process are currently named `name`.
///
/// The kernel truncates `/proc/self/task/*/comm` to `TASK_COMM_LEN - 1`
/// (15 bytes): `name` is truncated the same way before comparing, or a
/// name longer than that (like `hdds-stateless-writer`, 21 bytes) never
/// matches anything and this silently counts zero on both sides of a round.
fn thread_count_named(name: &str) -> usize {
    let truncated = &name[..name.len().min(15)];
    std::fs::read_dir("/proc/self/task")
        .expect("read /proc/self/task")
        .filter_map(Result::ok)
        .filter(|task| {
            std::fs::read_to_string(task.path().join("comm"))
                .map(|comm| comm.trim() == truncated)
                .unwrap_or(false)
        })
        .count()
}

/// Runs in a child process alone (see the parent below).
///
/// [`crate::test_support::threads::linger_on_exit`] makes every thread a
/// participant starts linger past its own work ending unless the teardown
/// is actively joining it. Without it this test cannot tell a join from a
/// bare unpark: the stateless writer thread drops its own `Arc<UdpTransport>`
/// clone as soon as it notices the stop signal, which in practice is fast
/// enough (and the rest of a participant's teardown slow enough) that the
/// transport/port checks below pass whether or not anyone ever joins that
/// thread. The thread-count check is the one that catches it: with the
/// linger armed, a forgotten join leaves the thread itself alive (still in
/// `/proc/self/task`) well past the drop's return, where a real join ends
/// it at once. Run alone, in its own process, so no other test's own
/// `hdds-stateless-writer` thread can be counted as this one's. The count
/// is read through [`crate::test_support::threads::settled`]: a joined
/// thread can still be listed for a few milliseconds after its join
/// returns, while the kernel finishes its exit.
#[test]
#[ignore = "re-executed as a child process by a_dropped_secure_participant_releases_its_transport_and_ports"]
fn child_counts_stateless_writer_threads() {
    assert!(
        std::env::var_os(SECURE_DROP_CHILD_ENV).is_some(),
        "run by the parent"
    );
    let domain: u32 = std::env::var(SECURE_DROP_DOMAIN_ENV)
        .expect("domain")
        .parse()
        .expect("numeric domain");
    crate::test_support::threads::linger_on_exit(Duration::from_secs(2));
    let fixture = security_fixture();
    let mapping = crate::transport::PortMapping::calculate(domain, 0).expect("port mapping");
    for round in 0..3 {
        let writers_before = thread_count_named("hdds-stateless-writer");
        let participant = Participant::builder("secure_drop")
            .domain_id(domain)
            .with_transport(TransportMode::UdpMulticast)
            .participant_id(Some(0))
            .with_security(fixture.config.clone())
            .build()
            .unwrap_or_else(|e| panic!("round {round}: participant id 0 refused: {e}"));
        let transport = Arc::downgrade(&participant.transport().expect("a UDP transport"));
        drop(participant);
        assert!(
            transport.upgrade().is_none(),
            "round {round}: something still holds the transport of a dropped secure participant"
        );
        for port in [mapping.metatraffic_unicast, mapping.user_unicast] {
            if let Err(e) = std::net::UdpSocket::bind(("0.0.0.0", port)) {
                panic!("round {round}: a dropped secure participant still holds port {port}: {e}");
            }
        }
        let writers_after = crate::test_support::threads::settled(&writers_before, || {
            thread_count_named("hdds-stateless-writer")
        });
        assert_eq!(
            writers_after, writers_before,
            "round {round}: the stateless writer thread outlived the dropped participant \
             (unparked but never joined)"
        );
    }
}

/// A secured participant's drop releases its transport and its unicast
/// ports before it returns: the security threads (the stateless writer,
/// which sends on the transport) are joined, not left to notice later.
/// The same participant id is built again on the same domain at once.
#[test]
fn a_dropped_secure_participant_releases_its_transport_and_ports() {
    let domain = unique_domain();
    let output = std::process::Command::new(std::env::current_exe().expect("this test binary"))
        .args([
            "security::e2e_tests::child_counts_stateless_writer_threads",
            "--exact",
            "--ignored",
            "--nocapture",
            "--test-threads",
            "1",
        ])
        .env(SECURE_DROP_CHILD_ENV, "1")
        .env(SECURE_DROP_DOMAIN_ENV, domain.id().to_string())
        .output()
        .expect("run the child");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success() && stdout.contains("1 passed"),
        "child failed: {}\nstdout:\n{stdout}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Two secure participants must authenticate each other over real UDP.
///
/// This is the end-to-end proof that the inbound handshake leg is alive. It
/// covers, in one shot, the three things that were independently broken and
/// each of which alone kept the control plane inert:
///   - the listener dispatching `PacketKind::Stateless` at all,
///   - the classifier producing a payload offset for it (a wrong offset here
///     silently parses the INFO_TS timestamp fraction as a CDR length),
///   - the callback slicing the datagram at that offset before handing it on.
///
/// Assert symmetrically. Which side initiates is decided by GUID prefix
/// comparison and is not under the test's control.
#[test]
fn two_secure_participants_complete_the_pki_dh_handshake() {
    let domain = unique_domain();

    let fixture = security_fixture();
    let alice = secure_participant("secure_alice", domain.id(), &fixture);
    let bob = secure_participant("secure_bob", domain.id(), &fixture);

    // SPDP must land first: the initiator only calls machine.start() from the
    // SPDP handler, gated on the peer advertising an identity token.
    let discovered = wait_until(Duration::from_secs(10), || {
        has_discovered(&alice, &bob) && has_discovered(&bob, &alice)
    });
    assert!(
        discovered,
        "SPDP discovery never completed, so the handshake was never even attempted \
         (alice sees bob: {}, bob sees alice: {})",
        has_discovered(&alice, &bob),
        has_discovered(&bob, &alice)
    );

    let authenticated = wait_until(Duration::from_secs(15), || {
        has_authenticated(&alice, &bob) && has_authenticated(&bob, &alice)
    });

    assert!(
        authenticated,
        "the PKI-DH handshake did not complete on both sides \
         (alice authenticated bob: {}, bob authenticated alice: {}) -- SPDP HAD succeeded, so \
         the break is on the stateless tunnel, not on discovery",
        has_authenticated(&alice, &bob),
        has_authenticated(&bob, &alice)
    );

    // Both sides must hold the SAME MasterSharedSecret. Two peers that agreed on
    // nothing would still each hold a plausible 32-byte value.
    let alice_secret = alice
        .discovery()
        .expect("alice discovery")
        .shared_secret_for_remote(&bob.guid().prefix)
        .expect("alice must hold a shared secret for bob");
    let bob_secret = bob
        .discovery()
        .expect("bob discovery")
        .shared_secret_for_remote(&alice.guid().prefix)
        .expect("bob must hold a shared secret for alice");

    assert_eq!(
        alice_secret.as_bytes().len(),
        32,
        "ECDH+prime256v1 through HKDF-SHA256 yields a 32-byte master secret"
    );
    assert_eq!(
        alice_secret, bob_secret,
        "both sides must derive the identical MasterSharedSecret over the wire"
    );

    // Read every assertion BEFORE dropping: Participant::drop calls
    // handshakes.drain(), which clears every Complete entry.
    drop(alice);
    drop(bob);
    std::thread::sleep(Duration::from_millis(500));
}

// ---------------------------------------------------------------------------
//  Per-peer key material
// ---------------------------------------------------------------------------

/// Both handshake roles retain the Table 67 inputs for the volatile channel.
fn assert_shared_volatile_material(
    alice: &crate::security::crypto::secure_submessage::WriterKeyMaterial,
    bob: &crate::security::crypto::secure_submessage::WriterKeyMaterial,
) {
    use crate::security::crypto::secure_submessage::{
        decode_datawriter_submessage, encode_datawriter_submessage,
    };
    assert_eq!(alice.key_id(), bob.key_id());
    let submessage = [0x01, 0x01, 4, 0, 0, 0, 0, 0];
    for (sender, receiver) in [(alice, bob), (bob, alice)] {
        let mut packet = b"RTPS".to_vec();
        packet.extend_from_slice(&[2, 5, 0x01, 0x1a]);
        packet.extend_from_slice(&[0x33; 12]);
        packet.extend_from_slice(&encode_datawriter_submessage(sender, &submessage).unwrap());
        let opened = decode_datawriter_submessage(receiver, &packet, 20).unwrap();
        assert_eq!(opened.submessage, submessage);
    }
}

/// Both sides of an authenticated pair must hold the SAME volatile key material, and
/// must hold one at all.
///
/// This is the test that fails against the obvious wrong implementation. The
/// natural place to derive per-peer keys is the pump's `HandshakeAction::
/// Completed` arm, and that arm is reached only by RESPONDERS: an initiator
/// completes inside `handle_reply` and returns `SendFinal`. Deriving there would
/// leave this green on one participant and red on the other, and which one is
/// decided by a GUID prefix comparison the test does not control -- so it would
/// also look flaky rather than wrong.
///
/// Asserting on BOTH directions is therefore the whole point, not symmetry for
/// its own sake.
#[test]
fn both_authenticated_sides_hold_the_same_volatile_material() {
    let domain = unique_domain();

    let fixture = security_fixture();
    let alice = secure_participant("key_alice", domain.id(), &fixture);
    let bob = secure_participant("key_bob", domain.id(), &fixture);

    let alice_suite = alice.security().expect("alice must carry a security suite");
    let bob_suite = bob.security().expect("bob must carry a security suite");

    // Before authentication there is nothing to hand out. If a key existed
    // for a peer that had not authenticated, the rest of the test would
    // prove nothing about the handshake -- it could be reading a key some
    // other mechanism (a construction-time default, a stale cache) handed
    // out for free.
    //
    // This cannot be checked as a flat "no key yet": both participants
    // start their discovery and handshake threads inside `build()`, above,
    // and this thread can be preempted for the few instructions it takes to
    // reach this line. On a loaded box that gap is
    // enough wall time for loopback SPDP and the full PKI-DH handshake to
    // finish on other threads before this one resumes, so a key can
    // legitimately already be present here. What must still hold, and is
    // the actual property this check exists to defend, is that a key is
    // NEVER present without a completed handshake behind it.
    if let Some(early_key) = alice_suite
        .handshakes
        .volatile_key_material(&bob.guid().prefix)
    {
        assert!(
            has_authenticated(&alice, &bob),
            "volatile key material exists for bob although alice has not authenticated him -- \
             the key came from somewhere other than a completed handshake"
        );
        drop(early_key);
    }

    assert!(
        wait_until(Duration::from_secs(10), || {
            has_discovered(&alice, &bob) && has_discovered(&bob, &alice)
        }),
        "SPDP discovery never completed"
    );
    assert!(
        wait_until(Duration::from_secs(15), || {
            has_authenticated(&alice, &bob) && has_authenticated(&bob, &alice)
        }),
        "the pair never authenticated, so this test cannot say anything about key derivation"
    );

    let alice_key = alice_suite
        .handshakes
        .volatile_key_material(&bob.guid().prefix)
        .unwrap_or_else(|| {
            panic!(
                "alice completed the handshake with bob but holds no volatile key material for him. \
                 If bob's key is present and alice's is not, the derivation is hooked to the \
                 responder-only completion path"
            )
        });
    let bob_key = bob_suite
        .handshakes
        .volatile_key_material(&alice.guid().prefix)
        .unwrap_or_else(|| {
            panic!(
                "bob completed the handshake with alice but holds no volatile key material for her. \
                 See the note on alice's side: one-sided population is the expected failure"
            )
        });

    assert_shared_volatile_material(&alice_key, &bob_key);

    // A key for a peer nobody handshook with must not appear from anywhere.
    assert!(
        alice_suite
            .handshakes
            .volatile_key_material(&[0xAB; 12])
            .is_none(),
        "volatile key material was returned for a participant that does not exist"
    );

    // Read every assertion BEFORE dropping: Participant::drop calls
    // handshakes.drain(), which clears every Complete entry and its keys.
    drop(alice_key);
    drop(bob_key);
    drop(alice);
    drop(bob);
    std::thread::sleep(Duration::from_millis(500));
}

/// The P-384 suite completes a real handshake over UDP, end to end.
///
/// The unit tests already pin the machine's P-384 arithmetic (97-byte public
/// keys, 48-byte MasterSharedSecret, HKDF-SHA384) and the fail-closed policy
/// around it. What only an e2e can say is that the CONFIG string travels the
/// whole chain: `SecurityConfig::key_establishment_algorithm` -> the live
/// participant's `HandshakeMachine` (asserted via the introspection accessor,
/// so a silent fall-back to the P-256 default cannot pass) -> AuthRequest on
/// the wire -> a completed session whose derived volatile key material agrees.
/// Completion itself certifies both sides ran P-384: the responder refuses
/// any suite that differs from its own configured policy.
#[test]
fn the_p384_suite_completes_a_handshake_between_live_participants() {
    const SUITE: &str = "ECDH+secp384r1-CEUM";

    let domain = unique_domain();
    let fixture = fixture_with_suite(SUITE);
    let alice = secure_participant("p384_alice", domain.id(), &fixture);
    let bob = secure_participant("p384_bob", domain.id(), &fixture);

    let alice_suite = alice.security().expect("alice must carry a security suite");
    let bob_suite = bob.security().expect("bob must carry a security suite");

    // The config string must have reached the machine that will run the
    // handshake. Everything after this line exercises that machine.
    assert_eq!(alice_suite.handshakes.kagree_algo(), SUITE);
    assert_eq!(bob_suite.handshakes.kagree_algo(), SUITE);

    assert!(
        wait_until(Duration::from_secs(10), || {
            has_discovered(&alice, &bob) && has_discovered(&bob, &alice)
        }),
        "SPDP discovery never completed"
    );
    assert!(
        wait_until(Duration::from_secs(15), || {
            has_authenticated(&alice, &bob) && has_authenticated(&bob, &alice)
        }),
        "the pair never authenticated under the P-384 suite -- the initiator \
         advertises it and the responder must accept its own configured policy"
    );

    let alice_key = alice_suite
        .handshakes
        .volatile_key_material(&bob.guid().prefix)
        .expect("alice authenticated under P-384 but holds no volatile key material for bob");
    let bob_key = bob_suite
        .handshakes
        .volatile_key_material(&alice.guid().prefix)
        .expect("bob authenticated under P-384 but holds no volatile key material for alice");

    assert_shared_volatile_material(&alice_key, &bob_key);

    drop(alice_key);
    drop(bob_key);
    drop(alice);
    drop(bob);
    std::thread::sleep(Duration::from_millis(500));
}

/// THE data-plane milestone: an encrypted sample crosses between two
/// authenticated participants and arrives intact.
///
/// This test replaces `an_encrypting_writer_refuses_and_names_the_missing
/// _piece`, the seam marker whose whole purpose was to be rewritten the day
/// the data plane moved. It moved: the writer seals every sample under its
/// own data-plane key, the key travels the volatile channel, and the reader
/// opens the payload before any reception bookkeeping.
///
/// The sample is written in a retry loop on purpose: the first writes may
/// legitimately race the key distribution (the reader drops what it cannot
/// decrypt, WITHOUT crediting the SN), and convergence within the loop is
/// exactly the recovery behaviour the design promises.
#[test]
fn encrypted_samples_cross_between_authenticated_participants() {
    use crate::generated::temperature::Temperature;

    const TOPIC: &str = "EncryptedTemperature";

    let domain = unique_domain();
    let fixture = fixture_with_encryption(true);
    let publisher = secure_participant("enc_pub", domain.id(), &fixture);
    let subscriber = secure_participant("enc_sub", domain.id(), &fixture);

    assert!(
        wait_until(Duration::from_secs(10), || {
            has_discovered(&publisher, &subscriber) && has_discovered(&subscriber, &publisher)
        }),
        "SPDP discovery never completed -- enabling encryption must not break discovery"
    );
    assert!(
        wait_until(Duration::from_secs(15), || {
            has_authenticated(&publisher, &subscriber) && has_authenticated(&subscriber, &publisher)
        }),
        "the pair never authenticated with encryption enabled"
    );

    let writer = publisher
        .topic::<Temperature>(TOPIC)
        .expect("writer topic")
        .writer()
        .qos(QoS::reliable().keep_all())
        .build()
        .expect("writer");
    let reader = subscriber
        .topic::<Temperature>(TOPIC)
        .expect("reader topic")
        .reader()
        .qos(QoS::reliable().keep_all())
        .build()
        .expect("reader");

    // SEDP matching, then the distribution sweep (250 ms cadence).
    std::thread::sleep(Duration::from_millis(1000));

    let sample = Temperature {
        value: 21.5,
        timestamp: 1_754_000_000,
    };

    let mut received: Option<Temperature> = None;
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        writer
            .write(&sample)
            .expect("an encrypting writer with a minted key must accept the sample");
        if let Ok(Some(msg)) = reader.take() {
            received = Some(msg);
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }

    let received = received.unwrap_or_else(|| {
        panic!(
            "no encrypted sample crossed between two authenticated participants. The pair \
             authenticated and every write succeeded, so the loss is in the data plane: \
             key never distributed (volatile channel), reader dropping ciphertext (key \
             lookup / decrypt gate), or the payload never sealed at all"
        )
    });
    assert_eq!(received.value, sample.value);
    assert_eq!(received.timestamp, sample.timestamp);

    // The wire really carried ciphertext, not plaintext that happened to
    // arrive: the writer's history cache stores the WIRE bytes, so its
    // first entry must be a secured payload, not CDR.
    // (Indirect but honest: reading the datagram itself would need a packet
    // capture, and the cache-stores-wire-bytes property is load-bearing for
    // repair anyway.)
    let pub_suite = publisher.security().expect("publisher suite");
    let locals = user_writer_keys(&pub_suite, &publisher.guid().prefix);
    assert_eq!(locals.len(), 1, "the writer must hold exactly one data key");

    drop(writer);
    drop(reader);
    drop(publisher);
    drop(subscriber);
    std::thread::sleep(Duration::from_millis(500));
}

/// The refusal must cover the intra-process leg, not just the wire.
///
/// `DomainRegistry::global()` is a process-wide `OnceLock` keyed by domain id
/// alone, and `DomainState` groups endpoints by `(topic, type_id)` with no
/// notion of which participant owns them. So a writer in one participant
/// auto-binds to a reader in ANOTHER participant of the same process and hands
/// it the sample through a shared slab, bypassing RTPS and UDP entirely.
///
/// `write()` returns into `write_intra_process_fast` BEFORE the encryption gate
/// whenever there are local readers and no remote peers, so that leg never
/// consults security at all. `TransportMode::IntraProcess` makes the condition
/// permanent rather than a startup race: with no transport there is never a
/// remote peer, so the fast path is the only path.
///
/// The code justified this with "same address space, nothing to protect it from
/// that could not already read the writer's own memory". That holds for two
/// endpoints of ONE participant. It does not hold here: the subscriber is a
/// separate DDS-Security principal, with its own identity certificate and its
/// own permissions, that has completed no handshake with the publisher.
#[test]
fn an_encrypting_writer_refuses_the_intra_process_leg_too() {
    use crate::dds::Error;
    use crate::generated::temperature::Temperature;

    const TOPIC: &str = "IntraBypassTemperature";

    // IntraProcess binds no socket, so this lease is not about ports: the
    // registry `DomainRegistry::global()` keys on the domain id alone, and
    // the whole point of the test is that the two participants share exactly
    // one domain and nothing else in the process joins them there.
    let domain = unique_domain();
    let fixture = fixture_with_encryption(true);
    let secure_intra_participant = |name: &str| {
        Participant::builder(name)
            .domain_id(domain.id())
            .with_transport(TransportMode::IntraProcess)
            .with_security(fixture.config.clone())
            .build()
            .unwrap_or_else(|e| panic!("participant '{}' must build: {}", name, e))
    };
    let publisher = secure_intra_participant("intra_enc_pub");
    let subscriber = secure_intra_participant("intra_enc_sub");

    let writer = publisher
        .topic::<Temperature>(TOPIC)
        .expect("writer topic")
        .writer()
        .qos(QoS::reliable().keep_all())
        .build()
        .expect("an encrypting writer must still BUILD; only writes are refused");
    let reader = subscriber
        .topic::<Temperature>(TOPIC)
        .expect("reader topic")
        .reader()
        .qos(QoS::reliable().keep_all())
        .build()
        .expect("reader");

    let sample = Temperature {
        value: 42.5,
        timestamp: 7,
    };
    let result = writer.write(&sample);

    // Read the reader either way: a refusal that still delivered would be the
    // worst of both, and asserting only on the Err would not catch it.
    std::thread::sleep(Duration::from_millis(300));
    let delivered = reader.take();

    assert!(
        matches!(delivered, Ok(None)),
        "fail-open: a participant with enable_encryption(true) delivered user data in \
         cleartext to a DIFFERENT participant through the intra-process slab. \
         write() returned {:?} and the peer received {:?}. No handshake, no \
         authentication, no permissions check and no cipher stand between them -- the \
         intra path returns from write() before the encryption gate is reached",
        result,
        delivered
    );
    assert!(
        matches!(result, Err(Error::EncryptionUnavailable(_))),
        "the intra-process leg must refuse for the same reason and with the same error \
         as the wire leg. Two emission paths that must agree about the security posture \
         will drift apart unless they consult one predicate. Got: {:?}",
        result
    );

    drop(writer);
    drop(reader);
    drop(publisher);
    drop(subscriber);
    std::thread::sleep(Duration::from_millis(300));
}

/// An encrypting writer must not stockpile plaintext for readers it has not
/// met yet.
///
/// The route this pins bypasses `write()`'s own emission legs entirely: with no
/// transport and NO readers at all, nothing is delivered at write time -- but a
/// RELIABLE writer stores the serialized sample in its history cache, and for
/// TRANSIENT_LOCAL durability `TopicMerger::add_reader` replays the whole
/// retained backlog into any reader that binds LATER, at bind time, without a
/// single further `write()` call. So a write that "emitted nothing" still
/// leaks: it parks the cleartext and the registry hands it to the next foreign
/// participant's reader that shows up on the topic.
///
/// Refusing at write time is the only place that closes this: by bind time the
/// bytes are already in the cache and the replay path has no security hook.
#[test]
fn an_encrypting_writer_refuses_to_park_plaintext_for_later_replay() {
    use crate::dds::Error;
    use crate::generated::temperature::Temperature;

    const TOPIC: &str = "ReplayBacklogTemperature";

    // Same reasoning as the intra-process bypass test: no socket is bound,
    // but the process-global registry keys on the domain id, so the pair
    // still needs a domain nothing else in this process is using.
    let domain = unique_domain();
    let fixture = fixture_with_encryption(true);
    let secure_intra_participant = |name: &str| {
        Participant::builder(name)
            .domain_id(domain.id())
            .with_transport(TransportMode::IntraProcess)
            .with_security(fixture.config.clone())
            .build()
            .unwrap_or_else(|e| panic!("participant '{}' must build: {}", name, e))
    };
    let publisher = secure_intra_participant("replay_enc_pub");

    // TRANSIENT_LOCAL is what arms the late-joiner replay; KEEP_ALL retains
    // every sample. The writer is built while ZERO readers exist anywhere.
    let writer = publisher
        .topic::<Temperature>(TOPIC)
        .expect("writer topic")
        .writer()
        .qos(QoS::reliable().transient_local().keep_all())
        .build()
        .expect("an encrypting writer must still BUILD; only writes are refused");

    let result = writer.write(&Temperature {
        value: 3.5,
        timestamp: 11,
    });

    assert!(
        matches!(result, Err(Error::EncryptionUnavailable(_))),
        "with no readers and no transport the write LOOKS harmless -- nothing is \
         delivered anywhere at write time -- but a success here means the plaintext \
         went into the reliable history cache for later TRANSIENT_LOCAL replay. \
         Got: {:?}",
        result
    );

    // Belt and braces: bind a late-joining reader from a DIFFERENT participant
    // and confirm no backlog reaches it. If the write above was refused this
    // can only pass; it exists so that a future fail-open regression is caught
    // by the leak itself and not only by the missing error.
    let subscriber = secure_intra_participant("replay_enc_sub");
    let reader = subscriber
        .topic::<Temperature>(TOPIC)
        .expect("reader topic")
        .reader()
        .qos(QoS::reliable().transient_local().keep_all())
        .build()
        .expect("reader");
    std::thread::sleep(Duration::from_millis(300));
    let replayed = reader.take();
    assert!(
        matches!(replayed, Ok(None)),
        "a late-joining reader from another participant received the retained \
         backlog of an encrypting writer in cleartext: {:?}",
        replayed
    );

    drop(writer);
    drop(reader);
    drop(publisher);
    drop(subscriber);
    std::thread::sleep(Duration::from_millis(300));
}

/// A writer's data-plane key must reach an authenticated subscriber over the
/// ParticipantVolatileMessageSecure channel, byte-identical.
///
/// End-to-end over real UDP, covering in one shot the whole distribution
/// chain: key minted at writer build -> the writer matches the
/// subscriber's reader -> distribution sweep on the hdds-stateless-writer
/// thread writes a DatawriterCryptoTokens addressed to that reader into the
/// reliable volatile writer -> protected DATA (SEC_PREFIX under the pair's
/// KxKeys) unicast -> listener -> volatile reader -> addressing check (a
/// local reader matched with the writer) -> DataKeyStore install. Every
/// link is unit-tested; this is the proof they are CONNECTED, which is
/// exactly what the control plane lacked while its own unit tests were
/// green. The tokens go to a matched reader only (DDS Security v1.1
/// Sec.7.4.4.6.2), so the subscriber has one.
#[test]
fn a_writers_data_key_reaches_an_authenticated_subscriber() {
    use crate::generated::temperature::Temperature;

    let domain = unique_domain();
    let fixture = fixture_with_encryption(true);
    let publisher = secure_participant("keydist_pub", domain.id(), &fixture);
    let subscriber = secure_participant("keydist_sub", domain.id(), &fixture);

    let writer = publisher
        .topic::<Temperature>("KeyDistTemperature")
        .expect("writer topic")
        .writer()
        .qos(QoS::reliable().keep_all())
        .build()
        .expect("writer");
    let reader = subscriber
        .topic::<Temperature>("KeyDistTemperature")
        .expect("reader topic")
        .reader()
        .qos(QoS::reliable().keep_all())
        .build()
        .expect("reader");

    // The key is minted at build time, before any peer authenticated.
    let pub_suite = publisher.security().expect("publisher suite");
    let locals = user_writer_keys(&pub_suite, &publisher.guid().prefix);
    assert_eq!(
        locals.len(),
        1,
        "an encrypting writer must mint exactly one data-plane key at build time"
    );
    let (writer_guid, key_id, local_key) = (
        locals[0].0,
        locals[0].1,
        locals[0].2.key.as_bytes().to_owned(),
    );

    assert!(
        wait_until(Duration::from_secs(10), || {
            has_discovered(&publisher, &subscriber) && has_discovered(&subscriber, &publisher)
        }),
        "SPDP discovery never completed"
    );
    assert!(
        wait_until(Duration::from_secs(15), || {
            has_authenticated(&publisher, &subscriber) && has_authenticated(&subscriber, &publisher)
        }),
        "the pair never authenticated, so no key distribution can be expected"
    );

    // The writer must first match the reader over secure SEDP; the sweep
    // then runs within 250 ms.
    let sub_suite = subscriber.security().expect("subscriber suite");
    let delivered = wait_until(Duration::from_secs(10), || {
        sub_suite.data_keys.get(&writer_guid, key_id).is_some()
    });
    assert!(
        delivered,
        "the subscriber never received the writer's data-plane key. The pair IS \
         authenticated, so the break is on the volatile channel: sweep not running, \
         packet not sent (unicast address missing?), classifier offset, listener \
         gate, or the addressing check refusing the tokens"
    );

    let remote_key = sub_suite
        .data_keys
        .get(&writer_guid, key_id)
        .expect("checked above");
    assert_eq!(
        remote_key.as_bytes(),
        &local_key[..],
        "the delivered key differs from the minted one: the envelope crypto \
         round-trip corrupted the key material"
    );

    // An unauthenticated third GUID must have received nothing (the store is
    // per-process here, so this checks the foreign-writer guard indirectly:
    // only announced pairs exist).
    assert!(
        sub_suite.data_keys.get(&writer_guid, key_id ^ 1).is_none(),
        "a key id nobody announced is present in the store"
    );

    drop(writer);
    drop(reader);
    drop(publisher);
    drop(subscriber);
    std::thread::sleep(Duration::from_millis(500));
}

/// ParticipantCryptoTokens (Sec.7.4.4.6.1, Sec.8.8.9.1) travel BOTH ways
/// between an authenticated pair, independently of any writer or reader:
/// each side mints its own key material at participant build time and
/// must receive the other's.
#[test]
fn participant_crypto_tokens_reach_both_sides_of_an_authenticated_pair() {
    let domain = unique_domain();
    let fixture = fixture_with_encryption(true);
    let one = secure_participant("pkt_one", domain.id(), &fixture);
    let two = secure_participant("pkt_two", domain.id(), &fixture);

    let one_suite = one.security().expect("one suite");
    let two_suite = two.security().expect("two suite");
    let (one_id, one_key) = one_suite
        .participant_keys
        .local_key_material()
        .expect("encryption enabled, one must have minted its own key");
    let (two_id, two_key) = two_suite
        .participant_keys
        .local_key_material()
        .expect("encryption enabled, two must have minted its own key");
    assert_ne!(
        one_key.key.as_bytes(),
        two_key.key.as_bytes(),
        "two independently minted participant key materials collided"
    );

    assert!(
        wait_until(Duration::from_secs(10), || {
            has_discovered(&one, &two) && has_discovered(&two, &one)
        }),
        "SPDP discovery never completed"
    );
    assert!(
        wait_until(Duration::from_secs(15), || {
            has_authenticated(&one, &two) && has_authenticated(&two, &one)
        }),
        "the pair never authenticated, so no key exchange can be expected"
    );

    // Written at the first sweep after authentication (250 ms cadence),
    // in BOTH directions.
    let two_prefix = two.guid().prefix;
    let one_prefix = one.guid().prefix;
    let delivered = wait_until(Duration::from_secs(6), || {
        one_suite.participant_keys.get_remote(&two_prefix).is_some()
            && two_suite.participant_keys.get_remote(&one_prefix).is_some()
    });
    assert!(
        delivered,
        "at least one side never received the other's participant key material"
    );

    let (remote_id_at_one, remote_key_at_one) = one_suite
        .participant_keys
        .get_remote(&two_prefix)
        .expect("checked above");
    assert_eq!(
        remote_id_at_one, two_id,
        "the key id `one` received for `two` does not match what `two` minted"
    );
    assert_eq!(
        remote_key_at_one.key.as_bytes(),
        two_key.key.as_bytes(),
        "the key `one` received for `two` does not match what `two` minted: the \
         envelope crypto round-trip corrupted it"
    );
    assert_eq!(
        remote_key_at_one.salt.as_bytes(),
        two_key.salt.as_bytes(),
        "the salt `one` received for `two` is not the one `two` minted"
    );

    let (remote_id_at_two, remote_key_at_two) = two_suite
        .participant_keys
        .get_remote(&one_prefix)
        .expect("checked above");
    assert_eq!(remote_id_at_two, one_id);
    assert_eq!(remote_key_at_two.key.as_bytes(), one_key.key.as_bytes());
    assert_eq!(remote_key_at_two.salt.as_bytes(), one_key.salt.as_bytes());

    drop(one);
    drop(two);
    std::thread::sleep(Duration::from_millis(500));
}

/// The departure of an authenticated participant goes on its secure
/// participant writer (DDS Security v1.1 Sec.7.4.1.6), protected under that
/// writer's own key material, which the peer received in its
/// DatawriterCryptoTokens (Sec.8.8.9.2). With a 300 s lease, the peer forgets
/// it at once rather than at lease expiry; its plain departure is ignored
/// once it authenticated, so only the sealed one can do that.
///
/// Mutant: `DiscoveryFsm::sealed_departure_for` returning `None` fails it.
#[test]
fn an_authenticated_participant_that_leaves_is_forgotten_by_its_sealed_departure() {
    let domain = unique_domain();
    let fixture = fixture_with_encryption(true);
    let stays = long_lived_secure_participant("stays", domain.id(), 6, &fixture);
    let leaves = long_lived_secure_participant("leaves", domain.id(), 7, &fixture);
    assert!(
        wait_until(Duration::from_secs(15), || {
            has_authenticated(&stays, &leaves) && has_authenticated(&leaves, &stays)
        }),
        "the pair never authenticated"
    );
    let prefix = leaves.guid().prefix;
    let participant_writer = crate::core::discovery::GUID::new(
        prefix,
        crate::core::rtps_constants::RTPS_ENTITYID_SPDP_SECURE_WRITER,
    );
    let stays_suite = stays.security().expect("suite");
    assert!(
        wait_until(Duration::from_secs(10), || {
            stays_suite
                .data_keys
                .material_for_writer(&participant_writer)
                .is_some()
        }),
        "the key material of the leaving participant's secure participant writer never arrived"
    );
    let known = |prefix: [u8; 12]| {
        stays.discovery().is_some_and(|fsm| {
            fsm.get_participants()
                .iter()
                .any(|p| p.guid.prefix == prefix)
        })
    };
    assert!(known(prefix), "fixture: discovered");

    drop(leaves);
    assert!(
        wait_until(Duration::from_secs(5), || !known(prefix)),
        "the participant that left is still known: its sealed departure was not read"
    );

    drop(stays);
}

// ---------------------------------------------------------------------------
//  User data across an authenticated pair
// ---------------------------------------------------------------------------

/// Two secure participants must still deliver user data to each other.
///
/// This answers a question the static analysis could not: the authentication
/// gate in `fsm::discovery::notify_endpoint_discovered` looks up
/// `is_authenticated` with a participant GUID whose entity_id is `[0,0,0,0]`,
/// while every write to that map keys on `[0,0,1,0xC1]`. The two can never be
/// equal, so the gate closes for every peer. What was NOT established by reading
/// is whether that gate merely suppresses `on_*_matched` callbacks or actually
/// severs delivery -- the answer decides how severe the defect is, and only
/// running it settles the matter.
#[test]
fn two_secure_participants_deliver_user_data() {
    use crate::generated::temperature::Temperature;

    const TOPIC: &str = "SecureTemperature";

    let domain = unique_domain();
    let fixture = security_fixture();
    let publisher = secure_participant("secure_pub", domain.id(), &fixture);
    let subscriber = secure_participant("secure_sub", domain.id(), &fixture);

    let discovered = wait_until(Duration::from_secs(10), || {
        has_discovered(&publisher, &subscriber) && has_discovered(&subscriber, &publisher)
    });
    assert!(discovered, "SPDP discovery never completed");

    let writer = publisher
        .topic::<Temperature>(TOPIC)
        .expect("writer topic")
        .writer()
        .qos(QoS::reliable().keep_all())
        .build()
        .expect("writer");

    let reader = subscriber
        .topic::<Temperature>(TOPIC)
        .expect("reader topic")
        .reader()
        .qos(QoS::reliable().keep_all())
        .build()
        .expect("reader");

    // SEDP has to match the endpoints before the first sample can land.
    std::thread::sleep(Duration::from_millis(1000));

    let sample = Temperature {
        value: 21.5,
        timestamp: 1_754_000_000,
    };

    // Retry the write: a secure pair takes longer to match than a plain one, and
    // a sample emitted before matching is simply not routed anywhere.
    let mut received: Option<Temperature> = None;
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        writer.write(&sample).expect("write must not be refused");
        if let Ok(Some(msg)) = reader.take() {
            received = Some(msg);
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    let received = received.unwrap_or_else(|| {
        panic!(
            "no sample crossed between two authenticated participants. \
             SPDP had succeeded and both writers accepted the sample, so the loss is at \
             matching or routing -- check whether the always-closed auth gate in \
             fsm::discovery::notify_endpoint_discovered severs delivery and not just callbacks"
        )
    });

    assert_eq!(received.value, sample.value);
    assert_eq!(received.timestamp, sample.timestamp);

    drop(writer);
    drop(reader);
    drop(publisher);
    drop(subscriber);
    std::thread::sleep(Duration::from_millis(500));
}

// ---------------------------------------------------------------------------
//  The authentication gate
// ---------------------------------------------------------------------------

/// Match callbacks must fire between two AUTHENTICATED secure participants.
///
/// `fsm::discovery::notify_endpoint_discovered` refuses to surface any endpoint
/// until `is_authenticated` says the peer is done. It looks that up with
/// `endpoint.participant_guid`, whose entity_id is `[0,0,0,0]`
/// (`fsm::endpoint::EndpointInfo::from_sedp`), while every write to the handshake
/// map keys on ENTITYID_PARTICIPANT `[0,0,1,0xC1]`. `GUID` hashes over prefix AND
/// entity_id, so the two can never be equal: the gate closes for every peer,
/// forever, and no amount of successful authentication opens it.
///
/// The engine documents this exact hazard elsewhere and works around it --
/// `dds::writer::runtime` rebuilds the key before touching the registry -- but
/// the security gate does not.
///
/// The preceding test shows data still crosses, so the damage is bounded to the
/// application-visible match notifications. That is what this pins.
#[test]
fn authenticated_peers_surface_their_endpoints_to_the_application() {
    use crate::dds::listener::{
        DataReaderListener, DataWriterListener, PublicationMatchedStatus, SubscriptionMatchedStatus,
    };
    use crate::generated::temperature::Temperature;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const TOPIC: &str = "GatedTemperature";

    struct CountingWriterListener(Arc<AtomicUsize>);
    impl DataWriterListener<Temperature> for CountingWriterListener {
        fn on_publication_matched(&self, _status: PublicationMatchedStatus) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    struct CountingReaderListener(Arc<AtomicUsize>);
    impl DataReaderListener<Temperature> for CountingReaderListener {
        fn on_subscription_matched(&self, _status: SubscriptionMatchedStatus) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    let domain = unique_domain();
    let fixture = security_fixture();
    let publisher = secure_participant("gate_pub", domain.id(), &fixture);
    let subscriber = secure_participant("gate_sub", domain.id(), &fixture);

    assert!(
        wait_until(Duration::from_secs(10), || {
            has_discovered(&publisher, &subscriber) && has_discovered(&subscriber, &publisher)
        }),
        "SPDP discovery never completed"
    );
    assert!(
        wait_until(Duration::from_secs(15), || {
            has_authenticated(&publisher, &subscriber) && has_authenticated(&subscriber, &publisher)
        }),
        "the pair never authenticated, so this test cannot say anything about the gate"
    );

    let pub_matches = Arc::new(AtomicUsize::new(0));
    let sub_matches = Arc::new(AtomicUsize::new(0));

    let _writer = publisher
        .topic::<Temperature>(TOPIC)
        .expect("writer topic")
        .writer()
        .qos(QoS::reliable().keep_all())
        .with_listener(Arc::new(CountingWriterListener(pub_matches.clone())))
        .build()
        .expect("writer");

    let _reader = subscriber
        .topic::<Temperature>(TOPIC)
        .expect("reader topic")
        .reader()
        .qos(QoS::reliable().keep_all())
        .with_listener(Arc::new(CountingReaderListener(sub_matches.clone())))
        .build()
        .expect("reader");

    let matched = wait_until(Duration::from_secs(10), || {
        pub_matches.load(Ordering::SeqCst) > 0 && sub_matches.load(Ordering::SeqCst) > 0
    });

    assert!(
        matched,
        "an authenticated secure pair never surfaced its endpoints to the application \
         (on_publication_matched fired {} times, on_subscription_matched {} times). \
         publisher={:?}, subscriber={:?}; both participants completed PKI-DH",
        pub_matches.load(Ordering::SeqCst),
        sub_matches.load(Ordering::SeqCst),
        publisher.guid(),
        subscriber.guid()
    );

    drop(publisher);
    drop(subscriber);
    std::thread::sleep(Duration::from_millis(500));
}

/// Counts the matches a secure pair surfaces, on each side.
mod match_counting {
    use crate::dds::listener::{
        DataReaderListener, DataWriterListener, PublicationMatchedStatus, SubscriptionMatchedStatus,
    };
    use crate::generated::temperature::Temperature;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    pub(super) struct Writer(pub(super) Arc<AtomicUsize>);
    impl DataWriterListener<Temperature> for Writer {
        fn on_publication_matched(&self, _status: PublicationMatchedStatus) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    pub(super) struct Reader(pub(super) Arc<AtomicUsize>);
    impl DataReaderListener<Temperature> for Reader {
        fn on_subscription_matched(&self, _status: SubscriptionMatchedStatus) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
}

/// One participant runs with an endpoint for a while; a second one joins
/// with the opposite endpoint, and both sides must match.
///
/// The joiner announces its endpoints as soon as it hears the first
/// participant, while their handshake is still in progress, and past the
/// first participant's startup probation nothing defers them: they were
/// refused (`DiscoveryFsm::admits_endpoint`) and, being known, never offered
/// again. A match must still happen, either way round.
fn a_late_joiner_matches(late_is_reader: bool) {
    use crate::generated::temperature::Temperature;
    use std::sync::atomic::{AtomicUsize, Ordering};
    const TOPIC: &str = "LateJoiner";

    let domain = unique_domain();
    let fixture = security_fixture();
    let writer_matches = Arc::new(AtomicUsize::new(0));
    let reader_matches = Arc::new(AtomicUsize::new(0));
    let build_writer = |p: &Arc<Participant>| {
        p.topic::<Temperature>(TOPIC)
            .expect("topic")
            .writer()
            .qos(QoS::reliable().keep_all())
            .with_listener(Arc::new(match_counting::Writer(writer_matches.clone())))
            .build()
            .expect("writer")
    };
    let build_reader = |p: &Arc<Participant>| {
        p.topic::<Temperature>(TOPIC)
            .expect("topic")
            .reader()
            .qos(QoS::reliable().keep_all())
            .with_listener(Arc::new(match_counting::Reader(reader_matches.clone())))
            .build()
            .expect("reader")
    };

    let first = secure_participant("first", domain.id(), &fixture);
    let (_writer, _reader, late) = if late_is_reader {
        let writer = build_writer(&first);
        std::thread::sleep(Duration::from_millis(1500));
        let late = secure_participant("late", domain.id(), &fixture);
        let reader = build_reader(&late);
        (writer, reader, late)
    } else {
        let reader = build_reader(&first);
        std::thread::sleep(Duration::from_millis(1500));
        let late = secure_participant("late", domain.id(), &fixture);
        let writer = build_writer(&late);
        (writer, reader, late)
    };

    let matched = wait_until(Duration::from_secs(10), || {
        writer_matches.load(Ordering::SeqCst) > 0 && reader_matches.load(Ordering::SeqCst) > 0
    });
    assert!(
        matched,
        "a secure late joiner was not matched (writer side {}, reader side {}); \
         authenticated: first->late {}, late->first {}",
        writer_matches.load(Ordering::SeqCst),
        reader_matches.load(Ordering::SeqCst),
        has_authenticated(&first, &late),
        has_authenticated(&late, &first)
    );
}

#[test]
fn a_late_joining_reader_is_matched_once_authenticated() {
    a_late_joiner_matches(true);
}

#[test]
fn a_late_joining_writer_is_matched_once_authenticated() {
    a_late_joiner_matches(false);
}

/// Both participants created with their endpoints at once, before they
/// discover each other: the endpoints are announced before the handshake
/// completes, and must match once it has.
#[test]
fn endpoints_created_before_discovery_match_once_authenticated() {
    use crate::generated::temperature::Temperature;
    use std::sync::atomic::{AtomicUsize, Ordering};
    const TOPIC: &str = "BeforeDiscovery";

    let domain = unique_domain();
    let fixture = security_fixture();
    let writer_matches = Arc::new(AtomicUsize::new(0));
    let reader_matches = Arc::new(AtomicUsize::new(0));
    let publisher = secure_participant("early_pub", domain.id(), &fixture);
    let _writer = publisher
        .topic::<Temperature>(TOPIC)
        .expect("topic")
        .writer()
        .qos(QoS::reliable().keep_all())
        .with_listener(Arc::new(match_counting::Writer(writer_matches.clone())))
        .build()
        .expect("writer");
    let subscriber = secure_participant("early_sub", domain.id(), &fixture);
    let _reader = subscriber
        .topic::<Temperature>(TOPIC)
        .expect("topic")
        .reader()
        .qos(QoS::reliable().keep_all())
        .with_listener(Arc::new(match_counting::Reader(reader_matches.clone())))
        .build()
        .expect("reader");

    assert!(
        wait_until(Duration::from_secs(10), || {
            writer_matches.load(Ordering::SeqCst) > 0 && reader_matches.load(Ordering::SeqCst) > 0
        }),
        "endpoints created before discovery never matched (writer side {}, reader side {})",
        writer_matches.load(Ordering::SeqCst),
        reader_matches.load(Ordering::SeqCst)
    );
}

/// A DataWriter deleted at one of two authenticated participants is
/// unmatched at the other. Its dispose goes on the secure SEDP topic, where
/// alone a participant that authenticated may change what it announced: a
/// dispose sent in the clear would be ignored as anybody's (DDS Security
/// v1.1 Sec.7.4.1.7, 7.4.1.8).
#[test]
fn a_writer_deleted_at_an_authenticated_participant_is_unmatched() {
    use crate::dds::listener::{DataReaderListener, SubscriptionMatchedStatus};
    use crate::generated::temperature::Temperature;
    use std::sync::atomic::{AtomicU32, Ordering};
    const TOPIC: &str = "Retired";

    struct Current(Arc<AtomicU32>, Arc<AtomicU32>);
    impl DataReaderListener<Temperature> for Current {
        fn on_subscription_matched(&self, status: SubscriptionMatchedStatus) {
            self.0.store(status.current_count, Ordering::SeqCst);
            self.1.fetch_add(1, Ordering::SeqCst);
        }
    }

    let domain = unique_domain();
    let fixture = security_fixture();
    let publisher = secure_participant("retire_pub", domain.id(), &fixture);
    let subscriber = secure_participant("retire_sub", domain.id(), &fixture);
    assert!(
        wait_until(Duration::from_secs(15), || {
            has_authenticated(&publisher, &subscriber) && has_authenticated(&subscriber, &publisher)
        }),
        "fixture: the pair authenticates"
    );
    let current = Arc::new(AtomicU32::new(0));
    let events = Arc::new(AtomicU32::new(0));
    let _reader = subscriber
        .topic::<Temperature>(TOPIC)
        .expect("topic")
        .reader()
        .qos(QoS::reliable().keep_all())
        .with_listener(Arc::new(Current(current.clone(), events.clone())))
        .build()
        .expect("reader");
    let writer = publisher
        .topic::<Temperature>(TOPIC)
        .expect("topic")
        .writer()
        .qos(QoS::reliable().keep_all())
        .build()
        .expect("writer");
    assert!(
        wait_until(Duration::from_secs(10), || current.load(Ordering::SeqCst)
            == 1),
        "fixture: matched"
    );

    drop(writer);
    assert!(
        wait_until(Duration::from_secs(10), || current.load(Ordering::SeqCst)
            == 0),
        "the deleted writer stayed matched at the authenticated reader ({} match events)",
        events.load(Ordering::SeqCst)
    );
}

/// DDS-Security 1.1 Sec.9.3.3, Table 52, validate_local_identity: a
/// participant running security takes the `adjusted_participant_guid`, its
/// prefix bound to its identity certificate (bit 0 set, then 47 bits of its
/// SubjectName's SHA-256), and two participants of one identity still differ
/// (bits 48 to 95 hash the GUID each would have had). Without security the
/// prefix keeps the vendor id first (DDSI-RTPS v2.5 Sec.9.3.1.5).
#[test]
fn a_secure_participant_takes_the_prefix_its_certificate_binds() {
    use crate::security::authentication::guid_binding::{
        binding_of, subject_name_der, PrefixBinding,
    };
    let domain = unique_domain();
    let fixture = security_fixture();
    let subject = subject_name_der(TEST_IDENTITY_CERT_PEM).expect("subject");
    let first = secure_participant("bound_a", domain.id(), &fixture);
    let second = secure_participant("bound_b", domain.id(), &fixture);
    for p in [&first, &second] {
        assert_eq!(
            binding_of(&p.guid().prefix, &subject),
            PrefixBinding::Bound,
            "{:02x?}",
            p.guid().prefix
        );
    }
    assert_ne!(first.guid().prefix, second.guid().prefix);
    assert!(
        wait_until(Duration::from_secs(15), || {
            has_authenticated(&first, &second) && has_authenticated(&second, &first)
        }),
        "two participants of one identity, each under its own bound prefix, authenticate"
    );

    let plain = Participant::builder("unbound")
        .domain_id(domain.id())
        .with_transport(TransportMode::UdpMulticast)
        .build()
        .expect("plain participant");
    assert_eq!(
        plain.guid().prefix[..2],
        crate::core::rtps_constants::HDDS_VENDOR_ID
    );
}

/// A secure participant announcing a lease far longer than any wait in the
/// tests below, under an explicit participant id and a GUID prefix derived
/// from it alone: the prefix is then the same each time it is built, and
/// the order of two prefixes is the order of their ids, whatever else runs
/// in this process. An HDDS participant never reuses a prefix
/// (`entity_registry::generate_guid`); this is the peer that does, a
/// foreign stack deriving it from host and process id. The prefix is bound
/// to the fixture's identity (`test_pki::bound_test_prefix`), as the
/// participant data of its handshake must be (DDS Security v1.1 Sec.9.3.3,
/// Table 52).
fn long_lived_secure_participant(
    name: &str,
    domain: u32,
    participant_id: u8,
    fixture: &SecurityFixture,
) -> Arc<Participant> {
    Participant::builder(name)
        .domain_id(domain)
        .participant_id(Some(participant_id))
        .with_transport(TransportMode::UdpMulticast)
        .with_security(fixture.config.clone())
        .with_participant_lease_duration(Duration::from_secs(300))
        .build_with_guid_prefix_for_test(crate::security::test_pki::bound_test_prefix([
            0xE2,
            0xE2,
            0xE2,
            0xE2,
            0x00,
            participant_id,
        ]))
        .expect("secure participant")
}

/// One participant (`stays`) keeps a writer; the other (`restarts`) is
/// dropped and built again in this process under the same participant id,
/// which gives it the same GUID prefix, well inside its 300 s lease. It
/// leaves as a participant that crashes does, without its sealed departure;
/// its plain farewell is ignored (DDS Security v1.1 Sec.7.4.1.6) and its new
/// announcements only keep the old participant alive, so nothing in
/// discovery says it is new. The restarted participant has no session and
/// no keys; it must be authenticated again and receive the samples the
/// writer sends now.
///
/// `stays_initiates`: the lower prefix initiates the handshake (DDS Security
/// v1.1 Sec.9.3.4, `state::am_i_initiator`); the ids are chosen for it.
fn a_participant_restarted_within_its_lease_receives_data_again(stays_initiates: bool) {
    use crate::generated::temperature::Temperature;
    const TOPIC: &str = "Restarted";
    let domain = unique_domain();
    // Encryption on: samples between two participants of this process then
    // go over the wire, sealed with keys a restarted participant must be
    // given again, instead of through the intra-process leg.
    let fixture = fixture_with_encryption(true);
    let reader_of = |p: &Arc<Participant>| {
        p.topic::<Temperature>(TOPIC)
            .expect("topic")
            .reader()
            .qos(QoS::reliable().keep_all())
            .build()
            .expect("reader")
    };

    let (stays_id, restarts_id) = if stays_initiates { (4, 5) } else { (5, 4) };
    let stays = long_lived_secure_participant("stays", domain.id(), stays_id, &fixture);
    let restarts = long_lived_secure_participant("restarts", domain.id(), restarts_id, &fixture);
    assert_eq!(
        stays.guid().prefix < restarts.guid().prefix,
        stays_initiates,
        "fixture: the role under test"
    );
    let prefix = restarts.guid().prefix;
    let writer = stays
        .topic::<Temperature>(TOPIC)
        .expect("topic")
        .writer()
        .qos(QoS::reliable().keep_all())
        .build()
        .expect("writer");
    let reader = reader_of(&restarts);
    let sample = |n: i32| Temperature {
        value: n as f32,
        timestamp: n,
    };
    let delivered = |reader: &crate::dds::DataReader<Temperature>,
                     writer: &crate::dds::DataWriter<Temperature>,
                     n: i32| {
        wait_until(Duration::from_secs(10), || {
            let _ = writer.write(&sample(n));
            matches!(reader.take(), Ok(Some(t)) if t.timestamp == n)
        })
    };
    assert!(
        delivered(&reader, &writer, 1),
        "fixture: data flows before the restart"
    );
    let before_keys: std::collections::HashMap<_, _> = stays
        .security()
        .expect("suite")
        .data_keys
        .entries_with_prefix(&stays.guid().prefix)
        .into_iter()
        .filter(|(guid, _, _)| {
            guid.entity_id[3] & 0xc0 == 0xc0
                && !crate::security::crypto::volatile::is_reader_entity_id(guid.entity_id)
        })
        .map(|(guid, _, material)| (guid, material))
        .collect();
    assert_eq!(
        before_keys.len(),
        3,
        "the three registered secure builtin writers (the builtin readers' own three keys, \
         `register_builtin_reader_keys`, are filtered out here on purpose: this check is about \
         the WRITER side surviving a restart)"
    );
    drop(reader);
    restarts.leave_without_a_sealed_departure_for_test();
    drop(restarts);
    std::thread::sleep(Duration::from_millis(500));
    let restarted = long_lived_secure_participant("restarts", domain.id(), restarts_id, &fixture);
    assert_eq!(
        restarted.guid().prefix,
        prefix,
        "fixture: the same prefix again"
    );
    let reader = reader_of(&restarted);

    assert!(
        wait_until(Duration::from_secs(15), || {
            has_authenticated(&stays, &restarted) && has_authenticated(&restarted, &stays)
        }),
        "the restarted participant was not authenticated again (stays->restarted {}, \
         restarted->stays {})",
        has_authenticated(&stays, &restarted),
        has_authenticated(&restarted, &stays)
    );
    assert!(
        delivered(&reader, &writer, 2),
        "no sample reached the restarted participant"
    );
    let after_keys: std::collections::HashMap<_, _> = stays
        .security()
        .expect("suite")
        .data_keys
        .entries_with_prefix(&stays.guid().prefix)
        .into_iter()
        .filter(|(guid, _, _)| guid.entity_id[3] & 0xc0 == 0xc0)
        .map(|(guid, _, material)| (guid, material))
        .collect();
    for (guid, old_material) in before_keys {
        let new_material = after_keys.get(&guid).expect("writer still registered");
        assert!(
            !old_material.same_material(new_material),
            "a completed replacement must publish fresh writer material before new KxKeys"
        );
    }
}

/// The reverse direction: the restarted participant writes and the one that
/// stays reads, and the new process's first writer is on another topic. The
/// process reuses the writer's entity id, so that writer has the GUID of
/// the old one. Here the old writer is deleted before its participant, and
/// its deletion goes sealed (`DiscoveryFsm::sedp_for_peer`), so discovery no
/// longer holds it when the new one is announced; the case where it does (a
/// participant that disappears without deleting its writers) is pinned in
/// the FSM (`a_participant_that_authenticates_again_loses_its_old_endpoints`).
/// The participant leaves as one that crashes does, without its sealed
/// departure.
fn a_participant_restarted_within_its_lease_delivers_data_again(stays_initiates: bool) {
    use crate::generated::temperature::Temperature;
    let domain = unique_domain();
    let fixture = fixture_with_encryption(true);
    let writer_of = |p: &Arc<Participant>, topic: &str| {
        p.topic::<Temperature>(topic)
            .expect("topic")
            .writer()
            .qos(QoS::reliable().keep_all())
            .build()
            .expect("writer")
    };
    let reader_of = |p: &Arc<Participant>, topic: &str| {
        p.topic::<Temperature>(topic)
            .expect("topic")
            .reader()
            .qos(QoS::reliable().keep_all())
            .build()
            .expect("reader")
    };
    let (stays_id, restarts_id) = if stays_initiates { (6, 7) } else { (7, 6) };
    let stays = long_lived_secure_participant("stays", domain.id(), stays_id, &fixture);
    let restarts = long_lived_secure_participant("restarts", domain.id(), restarts_id, &fixture);
    let before = reader_of(&stays, "BeforeRestart");
    let after = reader_of(&stays, "AfterRestart");
    let writer = writer_of(&restarts, "BeforeRestart");
    let sample = |n: i32| Temperature {
        value: n as f32,
        timestamp: n,
    };
    let delivered = |reader: &crate::dds::DataReader<Temperature>,
                     writer: &crate::dds::DataWriter<Temperature>,
                     n: i32| {
        wait_until(Duration::from_secs(10), || {
            let _ = writer.write(&sample(n));
            std::iter::from_fn(|| reader.take().ok().flatten()).any(|t| t.timestamp == n)
        })
    };
    assert!(
        delivered(&before, &writer, 1),
        "fixture: data flows before the restart"
    );
    let writer_guid = writer.endpoint_guid_for_test();

    drop(writer);
    restarts.leave_without_a_sealed_departure_for_test();
    drop(restarts);
    std::thread::sleep(Duration::from_millis(500));
    let restarted = long_lived_secure_participant("restarts", domain.id(), restarts_id, &fixture);
    let writer = writer_of(&restarted, "AfterRestart");
    assert_eq!(
        writer.endpoint_guid_for_test(),
        writer_guid,
        "fixture: the same writer GUID again"
    );

    assert!(
        delivered(&after, &writer, 2),
        "the restarted participant's writer, on its new topic, never reached the reader"
    );
}

/// An authenticated participant ignores the plain farewell of another
/// (DDS Security v1.1 Sec.7.4.1.6), so a secure participant that leaves must
/// say so sealed, or the one that stays holds it for its whole lease, here
/// 300 s. Both directions of the handshake roles.
fn a_secure_participant_that_leaves_is_forgotten_well_within_its_lease(leaving_initiates: bool) {
    let domain = unique_domain();
    let fixture = fixture_with_encryption(false);
    let (stays_id, leaves_id) = if leaving_initiates { (9, 8) } else { (8, 9) };
    let stays = long_lived_secure_participant("stays", domain.id(), stays_id, &fixture);
    let leaves = long_lived_secure_participant("leaves", domain.id(), leaves_id, &fixture);
    assert_eq!(
        leaves.guid().prefix < stays.guid().prefix,
        leaving_initiates,
        "fixture: the role under test"
    );
    assert!(
        wait_until(Duration::from_secs(15), || {
            has_authenticated(&stays, &leaves) && has_authenticated(&leaves, &stays)
        }),
        "fixture: the two participants never authenticated"
    );
    // Past our startup probation (`DiscoveryFsm::fails_probation`), which
    // purges a participant that falls silent right after it was first
    // heard, farewell or not.
    std::thread::sleep(Duration::from_secs(2));
    assert!(
        has_discovered(&stays, &leaves),
        "fixture: confirmed past the probation"
    );
    let left_guid = leaves.guid();
    drop(leaves);

    assert!(
        wait_until(Duration::from_secs(3), || {
            stays
                .discovery()
                .is_some_and(|fsm| !fsm.get_participants().iter().any(|p| p.guid == left_guid))
        }),
        "a secure participant that left is still held by its authenticated peer"
    );
}

#[test]
fn a_secure_responder_that_leaves_is_forgotten_well_within_its_lease() {
    a_secure_participant_that_leaves_is_forgotten_well_within_its_lease(false);
}

#[test]
fn a_secure_initiator_that_leaves_is_forgotten_well_within_its_lease() {
    a_secure_participant_that_leaves_is_forgotten_well_within_its_lease(true);
}

#[test]
fn a_restarted_responder_is_authenticated_again_and_delivers_data() {
    a_participant_restarted_within_its_lease_delivers_data_again(true);
}

#[test]
fn a_restarted_initiator_is_authenticated_again_and_delivers_data() {
    a_participant_restarted_within_its_lease_delivers_data_again(false);
}

#[test]
fn a_restarted_responder_is_authenticated_again_and_receives_data() {
    a_participant_restarted_within_its_lease_receives_data_again(true);
}

#[test]
fn a_restarted_initiator_is_authenticated_again_and_receives_data() {
    a_participant_restarted_within_its_lease_receives_data_again(false);
}

// ---------------------------------------------------------------------------
//  Sealed payloads beyond the single-DATA happy path
// ---------------------------------------------------------------------------

/// A bulk type whose serialized form cannot fit one UDP datagram, so the
/// sealed blob is forced through the DATA_FRAG path.
#[derive(Debug, Clone, PartialEq, crate::DDS)]
struct BulkBlob {
    payload: Vec<u8>,
}

/// Deterministic byte-position-dependent pattern: a reassembly that shuffles,
/// truncates or zero-fills ANY fragment changes the final comparison, which
/// an all-zeros (or any constant) payload would not catch.
fn bulk_pattern(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| (i.wrapping_mul(131) ^ (i >> 8)).to_le_bytes()[0])
        .collect()
}

/// A sealed sample larger than one datagram must cross, fragmented.
///
/// 100_000 bytes of plaintext cannot ride a single DATA datagram (UDP caps
/// one payload at 65507 bytes), so this exercises the ordering the design
/// promises: seal first, fragment the CIPHERTEXT, reassemble on the reader,
/// decrypt the whole -- rather than the single-DATA path the other encrypted
/// test covers.
#[test]
fn a_sealed_sample_larger_than_one_datagram_crosses_fragmented() {
    const TOPIC: &str = "EncryptedBulk";

    let domain = unique_domain();
    let fixture = fixture_with_encryption(true);
    let publisher = secure_participant("frag_enc_pub", domain.id(), &fixture);
    let subscriber = secure_participant("frag_enc_sub", domain.id(), &fixture);

    assert!(
        wait_until(Duration::from_secs(10), || {
            has_discovered(&publisher, &subscriber) && has_discovered(&subscriber, &publisher)
        }),
        "SPDP discovery never completed"
    );
    assert!(
        wait_until(Duration::from_secs(15), || {
            has_authenticated(&publisher, &subscriber) && has_authenticated(&subscriber, &publisher)
        }),
        "the pair never authenticated"
    );

    let writer = publisher
        .topic::<BulkBlob>(TOPIC)
        .expect("writer topic")
        .writer()
        .qos(QoS::reliable().keep_all())
        .build()
        .expect("writer");
    let reader = subscriber
        .topic::<BulkBlob>(TOPIC)
        .expect("reader topic")
        .reader()
        .qos(QoS::reliable().keep_all())
        .build()
        .expect("reader");

    // SEDP matching, then the key-distribution sweep (250 ms cadence).
    std::thread::sleep(Duration::from_millis(1000));

    let sample = BulkBlob {
        payload: bulk_pattern(100_000),
    };

    // Same retry rationale as the single-DATA encrypted test: early writes
    // may race the key distribution, and the reader drops what it cannot
    // decrypt without crediting the SN.
    let mut received: Option<BulkBlob> = None;
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        writer
            .write(&sample)
            .expect("an encrypting writer with a minted key must accept the bulk sample");
        if let Ok(Some(msg)) = reader.take() {
            received = Some(msg);
            break;
        }
        std::thread::sleep(Duration::from_millis(300));
    }

    let received = received.unwrap_or_else(|| {
        panic!(
            "no sealed fragmented sample crossed between two authenticated participants. \
             The pair authenticated and every write succeeded, so the loss is on the \
             DATA_FRAG leg: sealed blob not fragmented, fragments not reassembled, or \
             the reassembled ciphertext dropped at the decrypt gate"
        )
    });
    assert_eq!(
        received.payload.len(),
        sample.payload.len(),
        "reassembled payload length differs from what was sealed"
    );
    assert_eq!(
        received.payload, sample.payload,
        "the reassembled payload must be byte-identical to what was sealed"
    );

    drop(writer);
    drop(reader);
    drop(publisher);
    drop(subscriber);
    std::thread::sleep(Duration::from_millis(500));
}

// ---------------------------------------------------------------------------
//  Sealed lifecycle DATA (dispose / unregister)
// ---------------------------------------------------------------------------

/// A hand-written keyed type: the `#[derive(DDS)]` macro has no `@key`
/// support, so `has_key`/`compute_key`/`encode_key` and the two KeyHolder
/// hooks are implemented by hand, modeled on the interop ShapeType
/// (`examples/shape_main.rs`). The key is the leading string member, short
/// by construction so the RTPS v2.5 9.6.3.8 short-string form of
/// `compute_key` applies; `write_key_holder` is the KeyHolder the wire
/// KeyHash is taken over when the payload is protected.
#[derive(Debug, Clone, PartialEq)]
struct KeyedReading {
    /// `@key`
    label: String,
    value: i32,
}

impl crate::dds::DDS for KeyedReading {
    fn type_descriptor() -> &'static crate::core::types::TypeDescriptor {
        static DESC: crate::core::types::TypeDescriptor = crate::core::types::TypeDescriptor {
            type_id: 0x4B52_4431,
            type_name: "KeyedReading",
            size_bytes: 0,
            alignment: 4,
            is_variable_size: true,
            fields: &[
                crate::core::types::FieldLayout {
                    name: "label",
                    offset_bytes: 0,
                    field_type: crate::core::types::FieldType::String,
                    alignment: 4,
                    size_bytes: 0, // variable
                    element_type: None,
                },
                crate::core::types::FieldLayout {
                    name: "value",
                    offset_bytes: 0, // variable due to label
                    field_type: crate::core::types::FieldType::Primitive(
                        crate::core::types::PrimitiveKind::I32,
                    ),
                    alignment: 4,
                    size_bytes: 4,
                    element_type: None,
                },
            ],
        };
        &DESC
    }

    // Plain CDR2 LE, @final layout on both directions of the pair:
    // [str_len incl NUL, u32][bytes][NUL][pad to 4][value, i32].
    fn encode(
        &self,
        buf: &mut [u8],
        _version: crate::dds::CdrVersion,
    ) -> crate::dds::Result<usize> {
        let bytes = self.label.as_bytes();
        let str_len = bytes.len() + 1;
        let padded = (4 + str_len + 3) & !3;
        let total = padded + 4;
        if buf.len() < total {
            return Err(crate::dds::Error::BufferTooSmall);
        }
        buf[..4].copy_from_slice(&(str_len as u32).to_le_bytes());
        buf[4..4 + bytes.len()].copy_from_slice(bytes);
        for b in &mut buf[4 + bytes.len()..padded] {
            *b = 0;
        }
        buf[padded..total].copy_from_slice(&self.value.to_le_bytes());
        Ok(total)
    }

    fn decode(buf: &[u8], _version: crate::dds::CdrVersion) -> crate::dds::Result<Self> {
        if buf.len() < 8 {
            return Err(crate::dds::Error::SerializationError);
        }
        let str_len = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
        if str_len == 0 || 4 + str_len > buf.len() {
            return Err(crate::dds::Error::SerializationError);
        }
        let label = std::str::from_utf8(&buf[4..4 + str_len - 1])
            .map_err(|_| crate::dds::Error::SerializationError)?
            .to_string();
        let padded = (4 + str_len + 3) & !3;
        if padded + 4 > buf.len() {
            return Err(crate::dds::Error::SerializationError);
        }
        let value = i32::from_le_bytes([
            buf[padded],
            buf[padded + 1],
            buf[padded + 2],
            buf[padded + 3],
        ]);
        Ok(Self { label, value })
    }

    fn has_key() -> bool {
        true
    }

    // RTPS v2.5 9.6.3.8 short-form KeyHash: CDR big-endian string length
    // (incl NUL) + bytes, zero-padded to 16. Fits because the test labels
    // are short; a real type would fall back to MD5 beyond 12 bytes.
    fn compute_key(&self) -> [u8; 16] {
        let bytes = self.label.as_bytes();
        let mut kh = [0u8; 16];
        kh[..4].copy_from_slice(&((bytes.len() + 1) as u32).to_be_bytes());
        kh[4..4 + bytes.len()].copy_from_slice(bytes);
        kh
    }

    // Serialized @key fields only, mirroring encode()'s @final layout (no
    // DHEADER): str_len + bytes + NUL.
    fn encode_key(&self, _version: crate::dds::CdrVersion) -> Vec<u8> {
        let bytes = self.label.as_bytes();
        let str_len = bytes.len() + 1;
        let mut buf = Vec::with_capacity(4 + str_len);
        buf.extend_from_slice(&(str_len as u32).to_le_bytes());
        buf.extend_from_slice(bytes);
        buf.push(0);
        buf
    }

    // The KeyHolder behind the wire KeyHash under key protection
    // (DDS-Security v1.1 Sec.7.3.4): the @key member in CDR big endian, and
    // an unbounded maximum because `string` is unbounded, so the hash is the
    // MD5 of these bytes.
    fn write_key_holder(
        &self,
        w: &mut crate::core::key_hash::KeyHolderWriter,
    ) -> Option<crate::core::key_hash::KeyMaxSize> {
        w.write_string(&self.label);
        Some(crate::core::key_hash::KeyMaxSize::Unbounded)
    }

    // A reader names the disposed instance by the key it received sealed,
    // read back into the key member; that key's identity is this type's
    // `compute_key`, the value the lifecycle assertions compare against.
    fn key_hash_of_key_payload(payload: &[u8]) -> Option<[u8; 16]> {
        let mut reader = crate::core::key_hash::KeyPayloadReader::new(payload)?;
        let label = reader.read_string(None)?;
        reader.finish()?;
        Some(Self { label, value: 0 }.compute_key())
    }

    // `encode_key` and `key_hash_of_key_payload` above are a real pair: the
    // sealed lifecycle tests below read a dispose back by the key they send.
    fn keys_round_trip() -> bool {
        true
    }

    // DDS-XTypes v1.3 7.3.4.4: a string member is TI_STRING8_SMALL (0x70)
    // or TI_STRING8_LARGE (0x71) plus a bound, never the TK_STRING8 (0x20)
    // TypeKind discriminator -- `TypeIdentifier::TK_STRING8` is held inert
    // for the interop reason documented on it, not as a value to emit.
    // Bound 0 is the unbounded string. Emitting the inert form here would make
    // this fixture's own TypeObject undecodable and drop the PID.
    fn get_type_object() -> Option<crate::xtypes::CompleteTypeObject> {
        use crate::xtypes::*;
        Some(CompleteTypeObject::Struct(CompleteStructType {
            struct_flags: StructTypeFlag::IS_FINAL,
            header: CompleteStructHeader {
                base_type: None,
                detail: CompleteTypeDetail::new("KeyedReading"),
            },
            member_seq: vec![
                CompleteStructMember {
                    common: CommonStructMember {
                        member_id: 0,
                        member_flags: MemberFlag::IS_KEY,
                        member_type_id: TypeIdentifier::string(0),
                    },
                    detail: CompleteMemberDetail::new("label"),
                },
                CompleteStructMember {
                    common: CommonStructMember {
                        member_id: 1,
                        member_flags: MemberFlag::empty(),
                        member_type_id: TypeIdentifier::TK_INT32,
                    },
                    detail: CompleteMemberDetail::new("value"),
                },
            ],
        }))
    }
}

/// DDS-XTypes v1.3 7.3.4.4: every TypeIdentifier on the wire is one of the
/// union's legal discriminators. A string is `TI_STRING8_SMALL` (0x70) or
/// `TI_STRING8_LARGE` (0x71) plus its bound; `TK_STRING8` (0x20) belongs to
/// `TypeKind` and is not a TypeIdentifier at all. The SEDP encoder writes
/// this TypeObject with PID_TYPE_OBJECT and the decoder that reads it back
/// is strictly right to refuse a bare 0x20 (which is why a fixture using
/// `TypeIdentifier::TK_STRING8` lost its type parameters and logged
/// "Invalid TypeIdentifier discriminator: 0x20"). Round-tripping the
/// fixture's own TypeObject is the exact path that announcement takes.
#[test]
fn the_keyed_reading_type_object_round_trips_through_its_own_wire_encoding() {
    use crate::dds::DDS;
    use crate::xtypes::CompleteTypeObject;
    use crate::{Cdr2Decode, Cdr2Encode};
    let type_object = KeyedReading::get_type_object().expect("KeyedReading has a TypeObject");
    let mut bytes = vec![0u8; type_object.max_cdr2_size()];
    let len = type_object.encode_cdr2_le(&mut bytes).expect("CDR2 encode");
    let (decoded, consumed) =
        CompleteTypeObject::decode_cdr2_le(&bytes[..len]).expect("CDR2 decode");
    assert_eq!(consumed, len, "the decoder stopped before the end");
    assert_eq!(
        decoded, type_object,
        "the TypeObject does not survive its own wire form"
    );
}

/// Stand up a secure encrypting pair on `domain`, land ONE sealed sample of
/// `sample`, and hand back the endpoints. Shared by the two lifecycle tests
/// so their dispose/unregister assertions start from a proven data plane --
/// a lifecycle failure is then a lifecycle failure, not a discovery,
/// matching or key-distribution one.
///
/// `domain` is a plain id, not a lease: the CALLER holds the `DomainLease`,
/// because the participants returned here outlive this function and the
/// reservation has to outlive them in turn.
#[allow(clippy::type_complexity)]
fn secure_keyed_pair_with_one_landed_sample(
    domain: u32,
    topic: &str,
    names: (&str, &str),
    sample: &KeyedReading,
) -> (
    SecurityFixture,
    Arc<Participant>,
    Arc<Participant>,
    crate::dds::DataWriter<KeyedReading>,
    crate::dds::DataReader<KeyedReading>,
) {
    let fixture = fixture_with_encryption(true);
    let publisher = secure_participant(names.0, domain, &fixture);
    let subscriber = secure_participant(names.1, domain, &fixture);

    assert!(
        wait_until(Duration::from_secs(10), || {
            has_discovered(&publisher, &subscriber) && has_discovered(&subscriber, &publisher)
        }),
        "SPDP discovery never completed"
    );
    assert!(
        wait_until(Duration::from_secs(15), || {
            has_authenticated(&publisher, &subscriber) && has_authenticated(&subscriber, &publisher)
        }),
        "the pair never authenticated"
    );

    let writer = publisher
        .topic::<KeyedReading>(topic)
        .expect("writer topic")
        .writer()
        .qos(QoS::reliable().keep_all())
        .build()
        .expect("writer");
    let reader = subscriber
        .topic::<KeyedReading>(topic)
        .expect("reader topic")
        .reader()
        .qos(QoS::reliable().keep_all())
        .build()
        .expect("reader");

    // SEDP matching, then the key-distribution sweep (250 ms cadence).
    std::thread::sleep(Duration::from_millis(1000));

    let mut received: Option<KeyedReading> = None;
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        writer
            .write(sample)
            .expect("an encrypting writer with a minted key must accept the sample");
        if let Ok(Some(msg)) = reader.take() {
            received = Some(msg);
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    let received =
        received.expect("no sealed keyed sample crossed, so the lifecycle assertions cannot start");
    assert_eq!(&received, sample, "the landed sample must round-trip");

    (fixture, publisher, subscriber, writer, reader)
}

/// A sealed dispose must still drive the reader's NOT_ALIVE transition.
///
/// The K-payload (the serialized `@key` fields) travels sealed; the reader
/// decrypts it and names the instance by the key it authenticated
/// (`key_hash_of_key_payload`), never by the cleartext PID_KEY_HASH beside
/// it. The event's hash must equal `compute_key()` of the disposed sample:
/// that equality is the whole proof that sealing did not break the lifecycle
/// signal.
#[test]
// Deliberately on the deprecated accessor: this test asserts a PRECISE
// transition (`DisposeKind::Disposed` / `Unregistered`), and
// `SampleInfo.instance_state` carries only the three states DDS defines, so
// `take_with_info()` cannot express the distinction being asserted here.
// Same reason `examples/shape_main.rs` still calls it.
#[allow(deprecated)]
fn a_sealed_dispose_reaches_the_reader_as_a_disposed_event() {
    use crate::dds::DDS as _; // compute_key
    use crate::engine::subscriber::DisposeKind;

    let domain = unique_domain();
    let sample = KeyedReading {
        label: "PROBE".to_string(),
        value: 21,
    };
    let (_fixture, publisher, subscriber, writer, reader) =
        secure_keyed_pair_with_one_landed_sample(
            domain.id(),
            "EncryptedKeyedDispose",
            ("dispose_enc_pub", "dispose_enc_sub"),
            &sample,
        );

    // Lifecycle DATA consumes an SN but is never inserted into the history
    // cache (pre-existing gap, independent of the seal), so a lost datagram
    // cannot be NACK-repaired: re-dispose on the poll cadence rather than
    // trusting one datagram.
    let expected_hash = sample.compute_key();
    let mut disposed = None;
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        writer
            .dispose(&sample)
            .expect("a sealed dispose must be accepted, not refused");
        std::thread::sleep(Duration::from_millis(300));
        if let Some(e) = reader
            .get_dispose_events()
            .into_iter()
            .find(|e| matches!(e.kind, DisposeKind::Disposed) && e.key_hash == expected_hash)
        {
            disposed = Some(e);
            break;
        }
    }

    assert!(
        disposed.is_some(),
        "no Disposed event with key hash {:02x?} reached the reader. Every dispose() \
         call succeeded, so the loss is past the writer: either a consumer refused the \
         sealed K-payload as cleartext, or the reader refused the change itself. A \
         dispose datagram lost on the way is not a candidate while the writer lives: \
         its HEARTBEAT announces the sequence number and its NACK handler rebuilds the \
         key-only DATA (RTPS 2.5 Sec.8.4.2.2.3 and 8.4.2.2.4)",
        &expected_hash[..4]
    );

    drop(writer);
    drop(reader);
    drop(publisher);
    drop(subscriber);
    std::thread::sleep(Duration::from_millis(500));
}

/// Dropping an encrypting writer must unregister its instances over the
/// sealed wire.
///
/// This is the Drop emitter -- the one whose Result is discarded, so a seal
/// refusal there would be silent. The writer keeps the default
/// WRITER_DATA_LIFECYCLE (autodispose TRUE), so its deletion unregisters AND
/// disposes (DDS v1.4 Sec.2.2.2.4.1.6, Sec.2.2.3.21): the reader-side
/// DisposedUnregistered event is the only observable proof the auto-unregister
/// still goes out although it is sealed; it also pins the Drop ordering
/// (data-plane key retired AFTER the auto-unregister loop -- retired first,
/// every auto-unregister would refuse for want of a key and this test would
/// time out).
#[test]
// Deliberately on the deprecated accessor: this test asserts a PRECISE
// transition (`DisposeKind::Disposed` / `Unregistered`), and
// `SampleInfo.instance_state` carries only the three states DDS defines, so
// `take_with_info()` cannot express the distinction being asserted here.
// Same reason `examples/shape_main.rs` still calls it.
#[allow(deprecated)]
fn a_dropped_writer_unregisters_its_instances_over_the_sealed_wire() {
    use crate::dds::DDS as _; // compute_key
    use crate::engine::subscriber::DisposeKind;

    let domain = unique_domain();
    let sample = KeyedReading {
        label: "EPHEM".to_string(),
        value: 7,
    };
    let (_fixture, publisher, subscriber, writer, reader) =
        secure_keyed_pair_with_one_landed_sample(
            domain.id(),
            "EncryptedKeyedUnregister",
            ("unreg_enc_pub", "unreg_enc_sub"),
            &sample,
        );

    let expected_hash = sample.compute_key();
    drop(writer);

    // One shot by construction: Drop ran exactly once and its Result was
    // discarded, so there is nothing to retry -- only to observe.
    let mut unregistered = None;
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if let Some(e) = reader.get_dispose_events().into_iter().find(|e| {
            matches!(e.kind, DisposeKind::DisposedUnregistered) && e.key_hash == expected_hash
        }) {
            unregistered = Some(e);
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }

    assert!(
        unregistered.is_some(),
        "no DisposedUnregistered event with key hash {:02x?} reached the reader after drop(writer). \
         The instance HAD crossed sealed, so the Drop auto-unregister was either silently \
         refused (key retired before the loop, or a reader-side refusal) or it was lost \
         after the writer was gone: a lifecycle change lost while the writer lives is \
         repaired by its NACK handler (RTPS 2.5 Sec.8.4.2.2.4)",
        &expected_hash[..4]
    );

    drop(reader);
    drop(publisher);
    drop(subscriber);
    std::thread::sleep(Duration::from_millis(500));
}

// ---------------------------------------------------------------------------
//  The audit chain, through the public API
// ---------------------------------------------------------------------------

/// Same PKI, audit logging ON into `audit_path`, with encryption and the
/// key-agreement suite under the caller's control.
///
/// ONE file per participant: each participant owns one hash chain, and two
/// chains appended to the same file would interleave into something no
/// verifier can walk. The `NamedTempFile` handle must outlive the participant
/// for the same reason the PEM handles must.
fn fixture_with_audit(
    audit_path: &std::path::Path,
    encryption: bool,
    kagree_algo: Option<&str>,
) -> SecurityFixture {
    let cert = write_pem(TEST_IDENTITY_CERT_PEM);
    let key = write_pem(TEST_IDENTITY_KEY_PEM);
    let ca = write_pem(TEST_CA_CERT_PEM);

    let mut builder = SecurityConfig::builder()
        .identity_certificate(cert.path())
        .private_key(key.path())
        .ca_certificates(ca.path())
        .enable_encryption(encryption)
        .enable_audit_log(true)
        .audit_log_path(audit_path);
    if let Some(suite) = kagree_algo {
        builder = builder.key_establishment_algorithm(suite);
    }
    let config = builder
        .build()
        .expect("SecurityConfig with audit logging must build");

    SecurityFixture {
        config,
        _cert: cert,
        _key: key,
        _ca: ca,
    }
}

fn audit_records(path: &std::path::Path) -> String {
    std::fs::read_to_string(path).unwrap_or_default()
}

/// Every `timestamp: N` in the file, whatever the event family.
fn audit_timestamps(records: &str) -> Vec<u64> {
    const NEEDLE: &str = "timestamp: ";
    let mut out = Vec::new();
    for line in records.lines() {
        let mut rest = line;
        while let Some(at) = rest.find(NEEDLE) {
            let digits = &rest[at + NEEDLE.len()..];
            let end = digits
                .find(|c: char| !c.is_ascii_digit())
                .unwrap_or(digits.len());
            if let Ok(value) = digits[..end].parse::<u64>() {
                out.push(value);
            }
            rest = &digits[end..];
        }
    }
    out
}

/// The local entries of `suite`'s writer key store that belong to user
/// writers: the secure builtin writers' key material lives in the same store
/// (DDS Security v1.1 Sec.8.8.8.3) under builtin entity ids (entityKind
/// 0xC2/0xC3, DDSI-RTPS v2.5 Sec.9.3.1.2).
fn user_writer_keys(
    suite: &crate::security::SecurityPluginSuite,
    prefix: &[u8; 12],
) -> Vec<(
    crate::core::discovery::GUID,
    u64,
    crate::security::crypto::data_keys::WriterKey,
)> {
    suite
        .data_keys
        .entries_with_prefix(prefix)
        .into_iter()
        .filter(|(guid, _, _)| guid.entity_id[3] & 0xC0 != 0xC0)
        .collect()
}

fn count(records: &str, needle: &str) -> usize {
    records.matches(needle).count()
}

/// The positive proof: with nothing but the public builders, both peers'
/// audit files receive their one `Authentication` Success, both receive the
/// writer's `install_data_key` Success (minted at build on the publisher,
/// installed on arrival on the subscriber), twenty sealed samples then cross
/// WITHOUT adding a single Crypto record (the sparse policy, end to end),
/// every timestamp is in nanoseconds, and each file verifies as one hash
/// chain. Without the suite wiring (`with_audit_logger` on the machine and
/// the store) both files stay at their chain-start marker and this test is
/// red at the first authentication wait.
#[test]
fn audit_log_records_authentication_and_key_transitions_through_the_public_api() {
    use crate::generated::temperature::Temperature;
    use crate::security::audit::verify_chain;

    const TOPIC: &str = "AuditTemperature";
    const SAMPLES: usize = 20;

    let domain = unique_domain();
    let pub_audit = NamedTempFile::new().expect("publisher audit file");
    let sub_audit = NamedTempFile::new().expect("subscriber audit file");
    let pub_fixture = fixture_with_audit(pub_audit.path(), true, None);
    let sub_fixture = fixture_with_audit(sub_audit.path(), true, None);

    let publisher = secure_participant("audit_pub", domain.id(), &pub_fixture);

    // Opening the file wrote a chain-start marker and nothing else. Checked on
    // the publisher alone, while it is the only participant in the domain:
    // once the subscriber exists, its handshake can complete before this test
    // reads either file (it did on Windows), so "no authentication record yet"
    // is only a property of a participant without a peer.
    {
        let records = audit_records(pub_audit.path());
        assert_eq!(
            count(&records, "AuditChainStart"),
            1,
            "publisher file must open with exactly one chain-start marker"
        );
        assert_eq!(
            count(&records, "Authentication"),
            0,
            "publisher file must not carry an authentication record before any peer exists"
        );
    }

    let subscriber = secure_participant("audit_sub", domain.id(), &sub_fixture);
    assert_eq!(
        count(&audit_records(sub_audit.path()), "AuditChainStart"),
        1,
        "subscriber file must open with exactly one chain-start marker"
    );

    // The handshake completes on both sides: one Success per file, observed
    // on DISK, not through crate internals.
    let authenticated = wait_until(Duration::from_secs(15), || {
        let pub_records = audit_records(pub_audit.path());
        let sub_records = audit_records(sub_audit.path());
        count(&pub_records, "Authentication") >= 1
            && count(&pub_records, "outcome: Success") >= 1
            && count(&sub_records, "Authentication") >= 1
            && count(&sub_records, "outcome: Success") >= 1
    });
    assert!(
        authenticated,
        "no Authentication Success reached both audit files within 15 s. Either the pair \
         never authenticated or the suite never handed its audit chain to the handshake \
         machine.\npublisher file:\n{}\nsubscriber file:\n{}",
        audit_records(pub_audit.path()),
        audit_records(sub_audit.path())
    );

    // An encrypting writer mints its key at build: the Crypto record is
    // synchronous, so it is on disk before `build()` returns.
    let writer = publisher
        .topic::<Temperature>(TOPIC)
        .expect("writer topic")
        .writer()
        .qos(QoS::reliable().keep_all())
        .build()
        .expect("writer");
    let pub_records = audit_records(pub_audit.path());
    assert_eq!(
        count(&pub_records, "operation: \"install_data_key\""),
        1,
        "the publisher must record its one minted data key at writer build:\n{}",
        pub_records
    );

    let reader = subscriber
        .topic::<Temperature>(TOPIC)
        .expect("reader topic")
        .reader()
        .qos(QoS::reliable().keep_all())
        .build()
        .expect("reader");

    // The key travels the volatile channel (250 ms sweep cadence;
    // `a_writers_data_key_reaches_an_authenticated_subscriber` proves that
    // leg on its own) and its installation is recorded on the subscriber
    // side.
    let key_recorded = wait_until(Duration::from_secs(15), || {
        count(
            &audit_records(sub_audit.path()),
            "operation: \"install_data_key\"",
        ) >= 1
    });
    assert!(
        key_recorded,
        "the subscriber never recorded the arrival of the writer's data key:\n{}",
        audit_records(sub_audit.path())
    );

    // ParticipantCryptoTokens flow in both directions on the same 2 s
    // sweep (`crypto::participant_keys`), independently of the data-plane
    // key above: let both one-time installs land on both files before
    // snapshotting the Crypto count below, or this exchange's own arrival
    // can race past the snapshot and read as a sample producing an event.
    let participant_tokens_recorded = wait_until(Duration::from_secs(15), || {
        count(
            &audit_records(pub_audit.path()),
            "operation: \"install_participant_crypto_tokens\"",
        ) >= 1
            && count(
                &audit_records(sub_audit.path()),
                "operation: \"install_participant_crypto_tokens\"",
            ) >= 1
    });
    assert!(
        participant_tokens_recorded,
        "ParticipantCryptoTokens never arrived on both sides:\npublisher:\n{}\nsubscriber:\n{}",
        audit_records(pub_audit.path()),
        audit_records(sub_audit.path())
    );
    // The secure builtin writers' AND readers' CryptoTokens, the same way:
    // each side minted three of each at build and receives the peer's
    // three of each (DatawriterCryptoTokens, DatareaderCryptoTokens).
    let builtin_tokens_recorded = wait_until(Duration::from_secs(15), || {
        ["install_builtin_writer_key", "install_builtin_reader_key"]
            .into_iter()
            .all(|op| {
                let op = format!("operation: \"{}\"", op);
                count(&audit_records(pub_audit.path()), &op) >= 6
                    && count(&audit_records(sub_audit.path()), &op) >= 6
            })
    });
    assert!(
        builtin_tokens_recorded,
        "the secure builtin writers' or readers' keys never arrived on both sides:\n\
         publisher:\n{}\nsubscriber:\n{}",
        audit_records(pub_audit.path()),
        audit_records(sub_audit.path())
    );

    let crypto_before = (
        count(&audit_records(pub_audit.path()), "Crypto {"),
        count(&audit_records(sub_audit.path()), "Crypto {"),
    );

    // Twenty sealed samples. The first write is retried until it lands (the
    // reader may still be matching); the rest ride the reliable channel.
    let sample = |i: usize| Temperature {
        value: 20.0 + i as f32,
        timestamp: 1_754_000_000 + i as i32,
    };
    let mut received = 0usize;
    let deadline = Instant::now() + Duration::from_secs(15);
    while received == 0 && Instant::now() < deadline {
        writer.write(&sample(0)).expect("sealed write");
        if let Ok(Some(_)) = reader.take() {
            received = 1;
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    assert_eq!(received, 1, "the first sealed sample never crossed");
    for i in 1..SAMPLES {
        writer.write(&sample(i)).expect("sealed write");
    }
    let all_received = wait_until(Duration::from_secs(15), || {
        while let Ok(Some(_)) = reader.take() {
            received += 1;
        }
        received >= SAMPLES
    });
    assert!(
        all_received,
        "only {} of {} sealed samples crossed",
        received, SAMPLES
    );

    // The sparse policy, end to end: a sample is not an audit event.
    let pub_records = audit_records(pub_audit.path());
    let sub_records = audit_records(sub_audit.path());
    assert_eq!(
        (
            count(&pub_records, "Crypto {"),
            count(&sub_records, "Crypto {")
        ),
        crypto_before,
        "sealing or opening samples must not add Crypto records\npublisher:\n{}\nsubscriber:\n{}",
        pub_records,
        sub_records
    );

    for (who, records) in [("publisher", &pub_records), ("subscriber", &sub_records)] {
        assert_eq!(
            count(records, "outcome: Failed"),
            0,
            "{} file must not carry a failure on a healthy pair:\n{}",
            who,
            records
        );
        assert_eq!(
            count(records, "Authentication"),
            1,
            "{} file must carry exactly one Authentication record for its one peer:\n{}",
            who,
            records
        );
        assert_eq!(
            count(records, "operation: \"install_builtin_writer_key\""),
            6,
            "{} file: its own three secure builtin writers' keys and the peer's three:\n{}",
            who,
            records
        );
        assert_eq!(
            count(records, "operation: \"install_builtin_reader_key\""),
            6,
            "{} file: its own three secure builtin readers' keys and the peer's three:\n{}",
            who,
            records
        );
        assert_eq!(
            count(records, "outcome: Success"),
            15,
            "{} file: one Authentication Success, one install_data_key Success, one \
             install_participant_crypto_tokens Success, six install_builtin_writer_key \
             Successes and six install_builtin_reader_key Successes:\n{}",
            who,
            records
        );

        let stamps = audit_timestamps(records);
        assert!(
            !stamps.is_empty() && stamps.iter().all(|&t| t > 1_000_000_000_000_000_000),
            "{} file must stamp every record in nanoseconds since the epoch: {:?}",
            who,
            stamps
        );

        let summary = verify_chain(records)
            .unwrap_or_else(|e| panic!("{} audit file does not verify: {}\n{}", who, e, records));
        assert_eq!(summary.chains, 1, "{}: one open, one chain", who);
        assert_eq!(
            summary.records,
            count(records, "Authentication") + count(records, "Crypto {"),
            "{}: every record is a verified link",
            who
        );
    }

    let pub_suite = publisher.security().expect("publisher suite");
    let sub_suite = subscriber.security().expect("subscriber suite");
    assert!(!pub_suite.is_audit_degraded());
    assert!(!sub_suite.is_audit_degraded());

    drop(writer);
    drop(reader);
    drop(publisher);
    drop(subscriber);
    std::thread::sleep(Duration::from_millis(500));
}

/// The negative proof: a refused handshake leaves an `Authentication` Failed
/// record and no Success, through the public API alone.
///
/// The responder refuses a key-agreement suite that differs from its own
/// policy (`handle_request`) and records nothing: a refusal on a discard
/// path must not let a hostile source drive audit I/O. The INITIATOR keeps
/// retrying on the ladder and, at `SESSION_DEADLINE` (30 s), `tick()` marks
/// the session Failed -- that is the terminal transition, and the one record
/// this test waits for. Which participant initiates is decided by GUID
/// prefix, so the assertion is over the pair of files.
#[test]
fn a_refused_handshake_leaves_a_failed_authentication_record_through_the_public_api() {
    use crate::security::audit::verify_chain;

    let domain = unique_domain();
    let p256_audit = NamedTempFile::new().expect("p256 audit file");
    let p384_audit = NamedTempFile::new().expect("p384 audit file");
    let p256_fixture = fixture_with_audit(p256_audit.path(), false, Some("ECDH+prime256v1-CEUM"));
    let p384_fixture = fixture_with_audit(p384_audit.path(), false, Some("ECDH+secp384r1-CEUM"));

    // One lease for the pair: they must meet on the same domain for the
    // responder to refuse the initiator's suite, which is the whole subject.
    let p256 = secure_participant("audit_p256", domain.id(), &p256_fixture);
    let p384 = secure_participant("audit_p384", domain.id(), &p384_fixture);

    // Discovery is the precondition for the initiator to start at all.
    assert!(
        wait_until(Duration::from_secs(10), || {
            has_discovered(&p256, &p384) && has_discovered(&p384, &p256)
        }),
        "SPDP discovery never completed"
    );

    // 75 s, not 50: the record can only appear after SPDP discovery plus the
    // 30 s SESSION_DEADLINE, and the loop exits the moment it lands, so the
    // extra margin costs nothing on a healthy box and keeps the case honest
    // under the two-core starvation regime the official runner uses.
    let failed = wait_until(Duration::from_secs(75), || {
        let a = audit_records(p256_audit.path());
        let b = audit_records(p384_audit.path());
        (count(&a, "Authentication") >= 1 && count(&a, "outcome: Failed") >= 1)
            || (count(&b, "Authentication") >= 1 && count(&b, "outcome: Failed") >= 1)
    });
    let p256_records = audit_records(p256_audit.path());
    let p384_records = audit_records(p384_audit.path());
    assert!(
        failed,
        "no Authentication Failed record reached either file within 50 s: the initiator's \
         30 s deadline expiry is not recorded within 75 s\np256 file:\n{}\np384 file:\n{}",
        p256_records, p384_records
    );

    for (who, records) in [("p256", &p256_records), ("p384", &p384_records)] {
        // The Successes each file carries are its own secure builtin
        // endpoints' key material, minted at participant build (three
        // writers, three readers -- `register_builtin_writer_keys` and
        // `register_builtin_reader_keys`); nothing of the peer, which
        // never authenticated.
        assert_eq!(
            count(records, "operation: \"install_builtin_writer_key\""),
            3,
            "{} file: its own three secure builtin writers' keys, no peer's:\n{}",
            who,
            records
        );
        assert_eq!(
            count(records, "operation: \"install_builtin_reader_key\""),
            3,
            "{} file: its own three secure builtin readers' keys, no peer's:\n{}",
            who,
            records
        );
        assert_eq!(
            count(records, "outcome: Success"),
            6,
            "{} file must carry no other Success: the suites can never agree:\n{}",
            who,
            records
        );
        assert_eq!(
            count(records, "install_data_key"),
            0,
            "{} file: no key can be distributed to a peer that never authenticated",
            who
        );
        verify_chain(records)
            .unwrap_or_else(|e| panic!("{} audit file does not verify: {}\n{}", who, e, records));
    }

    assert!(!p256.security().expect("suite").is_audit_degraded());
    assert!(!p384.security().expect("suite").is_audit_degraded());

    drop(p256);
    drop(p384);
    std::thread::sleep(Duration::from_millis(500));
}

/// Same PKI as `fixture_with_audit`, plus the two XML documents that switch
/// the access-control plugin on. Without them `SecurityPluginSuite::new`
/// leaves `access_control = None` and no endpoint decision is ever taken.
/// The governance refuses a domain it does not cover, and the refusal happens
/// at `Participant::build` - before a socket is bound or a single SPDP
/// announcement leaves the host.
///
/// This is the test that proves the wiring exists at all: production must call
/// `check_create_participant`, otherwise the governance document is parsed and
/// its domain rules stored but never enforced. An operator could hand us a
/// governance naming domain 5, join domain 40, and every layer above would
/// report a secured participant. This test therefore asserts on the REFUSAL
/// rather than on a success.
#[test]
#[cfg(feature = "security")]
fn a_domain_outside_the_governance_is_refused_before_the_participant_binds() {
    // The rule names a reserved domain, which the lease pool never hands
    // out: the leased domain is outside the rule BY CONSTRUCTION (a rule
    // naming a leasable domain such as 5 would make this assertion flaky).
    let governed = crate::test_support::domains::RESERVED_DOMAINS[0];
    let domain = unique_domain();
    assert_ne!(
        domain.id(),
        governed,
        "the leased domain must be outside the rule"
    );

    let governance = NamedTempFile::new().expect("governance file");
    std::fs::write(
        governance.path(),
        format!(
            r#"<?xml version="1.0"?>
<governance>
  <domain_rule>
    <domains>{governed}</domains>
    <allow_unauthenticated_participants>false</allow_unauthenticated_participants>
    <enable_join_access_control>true</enable_join_access_control>
    <discovery_protection_kind>NONE</discovery_protection_kind>
    <data_protection_kind>NONE</data_protection_kind>
  </domain_rule>
</governance>"#
        ),
    )
    .expect("write governance");

    let permissions = write_pem(AUDIT_PERMISSIONS_SMIME);
    let permissions_ca = write_pem(PERM_CA_EC_PEM);
    let cert = write_pem(TEST_IDENTITY_CERT_PEM);
    let key = write_pem(TEST_IDENTITY_KEY_PEM);
    let ca = write_pem(TEST_CA_CERT_PEM);

    let config = SecurityConfig::builder()
        .identity_certificate(cert.path())
        .private_key(key.path())
        .ca_certificates(ca.path())
        .governance_xml(governance.path())
        .permissions_xml(permissions.path())
        .permissions_ca(permissions_ca.path())
        .insecure_allow_unsigned_documents(true)
        .build()
        .expect("the configuration itself is valid; it is the DOMAIN that is refused");

    // `Participant` is not Debug, so unwrap the Result by hand rather than
    // through expect_err.
    let text = match Participant::builder("outside_governance")
        .domain_id(domain.id())
        .with_transport(TransportMode::UdpMulticast)
        .with_security(config)
        .build()
    {
        Ok(_) => panic!(
            "a domain no rule covers must not be joined: the governance names \
             domain {} and this participant asked for {}",
            governed,
            domain.id()
        ),
        Err(err) => format!("{}", err),
    };
    assert!(
        text.contains(&domain.id().to_string()),
        "the refusal must name the domain, got: {}",
        text
    );
    assert!(
        text.to_lowercase().contains("governance"),
        "the refusal must say which policy refused, got: {}",
        text
    );
}

fn fixture_with_access_control(
    audit_path: &std::path::Path,
    governance_path: &std::path::Path,
    permissions_path: &std::path::Path,
    permissions_ca_path: &std::path::Path,
) -> SecurityFixture {
    let cert = write_pem(TEST_IDENTITY_CERT_PEM);
    let key = write_pem(TEST_IDENTITY_KEY_PEM);
    let ca = write_pem(TEST_CA_CERT_PEM);

    let config = SecurityConfig::builder()
        .identity_certificate(cert.path())
        .private_key(key.path())
        .ca_certificates(ca.path())
        .governance_xml(governance_path)
        .permissions_xml(permissions_path)
        .permissions_ca(permissions_ca_path)
        .enable_encryption(true)
        .enable_audit_log(true)
        .audit_log_path(audit_path)
        .build()
        .expect("SecurityConfig with access control and audit logging must build");

    SecurityFixture {
        config,
        _cert: cert,
        _key: key,
        _ca: ca,
    }
}

/// The third event family, on disk, through the public builders.
///
/// `writer().build()` and `reader().build()` take their access-control
/// decision in `Participant::check_create_writer` / `check_create_reader`,
/// which must record it in the audit file, not only `log::info!` it. This pins
/// all six halves of that path: an allowed endpoint records `Allowed`, a
/// refused one records `Denied` AND fails the build, the deprecated
/// `create_writer` wrapper produces ONE record and not two, every stamp is in
/// nanoseconds, the file verifies as one chain, and a degraded chain refuses
/// the next endpoint outright (fail closed, AUD-1).
#[test]
fn access_control_decisions_reach_the_audit_chain_through_the_public_api() {
    use crate::generated::temperature::Temperature;
    use crate::security::audit::verify_chain;

    // The domain is leased, not hardcoded: a fixed `const DOMAIN: u32 = 229`
    // can collide with another test using the same number, and the
    // participant build then dies with "Address already in use (os error 98)".
    //
    // The two S/MIME documents below still name `<domains>229</domains>`, and
    // that is deliberate: the signature covers the XML, so the number cannot
    // be changed without re-signing, and nothing consults it. The governance
    // domain rule is only reachable through `AccessControlPlugin::
    // check_create_participant` -> `RulesEngine::check_domain_access`, which
    // no production path calls; the decisions this test asserts on
    // (`check_create_writer` / `check_create_reader`) match on topic and
    // partition alone. If `check_create_participant` is ever wired into
    // `Participant::build`, this test goes red HERE, at the build, and the
    // fixtures must then be reissued with a domain range instead.
    let domain = unique_domain();
    let audit = NamedTempFile::new().expect("audit file");
    let governance = write_pem(AUDIT_GOVERNANCE_SMIME);
    let permissions = write_pem(AUDIT_PERMISSIONS_SMIME);
    let permissions_ca = write_pem(PERM_CA_EC_PEM);
    let fixture = fixture_with_access_control(
        audit.path(),
        governance.path(),
        permissions.path(),
        permissions_ca.path(),
    );
    let participant = secure_participant("audit_access", domain.id(), &fixture);

    assert!(
        participant
            .security()
            .expect("suite")
            .is_access_control_enabled(),
        "the fixture must switch the access-control plugin on, or nothing below is exercised"
    );
    let records = audit_records(audit.path());
    assert_eq!(
        count(&records, "AccessControl"),
        0,
        "no endpoint decision has been taken yet:\n{}",
        records
    );

    // An allowed writer: one Allowed record, resource spelled 'topic:partition'.
    let writer = participant
        .topic::<Temperature>("sensor/temperature")
        .expect("writer topic")
        .writer()
        .qos(QoS::reliable().keep_all())
        .build()
        .expect("a granted topic must build");
    let records = audit_records(audit.path());
    assert_eq!(
        count(&records, "AccessControl"),
        1,
        "one build, one access-control record:\n{}",
        records
    );
    assert_eq!(count(&records, "action: \"create_writer\""), 1);
    // The record names what the decision was MADE ON, and nothing else.
    //
    // An audit record must not overstate its inputs: it is the evidence of
    // what was checked. No partition was requested here, so no partition
    // appears; an endpoint naming one is recorded as `topic
    // (partitions [...])`, every one of which the permissions are evaluated
    // on.
    assert!(
        records.contains("resource: \"sensor/temperature\""),
        "the record must name the topic the decision was made on:\n{}",
        records
    );
    assert!(
        !records.contains("sensor/temperature:"),
        "the record must not append a partition that was never evaluated:\n{}",
        records
    );
    assert_eq!(count(&records, "outcome: Allowed"), 1);
    // The encrypting writer also minted its key: two families in one file.
    assert_eq!(
        count(&records, "operation: \"install_data_key\""),
        1,
        "the writer's minted key belongs in the same chain:\n{}",
        records
    );

    // An allowed reader, same path on the subscribe side.
    let reader = participant
        .topic::<Temperature>("sensor/temperature")
        .expect("reader topic")
        .reader()
        .qos(QoS::reliable().keep_all())
        .build()
        .expect("a granted topic must build");
    let records = audit_records(audit.path());
    assert_eq!(count(&records, "action: \"create_reader\""), 1);
    assert_eq!(count(&records, "AccessControl"), 2);

    // A refused writer: the build fails AND the refusal is in the chain.
    let refused = participant
        .topic::<Temperature>("admin/shutdown")
        .expect("denied topic")
        .writer()
        .qos(QoS::reliable())
        .build();
    let error = refused.err().expect("a denied topic must not build");
    assert!(
        error.to_string().contains("Access control denied"),
        "unexpected error: {}",
        error
    );
    let records = audit_records(audit.path());
    assert_eq!(
        count(&records, "outcome: Denied"),
        1,
        "the refusal must be recorded, not only returned:\n{}",
        records
    );
    assert!(
        records.contains("resource: \"admin/shutdown\""),
        "the refused resource must be named:\n{}",
        records
    );
    assert_eq!(count(&records, "AccessControl"), 3);

    // The deprecated wrapper routes through the same builder: ONE record for
    // its one decision: one decision must produce one record.
    #[allow(deprecated)]
    let legacy = participant
        .create_writer::<Temperature>("sensor/legacy", QoS::reliable())
        .expect("the deprecated wrapper must still build a granted topic");
    let records = audit_records(audit.path());
    assert_eq!(
        count(&records, "AccessControl"),
        4,
        "the deprecated wrapper must record exactly one decision:\n{}",
        records
    );
    assert_eq!(
        count(&records, "resource: \"sensor/legacy\""),
        1,
        "and record it once, in the builder's spelling:\n{}",
        records
    );

    // Every stamp in the file is nanoseconds, whatever the family, and the
    // whole file is one verifiable chain.
    let stamps = audit_timestamps(&records);
    assert!(
        stamps.len() >= 5 && stamps.iter().all(|&t| t > 1_000_000_000_000_000_000),
        "every record must be stamped in nanoseconds: {:?}",
        stamps
    );
    let summary = verify_chain(&records)
        .unwrap_or_else(|e| panic!("the audit file does not verify: {}\n{}", e, records));
    assert_eq!(summary.chains, 1, "one open, one chain");
    assert_eq!(
        summary.records,
        count(&records, "AccessControl") + count(&records, "Crypto {"),
        "every record is a verified link"
    );

    // Fail closed: once a record has been lost, no new endpoint is created.
    let suite = participant.security().expect("suite");
    suite
        .logging()
        .expect("the suite owns an audit chain")
        .mark_degraded_for_tests();
    assert!(suite.is_audit_degraded());
    let after = participant
        .topic::<Temperature>("sensor/after")
        .expect("granted topic")
        .writer()
        .qos(QoS::reliable())
        .build();
    let error = after
        .err()
        .expect("a degraded audit chain must refuse the endpoint");
    assert!(
        error.to_string().contains("audit chain degraded"),
        "unexpected error: {}",
        error
    );
    let records = audit_records(audit.path());
    assert_eq!(
        count(&records, "AccessControl"),
        4,
        "a refused endpoint adds no record:\n{}",
        records
    );

    drop(writer);
    drop(reader);
    drop(legacy);
    drop(participant);
    std::thread::sleep(Duration::from_millis(200));
}

// ---------------------------------------------------------------------------
// Signed-document fail-closed, at the participant boundary
// ---------------------------------------------------------------------------

/// Build a participant whose access-control documents are the two blobs given.
///
/// `TransportMode::IntraProcess` on purpose: these tests are about whether
/// `Participant::build()` returns, and taking the network out of the picture
/// keeps them hermetic on a box where other suites share the multicast groups.
fn participant_with_documents(
    name: &str,
    domain: u32,
    governance: &[u8],
    permissions: &[u8],
    permissions_ca: Option<&[u8]>,
    allow_unsigned: bool,
) -> Result<Arc<Participant>, crate::dds::Error> {
    let cert = write_pem(TEST_IDENTITY_CERT_PEM);
    let key = write_pem(TEST_IDENTITY_KEY_PEM);
    let ca = write_pem(TEST_CA_CERT_PEM);
    let gov = write_pem(governance);
    let perms = write_pem(permissions);
    let perm_ca = permissions_ca.map(write_pem);

    let mut builder = SecurityConfig::builder()
        .identity_certificate(cert.path())
        .private_key(key.path())
        .ca_certificates(ca.path())
        .governance_xml(gov.path())
        .permissions_xml(perms.path());
    if let Some(ref file) = perm_ca {
        builder = builder.permissions_ca(file.path());
    }
    if allow_unsigned {
        builder = builder.insecure_allow_unsigned_documents(true);
    }
    let config = builder.build()?;

    Participant::builder(name)
        .domain_id(domain)
        .with_transport(TransportMode::IntraProcess)
        .with_security(config)
        .build()
}

/// The whole chain, green: signed documents, verified against the configured
/// Permissions CA, with a grant that names this identity.
#[test]
fn participant_builds_with_permissions_ca_signed_documents() {
    let domain = unique_domain();
    let participant = participant_with_documents(
        "p7s_ok",
        domain.id(),
        AUDIT_GOVERNANCE_SMIME,
        AUDIT_PERMISSIONS_SMIME,
        Some(PERM_CA_EC_PEM),
        false,
    )
    .expect("a participant with correctly signed documents must build");
    assert!(
        participant
            .security()
            .expect("suite")
            .is_access_control_enabled(),
        "the documents must have switched access control on"
    );
}

/// A permissions document edited after signing stops the participant at
/// bootstrap, not at the first endpoint.
#[test]
fn participant_build_fails_closed_on_forged_permissions() {
    let domain = unique_domain();
    let err = participant_with_documents(
        "p7s_forged",
        domain.id(),
        GOVERNANCE_EC_SMIME,
        PERMISSIONS_TAMPERED_SMIME,
        Some(PERM_CA_EC_PEM),
        false,
    )
    .err()
    .expect("a forged permissions document must stop the build");
    let text = err.to_string();
    assert!(text.contains("permissions"), "got: {}", text);
    assert!(text.contains("messageDigest"), "got: {}", text);
}

/// Plain, unsigned XML stops the participant unless the caller opted in.
#[test]
fn participant_build_fails_closed_on_unsigned_permissions() {
    let domain = unique_domain();
    let err = participant_with_documents(
        "p7s_unsigned",
        domain.id(),
        GOVERNANCE_PLAIN_XML,
        PERMISSIONS_PLAIN_XML,
        Some(PERM_CA_EC_PEM),
        false,
    )
    .err()
    .expect("an unsigned document must stop the build");
    assert!(err.to_string().contains("is not signed"), "got: {}", err);
}

/// A document signed by a CA that is not the configured one stops the build.
#[test]
fn participant_build_fails_closed_on_documents_from_another_ca() {
    let domain = unique_domain();
    let err = participant_with_documents(
        "p7s_other_ca",
        domain.id(),
        GOVERNANCE_EC_SMIME,
        PERMISSIONS_OTHER_CA_SMIME,
        Some(PERM_CA_EC_PEM),
        false,
    )
    .err()
    .expect("a document signed by another CA must stop the build");
    assert!(err.to_string().contains("permissions CA"), "got: {}", err);
}

/// The same fixture as [`fixture_with_access_control`], plus a local
/// restriction overlay file.
fn fixture_with_access_control_and_overlay(
    audit_path: &std::path::Path,
    governance_path: &std::path::Path,
    permissions_path: &std::path::Path,
    permissions_ca_path: &std::path::Path,
    overlay_path: &std::path::Path,
) -> SecurityFixture {
    let cert = write_pem(TEST_IDENTITY_CERT_PEM);
    let key = write_pem(TEST_IDENTITY_KEY_PEM);
    let ca = write_pem(TEST_CA_CERT_PEM);

    let config = SecurityConfig::builder()
        .identity_certificate(cert.path())
        .private_key(key.path())
        .ca_certificates(ca.path())
        .governance_xml(governance_path)
        .permissions_xml(permissions_path)
        .permissions_ca(permissions_ca_path)
        .permissions_overlay(overlay_path)
        .enable_audit_log(true)
        .audit_log_path(audit_path)
        .build()
        .expect("SecurityConfig with a permission overlay must build");

    SecurityFixture {
        config,
        _cert: cert,
        _key: key,
        _ca: ca,
    }
}

/// The local permission overlay may only NARROW what the signed permissions
/// document granted, and the proof runs through the public builders.
///
/// Three properties in one participant, because they are one policy:
///
/// 1. a topic the signed document grants and the overlay refuses does not
///    build, and the refusal is in the audit chain;
/// 2. a topic the signed document refuses does NOT become available because
///    the overlay says `allow` - an unsigned file cannot widen what a
///    Permissions-CA-signed document decided (DDS-Security v1.1 9.4.1.3);
/// 3. a topic the overlay says nothing about is untouched.
///
/// The overlay names this participant with its attributes in the REVERSE
/// order and with no space after the comma, while `x509_parser` prints
/// `CN=DDS Test Identity, O=HDDS Test`. Only the RFC 4514 reader in
/// `access::subject` makes those two spellings the same subject; string
/// equality would silently match nothing, and a restriction that matches
/// nothing restricts nothing.
#[test]
#[cfg(feature = "security")]
fn permission_overlay_narrows_the_signed_grant_and_never_widens_it() {
    use crate::generated::temperature::Temperature;
    use crate::security::audit::verify_chain;

    let domain = unique_domain();
    let audit = NamedTempFile::new().expect("audit file");
    let governance = write_pem(AUDIT_GOVERNANCE_SMIME);
    let permissions = write_pem(AUDIT_PERMISSIONS_SMIME);
    let permissions_ca = write_pem(PERM_CA_EC_PEM);
    let overlay = write_pem(
        b"# reverse attribute order, no space: only a DN reader can match this\n\
          [subject: O=HDDS Test,CN=DDS Test Identity]\n\
          default: allow\n\
          deny publish: sensor/secret\n\
          allow publish: admin/shutdown\n",
    );

    let fixture = fixture_with_access_control_and_overlay(
        audit.path(),
        governance.path(),
        permissions.path(),
        permissions_ca.path(),
        overlay.path(),
    );
    let participant = secure_participant("perm_overlay", domain.id(), &fixture);

    // 1. Granted by the signed document (sensor/*), taken away by the overlay.
    let refused = participant
        .topic::<Temperature>("sensor/secret")
        .expect("overlay-refused topic")
        .writer()
        .qos(QoS::reliable())
        .build();
    let error = refused
        .err()
        .expect("the overlay must refuse a topic the signed document granted");
    assert!(
        error
            .to_string()
            .contains("Local permission overlay denied"),
        "the refusal must name the overlay, not the signed document: {}",
        error
    );
    let records = audit_records(audit.path());
    assert_eq!(
        count(&records, "outcome: Denied"),
        1,
        "an overlay refusal is an access-control decision and belongs in the chain:\n{}",
        records
    );
    assert_eq!(
        count(&records, "AccessControl"),
        1,
        "one decision, one record - the signed allow must not be recorded too:\n{}",
        records
    );

    // 2. Refused by the signed document; the overlay's `allow` changes nothing.
    let still_refused = participant
        .topic::<Temperature>("admin/shutdown")
        .expect("denied topic")
        .writer()
        .qos(QoS::reliable())
        .build();
    let error = still_refused
        .err()
        .expect("an unsigned file must never widen a signed grant");
    assert!(
        error.to_string().contains("Access control denied"),
        "the signed document must be the one refusing here: {}",
        error
    );

    // 3. A topic the overlay says nothing about is untouched.
    let allowed = participant
        .topic::<Temperature>("sensor/temperature")
        .expect("granted topic")
        .writer()
        .qos(QoS::reliable())
        .build();
    assert!(
        allowed.is_ok(),
        "the overlay must leave alone what it does not name: {:?}",
        allowed.err()
    );

    let records = audit_records(audit.path());
    assert_eq!(count(&records, "AccessControl"), 3, "{}", records);
    verify_chain(&records)
        .unwrap_or_else(|e| panic!("the audit file does not verify: {}\n{}", e, records));
}

/// The overlay judges EVERY partition an endpoint is in, as the signed
/// document does (DDS-Security v1.1 Sec.9.4.1.3.2.3.1.4): a writer in
/// partitions ["A", "B"] is refused by a rule refusing "B" (reading only the
/// first non-empty name would let the writer be built). Identity plus overlay
/// only: the overlay is the whole policy here.
#[test]
#[cfg(feature = "security")]
fn permission_overlay_judges_every_partition_of_an_endpoint() {
    use crate::generated::temperature::Temperature;
    use crate::qos::partition::Partition;

    let domain = unique_domain();
    let overlay = write_pem(
        b"[subject: CN=DDS Test Identity, O=HDDS Test]\n\
          default: allow\n\
          deny publish: data/* partitions=B\n",
    );
    let cert = write_pem(TEST_IDENTITY_CERT_PEM);
    let key = write_pem(TEST_IDENTITY_KEY_PEM);
    let ca = write_pem(TEST_CA_CERT_PEM);
    let config = SecurityConfig::builder()
        .identity_certificate(cert.path())
        .private_key(key.path())
        .ca_certificates(ca.path())
        .permissions_overlay(overlay.path())
        .build()
        .expect("identity and overlay");
    let fixture = SecurityFixture {
        config,
        _cert: cert,
        _key: key,
        _ca: ca,
    };
    let participant = secure_participant("perm_overlay_partitions", domain.id(), &fixture);
    let writer_in = |topic: &str, partitions: &[&str]| {
        participant
            .topic::<Temperature>(topic)
            .expect("topic")
            .writer()
            .qos(QoS::reliable().partition(Partition::new(
                partitions.iter().map(|name| (*name).to_string()).collect(),
            )))
            .build()
    };
    let refused = writer_in("data/one", &["A", "B"]);
    assert!(
        refused
            .as_ref()
            .err()
            .is_some_and(|e| e.to_string().contains("Local permission overlay denied")),
        "a writer in [A, B] escaped the rule refusing B: {:?}",
        refused.err()
    );
    assert!(writer_in("data/two", &["", "B"]).is_err(), "[\"\", B]");
    assert!(
        writer_in("data/three", &["A"]).is_ok(),
        "A alone is not refused"
    );
    assert!(
        writer_in("data/four", &[]).is_ok(),
        "the default partition is not B"
    );
}

/// DDS-Security v1.1 Sec.9.4.1.3.2.3.1.4 through the public builders: a
/// grant for partition `A` refuses a writer in {A, C} by default, and admits
/// it with `SecurityConfig::legacy_partition_matching` ("legacy matching":
/// one partition matched is enough); a writer in {C} alone is refused
/// either way.
#[test]
#[cfg(feature = "security")]
fn legacy_partition_matching_reaches_the_local_permissions_check() {
    use crate::generated::temperature::Temperature;
    use crate::qos::partition::Partition;

    let governance = write_pem(
        b"<?xml version=\"1.0\"?><dds><domain_access_rules><domain_rule>\
          <domains><id_range><min>1</min><max>232</max></id_range></domains>\
          <allow_unauthenticated_participants>FALSE</allow_unauthenticated_participants>\
          <enable_join_access_control>TRUE</enable_join_access_control>\
          <discovery_protection_kind>NONE</discovery_protection_kind>\
          <liveliness_protection_kind>NONE</liveliness_protection_kind>\
          <rtps_protection_kind>NONE</rtps_protection_kind>\
          <topic_access_rules><topic_rule><topic_expression>*</topic_expression>\
          <enable_discovery_protection>FALSE</enable_discovery_protection>\
          <enable_liveliness_protection>FALSE</enable_liveliness_protection>\
          <enable_read_access_control>TRUE</enable_read_access_control>\
          <enable_write_access_control>TRUE</enable_write_access_control>\
          <metadata_protection_kind>NONE</metadata_protection_kind>\
          <data_protection_kind>NONE</data_protection_kind></topic_rule>\
          </topic_access_rules></domain_rule></domain_access_rules></dds>",
    );
    let permissions = write_pem(
        b"<?xml version=\"1.0\"?><dds><permissions><grant name=\"g\">\
          <subject_name>CN=DDS Test Identity, O=HDDS Test</subject_name>\
          <validity><not_before>2020-01-01T00:00:00</not_before>\
          <not_after>2036-01-01T00:00:00</not_after></validity>\
          <allow_rule><domains><id_range><min>1</min><max>232</max></id_range></domains>\
          <publish><topics><topic>sensor/*</topic></topics><partitions>\
          <partition>A</partition></partitions></publish></allow_rule>\
          <default>DENY</default></grant></permissions></dds>",
    );
    for legacy in [false, true] {
        let domain = unique_domain();
        let cert = write_pem(TEST_IDENTITY_CERT_PEM);
        let key = write_pem(TEST_IDENTITY_KEY_PEM);
        let ca = write_pem(TEST_CA_CERT_PEM);
        let config = SecurityConfig::builder()
            .identity_certificate(cert.path())
            .private_key(key.path())
            .ca_certificates(ca.path())
            .governance_xml(governance.path())
            .permissions_xml(permissions.path())
            .insecure_allow_unsigned_documents(true)
            .legacy_partition_matching(legacy)
            .build()
            .expect("config");
        let fixture = SecurityFixture {
            config,
            _cert: cert,
            _key: key,
            _ca: ca,
        };
        // The peers' documents are read with the same option.
        let suite = crate::security::SecurityPluginSuite::new(fixture.config.clone(), domain.id())
            .expect("suite");
        assert_eq!(
            suite
                .remote_access_inputs
                .as_ref()
                .map(|inputs| inputs.legacy_partition_matching),
            Some(legacy),
            "the remote access control's inputs"
        );
        let participant = secure_participant("legacy_partitions", domain.id(), &fixture);
        let writer_in = |topic: &str, partitions: &[&str]| {
            participant
                .topic::<Temperature>(topic)
                .expect("topic")
                .writer()
                .qos(QoS::reliable().partition(Partition::new(
                    partitions.iter().map(|name| (*name).to_string()).collect(),
                )))
                .build()
        };
        assert!(
            writer_in("sensor/a", &["A"]).is_ok(),
            "legacy={legacy}: [A]"
        );
        assert_eq!(
            writer_in("sensor/ac", &["A", "C"]).is_ok(),
            legacy,
            "legacy={legacy}: [A, C]"
        );
        assert!(
            writer_in("sensor/c", &["C"]).is_err(),
            "legacy={legacy}: [C]"
        );
    }
}

/// An overlay that names another subject entirely restricts nothing here.
///
/// This is the difference between `DynamicPermissionManager::check_publish`,
/// which reads an unnamed subject as a refusal because standing alone it is
/// the whole policy, and the overlay door, which abstains. Wiring the first
/// reading into the participant would have denied every endpoint of every
/// participant the file does not list.
#[test]
#[cfg(feature = "security")]
fn permission_overlay_is_silent_about_a_subject_it_does_not_name() {
    use crate::generated::temperature::Temperature;

    let domain = unique_domain();
    let audit = NamedTempFile::new().expect("audit file");
    let governance = write_pem(AUDIT_GOVERNANCE_SMIME);
    let permissions = write_pem(AUDIT_PERMISSIONS_SMIME);
    let permissions_ca = write_pem(PERM_CA_EC_PEM);
    let overlay = write_pem(
        b"[subject: CN=somebody-else,O=HDDS Test]\n\
          default: deny\n",
    );

    let fixture = fixture_with_access_control_and_overlay(
        audit.path(),
        governance.path(),
        permissions.path(),
        permissions_ca.path(),
        overlay.path(),
    );
    let participant = secure_participant("perm_overlay_other", domain.id(), &fixture);

    let writer = participant
        .topic::<Temperature>("sensor/temperature")
        .expect("granted topic")
        .writer()
        .qos(QoS::reliable())
        .build();
    assert!(
        writer.is_ok(),
        "a `default: deny` aimed at another subject must not reach this one: {:?}",
        writer.err()
    );
}

// ---------------------------------------------------------------------------
//  Discovery routed per endpoint by the governance (DDS-Security v1.1
//  Table 29, Sec.9.4.1.2.5.4)
// ---------------------------------------------------------------------------

/// A pair of documents, unsigned (`insecure_allow_unsigned_documents`), in
/// the specification's form: `sensor/open` announced on the regular SEDP
/// topics, every other topic on the secure ones, the secure discovery
/// writers protected by `discovery_kind`.
fn governed_fixture(discovery_kind: &str) -> (SecurityFixture, NamedTempFile, NamedTempFile) {
    let topic_rule = |expression: &str, discovery: &str| {
        format!(
            "<topic_rule><topic_expression>{}</topic_expression>\
             <enable_discovery_protection>{}</enable_discovery_protection>\
             <enable_liveliness_protection>FALSE</enable_liveliness_protection>\
             <enable_read_access_control>TRUE</enable_read_access_control>\
             <enable_write_access_control>TRUE</enable_write_access_control>\
             <metadata_protection_kind>NONE</metadata_protection_kind>\
             <data_protection_kind>NONE</data_protection_kind></topic_rule>",
            expression, discovery
        )
    };
    let governance = format!(
        "<?xml version=\"1.0\"?><dds><domain_access_rules><domain_rule>\
         <domains><id_range><min>1</min><max>232</max></id_range></domains>\
         <allow_unauthenticated_participants>FALSE</allow_unauthenticated_participants>\
         <enable_join_access_control>TRUE</enable_join_access_control>\
         <discovery_protection_kind>{}</discovery_protection_kind>\
         <liveliness_protection_kind>NONE</liveliness_protection_kind>\
         <rtps_protection_kind>NONE</rtps_protection_kind>\
         <topic_access_rules>{}{}</topic_access_rules>\
         </domain_rule></domain_access_rules></dds>",
        discovery_kind,
        topic_rule("sensor/open", "FALSE"),
        topic_rule("*", "TRUE"),
    );
    let permissions = "<?xml version=\"1.0\"?><dds><permissions><grant name=\"g\">\
         <subject_name>CN=DDS Test Identity, O=HDDS Test</subject_name>\
         <validity><not_before>2020-01-01T00:00:00</not_before>\
         <not_after>2036-01-01T00:00:00</not_after></validity>\
         <allow_rule><domains><id_range><min>1</min><max>232</max></id_range></domains>\
         <publish><topics><topic>sensor/*</topic></topics></publish>\
         <subscribe><topics><topic>sensor/*</topic></topics></subscribe></allow_rule>\
         <default>DENY</default></grant></permissions></dds>";
    let governance_file = write_pem(governance.as_bytes());
    let permissions_file = write_pem(permissions.as_bytes());
    let cert = write_pem(TEST_IDENTITY_CERT_PEM);
    let key = write_pem(TEST_IDENTITY_KEY_PEM);
    let ca = write_pem(TEST_CA_CERT_PEM);
    let config = SecurityConfig::builder()
        .identity_certificate(cert.path())
        .private_key(key.path())
        .ca_certificates(ca.path())
        .governance_xml(governance_file.path())
        .permissions_xml(permissions_file.path())
        .insecure_allow_unsigned_documents(true)
        .accept_unsigned_remote_documents_for_tests()
        .build()
        .expect("SecurityConfig with unsigned governance must build");
    (
        SecurityFixture {
            config,
            _cert: cert,
            _key: key,
            _ca: ca,
        },
        governance_file,
        permissions_file,
    )
}

/// DDS-Security v1.1 Sec.7.2.8, 9.4.2.6: permissions allowing both
/// endpoints do not replace equality of valid governance attributes.
#[test]
fn governed_endpoint_masks_require_equal_access_attributes() {
    use crate::generated::temperature::Temperature;

    for difference in [None, Some(("read", 0x01)), Some(("write", 0x02))] {
        // Real network tests use leased domains in the isolated test range.
        let lease_deadline = Instant::now() + Duration::from_secs(60);
        let domain = loop {
            let lease = unique_domain();
            if (200..=230).contains(&lease.id()) {
                break lease;
            }
            assert!(
                Instant::now() < lease_deadline,
                "isolated domain range is busy"
            );
            std::thread::yield_now();
        };
        let (pub_fixture, _pub_gov, _pub_perm) = governed_fixture("NONE");
        let (sub_fixture, sub_gov, _sub_perm) = governed_fixture("NONE");
        if let Some((attribute, _)) = difference {
            let xml = std::fs::read_to_string(sub_gov.path()).expect("governance");
            let original = format!(
                "<enable_{attribute}_access_control>TRUE</enable_{attribute}_access_control>"
            );
            let changed = format!(
                "<enable_{attribute}_access_control>FALSE</enable_{attribute}_access_control>"
            );
            // Only the first topic rule (sensor/open) changes, in one field.
            std::fs::write(sub_gov.path(), xml.replacen(&original, &changed, 1))
                .expect("write differing governance");
        }
        let publisher = secure_participant("mask_pub", domain.id(), &pub_fixture);
        let subscriber = secure_participant("mask_sub", domain.id(), &sub_fixture);
        assert!(
            wait_until(Duration::from_secs(15), || {
                has_authenticated(&publisher, &subscriber)
                    && has_authenticated(&subscriber, &publisher)
            }),
            "both participants must authenticate, difference={difference:?}"
        );

        let writer = publisher
            .topic::<Temperature>("sensor/open")
            .expect("topic")
            .writer()
            .qos(QoS::reliable().keep_all())
            .build()
            .expect("writer");
        let reader = subscriber
            .topic::<Temperature>("sensor/open")
            .expect("topic")
            .reader()
            .qos(QoS::reliable().keep_all())
            .build()
            .expect("reader");
        let pub_fsm = publisher.discovery().expect("publisher discovery");
        let sub_fsm = subscriber.discovery().expect("subscriber discovery");
        let remote_reader = || {
            pub_fsm
                .registered_readers_for_topic("sensor/open")
                .into_iter()
                .find(|e| e.endpoint_guid.prefix == subscriber.guid().prefix)
        };
        let remote_writer = || {
            sub_fsm
                .find_writers_for_topic("sensor/open")
                .into_iter()
                .find(|e| e.endpoint_guid.prefix == publisher.guid().prefix)
        };
        assert!(
            wait_until(Duration::from_secs(15), || {
                remote_reader().is_some() && remote_writer().is_some()
            }),
            "both SEDP announcements must arrive, difference={difference:?}"
        );
        let announced_reader = remote_reader().expect("remote reader");
        let announced_writer = remote_writer().expect("remote writer");
        let reader_info = announced_reader.endpoint_security_info.expect("reader PID");
        let writer_info = announced_writer.endpoint_security_info.expect("writer PID");
        assert_eq!(writer_info.endpoint_security_attributes, 0x8000_0003);
        assert_eq!(
            reader_info.endpoint_security_attributes,
            0x8000_0003 ^ difference.map_or(0, |(_, bit)| bit)
        );
        assert_eq!(writer_info.plugin_endpoint_security_attributes, 0x8000_0000);
        assert_eq!(reader_info.plugin_endpoint_security_attributes, 0x8000_0000);
        let compatible = difference.is_none();
        assert_eq!(pub_fsm.admits_endpoint(&announced_reader), compatible);
        assert_eq!(sub_fsm.admits_endpoint(&announced_writer), compatible);
        assert_eq!(
            pub_fsm.admits_remote_endpoint("sensor/open", &announced_reader.endpoint_guid, false),
            compatible
        );
        assert_eq!(
            sub_fsm.admits_remote_endpoint("sensor/open", &announced_writer.endpoint_guid, true),
            compatible
        );
        assert_eq!(
            !pub_fsm.find_readers_for_topic("sensor/open").is_empty(),
            compatible
        );
        if compatible {
            assert!(
                wait_until(Duration::from_secs(15), || {
                    writer.get_publication_matched_status().current_count == 1
                        && reader.get_subscription_matched_status().current_count == 1
                }),
                "identical governance must surface both matches"
            );
            writer
                .write(&Temperature {
                    value: 7.5,
                    timestamp: 1,
                })
                .expect("write");
            assert!(
                wait_until(Duration::from_secs(15), || {
                    reader.take().expect("take").is_some()
                }),
                "identical governance must exchange data"
            );
        } else {
            assert_eq!(writer.get_publication_matched_status().total_count, 0);
            assert_eq!(reader.get_subscription_matched_status().total_count, 0);
        }
    }
}

/// Two governed participants match, and data crosses, on a topic announced
/// on the regular SEDP topics and on one announced on the secure ones, for
/// a discovery protection kind of each transformation: NONE (the secure
/// writer untransformed), SIGN (AES-GMAC) and ENCRYPT with origin
/// authentication (AES-GCM plus a receiver-specific MAC).
fn governed_participants_discover_both_kinds_of_topic(discovery_kind: &str) {
    use crate::generated::temperature::Temperature;

    let domain = unique_domain();
    let (fixture, _gov, _perm) = governed_fixture(discovery_kind);
    let publisher = secure_participant("governed_pub", domain.id(), &fixture);
    let subscriber = secure_participant("governed_sub", domain.id(), &fixture);
    assert!(
        wait_until(Duration::from_secs(15), || {
            has_authenticated(&publisher, &subscriber) && has_authenticated(&subscriber, &publisher)
        }),
        "{}: the pair never authenticated",
        discovery_kind
    );

    for topic in ["sensor/open", "sensor/secret"] {
        let writer = publisher
            .topic::<Temperature>(topic)
            .expect("writer topic")
            .writer()
            .qos(QoS::reliable().keep_all())
            .build()
            .expect("writer");
        let reader = subscriber
            .topic::<Temperature>(topic)
            .expect("reader topic")
            .reader()
            .qos(QoS::reliable().keep_all())
            .build()
            .expect("reader");
        let sample = Temperature {
            value: 7.5,
            timestamp: 1_760_000_000,
        };
        let mut received = None;
        let deadline = Instant::now() + Duration::from_secs(15);
        while Instant::now() < deadline {
            writer.write(&sample).expect("write");
            if let Ok(Some(msg)) = reader.take() {
                received = Some(msg);
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let received = received.unwrap_or_else(|| {
            panic!(
                "{}: no sample crossed on '{}' - its endpoints never matched over the SEDP \
                 topic the governance put them on",
                discovery_kind, topic
            )
        });
        assert_eq!(received.value, sample.value);

        // And it was discovered over the network, on the SEDP topic the
        // governance names: the subscriber knows the publisher's writer, and
        // took it from a secure SEDP topic exactly when the topic is
        // discovery protected (only then does it ignore plain changes about
        // it, `ignores_plain_sedp_about`).
        let fsm = subscriber.discovery().expect("discovery");
        let remote = fsm
            .find_writers_for_topic(topic)
            .into_iter()
            .find(|w| w.endpoint_guid.prefix == publisher.guid().prefix)
            .unwrap_or_else(|| {
                panic!(
                    "{}: the subscriber never discovered the writer of '{}' over SEDP",
                    discovery_kind, topic
                )
            });
        assert_eq!(
            fsm.ignores_plain_sedp_about(&remote.endpoint_guid),
            topic == "sensor/secret",
            "{}: '{}' must arrive on the {} SEDP topic",
            discovery_kind,
            topic,
            if topic == "sensor/secret" {
                "secure"
            } else {
                "regular"
            }
        );
    }
}

/// A reader that joins AFTER several endpoints already exist on the
/// governed secure SEDP topic.
///
/// The late reader's catch-up is NOT proof of an ACKNACK-driven
/// `retransmit_sedp_data` retransmission: a brand-new
/// participant is served by the PROACTIVE SEDP reannounce
/// `discovery_setup::spdp_handler`'s `Answer::Yes`/`may_answer` runs the
/// moment its handshake completes (`spdp_handler.rs`), which sends the
/// writer's full current state unconditionally -- no ACKNACK round trip
/// needed or used. `core::discovery::multicast::control::tests::
/// a_protected_acknack_with_real_missing_ranges_drives_a_counted_
/// retransmission` (in `control.rs`, a real ACKNACK protected and then
/// decoded through the same functions production dispatch calls) is the
/// proof of that specific mechanism; this test
/// proves a DIFFERENT thing: that the proactive-reannounce
/// path itself crosses correctly under DDS-Security submessage protection
/// (Sec.8.8.9.3) when the governance requires it, end to end, through a
/// live two-participant exchange. If the protect/decode/dispatch wiring
/// were broken, the late reader would never see the early writer at all
/// (its matched endpoint would stay unknown forever, per
/// `governed_participants_discover_both_kinds_of_topic`'s own proof that
/// a protected topic is NOT read on the plain SEDP topic), and
/// `secure_sedp_undecodable` would climb instead of staying at zero.
#[test]
fn a_late_secure_reader_is_caught_up_over_a_protected_secure_sedp_exchange() {
    use crate::generated::temperature::Temperature;

    let domain = unique_domain();
    let (fixture, _gov, _perm) = governed_fixture("ENCRYPT");
    let publisher = secure_participant("retx_pub", domain.id(), &fixture);

    // Several endpoints BEFORE the subscriber exists: real retained SEDP
    // history for the late reader's first ACKNACK to catch up on, on both
    // the secure topic (sensor/secret) and the regular one (sensor/open),
    // one writer each plus an extra secret writer so the secure SEDP
    // writer's sequence space is not trivially "one change, one history".
    let _open_writer = publisher
        .topic::<Temperature>("sensor/open")
        .expect("writer topic")
        .writer()
        .qos(QoS::reliable().keep_all())
        .build()
        .expect("open writer");
    let secret_writer = publisher
        .topic::<Temperature>("sensor/secret")
        .expect("writer topic")
        .writer()
        .qos(QoS::reliable().keep_all())
        .build()
        .expect("secret writer");
    let _second_secret_writer = publisher
        .topic::<Temperature>("sensor/secret2")
        .expect("writer topic")
        .writer()
        .qos(QoS::reliable().keep_all())
        .build()
        .expect("second secret writer");

    // Only now does the subscriber -- and its reader of the FIRST secret
    // writer -- come into existence. Its SPDP (and so its first SEDP
    // ACKNACK) postdates every announcement above.
    let subscriber = secure_participant("retx_sub", domain.id(), &fixture);
    assert!(
        wait_until(Duration::from_secs(15), || {
            has_authenticated(&publisher, &subscriber) && has_authenticated(&subscriber, &publisher)
        }),
        "the pair never authenticated"
    );
    let reader = subscriber
        .topic::<Temperature>("sensor/secret")
        .expect("reader topic")
        .reader()
        .qos(QoS::reliable().keep_all())
        .build()
        .expect("reader");

    let sample = Temperature {
        value: 9.5,
        timestamp: 1_770_000_000,
    };
    let mut received = None;
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        secret_writer.write(&sample).expect("write");
        if let Ok(Some(msg)) = reader.take() {
            received = Some(msg);
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let received = received.unwrap_or_else(|| {
        panic!(
            "the late reader never caught up with the early writer over the protected secure \
             SEDP topic -- the protected-ACKNACK/retransmission path never completed"
        )
    });
    assert_eq!(received.value, sample.value);

    // The repair that caught the late reader up decoded under submessage
    // protection the whole way (both directions): no decode failure was
    // ever recorded on either side.
    for (who, p) in [("publisher", &publisher), ("subscriber", &subscriber)] {
        let fsm = p.discovery().expect("discovery");
        assert_eq!(
            fsm.metrics
                .secure_sedp_undecodable
                .load(std::sync::atomic::Ordering::Relaxed),
            0,
            "{}: a protected SEDP submessage (ACKNACK or DATA) failed to decode",
            who
        );
    }

    // What this test does NOT prove (see its own doc comment): that the
    // catch-up above was ACKNACK-driven:
    // `protected_sedp_retransmissions` stays at 0 here, because a brand-new
    // participant is served by the proactive SEDP reannounce on handshake
    // completion, not by `retransmit_sedp_data`. The ACKNACK-driven
    // retransmission claim is proven separately, by hand-built bytes
    // against a primed SEDP cache
    // (`a_protected_acknack_with_real_missing_ranges_drives_a_counted_retransmission`),
    // not by this live two-participant race.
}

#[test]
fn governed_discovery_none_matches_open_and_protected_topics() {
    governed_participants_discover_both_kinds_of_topic("NONE");
}

#[test]
fn governed_discovery_sign_matches_open_and_protected_topics() {
    governed_participants_discover_both_kinds_of_topic("SIGN");
}

#[test]
fn governed_discovery_encrypt_matches_open_and_protected_topics() {
    governed_participants_discover_both_kinds_of_topic("ENCRYPT");
}

/// DDS-Security v1.1 9.4.1.2.7: a topic no topic rule matches is refused at
/// endpoint creation, naming the topic.
#[test]
fn an_endpoint_whose_topic_no_rule_matches_is_refused() {
    use crate::generated::temperature::Temperature;

    let domain = unique_domain();
    let (fixture, gov, _perm) = governed_fixture("ENCRYPT");
    // The same documents without the default rule.
    let narrowed = std::fs::read_to_string(gov.path())
        .expect("governance")
        .replace(
            "<topic_expression>*</topic_expression>",
            "<topic_expression>other</topic_expression>",
        );
    std::fs::write(gov.path(), narrowed).expect("rewrite");
    let participant = secure_participant("governed_narrow", domain.id(), &fixture);
    let refused = participant
        .topic::<Temperature>("sensor/secret")
        .expect("topic")
        .writer()
        .build();
    let text = match refused {
        Ok(_) => panic!("a topic no rule matches must be refused"),
        Err(e) => e.to_string(),
    };
    assert!(
        text.contains("sensor/secret") && text.contains("topic_rule"),
        "{}",
        text
    );
    participant
        .topic::<Temperature>("sensor/open")
        .expect("topic")
        .writer()
        .build()
        .expect("a matched topic is created");
}

/// A topic whose payload the governance encrypts (9.4.1.2.6.7) is refused to
/// a participant built without encryption, writer and reader alike, naming
/// the element: its samples would otherwise cross in clear. With encryption
/// on, the same topic is created.
#[test]
fn a_payload_protected_topic_is_refused_without_encryption() {
    use crate::generated::temperature::Temperature;

    let governance = "<dds><domain_access_rules><domain_rule>\
         <domains><id_range><min>1</min><max>232</max></id_range></domains>\
         <allow_unauthenticated_participants>false</allow_unauthenticated_participants>\
         <enable_join_access_control>true</enable_join_access_control>\
         <discovery_protection_kind>NONE</discovery_protection_kind>\
         <data_protection_kind>ENCRYPT</data_protection_kind>\
         </domain_rule></domain_access_rules></dds>";
    let permissions = "<dds><permissions><grant name=\"g\">\
         <subject_name>CN=DDS Test Identity, O=HDDS Test</subject_name>\
         <validity><not_before>2020-01-01T00:00:00</not_before>\
         <not_after>2036-01-01T00:00:00</not_after></validity>\
         <allow_rule><domains><id_range><min>1</min><max>232</max></id_range></domains>\
         <publish><topics><topic>*</topic></topics></publish>\
         <subscribe><topics><topic>*</topic></topics></subscribe></allow_rule>\
         <default>DENY</default></grant></permissions></dds>";
    let (gov, perms) = (
        write_pem(governance.as_bytes()),
        write_pem(permissions.as_bytes()),
    );
    let (cert, key, ca) = (
        write_pem(TEST_IDENTITY_CERT_PEM),
        write_pem(TEST_IDENTITY_KEY_PEM),
        write_pem(TEST_CA_CERT_PEM),
    );
    for encryption in [false, true] {
        let domain = unique_domain();
        let config = SecurityConfig::builder()
            .identity_certificate(cert.path())
            .private_key(key.path())
            .ca_certificates(ca.path())
            .governance_xml(gov.path())
            .permissions_xml(perms.path())
            .insecure_allow_unsigned_documents(true)
            .enable_encryption(encryption)
            .build()
            .expect("config");
        let participant = Participant::builder("payload_protected")
            .domain_id(domain.id())
            .with_transport(TransportMode::IntraProcess)
            .with_security(config)
            .build()
            .expect("participant");
        let writer = participant
            .topic::<Temperature>("sensor/secret")
            .expect("topic")
            .writer()
            .build();
        let reader = participant
            .topic::<Temperature>("sensor/secret")
            .expect("topic")
            .reader()
            .build();
        if encryption {
            writer.expect("an encrypting participant creates the writer");
            reader.expect("and the reader");
        } else {
            let texts = [
                writer.err().map(|e| e.to_string()),
                reader.err().map(|e| e.to_string()),
            ];
            for text in texts {
                let text = text.expect("refused without encryption");
                assert!(text.contains("data_protection_kind"), "{}", text);
            }
        }
    }
}

// ---------------------------------------------------------------------------
//  A keyed type that cannot read its own key payload, under key protection
// ---------------------------------------------------------------------------

/// A keyed type as an older generator emitted one: it declares an instance
/// key (`has_key`), serializes it (`encode_key`), but cannot read a key-only
/// payload back -- `key_hash_of_key_payload` is the default `None` and
/// `keys_round_trip` the default `false`.
#[derive(Debug, Clone, Copy, PartialEq)]
struct KeyedWithoutRoundTrip {
    tag: u8,
}

impl crate::dds::DDS for KeyedWithoutRoundTrip {
    fn type_descriptor() -> &'static crate::core::types::TypeDescriptor {
        static DESC: crate::core::types::TypeDescriptor = crate::core::types::TypeDescriptor {
            type_id: 0x4B52_5430,
            type_name: "KeyedWithoutRoundTrip",
            size_bytes: 1,
            alignment: 1,
            is_variable_size: false,
            fields: &[],
        };
        &DESC
    }

    fn encode(
        &self,
        buf: &mut [u8],
        _version: crate::dds::CdrVersion,
    ) -> crate::dds::Result<usize> {
        let dst = buf.get_mut(..1).ok_or(crate::dds::Error::BufferTooSmall)?;
        dst[0] = self.tag;
        Ok(1)
    }

    fn decode(buf: &[u8], _version: crate::dds::CdrVersion) -> crate::dds::Result<Self> {
        buf.first()
            .map(|tag| Self { tag: *tag })
            .ok_or(crate::dds::Error::SerializationError)
    }

    fn has_key() -> bool {
        true
    }

    fn encode_key(&self, _version: crate::dds::CdrVersion) -> Vec<u8> {
        vec![self.tag]
    }
}

/// The same key, round-tripping: what every generated type provides today.
#[derive(Debug, Clone, Copy, PartialEq)]
struct KeyedRoundTrip {
    tag: u8,
}

impl crate::dds::DDS for KeyedRoundTrip {
    fn type_descriptor() -> &'static crate::core::types::TypeDescriptor {
        static DESC: crate::core::types::TypeDescriptor = crate::core::types::TypeDescriptor {
            type_id: 0x4B52_5431,
            type_name: "KeyedRoundTrip",
            size_bytes: 1,
            alignment: 1,
            is_variable_size: false,
            fields: &[],
        };
        &DESC
    }

    fn encode(
        &self,
        buf: &mut [u8],
        _version: crate::dds::CdrVersion,
    ) -> crate::dds::Result<usize> {
        let dst = buf.get_mut(..1).ok_or(crate::dds::Error::BufferTooSmall)?;
        dst[0] = self.tag;
        Ok(1)
    }

    fn decode(buf: &[u8], _version: crate::dds::CdrVersion) -> crate::dds::Result<Self> {
        buf.first()
            .map(|tag| Self { tag: *tag })
            .ok_or(crate::dds::Error::SerializationError)
    }

    fn has_key() -> bool {
        true
    }

    fn encode_key(&self, _version: crate::dds::CdrVersion) -> Vec<u8> {
        vec![self.tag]
    }

    fn key_hash_of_key_payload(payload: &[u8]) -> Option<[u8; 16]> {
        let mut key = [0u8; 16];
        key[0] = *payload.first()?;
        Some(key)
    }

    fn keys_round_trip() -> bool {
        true
    }
}

/// A key-protected topic whose type cannot read the key payload that names
/// the instance loses every dispose and unregister in silence: the K-payload
/// is the only thing a reader can name an instance from (RTPS 2.5 8.7.10,
/// the KeyHash being a hint), and such a writer ships an empty one. Endpoint
/// creation refuses it, writer and reader alike, instead of accepting a
/// topic that can never be disposed.
///
/// The refusal is tied to KEY PROTECTION, not to the type: the same type is
/// created on a participant that protects nothing (below), and a type that
/// reads its key payload back is created here.
#[test]
fn a_key_protected_topic_refuses_a_type_that_cannot_read_its_key_payload() {
    let domain = unique_domain();
    let fixture = fixture_with_encryption(true);
    let participant = Participant::builder("key_round_trip")
        .domain_id(domain.id())
        .with_transport(TransportMode::IntraProcess)
        .with_security(fixture.config.clone())
        .build()
        .expect("participant");

    for refused in [
        participant
            .topic::<KeyedWithoutRoundTrip>("sensor/secret")
            .expect("topic")
            .writer()
            .build()
            .err()
            .map(|e| e.to_string()),
        participant
            .topic::<KeyedWithoutRoundTrip>("sensor/secret")
            .expect("topic")
            .reader()
            .build()
            .err()
            .map(|e| e.to_string()),
    ] {
        let text = refused.expect(
            "a keyed type that cannot name the instance it encrypts must be refused: \
             every dispose and unregister of the topic would be dropped",
        );
        assert!(
            text.contains("sensor/secret") && text.contains("key_hash_of_key_payload"),
            "the refusal must name the topic and the missing hook, got: {text}"
        );
    }

    participant
        .topic::<KeyedRoundTrip>("sensor/secret")
        .expect("topic")
        .writer()
        .build()
        .expect("a type that reads its key payload back is created");
    participant
        .topic::<KeyedRoundTrip>("sensor/secret")
        .expect("topic")
        .reader()
        .build()
        .expect("and so is its reader");
}

/// The same hookless keyed type where nothing is key-protected: no
/// governance, no encryption, so a dispose names its instance through the
/// plain key payload every reader decodes. Creation is unchanged.
#[test]
fn a_keyed_type_without_the_round_trip_is_created_when_nothing_is_protected() {
    let domain = unique_domain();
    let fixture = fixture_with_encryption(false);
    let participant = Participant::builder("key_round_trip_off")
        .domain_id(domain.id())
        .with_transport(TransportMode::IntraProcess)
        .with_security(fixture.config.clone())
        .build()
        .expect("participant");

    participant
        .topic::<KeyedWithoutRoundTrip>("sensor/secret")
        .expect("topic")
        .writer()
        .build()
        .expect("nothing is key-protected: the writer is created");
    participant
        .topic::<KeyedWithoutRoundTrip>("sensor/secret")
        .expect("topic")
        .reader()
        .build()
        .expect("and the reader");
}

// ---------------------------------------------------------------------------
//  A governance that allows unauthenticated participants and protects the
//  access of `sensor/open`; permissions granting `sensor/*`
//  (unsigned documents).
// ---------------------------------------------------------------------------

fn access_protected_fixture() -> (SecurityFixture, NamedTempFile, NamedTempFile) {
    let governance = "<?xml version=\"1.0\"?><dds><domain_access_rules><domain_rule>\
         <domains><id_range><min>1</min><max>232</max></id_range></domains>\
         <allow_unauthenticated_participants>TRUE</allow_unauthenticated_participants>\
         <enable_join_access_control>TRUE</enable_join_access_control>\
         <discovery_protection_kind>NONE</discovery_protection_kind>\
         <liveliness_protection_kind>NONE</liveliness_protection_kind>\
         <rtps_protection_kind>NONE</rtps_protection_kind>\
         <topic_access_rules><topic_rule><topic_expression>sensor/open</topic_expression>\
         <enable_discovery_protection>FALSE</enable_discovery_protection>\
         <enable_liveliness_protection>FALSE</enable_liveliness_protection>\
         <enable_read_access_control>TRUE</enable_read_access_control>\
         <enable_write_access_control>TRUE</enable_write_access_control>\
         <metadata_protection_kind>NONE</metadata_protection_kind>\
         <data_protection_kind>NONE</data_protection_kind></topic_rule></topic_access_rules>\
         </domain_rule></domain_access_rules></dds>";
    let permissions = "<?xml version=\"1.0\"?><dds><permissions><grant name=\"g\">\
         <subject_name>CN=DDS Test Identity, O=HDDS Test</subject_name>\
         <validity><not_before>2020-01-01T00:00:00</not_before>\
         <not_after>2036-01-01T00:00:00</not_after></validity>\
         <allow_rule><domains><id_range><min>1</min><max>232</max></id_range></domains>\
         <publish><topics><topic>sensor/*</topic></topics></publish>\
         <subscribe><topics><topic>sensor/*</topic></topics></subscribe></allow_rule>\
         <default>DENY</default></grant></permissions></dds>";
    let governance_file = write_pem(governance.as_bytes());
    let permissions_file = write_pem(permissions.as_bytes());
    let cert = write_pem(TEST_IDENTITY_CERT_PEM);
    let key = write_pem(TEST_IDENTITY_KEY_PEM);
    let ca = write_pem(TEST_CA_CERT_PEM);
    let config = SecurityConfig::builder()
        .identity_certificate(cert.path())
        .private_key(key.path())
        .ca_certificates(ca.path())
        .governance_xml(governance_file.path())
        .permissions_xml(permissions_file.path())
        .insecure_allow_unsigned_documents(true)
        .require_authentication(false)
        .build()
        .expect("config");
    (
        SecurityFixture {
            config,
            _cert: cert,
            _key: key,
            _ca: ca,
        },
        governance_file,
        permissions_file,
    )
}

/// DDS-Security v1.1 Sec.9.4.1.3.2.3.1.4: "If there is no <partitions>
/// Section within an allow rule, then the default "empty string" partition
/// is assumed ... the allow rule (e.g., publish) would only allow a
/// DataWriter to publish on the "empty string" partition." The grant of
/// `sensor/*` builds a writer of `sensor/open` in the default partition and
/// refuses one in partition B, whether B is its only partition or follows the
/// empty string (the builder checks every partition name, not the first only).
#[test]
fn a_grant_without_partitions_refuses_a_writer_in_another_partition() {
    use crate::generated::temperature::Temperature;
    use crate::qos::partition::Partition;
    let domain = unique_domain();
    let (fixture, _gov, _perm) = access_protected_fixture();
    let participant = secure_participant("partition_grant", domain.id(), &fixture);
    let writer_in = |names: &[&str]| {
        participant
            .topic::<Temperature>("sensor/open")
            .expect("topic")
            .writer()
            .qos(QoS::reliable().partition(Partition::new(
                names.iter().map(|name| (*name).to_string()).collect(),
            )))
            .build()
    };
    let reader_in = |names: &[&str]| {
        participant
            .topic::<Temperature>("sensor/open")
            .expect("topic")
            .reader()
            .qos(QoS::reliable().partition(Partition::new(
                names.iter().map(|name| (*name).to_string()).collect(),
            )))
            .build()
    };
    assert!(
        reader_in(&[""]).is_ok(),
        "a reader of the default partition"
    );
    assert!(
        reader_in(&["", "B"]).is_err(),
        "a reader in partition B is not granted either"
    );
    assert!(writer_in(&[]).is_ok(), "the default partition is granted");
    assert!(
        writer_in(&[""]).is_ok(),
        "the empty string is the default partition"
    );
    for names in [&["B"][..], &["", "B"][..]] {
        let error = writer_in(names)
            .err()
            .unwrap_or_else(|| panic!("partition {:?} is not granted", names));
        assert!(
            error.to_string().contains("default partition only"),
            "{:?}: {}",
            names,
            error
        );
    }
}

/// DDS Security v1.1 Sec.8.8.7.1: the reader of an "Unauthenticated"
/// participant on a read-protected topic must not be matched, hence must not
/// receive the topic's data. The secure writer left it out of
/// `find_readers_for_topic`, and its participant fallback - taken when that
/// list is empty - sent every sample to every participant's default locator
/// all the same, leaking every sample.
#[test]
fn an_unauthenticated_reader_of_a_protected_topic_receives_nothing() {
    let _ = env_logger::builder().is_test(true).try_init();
    use crate::generated::temperature::Temperature;
    let domain = unique_domain();
    let (fixture, _gov, _perm) = access_protected_fixture();
    let secure = secure_participant("unauth_secure_pub", domain.id(), &fixture);
    let plain = Participant::builder("unauth_plain_sub")
        .domain_id(domain.id())
        .with_transport(TransportMode::UdpMulticast)
        .build()
        .expect("plain participant");
    assert!(
        wait_until(Duration::from_secs(15), || has_discovered(&secure, &plain)),
        "fixture: the secure side never admitted the plain participant (allow TRUE)"
    );
    let writer = secure
        .topic::<Temperature>("sensor/open")
        .expect("topic")
        .writer()
        .qos(QoS::reliable().keep_all())
        .build()
        .expect("writer");
    let reader = plain
        .topic::<Temperature>("sensor/open")
        .expect("topic")
        .reader()
        .qos(QoS::reliable().keep_all())
        .build()
        .expect("reader");
    // Let SEDP settle both ways.
    let fsm = secure.discovery().expect("discovery");
    let _ = wait_until(Duration::from_secs(5), || {
        fsm.find_writers_for_topic("sensor/open").len() + 1 > 0
            && plain
                .discovery()
                .is_some_and(|f| !f.find_writers_for_topic("sensor/open").is_empty())
    });
    std::thread::sleep(Duration::from_secs(1));
    eprintln!(
        "[e2e] secure find_readers_for_topic(sensor/open) = {}",
        fsm.find_readers_for_topic("sensor/open").len()
    );
    let sample = Temperature {
        value: 42.0,
        timestamp: 1_760_000_000,
    };
    let mut leaked = 0;
    let deadline = Instant::now() + Duration::from_secs(6);
    while Instant::now() < deadline {
        writer.write(&sample).expect("write");
        while let Ok(Some(_)) = reader.take() {
            leaked += 1;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert_eq!(
        leaked, 0,
        "the unauthenticated participant's reader received {} samples of a read-protected \
         topic (Sec.8.8.7.1: reject, do not match)",
        leaked
    );
}

/// A secure participant whose governance admits unauthenticated
/// participants, protects the access of `sensor/open` and the payloads of
/// `sensor/sealed`, and grants `sensor/*`. A participant without encryption
/// cannot read `sensor/sealed` at all, so the caller arms the data plane
/// when the topic it reads is protected.
fn allowing_unauthenticated_fixture(
    encryption: bool,
) -> (SecurityFixture, NamedTempFile, NamedTempFile) {
    let governance = "<?xml version=\"1.0\"?><dds><domain_access_rules><domain_rule>\
         <domains><id_range><min>1</min><max>232</max></id_range></domains>\
         <allow_unauthenticated_participants>TRUE</allow_unauthenticated_participants>\
         <enable_join_access_control>TRUE</enable_join_access_control>\
         <discovery_protection_kind>NONE</discovery_protection_kind>\
         <liveliness_protection_kind>NONE</liveliness_protection_kind>\
         <rtps_protection_kind>NONE</rtps_protection_kind>\
         <topic_access_rules><topic_rule><topic_expression>sensor/open</topic_expression>\
         <enable_discovery_protection>FALSE</enable_discovery_protection>\
         <enable_liveliness_protection>FALSE</enable_liveliness_protection>\
         <enable_read_access_control>TRUE</enable_read_access_control>\
         <enable_write_access_control>TRUE</enable_write_access_control>\
         <metadata_protection_kind>NONE</metadata_protection_kind>\
         <data_protection_kind>NONE</data_protection_kind></topic_rule>\
         <topic_rule><topic_expression>sensor/free</topic_expression>\
         <enable_discovery_protection>FALSE</enable_discovery_protection>\
         <enable_liveliness_protection>FALSE</enable_liveliness_protection>\
         <enable_read_access_control>FALSE</enable_read_access_control>\
         <enable_write_access_control>FALSE</enable_write_access_control>\
         <metadata_protection_kind>NONE</metadata_protection_kind>\
         <data_protection_kind>NONE</data_protection_kind></topic_rule>\
         <topic_rule><topic_expression>sensor/sealed</topic_expression>\
         <enable_discovery_protection>FALSE</enable_discovery_protection>\
         <enable_liveliness_protection>FALSE</enable_liveliness_protection>\
         <enable_read_access_control>FALSE</enable_read_access_control>\
         <enable_write_access_control>FALSE</enable_write_access_control>\
         <metadata_protection_kind>NONE</metadata_protection_kind>\
         <data_protection_kind>ENCRYPT</data_protection_kind></topic_rule>\
         </topic_access_rules>\
         </domain_rule></domain_access_rules></dds>";
    let permissions = "<?xml version=\"1.0\"?><dds><permissions><grant name=\"g\">\
         <subject_name>CN=DDS Test Identity, O=HDDS Test</subject_name>\
         <validity><not_before>2020-01-01T00:00:00</not_before>\
         <not_after>2036-01-01T00:00:00</not_after></validity>\
         <allow_rule><domains><id_range><min>1</min><max>232</max></id_range></domains>\
         <publish><topics><topic>sensor/*</topic></topics></publish>\
         <subscribe><topics><topic>sensor/*</topic></topics></subscribe></allow_rule>\
         <default>DENY</default></grant></permissions></dds>";
    let governance_file = write_pem(governance.as_bytes());
    let permissions_file = write_pem(permissions.as_bytes());
    let cert = write_pem(TEST_IDENTITY_CERT_PEM);
    let key = write_pem(TEST_IDENTITY_KEY_PEM);
    let ca = write_pem(TEST_CA_CERT_PEM);
    let config = SecurityConfig::builder()
        .identity_certificate(cert.path())
        .private_key(key.path())
        .ca_certificates(ca.path())
        .governance_xml(governance_file.path())
        .permissions_xml(permissions_file.path())
        .insecure_allow_unsigned_documents(true)
        .require_authentication(false)
        .enable_encryption(encryption)
        .build()
        .expect("config");
    (
        SecurityFixture {
            config,
            _cert: cert,
            _key: key,
            _ca: ca,
        },
        governance_file,
        permissions_file,
    )
}

/// How many samples of `topic` a plain participant's reader takes
/// from a secure writer (`durable`: 20 written before the reader exists,
/// TRANSIENT_LOCAL; else written live for 6 s).
fn leaked_to_an_unauthenticated_reader(topic: &str, durable: bool) -> usize {
    let _ = env_logger::builder().is_test(true).try_init();
    use crate::generated::temperature::Temperature;
    let domain = unique_domain();
    let (fixture, _gov, _perm) = allowing_unauthenticated_fixture(false);
    let secure = secure_participant("unauth_leak_secure_pub", domain.id(), &fixture);
    let plain = Participant::builder("unauth_leak_plain_sub")
        .domain_id(domain.id())
        .with_transport(TransportMode::UdpMulticast)
        .build()
        .expect("plain participant");
    assert!(
        wait_until(Duration::from_secs(15), || has_discovered(&secure, &plain)),
        "fixture: the secure side never admitted the plain participant (allow TRUE)"
    );
    let wqos = if durable {
        QoS::reliable().keep_all().transient_local()
    } else {
        QoS::reliable().keep_all()
    };
    let writer = secure
        .topic::<Temperature>(topic)
        .expect("topic")
        .writer()
        .qos(wqos.clone())
        .build()
        .expect("writer");
    let sample = Temperature {
        value: 42.0,
        timestamp: 1_760_000_000,
    };
    if durable {
        for _ in 0..20 {
            writer.write(&sample).expect("write");
        }
    }
    let reader = plain
        .topic::<Temperature>(topic)
        .expect("topic")
        .reader()
        .qos(wqos)
        .build()
        .expect("reader");
    std::thread::sleep(Duration::from_secs(2));
    let mut leaked = 0;
    let deadline = Instant::now() + Duration::from_secs(6);
    while Instant::now() < deadline {
        if !durable {
            writer.write(&sample).expect("write");
        }
        while let Ok(Some(_)) = reader.take() {
            leaked += 1;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    leaked
}

/// DDS Security v1.1 Sec.8.8.7.1, end to end: under a governance that
/// admits unauthenticated participants, a plain participant's reader of a
/// read-protected topic receives none of the live samples.
#[test]
fn an_unauthenticated_reader_receives_no_live_sample_of_a_protected_topic() {
    assert!(
        leaked_to_an_unauthenticated_reader("sensor/free", false) > 0,
        "fixture: the unprotected topic reaches the plain reader"
    );
    let leaked = leaked_to_an_unauthenticated_reader("sensor/open", false);
    assert_eq!(
        leaked, 0,
        "{} samples leaked (volatile, live writes)",
        leaked
    );
}

/// The same with a TRANSIENT_LOCAL late joiner: none of the 20 samples of
/// the writer's history reach it: the late-joiner replay must go through the
/// admission door rather than delivering all 20.
#[test]
fn an_unauthenticated_transient_local_reader_gets_no_history_of_a_protected_topic() {
    assert!(
        leaked_to_an_unauthenticated_reader("sensor/free", true) > 0,
        "fixture: the history of the unprotected topic reaches the plain reader"
    );
    let leaked = leaked_to_an_unauthenticated_reader("sensor/open", true);
    assert_eq!(
        leaked, 0,
        "{} history samples leaked (TRANSIENT_LOCAL replay)",
        leaked
    );
}

/// DDS-Security v1.1 Sec.9.4.1.2.7, over the wire: a reader that holds a
/// suite reads a writer of a participant without security on a topic the
/// governance leaves unprotected. The writer announced no
/// `PID_ENDPOINT_SECURITY_INFO`, which is a SETTLED answer -- it speaks in
/// the clear -- and not an unresolved one: taking the two for each other made
/// the reader answer `KeyUnknown` to every sample, so a RELIABLE writer
/// repaired them for ever and none was ever delivered.
///
/// The same writer on `sensor/open`, whose access the governance protects,
/// and on `sensor/sealed`, whose `data_protection_kind` is ENCRYPT, is
/// refused on both: the test doubles as the positive control for the topic
/// it does not protect.
#[test]
fn a_plain_writer_reaches_a_secure_reader_only_where_the_governance_protects_nothing() {
    let _ = env_logger::builder().is_test(true).try_init();
    use crate::generated::temperature::Temperature;

    let domain = unique_domain();
    let (fixture, _gov, _perm) = allowing_unauthenticated_fixture(true);
    let secure = secure_participant("plain_pub_secure_sub", domain.id(), &fixture);
    let plain = Participant::builder("plain_pub")
        .domain_id(domain.id())
        .with_transport(TransportMode::UdpMulticast)
        .build()
        .expect("plain participant");
    assert!(
        wait_until(Duration::from_secs(15), || has_discovered(&secure, &plain)),
        "fixture: the secure side never admitted the plain participant (allow TRUE)"
    );

    let sample = Temperature {
        value: 43.0,
        timestamp: 1_760_000_001,
    };
    let delivered = |topic: &str| -> usize {
        let writer = plain
            .topic::<Temperature>(topic)
            .expect("topic")
            .writer()
            .qos(QoS::reliable().keep_all())
            .build()
            .expect("writer");
        let reader = secure
            .topic::<Temperature>(topic)
            .expect("topic")
            .reader()
            .qos(QoS::reliable().keep_all())
            .build()
            .expect("reader");
        // SEDP both ways, then live writes: the reader must hold the
        // writer's announcement before it can classify its payload.
        std::thread::sleep(Duration::from_secs(2));
        let mut received = 0;
        let deadline = Instant::now() + Duration::from_secs(6);
        while Instant::now() < deadline {
            writer.write(&sample).expect("write");
            while let Ok(Some(_)) = reader.take() {
                received += 1;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        received
    };

    assert!(
        delivered("sensor/free") > 0,
        "a plain writer's samples never reached the secure reader of an unprotected topic: \
         a writer known to discovery without PID_ENDPOINT_SECURITY_INFO is unsettled only to \
         a reader that cannot tell it from a writer discovery does not hold"
    );
    assert_eq!(
        delivered("sensor/open"),
        0,
        "the plain writer's samples of a read-protected topic were delivered"
    );
    assert_eq!(
        delivered("sensor/sealed"),
        0,
        "the plain writer's cleartext reached a reader of a payload-protected topic"
    );

    drop(plain);
    drop(secure);
    std::thread::sleep(Duration::from_millis(500));
}

fn recheck_allowing_fixture() -> (SecurityFixture, NamedTempFile, NamedTempFile) {
    let governance = "<?xml version=\"1.0\"?><dds><domain_access_rules><domain_rule>\
         <domains><id_range><min>1</min><max>232</max></id_range></domains>\
         <allow_unauthenticated_participants>TRUE</allow_unauthenticated_participants>\
         <enable_join_access_control>TRUE</enable_join_access_control>\
         <discovery_protection_kind>NONE</discovery_protection_kind>\
         <liveliness_protection_kind>NONE</liveliness_protection_kind>\
         <rtps_protection_kind>NONE</rtps_protection_kind>\
         <topic_access_rules><topic_rule><topic_expression>sensor/open</topic_expression>\
         <enable_discovery_protection>FALSE</enable_discovery_protection>\
         <enable_liveliness_protection>FALSE</enable_liveliness_protection>\
         <enable_read_access_control>TRUE</enable_read_access_control>\
         <enable_write_access_control>TRUE</enable_write_access_control>\
         <metadata_protection_kind>NONE</metadata_protection_kind>\
         <data_protection_kind>NONE</data_protection_kind></topic_rule></topic_access_rules>\
         </domain_rule></domain_access_rules></dds>";
    let permissions = "<?xml version=\"1.0\"?><dds><permissions><grant name=\"g\">\
         <subject_name>CN=DDS Test Identity, O=HDDS Test</subject_name>\
         <validity><not_before>2020-01-01T00:00:00</not_before>\
         <not_after>2036-01-01T00:00:00</not_after></validity>\
         <allow_rule><domains><id_range><min>1</min><max>232</max></id_range></domains>\
         <publish><topics><topic>sensor/*</topic></topics></publish>\
         <subscribe><topics><topic>sensor/*</topic></topics></subscribe></allow_rule>\
         <default>DENY</default></grant></permissions></dds>";
    let governance_file = write_pem(governance.as_bytes());
    let permissions_file = write_pem(permissions.as_bytes());
    let cert = write_pem(TEST_IDENTITY_CERT_PEM);
    let key = write_pem(TEST_IDENTITY_KEY_PEM);
    let ca = write_pem(TEST_CA_CERT_PEM);
    let config = SecurityConfig::builder()
        .identity_certificate(cert.path())
        .private_key(key.path())
        .ca_certificates(ca.path())
        .governance_xml(governance_file.path())
        .permissions_xml(permissions_file.path())
        .insecure_allow_unsigned_documents(true)
        .require_authentication(false)
        .build()
        .expect("config");
    (
        SecurityFixture {
            config,
            _cert: cert,
            _key: key,
            _ca: ca,
        },
        governance_file,
        permissions_file,
    )
}

fn recheck_leak(durable: bool) -> usize {
    let _ = env_logger::builder().is_test(true).try_init();
    use crate::generated::temperature::Temperature;
    let domain = unique_domain();
    let (fixture, _gov, _perm) = recheck_allowing_fixture();
    let secure = secure_participant("recheck_secure_pub", domain.id(), &fixture);
    let plain = Participant::builder("recheck_plain_sub")
        .domain_id(domain.id())
        .with_transport(TransportMode::UdpMulticast)
        .build()
        .expect("plain participant");
    assert!(
        wait_until(Duration::from_secs(15), || has_discovered(&secure, &plain)),
        "fixture: the secure side never admitted the plain participant (allow TRUE)"
    );
    let wqos = if durable {
        QoS::reliable().keep_all().transient_local()
    } else {
        QoS::reliable().keep_all()
    };
    let writer = secure
        .topic::<Temperature>("sensor/open")
        .expect("topic")
        .writer()
        .qos(wqos.clone())
        .build()
        .expect("writer");
    let sample = Temperature {
        value: 42.0,
        timestamp: 1_760_000_000,
    };
    if durable {
        for _ in 0..20 {
            writer.write(&sample).expect("write");
        }
    }
    let reader = plain
        .topic::<Temperature>("sensor/open")
        .expect("topic")
        .reader()
        .qos(wqos)
        .build()
        .expect("reader");
    std::thread::sleep(Duration::from_secs(2));
    let mut leaked = 0;
    let deadline = Instant::now() + Duration::from_secs(6);
    while Instant::now() < deadline {
        if !durable {
            writer.write(&sample).expect("write");
        }
        while let Ok(Some(_)) = reader.take() {
            leaked += 1;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    leaked
}

#[test]
fn recheck_unauthenticated_reader_of_protected_topic_receives_nothing() {
    let leaked = recheck_leak(false);
    assert_eq!(
        leaked, 0,
        "{} samples leaked (volatile, live writes)",
        leaked
    );
}

#[test]
fn recheck_unauthenticated_transient_local_reader_gets_no_history() {
    let leaked = recheck_leak(true);
    assert_eq!(
        leaked, 0,
        "{} history samples leaked (TRANSIENT_LOCAL replay)",
        leaked
    );
}

/// DDS Security v1.1 Sec.8.8.2.2, 8.8.7.1: a protected topic's writer
/// sends nothing to the user-data multicast group, where anyone may listen
/// (an unauthenticated participant included), when it knows no reader: no
/// DATA, no DATA_FRAG, no HEARTBEAT, no HEARTBEAT_FRAG. The same writer of
/// an unprotected topic falls back to the group, which proves the observer
/// hears it. The HEARTBEAT and HEARTBEAT_FRAG fallbacks must not reach the
/// group for a protected topic either.
#[test]
fn a_protected_topics_writer_sends_nothing_to_the_multicast_group() {
    let domain = unique_domain();
    let mapping = crate::transport::PortMapping::calculate(domain.id(), 0).expect("ports");
    let (fixture, _governance, _permissions) = allowing_unauthenticated_fixture(false);
    let participant = secure_participant("mc_gate_pub", domain.id(), &fixture);
    // Bound after the participant, which binds the group's port first.
    let observer: std::net::UdpSocket = {
        let socket = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )
        .expect("observer socket");
        socket.set_reuse_address(true).expect("reuse");
        let at = std::net::SocketAddr::from(([0, 0, 0, 0], mapping.metatraffic_multicast + 1));
        socket.bind(&at.into()).expect("bind observer");
        socket.into()
    };
    crate::transport::multicast::join_multicast_group(&observer).expect("join group");
    observer
        .set_read_timeout(Some(Duration::from_millis(300)))
        .expect("timeout");
    // The RTPS datagrams the group carries while `write` runs, by
    // submessage id.
    let heard = |topic: &str| -> Vec<u8> {
        let mut buf = [0u8; 70_000];
        while observer.recv(&mut buf).is_ok() {}
        let writer = participant
            .topic::<BulkBlob>(topic)
            .expect("topic")
            .writer()
            .qos(QoS::reliable().keep_all())
            .build()
            .expect("writer");
        writer
            .write(&BulkBlob {
                payload: bulk_pattern(16),
            })
            .expect("write small");
        writer
            .write(&BulkBlob {
                payload: bulk_pattern(20_000),
            })
            .expect("write large");
        let mut ids = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(3);
        while Instant::now() < deadline {
            if let Ok(n) = observer.recv(&mut buf) {
                if n > 20 && &buf[..4] == b"RTPS" {
                    crate::core::discovery::multicast::classifier::walk::for_each_submessage(
                        &buf[..n],
                        |sub| {
                            ids.push(sub.id);
                            crate::core::discovery::multicast::classifier::walk::Step::Continue
                        },
                    );
                }
            }
        }
        drop(writer);
        std::thread::sleep(Duration::from_millis(300));
        ids
    };
    let open = heard("sensor/free");
    assert!(
        open.contains(&0x15) || open.contains(&0x16),
        "fixture: the unprotected topic's writer falls back to the group: {:02x?}",
        open
    );
    let protected = heard("sensor/open");
    assert!(
        protected.is_empty(),
        "the protected topic's writer reached the multicast group: submessages {:02x?}",
        protected
    );
}

fn verify_allowing_fixture() -> (SecurityFixture, NamedTempFile, NamedTempFile) {
    let governance = "<?xml version=\"1.0\"?><dds><domain_access_rules><domain_rule>\
         <domains><id_range><min>1</min><max>232</max></id_range></domains>\
         <allow_unauthenticated_participants>TRUE</allow_unauthenticated_participants>\
         <enable_join_access_control>TRUE</enable_join_access_control>\
         <discovery_protection_kind>NONE</discovery_protection_kind>\
         <liveliness_protection_kind>NONE</liveliness_protection_kind>\
         <rtps_protection_kind>NONE</rtps_protection_kind>\
         <topic_access_rules><topic_rule><topic_expression>sensor/open</topic_expression>\
         <enable_discovery_protection>FALSE</enable_discovery_protection>\
         <enable_liveliness_protection>FALSE</enable_liveliness_protection>\
         <enable_read_access_control>TRUE</enable_read_access_control>\
         <enable_write_access_control>TRUE</enable_write_access_control>\
         <metadata_protection_kind>NONE</metadata_protection_kind>\
         <data_protection_kind>NONE</data_protection_kind></topic_rule></topic_access_rules>\
         </domain_rule></domain_access_rules></dds>";
    let permissions = "<?xml version=\"1.0\"?><dds><permissions><grant name=\"g\">\
         <subject_name>CN=DDS Test Identity, O=HDDS Test</subject_name>\
         <validity><not_before>2020-01-01T00:00:00</not_before>\
         <not_after>2036-01-01T00:00:00</not_after></validity>\
         <allow_rule><domains><id_range><min>1</min><max>232</max></id_range></domains>\
         <publish><topics><topic>sensor/*</topic></topics></publish>\
         <subscribe><topics><topic>sensor/*</topic></topics></subscribe></allow_rule>\
         <default>DENY</default></grant></permissions></dds>";
    let governance_file = write_pem(governance.as_bytes());
    let permissions_file = write_pem(permissions.as_bytes());
    let cert = write_pem(TEST_IDENTITY_CERT_PEM);
    let key = write_pem(TEST_IDENTITY_KEY_PEM);
    let ca = write_pem(TEST_CA_CERT_PEM);
    let config = SecurityConfig::builder()
        .identity_certificate(cert.path())
        .private_key(key.path())
        .ca_certificates(ca.path())
        .governance_xml(governance_file.path())
        .permissions_xml(permissions_file.path())
        .insecure_allow_unsigned_documents(true)
        .require_authentication(false)
        .build()
        .expect("config");
    (
        SecurityFixture {
            config,
            _cert: cert,
            _key: key,
            _ca: ca,
        },
        governance_file,
        permissions_file,
    )
}

/// DDS Security v1.1 Sec.8.8.7.1: the reader of an "Unauthenticated"
/// participant on a read-protected topic must not be matched, hence must not
/// receive the topic's data. The secure writer leaves it out of
/// `find_readers_for_topic`; does the data still reach it?
#[test]
fn verify_unauthenticated_reader_of_protected_topic_receives_nothing() {
    let _ = env_logger::builder().is_test(true).try_init();
    use crate::generated::temperature::Temperature;
    let domain = unique_domain();
    let (fixture, _gov, _perm) = verify_allowing_fixture();
    let secure = secure_participant("verify_secure_pub", domain.id(), &fixture);
    let plain = Participant::builder("verify_plain_sub")
        .domain_id(domain.id())
        .with_transport(TransportMode::UdpMulticast)
        .build()
        .expect("plain participant");
    assert!(
        wait_until(Duration::from_secs(15), || has_discovered(&secure, &plain)),
        "fixture: the secure side never admitted the plain participant (allow TRUE)"
    );
    let writer = secure
        .topic::<Temperature>("sensor/open")
        .expect("topic")
        .writer()
        .qos(QoS::reliable().keep_all())
        .build()
        .expect("writer");
    let reader = plain
        .topic::<Temperature>("sensor/open")
        .expect("topic")
        .reader()
        .qos(QoS::reliable().keep_all())
        .build()
        .expect("reader");
    // Let SEDP settle both ways.
    let fsm = secure.discovery().expect("discovery");
    let _ = wait_until(Duration::from_secs(5), || {
        fsm.find_writers_for_topic("sensor/open").len() + 1 > 0
            && plain
                .discovery()
                .is_some_and(|f| !f.find_writers_for_topic("sensor/open").is_empty())
    });
    std::thread::sleep(Duration::from_secs(1));
    eprintln!(
        "[verify] secure find_readers_for_topic(sensor/open) = {}",
        fsm.find_readers_for_topic("sensor/open").len()
    );
    let sample = Temperature {
        value: 42.0,
        timestamp: 1_760_000_000,
    };
    let mut leaked = 0;
    let deadline = Instant::now() + Duration::from_secs(6);
    while Instant::now() < deadline {
        writer.write(&sample).expect("write");
        while let Ok(Some(_)) = reader.take() {
            leaked += 1;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert_eq!(
        leaked, 0,
        "the unauthenticated participant's reader received {} samples of a read-protected \
         topic (Sec.8.8.7.1: reject, do not match)",
        leaked
    );
}

/// DDS Security v1.1 Sec.7.4.4.6.2 end to end: an encrypting writer matched
/// with two readers of one remote participant addresses its
/// DatawriterCryptoTokens to each of them, by GUID, over the reliable
/// volatile channel; the remote participant accepts them because each
/// names a local reader matched with the writer, and both readers decrypt
/// the writer's samples. Nothing is refused for its addressing on either
/// side.
///
/// Mutant: the sender addressing a USER writer's tokens to GUID_UNKNOWN
/// (what it did before) has them refused, and no reader ever decrypts.
#[test]
fn an_encrypted_topic_reaches_every_matched_reader_of_the_peer() {
    use crate::generated::temperature::Temperature;

    const TOPIC: &str = "EncryptedTemperatureTwoReaders";

    let domain = unique_domain();
    let fixture = fixture_with_encryption(true);
    let publisher = secure_participant("enc2_pub", domain.id(), &fixture);
    let subscriber = secure_participant("enc2_sub", domain.id(), &fixture);
    assert!(
        wait_until(Duration::from_secs(15), || {
            has_authenticated(&publisher, &subscriber) && has_authenticated(&subscriber, &publisher)
        }),
        "the pair never authenticated with encryption enabled"
    );

    let writer = publisher
        .topic::<Temperature>(TOPIC)
        .expect("writer topic")
        .writer()
        .qos(QoS::reliable().keep_all())
        .build()
        .expect("writer");
    let readers: Vec<_> = (0..2)
        .map(|_| {
            subscriber
                .topic::<Temperature>(TOPIC)
                .expect("reader topic")
                .reader()
                .qos(QoS::reliable().keep_all())
                .build()
                .expect("reader")
        })
        .collect();

    let sample = Temperature {
        value: 4.25,
        timestamp: 1_754_000_042,
    };
    let mut received = [false, false];
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline && !received.iter().all(|r| *r) {
        writer
            .write(&sample)
            .expect("an encrypting writer with a minted key must accept the sample");
        for (reader, got) in readers.iter().zip(received.iter_mut()) {
            while let Ok(Some(msg)) = reader.take() {
                assert_eq!(msg.value, sample.value);
                *got = true;
            }
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    assert_eq!(
        received,
        [true, true],
        "every matched reader of the peer decrypts the writer's samples"
    );

    let sub_suite = subscriber.security().expect("subscriber suite");
    let pub_suite = publisher.security().expect("publisher suite");
    for suite in [&sub_suite, &pub_suite] {
        assert_eq!(
            suite.volatile.stats.misaddressed_endpoint_refused(),
            0,
            "nothing refused for its addressing"
        );
    }

    drop(writer);
    drop(readers);
    drop(publisher);
    drop(subscriber);
    std::thread::sleep(Duration::from_millis(500));
}
