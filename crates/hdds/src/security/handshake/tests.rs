// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Integration tests for the 3-message PKI-DH handshake state machine.
//!
//! # These tests only ever run WITH the `security` feature
//!
//! This module is reached through `security/mod.rs`, whose `pub mod handshake;`
//! is `#[cfg(feature = "security")]`. There is no feature-off build of this
//! file, and there are no crypto stubs behind it: `validate_cert_chain` and
//! `verify_sig` in `machine.rs` are the real `x509-parser` + `ring`
//! implementations in every configuration this module compiles in.
//!
//! A test gated on `#[cfg(not(feature = "security"))]` here would combine with
//! the module's own gate into an unsatisfiable predicate: it would never be
//! compiled, let alone run, while appearing in the file as coverage of the
//! full handshake, the replay window and the retry timer. Every test therefore
//! runs against the real PKI material in [`crate::security::test_pki`].
//!
//! Two classes of test live here:
//! - those that stop before any crypto call (role guard, challenge echoes,
//!   missing-state errors, parse errors) and use the `dummy_*` helpers;
//! - those that must reach cert validation, ECDSA and ECDH, and use the
//!   `real_*` helpers.

#[cfg(test)]
mod fsm_tests {
    use crate::core::discovery::GUID;
    use crate::security::audit::{AuditChain, LoggingPlugin, SharedAuditLogger};
    use crate::security::handshake::machine::{HandshakeAction, HandshakeMachine};
    use crate::security::handshake::tokens::{
        encode_final, encode_reply, encode_request, parse_token, AuthFinalToken, AuthRequestToken,
        TokenKind,
    };
    use std::fs;
    use std::sync::Arc;
    use std::time::{Duration, Instant};
    use tempfile::NamedTempFile;

    // --------------------------------------------------------
    //  Helpers
    // --------------------------------------------------------

    /// A participant GUID whose prefix is bound to the test identity
    /// (`test_pki::bound_test_prefix`), ordered as `prefix_byte`.
    fn make_guid(prefix_byte: u8) -> GUID {
        GUID::new(
            crate::security::test_pki::bound_test_prefix([prefix_byte; 6]),
            [0, 0, 0x01, 0xC1],
        )
    }

    /// Dummy DER bytes that pass the cert-chain stub.
    fn dummy_cert() -> Vec<u8> {
        vec![0x30, 0x82, 0x01, 0xAA, 0xBB]
    }

    /// Dummy PEM key bytes that the non-security sign_data stub accepts.
    fn dummy_key_pem() -> Vec<u8> {
        b"-----BEGIN EC PRIVATE KEY-----\ntest\n-----END EC PRIVATE KEY-----\n".to_vec()
    }

    fn dummy_ca_pem() -> Vec<u8> {
        b"-----BEGIN CERTIFICATE-----\ndummy\n-----END CERTIFICATE-----\n".to_vec()
    }

    fn audit_fixture() -> (NamedTempFile, SharedAuditLogger) {
        let file = NamedTempFile::new().expect("create audit fixture");
        let logger = LoggingPlugin::with_file(file.path()).expect("open audit fixture");
        (file, Arc::new(AuditChain::new(logger)))
    }

    /// A chain over `/dev/full`: opens, then loses every record.
    #[cfg(target_os = "linux")]
    fn degrading_audit_fixture() -> SharedAuditLogger {
        let sink = fs::File::create("/dev/full").expect("/dev/full opens on linux");
        Arc::new(AuditChain::new(LoggingPlugin::over_file_for_tests(sink)))
    }

    // --------------------------------------------------------
    //  Real PKI material, for the tests that reach the crypto
    // --------------------------------------------------------
    //
    // Both peers deliberately present the SAME identity. The handshake never
    // compares the two certificates against each other -- each side validates
    // what it received against the CA and verifies a signature with the public
    // key inside it -- so one identity exercises every cryptographic step:
    // chain validation, ECDSA-P256 sign, ECDSA-P256 verify, ECDH and HKDF.
    // Distinct identities would prove something about PKI provisioning, which
    // is not what these tests are about.
    //
    // The field is named `identity_cert_der` but `machine.rs` parses it with
    // `parse_x509_pem`, so this must be the PEM text.

    fn real_cert() -> Vec<u8> {
        crate::security::test_pki::TEST_IDENTITY_CERT_PEM.to_vec()
    }

    fn real_key_pem() -> Vec<u8> {
        crate::security::test_pki::TEST_IDENTITY_KEY_PEM.to_vec()
    }

    fn real_ca_pem() -> Vec<u8> {
        crate::security::test_pki::TEST_CA_CERT_PEM.to_vec()
    }

    // --------------------------------------------------------
    //  Full round-trip: initiator (high GUID) + responder (low GUID)
    //
    //  Real PKI end to end: X.509 chain validation, ECDSA-P256 signature over
    //  the AuthReply and the AuthFinal, ECDH-P256 and HKDF on both sides. This
    //  is the test that proves the state machine can actually reach `Complete`;
    //  until the `#[cfg(not(feature = "security"))]` below was removed it had
    //  never been compiled.
    // --------------------------------------------------------

    #[test]
    fn full_handshake_both_sides_complete() {
        let initiator_guid = make_guid(0x00); // high -> Initiator
        let responder_guid = make_guid(0xFE); // low  -> Responder

        let (audit_file, audit) = audit_fixture();
        let init_machine = HandshakeMachine::new().with_audit_logger(Some(audit.clone()));
        let resp_machine = HandshakeMachine::new().with_audit_logger(Some(audit));

        let init_cert = real_cert();
        let init_key = real_key_pem();
        let resp_cert = real_cert();
        let resp_key = real_key_pem();
        let ca = real_ca_pem();

        // Step 1: Initiator starts, produces AuthRequest.
        let action = init_machine
            .start(initiator_guid, responder_guid, &init_cert, &init_key)
            .expect("start should succeed");

        let req_token = match action.expect("initiator should produce SendRequest") {
            HandshakeAction::SendRequest(guid, tok) => {
                assert_eq!(guid, responder_guid);
                tok
            }
            other => panic!(
                "expected SendRequest, got {:?}",
                std::mem::discriminant(&other)
            ),
        };

        // Step 2: Responder receives AuthRequest, produces AuthReply.
        let req_bytes = encode_request(&req_token).expect("encode");
        let resp_action = resp_machine
            .on_message(
                initiator_guid,
                &req_bytes,
                responder_guid,
                &resp_cert,
                &resp_key,
                &ca,
            )
            .expect("on_message(req) should succeed");

        let reply_token = match resp_action {
            HandshakeAction::SendReply(guid, tok) => {
                assert_eq!(guid, initiator_guid);
                tok
            }
            other => panic!(
                "expected SendReply, got {:?}",
                std::mem::discriminant(&other)
            ),
        };

        // Verify responder is in ReplySent state (not yet Complete).
        assert!(!resp_machine.is_authenticated(&initiator_guid));

        // Step 3: Initiator receives AuthReply, produces AuthFinal.
        let reply_bytes = encode_reply(&reply_token).expect("encode");
        let init_action = init_machine
            .on_message(
                responder_guid,
                &reply_bytes,
                initiator_guid,
                &init_cert,
                &init_key,
                &ca,
            )
            .expect("on_message(reply) should succeed");

        let final_token = match init_action {
            HandshakeAction::SendFinal(guid, tok) => {
                assert_eq!(guid, responder_guid);
                tok
            }
            other => panic!(
                "expected SendFinal, got {:?}",
                std::mem::discriminant(&other)
            ),
        };

        // Initiator is now Complete.
        assert!(init_machine.is_authenticated(&responder_guid));

        // Step 4: Responder receives AuthFinal, completes.
        let final_bytes = encode_final(&final_token).expect("encode");
        let resp_final_action = resp_machine
            .on_message(
                initiator_guid,
                &final_bytes,
                responder_guid,
                &resp_cert,
                &resp_key,
                &ca,
            )
            .expect("on_message(final) should succeed");

        let responder_secret = match resp_final_action {
            HandshakeAction::Completed(guid, secret) => {
                assert_eq!(guid, initiator_guid);
                secret
            }
            other => panic!(
                "expected Completed, got {:?}",
                std::mem::discriminant(&other)
            ),
        };

        assert!(resp_machine.is_authenticated(&initiator_guid));

        // The point of the whole exchange: both sides must hold the SAME
        // MasterSharedSecret. The original test only checked that the
        // responder's copy was non-empty, which two peers that agreed on
        // nothing would also satisfy.
        //
        // The salts are built in opposite orders on the two sides
        // (`our_nonce || challenge2` in handle_reply, `peer_nonce || our_nonce`
        // in handle_final) and are equal only because challenge1 is stored as
        // peer_nonce and challenge2 is sent as our_nonce. That symmetry is the
        // thing worth pinning; an inverted concatenation would still produce
        // two plausible 32-byte secrets that never match.
        let initiator_secret = init_machine
            .shared_secret_for(&responder_guid)
            .expect("initiator must hold a shared secret after Complete");
        assert_eq!(
            initiator_secret.as_bytes().len(),
            32,
            "ECDH+prime256v1 through HKDF-SHA256 yields a 32-byte master secret"
        );
        assert_eq!(
            initiator_secret, responder_secret,
            "both sides must derive the identical MasterSharedSecret"
        );

        let records = fs::read_to_string(audit_file.path()).expect("read audit records");
        assert_eq!(
            records.matches("Authentication").count(),
            2,
            "each peer must record its one genuine completion transition"
        );
        assert_eq!(records.matches("outcome: Success").count(), 2);
    }

    /// AUD-1: the first lost record closes the machine to any further
    /// handshake, on both roles, until the participant is rebuilt. The
    /// session whose record was lost stays Complete (the transition had
    /// committed); nothing new is started or advanced afterwards.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_degraded_audit_chain_refuses_new_handshakes() {
        let initiator_guid = make_guid(0x00);
        let responder_guid = make_guid(0xFE);
        let third_guid = make_guid(0xFD);

        let audit = degrading_audit_fixture();
        let init_machine = HandshakeMachine::new().with_audit_logger(Some(audit.clone()));
        let resp_machine = HandshakeMachine::new().with_audit_logger(Some(audit.clone()));

        let cert = real_cert();
        let key = real_key_pem();
        let ca = real_ca_pem();

        // Nothing has been recorded yet: both roles are open for business.
        let req_token = match init_machine
            .start(initiator_guid, responder_guid, &cert, &key)
            .expect("start before any lost record")
            .expect("initiator role")
        {
            HandshakeAction::SendRequest(_, tok) => tok,
            other => panic!(
                "expected SendRequest, got {:?}",
                std::mem::discriminant(&other)
            ),
        };
        let reply_token = match resp_machine
            .on_message(
                initiator_guid,
                &encode_request(&req_token).expect("encode"),
                responder_guid,
                &cert,
                &key,
                &ca,
            )
            .expect("responder accepts the request")
        {
            HandshakeAction::SendReply(_, tok) => tok,
            other => panic!(
                "expected SendReply, got {:?}",
                std::mem::discriminant(&other)
            ),
        };
        assert!(
            !audit.is_degraded(),
            "no terminal transition has happened yet"
        );

        // The initiator completes: its Success record is the first write and
        // it is lost. The session stays Complete; the chain is now degraded.
        let final_token = match init_machine
            .on_message(
                responder_guid,
                &encode_reply(&reply_token).expect("encode"),
                initiator_guid,
                &cert,
                &key,
                &ca,
            )
            .expect("the committed transition is never reversed by audit I/O")
        {
            HandshakeAction::SendFinal(_, tok) => tok,
            other => panic!(
                "expected SendFinal, got {:?}",
                std::mem::discriminant(&other)
            ),
        };
        assert!(init_machine.is_authenticated(&responder_guid));
        assert!(
            audit.is_degraded(),
            "the lost record must degrade the chain"
        );

        // Responder side: the shared chain is degraded, so the AuthFinal that
        // would complete its session is refused and it never authenticates.
        let error = resp_machine
            .on_message(
                initiator_guid,
                &encode_final(&final_token).expect("encode"),
                responder_guid,
                &cert,
                &key,
                &ca,
            )
            .expect_err("a degraded chain refuses to advance any handshake");
        assert!(
            error.to_string().contains("audit chain degraded"),
            "{}",
            error
        );
        assert!(!resp_machine.is_authenticated(&initiator_guid));

        // Initiator side: no new handshake toward anyone.
        let error = init_machine
            .start(initiator_guid, third_guid, &cert, &key)
            .expect_err("a degraded chain refuses to start a handshake");
        assert!(
            error.to_string().contains("audit chain degraded"),
            "{}",
            error
        );
        assert!(!init_machine.has_session(&third_guid));
    }

    // --------------------------------------------------------
    //  P-384 suite: full handshake + the fail-closed policy (TODO 2.3)
    // --------------------------------------------------------

    /// The P-384 sibling of `full_handshake_both_sides_complete`: both sides
    /// configured for ECDH+secp384r1-CEUM must complete and agree on a
    /// 48-byte HKDF-SHA384 master secret. The length assertion is the pin:
    /// a silent fallback to P-256 anywhere in the chain yields 32 bytes and
    /// fails here rather than passing as "some secret exists".
    #[test]
    fn full_p384_handshake_yields_a_48_byte_shared_secret() {
        const P384: &str = "ECDH+secp384r1-CEUM";
        let initiator_guid = make_guid(0x00);
        let responder_guid = make_guid(0xFE);

        let init_machine = HandshakeMachine::with_kagree_algo(P384);
        let resp_machine = HandshakeMachine::with_kagree_algo(P384);

        let init_cert = real_cert();
        let init_key = real_key_pem();
        let resp_cert = real_cert();
        let resp_key = real_key_pem();
        let ca = real_ca_pem();

        let action = init_machine
            .start(initiator_guid, responder_guid, &init_cert, &init_key)
            .expect("start should succeed");
        let req_token = match action.expect("initiator should produce SendRequest") {
            HandshakeAction::SendRequest(_, tok) => tok,
            other => panic!(
                "expected SendRequest, got {:?}",
                std::mem::discriminant(&other)
            ),
        };
        assert_eq!(
            req_token.kagree_algo, P384,
            "the configured suite must ride the AuthRequest verbatim"
        );
        assert_eq!(
            req_token.dh1.len(),
            97,
            "a P-384 handshake must carry a 97-byte uncompressed public key, \
             not a P-256 one wearing the wrong label"
        );

        let resp_action = resp_machine
            .on_message(
                initiator_guid,
                &encode_request(&req_token).expect("encode"),
                responder_guid,
                &resp_cert,
                &resp_key,
                &ca,
            )
            .expect("on_message(req) should succeed");
        let reply_token = match resp_action {
            HandshakeAction::SendReply(_, tok) => tok,
            other => panic!(
                "expected SendReply, got {:?}",
                std::mem::discriminant(&other)
            ),
        };
        assert_eq!(
            reply_token.dh2.len(),
            97,
            "the responder must answer on the same curve"
        );

        let init_action = init_machine
            .on_message(
                responder_guid,
                &encode_reply(&reply_token).expect("encode"),
                initiator_guid,
                &init_cert,
                &init_key,
                &ca,
            )
            .expect("on_message(reply) should succeed");
        let final_token = match init_action {
            HandshakeAction::SendFinal(_, tok) => tok,
            other => panic!(
                "expected SendFinal, got {:?}",
                std::mem::discriminant(&other)
            ),
        };

        let resp_final_action = resp_machine
            .on_message(
                initiator_guid,
                &encode_final(&final_token).expect("encode"),
                responder_guid,
                &resp_cert,
                &resp_key,
                &ca,
            )
            .expect("on_message(final) should succeed");
        let responder_secret = match resp_final_action {
            HandshakeAction::Completed(_, secret) => secret,
            other => panic!(
                "expected Completed, got {:?}",
                std::mem::discriminant(&other)
            ),
        };

        let initiator_secret = init_machine
            .shared_secret_for(&responder_guid)
            .expect("initiator must hold a shared secret after Complete");
        assert_eq!(
            initiator_secret.as_bytes().len(),
            48,
            "ECDH+secp384r1 through HKDF-SHA384 yields a 48-byte master secret; \
             32 here means something silently fell back to the P-256 chain"
        );
        assert_eq!(
            initiator_secret, responder_secret,
            "both sides must derive the identical MasterSharedSecret"
        );
    }

    /// Suite selection is POLICY, not negotiation: a responder configured for
    /// P-384 must refuse a P-256 AuthRequest instead of silently adopting it.
    /// Before this, the responder ignored its own configuration entirely, so
    /// "we deployed P-384" was true only of whichever side happened to
    /// initiate -- an invisible downgrade.
    #[test]
    fn responder_refuses_a_suite_below_its_configured_policy() {
        let initiator_guid = make_guid(0x00);
        let responder_guid = make_guid(0xFE);

        // Initiator on the default P-256, responder on P-384 policy.
        let init_machine = HandshakeMachine::new();
        let resp_machine = HandshakeMachine::with_kagree_algo("ECDH+secp384r1-CEUM");

        let init_cert = real_cert();
        let init_key = real_key_pem();
        let ca = real_ca_pem();

        let req_token = match init_machine
            .start(initiator_guid, responder_guid, &init_cert, &init_key)
            .expect("start should succeed")
            .expect("initiator should produce SendRequest")
        {
            HandshakeAction::SendRequest(_, tok) => tok,
            other => panic!(
                "expected SendRequest, got {:?}",
                std::mem::discriminant(&other)
            ),
        };

        let err = resp_machine
            .on_message(
                initiator_guid,
                &encode_request(&req_token).expect("encode"),
                responder_guid,
                &real_cert(),
                &real_key_pem(),
                &ca,
            )
            .expect_err("a P-384 responder must not complete a P-256 handshake");
        let msg = format!("{}", err);
        assert!(
            msg.contains("suite mismatch"),
            "the refusal must name the policy conflict, got: {}",
            msg
        );
    }

    /// An unknown advertised suite is refused outright -- a fallback would
    /// answer it with P-256 material the initiator never asked for.
    #[test]
    fn responder_refuses_an_unknown_kagree_algo() {
        let initiator_guid = make_guid(0x00);
        let responder_guid = make_guid(0xFE);
        let resp_machine = HandshakeMachine::new();

        let req = crate::security::handshake::tokens::AuthRequestToken {
            identity_cert_der: real_cert(),
            challenge1: [0xAB; 32],
            dh1: vec![0x04; 65],
            pdata: crate::security::handshake::pdata::serialize(&initiator_guid),
            dsign_algo: "ECDSA-SHA256".to_string(),
            // Spec-defined but unimplemented: the honest answer is refusal,
            // not a silent ECDH substitution for a finite-field request.
            kagree_algo: "DH+MODP-2048-256".to_string(),
            permissions_doc: None,
        };

        let err = resp_machine
            .on_message(
                initiator_guid,
                &encode_request(&req).expect("encode"),
                responder_guid,
                &real_cert(),
                &real_key_pem(),
                &real_ca_pem(),
            )
            .expect_err("an unsupported kagree_algo must refuse the handshake");
        assert!(
            format!("{}", err).contains("unsupported kagree_algo"),
            "got: {}",
            err
        );
    }

    // --------------------------------------------------------
    //  Role collision: the initiator receives an AuthRequest from its responder
    // --------------------------------------------------------

    #[test]
    fn role_collision_request_from_the_responder_rejected() {
        // DDS Security v1.1 Sec.9.3.4: the lower GUID initiates.
        let initiator = make_guid(0x00);
        let responder = make_guid(0xFE);
        let machine = HandshakeMachine::new();
        let req = crate::security::handshake::tokens::AuthRequestToken {
            identity_cert_der: dummy_cert(),
            challenge1: [0xAA; 32],
            dh1: vec![0x04; 65],
            pdata: vec![],
            dsign_algo: "ECDSA-SHA256".to_string(),
            kagree_algo: "ECDH+prime256v1-CEUM".to_string(),
            permissions_doc: None,
        };
        let bytes = encode_request(&req).expect("encode");
        // The initiator receives a Request claiming to come from its
        // responder: it should reject this.
        let result = machine.on_message(
            responder, // remote_guid
            &bytes,
            initiator, // local_guid
            &dummy_cert(),
            &dummy_key_pem(),
            &dummy_ca_pem(),
        );
        assert!(
            result.is_err(),
            "initiator must reject an incoming AuthRequest from its responder"
        );
    }

    // --------------------------------------------------------
    //  Replay protection: same nonce must be rejected
    // --------------------------------------------------------

    #[test]
    fn replayed_request_nonce_rejected() {
        let initiator_guid = make_guid(0x00);
        let responder_guid = make_guid(0xFE);
        let machine = HandshakeMachine::new();

        let req = crate::security::handshake::tokens::AuthRequestToken {
            identity_cert_der: real_cert(),
            challenge1: [0x42; 32], // fixed nonce to reproduce
            dh1: vec![0x04; 65],
            pdata: crate::security::handshake::pdata::serialize(&initiator_guid),
            dsign_algo: "ECDSA-SHA256".to_string(),
            kagree_algo: "ECDH+prime256v1-CEUM".to_string(),
            permissions_doc: None,
        };
        let bytes = encode_request(&req).expect("encode");

        // First delivery must succeed.
        let r1 = machine.on_message(
            initiator_guid,
            &bytes,
            responder_guid,
            &real_cert(),
            &real_key_pem(),
            &real_ca_pem(),
        );
        assert!(r1.is_ok(), "first delivery should succeed");

        // Second delivery with same nonce must fail.
        let r2 = machine.on_message(
            initiator_guid,
            &bytes,
            responder_guid,
            &real_cert(),
            &real_key_pem(),
            &real_ca_pem(),
        );
        assert!(r2.is_err(), "replayed nonce must be rejected");
        let msg = r2.unwrap_err().to_string();
        assert!(
            msg.contains("replay"),
            "error should mention replay: {}",
            msg
        );
    }

    // --------------------------------------------------------
    //  Challenge1 echo mismatch in AuthReply -> back to ReqSent, resent
    // --------------------------------------------------------

    /// DDS Security v1.1 Sec.8.3.2.9.1 rule 3: an AuthReply that does not
    /// validate (here its challenge1 is not ours) puts the initiator back in
    /// the state that sent the AuthRequest, and the AuthRequest is sent
    /// again, the same message. Nothing is failed and nothing audited: the
    /// reply is anyone's, and the session goes on.
    #[test]
    fn reply_challenge_mismatch_resends_the_request() {
        let initiator_guid = make_guid(0x00);
        let responder_guid = make_guid(0xFE);
        let (audit_file, audit) = audit_fixture();
        let machine = HandshakeMachine::new().with_audit_logger(Some(audit));

        // Start handshake.
        let action = machine
            .start(
                initiator_guid,
                responder_guid,
                &real_cert(),
                &real_key_pem(),
            )
            .expect("start")
            .expect("should produce SendRequest");

        let req_tok = match action {
            HandshakeAction::SendRequest(_, t) => t,
            _ => panic!("expected SendRequest"),
        };

        // Forge a reply with a different challenge1.
        let tampered_reply = crate::security::handshake::tokens::AuthReplyToken {
            responder_cert_der: dummy_cert(),
            pdata: Vec::new(),
            dsign_algo: "ECDSA-SHA256".to_string(),
            kagree_algo: "ECDH+prime256v1-CEUM".to_string(),
            hash_c1: None,
            challenge1: [0xFF; 32], // wrong: should echo req_tok.challenge1
            dh1: Some(req_tok.dh1),
            challenge2: [0xCC; 32],
            dh2: vec![0x05; 65],
            signature: vec![0xDD; 64],
            permissions_doc: None,
        };
        let reply_bytes = encode_reply(&tampered_reply).expect("encode");

        let result = machine.on_message(
            responder_guid,
            &reply_bytes,
            initiator_guid,
            &dummy_cert(),
            &dummy_key_pem(),
            &dummy_ca_pem(),
        );

        match result {
            Ok(HandshakeAction::SendRequest(guid, token)) => {
                assert_eq!(guid, responder_guid);
                assert_eq!(token.challenge1, req_tok.challenge1, "the same message");
            }
            Ok(other) => panic!(
                "expected SendRequest action, got {:?}",
                std::mem::discriminant(&other)
            ),
            Err(e) => panic!("unexpected error: {}", e),
        }
        assert!(machine.has_session(&responder_guid), "the session goes on");
        assert!(!machine.is_authenticated(&responder_guid));

        let records = fs::read_to_string(audit_file.path()).unwrap_or_default();
        assert_eq!(
            records.matches("outcome: Failed").count(),
            0,
            "a refused reply is no failed authentication"
        );
    }

    // --------------------------------------------------------
    //  is_authenticated returns false before completion
    // --------------------------------------------------------

    #[test]
    fn is_not_authenticated_before_completion() {
        let machine = HandshakeMachine::new();
        let unknown = make_guid(0x88);
        assert!(!machine.is_authenticated(&unknown));
    }

    // --------------------------------------------------------
    //  drop_handshake cleans up
    // --------------------------------------------------------

    #[test]
    fn drop_handshake_removes_entry() {
        let initiator_guid = make_guid(0x00);
        let responder_guid = make_guid(0xFE);
        let machine = HandshakeMachine::new();

        machine
            .start(
                initiator_guid,
                responder_guid,
                &real_cert(),
                &real_key_pem(),
            )
            .expect("start")
            .expect("should produce SendRequest");

        // Should not be authenticated (still in ReqSent).
        assert!(!machine.is_authenticated(&responder_guid));

        // Drop it.
        machine.drop_handshake(&responder_guid);
        assert!(!machine.is_authenticated(&responder_guid));
    }

    // --------------------------------------------------------
    //  Duplicate start: second start for same peer is idempotent
    // --------------------------------------------------------

    #[test]
    fn duplicate_start_is_idempotent() {
        let initiator_guid = make_guid(0x00);
        let responder_guid = make_guid(0xFE);
        let machine = HandshakeMachine::new();

        let a1 = machine
            .start(
                initiator_guid,
                responder_guid,
                &real_cert(),
                &real_key_pem(),
            )
            .expect("start 1");
        assert!(a1.is_some());

        // Second call while ReqSent is in progress: must return None (no duplicate request).
        let a2 = machine
            .start(
                initiator_guid,
                responder_guid,
                &real_cert(),
                &real_key_pem(),
            )
            .expect("start 2");
        assert!(a2.is_none(), "duplicate start must be suppressed");
    }

    // --------------------------------------------------------
    //  Non-initiator start returns None
    // --------------------------------------------------------

    /// `start()` must file the session under the normalized participant GUID.
    ///
    /// The caller hands over the raw `PID_PARTICIPANT_GUID` off the wire, and its
    /// entity-id half is whatever the peer put there; every other write and read
    /// in the machine keys on prefix + ENTITYID_PARTICIPANT. Filing the ReqSent
    /// entry under the raw key hides it from the lookup that matches the peer's
    /// AuthReply, and the handshake then dies at "received AuthReply without a
    /// matching ReqSent state" with nothing pointing at the key.
    ///
    /// HDDS always writes ENTITYID_PARTICIPANT, so this is invisible in
    /// self-pairing and only bites cross-vendor -- which is exactly the kind of
    /// defect that gets found in someone else's lab.
    #[test]
    fn start_files_the_session_under_the_normalized_participant_guid() {
        let local = make_guid(0x00);
        let prefix = crate::security::test_pki::bound_test_prefix([0x01; 6]);
        // A peer that puts something else in the entity-id half.
        let remote_as_announced = GUID::new(prefix, [0x00, 0x00, 0x00, 0x00]);

        let machine = HandshakeMachine::new();
        let action = machine
            .start(local, remote_as_announced, &real_cert(), &real_key_pem())
            .expect("start must succeed")
            .expect("the lower GUID prefix takes the initiator role");

        let normalized = GUID::new(prefix, [0x00, 0x00, 0x01, 0xC1]);
        assert!(
            machine.has_session(&normalized),
            "the session is not reachable under the key every lookup uses"
        );
        assert!(
            !machine.has_session(&remote_as_announced),
            "the session is still filed under the raw wire GUID, so two conventions coexist \
             in one map"
        );

        // The emitted action must address the normalized GUID too, otherwise the
        // reply comes back keyed differently from the entry.
        match action {
            HandshakeAction::SendRequest(guid, _) => assert_eq!(
                guid, normalized,
                "SendRequest carries the un-normalized GUID, so the reply will not match"
            ),
            other => panic!("expected SendRequest, got {:?}", other),
        }
    }

    /// The responder does not begin the handshake (DDS Security v1.1
    /// Sec.9.3.4.1), but with no session for the peer it asks the peer to
    /// begin one (Sec.7.4.3.6.2, 9.3.2.4): the peer may hold a completed
    /// session from before, and then nothing else would make it begin again.
    /// It does so once, and waits; a peer it waits for has a session (its
    /// endpoints are held back) and has not authenticated.
    #[test]
    fn a_responder_without_a_session_asks_the_peer_to_begin() {
        let low_guid = make_guid(0xFE); // will be Responder
        let high_guid = make_guid(0x00); // will be Initiator
        let machine = HandshakeMachine::new();

        let action = machine
            .start(low_guid, high_guid, &dummy_cert(), &dummy_key_pem())
            .expect("start");
        assert!(
            matches!(action, Some(HandshakeAction::SendAuthRequest(guid, _)) if guid == high_guid),
            "expected an authentication request to the initiator, got {:?}",
            action
        );
        assert!(machine.has_session(&high_guid) && !machine.is_authenticated(&high_guid));
        assert!(
            machine
                .start(low_guid, high_guid, &dummy_cert(), &dummy_key_pem())
                .expect("start")
                .is_none(),
            "asked once, not on every announcement"
        );
    }

    // --------------------------------------------------------
    //  Reply without prior request -> error
    // --------------------------------------------------------

    #[test]
    fn reply_without_request_returns_error() {
        let machine = HandshakeMachine::new();
        let remote = make_guid(0x55);
        let local = make_guid(0x00);

        let reply = crate::security::handshake::tokens::AuthReplyToken {
            responder_cert_der: dummy_cert(),
            pdata: Vec::new(),
            dsign_algo: "ECDSA-SHA256".to_string(),
            kagree_algo: "ECDH+prime256v1-CEUM".to_string(),
            hash_c1: None,
            challenge1: [0x01; 32],
            dh1: Some(vec![0x04; 65]),
            challenge2: [0x02; 32],
            dh2: vec![0x05; 65],
            signature: vec![0xAB; 64],
            permissions_doc: None,
        };
        let bytes = encode_reply(&reply).expect("encode");

        let result = machine.on_message(
            remote,
            &bytes,
            local,
            &dummy_cert(),
            &dummy_key_pem(),
            &dummy_ca_pem(),
        );
        assert!(result.is_err());
    }

    // --------------------------------------------------------
    //  Final without prior reply -> error
    // --------------------------------------------------------

    #[test]
    fn final_without_reply_returns_error() {
        let machine = HandshakeMachine::new();
        let remote = make_guid(0xEF);
        let local = make_guid(0x00);

        let fin = crate::security::handshake::tokens::AuthFinalToken {
            hash_c1: None,
            hash_c2: None,
            challenge1: [0x01; 32],
            dh1: Some(vec![0x04; 65]),
            dh2: Some(vec![0x05; 65]),
            challenge2: [0x02; 32],
            signature: vec![0xEF; 64],
        };
        let bytes = encode_final(&fin).expect("encode");

        let result = machine.on_message(
            remote,
            &bytes,
            local,
            &dummy_cert(),
            &dummy_key_pem(),
            &dummy_ca_pem(),
        );
        assert!(result.is_err());
    }

    // --------------------------------------------------------
    //  Malformed bytes -> parse error
    // --------------------------------------------------------

    #[test]
    fn malformed_bytes_return_parse_error() {
        let machine = HandshakeMachine::new();
        let remote = make_guid(0xEE);
        let local = make_guid(0x00);

        let result = machine.on_message(
            remote,
            &[0x00, 0x01, 0x02],
            local,
            &dummy_cert(),
            &dummy_key_pem(),
            &dummy_ca_pem(),
        );
        assert!(result.is_err());
    }

    // --------------------------------------------------------
    //  Token encode/decode round-trips (sanity)
    // --------------------------------------------------------

    #[test]
    fn request_token_encode_decode() {
        let tok = crate::security::handshake::tokens::AuthRequestToken {
            identity_cert_der: dummy_cert(),
            challenge1: [0x12; 32],
            dh1: vec![0x04; 65],
            pdata: vec![0xDE, 0xAD],
            dsign_algo: "ECDSA-SHA256".to_string(),
            kagree_algo: "ECDH+prime256v1-CEUM".to_string(),
            permissions_doc: None,
        };
        let bytes = encode_request(&tok).expect("encode");
        let parsed = parse_token(&bytes).expect("should parse");
        assert!(matches!(parsed, TokenKind::Request(_)));
    }

    /// `c.perm` survives the wire, and its ABSENCE survives it too.
    ///
    /// Both halves matter and the second is the one that would break a fleet.
    /// Peers that send no `c.perm` exist, so a token without
    /// it must still parse - as `None`, never as an empty document. An empty
    /// permissions document is a real statement (it grants nothing); "the peer
    /// sent nothing" is a different one, and collapsing the two would turn
    /// every older peer into one whose grants we appear to have read.
    #[test]
    fn a_permissions_document_survives_the_request_round_trip() {
        use crate::security::handshake::tokens::AuthRequestToken;

        let signed = b"-----BEGIN PKCS7-----\nnot really a signature\n".to_vec();
        let with_perm = AuthRequestToken {
            identity_cert_der: dummy_cert(),
            challenge1: [0x12; 32],
            dh1: vec![0x04; 65],
            pdata: vec![0xDE, 0xAD],
            dsign_algo: "ECDSA-SHA256".to_string(),
            kagree_algo: "ECDH+prime256v1-CEUM".to_string(),
            permissions_doc: Some(signed.clone()),
        };
        match parse_token(&encode_request(&with_perm).expect("encode")).expect("should parse") {
            TokenKind::Request(req) => {
                assert_eq!(
                    req.permissions_doc.as_deref(),
                    Some(signed.as_slice()),
                    "c.perm must arrive byte for byte: a re-serialised document \
                     would not verify against the permissions CA"
                );
            }
            other => panic!("expected a Request, got {:?}", other),
        }

        let without_perm = AuthRequestToken {
            permissions_doc: None,
            ..with_perm
        };
        match parse_token(&encode_request(&without_perm).expect("encode"))
            .expect("a token with no c.perm must parse")
        {
            TokenKind::Request(req) => {
                assert!(
                    req.permissions_doc.is_none(),
                    "absent must stay absent, not become an empty document"
                );
            }
            other => panic!("expected a Request, got {:?}", other),
        }
    }

    /// The same for the reply, which is the responder's only chance to present
    /// its permissions.
    #[test]
    fn a_permissions_document_survives_the_reply_round_trip() {
        use crate::security::handshake::tokens::AuthReplyToken;

        let signed = b"-----BEGIN PKCS7-----\nresponder\n".to_vec();
        let reply = AuthReplyToken {
            responder_cert_der: dummy_cert(),
            pdata: Vec::new(),
            dsign_algo: "ECDSA-SHA256".to_string(),
            kagree_algo: "ECDH+prime256v1-CEUM".to_string(),
            hash_c1: None,
            challenge1: [0x01; 32],
            dh1: Some(vec![0x04; 65]),
            challenge2: [0x02; 32],
            dh2: vec![0x04; 65],
            signature: vec![0x30, 0x44],
            permissions_doc: Some(signed.clone()),
        };
        match parse_token(&encode_reply(&reply).expect("encode")).expect("should parse") {
            TokenKind::Reply(rep) => {
                assert_eq!(rep.permissions_doc.as_deref(), Some(signed.as_slice()));
            }
            other => panic!("expected a Reply, got {:?}", other),
        }

        let bare = AuthReplyToken {
            permissions_doc: None,
            ..reply
        };
        match parse_token(&encode_reply(&bare).expect("encode"))
            .expect("a reply with no c.perm must parse")
        {
            TokenKind::Reply(rep) => assert!(rep.permissions_doc.is_none()),
            other => panic!("expected a Reply, got {:?}", other),
        }
    }

    /// DDS Security v1.1 Tables 49 and 50 list `c.perm` among the
    /// properties of the request and the reply, not as an optional one:
    /// HDDS sends it always, empty when it runs without access control (as
    /// Cyclone DDS does, which refuses a handshake message without it).
    #[test]
    fn c_perm_is_sent_empty_without_access_control() {
        use crate::protocol::discovery::spdp::data_holder::parse_data_holder;
        let pki = test_pki();
        let initiator = make_guid(0x00);
        let responder = make_guid(0xFE);
        let c_perm = |bytes: &[u8]| {
            parse_data_holder(bytes)
                .expect("a DataHolder")
                .binary_properties
                .into_iter()
                .find(|(n, _, _)| n == "c.perm")
                .map(|(_, v, _)| v)
        };
        let init = HandshakeMachine::new();
        let resp = HandshakeMachine::new();
        let request = request_from(&init, initiator, responder, &pki);
        assert_eq!(c_perm(&request), Some(Vec::new()), "the request");
        let reply = answer(&resp, initiator, &request, responder, &pki);
        assert_eq!(c_perm(&reply), Some(Vec::new()), "the reply");

        // And an empty c.perm is no document: each side files the peer as
        // having presented none, for its governance to judge.
        let final_bytes = answer(&init, responder, &reply, initiator, &pki);
        resp.on_message(
            initiator,
            &final_bytes,
            responder,
            &pki.cert,
            &pki.key,
            &pki.ca,
        )
        .expect("the responder completes");
        assert_eq!(init.peer_credentials(&responder).map(|c| c.1), Some(None));
        assert_eq!(resp.peer_credentials(&initiator).map(|c| c.1), Some(None));
    }

    // --------------------------------------------------------
    //  tick: no actions on empty machine
    // --------------------------------------------------------

    #[test]
    fn tick_empty_machine_produces_no_actions() {
        let machine = HandshakeMachine::new();
        let actions = machine.tick(std::time::Instant::now());
        assert!(actions.is_empty());
    }

    // --------------------------------------------------------
    //  tick: completed session produces no actions
    // --------------------------------------------------------

    #[test]
    fn tick_completed_session_produces_no_actions() {
        // Run a full handshake to get a Complete entry, then tick.
        let initiator_guid = make_guid(0x00);
        let responder_guid = make_guid(0xFE);

        let init_machine = HandshakeMachine::new();
        let resp_machine = HandshakeMachine::new();

        let ca = real_ca_pem();
        let cert = real_cert();
        let key = real_key_pem();

        let req_action = init_machine
            .start(initiator_guid, responder_guid, &cert, &key)
            .unwrap()
            .unwrap();
        let req_tok = match req_action {
            HandshakeAction::SendRequest(_, t) => t,
            _ => panic!(),
        };

        let reply_action = resp_machine
            .on_message(
                initiator_guid,
                &encode_request(&req_tok).expect("encode"),
                responder_guid,
                &cert,
                &key,
                &ca,
            )
            .unwrap();
        let reply_tok = match reply_action {
            HandshakeAction::SendReply(_, t) => t,
            _ => panic!(),
        };

        let final_action = init_machine
            .on_message(
                responder_guid,
                &encode_reply(&reply_tok).expect("encode"),
                initiator_guid,
                &cert,
                &key,
                &ca,
            )
            .unwrap();
        let final_tok = match final_action {
            HandshakeAction::SendFinal(_, t) => t,
            _ => panic!(),
        };

        let _ = resp_machine
            .on_message(
                initiator_guid,
                &encode_final(&final_tok).expect("encode"),
                responder_guid,
                &cert,
                &key,
                &ca,
            )
            .unwrap();

        // Both machines are now Complete; tick should produce nothing.
        assert!(init_machine.tick(std::time::Instant::now()).is_empty());
        assert!(resp_machine.tick(std::time::Instant::now()).is_empty());
    }

    // --------------------------------------------------------
    //  tick: the retry ladder (gap G14)
    // --------------------------------------------------------
    //
    // The ladder below is the sec. 9.3.4.1 contract, not a copy of the
    // implementation's constants: 1 s / 4 s / 16 s measured from the first
    // transmission, then a hard 30 s deadline. Written as literals on
    // purpose, so that changing the constants has to be a deliberate act
    // that also updates this contract.
    //
    // Three properties are pinned here:
    //   1. a due rung returns a SEND action carrying the original token
    //      (not `Failed(guid, "retransmit ...")`, which the pump logs as a
    //      failure and never puts on the wire);
    //   2. a rung fires exactly once, because tick advances `retries`
    //      itself (leaving `retries` at 0 would re-fire the same rung on
    //      every call from the first second onward);
    //   3. past the deadline the session becomes Failed, which is the only
    //      thing that lets `handle_spdp` call `start()` again for that peer.

    /// The documented ladder, per DDS Security v1.1 sec. 9.3.4.1.
    const RUNG_1: Duration = Duration::from_secs(1);
    const RUNG_2: Duration = Duration::from_secs(4);
    const RUNG_3: Duration = Duration::from_secs(16);
    const DEADLINE: Duration = Duration::from_secs(30);
    /// A margin past a rung, so the strict `>` comparison is unambiguous.
    const PAST: Duration = Duration::from_millis(100);

    /// Drive a fresh machine into `ReqSent` and hand back the AuthRequest it
    /// emitted, so a test can compare a retransmission against the original.
    fn initiator_in_req_sent() -> (HandshakeMachine, GUID, AuthRequestToken) {
        let local = make_guid(0x00);
        let remote = make_guid(0xFE);
        let machine = HandshakeMachine::new();

        let action = machine
            .start(local, remote, &real_cert(), &real_key_pem())
            .expect("start must succeed")
            .expect("the lower GUID prefix takes the initiator role");

        match action {
            HandshakeAction::SendRequest(guid, token) => {
                assert_eq!(guid, remote);
                (machine, remote, token)
            }
            other => panic!("expected SendRequest, got {:?}", other),
        }
    }

    #[test]
    fn tick_before_the_first_rung_is_silent() {
        let (machine, remote, _) = initiator_in_req_sent();

        assert!(
            machine.tick(Instant::now()).is_empty(),
            "no rung is due in the first millisecond"
        );
        assert!(
            machine.has_session(&remote),
            "the session must still be live"
        );
        assert!(!machine.is_authenticated(&remote));
    }

    #[test]
    fn tick_retransmits_the_original_authrequest() {
        let (machine, remote, original) = initiator_in_req_sent();

        let actions = machine.tick(Instant::now() + RUNG_1 + PAST);
        assert_eq!(actions.len(), 1, "one due rung, one action");

        match &actions[0] {
            HandshakeAction::SendRequest(guid, token) => {
                assert_eq!(*guid, remote);
                assert_eq!(
                    token.challenge1, original.challenge1,
                    "a retransmission carries the original nonce; a fresh one would \
                     be a second handshake the peer has no state for"
                );
                assert_eq!(
                    token.dh1, original.dh1,
                    "a retransmission carries the original DH public key"
                );
                assert_eq!(
                    encode_request(token).expect("encode"),
                    encode_request(&original).expect("encode"),
                    "the retransmitted AuthRequest must be byte-identical on the wire"
                );
            }
            other => panic!(
                "a due rung must produce a sendable SendRequest, got {:?}",
                other
            ),
        }
    }

    #[test]
    fn tick_advances_the_ladder_instead_of_storming() {
        let (machine, _, _) = initiator_in_req_sent();
        let due = Instant::now() + RUNG_1 + PAST;

        assert_eq!(machine.tick(due).len(), 1, "the 1 s rung fires");
        assert!(
            machine.tick(due).is_empty(),
            "a rung that already fired must not fire again: tick advances `retries` itself"
        );
        assert!(
            machine.tick(due + PAST).is_empty(),
            "the 4 s rung is not due yet"
        );
    }

    #[test]
    fn tick_ladder_stops_after_three_retransmissions() {
        let (machine, _, _) = initiator_in_req_sent();
        let t0 = Instant::now();

        for (attempt, rung) in [(1u8, RUNG_1), (2, RUNG_2), (3, RUNG_3)] {
            let actions = machine.tick(t0 + rung + PAST);
            assert_eq!(
                actions.len(),
                1,
                "attempt {} must produce exactly one retransmission",
                attempt
            );
            assert!(
                matches!(actions[0], HandshakeAction::SendRequest(..)),
                "attempt {} must be sendable, got {:?}",
                attempt,
                actions[0]
            );
        }

        assert!(
            machine.tick(t0 + RUNG_3 + RUNG_2).is_empty(),
            "the ladder is exhausted after 3 retransmissions; only the deadline may act now"
        );
    }

    #[test]
    fn tick_expires_the_session_and_unblocks_a_restart() {
        let local = make_guid(0x00);
        let remote = make_guid(0xFE);
        let machine = HandshakeMachine::new();
        let cert = real_cert();
        let key = real_key_pem();

        assert!(machine
            .start(local, remote, &cert, &key)
            .expect("start")
            .is_some());
        assert!(
            machine
                .start(local, remote, &cert, &key)
                .expect("start")
                .is_none(),
            "start refuses to restart a pending session -- which is exactly why an \
             inert tick() turned one lost packet into a permanent auth failure"
        );

        let actions = machine.tick(Instant::now() + DEADLINE + PAST);
        assert_eq!(actions.len(), 1);
        assert!(
            matches!(actions[0], HandshakeAction::Failed(..)),
            "past the 30 s deadline the session must fail, got {:?}",
            actions[0]
        );
        assert!(machine.has_session(&remote), "the failure is recorded");
        assert!(!machine.is_authenticated(&remote));

        assert!(
            machine
                .start(local, remote, &cert, &key)
                .expect("start")
                .is_some(),
            "expiring the session is what re-opens the restart path taken by \
             handle_spdp on the next SPDP announcement"
        );
    }

    // --------------------------------------------------------
    //  Duplicate messages, which the retry ladder generates
    // --------------------------------------------------------
    //
    // `handle_reply` and `handle_final` must check what they found before
    // removing it: a reply or final arriving for a peer in the wrong state
    // must not delete that peer's entry, in particular a `Complete` one
    // holding the MasterSharedSecret. The retry ladder makes plain packet
    // loss produce exactly those duplicates, so the two paths are pinned
    // here: a duplicate must be answered, never destructive.

    /// A completed pair, plus the wire bytes of the reply and the final, so a
    /// test can replay either one.
    struct CompletedPair {
        init: HandshakeMachine,
        resp: HandshakeMachine,
        initiator_guid: GUID,
        responder_guid: GUID,
        reply: crate::security::handshake::tokens::AuthReplyToken,
        final_bytes: Vec<u8>,
    }

    fn completed_pair() -> CompletedPair {
        let initiator_guid = make_guid(0x00);
        let responder_guid = make_guid(0xFE);
        let init = HandshakeMachine::new();
        let resp = HandshakeMachine::new();
        let cert = real_cert();
        let key = real_key_pem();
        let ca = real_ca_pem();

        let req = match init
            .start(initiator_guid, responder_guid, &cert, &key)
            .expect("start")
            .expect("initiator role")
        {
            HandshakeAction::SendRequest(_, token) => token,
            other => panic!("expected SendRequest, got {:?}", other),
        };

        let reply = match resp
            .on_message(
                initiator_guid,
                &encode_request(&req).expect("encode"),
                responder_guid,
                &cert,
                &key,
                &ca,
            )
            .expect("responder accepts the request")
        {
            HandshakeAction::SendReply(_, token) => token,
            other => panic!("expected SendReply, got {:?}", other),
        };

        let final_token = match init
            .on_message(
                responder_guid,
                &encode_reply(&reply).expect("encode"),
                initiator_guid,
                &cert,
                &key,
                &ca,
            )
            .expect("initiator accepts the reply")
        {
            HandshakeAction::SendFinal(_, token) => token,
            other => panic!("expected SendFinal, got {:?}", other),
        };
        let final_bytes = encode_final(&final_token).expect("encode");

        resp.on_message(
            initiator_guid,
            &final_bytes,
            responder_guid,
            &cert,
            &key,
            &ca,
        )
        .expect("responder accepts the final");

        assert!(init.is_authenticated(&responder_guid));
        assert!(resp.is_authenticated(&initiator_guid));

        CompletedPair {
            init,
            resp,
            initiator_guid,
            responder_guid,
            reply,
            final_bytes,
        }
    }

    #[test]
    fn duplicate_authreply_resends_the_final_and_keeps_the_session() {
        let pair = completed_pair();
        let secret_before = pair
            .init
            .shared_secret_for(&pair.responder_guid)
            .expect("initiator holds a secret");

        // The responder's ladder retransmits its AuthReply because our
        // AuthFinal never arrived.
        let action = pair
            .init
            .on_message(
                pair.responder_guid,
                &encode_reply(&pair.reply).expect("encode"),
                pair.initiator_guid,
                &real_cert(),
                &real_key_pem(),
                &real_ca_pem(),
            )
            .expect("a duplicate AuthReply is ordinary traffic, not an error");

        assert!(
            matches!(action, HandshakeAction::SendFinal(..)),
            "the duplicate must be answered with a fresh AuthFinal -- nothing else \
             can repair the third leg once we are Complete; got {:?}",
            action
        );
        assert!(
            pair.init.is_authenticated(&pair.responder_guid),
            "the completed session must survive its own peer's retransmission"
        );
        assert_eq!(
            pair.init.shared_secret_for(&pair.responder_guid),
            Some(secret_before),
            "the MasterSharedSecret must be untouched"
        );
    }

    /// A duplicate AuthReply that echoes another hash_c1 than our request's
    /// answers no request of the completed session: no AuthFinal is
    /// re-signed for it, and the session stays.
    #[test]
    fn a_duplicate_reply_echoing_another_hash_c1_is_not_answered() {
        let pair = completed_pair();
        let forged = crate::security::handshake::tokens::AuthReplyToken {
            hash_c1: Some([0x77; 32]),
            ..pair.reply.clone()
        };
        let outcome = pair.init.on_message(
            pair.responder_guid,
            &encode_reply(&forged).expect("encode"),
            pair.initiator_guid,
            &real_cert(),
            &real_key_pem(),
            &real_ca_pem(),
        );
        assert!(
            outcome.is_err(),
            "a duplicate echoing another hash_c1 was answered: {:?}",
            outcome
        );
        assert!(pair.init.is_authenticated(&pair.responder_guid));
    }

    /// A duplicate AuthReply whose dh2 was swapped is not re-signed into
    /// an AuthFinal either: the duplicate is verified as the first one was.
    #[test]
    fn a_duplicate_reply_whose_dh2_was_swapped_is_not_answered() {
        let pair = completed_pair();
        let forged = crate::security::handshake::tokens::AuthReplyToken {
            dh2: attacker_dh_key(),
            ..pair.reply.clone()
        };
        let outcome = pair.init.on_message(
            pair.responder_guid,
            &encode_reply(&forged).expect("encode"),
            pair.initiator_guid,
            &real_cert(),
            &real_key_pem(),
            &real_ca_pem(),
        );
        assert!(
            outcome.is_err(),
            "a duplicate with the attacker's dh2 was answered: {:?}",
            outcome
        );
        assert!(pair.init.is_authenticated(&pair.responder_guid));
    }

    #[test]
    fn duplicate_authfinal_is_idempotent_and_keeps_the_session() {
        let pair = completed_pair();
        let secret_before = pair
            .resp
            .shared_secret_for(&pair.initiator_guid)
            .expect("responder holds a secret");

        let action = pair
            .resp
            .on_message(
                pair.initiator_guid,
                &pair.final_bytes,
                pair.responder_guid,
                &real_cert(),
                &real_key_pem(),
                &real_ca_pem(),
            )
            .expect("a duplicate AuthFinal is ordinary traffic, not an error");

        match action {
            HandshakeAction::Completed(guid, secret) => {
                assert_eq!(guid, pair.initiator_guid);
                assert_eq!(secret, secret_before, "the same secret is re-announced");
            }
            other => panic!("expected Completed, got {:?}", other),
        }
        assert!(
            pair.resp.is_authenticated(&pair.initiator_guid),
            "a duplicate AuthFinal must not de-authenticate the peer that sent it"
        );
        assert_eq!(
            pair.resp.shared_secret_for(&pair.initiator_guid),
            Some(secret_before),
            "the MasterSharedSecret must be untouched"
        );
    }

    #[test]
    fn duplicate_authreply_from_another_certificate_is_refused() {
        let pair = completed_pair();
        let secret_before = pair
            .init
            .shared_secret_for(&pair.responder_guid)
            .expect("initiator holds a secret");

        // Same session, different identity: the re-send path signs data taken
        // from the message, so it must be reachable only by the peer we
        // actually completed with.
        let mut forged = pair.reply.clone();
        forged.responder_cert_der = real_ca_pem();

        let result = pair.init.on_message(
            pair.responder_guid,
            &encode_reply(&forged).expect("encode"),
            pair.initiator_guid,
            &real_cert(),
            &real_key_pem(),
            &real_ca_pem(),
        );

        assert!(
            result.is_err(),
            "a reply bearing a different certificate must be refused, got {:?}",
            result
        );
        assert!(
            pair.init.is_authenticated(&pair.responder_guid),
            "and refusing it must not cost the session"
        );
        assert_eq!(
            pair.init.shared_secret_for(&pair.responder_guid),
            Some(secret_before)
        );
    }

    #[test]
    fn tick_retransmits_the_original_authreply() {
        // Responder role: the local prefix must be the lower of the two.
        let responder = make_guid(0xFE);
        let initiator = make_guid(0x00);
        let init_machine = HandshakeMachine::new();
        let resp_machine = HandshakeMachine::new();
        let cert = real_cert();
        let key = real_key_pem();
        let ca = real_ca_pem();

        let req = match init_machine
            .start(initiator, responder, &cert, &key)
            .expect("start")
            .expect("initiator role")
        {
            HandshakeAction::SendRequest(_, token) => token,
            other => panic!("expected SendRequest, got {:?}", other),
        };

        let reply = match resp_machine
            .on_message(
                initiator,
                &encode_request(&req).expect("encode"),
                responder,
                &cert,
                &key,
                &ca,
            )
            .expect("the responder must accept a well-formed AuthRequest")
        {
            HandshakeAction::SendReply(_, token) => token,
            other => panic!("expected SendReply, got {:?}", other),
        };

        let actions = resp_machine.tick(Instant::now() + RUNG_1 + PAST);
        assert_eq!(actions.len(), 1, "the responder has its own ladder");

        match &actions[0] {
            HandshakeAction::SendReply(guid, token) => {
                assert_eq!(*guid, initiator);
                assert_eq!(
                    encode_reply(token).expect("encode"),
                    encode_reply(&reply).expect("encode"),
                    "the retransmitted AuthReply must be byte-identical, signature \
                     included -- rebuilding it would put the private key on the timer path"
                );
            }
            other => panic!("expected SendReply, got {:?}", other),
        }
    }

    // --------------------------------------------------------
    //  Session lifecycle: a session dropped or replaced while one of its
    //  messages is being verified takes nothing from what replaced it, and a
    //  peer that authenticates again keeps its completed session until the
    //  new one's AuthFinal verifies.
    // --------------------------------------------------------

    /// The four certificate arguments a machine call takes, for one PKI.
    struct Pki {
        cert: Vec<u8>,
        key: Vec<u8>,
        ca: Vec<u8>,
    }

    fn test_pki() -> Pki {
        Pki {
            cert: real_cert(),
            key: real_key_pem(),
            ca: real_ca_pem(),
        }
    }

    /// The AuthRequest `machine` emits toward `remote` from `local`.
    fn request_from(machine: &HandshakeMachine, local: GUID, remote: GUID, pki: &Pki) -> Vec<u8> {
        match machine
            .start(local, remote, &pki.cert, &pki.key)
            .expect("start")
            .expect("initiator role")
        {
            HandshakeAction::SendRequest(_, token) => encode_request(&token).expect("encode"),
            other => panic!("expected SendRequest, got {:?}", other),
        }
    }

    /// `machine`'s answer to `bytes`, which must be a message it sends on.
    fn answer(
        machine: &HandshakeMachine,
        from: GUID,
        bytes: &[u8],
        local: GUID,
        pki: &Pki,
    ) -> Vec<u8> {
        match machine
            .on_message(from, bytes, local, &pki.cert, &pki.key, &pki.ca)
            .expect("the message must be accepted")
        {
            HandshakeAction::SendRequest(_, token) => encode_request(&token).expect("encode"),
            HandshakeAction::SendReply(_, token) => encode_reply(&token).expect("encode"),
            HandshakeAction::SendFinal(_, token) => encode_final(&token).expect("encode"),
            other => panic!("expected a message to send, got {:?}", other),
        }
    }

    /// Tables 49-51 define +Req, +Reply and +Final. The pre-1.5 HDDS
    /// class ids are refused before any session transition, even when all
    /// properties and signatures would pass under the current class id.
    #[test]
    fn pre_1_5_messages_cannot_advance_either_handshake_role() {
        use crate::protocol::discovery::spdp::data_holder::{
            parse_data_holder, serialize_data_holder,
        };
        let old_class = |bytes: &[u8], class_id: &str| {
            let holder = parse_data_holder(bytes).expect("valid token");
            serialize_data_holder(class_id, &[], &holder.binary_properties).expect("encode")
        };
        let pki = test_pki();
        let initiator = make_guid(0x00);
        let responder = make_guid(0xFE);
        let init = HandshakeMachine::new();
        let resp = HandshakeMachine::new();
        let request = request_from(&init, initiator, responder, &pki);
        let refused = |machine: &HandshakeMachine, from, local, bytes: &[u8], class_id| {
            let error = machine
                .on_message(
                    from,
                    &old_class(bytes, class_id),
                    local,
                    &pki.cert,
                    &pki.key,
                    &pki.ca,
                )
                .expect_err("pre-1.5 class id cannot advance the handshake");
            assert!(error.to_string().contains("pre-1.5 handshake signature"));
            assert!(!machine.is_authenticated(&from));
            assert!(machine.volatile_key_material(&from.prefix).is_none());
        };
        refused(
            &resp,
            initiator,
            responder,
            &request,
            "DDS:Auth:PKI-DH:1.0+AuthRequest",
        );
        let reply = answer(&resp, initiator, &request, responder, &pki);
        refused(
            &init,
            responder,
            initiator,
            &reply,
            "DDS:Auth:PKI-DH:1.0+AuthReply",
        );
        let final_message = answer(&init, responder, &reply, initiator, &pki);
        refused(
            &resp,
            initiator,
            responder,
            &final_message,
            "DDS:Auth:PKI-DH:1.0+AuthFinal",
        );
        assert!(matches!(
            resp.on_message(
                initiator,
                &final_message,
                responder,
                &pki.cert,
                &pki.key,
                &pki.ca
            ),
            Ok(HandshakeAction::Completed(..))
        ));
        assert!(init.is_authenticated(&responder));
        assert!(resp.is_authenticated(&initiator));
    }

    /// An AuthReply that arrives for a session dropped while it was being
    /// verified installs nothing: the participant left discovery, and a
    /// `Complete` filed after that would authenticate a peer nobody knows
    /// any more, with keys the next participant under that prefix never
    /// agreed to.
    #[test]
    fn a_reply_verified_after_its_session_was_dropped_installs_nothing() {
        let pki = test_pki();
        let initiator = make_guid(0x00);
        let responder = make_guid(0xFE);
        let init = HandshakeMachine::new();
        let resp = HandshakeMachine::new();

        let request = request_from(&init, initiator, responder, &pki);
        let reply = answer(&resp, initiator, &request, responder, &pki);

        init.set_parked_hook(Box::new(move |m: &HandshakeMachine| {
            m.drop_handshake(&responder);
        }));
        let outcome = init.on_message(responder, &reply, initiator, &pki.cert, &pki.key, &pki.ca);

        assert!(
            outcome.is_err(),
            "no AuthFinal may go out for a dropped session, got {:?}",
            outcome
        );
        assert!(
            !init.has_session(&responder),
            "the dropped session came back as {:?}",
            init.is_authenticated(&responder)
        );
    }

    /// The same window, with a NEW session begun in it (the participant came
    /// back and announced itself): the late reply of the old session must
    /// not overwrite the new one, whose AuthRequest is what the peer answers
    /// next.
    #[test]
    fn a_reply_verified_after_a_new_session_began_leaves_the_new_one() {
        let pki = test_pki();
        let initiator = make_guid(0x00);
        let responder = make_guid(0xFE);
        let init = HandshakeMachine::new();
        let resp = HandshakeMachine::new();

        let request = request_from(&init, initiator, responder, &pki);
        let reply = answer(&resp, initiator, &request, responder, &pki);

        let (cert, key) = (pki.cert.clone(), pki.key.clone());
        init.set_parked_hook(Box::new(move |m: &HandshakeMachine| {
            m.drop_handshake(&responder);
            m.start(initiator, responder, &cert, &key)
                .expect("start")
                .expect("a new session begins");
        }));
        let outcome = init.on_message(responder, &reply, initiator, &pki.cert, &pki.key, &pki.ca);

        assert!(outcome.is_err(), "got {:?}", outcome);
        assert!(
            init.has_session(&responder) && !init.is_authenticated(&responder),
            "the new session must still be waiting for its own reply"
        );
    }

    /// The responder's side of the same rule: an AuthFinal verified across a
    /// drop installs nothing.
    #[test]
    fn a_final_verified_after_its_session_was_dropped_installs_nothing() {
        let pki = test_pki();
        let initiator = make_guid(0x00);
        let responder = make_guid(0xFE);
        let init = HandshakeMachine::new();
        let resp = HandshakeMachine::new();

        let request = request_from(&init, initiator, responder, &pki);
        let reply = answer(&resp, initiator, &request, responder, &pki);
        let final_bytes = answer(&init, responder, &reply, initiator, &pki);

        resp.set_parked_hook(Box::new(move |m: &HandshakeMachine| {
            m.drop_handshake(&initiator);
        }));
        let outcome = resp.on_message(
            initiator,
            &final_bytes,
            responder,
            &pki.cert,
            &pki.key,
            &pki.ca,
        );

        assert!(outcome.is_err(), "got {:?}", outcome);
        assert!(!resp.has_session(&initiator));
    }

    /// A reply refused after its session was dropped during the verification
    /// (its participant left discovery) puts nothing back: the refusal of
    /// rule 3 returns the session it took out only while that session is
    /// still the peer's, or it would bring back one discovery removed.
    #[test]
    fn a_refused_reply_whose_session_was_dropped_puts_nothing_back() {
        let pki = test_pki();
        let initiator = make_guid(0x00);
        let responder = make_guid(0xFE);
        let init = HandshakeMachine::new();
        let resp = HandshakeMachine::new();

        let request = request_from(&init, initiator, responder, &pki);
        let reply = answer(&resp, initiator, &request, responder, &pki);
        let mut token = match parse_token(&reply).expect("parse") {
            TokenKind::Reply(token) => token,
            _ => panic!("not a reply"),
        };
        token.challenge1 = [0x5A; 32];
        let bad_reply = encode_reply(&token).expect("encode");

        init.set_parked_hook(Box::new(move |m: &HandshakeMachine| {
            m.drop_handshake(&responder);
        }));
        let outcome = init.on_message(
            responder, &bad_reply, initiator, &pki.cert, &pki.key, &pki.ca,
        );

        assert!(outcome.is_err(), "nothing resent, got {:?}", outcome);
        assert!(
            !init.has_session(&responder),
            "a dropped session was brought back"
        );
    }

    /// A failure verified across a new session is not recorded on it either:
    /// the late verdict belongs to the session that was replaced.
    #[test]
    fn a_late_failure_of_a_replaced_session_does_not_fail_the_new_one() {
        let pki = test_pki();
        let initiator = make_guid(0x00);
        let responder = make_guid(0xFE);
        let init = HandshakeMachine::new();
        let resp = HandshakeMachine::new();

        let request = request_from(&init, initiator, responder, &pki);
        let reply = answer(&resp, initiator, &request, responder, &pki);
        // A reply whose challenge1 is not ours fails at its first check.
        let mut token = match parse_token(&reply).expect("parse") {
            TokenKind::Reply(token) => token,
            _ => panic!("not a reply"),
        };
        token.challenge1 = [0x5A; 32];
        let bad_reply = encode_reply(&token).expect("encode");

        let (cert, key) = (pki.cert.clone(), pki.key.clone());
        init.set_parked_hook(Box::new(move |m: &HandshakeMachine| {
            m.drop_handshake(&responder);
            m.start(initiator, responder, &cert, &key)
                .expect("start")
                .expect("a new session begins");
        }));
        let _ = init.on_message(
            responder, &bad_reply, initiator, &pki.cert, &pki.key, &pki.ca,
        );

        assert!(
            init.start(initiator, responder, &pki.cert, &pki.key)
                .expect("start")
                .is_none(),
            "the new session must still be in progress, not Failed (start restarts a Failed one)"
        );
    }

    /// The responder takes its session out of the table to verify the
    /// AuthFinal with no lock held. The peer's announcement handled in that
    /// window (`start`, which the SPDP handler calls on every admission)
    /// must see the session in progress and begin nothing: seeing no session
    /// and beginning one would make the AuthFinal install nothing, and the
    /// responder would stay unauthenticated while the initiator had completed.
    /// Two participants that start together cross exactly so.
    #[test]
    fn an_announcement_while_the_final_is_verified_begins_nothing() {
        let pki = test_pki();
        let initiator = make_guid(0x00);
        let responder = make_guid(0xFE);
        let init = HandshakeMachine::new();
        let resp = HandshakeMachine::new();

        let request = request_from(&init, initiator, responder, &pki);
        let reply = answer(&resp, initiator, &request, responder, &pki);
        let final_bytes = answer(&init, responder, &reply, initiator, &pki);

        let (cert, key) = (pki.cert.clone(), pki.key.clone());
        let began = Arc::new(parking_lot::Mutex::new(None));
        let began_in_hook = began.clone();
        resp.set_parked_hook(Box::new(move |m: &HandshakeMachine| {
            let action = m.start(responder, initiator, &cert, &key).expect("start");
            *began_in_hook.lock() = Some(action.is_some());
        }));
        let outcome = resp.on_message(
            initiator,
            &final_bytes,
            responder,
            &pki.cert,
            &pki.key,
            &pki.ca,
        );

        assert_eq!(
            *began.lock(),
            Some(false),
            "fixture: the announcement must be handled inside the window, and begin nothing"
        );
        assert!(
            matches!(outcome, Ok(HandshakeAction::Completed(..))),
            "the AuthFinal must complete the session, got {:?}",
            outcome
        );
        assert!(resp.is_authenticated(&initiator));
    }

    /// The initiator's side: an announcement handled while the AuthReply is
    /// verified begins no second request, and the reply completes.
    #[test]
    fn an_announcement_while_the_reply_is_verified_begins_nothing() {
        let pki = test_pki();
        let initiator = make_guid(0x00);
        let responder = make_guid(0xFE);
        let init = HandshakeMachine::new();
        let resp = HandshakeMachine::new();

        let request = request_from(&init, initiator, responder, &pki);
        let reply = answer(&resp, initiator, &request, responder, &pki);

        let (cert, key) = (pki.cert.clone(), pki.key.clone());
        let began = Arc::new(parking_lot::Mutex::new(None));
        let began_in_hook = began.clone();
        init.set_parked_hook(Box::new(move |m: &HandshakeMachine| {
            let action = m.start(initiator, responder, &cert, &key).expect("start");
            *began_in_hook.lock() = Some(action.is_some());
        }));
        let outcome = init.on_message(responder, &reply, initiator, &pki.cert, &pki.key, &pki.ca);

        assert_eq!(
            *began.lock(),
            Some(false),
            "fixture: the announcement must be handled inside the window, and begin nothing"
        );
        assert!(
            matches!(outcome, Ok(HandshakeAction::SendFinal(..))),
            "the AuthReply must complete the session, got {:?}",
            outcome
        );
        assert!(init.is_authenticated(&responder));
    }

    /// A session whose AuthReply is being verified is out of the table, yet
    /// it is a session in progress (DDS Security v1.1 Sec.8.8.2.1): the peer
    /// is not "Unauthenticated", and what it sends is not to be judged as if
    /// no handshake had begun.
    #[test]
    fn a_session_whose_reply_is_verified_is_a_session_in_progress() {
        let pki = test_pki();
        let initiator = make_guid(0x00);
        let responder = make_guid(0xFE);
        let init = HandshakeMachine::new();
        let resp = HandshakeMachine::new();

        let request = request_from(&init, initiator, responder, &pki);
        let reply = answer(&resp, initiator, &request, responder, &pki);

        let seen = Arc::new(parking_lot::Mutex::new(None));
        let seen_in_hook = seen.clone();
        init.set_parked_hook(Box::new(move |m: &HandshakeMachine| {
            *seen_in_hook.lock() =
                Some((m.has_session(&responder), m.is_authenticated(&responder)));
        }));
        let outcome = init.on_message(responder, &reply, initiator, &pki.cert, &pki.key, &pki.ca);

        assert!(
            matches!(outcome, Ok(HandshakeAction::SendFinal(..))),
            "fixture: the reply completes the session, got {:?}",
            outcome
        );
        assert_eq!(
            *seen.lock(),
            Some((true, false)),
            "while its reply is verified the session is in progress: held, not authenticated"
        );
    }

    /// The responder's side: the session whose AuthFinal is being verified.
    #[test]
    fn a_session_whose_final_is_verified_is_a_session_in_progress() {
        let pki = test_pki();
        let initiator = make_guid(0x00);
        let responder = make_guid(0xFE);
        let init = HandshakeMachine::new();
        let resp = HandshakeMachine::new();

        let request = request_from(&init, initiator, responder, &pki);
        let reply = answer(&resp, initiator, &request, responder, &pki);
        let final_bytes = answer(&init, responder, &reply, initiator, &pki);

        let seen = Arc::new(parking_lot::Mutex::new(None));
        let seen_in_hook = seen.clone();
        resp.set_parked_hook(Box::new(move |m: &HandshakeMachine| {
            *seen_in_hook.lock() =
                Some((m.has_session(&initiator), m.is_authenticated(&initiator)));
        }));
        let outcome = resp.on_message(
            initiator,
            &final_bytes,
            responder,
            &pki.cert,
            &pki.key,
            &pki.ca,
        );

        assert!(
            matches!(outcome, Ok(HandshakeAction::Completed(..))),
            "fixture: the final completes the session, got {:?}",
            outcome
        );
        assert_eq!(*seen.lock(), Some((true, false)));
    }

    /// A re-authentication whose AuthFinal is being verified is still in
    /// flight: the parallel session is out of its table, and the keys of the
    /// peer are changing until it is done.
    #[test]
    fn a_parallel_session_whose_final_is_verified_is_still_in_flight() {
        let pki = test_pki();
        let initiator = make_guid(0x00);
        let responder = make_guid(0xFE);
        let first = HandshakeMachine::new();
        let resp = HandshakeMachine::new();

        let request = request_from(&first, initiator, responder, &pki);
        let reply = answer(&resp, initiator, &request, responder, &pki);
        let final_bytes = answer(&first, responder, &reply, initiator, &pki);
        resp.on_message(
            initiator,
            &final_bytes,
            responder,
            &pki.cert,
            &pki.key,
            &pki.ca,
        )
        .expect("fixture: the first session completes");
        assert!(resp.is_authenticated(&initiator), "fixture: completed");

        // The peer comes back as a new process under the same prefix.
        let restarted = HandshakeMachine::new();
        let request = request_from(&restarted, initiator, responder, &pki);
        let reply = answer(&resp, initiator, &request, responder, &pki);
        let final_bytes = answer(&restarted, responder, &reply, initiator, &pki);
        assert!(
            resp.has_parallel_session(&initiator),
            "fixture: the second AuthRequest began a parallel session"
        );

        let seen = Arc::new(parking_lot::Mutex::new(None));
        let seen_in_hook = seen.clone();
        resp.set_parked_hook(Box::new(move |m: &HandshakeMachine| {
            *seen_in_hook.lock() = Some(m.has_parallel_session(&initiator));
        }));
        let outcome = resp.on_message(
            initiator,
            &final_bytes,
            responder,
            &pki.cert,
            &pki.key,
            &pki.ca,
        );

        assert!(
            matches!(outcome, Ok(HandshakeAction::Completed(..))),
            "fixture: the parallel session completes, got {:?}",
            outcome
        );
        assert_eq!(
            *seen.lock(),
            Some(true),
            "the parallel session is in flight while its AuthFinal is verified"
        );
        assert!(
            !resp.has_parallel_session(&initiator),
            "the note goes with the verification"
        );
    }

    /// An AuthRequest handled while the responder verifies the AuthFinal of
    /// the session in progress is a parallel session, as it is while that
    /// session is `ReplySent` (`handle_request`): it must not replace the
    /// session whose AuthFinal is being verified.
    #[test]
    fn an_authrequest_while_the_final_is_verified_does_not_replace_the_session() {
        let pki = test_pki();
        let initiator = make_guid(0x00);
        let responder = make_guid(0xFE);
        let init = HandshakeMachine::new();
        let resp = HandshakeMachine::new();

        let request = request_from(&init, initiator, responder, &pki);
        let reply = answer(&resp, initiator, &request, responder, &pki);
        let final_bytes = answer(&init, responder, &reply, initiator, &pki);
        // Another AuthRequest of the same peer (a new process under its
        // prefix, or its own retry after a restart), from a fresh machine.
        let again = request_from(&HandshakeMachine::new(), initiator, responder, &pki);

        let pki_in_hook = test_pki();
        let answered = Arc::new(parking_lot::Mutex::new(None));
        let answered_in_hook = answered.clone();
        resp.set_parked_hook(Box::new(move |m: &HandshakeMachine| {
            let action = m.on_message(
                initiator,
                &again,
                responder,
                &pki_in_hook.cert,
                &pki_in_hook.key,
                &pki_in_hook.ca,
            );
            *answered_in_hook.lock() = Some(matches!(action, Ok(HandshakeAction::SendReply(..))));
        }));
        let outcome = resp.on_message(
            initiator,
            &final_bytes,
            responder,
            &pki.cert,
            &pki.key,
            &pki.ca,
        );

        assert_eq!(
            *answered.lock(),
            Some(true),
            "fixture: the second AuthRequest must be answered inside the window"
        );
        assert!(
            matches!(outcome, Ok(HandshakeAction::Completed(..))),
            "the AuthFinal must complete the session in progress, got {:?}",
            outcome
        );
        assert!(resp.is_authenticated(&initiator));
        assert!(
            !resp.has_parallel_session(&initiator),
            "the session of record that completed forgets the parallel one"
        );
    }

    /// A reply refused while its session was out of the table for
    /// verification (here a reply whose challenge1 is not ours) puts the
    /// session back, in progress (DDS Security v1.1 Sec.8.3.2.9.1 rule 3):
    /// `start` begins nothing over it, and the genuine reply then completes
    /// it. The note that kept the session in progress during its verification
    /// goes with the verification, or that reply would find nothing.
    #[test]
    fn a_session_refused_while_verified_goes_on_and_completes() {
        let pki = test_pki();
        let initiator = make_guid(0x00);
        let responder = make_guid(0xFE);
        let init = HandshakeMachine::new();
        let resp = HandshakeMachine::new();

        let request = request_from(&init, initiator, responder, &pki);
        let reply = answer(&resp, initiator, &request, responder, &pki);
        let mut token = match parse_token(&reply).expect("parse") {
            TokenKind::Reply(token) => token,
            _ => panic!("not a reply"),
        };
        token.challenge1 = [0x5A; 32];
        let bad_reply = encode_reply(&token).expect("encode");
        let outcome = init.on_message(
            responder, &bad_reply, initiator, &pki.cert, &pki.key, &pki.ca,
        );
        assert!(
            matches!(outcome, Ok(HandshakeAction::SendRequest(..))),
            "fixture: the reply is refused and the request sent again, got {:?}",
            outcome
        );

        assert!(
            init.start(initiator, responder, &pki.cert, &pki.key)
                .expect("start")
                .is_none(),
            "the session is still in progress: nothing begins over it"
        );
        let outcome = init.on_message(responder, &reply, initiator, &pki.cert, &pki.key, &pki.ca);
        assert!(
            matches!(outcome, Ok(HandshakeAction::SendFinal(..))),
            "the genuine reply completes the session, got {:?}",
            outcome
        );
        assert!(init.is_authenticated(&responder));
    }

    /// The resends of rule 3 are bounded: each one is a rung of the retry
    /// ladder, so a peer that keeps answering badly gets `MAX_RETRIES`
    /// resends and then nothing, and its session still ends, `Failed`, at
    /// its deadline. No loop between two machines, no session that lives
    /// forever on bad replies.
    #[test]
    fn a_peer_that_keeps_answering_badly_gets_bounded_resends_and_fails_at_the_deadline() {
        let pki = test_pki();
        let initiator = make_guid(0x00);
        let responder = make_guid(0xFE);
        let init = HandshakeMachine::new();
        let resp = HandshakeMachine::new();

        let request = request_from(&init, initiator, responder, &pki);
        let reply = answer(&resp, initiator, &request, responder, &pki);
        let mut token = match parse_token(&reply).expect("parse") {
            TokenKind::Reply(token) => token,
            _ => panic!("not a reply"),
        };
        token.signature[4] ^= 0x01;
        let bad_reply = encode_reply(&token).expect("encode");
        let mut resent = 0;
        for _ in 0..10 {
            match init.on_message(
                responder, &bad_reply, initiator, &pki.cert, &pki.key, &pki.ca,
            ) {
                Ok(HandshakeAction::SendRequest(..)) => resent += 1,
                Ok(HandshakeAction::Ignored(..)) => {}
                other => panic!("a bad reply is refused, got {:?}", other),
            }
        }
        assert_eq!(resent, 3, "MAX_RETRIES resends, then none");
        assert!(
            init.has_session(&responder),
            "in progress until its deadline"
        );
        assert!(
            init.tick(Instant::now()).is_empty(),
            "the ladder is spent: the timer resends nothing more"
        );

        let actions = init.tick(Instant::now() + DEADLINE + PAST);
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, HandshakeAction::Failed(..))),
            "the session fails at its deadline, got {:?}",
            actions
        );
        assert!(!init.is_authenticated(&responder));
        assert!(
            init.start(initiator, responder, &pki.cert, &pki.key)
                .expect("start")
                .is_some(),
            "a failed session begins again on the next announcement"
        );
    }

    /// The same rule at the responder: a refused AuthFinal puts `ReplySent`
    /// back and sends the AuthReply again, within the same bound.
    #[test]
    fn a_refused_final_resends_the_reply_within_the_bound() {
        let pki = test_pki();
        let initiator = make_guid(0x00);
        let responder = make_guid(0xFE);
        let init = HandshakeMachine::new();
        let resp = HandshakeMachine::new();
        let request = request_from(&init, initiator, responder, &pki);
        let reply = answer(&resp, initiator, &request, responder, &pki);
        let final_bytes = answer(&init, responder, &reply, initiator, &pki);
        let mut forged = match parse_token(&final_bytes).expect("parse") {
            TokenKind::Final(t) => t,
            _ => panic!("not a final"),
        };
        forged.signature[4] ^= 0x01;
        let forged = encode_final(&forged).expect("encode");
        let outcomes: Vec<_> = (0..5)
            .map(|_| resp.on_message(initiator, &forged, responder, &pki.cert, &pki.key, &pki.ca))
            .collect();
        assert_eq!(
            outcomes
                .iter()
                .filter(|o| matches!(o, Ok(HandshakeAction::SendReply(..))))
                .count(),
            3,
            "got {:?}",
            outcomes
        );
        assert!(outcomes[3..]
            .iter()
            .all(|o| matches!(o, Ok(HandshakeAction::Ignored(..)))));
        let outcome = resp.on_message(
            initiator,
            &final_bytes,
            responder,
            &pki.cert,
            &pki.key,
            &pki.ca,
        );
        assert!(
            matches!(outcome, Ok(HandshakeAction::Completed(..))),
            "the genuine AuthFinal still completes, got {:?}",
            outcome
        );
    }

    /// A panic inside the verification window does not leave the
    /// `verifying` note set, which would lock the peer out for good
    /// (`Verifying` is a drop guard).
    #[test]
    fn a_panic_in_the_verification_window_clears_the_note() {
        let pki = test_pki();
        let initiator = make_guid(0x00);
        let responder = make_guid(0xFE);
        let init = HandshakeMachine::new();
        let resp = HandshakeMachine::new();
        let request = request_from(&init, initiator, responder, &pki);
        let reply = answer(&resp, initiator, &request, responder, &pki);
        let final_bytes = answer(&init, responder, &reply, initiator, &pki);
        resp.set_parked_hook(Box::new(|_: &HandshakeMachine| panic!("injected panic")));
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            resp.on_message(
                initiator,
                &final_bytes,
                responder,
                &pki.cert,
                &pki.key,
                &pki.ca,
            )
        }));
        assert!(r.is_err(), "fixture: the hook panicked inside the window");
        let began = resp
            .start(responder, initiator, &pki.cert, &pki.key)
            .expect("start");
        assert!(
            began.is_some(),
            "a panic in verification locked the peer out"
        );
    }

    /// DDS Security v1.1 Sec.8.3.2.9.1 rule 3: an AuthFinal whose echoes do
    /// not match (an off-path sender knowing only the prefix) does not fail
    /// the session in progress: the genuine AuthFinal arriving next still
    /// completes it.
    #[test]
    fn a_forged_final_does_not_end_the_session_in_progress() {
        let pki = test_pki();
        let initiator = make_guid(0x00);
        let responder = make_guid(0xFE);
        let init = HandshakeMachine::new();
        let resp = HandshakeMachine::new();
        let request = request_from(&init, initiator, responder, &pki);
        let reply = answer(&resp, initiator, &request, responder, &pki);
        let final_bytes = answer(&init, responder, &reply, initiator, &pki);
        let mut forged = match parse_token(&final_bytes).expect("parse") {
            TokenKind::Final(t) => t,
            _ => panic!("not a final"),
        };
        forged.challenge1 = [0x5A; 32];
        let forged = encode_final(&forged).expect("encode");
        let _ = resp.on_message(initiator, &forged, responder, &pki.cert, &pki.key, &pki.ca);
        let outcome = resp.on_message(
            initiator,
            &final_bytes,
            responder,
            &pki.cert,
            &pki.key,
            &pki.ca,
        );
        assert!(
            matches!(outcome, Ok(HandshakeAction::Completed(..))),
            "one forged AuthFinal killed the in-progress session: {:?}",
            outcome
        );
    }

    /// A key of the attacker's own, valid on the curve: what an on-path
    /// attacker puts in place of a DH public key it wants to know the
    /// secret of.
    fn attacker_dh_key() -> Vec<u8> {
        use crate::security::crypto::key_exchange::{EcdhKeyExchange, KeyAgreementSuite};
        EcdhKeyExchange::generate_keypair(KeyAgreementSuite::EcdhP256)
            .expect("keypair")
            .0
    }

    /// An on-path attacker that swaps dh2 in a genuine AuthReply for a key
    /// of its own would share the initiator's secret: the reply signature
    /// covers dh2 (DDS Security v1.1 Sec.9.3.2.5.2: hash_c2, challenge2,
    /// dh2, challenge1, dh1, hash_c1), so the initiator refuses the reply,
    /// sends no AuthFinal and derives no key, and the genuine reply then
    /// completes the session.
    #[test]
    fn a_reply_whose_dh2_was_swapped_is_refused() {
        let pki = test_pki();
        let initiator = make_guid(0x00);
        let responder = make_guid(0xFE);
        let init = HandshakeMachine::new();
        let resp = HandshakeMachine::new();
        let request = request_from(&init, initiator, responder, &pki);
        let reply = answer(&resp, initiator, &request, responder, &pki);

        let mut forged = match parse_token(&reply).expect("parse") {
            TokenKind::Reply(t) => t,
            _ => panic!("not a reply"),
        };
        forged.dh2 = attacker_dh_key();
        let forged = encode_reply(&forged).expect("encode");
        let outcome = init.on_message(responder, &forged, initiator, &pki.cert, &pki.key, &pki.ca);
        assert!(
            !matches!(outcome, Ok(HandshakeAction::SendFinal(..))),
            "a reply with the attacker's dh2 was answered: {:?}",
            outcome
        );
        assert!(!init.is_authenticated(&responder));
        assert!(init.shared_secret_for(&responder).is_none());

        let final_bytes = answer(&init, responder, &reply, initiator, &pki);
        assert!(matches!(
            resp.on_message(
                initiator,
                &final_bytes,
                responder,
                &pki.cert,
                &pki.key,
                &pki.ca
            ),
            Ok(HandshakeAction::Completed(..))
        ));
    }

    /// Whether `signature` verifies over `data` under the key of the PEM
    /// certificate `cert`, checked here with ring directly rather than with
    /// the machine's own verifier.
    fn signed_by(cert: &[u8], data: &[u8], signature: &[u8]) -> bool {
        use ring::signature::{UnparsedPublicKey, ECDSA_P256_SHA256_ASN1, ECDSA_P256_SHA256_FIXED};
        let (_, pem) = x509_parser::pem::parse_x509_pem(cert).expect("PEM");
        let cert = pem.parse_x509().expect("X.509");
        let key = cert.public_key().subject_public_key.data.as_ref();
        UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, key)
            .verify(data, signature)
            .is_ok()
            || UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, key)
                .verify(data, signature)
                .is_ok()
    }

    /// Two machines whose `c.perm` differ, so that their hash_c1 and
    /// hash_c2 differ and a signature over one in place of the other shows.
    fn machines_with_distinct_hashes() -> (HandshakeMachine, HandshakeMachine) {
        (
            HandshakeMachine::new().with_local_permissions(Some(b"initiator".to_vec())),
            HandshakeMachine::new().with_local_permissions(Some(b"responder".to_vec())),
        )
    }

    /// The reply signature is over the sequence of Table 50, rebuilt here
    /// from the property names and the two tokens rather than with
    /// `reply_sign_input`: a machine that passed its arguments in another
    /// order would still pair with itself, and with no other implementation.
    #[test]
    fn the_reply_signature_is_over_the_sequence_of_table_50() {
        use crate::security::handshake::tokens::binary_property_seq_be;
        let pki = test_pki();
        let initiator = make_guid(0x00);
        let responder = make_guid(0xFE);
        let (init, resp) = machines_with_distinct_hashes();
        let request = request_from(&init, initiator, responder, &pki);
        let reply = answer(&resp, initiator, &request, responder, &pki);
        let (req, rep) = match (parse_token(&request), parse_token(&reply)) {
            (Ok(TokenKind::Request(req)), Ok(TokenKind::Reply(rep))) => (req, rep),
            other => panic!("expected a request and a reply, got {:?}", other),
        };
        let (hash_c1, hash_c2) = (req.hash_c1().expect("hash"), rep.hash_c2().expect("hash"));
        assert_ne!(hash_c1, hash_c2);
        let signed = binary_property_seq_be(&[
            ("hash_c2", &hash_c2),
            ("challenge2", &rep.challenge2),
            ("dh2", &rep.dh2),
            ("challenge1", &req.challenge1),
            ("dh1", &req.dh1),
            ("hash_c1", &hash_c1),
        ])
        .expect("serialize");
        assert!(signed_by(&pki.cert, &signed, &rep.signature));
    }

    /// The final signature is over the sequence of Table 51, rebuilt as for
    /// the reply.
    #[test]
    fn the_final_signature_is_over_the_sequence_of_table_51() {
        use crate::security::handshake::tokens::binary_property_seq_be;
        let pki = test_pki();
        let initiator = make_guid(0x00);
        let responder = make_guid(0xFE);
        let (init, resp) = machines_with_distinct_hashes();
        let request = request_from(&init, initiator, responder, &pki);
        let reply = answer(&resp, initiator, &request, responder, &pki);
        let final_bytes = answer(&init, responder, &reply, initiator, &pki);
        let (req, rep, fin) = match (
            parse_token(&request),
            parse_token(&reply),
            parse_token(&final_bytes),
        ) {
            (Ok(TokenKind::Request(req)), Ok(TokenKind::Reply(rep)), Ok(TokenKind::Final(fin))) => {
                (req, rep, fin)
            }
            other => panic!("expected a request, a reply and a final, got {:?}", other),
        };
        let (hash_c1, hash_c2) = (req.hash_c1().expect("hash"), rep.hash_c2().expect("hash"));
        assert_ne!(hash_c1, hash_c2);
        let signed = binary_property_seq_be(&[
            ("hash_c1", &hash_c1),
            ("challenge1", &req.challenge1),
            ("dh1", &req.dh1),
            ("challenge2", &rep.challenge2),
            ("dh2", &rep.dh2),
            ("hash_c2", &hash_c2),
        ])
        .expect("serialize");
        assert!(signed_by(&pki.cert, &signed, &fin.signature));
    }

    /// A request whose `c.perm` was replaced on the way (by another valid
    /// permissions document) authenticates nobody: its hash_c1 is in both
    /// signatures, and the initiator signs the hash of the request it sent.
    /// HDDS before 1.5 signed no hash, and both sides completed, the
    /// responder holding the substituted document as the initiator's.
    #[test]
    fn a_request_whose_permissions_were_replaced_on_the_way_completes_nothing() {
        let pki = test_pki();
        let initiator = make_guid(0x00);
        let responder = make_guid(0xFE);
        let (init, resp) = machines_with_distinct_hashes();
        let request = request_from(&init, initiator, responder, &pki);
        let mut forged = match parse_token(&request).expect("parse") {
            TokenKind::Request(t) => t,
            _ => panic!("not a request"),
        };
        forged.permissions_doc = Some(b"substituted".to_vec());
        let forged = encode_request(&forged).expect("encode");
        let reply = answer(&resp, initiator, &forged, responder, &pki);
        let outcome = init.on_message(responder, &reply, initiator, &pki.cert, &pki.key, &pki.ca);
        if let Ok(HandshakeAction::SendFinal(_, fin)) = &outcome {
            let completed = resp.on_message(
                initiator,
                &encode_final(fin).expect("encode"),
                responder,
                &pki.cert,
                &pki.key,
                &pki.ca,
            );
            assert!(
                !matches!(completed, Ok(HandshakeAction::Completed(..))),
                "the responder completed on a substituted permissions document"
            );
        }
        assert!(!init.is_authenticated(&responder), "{:?}", outcome);
        assert!(!resp.is_authenticated(&initiator));
    }

    /// The responder verifies the final over the hash_c1 of the request it
    /// received: a final signed over the hash of another request (the one
    /// the initiator sent, when the responder's copy was changed on the
    /// way) is refused, and the same final signed over the received
    /// request's hash completes - so it is the hash that refuses it.
    #[test]
    fn a_final_over_another_request_s_hash_is_refused() {
        use crate::security::handshake::tokens::final_sign_input;
        use ring::signature::{EcdsaKeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};
        let pki = test_pki();
        let initiator = make_guid(0x00);
        let responder = make_guid(0xFE);
        let rng = ring::rand::SystemRandom::new();
        let key_der = ::pem::parse(&pki.key).expect("PEM").into_contents();
        let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &key_der, &rng)
            .expect("the test identity key");

        // The final the initiator signs over the hash_c1 of its request
        // with `c.perm` = `perm`, the responder having received it with
        // `c.perm` = "substituted".
        let final_over = |perm: &[u8]| {
            let (init, resp) = machines_with_distinct_hashes();
            let request = request_from(&init, initiator, responder, &pki);
            let sent = match parse_token(&request).expect("parse") {
                TokenKind::Request(t) => t,
                _ => panic!("not a request"),
            };
            let received = AuthRequestToken {
                permissions_doc: Some(b"substituted".to_vec()),
                ..sent.clone()
            };
            let reply = answer(
                &resp,
                initiator,
                &encode_request(&received).expect("encode"),
                responder,
                &pki,
            );
            let rep = match parse_token(&reply).expect("parse") {
                TokenKind::Reply(t) => t,
                _ => panic!("not a reply"),
            };
            let hash_c1 = AuthRequestToken {
                permissions_doc: Some(perm.to_vec()),
                ..sent.clone()
            }
            .hash_c1()
            .expect("hash");
            let signed = final_sign_input(
                &hash_c1,
                &sent.challenge1,
                &sent.dh1,
                &rep.challenge2,
                &rep.dh2,
                &rep.hash_c2().expect("hash"),
            )
            .expect("serialize");
            let fin = AuthFinalToken {
                hash_c1: None,
                hash_c2: None,
                challenge1: sent.challenge1,
                challenge2: rep.challenge2,
                dh1: Some(sent.dh1.clone()),
                dh2: Some(rep.dh2.clone()),
                signature: key.sign(&rng, &signed).expect("sign").as_ref().to_vec(),
            };
            resp.on_message(
                initiator,
                &encode_final(&fin).expect("encode"),
                responder,
                &pki.cert,
                &pki.key,
                &pki.ca,
            )
        };

        let outcome = final_over(b"initiator");
        assert!(
            !matches!(outcome, Ok(HandshakeAction::Completed(..))),
            "a final over the hash of another request completed: {:?}",
            outcome
        );
        let outcome = final_over(b"substituted");
        assert!(
            matches!(outcome, Ok(HandshakeAction::Completed(..))),
            "the control final must complete: {:?}",
            outcome
        );
    }

    /// The reply's `hash_c1` and the final's `hash_c1`/`hash_c2`, when they
    /// are sent (optional, Tables 50 and 51), are the hashes of the request
    /// and the reply of this session, and the final's dh1 is the request's:
    /// an echo of any other is refused, and the genuine message completes
    /// the session after it.
    #[test]
    fn an_echo_that_is_not_this_session_s_is_refused() {
        let pki = test_pki();
        let initiator = make_guid(0x00);
        let responder = make_guid(0xFE);
        let init = HandshakeMachine::new();
        let resp = HandshakeMachine::new();
        let request = request_from(&init, initiator, responder, &pki);
        let reply = answer(&resp, initiator, &request, responder, &pki);

        let mut forged = match parse_token(&reply).expect("parse") {
            TokenKind::Reply(t) => t,
            _ => panic!("not a reply"),
        };
        assert!(forged.hash_c1.is_some(), "HDDS sends the hash_c1 echo");
        forged.hash_c1 = Some([0x77; 32]);
        let forged = encode_reply(&forged).expect("encode");
        let outcome = init.on_message(responder, &forged, initiator, &pki.cert, &pki.key, &pki.ca);
        assert!(
            !matches!(outcome, Ok(HandshakeAction::SendFinal(..))),
            "a reply echoing another hash_c1 was answered: {:?}",
            outcome
        );
        assert!(!init.is_authenticated(&responder));
        let final_bytes = answer(&init, responder, &reply, initiator, &pki);

        let token = match parse_token(&final_bytes).expect("parse") {
            TokenKind::Final(t) => t,
            _ => panic!("not a final"),
        };
        assert!(token.hash_c1.is_some() && token.hash_c2.is_some());
        for forged in [
            AuthFinalToken {
                hash_c1: Some([0x77; 32]),
                ..token.clone()
            },
            // dh1 too is an echo (Table 51: the request's dh1), and the
            // signature is verified over the dh1 we received, so only the
            // echo check refuses this one.
            AuthFinalToken {
                dh1: Some(attacker_dh_key()),
                ..token.clone()
            },
            AuthFinalToken {
                hash_c2: Some([0x77; 32]),
                ..token.clone()
            },
        ] {
            let forged = encode_final(&forged).expect("encode");
            let outcome =
                resp.on_message(initiator, &forged, responder, &pki.cert, &pki.key, &pki.ca);
            assert!(
                !matches!(outcome, Ok(HandshakeAction::Completed(..))),
                "a final echoing another hash completed: {:?}",
                outcome
            );
            assert!(!resp.is_authenticated(&initiator));
        }
        let outcome = resp.on_message(
            initiator,
            &final_bytes,
            responder,
            &pki.cert,
            &pki.key,
            &pki.ca,
        );
        assert!(
            matches!(outcome, Ok(HandshakeAction::Completed(..))),
            "the genuine final after the refused ones: {:?}",
            outcome
        );
    }

    /// `bytes`, a handshake message, without its binary properties `names`.
    fn without(bytes: &[u8], names: &[&str]) -> Vec<u8> {
        use crate::protocol::discovery::spdp::data_holder::{
            parse_data_holder, serialize_data_holder,
        };
        let mut holder = parse_data_holder(bytes).expect("a DataHolder");
        holder
            .binary_properties
            .retain(|(n, _, _)| !names.contains(&n.as_str()));
        serialize_data_holder(&holder.class_id, &[], &holder.binary_properties).expect("encode")
    }

    /// DDS Security v1.1 Table 50: the reply's dh1, and Table 51: the
    /// final's dh1 and dh2, "Inclusion of the dh1 property is optional": a
    /// reply without dh1 and a final without either complete the session,
    /// signed and derived over the values the session holds, and both sides
    /// hold one secret. A dh1 that is present and is not the request's is
    /// still refused.
    #[test]
    fn the_optional_dh_echoes_may_be_omitted() {
        let pki = test_pki();
        let initiator = make_guid(0x00);
        let responder = make_guid(0xFE);
        let init = HandshakeMachine::new();
        let resp = HandshakeMachine::new();
        let request = request_from(&init, initiator, responder, &pki);
        let reply = answer(&resp, initiator, &request, responder, &pki);

        let mut forged = match parse_token(&reply).expect("parse") {
            TokenKind::Reply(t) => t,
            _ => panic!("not a reply"),
        };
        forged.dh1 = Some(attacker_dh_key());
        let forged = encode_reply(&forged).expect("encode");
        let outcome = init.on_message(responder, &forged, initiator, &pki.cert, &pki.key, &pki.ca);
        assert!(
            !matches!(outcome, Ok(HandshakeAction::SendFinal(..))),
            "a reply echoing another dh1 was answered: {:?}",
            outcome
        );

        let final_bytes = answer(
            &init,
            responder,
            &without(&reply, &["dh1"]),
            initiator,
            &pki,
        );
        assert!(init.is_authenticated(&responder));
        let mut forged = match parse_token(&final_bytes).expect("parse") {
            TokenKind::Final(t) => t,
            _ => panic!("not a final"),
        };
        forged.dh2 = Some(attacker_dh_key());
        let forged = encode_final(&forged).expect("encode");
        let outcome = resp.on_message(initiator, &forged, responder, &pki.cert, &pki.key, &pki.ca);
        assert!(
            !matches!(outcome, Ok(HandshakeAction::Completed(..))),
            "a final echoing another dh2 completed: {:?}",
            outcome
        );
        let outcome = resp.on_message(
            initiator,
            &without(&final_bytes, &["dh1", "dh2"]),
            responder,
            &pki.cert,
            &pki.key,
            &pki.ca,
        );
        assert!(
            matches!(outcome, Ok(HandshakeAction::Completed(..))),
            "a final without its dh echoes: {:?}",
            outcome
        );
        assert_eq!(
            init.shared_secret_for(&responder),
            resp.shared_secret_for(&initiator)
        );
    }

    /// `bytes`, a handshake message, with its binary property `name` set to
    /// `value` and no `hash_c1`/`hash_c2` (optional), which would no longer
    /// be the hash of its `c.` properties.
    fn with_property(bytes: &[u8], name: &str, value: &[u8]) -> Vec<u8> {
        use crate::protocol::discovery::spdp::data_holder::{
            parse_data_holder, serialize_data_holder,
        };
        let mut holder = parse_data_holder(bytes).expect("a DataHolder");
        holder
            .binary_properties
            .retain(|(n, _, _)| n != "hash_c1" && n != "hash_c2");
        for (n, v, _) in &mut holder.binary_properties {
            if n == name {
                *v = value.to_vec();
            }
        }
        serialize_data_holder(&holder.class_id, &[], &holder.binary_properties).expect("encode")
    }

    /// The `c.pdata` of `bytes`, a request or a reply.
    fn c_pdata(bytes: &[u8]) -> Vec<u8> {
        crate::protocol::discovery::spdp::data_holder::parse_data_holder(bytes)
            .expect("a DataHolder")
            .binary_properties
            .into_iter()
            .find(|(n, _, _)| n == "c.pdata")
            .map(|(_, v, _)| v)
            .expect("c.pdata")
    }

    /// DDS Security v1.1 Tables 49 and 50: `c.pdata` is "the CDR Big Endian
    /// serialization of the ParticipantBuiltinTopicData" of the sender, a
    /// parameter list (Sec.7.4.1.3) whose key is its participant GUID; and
    /// Sec.9.3.3 Table 52, begin_handshake_reply: the responder "shall
    /// verify that the first bit of the participant_guid of the
    /// ParticipantBuiltinTopic data inside the c.pdata is set to 1 and that
    /// the following 47 bits match the first 47 bits of the SHA-256 hash of
    /// the SubjectName appearing in the IdentityCredential", else fail. The
    /// initiator checks the reply's the same way, as Cyclone DDS and Fast
    /// DDS do, and both check that it names the participant the handshake is
    /// with.
    #[test]
    fn c_pdata_names_the_participant_its_certificate_binds() {
        let pki = test_pki();
        let initiator = make_guid(0x00);
        let responder = make_guid(0xFE);
        let init = HandshakeMachine::new();
        let resp = HandshakeMachine::new();

        // What goes on the wire: PID_PARTICIPANT_GUID (0x0050), 16 octets,
        // the participant GUID, PID_VENDORID, HDDS capabilities, then
        // PID_SENTINEL (0x0001). Big endian.
        let request = request_from(&init, initiator, responder, &pki);
        let mut expected = vec![0x00, 0x50, 0x00, 0x10];
        expected.extend_from_slice(&initiator.as_bytes());
        expected.extend_from_slice(&[
            0x00, 0x16, 0x00, 0x04, 0x01, 0x1a, 0, 0, 0x80, 0x32, 0x00, 0x04,
        ]);
        expected.extend_from_slice(&crate::protocol::group::LOCAL_CAPABILITIES.to_be_bytes());
        expected.extend_from_slice(&[0x00, 0x01, 0x00, 0x00]);
        assert_eq!(c_pdata(&request), expected, "the request");
        let reply = answer(&resp, initiator, &request, responder, &pki);
        let mut expected = vec![0x00, 0x50, 0x00, 0x10];
        expected.extend_from_slice(&responder.as_bytes());
        expected.extend_from_slice(&[
            0x00, 0x16, 0x00, 0x04, 0x01, 0x1a, 0, 0, 0x80, 0x32, 0x00, 0x04,
        ]);
        expected.extend_from_slice(&crate::protocol::group::LOCAL_CAPABILITIES.to_be_bytes());
        expected.extend_from_slice(&[0x00, 0x01, 0x00, 0x00]);
        assert_eq!(c_pdata(&reply), expected, "the reply");

        // A request whose c.pdata is empty, carries no GUID, or names a
        // participant its certificate does not bind is refused.
        let mut unbound = vec![0x00, 0x50, 0x00, 0x10];
        unbound.extend_from_slice(&[0x01; 12]);
        unbound.extend_from_slice(&[0, 0, 1, 0xC1, 0x00, 0x01, 0x00, 0x00]);
        let other = make_guid(0x01);
        let fresh_request = || request_from(&HandshakeMachine::new(), initiator, responder, &pki);
        for (pdata, what) in [
            (Vec::new(), "empty"),
            (vec![0x00, 0x01, 0x00, 0x00], "no GUID"),
            (unbound, "an unbound GUID"),
        ] {
            let resp = HandshakeMachine::new();
            let forged = with_property(&fresh_request(), "c.pdata", &pdata);
            let outcome =
                resp.on_message(initiator, &forged, responder, &pki.cert, &pki.key, &pki.ca);
            assert!(outcome.is_err(), "{}: {:?}", what, outcome);
            assert!(!resp.has_session(&initiator), "{}: nothing filed", what);
        }

        // A request whose c.pdata is another participant's, bound to the
        // same certificate, presented by `initiator`: refused.
        let resp = HandshakeMachine::new();
        let request = request_from(&HandshakeMachine::new(), other, responder, &pki);
        let outcome = resp.on_message(initiator, &request, responder, &pki.cert, &pki.key, &pki.ca);
        assert!(
            outcome.is_err(),
            "another participant's request: {:?}",
            outcome
        );

        // A reply signed by a responder whose c.pdata is another
        // participant's than the one we address: refused, nothing installed.
        let init = HandshakeMachine::new();
        let request = request_from(&init, initiator, responder, &pki);
        let reply = answer(
            &HandshakeMachine::new(),
            initiator,
            &request,
            make_guid(0xFD),
            &pki,
        );
        let outcome = init.on_message(responder, &reply, initiator, &pki.cert, &pki.key, &pki.ca);
        assert!(
            !matches!(outcome, Ok(HandshakeAction::SendFinal(..))),
            "another participant's reply: {:?}",
            outcome
        );
        assert!(!init.is_authenticated(&responder));
    }

    /// The `c.dsign_algo` of `bytes`, a request or a reply.
    fn c_dsign_algo(bytes: &[u8]) -> Vec<u8> {
        crate::protocol::discovery::spdp::data_holder::parse_data_holder(bytes)
            .expect("a DataHolder")
            .binary_properties
            .into_iter()
            .find(|(n, _, _)| n == "c.dsign_algo")
            .map(|(_, v, _)| v)
            .expect("c.dsign_algo")
    }

    /// DDS Security v1.1 Sec.9.3.2.5.1 and Sec.9.3.2.5.2: "If the
    /// Participant Identity uses a RSA Public Key, then the c.dsign_algo
    /// shall be RSASSA-PSS-SHA256", an EC one "ECDSA-SHA256", and each signs
    /// with that algorithm. An RSA identity and an EC identity authenticate
    /// each other: each announces its own algorithm, each signature is
    /// verified by the algorithm its signer announced, and both hold one
    /// secret.
    #[test]
    fn an_rsa_identity_authenticates_with_rsassa_pss() {
        use crate::security::authentication::guid_binding::{
            adjusted_participant_prefix, subject_name_der,
        };
        use crate::security::test_pki::{
            RSA_IDENTITY_CA_PEM, RSA_IDENTITY_CERT_PEM, RSA_IDENTITY_KEY_PEM,
        };
        let mut ca = real_ca_pem();
        ca.extend_from_slice(RSA_IDENTITY_CA_PEM);
        let rsa = Pki {
            cert: RSA_IDENTITY_CERT_PEM.to_vec(),
            key: RSA_IDENTITY_KEY_PEM.to_vec(),
            ca: ca.clone(),
        };
        let ec = Pki {
            cert: real_cert(),
            key: real_key_pem(),
            ca,
        };
        let rsa_guid = |tail: u8| {
            let subject = subject_name_der(&rsa.cert).expect("subject");
            let mut prefix = adjusted_participant_prefix(&subject, &[0; 16]);
            prefix[6..].copy_from_slice(&[tail; 6]);
            GUID::new(prefix, [0, 0, 0x01, 0xC1])
        };
        let ordered = |a: (GUID, &'static str), b: (GUID, &'static str)| {
            if a.0.prefix < b.0.prefix {
                (a, b)
            } else {
                (b, a)
            }
        };
        // An RSA and an EC identity, whichever initiates; and two RSA
        // identities, so that an RSA initiator signs the final.
        for ((low, low_algo), (high, high_algo)) in [
            ordered(
                (rsa_guid(0x00), "RSASSA-PSS-SHA256"),
                (make_guid(0x00), "ECDSA-SHA256"),
            ),
            ordered(
                (rsa_guid(0x00), "RSASSA-PSS-SHA256"),
                (rsa_guid(0xFE), "RSASSA-PSS-SHA256"),
            ),
        ] {
            let pki_of = |algo: &str| if algo == "ECDSA-SHA256" { &ec } else { &rsa };
            let (low_pki, high_pki) = (pki_of(low_algo), pki_of(high_algo));
            let init = HandshakeMachine::new();
            let resp = HandshakeMachine::new();
            let request = request_from(&init, low, high, low_pki);
            assert_eq!(c_dsign_algo(&request), low_algo.as_bytes(), "the request");
            let reply = answer(&resp, low, &request, high, high_pki);
            assert_eq!(c_dsign_algo(&reply), high_algo.as_bytes(), "the reply");
            let final_bytes = answer(&init, high, &reply, low, low_pki);
            let outcome = resp.on_message(
                low,
                &final_bytes,
                high,
                &high_pki.cert,
                &high_pki.key,
                &high_pki.ca,
            );
            assert!(
                matches!(outcome, Ok(HandshakeAction::Completed(..))),
                "{} -> {}: {:?}",
                low_algo,
                high_algo,
                outcome
            );
            assert_eq!(init.shared_secret_for(&high), resp.shared_secret_for(&low));
        }
    }

    /// A reply that announces another signature algorithm than its key's is
    /// refused, even signed by that key over the c. properties announcing
    /// it: the algorithm is the key's (Sec.9.3.2.5.2).
    #[test]
    fn a_reply_announcing_another_signature_algorithm_is_refused() {
        use crate::security::handshake::tokens::reply_sign_input;
        let pki = test_pki();
        let initiator = make_guid(0x00);
        let responder = make_guid(0xFE);
        let init = HandshakeMachine::new();
        let request = request_from(&init, initiator, responder, &pki);
        let reply = answer(
            &HandshakeMachine::new(),
            initiator,
            &request,
            responder,
            &pki,
        );
        let mut token = match parse_token(&reply).expect("parse") {
            TokenKind::Reply(t) => t,
            _ => panic!("not a reply"),
        };
        let hash_c1 = token.hash_c1.expect("HDDS sends hash_c1");
        let request = match parse_token(&request).expect("parse") {
            TokenKind::Request(t) => t,
            _ => panic!("not a request"),
        };
        token.dsign_algo = "RSASSA-PSS-SHA256".to_string();
        let input = reply_sign_input(
            &token.hash_c2().expect("hash"),
            &token.challenge2,
            &token.dh2,
            &request.challenge1,
            &request.dh1,
            &hash_c1,
        )
        .expect("serialize");
        let pem = ::pem::parse(&pki.key).expect("PEM");
        let rng = ring::rand::SystemRandom::new();
        token.signature = ring::signature::EcdsaKeyPair::from_pkcs8(
            &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
            pem.contents(),
            &rng,
        )
        .expect("key")
        .sign(&rng, &input)
        .expect("sign")
        .as_ref()
        .to_vec();
        let forged = encode_reply(&token).expect("encode");
        let outcome = init.on_message(responder, &forged, initiator, &pki.cert, &pki.key, &pki.ca);
        assert!(
            !matches!(outcome, Ok(HandshakeAction::SendFinal(..))),
            "{:?}",
            outcome
        );
        assert!(!init.is_authenticated(&responder));
    }

    /// The signature algorithm a peer announces is the one of its
    /// certificate's key (Sec.9.3.2.5.1): one that is not, or one the
    /// specification does not define, refuses the handshake; the
    /// terminating NUL Cyclone DDS sends is no part of the name.
    #[test]
    fn a_signature_algorithm_that_is_not_the_certificate_s_is_refused() {
        let pki = test_pki();
        let initiator = make_guid(0x00);
        let responder = make_guid(0xFE);
        for (algo, accepted) in [
            (&b"RSASSA-PSS-SHA256"[..], false),
            (&b"ECDSA-SHA384"[..], false),
            (&b""[..], false),
            (&b"ECDSA-SHA256\0"[..], true),
        ] {
            let resp = HandshakeMachine::new();
            let request = with_property(
                &request_from(&HandshakeMachine::new(), initiator, responder, &pki),
                "c.dsign_algo",
                algo,
            );
            let outcome =
                resp.on_message(initiator, &request, responder, &pki.cert, &pki.key, &pki.ca);
            assert_eq!(
                matches!(outcome, Ok(HandshakeAction::SendReply(..))),
                accepted,
                "{:?}: {:?}",
                String::from_utf8_lossy(algo),
                outcome
            );
        }
    }

    /// The verification of a dropped session that ends while the session
    /// that replaced it is itself out for verification leaves that one's
    /// note: an announcement handled then begins nothing, and the new
    /// session completes. Each verification removes only the note of its own
    /// generation.
    #[test]
    fn a_stale_verification_that_ends_leaves_the_note_of_the_current_one() {
        use std::sync::mpsc;
        let pki = test_pki();
        let initiator = make_guid(0x00);
        let responder = make_guid(0xFE);
        let init = Arc::new(HandshakeMachine::new());
        let resp = HandshakeMachine::new();

        let request = request_from(&init, initiator, responder, &pki);
        let reply = answer(&resp, initiator, &request, responder, &pki);

        let (reply2_tx, reply2_rx) = mpsc::channel::<Vec<u8>>();
        let (parked_tx, parked_rx) = mpsc::channel::<()>();
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let reply2_tx = parking_lot::Mutex::new(reply2_tx);
        let parked_rx = parking_lot::Mutex::new(parked_rx);
        let parked_tx = parking_lot::Mutex::new(parked_tx);
        let release_rx = Arc::new(parking_lot::Mutex::new(release_rx));
        let (cert, key) = (pki.cert.clone(), pki.key.clone());
        init.set_parked_hook(Box::new(move |m: &HandshakeMachine| {
            // In the first reply's window: its session is dropped and a new
            // one begins, answered by a responder that never saw the first.
            m.drop_handshake(&responder);
            let request2 = match m
                .start(initiator, responder, &cert, &key)
                .expect("start")
                .expect("a new session begins")
            {
                HandshakeAction::SendRequest(_, token) => encode_request(&token).expect("encode"),
                other => panic!("expected SendRequest, got {:?}", other),
            };
            let pki2 = test_pki();
            let reply2 = answer(
                &HandshakeMachine::new(),
                initiator,
                &request2,
                responder,
                &pki2,
            );
            // The second reply parks in its own window until released.
            let parked_tx = parking_lot::Mutex::new(parked_tx.lock().clone());
            let release_rx = Arc::clone(&release_rx);
            m.set_parked_hook(Box::new(move |_: &HandshakeMachine| {
                parked_tx.lock().send(()).expect("parked");
                release_rx.lock().recv().expect("release");
            }));
            reply2_tx.lock().send(reply2).expect("reply2");
            // The first verification ends only once the second is out.
            parked_rx.lock().recv().expect("second reply parked");
        }));

        let first = {
            let init = Arc::clone(&init);
            let pki = test_pki();
            std::thread::spawn(move || {
                init.on_message(responder, &reply, initiator, &pki.cert, &pki.key, &pki.ca)
            })
        };
        let reply2 = reply2_rx.recv().expect("reply2");
        let second = {
            let init = Arc::clone(&init);
            let pki = test_pki();
            std::thread::spawn(move || {
                init.on_message(responder, &reply2, initiator, &pki.cert, &pki.key, &pki.ca)
            })
        };
        let first = first.join().expect("first");
        assert!(
            first.is_err(),
            "fixture: the dropped session installs nothing, got {:?}",
            first
        );

        let began = init
            .start(initiator, responder, &pki.cert, &pki.key)
            .expect("start")
            .is_some();
        release_tx.send(()).expect("release");
        let second = second.join().expect("second");

        assert!(
            !began,
            "an announcement while the current session is verified began another"
        );
        assert!(
            matches!(second, Ok(HandshakeAction::SendFinal(..))),
            "the current session must complete, got {:?}",
            second
        );
        assert!(init.is_authenticated(&responder));
    }

    /// An AuthRequest is signed by nobody. One arriving for a peer we
    /// completed with (a participant re-created under the same prefix sends
    /// exactly that) must not cost the completed session anything until the
    /// new one is proven.
    #[test]
    fn an_authrequest_alone_does_not_unseat_a_completed_session() {
        let pair = completed_pair();
        let pki = test_pki();
        let secret = pair
            .resp
            .shared_secret_for(&pair.initiator_guid)
            .expect("completed");

        let again = HandshakeMachine::new();
        let request = request_from(&again, pair.initiator_guid, pair.responder_guid, &pki);
        let _reply = answer(
            &pair.resp,
            pair.initiator_guid,
            &request,
            pair.responder_guid,
            &pki,
        );

        assert!(
            pair.resp.is_authenticated(&pair.initiator_guid),
            "an unsigned AuthRequest de-authenticated a completed peer"
        );
        assert_eq!(
            pair.resp.shared_secret_for(&pair.initiator_guid),
            Some(secret)
        );
    }

    /// ... and the new session replaces it once its own AuthFinal, signed by
    /// the peer, verifies: the peer that came back gets the keys it now holds.
    #[test]
    fn a_reauthentication_replaces_the_completed_session_at_its_final() {
        let pair = completed_pair();
        let pki = test_pki();
        let old_secret = pair
            .resp
            .shared_secret_for(&pair.initiator_guid)
            .expect("completed");

        let again = HandshakeMachine::new();
        let request = request_from(&again, pair.initiator_guid, pair.responder_guid, &pki);
        let reply = answer(
            &pair.resp,
            pair.initiator_guid,
            &request,
            pair.responder_guid,
            &pki,
        );
        // A duplicate of the OLD session's AuthFinal arriving now changes
        // nothing: its echoes are not the pending session's.
        match pair
            .resp
            .on_message(
                pair.initiator_guid,
                &pair.final_bytes,
                pair.responder_guid,
                &pki.cert,
                &pki.key,
                &pki.ca,
            )
            .expect("a duplicate is ordinary traffic")
        {
            HandshakeAction::Completed(_, secret) => assert_eq!(secret, old_secret),
            other => panic!("expected Completed, got {:?}", other),
        }

        let final_bytes = answer(
            &again,
            pair.responder_guid,
            &reply,
            pair.initiator_guid,
            &pki,
        );
        pair.resp
            .on_message(
                pair.initiator_guid,
                &final_bytes,
                pair.responder_guid,
                &pki.cert,
                &pki.key,
                &pki.ca,
            )
            .expect("the new session completes");

        let new_secret = again
            .shared_secret_for(&pair.responder_guid)
            .expect("the returning peer completed");
        assert_ne!(new_secret, old_secret);
        assert_eq!(
            pair.resp.shared_secret_for(&pair.initiator_guid),
            Some(new_secret),
            "the responder must now hold the keys the returning peer holds"
        );
    }

    /// A re-authentication whose AuthFinal does not verify is forgotten; the
    /// completed session stays.
    #[test]
    fn a_reauthentication_with_a_forged_final_keeps_the_completed_session() {
        let pair = completed_pair();
        let pki = test_pki();
        let old_secret = pair
            .resp
            .shared_secret_for(&pair.initiator_guid)
            .expect("completed");

        let again = HandshakeMachine::new();
        let request = request_from(&again, pair.initiator_guid, pair.responder_guid, &pki);
        let reply = answer(
            &pair.resp,
            pair.initiator_guid,
            &request,
            pair.responder_guid,
            &pki,
        );
        let final_bytes = answer(
            &again,
            pair.responder_guid,
            &reply,
            pair.initiator_guid,
            &pki,
        );
        let mut token = match parse_token(&final_bytes).expect("parse") {
            TokenKind::Final(token) => token,
            _ => panic!("not a final"),
        };
        let last = token.signature.len() - 1;
        token.signature[last] ^= 0xFF;
        let forged = encode_final(&token).expect("encode");

        let outcome = pair.resp.on_message(
            pair.initiator_guid,
            &forged,
            pair.responder_guid,
            &pki.cert,
            &pki.key,
            &pki.ca,
        );
        assert!(outcome.is_err(), "got {:?}", outcome);
        assert_eq!(
            pair.resp.shared_secret_for(&pair.initiator_guid),
            Some(old_secret),
            "a forged AuthFinal must not cost the completed session"
        );
    }

    /// A peer we completed with authenticates again only under the identity it
    /// completed with. Any certificate the CA issued could otherwise open a
    /// session under that peer's prefix and complete it with its own key.
    ///
    /// Two defences answer it: the session is held to the certificate it
    /// completed with (`refuses_reauthentication`), and the participant data
    /// of a request must be bound to its certificate (DDS Security v1.1
    /// Sec.9.3.3, Table 52), which refuses another subject's certificate.
    #[test]
    fn a_completed_peer_cannot_authenticate_again_under_another_certificate() {
        use crate::security::authentication::guid_binding::{
            adjusted_participant_prefix, subject_name_der,
        };
        use crate::security::test_pki::{
            REVOCATION_CA_PEM, REVOCATION_GOOD_IDENTITY_PEM, REVOCATION_LOCAL_IDENTITY_KEY_PEM,
            REVOCATION_LOCAL_IDENTITY_PEM,
        };
        let pki = Pki {
            cert: REVOCATION_LOCAL_IDENTITY_PEM.to_vec(),
            key: REVOCATION_LOCAL_IDENTITY_KEY_PEM.to_vec(),
            ca: REVOCATION_CA_PEM.to_vec(),
        };
        let bound = |tail: u8| {
            let subject = subject_name_der(&pki.cert).expect("subject");
            let mut prefix = adjusted_participant_prefix(&subject, &[0; 16]);
            prefix[6..].copy_from_slice(&[tail; 6]);
            GUID::new(prefix, [0, 0, 0x01, 0xC1])
        };
        let (initiator, responder) = (bound(0x00), bound(0xFE));
        let init = HandshakeMachine::new();
        let resp = HandshakeMachine::new();
        let request = request_from(&init, initiator, responder, &pki);
        let reply = answer(&resp, initiator, &request, responder, &pki);
        let final_bytes = answer(&init, responder, &reply, initiator, &pki);
        resp.on_message(
            initiator,
            &final_bytes,
            responder,
            &pki.cert,
            &pki.key,
            &pki.ca,
        )
        .expect("completes");
        let secret = resp.shared_secret_for(&initiator).expect("completed");

        // Another certificate of the same CA, valid and unrevoked. An
        // AuthRequest carries no signature, so its key is not needed to
        // send one.
        let other = Pki {
            cert: REVOCATION_GOOD_IDENTITY_PEM.to_vec(),
            key: pki.key.clone(),
            ca: pki.ca.clone(),
        };
        let intruder = HandshakeMachine::new();
        let request = request_from(&intruder, initiator, responder, &other);
        let outcome = resp.on_message(initiator, &request, responder, &pki.cert, &pki.key, &pki.ca);

        assert!(
            outcome.is_err(),
            "an AuthRequest under another certificate must be refused, got {:?}",
            outcome
        );
        assert_eq!(resp.shared_secret_for(&initiator), Some(secret));
    }

    /// DDS Security v1.1 Sec.9.3.3, Table 52, begin_handshake_reply: the
    /// initiator's participant is the one its certificate names - bit 0 of
    /// its prefix set, bits 1 to 47 those of its SubjectName's SHA-256 - or
    /// the handshake fails. A certificate the CA issued, presented under the
    /// prefix of another subject, authenticates nothing; nor does a responder
    /// replying under one, at the initiator. The prefix of the HDDS shape
    /// before the binding (vendor id first) is refused as any unbound one:
    /// HDDS before 1.5 cannot authenticate with this release.
    #[test]
    fn a_participant_is_the_one_its_certificate_names() {
        let pki = test_pki();
        let bound_low = make_guid(0x00);
        let bound_high = make_guid(0xFE);
        let foreign_low = GUID::new([0x01, 0x0f, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], [0, 0, 1, 0xC1]);
        let mut hdds = [0x00u8; 12];
        hdds[..2].copy_from_slice(&crate::core::rtps_constants::HDDS_VENDOR_ID);
        let hdds_low = GUID::new(hdds, [0, 0, 1, 0xC1]);

        // An initiator under a prefix its certificate does not bind.
        let resp = HandshakeMachine::new();
        let request = request_from(&HandshakeMachine::new(), foreign_low, bound_high, &pki);
        let refused = resp.on_message(
            foreign_low,
            &request,
            bound_high,
            &pki.cert,
            &pki.key,
            &pki.ca,
        );
        assert!(refused.is_err(), "got {:?}", refused);
        assert!(!resp.has_session(&foreign_low), "nothing filed for it");

        // The HDDS shape before the binding: refused as well.
        let request = request_from(&HandshakeMachine::new(), hdds_low, bound_high, &pki);
        let refused = resp.on_message(hdds_low, &request, bound_high, &pki.cert, &pki.key, &pki.ca);
        assert!(refused.is_err(), "got {:?}", refused);
        assert!(!resp.has_session(&hdds_low), "nothing filed for it");

        // A responder replying under a prefix its certificate does not bind:
        // the initiator refuses the reply and installs nothing.
        let init = HandshakeMachine::new();
        let unbound_high = GUID::new([0xff, 0x0f, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], [0, 0, 1, 0xC1]);
        assert!(
            bound_low.prefix < unbound_high.prefix,
            "fixture: we initiate"
        );
        let request = request_from(&init, bound_low, unbound_high, &pki);
        let reply = answer(
            &HandshakeMachine::new(),
            bound_low,
            &request,
            unbound_high,
            &pki,
        );
        let outcome = init.on_message(
            unbound_high,
            &reply,
            bound_low,
            &pki.cert,
            &pki.key,
            &pki.ca,
        );
        assert!(
            matches!(outcome, Ok(HandshakeAction::SendRequest(..))),
            "refused, the AuthRequest sent again (Sec.8.3.2.9.1 rule 3); got {:?}",
            outcome
        );
        assert!(!init.is_authenticated(&unbound_high));

        // Bound on both sides: the control.
        let init = HandshakeMachine::new();
        let request = request_from(&init, bound_low, bound_high, &pki);
        let reply = answer(
            &HandshakeMachine::new(),
            bound_low,
            &request,
            bound_high,
            &pki,
        );
        let _ = answer(&init, bound_high, &reply, bound_low, &pki);
        assert!(init.is_authenticated(&bound_high));
    }

    /// An AuthRequest is signed by nobody, so one arriving while a handshake
    /// is in progress (`ReplySent`) must not replace it: the legitimate
    /// AuthFinal still completes it. Before, the second request took the
    /// session's place, the AuthFinal failed its echo check, and the pair was
    /// stuck - we are the responder and never begin again.
    #[test]
    fn an_authrequest_during_a_handshake_does_not_replace_it() {
        let pki = test_pki();
        let initiator = make_guid(0x00);
        let responder = make_guid(0xFE);
        let init = HandshakeMachine::new();
        let resp = HandshakeMachine::new();

        let request = request_from(&init, initiator, responder, &pki);
        let reply = answer(&resp, initiator, &request, responder, &pki);

        // Anybody can send an AuthRequest under the initiator's prefix with
        // its public certificate.
        let intruder = HandshakeMachine::new();
        let forged = request_from(&intruder, initiator, responder, &pki);
        let forged_reply = answer(&resp, initiator, &forged, responder, &pki);
        let forged_final = answer(&intruder, responder, &forged_reply, initiator, &pki);

        let final_bytes = answer(&init, responder, &reply, initiator, &pki);
        match resp
            .on_message(
                initiator,
                &final_bytes,
                responder,
                &pki.cert,
                &pki.key,
                &pki.ca,
            )
            .expect("the legitimate AuthFinal is accepted")
        {
            HandshakeAction::Completed(_, secret) => assert_eq!(
                Some(secret),
                init.shared_secret_for(&responder),
                "the two sides must hold one secret"
            ),
            other => panic!("expected Completed, got {:?}", other),
        }

        // The session of record completed: the parallel one is forgotten, and
        // its AuthFinal, arriving now, completes nothing.
        let _ = resp.on_message(
            initiator,
            &forged_final,
            responder,
            &pki.cert,
            &pki.key,
            &pki.ca,
        );
        assert_eq!(
            resp.shared_secret_for(&initiator),
            init.shared_secret_for(&responder),
            "the parallel session survived the completion of the session of record"
        );
    }

    /// The parallel session is the one that completes when ITS AuthFinal
    /// arrives (a peer that restarted in the middle of a handshake), and it
    /// then replaces the session of record.
    #[test]
    fn a_parallel_session_that_completes_replaces_the_one_in_progress() {
        let pki = test_pki();
        let initiator = make_guid(0x00);
        let responder = make_guid(0xFE);
        let first = HandshakeMachine::new();
        let resp = HandshakeMachine::new();

        let request = request_from(&first, initiator, responder, &pki);
        let _ = answer(&resp, initiator, &request, responder, &pki);

        let restarted = HandshakeMachine::new();
        let request = request_from(&restarted, initiator, responder, &pki);
        let reply = answer(&resp, initiator, &request, responder, &pki);
        let final_bytes = answer(&restarted, responder, &reply, initiator, &pki);
        resp.on_message(
            initiator,
            &final_bytes,
            responder,
            &pki.cert,
            &pki.key,
            &pki.ca,
        )
        .expect("the parallel session completes");

        assert_eq!(
            resp.shared_secret_for(&initiator),
            restarted.shared_secret_for(&responder)
        );
    }

    /// Two announcements of a peer racing into `start`: both pass the
    /// unlocked check, only one session begins. Without the re-check under
    /// the write lock the second overwrote the first, whose AuthRequest was
    /// already on its way: the peer answers a request whose state is gone.
    #[test]
    fn two_starts_racing_begin_one_session() {
        let pki = test_pki();
        let local = make_guid(0x00);
        let remote = make_guid(0xFE);
        let machine = Arc::new(HandshakeMachine::new());
        let inner_request = Arc::new(std::sync::Mutex::new(None));
        let (cert, key) = (pki.cert.clone(), pki.key.clone());
        let seen = Arc::clone(&inner_request);
        machine.set_parked_hook(Box::new(move |m: &HandshakeMachine| {
            // The other announcement's handler, on another thread, while this
            // one is between its check and its decision.
            let action = std::thread::scope(|scope| {
                scope
                    .spawn(|| m.start(local, remote, &cert, &key))
                    .join()
                    .expect("thread")
            })
            .expect("start")
            .expect("the first decider begins the session");
            *seen.lock().expect("lock") = Some(action);
        }));

        let outer = machine
            .start(local, remote, &pki.cert, &pki.key)
            .expect("start");
        assert!(
            outer.is_none(),
            "a second session began over the one the other start just filed"
        );
        let inner = match inner_request.lock().expect("lock").take() {
            Some(HandshakeAction::SendRequest(_, token)) => token,
            other => panic!("expected the other start's request, got {:?}", other),
        };
        let resent = machine.tick(Instant::now() + RUNG_1 + PAST);
        match resent.as_slice() {
            [HandshakeAction::SendRequest(_, token)] => assert_eq!(
                token.challenge1, inner.challenge1,
                "the session kept must be the one whose request went out"
            ),
            other => panic!("expected one retransmission, got {:?}", other),
        }
    }

    /// A re-authentication that never completes is abandoned at the deadline
    /// and costs the completed session nothing: no failure is reported, the
    /// peer stays authenticated, with its secret.
    #[test]
    fn a_reauthentication_that_never_completes_costs_the_completed_session_nothing() {
        let pair = completed_pair();
        let pki = test_pki();
        let secret = pair
            .resp
            .shared_secret_for(&pair.initiator_guid)
            .expect("completed");
        let again = HandshakeMachine::new();
        let request = request_from(&again, pair.initiator_guid, pair.responder_guid, &pki);
        let reply = answer(
            &pair.resp,
            pair.initiator_guid,
            &request,
            pair.responder_guid,
            &pki,
        );

        let actions = pair.resp.tick(Instant::now() + DEADLINE + PAST);
        assert!(
            !actions
                .iter()
                .any(|a| matches!(a, HandshakeAction::Failed(..))),
            "an abandoned re-authentication was reported as a failure: {:?}",
            actions
        );
        assert!(pair.resp.is_authenticated(&pair.initiator_guid));
        assert_eq!(
            pair.resp.shared_secret_for(&pair.initiator_guid),
            Some(secret.clone())
        );
        // Abandoned means gone: its AuthFinal, arriving after the deadline,
        // is not the AuthFinal of any session any more.
        let late_final = answer(
            &again,
            pair.responder_guid,
            &reply,
            pair.initiator_guid,
            &pki,
        );
        let _ = pair.resp.on_message(
            pair.initiator_guid,
            &late_final,
            pair.responder_guid,
            &pki.cert,
            &pki.key,
            &pki.ca,
        );
        assert_eq!(
            pair.resp.shared_secret_for(&pair.initiator_guid),
            Some(secret),
            "an abandoned session completed after its deadline"
        );
    }

    // --------------------------------------------------------
    //  The authentication request: a peer re-created under the same prefix
    //  while we hold a completed session with its predecessor
    // --------------------------------------------------------

    /// The authentication request `machine` (the responder, holding no
    /// session) sends `initiator`.
    fn auth_request_from(
        machine: &HandshakeMachine,
        responder: GUID,
        initiator: GUID,
    ) -> (Vec<u8>, [u8; 32]) {
        match machine
            .start(responder, initiator, &real_cert(), &real_key_pem())
            .expect("start")
        {
            Some(HandshakeAction::SendAuthRequest(_, token)) => (
                crate::security::handshake::tokens::encode_auth_req(&token).expect("encode"),
                token.future_challenge,
            ),
            other => panic!("expected an authentication request, got {:?}", other),
        }
    }

    /// The initiator holds a completed session with a peer that comes back
    /// under the same prefix with no session (a new process): the peer's
    /// authentication request makes the initiator begin a new handshake, the
    /// peer answers with the challenge it announced, and both end up with the
    /// same new secret. Before, the initiator never began again over its
    /// completed session and the new peer waited for ever.
    #[test]
    fn an_authentication_request_makes_the_initiator_authenticate_a_returning_peer() {
        let pair = completed_pair();
        let pki = test_pki();
        let old_secret = pair
            .init
            .shared_secret_for(&pair.responder_guid)
            .expect("completed");

        let returned = HandshakeMachine::new();
        let (auth_req, future_challenge) =
            auth_request_from(&returned, pair.responder_guid, pair.initiator_guid);
        let request = match pair
            .init
            .on_message(
                pair.responder_guid,
                &auth_req,
                pair.initiator_guid,
                &pki.cert,
                &pki.key,
                &pki.ca,
            )
            .expect("the request is honoured")
        {
            HandshakeAction::SendRequest(_, token) => encode_request(&token).expect("encode"),
            other => panic!("expected a new AuthRequest, got {:?}", other),
        };
        assert_eq!(
            pair.init.shared_secret_for(&pair.responder_guid),
            Some(old_secret.clone()),
            "an unsigned request replaced nothing yet"
        );

        let reply = answer(
            &returned,
            pair.initiator_guid,
            &request,
            pair.responder_guid,
            &pki,
        );
        match parse_token(&reply).expect("parse") {
            TokenKind::Reply(token) => assert_eq!(
                token.challenge2, future_challenge,
                "the responder answers with the challenge it announced"
            ),
            _ => panic!("not a reply"),
        }
        let final_bytes = answer(
            &pair.init,
            pair.responder_guid,
            &reply,
            pair.initiator_guid,
            &pki,
        );
        returned
            .on_message(
                pair.initiator_guid,
                &final_bytes,
                pair.responder_guid,
                &pki.cert,
                &pki.key,
                &pki.ca,
            )
            .expect("the returning peer completes");

        let new_secret = returned
            .shared_secret_for(&pair.initiator_guid)
            .expect("completed");
        assert_ne!(new_secret, old_secret);
        assert_eq!(
            pair.init.shared_secret_for(&pair.responder_guid),
            Some(new_secret)
        );
    }

    /// Anyone can send an authentication request, and each one honoured costs
    /// a key pair here and a signature at the peer: one new session per peer
    /// at a time, and at most `REAUTHENTICATIONS_PER_INTERVAL` (3) per
    /// `REAUTHENTICATION_INTERVAL`. Three are begun, the fourth inside the
    /// interval is refused, and past it a request begins one again.
    #[test]
    fn authentication_requests_begin_at_most_three_sessions_per_interval() {
        let pair = completed_pair();
        let pki = test_pki();
        let send = || {
            let (bytes, _) = auth_request_from(
                &HandshakeMachine::new(),
                pair.responder_guid,
                pair.initiator_guid,
            );
            pair.init
                .on_message(
                    pair.responder_guid,
                    &bytes,
                    pair.initiator_guid,
                    &pki.cert,
                    &pki.key,
                    &pki.ca,
                )
                .expect("ordinary traffic")
        };
        // The one in flight ends (here: the peer is gone and it is abandoned
        // at its deadline); the count of the interval stays.
        let abandon = || {
            assert!(pair
                .init
                .tick(Instant::now() + DEADLINE + PAST)
                .iter()
                .all(|a| !matches!(a, HandshakeAction::Failed(..))));
        };

        assert!(matches!(send(), HandshakeAction::SendRequest(..)));
        assert!(
            matches!(send(), HandshakeAction::Ignored(..)),
            "a second request while one is in flight"
        );
        abandon();
        assert!(
            matches!(send(), HandshakeAction::SendRequest(..)),
            "the second session of the interval"
        );
        abandon();
        assert!(
            matches!(send(), HandshakeAction::SendRequest(..)),
            "the third session of the interval"
        );
        abandon();
        assert!(
            matches!(send(), HandshakeAction::Ignored(..)),
            "a fourth inside the interval"
        );
        assert!(pair.init.is_authenticated(&pair.responder_guid));

        // Past the interval the slots come back.
        pair.init.age_reauthentication(&pair.responder_guid);
        assert!(
            matches!(send(), HandshakeAction::SendRequest(..)),
            "refilled past the interval"
        );
    }

    /// The responder asks to be authenticated as soon as it hears the
    /// initiator, and the initiator begins on its own announcement too: the
    /// two cross, the initiator's AuthRequest wins, and the responder answers
    /// it with the challenge it announced. Its authentication request, late
    /// (a busy receive thread) or retransmitted (its ladder rung fired before
    /// the AuthRequest arrived), then reaches an initiator that has completed.
    /// That request is the one the completed session answered: it begins
    /// nothing, and above all it does not take the peer's one re-keying per
    /// `REAUTHENTICATION_INTERVAL` - which would leave a participant that
    /// really restarted in the next 30 s unauthenticated for the rest of them.
    #[test]
    fn a_late_authentication_request_the_completed_session_answered_begins_nothing() {
        let pki = test_pki();
        let initiator_guid = make_guid(0x00);
        let responder_guid = make_guid(0xFE);
        let init = HandshakeMachine::new();
        let resp = HandshakeMachine::new();

        let (late, future_challenge) = auth_request_from(&resp, responder_guid, initiator_guid);
        let request = request_from(&init, initiator_guid, responder_guid, &pki);
        let reply = answer(&resp, initiator_guid, &request, responder_guid, &pki);
        match parse_token(&reply).expect("parse") {
            TokenKind::Reply(token) => assert_eq!(
                token.challenge2, future_challenge,
                "fixture: the reply answers with the announced challenge"
            ),
            _ => panic!("not a reply"),
        }
        let final_bytes = answer(&init, responder_guid, &reply, initiator_guid, &pki);
        resp.on_message(
            initiator_guid,
            &final_bytes,
            responder_guid,
            &pki.cert,
            &pki.key,
            &pki.ca,
        )
        .expect("the responder completes");
        let secret = init
            .shared_secret_for(&responder_guid)
            .expect("fixture: the initiator completed");

        let send = |bytes: &[u8]| {
            init.on_message(
                responder_guid,
                bytes,
                initiator_guid,
                &pki.cert,
                &pki.key,
                &pki.ca,
            )
            .expect("ordinary traffic")
        };
        let action = send(&late);
        assert!(
            matches!(action, HandshakeAction::Ignored(..)),
            "the request the completed session answered begins nothing; got {:?}",
            action
        );
        assert_eq!(init.shared_secret_for(&responder_guid), Some(secret));

        // Past `CROSSING_WINDOW` the same request is no longer one that
        // crossed the completion: the responder, which announces one
        // challenge per identity, sends it after giving up on a session we
        // completed, and it begins one.
        let later = HandshakeMachine::new();
        let request = request_from(&later, initiator_guid, responder_guid, &pki);
        let reply = answer(&resp, initiator_guid, &request, responder_guid, &pki);
        let _ = answer(&later, responder_guid, &reply, initiator_guid, &pki);
        let action = later
            .on_message(
                responder_guid,
                &late,
                initiator_guid,
                &pki.cert,
                &pki.key,
                &pki.ca,
            )
            .expect("ordinary traffic");
        assert!(
            matches!(action, HandshakeAction::Ignored(..)),
            "fixture: inside the window; got {:?}",
            action
        );
        later.age_completion(&responder_guid);
        let action = later
            .on_message(
                responder_guid,
                &late,
                initiator_guid,
                &pki.cert,
                &pki.key,
                &pki.ca,
            )
            .expect("ordinary traffic");
        assert!(
            matches!(action, HandshakeAction::SendRequest(..)),
            "past the window, the request begins a session; got {:?}",
            action
        );

        // The peer really restarts: a new process, a new challenge.
        let (fresh, _) =
            auth_request_from(&HandshakeMachine::new(), responder_guid, initiator_guid);
        let action = send(&fresh);
        assert!(
            matches!(action, HandshakeAction::SendRequest(..)),
            "a returning peer is authenticated again at once, not 30 s later; got {:?}",
            action
        );
    }

    /// The responder hears the initiator's announcement while it signs its
    /// reply to the initiator's AuthRequest: it files a future_challenge and
    /// sends it in an authentication request. The reply must answer with that
    /// challenge, or the session that completes is not the one the request
    /// asked for, and the request, reaching the initiator after it
    /// completed, begins a session for nothing and spends the re-keying of
    /// the interval (seen live: a restarted participant then waited 30 s).
    #[test]
    fn an_announcement_handled_while_the_reply_is_signed_is_the_challenge_it_answers() {
        let pki = test_pki();
        let initiator_guid = make_guid(0x00);
        let responder_guid = make_guid(0xFE);
        let init = HandshakeMachine::new();
        let resp = HandshakeMachine::new();

        let request = request_from(&init, initiator_guid, responder_guid, &pki);
        let asked = Arc::new(std::sync::Mutex::new(None));
        let seen = Arc::clone(&asked);
        let (cert, key) = (pki.cert.clone(), pki.key.clone());
        resp.set_parked_hook(Box::new(move |m: &HandshakeMachine| {
            *seen.lock().expect("lock") = Some(auth_request_bytes(
                m.start(responder_guid, initiator_guid, &cert, &key)
                    .expect("start"),
            ));
        }));
        let reply = answer(&resp, initiator_guid, &request, responder_guid, &pki);
        let (late, future_challenge) = asked
            .lock()
            .expect("lock")
            .take()
            .expect("fixture: the announcement was handled inside the window");
        match parse_token(&reply).expect("parse") {
            TokenKind::Reply(token) => assert_eq!(
                token.challenge2, future_challenge,
                "the reply answers with the challenge the responder announced meanwhile"
            ),
            _ => panic!("not a reply"),
        }

        let final_bytes = answer(&init, responder_guid, &reply, initiator_guid, &pki);
        resp.on_message(
            initiator_guid,
            &final_bytes,
            responder_guid,
            &pki.cert,
            &pki.key,
            &pki.ca,
        )
        .expect("the responder completes");
        let action = init
            .on_message(
                responder_guid,
                &late,
                initiator_guid,
                &pki.cert,
                &pki.key,
                &pki.ca,
            )
            .expect("ordinary traffic");
        assert!(
            matches!(action, HandshakeAction::Ignored(..)),
            "the request the completed session answered begins nothing; got {:?}",
            action
        );
    }

    /// The responder, still holding its completed session, asked the
    /// initiator to begin again (a parallel session abandoned where the peer
    /// may have completed it), and the initiator's AuthRequest answers that
    /// request: it accepts only a reply whose challenge2 is the announced
    /// one. While the responder signs that reply, its timer replaces the
    /// announcement with a new one (the old one's deadline passed). The reply
    /// must still answer the challenge the AuthRequest was built on, or the
    /// initiator refuses it and has spent its one re-keying of the interval.
    #[test]
    fn an_announcement_replaced_while_the_reply_is_signed_keeps_the_answered_challenge() {
        let pair = completed_pair();
        let pki = test_pki();
        let t0 = Instant::now();

        // A parallel session in which the responder replied, abandoned at
        // its deadline: the responder asks the initiator to begin again.
        let other = request_from(
            &HandshakeMachine::new(),
            pair.initiator_guid,
            pair.responder_guid,
            &pki,
        );
        let _ = answer(
            &pair.resp,
            pair.initiator_guid,
            &other,
            pair.responder_guid,
            &pki,
        );
        let asked = pair
            .resp
            .tick(t0 + DEADLINE + PAST)
            .into_iter()
            .find_map(|action| match action {
                HandshakeAction::SendAuthRequest(_, token) => Some(token),
                _ => None,
            })
            .expect("fixture: the responder asks to begin again");
        // It reaches the initiator well past the completion it may have
        // missed (`CROSSING_WINDOW`).
        pair.init.age_completion(&pair.responder_guid);
        let request = match pair
            .init
            .on_message(
                pair.responder_guid,
                &crate::security::handshake::tokens::encode_auth_req(&asked).expect("encode"),
                pair.initiator_guid,
                &pki.cert,
                &pki.key,
                &pki.ca,
            )
            .expect("honoured")
        {
            HandshakeAction::SendRequest(_, token) => encode_request(&token).expect("encode"),
            other => panic!("fixture: expected an AuthRequest, got {:?}", other),
        };

        // The announcement's own deadline passes while the reply is signed.
        pair.resp
            .set_parked_hook(Box::new(move |m: &HandshakeMachine| {
                let replaced = m.tick(t0 + (DEADLINE + PAST) * 3);
                assert!(
                    replaced
                        .iter()
                        .any(|a| matches!(a, HandshakeAction::SendAuthRequest(..))),
                    "fixture: the announcement was replaced inside the window: {:?}",
                    replaced
                );
            }));
        let reply = answer(
            &pair.resp,
            pair.initiator_guid,
            &request,
            pair.responder_guid,
            &pki,
        );
        match parse_token(&reply).expect("parse") {
            TokenKind::Reply(token) => assert_eq!(
                token.challenge2, asked.future_challenge,
                "the reply answers the challenge the AuthRequest was built on"
            ),
            _ => panic!("not a reply"),
        }
        let action = pair
            .init
            .on_message(
                pair.responder_guid,
                &reply,
                pair.initiator_guid,
                &pki.cert,
                &pki.key,
                &pki.ca,
            )
            .expect("the initiator accepts the reply");
        assert!(
            matches!(action, HandshakeAction::SendFinal(..)),
            "the re-authentication completes; got {:?}",
            action
        );
    }

    /// The encoded authentication request in `action`, and its challenge.
    fn auth_request_bytes(action: Option<HandshakeAction>) -> (Vec<u8>, [u8; 32]) {
        match action {
            Some(HandshakeAction::SendAuthRequest(_, token)) => (
                crate::security::handshake::tokens::encode_auth_req(&token).expect("encode"),
                token.future_challenge,
            ),
            other => panic!("expected an authentication request, got {:?}", other),
        }
    }

    /// The in-flight bound alone, the interval set aside: while a session
    /// begun on a request is in flight, another request begins nothing; once
    /// it has ended, one does.
    #[test]
    fn one_session_on_request_at_a_time() {
        let pair = completed_pair();
        let pki = test_pki();
        let send = || {
            let (bytes, _) = auth_request_from(
                &HandshakeMachine::new(),
                pair.responder_guid,
                pair.initiator_guid,
            );
            pair.init
                .on_message(
                    pair.responder_guid,
                    &bytes,
                    pair.initiator_guid,
                    &pki.cert,
                    &pki.key,
                    &pki.ca,
                )
                .expect("ordinary traffic")
        };
        assert!(matches!(send(), HandshakeAction::SendRequest(..)));
        pair.init.age_reauthentication(&pair.responder_guid);
        assert!(
            matches!(send(), HandshakeAction::Ignored(..)),
            "a second session while one is in flight"
        );
        let _ = pair.init.tick(Instant::now() + DEADLINE + PAST);
        pair.init.age_reauthentication(&pair.responder_guid);
        assert!(matches!(send(), HandshakeAction::SendRequest(..)));
    }

    /// The new session completes only with the challenge the peer announced:
    /// a forged authentication request (anyone can send one) whose
    /// future_challenge the real peer never chose gets a reply with another
    /// challenge2, refused, and the completed session stays.
    #[test]
    fn a_reply_that_does_not_answer_the_announced_challenge_installs_nothing() {
        let pair = completed_pair();
        let pki = test_pki();
        let old_secret = pair
            .init
            .shared_secret_for(&pair.responder_guid)
            .expect("completed");
        let forged = crate::security::handshake::tokens::encode_auth_req(
            &crate::security::handshake::tokens::AuthReqToken {
                future_challenge: [0x42; 32],
            },
        )
        .expect("encode");
        let request = match pair
            .init
            .on_message(
                pair.responder_guid,
                &forged,
                pair.initiator_guid,
                &pki.cert,
                &pki.key,
                &pki.ca,
            )
            .expect("honoured")
        {
            HandshakeAction::SendRequest(_, token) => encode_request(&token).expect("encode"),
            other => panic!("expected an AuthRequest, got {:?}", other),
        };
        // A responder that announced nothing answers with a challenge of its
        // own.
        let unaware = HandshakeMachine::new();
        let reply = answer(
            &unaware,
            pair.initiator_guid,
            &request,
            pair.responder_guid,
            &pki,
        );
        let outcome = pair.init.on_message(
            pair.responder_guid,
            &reply,
            pair.initiator_guid,
            &pki.cert,
            &pki.key,
            &pki.ca,
        );
        assert!(outcome.is_err(), "got {:?}", outcome);
        assert_eq!(
            pair.init.shared_secret_for(&pair.responder_guid),
            Some(old_secret)
        );
    }

    /// The new session stays with the identity the completed one was made
    /// with: a reply under another certificate the CA bundle trusts, signed
    /// with that certificate's own key, is refused.
    #[test]
    fn a_new_session_on_request_stays_with_the_completed_certificate() {
        use crate::security::test_pki::{
            REVOCATION_CA_PEM, REVOCATION_LOCAL_IDENTITY_KEY_PEM, REVOCATION_LOCAL_IDENTITY_PEM,
        };
        // Both identities chain to a CA of the bundle.
        let mut bundle = real_ca_pem();
        bundle.extend_from_slice(REVOCATION_CA_PEM);
        let pki = Pki {
            cert: real_cert(),
            key: real_key_pem(),
            ca: bundle.clone(),
        };
        let other = Pki {
            cert: REVOCATION_LOCAL_IDENTITY_PEM.to_vec(),
            key: REVOCATION_LOCAL_IDENTITY_KEY_PEM.to_vec(),
            ca: bundle,
        };
        let initiator = make_guid(0x00);
        let responder = make_guid(0xFE);
        let init = HandshakeMachine::new();
        let resp = HandshakeMachine::new();
        let request = request_from(&init, initiator, responder, &pki);
        let reply = answer(&resp, initiator, &request, responder, &pki);
        let final_bytes = answer(&init, responder, &reply, initiator, &pki);
        resp.on_message(
            initiator,
            &final_bytes,
            responder,
            &pki.cert,
            &pki.key,
            &pki.ca,
        )
        .expect("completes");
        let secret = init.shared_secret_for(&responder).expect("completed");

        let impostor = HandshakeMachine::new();
        let (auth_req, _) = auth_request_from(&impostor, responder, initiator);
        let request = match init
            .on_message(
                responder, &auth_req, initiator, &pki.cert, &pki.key, &pki.ca,
            )
            .expect("honoured")
        {
            HandshakeAction::SendRequest(_, token) => encode_request(&token).expect("encode"),
            other => panic!("expected an AuthRequest, got {:?}", other),
        };
        let reply = answer(&impostor, initiator, &request, responder, &other);
        let outcome = init.on_message(responder, &reply, initiator, &pki.cert, &pki.key, &pki.ca);
        assert!(outcome.is_err(), "got {:?}", outcome);
        assert_eq!(init.shared_secret_for(&responder), Some(secret));
    }

    /// Requests that are not honoured create no state: one from a peer that
    /// begins its own handshakes (we are its responder), and one for a prefix
    /// we hold no completed session with - honouring those would let anyone
    /// make us keep state, and spend a key pair, for any prefix.
    #[test]
    fn an_authentication_request_creates_no_state_where_it_is_not_honoured() {
        let pki = test_pki();
        let low = make_guid(0xFE);
        let high = make_guid(0x00);
        let send = |machine: &HandshakeMachine, from: GUID, local: GUID| {
            let (bytes, _) = auth_request_from(&HandshakeMachine::new(), make_guid(0xFF), from);
            machine
                .on_message(from, &bytes, local, &pki.cert, &pki.key, &pki.ca)
                .expect("ordinary traffic")
        };
        let as_responder = HandshakeMachine::new();
        assert!(matches!(
            send(&as_responder, high, low),
            HandshakeAction::Ignored(..)
        ));
        assert!(!as_responder.has_session(&high));
        let unknown = HandshakeMachine::new();
        assert!(matches!(
            send(&unknown, low, high),
            HandshakeAction::Ignored(..)
        ));
        assert!(!unknown.has_session(&low));
    }

    /// The authentication request rides the retry ladder, and a peer that
    /// never begins leaves us `Failed` - no failure reported or audited, it
    /// is no failed authentication - so its next announcement asks again.
    #[test]
    fn an_unanswered_authentication_request_is_retried_then_asked_again() {
        let low = make_guid(0xFE);
        let high = make_guid(0x00);
        let machine = HandshakeMachine::new();
        let (_, future_challenge) = auth_request_from(&machine, low, high);
        match machine.tick(Instant::now() + RUNG_1 + PAST).as_slice() {
            [HandshakeAction::SendAuthRequest(_, token)] => {
                assert_eq!(token.future_challenge, future_challenge)
            }
            other => panic!("expected a retransmission, got {:?}", other),
        }
        let at_deadline = machine.tick(Instant::now() + DEADLINE + PAST);
        assert!(
            at_deadline
                .iter()
                .all(|a| !matches!(a, HandshakeAction::Failed(..))),
            "{:?}",
            at_deadline
        );
        let (_, again) = auth_request_from(&machine, low, high);
        assert_eq!(
            again, future_challenge,
            "a new request, the one challenge of this identity (DDS Security v1.1 \
             Sec.9.3.3, Table 52)"
        );
    }

    /// DDS Security v1.1 Sec.9.3.3, Table 52: `validate_remote_identity`
    /// generates the local_auth_request_token, and `begin_handshake_reply`
    /// answers with ITS future_challenge as challenge2: one challenge per
    /// remote identity, whatever the session. HDDS drew a new one at each
    /// request it sent and answered other requests with a random one. The
    /// identity ends when the participant leaves discovery
    /// (`drop_handshake`): the next one has its own.
    #[test]
    fn a_responder_announces_one_challenge_per_remote_identity() {
        let pki = test_pki();
        let low = make_guid(0xFE);
        let high = make_guid(0x00);
        let resp = HandshakeMachine::new();

        let (_, announced) = auth_request_from(&resp, low, high);
        let _ = resp.tick(Instant::now() + DEADLINE + PAST);
        let (_, again) = auth_request_from(&resp, low, high);
        assert_eq!(again, announced, "asked again: the same challenge");

        // A request from the initiator, which never saw ours: answered with
        // that challenge too.
        let request = request_from(&HandshakeMachine::new(), high, low, &pki);
        let reply = answer(&resp, high, &request, low, &pki);
        match parse_token(&reply).expect("parse") {
            TokenKind::Reply(token) => assert_eq!(token.challenge2, announced),
            _ => panic!("not a reply"),
        }

        // A responder that never announced one answers with the one it
        // holds from then on, and announces that one.
        let fresh = HandshakeMachine::new();
        let request = request_from(&HandshakeMachine::new(), high, low, &pki);
        let reply = answer(&fresh, high, &request, low, &pki);
        let answered = match parse_token(&reply).expect("parse") {
            TokenKind::Reply(token) => token.challenge2,
            _ => panic!("not a reply"),
        };
        let _ = fresh.tick(Instant::now() + DEADLINE + PAST);
        let (_, kept) = auth_request_from(&fresh, low, high);
        assert_eq!(kept, answered, "announced: the challenge it answered with");
        let _ = fresh.drop_handshake(&high);
        let (_, after_drop) = auth_request_from(&fresh, low, high);
        assert_ne!(after_drop, answered, "a new identity, a new challenge");
    }

    /// The future_challenges kept are bounded (`MAX_FUTURE_CHALLENGES`): an
    /// identity past the bound is challenged with a new nonce each time,
    /// and the identities kept keep theirs.
    #[test]
    fn the_challenges_kept_are_bounded() {
        // Every identity asked holds a session: the session bound is not
        // what this test is about.
        let resp = HandshakeMachine::new().with_max_sessions_for_tests(usize::MAX);
        let (_, bound) = resp.future_challenges_kept();
        let local = GUID::new([0xFF; 12], [0, 0, 1, 0xC1]);
        let identity = |n: usize| {
            let mut prefix = [0u8; 12];
            prefix[4..12].copy_from_slice(&(n as u64).to_be_bytes());
            GUID::new(prefix, [0, 0, 1, 0xC1])
        };
        let (_, first) = auth_request_from(&resp, local, identity(0));
        for n in 1..bound {
            let _ = auth_request_from(&resp, local, identity(n));
        }
        assert_eq!(resp.future_challenges_kept().0, bound);
        let (_, a) = auth_request_from(&resp, local, identity(bound));
        let _ = resp.tick(Instant::now() + DEADLINE + PAST);
        let (_, b) = auth_request_from(&resp, local, identity(bound));
        assert_ne!(a, b, "past the bound: a new challenge each time");
        assert_eq!(resp.future_challenges_kept().0, bound);
        let (_, again) = auth_request_from(&resp, local, identity(0));
        assert_eq!(again, first, "a kept identity keeps its challenge");
    }

    /// Every remote identity is asked with its one future_challenge (DDS
    /// Security v1.1 Sec.9.3.3, Table 52), whatever its SPDP announced: an
    /// HDDS participant without `CAP_ONE_FUTURE_CHALLENGE` (1.4.x) cannot
    /// authenticate with this release, and is not challenged otherwise for
    /// it.
    #[test]
    fn every_participant_is_asked_with_one_challenge_per_identity() {
        use crate::core::rtps_constants::HDDS_VENDOR_ID_U16;
        use crate::protocol::group::CAP_SPEC_GROUP_COHERENT;
        let low = make_guid(0xFE);
        let high = make_guid(0x00);
        for (vendor, caps) in [
            (Some(HDDS_VENDOR_ID_U16), Some(CAP_SPEC_GROUP_COHERENT)),
            (Some(HDDS_VENDOR_ID_U16), None),
            (Some(0x0101), None),
        ] {
            let resp = HandshakeMachine::new();
            resp.note_peer_capabilities(high, vendor, caps);
            let (_, first) = auth_request_from(&resp, low, high);
            let _ = resp.tick(Instant::now() + DEADLINE + PAST);
            let (_, second) = auth_request_from(&resp, low, high);
            assert_eq!(
                second, first,
                "vendor {:?}, capabilities {:?}",
                vendor, caps
            );
        }
    }

    /// An HDDS participant without `CAP_ONE_FUTURE_CHALLENGE` is a 1.4.x
    /// release, which signs the handshake otherwise than the specification:
    /// it is said once, in the audit chain, at its first note - not for a
    /// participant that announces the capability, nor for another vendor's,
    /// nor again at a later note of the same one.
    #[test]
    fn a_pre_1_5_hdds_participant_is_audited_once_as_unable_to_authenticate() {
        use crate::core::rtps_constants::HDDS_VENDOR_ID_U16;
        use crate::protocol::group::{CAP_ONE_FUTURE_CHALLENGE, CAP_SPEC_GROUP_COHERENT};
        let (audit_file, audit) = audit_fixture();
        let machine = HandshakeMachine::new().with_audit_logger(Some(audit));
        let old = make_guid(0x01);
        machine.note_peer_capabilities(
            old,
            Some(HDDS_VENDOR_ID_U16),
            Some(CAP_SPEC_GROUP_COHERENT),
        );
        machine.note_peer_capabilities(old, Some(HDDS_VENDOR_ID_U16), None);
        machine.note_peer_capabilities(
            make_guid(0x02),
            Some(HDDS_VENDOR_ID_U16),
            Some(CAP_ONE_FUTURE_CHALLENGE),
        );
        machine.note_peer_capabilities(make_guid(0x03), Some(0x0101), None);
        let records = fs::read_to_string(audit_file.path()).expect("read audit records");
        assert_eq!(records.matches("Authentication").count(), 1, "{}", records);
        assert_eq!(records.matches("outcome: Failed").count(), 1, "{}", records);
    }

    /// The late AuthReply of an abandoned parallel session (we began it on the
    /// peer's authentication request, it reached its deadline) answers no
    /// request of the completed session: it is refused. Before, the duplicate
    /// path re-signed an AuthFinal over whatever the reply carried, and the
    /// peer completed alone, on a secret we did not hold.
    #[test]
    fn a_late_reply_of_an_abandoned_parallel_session_completes_nothing() {
        let pair = completed_pair();
        let pki = test_pki();
        let secret = pair
            .init
            .shared_secret_for(&pair.responder_guid)
            .expect("completed");
        let returned = HandshakeMachine::new();
        let (auth_req, _) = auth_request_from(&returned, pair.responder_guid, pair.initiator_guid);
        let request = match pair
            .init
            .on_message(
                pair.responder_guid,
                &auth_req,
                pair.initiator_guid,
                &pki.cert,
                &pki.key,
                &pki.ca,
            )
            .expect("honoured")
        {
            HandshakeAction::SendRequest(_, token) => encode_request(&token).expect("encode"),
            other => panic!("expected an AuthRequest, got {:?}", other),
        };
        let reply = answer(
            &returned,
            pair.initiator_guid,
            &request,
            pair.responder_guid,
            &pki,
        );
        let _ = pair.init.tick(Instant::now() + DEADLINE + PAST);

        let outcome = pair.init.on_message(
            pair.responder_guid,
            &reply,
            pair.initiator_guid,
            &pki.cert,
            &pki.key,
            &pki.ca,
        );
        assert!(
            !matches!(outcome, Ok(HandshakeAction::SendFinal(..))),
            "an AuthFinal was signed for a session we no longer hold: {:?}",
            outcome
        );
        assert_eq!(
            pair.init.shared_secret_for(&pair.responder_guid),
            Some(secret)
        );
    }

    /// With a parallel session in flight, a duplicate of the completed
    /// session's AuthReply (the responder's own retransmission) is still the
    /// completed session's: answered with a fresh AuthFinal, and the parallel
    /// session untouched - it completes when its own reply arrives. The
    /// challenge1 of the reply is what tells the two apart.
    #[test]
    fn a_duplicate_reply_of_the_completed_session_does_not_reach_the_parallel_one() {
        let pair = completed_pair();
        let pki = test_pki();
        let returned = HandshakeMachine::new();
        let (auth_req, _) = auth_request_from(&returned, pair.responder_guid, pair.initiator_guid);
        let request = match pair
            .init
            .on_message(
                pair.responder_guid,
                &auth_req,
                pair.initiator_guid,
                &pki.cert,
                &pki.key,
                &pki.ca,
            )
            .expect("honoured")
        {
            HandshakeAction::SendRequest(_, token) => encode_request(&token).expect("encode"),
            other => panic!("expected an AuthRequest, got {:?}", other),
        };

        let duplicate = pair
            .init
            .on_message(
                pair.responder_guid,
                &encode_reply(&pair.reply).expect("encode"),
                pair.initiator_guid,
                &pki.cert,
                &pki.key,
                &pki.ca,
            )
            .expect("a duplicate is ordinary traffic");
        assert!(
            matches!(duplicate, HandshakeAction::SendFinal(..)),
            "{:?}",
            duplicate
        );

        let reply = answer(
            &returned,
            pair.initiator_guid,
            &request,
            pair.responder_guid,
            &pki,
        );
        let final_bytes = answer(
            &pair.init,
            pair.responder_guid,
            &reply,
            pair.initiator_guid,
            &pki,
        );
        returned
            .on_message(
                pair.initiator_guid,
                &final_bytes,
                pair.responder_guid,
                &pki.cert,
                &pki.key,
                &pki.ca,
            )
            .expect("completes");
        assert_eq!(
            pair.init.shared_secret_for(&pair.responder_guid),
            returned.shared_secret_for(&pair.initiator_guid)
        );
    }

    /// The responder does not begin handshakes: an authentication request
    /// from its initiator begins nothing, even over a completed session.
    #[test]
    fn a_responder_does_not_honour_an_authentication_request() {
        let pair = completed_pair();
        let pki = test_pki();
        let auth_req = crate::security::handshake::tokens::encode_auth_req(
            &crate::security::handshake::tokens::AuthReqToken {
                future_challenge: [0x24; 32],
            },
        )
        .expect("encode");
        let outcome = pair
            .resp
            .on_message(
                pair.initiator_guid,
                &auth_req,
                pair.responder_guid,
                &pki.cert,
                &pki.key,
                &pki.ca,
            )
            .expect("ordinary traffic");
        assert!(
            matches!(outcome, HandshakeAction::Ignored(..)),
            "{:?}",
            outcome
        );
    }

    /// The parallel session is completed by the AuthFinal whose challenge1,
    /// challenge2 AND dh2 are its own. One with its challenges and another
    /// dh2 is not its AuthFinal: it is a duplicate for the completed session,
    /// and leaves the parallel one to complete with its own.
    #[test]
    fn an_authfinal_with_another_dh2_does_not_reach_the_parallel_session() {
        let pair = completed_pair();
        let pki = test_pki();
        let old_secret = pair
            .resp
            .shared_secret_for(&pair.initiator_guid)
            .expect("completed");
        let again = HandshakeMachine::new();
        let request = request_from(&again, pair.initiator_guid, pair.responder_guid, &pki);
        let reply = answer(
            &pair.resp,
            pair.initiator_guid,
            &request,
            pair.responder_guid,
            &pki,
        );
        let final_bytes = answer(
            &again,
            pair.responder_guid,
            &reply,
            pair.initiator_guid,
            &pki,
        );
        let mut token = match parse_token(&final_bytes).expect("parse") {
            TokenKind::Final(token) => token,
            _ => panic!("not a final"),
        };
        let dh2 = token.dh2.as_mut().expect("HDDS sends the dh2 echo");
        let last = dh2.len() - 1;
        dh2[last] ^= 0x01;
        let skewed = encode_final(&token).expect("encode");
        match pair
            .resp
            .on_message(
                pair.initiator_guid,
                &skewed,
                pair.responder_guid,
                &pki.cert,
                &pki.key,
                &pki.ca,
            )
            .expect("a duplicate for the completed session")
        {
            HandshakeAction::Completed(_, secret) => assert_eq!(secret, old_secret),
            other => panic!(
                "expected the completed session's duplicate, got {:?}",
                other
            ),
        }

        pair.resp
            .on_message(
                pair.initiator_guid,
                &final_bytes,
                pair.responder_guid,
                &pki.cert,
                &pki.key,
                &pki.ca,
            )
            .expect("the parallel session completes with its own AuthFinal");
        assert_eq!(
            pair.resp.shared_secret_for(&pair.initiator_guid),
            again.shared_secret_for(&pair.responder_guid)
        );
    }

    /// We hold a completed session; the peer, re-created, initiates a new
    /// one, and completes it on our AuthReply - whose AuthFinal to us is lost,
    /// with every retransmission. At the deadline our parallel session is
    /// abandoned, and the peer holds a secret we do not: neither side would
    /// begin again over its completed session. We ask the peer to begin
    /// again, and the next session gives both one secret.
    #[test]
    fn an_abandoned_reply_the_peer_may_have_completed_is_healed() {
        let pair = completed_pair();
        let pki = test_pki();
        let again = HandshakeMachine::new();
        let request = request_from(&again, pair.initiator_guid, pair.responder_guid, &pki);
        let reply = answer(
            &pair.resp,
            pair.initiator_guid,
            &request,
            pair.responder_guid,
            &pki,
        );
        let _lost_final = answer(
            &again,
            pair.responder_guid,
            &reply,
            pair.initiator_guid,
            &pki,
        );
        assert_ne!(
            again.shared_secret_for(&pair.responder_guid),
            pair.resp.shared_secret_for(&pair.initiator_guid),
            "fixture: the two sides now differ"
        );

        let actions = pair.resp.tick(Instant::now() + DEADLINE + PAST);
        let auth_req = match actions.as_slice() {
            [HandshakeAction::SendAuthRequest(guid, token)] => {
                assert_eq!(*guid, pair.initiator_guid);
                match parse_token(&reply).expect("parse") {
                    TokenKind::Reply(answered) => assert_eq!(
                        token.future_challenge, answered.challenge2,
                        "the one challenge of the identity, the one the session answered"
                    ),
                    _ => panic!("not a reply"),
                }
                crate::security::handshake::tokens::encode_auth_req(token).expect("encode")
            }
            other => panic!("expected an authentication request, got {:?}", other),
        };

        // The request reaches the initiator `SESSION_DEADLINE` after the
        // reply it completed on, at the least 14 s after its completion:
        // past `CROSSING_WINDOW` (here, the completion made older).
        again.age_completion(&pair.responder_guid);
        let request = match again
            .on_message(
                pair.responder_guid,
                &auth_req,
                pair.initiator_guid,
                &pki.cert,
                &pki.key,
                &pki.ca,
            )
            .expect("honoured")
        {
            HandshakeAction::SendRequest(_, token) => encode_request(&token).expect("encode"),
            other => panic!("expected an AuthRequest, got {:?}", other),
        };
        let reply = answer(
            &pair.resp,
            pair.initiator_guid,
            &request,
            pair.responder_guid,
            &pki,
        );
        let final_bytes = answer(
            &again,
            pair.responder_guid,
            &reply,
            pair.initiator_guid,
            &pki,
        );
        pair.resp
            .on_message(
                pair.initiator_guid,
                &final_bytes,
                pair.responder_guid,
                &pki.cert,
                &pki.key,
                &pki.ca,
            )
            .expect("completes");
        assert_eq!(
            again.shared_secret_for(&pair.responder_guid),
            pair.resp.shared_secret_for(&pair.initiator_guid),
            "the two sides hold one secret again"
        );
    }

    /// An authentication request we sent over a completed session that the
    /// peer never answers is sent again at each deadline, until a session
    /// completes: with the one challenge of the identity (DDS Security v1.1
    /// Sec.9.3.3, Table 52), not a new one.
    #[test]
    fn an_unanswered_request_over_a_completed_session_is_asked_again() {
        let pair = completed_pair();
        let pki = test_pki();
        let again = HandshakeMachine::new();
        let request = request_from(&again, pair.initiator_guid, pair.responder_guid, &pki);
        let _ = answer(
            &pair.resp,
            pair.initiator_guid,
            &request,
            pair.responder_guid,
            &pki,
        );
        let first = match pair.resp.tick(Instant::now() + DEADLINE + PAST).as_slice() {
            [HandshakeAction::SendAuthRequest(_, token)] => token.future_challenge,
            other => panic!("expected an authentication request, got {:?}", other),
        };
        let asked = pair
            .resp
            .tick(Instant::now() + DEADLINE + DEADLINE + PAST + PAST)
            .into_iter()
            .filter_map(|a| match a {
                HandshakeAction::SendAuthRequest(_, token) => Some(token.future_challenge),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert!(
            !asked.is_empty() && asked.iter().all(|c| *c == first),
            "asked again, with the one challenge of the identity: {:?}",
            asked.len()
        );
        assert!(pair.resp.is_authenticated(&pair.initiator_guid));
    }

    // --------------------------------------------------------
    //  Initiator's own AuthRequestMessageToken (DDS Security v1.1 Sec.9.3.3
    //  Table 52, validate_remote_identity / begin_handshake_request): the
    //  initiator, having received nothing from the peer yet, must announce
    //  its own future_challenge and use it as challenge1 -- not an
    //  independent nonce -- and the responder that receives the
    //  announcement first must hold the real Request to it.
    // --------------------------------------------------------

    /// `start_and_announce` on first contact returns both messages, and the
    /// Request's challenge1 is exactly the future_challenge of the
    /// announcement, not an unrelated nonce (Table 52,
    /// begin_handshake_request: "use the value of property named
    /// future_challenge found in the local_auth_request_token to fill the
    /// property named challenge1").
    #[test]
    fn start_and_announce_uses_the_announced_future_challenge_as_challenge1() {
        let initiator_guid = make_guid(0x00);
        let responder_guid = make_guid(0xFE);
        let init = HandshakeMachine::new();
        let pki = test_pki();

        let actions = init
            .start_and_announce(initiator_guid, responder_guid, &pki.cert, &pki.key)
            .expect("start_and_announce");
        let (auth_req, request) = match actions.as_slice() {
            [HandshakeAction::SendAuthRequest(auth_remote, auth_req), HandshakeAction::SendRequest(req_remote, req)] =>
            {
                assert_eq!(*auth_remote, responder_guid);
                assert_eq!(*req_remote, responder_guid);
                (auth_req.clone(), req.clone())
            }
            other => panic!("expected [SendAuthRequest, SendRequest], got {:?}", other),
        };
        assert_eq!(
            auth_req.future_challenge, request.challenge1,
            "challenge1 of the HandshakeRequest must be the future_challenge we announced"
        );

        // The announcement is the real wire token (Table 48's class id),
        // not a stand-in: decode it back and check the value survives.
        let auth_bytes =
            crate::security::handshake::tokens::encode_auth_req(&auth_req).expect("encode");
        match crate::security::handshake::tokens::parse_token(&auth_bytes).expect("parse") {
            crate::security::handshake::tokens::TokenKind::AuthReq(decoded) => {
                assert_eq!(decoded.future_challenge, request.challenge1);
            }
            other => panic!("expected AuthReq, got {:?}", other),
        }

        // A session is already in progress for this peer (the call above):
        // `start_and_announce` defers to the same `may_start` guard as
        // `start` and announces nothing a second time.
        assert!(
            init.start_and_announce(initiator_guid, responder_guid, &pki.cert, &pki.key)
                .expect("start_and_announce")
                .is_empty(),
            "a second call for a peer already in progress must send nothing"
        );
    }

    /// The responder that receives the initiator's announcement BEFORE the
    /// real Request still completes the handshake normally when the
    /// Request's challenge1 matches what was announced: the cross-check
    /// does not fail the common case.
    #[test]
    fn a_request_matching_its_earlier_announcement_is_accepted() {
        let initiator_guid = make_guid(0x00);
        let responder_guid = make_guid(0xFE);
        let init = HandshakeMachine::new();
        let resp = HandshakeMachine::new();
        let pki = test_pki();

        let actions = init
            .start_and_announce(initiator_guid, responder_guid, &pki.cert, &pki.key)
            .expect("start_and_announce");
        let (auth_req_bytes, request_bytes) = match actions.as_slice() {
            [HandshakeAction::SendAuthRequest(_, auth_req), HandshakeAction::SendRequest(_, req)] => {
                (
                    crate::security::handshake::tokens::encode_auth_req(auth_req).expect("encode"),
                    encode_request(req).expect("encode"),
                )
            }
            other => panic!("expected [SendAuthRequest, SendRequest], got {:?}", other),
        };

        match resp
            .on_message(
                initiator_guid,
                &auth_req_bytes,
                responder_guid,
                &pki.cert,
                &pki.key,
                &pki.ca,
            )
            .expect("the announcement is honoured")
        {
            HandshakeAction::Ignored(..) => {}
            other => panic!("expected Ignored (cached, no wire action), got {:?}", other),
        }

        match resp
            .on_message(
                initiator_guid,
                &request_bytes,
                responder_guid,
                &pki.cert,
                &pki.key,
                &pki.ca,
            )
            .expect("the Request matches the earlier announcement")
        {
            HandshakeAction::SendReply(..) => {}
            other => panic!("expected SendReply, got {:?}", other),
        }
    }

    /// DDS Security v1.1 Sec.9.3.3 Table 52, begin_handshake_reply: "If the
    /// \[remote_auth_request_token\] was different from TokenNIL, the
    /// operation shall verify that the ... future_challenge ... is the same
    /// value as ... challenge1 ... If the condition is not met ...
    /// VALIDATION_FAILED." A Request whose challenge1 does not match the
    /// future_challenge this same identity announced earlier is refused,
    /// even though every other field (certificate, dh1, pdata, signature
    /// algorithm) is exactly what the real initiator would send.
    #[test]
    fn a_request_whose_challenge1_does_not_match_its_earlier_announcement_is_refused() {
        let initiator_guid = make_guid(0x00);
        let responder_guid = make_guid(0xFE);
        let init = HandshakeMachine::new();
        let resp = HandshakeMachine::new();
        let pki = test_pki();

        let actions = init
            .start_and_announce(initiator_guid, responder_guid, &pki.cert, &pki.key)
            .expect("start_and_announce");
        let (auth_req, request) = match actions.as_slice() {
            [HandshakeAction::SendAuthRequest(_, auth_req), HandshakeAction::SendRequest(_, req)] => {
                (auth_req.clone(), req.clone())
            }
            other => panic!("expected [SendAuthRequest, SendRequest], got {:?}", other),
        };
        let auth_req_bytes =
            crate::security::handshake::tokens::encode_auth_req(&auth_req).expect("encode");

        resp.on_message(
            initiator_guid,
            &auth_req_bytes,
            responder_guid,
            &pki.cert,
            &pki.key,
            &pki.ca,
        )
        .expect("the announcement is cached");

        // A Request that carries a DIFFERENT challenge1 than the one just
        // announced: everything else (identity, dh1, pdata) is the real
        // initiator's.
        let mut forged = request.clone();
        forged.challenge1 = {
            let mut c = request.challenge1;
            c[0] ^= 0xFF;
            c
        };
        assert_ne!(forged.challenge1, auth_req.future_challenge);
        let forged_bytes = encode_request(&forged).expect("encode");

        let error = resp
            .on_message(
                initiator_guid,
                &forged_bytes,
                responder_guid,
                &pki.cert,
                &pki.key,
                &pki.ca,
            )
            .expect_err("a Request whose challenge1 does not match the announcement is refused");
        assert!(
            error.to_string().contains("future_challenge"),
            "got: {}",
            error
        );
        assert!(!resp.has_session(&initiator_guid) || !resp.is_authenticated(&initiator_guid));

        // The genuine Request (unmutated) still works: the refusal is
        // specific to the mismatch, not to having announced at all.
        let real_bytes = encode_request(&request).expect("encode");
        match resp
            .on_message(
                initiator_guid,
                &real_bytes,
                responder_guid,
                &pki.cert,
                &pki.key,
                &pki.ca,
            )
            .expect("the genuine Request still matches its own announcement")
        {
            HandshakeAction::SendReply(..) => {}
            other => panic!("expected SendReply, got {:?}", other),
        }
    }

    /// A Request with no prior announcement at all (the announcement was
    /// lost, or the responder got to the Request first) is not held to this
    /// check: the common case where nothing crossed stays unaffected.
    #[test]
    fn a_request_with_no_prior_announcement_is_not_held_to_a_crosscheck() {
        let initiator_guid = make_guid(0x00);
        let responder_guid = make_guid(0xFE);
        let pki = test_pki();
        let resp = HandshakeMachine::new();
        // `request_from` uses plain `start`, which never sends the
        // announcement on the wire; the responder here sees the Request
        // with nothing cached for this identity.
        let request = request_from(
            &HandshakeMachine::new(),
            initiator_guid,
            responder_guid,
            &pki,
        );
        match resp
            .on_message(
                initiator_guid,
                &request,
                responder_guid,
                &pki.cert,
                &pki.key,
                &pki.ca,
            )
            .expect("no announcement was ever cached for this identity")
        {
            HandshakeAction::SendReply(..) => {}
            other => panic!("expected SendReply, got {:?}", other),
        }
    }

    /// Table 52 binds challenge1 to the local token even when the bounded
    /// identity cache cannot retain another entry.
    #[test]
    fn authreq_saturated_cache_announces_the_committed_request() {
        let init = HandshakeMachine::new().with_max_sessions_for_tests(usize::MAX);
        let resp = HandshakeMachine::new();
        let pki = test_pki();
        let initiator = make_guid(0x00);
        let responder = make_guid(0xFE);
        let (_, bound) = init.future_challenges_kept();
        for n in 0..bound {
            let mut prefix = [0u8; 12];
            prefix[4..12].copy_from_slice(&(n as u64).to_be_bytes());
            let peer = GUID::new(prefix, [0, 0, 1, 0xC1]);
            let _ = auth_request_from(&init, initiator, peer);
        }
        assert_eq!(init.future_challenges_kept().0, bound);
        let (announcement, request) = announced_request(&init, initiator, responder, &pki);
        assert_eq!(announcement.future_challenge, request.challenge1);
        deliver_announcement(&resp, initiator, responder, &announcement, &pki);
        complete_announced_request(&init, &resp, initiator, responder, &request, &pki);
    }

    fn announced_request(
        init: &HandshakeMachine,
        initiator: GUID,
        responder: GUID,
        pki: &Pki,
    ) -> (
        crate::security::handshake::tokens::AuthReqToken,
        crate::security::handshake::tokens::AuthRequestToken,
    ) {
        let actions = init
            .start_and_announce(initiator, responder, &pki.cert, &pki.key)
            .expect("start and announce");
        match actions.as_slice() {
            [HandshakeAction::SendAuthRequest(_, announcement), HandshakeAction::SendRequest(_, request)] => {
                (announcement.clone(), request.clone())
            }
            other => panic!("expected announcement and Request, got {:?}", other),
        }
    }

    fn deliver_announcement(
        machine: &HandshakeMachine,
        from: GUID,
        local: GUID,
        announcement: &crate::security::handshake::tokens::AuthReqToken,
        pki: &Pki,
    ) {
        let bytes = crate::security::handshake::tokens::encode_auth_req(announcement)
            .expect("encode announcement");
        assert!(matches!(
            machine
                .on_message(from, &bytes, local, &pki.cert, &pki.key, &pki.ca)
                .expect("receive announcement"),
            HandshakeAction::Ignored(..)
        ));
    }

    fn complete_announced_request(
        init: &HandshakeMachine,
        resp: &HandshakeMachine,
        initiator: GUID,
        responder: GUID,
        request: &crate::security::handshake::tokens::AuthRequestToken,
        pki: &Pki,
    ) {
        let reply = answer(
            resp,
            initiator,
            &encode_request(request).expect("encode"),
            responder,
            pki,
        );
        let final_bytes = answer(init, responder, &reply, initiator, pki);
        assert!(matches!(
            resp.on_message(
                initiator,
                &final_bytes,
                responder,
                &pki.cert,
                &pki.key,
                &pki.ca
            )
            .expect("complete responder"),
            HandshakeAction::Completed(..)
        ));
        assert_eq!(
            init.shared_secret_for(&responder),
            resp.shared_secret_for(&initiator)
        );
        assert!(init.is_authenticated(&responder));
        assert!(resp.is_authenticated(&initiator));
    }

    /// Tables 49 and 52 require a new nonce for a new Request, while timer
    /// retransmissions preserve the original Request and announcement.
    #[test]
    fn authreq_reply_loss_restart_uses_a_fresh_announced_nonce() {
        let init = HandshakeMachine::new();
        let resp = HandshakeMachine::new();
        let pki = test_pki();
        let initiator = make_guid(0x00);
        let responder = make_guid(0xFE);
        let (announcement, request) = announced_request(&init, initiator, responder, &pki);
        deliver_announcement(&resp, initiator, responder, &announcement, &pki);
        let _lost_reply = answer(
            &resp,
            initiator,
            &encode_request(&request).expect("encode"),
            responder,
            &pki,
        );
        let retries = init.tick(Instant::now() + RUNG_1 + PAST);
        match retries.as_slice() {
            [HandshakeAction::SendRequest(_, retry)] => {
                assert_eq!(
                    encode_request(retry).expect("encode"),
                    encode_request(&request).expect("encode")
                );
                assert!(
                    resp.on_message(
                        initiator,
                        &encode_request(retry).expect("encode"),
                        responder,
                        &pki.cert,
                        &pki.key,
                        &pki.ca
                    )
                    .is_err(),
                    "an already accepted nonce stays in the replay window"
                );
            }
            other => panic!("expected Request retransmission, got {:?}", other),
        }
        let _ = init.tick(Instant::now() + DEADLINE + PAST);
        let _ = resp.tick(Instant::now() + DEADLINE + PAST);
        let (next_announcement, next_request) =
            announced_request(&init, initiator, responder, &pki);
        assert_ne!(
            next_request.challenge1, request.challenge1,
            "a restarted attempt must not replay challenge1"
        );
        assert_eq!(next_request.challenge1, next_announcement.future_challenge);
        deliver_announcement(&resp, initiator, responder, &next_announcement, &pki);
        complete_announced_request(&init, &resp, initiator, responder, &next_request, &pki);
    }

    /// Table 52 validation failure does not accept a Request or reserve its
    /// nonce: receiving the correct announcement must rescue that Request.
    #[test]
    fn authreq_mismatch_does_not_poison_the_request_nonce() {
        let init = HandshakeMachine::new();
        let resp = HandshakeMachine::new();
        let pki = test_pki();
        let initiator = make_guid(0x00);
        let responder = make_guid(0xFE);
        let (announcement, request) = announced_request(&init, initiator, responder, &pki);
        let mut wrong = announcement.clone();
        wrong.future_challenge[0] ^= 0xFF;
        deliver_announcement(&resp, initiator, responder, &wrong, &pki);
        let bytes = encode_request(&request).expect("encode");
        let error = resp
            .on_message(initiator, &bytes, responder, &pki.cert, &pki.key, &pki.ca)
            .expect_err("challenge1 must match the received token");
        assert!(error.to_string().contains("future_challenge"));
        deliver_announcement(&resp, initiator, responder, &announcement, &pki);
        complete_announced_request(&init, &resp, initiator, responder, &request, &pki);
    }

    /// The token constrains its own attempt, not a Request sent after the
    /// first responder session expired with every Final lost.
    #[test]
    fn authreq_final_loss_does_not_bind_the_recovery_request_to_the_old_token() {
        let init = HandshakeMachine::new();
        let resp = HandshakeMachine::new();
        let pki = test_pki();
        let initiator = make_guid(0x00);
        let responder = make_guid(0xFE);
        let (announcement, request) = announced_request(&init, initiator, responder, &pki);
        deliver_announcement(&resp, initiator, responder, &announcement, &pki);
        let reply = answer(
            &resp,
            initiator,
            &encode_request(&request).expect("encode"),
            responder,
            &pki,
        );
        let _lost_final = answer(&init, responder, &reply, initiator, &pki);
        assert!(init.is_authenticated(&responder));
        assert!(!resp.is_authenticated(&initiator));
        let _ = resp.tick(Instant::now() + DEADLINE + PAST);
        init.age_completion(&responder);
        let (retry, _) = auth_request_from(&resp, responder, initiator);
        let new_request = answer(&init, responder, &retry, initiator, &pki);
        let new_reply = answer(&resp, initiator, &new_request, responder, &pki);
        let final_bytes = answer(&init, responder, &new_reply, initiator, &pki);
        assert!(matches!(
            resp.on_message(
                initiator,
                &final_bytes,
                responder,
                &pki.cert,
                &pki.key,
                &pki.ca
            )
            .expect("recovery completes"),
            HandshakeAction::Completed(..)
        ));
        assert_eq!(
            init.shared_secret_for(&responder),
            resp.shared_secret_for(&initiator)
        );
    }

    /// Best-effort delivery may put a delayed old announcement after the
    /// Request, and lose the next announcement entirely.
    #[test]
    fn authreq_late_announcement_cannot_leak_into_the_next_attempt() {
        let init = HandshakeMachine::new();
        let resp = HandshakeMachine::new();
        let pki = test_pki();
        let initiator = make_guid(0x00);
        let responder = make_guid(0xFE);
        let (announcement, request) = announced_request(&init, initiator, responder, &pki);
        let _lost_reply = answer(
            &resp,
            initiator,
            &encode_request(&request).expect("encode"),
            responder,
            &pki,
        );
        deliver_announcement(&resp, initiator, responder, &announcement, &pki);
        let _ = init.tick(Instant::now() + DEADLINE + PAST);
        let (_lost_announcement, next) = announced_request(&init, initiator, responder, &pki);
        complete_announced_request(&init, &resp, initiator, responder, &next, &pki);
    }

    /// An announcement whose Request never arrives has the same bounded
    /// lifetime as an authentication attempt.
    #[test]
    fn authreq_unanswered_announcement_expires_before_a_later_request() {
        let pki = test_pki();
        let initiator = make_guid(0x00);
        let responder = make_guid(0xFE);
        let abandoned = HandshakeMachine::new();
        let resp = HandshakeMachine::new();
        let (announcement, _lost_request) =
            announced_request(&abandoned, initiator, responder, &pki);
        deliver_announcement(&resp, initiator, responder, &announcement, &pki);
        let _ = resp.tick(Instant::now() + DEADLINE + PAST);
        let restarted = HandshakeMachine::new();
        let (_lost_announcement, request) =
            announced_request(&restarted, initiator, responder, &pki);
        complete_announced_request(&restarted, &resp, initiator, responder, &request, &pki);
    }

    /// Table 52, validate_remote_identity: a token received before SPDP
    /// makes the local token NIL. process_handshake must check challenge2
    /// against that received token, even though no session existed then.
    #[test]
    fn authreq_before_spdp_suppresses_the_local_token_and_binds_challenge2() {
        let init = HandshakeMachine::new();
        let resp = HandshakeMachine::new();
        let pki = test_pki();
        let initiator = make_guid(0x00);
        let responder = make_guid(0xFE);
        let (announcement, expected) = auth_request_from(&resp, responder, initiator);
        assert!(matches!(
            init.on_message(
                responder,
                &announcement,
                initiator,
                &pki.cert,
                &pki.key,
                &pki.ca
            )
            .expect("token arrives before SPDP"),
            HandshakeAction::Ignored(..)
        ));
        assert!(!init.has_session(&responder));
        let actions = init
            .start_and_announce(initiator, responder, &pki.cert, &pki.key)
            .expect("SPDP starts the Request");
        let request = match actions.as_slice() {
            [HandshakeAction::SendRequest(_, request)] => request,
            other => panic!("a remote token makes the local token NIL, got {:?}", other),
        };
        // This peer signs a valid Reply with another challenge2. All the
        // ordinary Request/Reply signature and certificate checks pass.
        let other_resp = HandshakeMachine::new();
        let wrong_reply = answer(
            &other_resp,
            initiator,
            &encode_request(request).expect("encode"),
            responder,
            &pki,
        );
        assert!(
            matches!(parse_token(&wrong_reply).expect("parse"), TokenKind::Reply(ref reply) if reply.challenge2 != expected)
        );
        assert!(matches!(
            init.on_message(
                responder,
                &wrong_reply,
                initiator,
                &pki.cert,
                &pki.key,
                &pki.ca
            )
            .expect("the original Request is retried after refusal"),
            HandshakeAction::SendRequest(..)
        ));
        assert!(
            !init.is_authenticated(&responder),
            "a signed Reply with the wrong future_challenge cannot complete"
        );
        complete_announced_request(&init, &resp, initiator, responder, request, &pki);
    }

    /// The same NIL-local-token condition applies when the responder hears
    /// the initiator's announcement before discovering it.
    #[test]
    fn authreq_responder_receipt_before_spdp_does_not_create_a_local_token() {
        let init = HandshakeMachine::new();
        let resp = HandshakeMachine::new();
        let pki = test_pki();
        let initiator = make_guid(0x00);
        let responder = make_guid(0xFE);
        let (announcement, request) = announced_request(&init, initiator, responder, &pki);
        deliver_announcement(&resp, initiator, responder, &announcement, &pki);
        assert!(resp
            .start_and_announce(responder, initiator, &pki.cert, &pki.key)
            .expect("SPDP after token receipt")
            .is_empty());
        assert!(resp.has_session(&initiator));
        assert!(!resp.is_authenticated(&initiator));
        assert_eq!(
            resp.future_challenges_kept().0,
            0,
            "no local token is created"
        );
        assert!(
            resp.tick(Instant::now() + RUNG_1 + PAST).is_empty(),
            "a NIL local token cannot be retransmitted"
        );
        complete_announced_request(&init, &resp, initiator, responder, &request, &pki);
    }

    /// Consuming the remote token on accepted Request must also work when
    /// the initiator retries a new attempt before the responder times out.
    #[test]
    fn authreq_accepted_announcement_does_not_bind_a_new_attempt() {
        let init = HandshakeMachine::new();
        let resp = HandshakeMachine::new();
        let pki = test_pki();
        let initiator = make_guid(0x00);
        let responder = make_guid(0xFE);
        let (announcement, request) = announced_request(&init, initiator, responder, &pki);
        deliver_announcement(&resp, initiator, responder, &announcement, &pki);
        let _lost_reply = answer(
            &resp,
            initiator,
            &encode_request(&request).expect("encode"),
            responder,
            &pki,
        );
        let _ = init.tick(Instant::now() + DEADLINE + PAST);
        let (_lost_announcement, next) = announced_request(&init, initiator, responder, &pki);
        complete_announced_request(&init, &resp, initiator, responder, &next, &pki);
    }

    /// Best-effort delivery may put an old attempt's announcement after a
    /// new one. A consumed token cannot replace the new pending token.
    #[test]
    fn authreq_old_announcement_after_timeout_cannot_replace_the_new_one() {
        let init = HandshakeMachine::new();
        let resp = HandshakeMachine::new();
        let pki = test_pki();
        let initiator = make_guid(0x00);
        let responder = make_guid(0xFE);
        let (old, request) = announced_request(&init, initiator, responder, &pki);
        deliver_announcement(&resp, initiator, responder, &old, &pki);
        let _lost_reply = answer(
            &resp,
            initiator,
            &encode_request(&request).expect("encode"),
            responder,
            &pki,
        );
        let _ = init.tick(Instant::now() + DEADLINE + PAST);
        let _ = resp.tick(Instant::now() + DEADLINE + PAST);
        let (new, request) = announced_request(&init, initiator, responder, &pki);
        deliver_announcement(&resp, initiator, responder, &new, &pki);
        deliver_announcement(&resp, initiator, responder, &old, &pki);
        complete_announced_request(&init, &resp, initiator, responder, &request, &pki);
    }

    /// A newly received remote token binds the next Request even when a
    /// previous attempt still awaits Final. It cannot change that earlier
    /// attempt's retained peer nonce or Final validation.
    #[test]
    fn authreq_new_announcement_during_reply_binds_the_next_request() {
        let pki = test_pki();
        let initiator = make_guid(0x00);
        let responder = make_guid(0xFE);
        let abandoned = HandshakeMachine::new();
        let resp = HandshakeMachine::new();
        let (old, request) = announced_request(&abandoned, initiator, responder, &pki);
        deliver_announcement(&resp, initiator, responder, &old, &pki);
        let _lost_reply = answer(
            &resp,
            initiator,
            &encode_request(&request).expect("encode"),
            responder,
            &pki,
        );
        let restarted = HandshakeMachine::new();
        let (new, request) = announced_request(&restarted, initiator, responder, &pki);
        deliver_announcement(&resp, initiator, responder, &new, &pki);
        let mut mismatched = request.clone();
        mismatched.challenge1[0] ^= 0xFF;
        let error = resp
            .on_message(
                initiator,
                &encode_request(&mismatched).expect("encode"),
                responder,
                &pki.cert,
                &pki.key,
                &pki.ca,
            )
            .expect_err("a fresh announcement constrains its next Request");
        assert!(error.to_string().contains("future_challenge"));
        complete_announced_request(&restarted, &resp, initiator, responder, &request, &pki);
    }

    /// A remote token and the NIL-local-token wait belong to one attempt,
    /// even when token delivery precedes SPDP by part of the deadline.
    #[test]
    fn authreq_delayed_spdp_keeps_the_nil_wait_on_the_tokens_deadline() {
        let pki = test_pki();
        let initiator = make_guid(0x00);
        let responder = make_guid(0xFE);
        let init = HandshakeMachine::new();
        let resp = HandshakeMachine::new();
        let (announcement, _lost_request) = announced_request(&init, initiator, responder, &pki);
        deliver_announcement(&resp, initiator, responder, &announcement, &pki);
        resp.age_pending_announcement(&initiator, DEADLINE / 2);
        assert!(resp
            .start_and_announce(responder, initiator, &pki.cert, &pki.key)
            .expect("delayed SPDP")
            .is_empty());
        // The remaining half of the attempt expires both the token and
        // the wait. A full new deadline starting at SPDP would stall here.
        assert!(resp.tick(Instant::now() + DEADLINE / 2 + PAST).is_empty());
        let _ = init.tick(Instant::now() + DEADLINE + PAST);
        let actions = resp
            .start_and_announce(responder, initiator, &pki.cert, &pki.key)
            .expect("the expired attempt can ask again");
        let announcement = match actions.as_slice() {
            [HandshakeAction::SendAuthRequest(_, token)] => token,
            other => panic!(
                "expected a new AuthRequest after the shared deadline, got {:?}",
                other
            ),
        };
        deliver_announcement(&init, responder, initiator, announcement, &pki);
        let actions = init
            .start_and_announce(initiator, responder, &pki.cert, &pki.key)
            .expect("new attempt answers the remote token");
        let request = match actions.as_slice() {
            [HandshakeAction::SendRequest(_, request)] => request,
            other => panic!("expected a Request without a local token, got {:?}", other),
        };
        complete_announced_request(&init, &resp, initiator, responder, request, &pki);
    }

    /// A token preparing a new attempt is not owned by the older ReplySent
    /// session. Expiring that older session must preserve the new binding.
    #[test]
    fn authreq_old_reply_timeout_preserves_the_new_pending_announcement() {
        let pki = test_pki();
        let initiator = make_guid(0x00);
        let responder = make_guid(0xFE);
        let abandoned = HandshakeMachine::new();
        let resp = HandshakeMachine::new();
        let (old, request) = announced_request(&abandoned, initiator, responder, &pki);
        deliver_announcement(&resp, initiator, responder, &old, &pki);
        let _lost_reply = answer(
            &resp,
            initiator,
            &encode_request(&request).expect("encode"),
            responder,
            &pki,
        );
        resp.age_pending_reply(&initiator, DEADLINE);
        let restarted = HandshakeMachine::new();
        let (new, request) = announced_request(&restarted, initiator, responder, &pki);
        deliver_announcement(&resp, initiator, responder, &new, &pki);
        let expired = resp.tick(Instant::now() + PAST);
        assert!(matches!(expired.as_slice(), [HandshakeAction::Failed(..)]));
        let mut wrong = request.clone();
        wrong.challenge1[0] ^= 0xFF;
        let error = resp
            .on_message(
                initiator,
                &encode_request(&wrong).expect("encode"),
                responder,
                &pki.cert,
                &pki.key,
                &pki.ca,
            )
            .expect_err("the fresh announcement still constrains the next Request");
        assert!(error.to_string().contains("future_challenge"));
        complete_announced_request(&restarted, &resp, initiator, responder, &request, &pki);
    }

    // --------------------------------------------------------
    //  Forged announcements (DDS Security v1.1 Sec.9.3.3, Table 52: an
    //  AuthRequestMessageToken is signed by nobody)
    // --------------------------------------------------------

    /// `machine`'s answer to a handshake message it must accept.
    fn deliver_request(
        machine: &HandshakeMachine,
        from: GUID,
        bytes: &[u8],
        local: GUID,
        pki: &Pki,
    ) -> HandshakeAction {
        machine
            .on_message(from, bytes, local, &pki.cert, &pki.key, &pki.ca)
            .expect("an AuthRequest is ordinary traffic")
    }

    /// DDS Security v1.1 Sec.9.3.3, Table 52: the Request's challenge1 is the
    /// future_challenge its initiator announced. An announcement is signed
    /// by nobody: a forged one under the initiator's prefix, received after
    /// the real one, must not get the real Request refused.
    ///
    /// Mutant: keeping one announcement per identity (the last) refuses the
    /// real Request.
    #[test]
    fn a_forged_announcement_does_not_lock_the_peer_out() {
        let init = HandshakeMachine::new();
        let resp = HandshakeMachine::new();
        let pki = test_pki();
        let initiator = make_guid(0x00);
        let responder = make_guid(0xFE);
        let (announcement, request) = announced_request(&init, initiator, responder, &pki);
        deliver_announcement(&resp, initiator, responder, &announcement, &pki);
        let mut forged = announcement.clone();
        forged.future_challenge = [0x42; 32];
        deliver_announcement(&resp, initiator, responder, &forged, &pki);
        complete_announced_request(&init, &resp, initiator, responder, &request, &pki);
    }

    /// The initiator's side of the same: a forged announcement under a
    /// completed peer's prefix begins a new session bound to its challenge;
    /// the peer's own announcement, received while that session is in
    /// flight, is the one the peer's Reply answers, and the session
    /// completes.
    ///
    /// Mutant: checking challenge2 against the session's own announcement
    /// only refuses the peer's Reply.
    #[test]
    fn a_forged_announcement_does_not_lock_a_completed_peer_out() {
        let pki = test_pki();
        let pair = completed_pair();
        let old_secret = pair
            .init
            .shared_secret_for(&pair.responder_guid)
            .expect("completed");
        let forged = crate::security::handshake::tokens::encode_auth_req(
            &crate::security::handshake::tokens::AuthReqToken {
                future_challenge: [0x42; 32],
            },
        )
        .expect("encode");
        let request = match deliver_request(
            &pair.init,
            pair.responder_guid,
            &forged,
            pair.initiator_guid,
            &pki,
        ) {
            HandshakeAction::SendRequest(_, token) => encode_request(&token).expect("encode"),
            other => panic!("expected an AuthRequest, got {:?}", other),
        };
        // The real responder announces its one future_challenge, the one
        // its completed session answered with.
        let real = crate::security::handshake::tokens::encode_auth_req(
            &crate::security::handshake::tokens::AuthReqToken {
                future_challenge: pair.reply.challenge2,
            },
        )
        .expect("encode");
        assert!(matches!(
            deliver_request(
                &pair.init,
                pair.responder_guid,
                &real,
                pair.initiator_guid,
                &pki
            ),
            HandshakeAction::Ignored(..)
        ));
        let reply = answer(
            &pair.resp,
            pair.initiator_guid,
            &request,
            pair.responder_guid,
            &pki,
        );
        let final_bytes = answer(
            &pair.init,
            pair.responder_guid,
            &reply,
            pair.initiator_guid,
            &pki,
        );
        assert!(matches!(
            deliver_request(
                &pair.resp,
                pair.initiator_guid,
                &final_bytes,
                pair.responder_guid,
                &pki
            ),
            HandshakeAction::Completed(..)
        ));
        let new_secret = pair
            .init
            .shared_secret_for(&pair.responder_guid)
            .expect("completed");
        assert_ne!(new_secret, old_secret);
        assert_eq!(
            pair.resp.shared_secret_for(&pair.initiator_guid),
            Some(new_secret)
        );
    }

    // --------------------------------------------------------
    //  Forged AuthRequests: what they may cost (DDS Security v1.1
    //  Sec.9.3.2.4: an AuthRequest is signed by nobody)
    // --------------------------------------------------------

    /// The AuthRequests of `count` participants bound to the test identity
    /// (a public certificate replayed under prefixes whose free bits vary),
    /// toward `responder`.
    fn forged_requests(responder: GUID, count: u8, pki: &Pki) -> Vec<(GUID, Vec<u8>)> {
        (0..count)
            .map(|n| {
                let initiator = make_guid(n);
                (
                    initiator,
                    request_from(&HandshakeMachine::new(), initiator, responder, pki),
                )
            })
            .collect()
    }

    /// A flood of AuthRequests is answered (a chain verification, a key
    /// pair, a signature, a session filed) at most the responder budget of
    /// the interval; the rest are refused before any of it.
    ///
    /// Mutant: `take_responder_budget` answering `true` files every one.
    #[test]
    fn a_flood_of_requests_is_answered_within_the_responder_budget() {
        let pki = test_pki();
        let responder = make_guid(0xFF);
        let resp = HandshakeMachine::new().with_responder_budget_for_tests(4, DEADLINE * 100);
        let mut answered = 0;
        for (initiator, bytes) in forged_requests(responder, 40, &pki) {
            match deliver_request(&resp, initiator, &bytes, responder, &pki) {
                HandshakeAction::SendReply(..) => answered += 1,
                HandshakeAction::Ignored(..) => {}
                other => panic!("expected a reply or nothing, got {:?}", other),
            }
        }
        assert_eq!(answered, 4);
        assert_eq!(resp.sessions_held(), 4);
    }

    /// The sessions held are bounded whatever the budget: past the bound a
    /// participant that holds none is not answered, and one that holds one
    /// still is.
    ///
    /// Mutant: `has_room_for` answering `true` files all forty.
    #[test]
    fn the_sessions_held_are_bounded() {
        let pki = test_pki();
        let responder = make_guid(0xFF);
        let resp = HandshakeMachine::new().with_max_sessions_for_tests(5);
        let requests = forged_requests(responder, 40, &pki);
        for (initiator, bytes) in &requests {
            let _ = deliver_request(&resp, *initiator, bytes, responder, &pki);
        }
        assert_eq!(resp.sessions_held(), 5);
        // One of the five sends a new Request: it holds a session, it is
        // answered.
        let (held, _) = requests[0];
        let again = request_from(&HandshakeMachine::new(), held, responder, &pki);
        assert!(matches!(
            deliver_request(&resp, held, &again, responder, &pki),
            HandshakeAction::SendReply(..)
        ));
        assert_eq!(resp.sessions_held(), 5);
    }

    /// A Request from a participant discovery has not seen costs nothing:
    /// no session, and none of the responder budget. Its announcement,
    /// once seen, begins the handshake, and its retransmitted Request is
    /// answered.
    ///
    /// Mutant: dropping the `participant_known` check answers the unseen
    /// participant, and spends the one session of the budget.
    #[test]
    fn a_request_from_a_participant_discovery_has_not_seen_costs_nothing() {
        use std::sync::Mutex;
        let pki = test_pki();
        let responder = make_guid(0xFF);
        let seen = make_guid(0x01);
        let unseen = make_guid(0x02);
        let known = Arc::new(Mutex::new(vec![seen.prefix]));
        let resp = HandshakeMachine::new().with_responder_budget_for_tests(1, DEADLINE * 100);
        let told = Arc::clone(&known);
        resp.set_participant_known(Box::new(move |prefix| {
            told.lock().unwrap().contains(prefix)
        }));

        let from_unseen = request_from(&HandshakeMachine::new(), unseen, responder, &pki);
        assert!(matches!(
            deliver_request(&resp, unseen, &from_unseen, responder, &pki),
            HandshakeAction::Ignored(..)
        ));
        assert!(!resp.has_session(&unseen));

        let from_seen = request_from(&HandshakeMachine::new(), seen, responder, &pki);
        assert!(matches!(
            deliver_request(&resp, seen, &from_seen, responder, &pki),
            HandshakeAction::SendReply(..)
        ));

        // Discovery sees it; the budget is renewed; the retransmission is
        // answered.
        known.lock().unwrap().push(unseen.prefix);
        resp.age_responder_budget(DEADLINE * 100);
        assert!(matches!(
            deliver_request(&resp, unseen, &from_unseen, responder, &pki),
            HandshakeAction::SendReply(..)
        ));
    }

    /// A failed session of a participant discovery no longer knows is
    /// freed with every table entry it held; one of a participant discovery
    /// knows stays (it says the participant takes part in authentication),
    /// until discovery drops it.
    ///
    /// Mutant: `free_failed_of_unknown` returning at once leaves both.
    #[test]
    fn a_failed_session_of_a_participant_discovery_does_not_know_is_freed() {
        use std::sync::Mutex;
        let pki = test_pki();
        let responder = make_guid(0xFF);
        let kept = make_guid(0x01);
        let gone = make_guid(0x02);
        let known = Arc::new(Mutex::new(vec![kept.prefix, gone.prefix]));
        let resp = HandshakeMachine::new();
        let told = Arc::clone(&known);
        resp.set_participant_known(Box::new(move |prefix| {
            told.lock().unwrap().contains(prefix)
        }));
        for initiator in [kept, gone] {
            let bytes = request_from(&HandshakeMachine::new(), initiator, responder, &pki);
            let _ = deliver_request(&resp, initiator, &bytes, responder, &pki);
        }
        assert_eq!(resp.sessions_held(), 2);
        known
            .lock()
            .unwrap()
            .retain(|prefix| *prefix != gone.prefix);

        let failed = resp.tick(Instant::now() + DEADLINE + PAST);
        assert_eq!(failed.len(), 2, "both sessions expire: {:?}", failed);
        assert!(
            resp.has_session(&kept),
            "the known participant's failure stays"
        );
        assert!(
            !resp.has_session(&gone),
            "the unknown participant's is freed"
        );
        assert_eq!(resp.sessions_held(), 1);
    }

    /// A participant that really restarted is not locked out by a flood
    /// that spent the responder budget: its Request, retransmitted once the
    /// budget is renewed, is answered, and the new session replaces the
    /// completed one at its Final.
    #[test]
    fn a_restarted_peer_authenticates_after_a_flood() {
        let pki = test_pki();
        let pair = completed_pair();
        let resp = HandshakeMachine::new().with_responder_budget_for_tests(3, DEADLINE * 100);
        // A responder with a budget, completed with the pair's initiator.
        let init = HandshakeMachine::new();
        let request = request_from(&init, pair.initiator_guid, pair.responder_guid, &pki);
        let reply = answer(
            &resp,
            pair.initiator_guid,
            &request,
            pair.responder_guid,
            &pki,
        );
        let final_bytes = answer(
            &init,
            pair.responder_guid,
            &reply,
            pair.initiator_guid,
            &pki,
        );
        assert!(matches!(
            deliver_request(
                &resp,
                pair.initiator_guid,
                &final_bytes,
                pair.responder_guid,
                &pki
            ),
            HandshakeAction::Completed(..)
        ));
        let old_secret = resp
            .shared_secret_for(&pair.initiator_guid)
            .expect("completed");

        for (initiator, bytes) in forged_requests(pair.responder_guid, 0x30, &pki)
            .into_iter()
            .skip(1)
        {
            let _ = deliver_request(&resp, initiator, &bytes, pair.responder_guid, &pki);
        }

        // The initiator restarts under the same prefix.
        let restarted = HandshakeMachine::new();
        let request = request_from(&restarted, pair.initiator_guid, pair.responder_guid, &pki);
        assert!(matches!(
            deliver_request(
                &resp,
                pair.initiator_guid,
                &request,
                pair.responder_guid,
                &pki
            ),
            HandshakeAction::Ignored(..)
        ));
        resp.age_responder_budget(DEADLINE * 100);
        let reply = answer(
            &resp,
            pair.initiator_guid,
            &request,
            pair.responder_guid,
            &pki,
        );
        let final_bytes = answer(
            &restarted,
            pair.responder_guid,
            &reply,
            pair.initiator_guid,
            &pki,
        );
        assert!(matches!(
            deliver_request(
                &resp,
                pair.initiator_guid,
                &final_bytes,
                pair.responder_guid,
                &pki
            ),
            HandshakeAction::Completed(..)
        ));
        let new_secret = resp
            .shared_secret_for(&pair.initiator_guid)
            .expect("completed");
        assert_ne!(new_secret, old_secret);
        assert_eq!(
            restarted.shared_secret_for(&pair.responder_guid),
            Some(new_secret)
        );
    }
}
