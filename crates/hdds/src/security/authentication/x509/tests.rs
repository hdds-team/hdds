// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

use super::plugin::X509AuthenticationPlugin;
// Only the `feature = "security"` tests below drive a handshake, so the GUID
// import follows them: ungated it is an unused import on the DEFAULT feature
// set, which `clippy -D warnings` refuses (the feature set no gate owned until
// the windows-gate W5 lane named it).
#[cfg(feature = "security")]
use crate::core::discovery::guid::GUID;
// The trait is only named by the `feature = "security"` tests below: the
// featureless build's one test stops at plugin CONSTRUCTION, which never
// succeeds there.
#[cfg(feature = "security")]
use crate::security::authentication::AuthenticationPlugin;
use crate::security::config::SecurityConfig;
use std::io::Write;
use tempfile::NamedTempFile;

fn create_pem_file(content: &str) -> NamedTempFile {
    let mut file = NamedTempFile::new().expect("Failed to create temp file");
    file.write_all(content.as_bytes())
        .expect("Failed to write to temp file");
    file.flush().expect("Failed to flush temp file");
    file
}

// Real X.509 material (EC P-256 CA + issued identity + its key, valid to 2036).
// It lives in `security::test_pki` so the X.509 validator tests and the PKI-DH
// handshake tests cannot drift onto two different certificates.
#[cfg(feature = "security")]
use crate::security::test_pki::{TEST_CA_CERT_PEM, TEST_IDENTITY_CERT_PEM, TEST_IDENTITY_KEY_PEM};

#[cfg(feature = "security")]
fn create_test_certificates() -> (SecurityConfig, NamedTempFile, NamedTempFile, NamedTempFile) {
    // Write test certificates to temp files
    let cert_file = create_pem_file(std::str::from_utf8(TEST_IDENTITY_CERT_PEM).unwrap());
    let key_file = create_pem_file(std::str::from_utf8(TEST_IDENTITY_KEY_PEM).unwrap());
    let ca_file = create_pem_file(std::str::from_utf8(TEST_CA_CERT_PEM).unwrap());

    let config = SecurityConfig::builder()
        .identity_certificate(cert_file.path())
        .private_key(key_file.path())
        .ca_certificates(ca_file.path())
        .build()
        .expect("SecurityConfig build should succeed");

    (config, cert_file, key_file, ca_file)
}

/// Fallback for tests without security feature
#[cfg(not(feature = "security"))]
fn create_test_certificates() -> (SecurityConfig, NamedTempFile, NamedTempFile, NamedTempFile) {
    let cert_file =
        create_pem_file("-----BEGIN CERTIFICATE-----\nMockCert\n-----END CERTIFICATE-----\n");
    let key_file =
        create_pem_file("-----BEGIN PRIVATE KEY-----\nMockKey\n-----END PRIVATE KEY-----\n");
    let ca_file =
        create_pem_file("-----BEGIN CERTIFICATE-----\nMockCA\n-----END CERTIFICATE-----\n");

    let config = SecurityConfig::builder()
        .identity_certificate(cert_file.path())
        .private_key(key_file.path())
        .ca_certificates(ca_file.path())
        .build()
        .expect("SecurityConfig build should succeed");

    (config, cert_file, key_file, ca_file)
}

fn create_mock_config() -> (SecurityConfig, NamedTempFile, NamedTempFile, NamedTempFile) {
    create_test_certificates()
}

#[test]
#[cfg(feature = "security")]
fn test_x509_plugin_creation() {
    let (config, _cert, _key, _ca) = create_mock_config();
    let plugin = X509AuthenticationPlugin::new(&config);
    if let Err(e) = &plugin {
        eprintln!("Plugin creation failed: {:?}", e);
    }
    assert!(
        plugin.is_ok(),
        "Plugin creation should succeed with valid config: {:?}",
        plugin.err()
    );
}

#[test]
#[cfg(feature = "security")]
fn test_x509_plugin_validate_identity() {
    let (config, _cert, _key, _ca) = create_mock_config();
    let plugin = X509AuthenticationPlugin::new(&config).expect("Plugin creation should succeed");
    let identity = plugin.validate_identity();
    assert!(identity.is_ok(), "Identity validation should succeed");
}

/// The SAME two calls without the `security` feature: they must FAIL, and the
/// error must name the feature.
///
/// A build with no X.509 parser must never report a valid identity: the
/// featureless bodies of `validate_certificate_chain`,
/// `derive_guid_from_certificate` and friends must not return `Ok`. This
/// test states that rule rather than mirroring the implementation.
#[test]
#[cfg(not(feature = "security"))]
fn a_build_without_the_security_feature_refuses_to_authenticate() {
    let (config, _cert, _key, _ca) = create_mock_config();
    let err = match X509AuthenticationPlugin::new(&config) {
        Ok(_) => panic!("a build with no X.509 parser must not produce an authentication plugin"),
        Err(e) => format!("{:?}", e),
    };
    assert!(
        err.contains("`security` feature"),
        "the refusal must name the missing feature, got: {}",
        err
    );
}

#[test]
#[cfg(feature = "security")]
fn test_x509_plugin_begin_handshake() {
    let (config, _cert, _key, _ca) = create_mock_config();
    let plugin = X509AuthenticationPlugin::new(&config).expect("Plugin creation should succeed");
    let identity = plugin
        .validate_identity()
        .expect("Identity validation should succeed");
    let token = plugin.begin_handshake(&identity, GUID::zero());
    assert!(token.is_ok(), "Handshake should begin successfully");

    let token = token.expect("Token should be present");
    assert!(token.challenge.is_some(), "Challenge should be present");
    assert!(token.signature.is_some(), "Signature should be present");
}

#[test]
#[cfg(feature = "security")]
fn test_x509_plugin_process_handshake() {
    let (config, _cert, _key, _ca) = create_mock_config();
    let plugin = X509AuthenticationPlugin::new(&config).expect("Plugin creation should succeed");
    let identity = plugin
        .validate_identity()
        .expect("Identity validation should succeed");
    let request = plugin
        .begin_handshake(&identity, GUID::zero())
        .expect("Handshake should begin successfully");
    let reply = plugin.process_handshake(&identity, &request);
    assert!(
        reply.is_ok(),
        "Handshake processing should succeed: {:?}",
        reply.err()
    );
    assert!(
        reply.expect("Reply should be present").is_some(),
        "Reply should contain token"
    );
}

#[test]
fn test_validate_pem_format_valid() {
    let pem = b"-----BEGIN CERTIFICATE-----
data
-----END CERTIFICATE-----
";
    let result = X509AuthenticationPlugin::validate_pem_format(pem, "test");
    assert!(result.is_ok());
}

#[test]
fn test_validate_pem_format_invalid() {
    let not_pem = b"This is not PEM";
    let result = X509AuthenticationPlugin::validate_pem_format(not_pem, "test");
    assert!(result.is_err());
}

#[test]
fn test_validate_pem_format_empty() {
    let empty = b"";
    let result = X509AuthenticationPlugin::validate_pem_format(empty, "test");
    assert!(result.is_err());
}

#[test]
#[cfg(feature = "security")]
fn test_generate_challenge() {
    let challenge = super::crypto::generate_challenge().unwrap();
    assert_eq!(challenge.len(), 32);
}

#[test]
#[cfg(feature = "security")]
fn test_sign_data() {
    let (_config, _cert_file, key_file, _ca_file) = create_test_certificates();
    let data = b"test challenge";

    // Read the real private key
    let key_pem = std::fs::read(key_file.path()).expect("Read key file");

    let signature = super::crypto::sign_data(data, &key_pem);
    assert!(signature.is_ok(), "Signature should succeed with valid key");
    assert!(!signature.expect("Signature should be present").is_empty());
}

#[test]
#[cfg(feature = "security")]
fn test_verify_signature() {
    let (_config, cert_file, key_file, _ca_file) = create_test_certificates();
    let data = b"test challenge";

    // Read the real key and cert
    let key_pem = std::fs::read(key_file.path()).expect("Read key file");
    let cert_pem = std::fs::read(cert_file.path()).expect("Read cert file");

    // Sign data with real key
    let signature = super::crypto::sign_data(data, &key_pem).expect("Signing should succeed");

    // Verify with matching cert
    let result = super::crypto::verify_signature(data, &signature, &cert_pem);
    assert!(
        result.is_ok(),
        "Verification should succeed with matching cert/key"
    );
}

// -------------------------------------------------------------------
// Revocation on the REMOTE path.
//
// `process_handshake` must validate the peer's chain with the CRL: a revoked
// peer that chains to a trusted CA must not be authenticated while the
// configuration says revocation is being checked. The plugin here
// authenticates AS the revocation PKI's local identity (serial 03), the only
// identity whose CA has a CRL in the fixtures, so the list can decide.
// -------------------------------------------------------------------

/// A plugin holding the revocation PKI's local identity. `crl` is `None` for
/// revocation OFF; the temp files ride along so they outlive the plugin.
#[cfg(feature = "security")]
fn revocation_pki_plugin(
    crl: Option<&[u8]>,
) -> Result<
    (
        X509AuthenticationPlugin,
        NamedTempFile,
        NamedTempFile,
        NamedTempFile,
        Option<NamedTempFile>,
    ),
    crate::dds::Error,
> {
    use crate::security::test_pki::{
        REVOCATION_CA_PEM, REVOCATION_LOCAL_IDENTITY_KEY_PEM, REVOCATION_LOCAL_IDENTITY_PEM,
    };
    let cert_file = create_pem_file(std::str::from_utf8(REVOCATION_LOCAL_IDENTITY_PEM).unwrap());
    let key_file = create_pem_file(std::str::from_utf8(REVOCATION_LOCAL_IDENTITY_KEY_PEM).unwrap());
    let ca_file = create_pem_file(std::str::from_utf8(REVOCATION_CA_PEM).unwrap());
    let crl_file = crl.map(|c| create_pem_file(std::str::from_utf8(c).unwrap()));

    let mut builder = SecurityConfig::builder()
        .identity_certificate(cert_file.path())
        .private_key(key_file.path())
        .ca_certificates(ca_file.path());
    if let Some(f) = &crl_file {
        builder = builder
            .check_certificate_revocation(true)
            .certificate_revocation_list(f.path());
    }
    let config = builder
        .build()
        .expect("SecurityConfig build should succeed");
    let plugin = X509AuthenticationPlugin::new(&config)?;
    Ok((plugin, cert_file, key_file, ca_file, crl_file))
}

#[cfg(feature = "security")]
fn request_from(peer_cert_pem: &[u8]) -> super::super::HandshakeRequestToken {
    super::super::HandshakeRequestToken::new(
        "DDS:Auth:PKI-DH:1.0".to_string(),
        peer_cert_pem.to_vec(),
    )
}

/// The remote path: the revoked peer is refused, the other peer from the
/// same CA is admitted. Both chain to the trusted CA; only the list differs.
#[test]
#[cfg(feature = "security")]
fn process_handshake_refuses_a_revoked_peer_and_admits_the_other() {
    use crate::security::test_pki::{
        REVOCATION_CRL_PEM, REVOCATION_GOOD_IDENTITY_PEM, REVOCATION_REVOKED_IDENTITY_PEM,
    };
    let (plugin, _c, _k, _ca, _crl) =
        revocation_pki_plugin(Some(REVOCATION_CRL_PEM)).expect("serial 03 is in no list");
    let identity = plugin
        .validate_identity()
        .expect("local identity is not revoked");

    let err = plugin
        .process_handshake(&identity, &request_from(REVOCATION_REVOKED_IDENTITY_PEM))
        .expect_err("a revoked peer must not be authenticated");
    let text = format!("{}", err);
    assert!(text.contains("REVOKED"), "got: {}", text);

    let reply = plugin
        .process_handshake(&identity, &request_from(REVOCATION_GOOD_IDENTITY_PEM))
        .expect("serial 02 is in no list");
    assert!(reply.is_some(), "the good peer gets a reply");
}

/// The same peer, no list, revocation OFF: the chain alone decides. This pins
/// that the flag is the one switch, and that the test above fails for the
/// list's reason and not because the peer does not chain.
#[test]
#[cfg(feature = "security")]
fn with_revocation_off_the_peer_is_judged_by_its_chain_alone() {
    use crate::security::test_pki::REVOCATION_REVOKED_IDENTITY_PEM;
    let (plugin, _c, _k, _ca, _crl) = revocation_pki_plugin(None).expect("plugin creation");
    let identity = plugin.validate_identity().expect("identity");
    plugin
        .process_handshake(&identity, &request_from(REVOCATION_REVOKED_IDENTITY_PEM))
        .expect("revocation is off, so the chain alone decides and it chains");
}

/// A list that carries no CRL from the local identity's own CA cannot prove
/// the local identity is not revoked, so the plugin does not BUILD. The
/// participant fails before it announces itself.
#[test]
#[cfg(feature = "security")]
fn a_list_with_no_crl_from_the_local_ca_refuses_to_build_the_plugin() {
    use crate::security::test_pki::REVOCATION_OTHER_ISSUER_CRL_PEM;
    let err = match revocation_pki_plugin(Some(REVOCATION_OTHER_ISSUER_CRL_PEM)) {
        Err(e) => e,
        Ok(_) => panic!("no CRL covers the local CA, the plugin must not build"),
    };
    let text = format!("{}", err);
    assert!(
        text.contains("no CRL in the revocation list was issued by"),
        "got: {}",
        text
    );
}

/// A forged list (right issuer name, wrong key) is refused at build too, with
/// the signature named as the reason.
#[test]
#[cfg(feature = "security")]
fn a_forged_list_refuses_to_build_the_plugin() {
    use crate::security::test_pki::REVOCATION_FORGED_CRL_PEM;
    let err = match revocation_pki_plugin(Some(REVOCATION_FORGED_CRL_PEM)) {
        Err(e) => e,
        Ok(_) => panic!("a forged CRL must not be honoured"),
    };
    let text = format!("{}", err);
    assert!(text.contains("signature does not verify"), "got: {}", text);
}

/// The plugin holds the identity's PEM private key. Its `Debug` output goes to
/// logs and panic messages, so it must show the placeholder and none of the key.
#[test]
#[cfg(feature = "security")]
fn the_plugin_debug_output_never_carries_the_identity_key() {
    use crate::security::test_pki::TEST_IDENTITY_KEY_PEM;
    let (config, _cert, _key, _ca) = create_mock_config();
    let plugin = X509AuthenticationPlugin::new(&config).expect("plugin");
    let shown = format!("{:?}", plugin);
    assert!(
        shown.contains("<redacted>"),
        "the key field is a placeholder: {}",
        shown
    );
    // Any base64 line of the key's body is enough to prove it is absent.
    let body = std::str::from_utf8(TEST_IDENTITY_KEY_PEM)
        .expect("PEM is text")
        .lines()
        .find(|line| line.len() >= 32 && !line.starts_with("-----"))
        .expect("the key has a body line");
    assert!(
        !shown.contains(&body[..32]),
        "no run of the key's base64 may print: {}",
        shown
    );
    // A `Vec<u8>` prints as decimal bytes, not base64: the same window of the
    // raw PEM bytes, in that form, must be absent too.
    let raw = TEST_IDENTITY_KEY_PEM;
    let decimal = format!("{:?}", &raw[40..56]);
    let decimal = decimal.trim_start_matches('[').trim_end_matches(']');
    assert!(
        !shown.contains(decimal),
        "no run of the key's bytes may print in decimal either: {}",
        shown
    );
}
