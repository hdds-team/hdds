// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

use super::plugin::X509AuthenticationPlugin;
use crate::core::discovery::guid::GUID;
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

/// Real X.509 certificates for testing (generated with openssl)
///
/// This is a valid certificate chain:
/// - CA: self-signed EC P-256 certificate
/// - Identity: certificate signed by the CA
///
/// Chain is valid for 10 years from 2026-02-16
#[cfg(feature = "security")]
const TEST_CA_CERT_PEM: &[u8] = b"-----BEGIN CERTIFICATE-----
MIIBmDCCAT6gAwIBAgIUObiMFsMjSoSPgyPZELIt0UqH3U8wCgYIKoZIzj0EAwIw
KjEUMBIGA1UEAwwLRERTIFRlc3QgQ0ExEjAQBgNVBAoMCUhERFMgVGVzdDAeFw0y
NjAyMTYxNzIyNTlaFw0zNjAyMTQxNzIyNTlaMCoxFDASBgNVBAMMC0REUyBUZXN0
IENBMRIwEAYDVQQKDAlIRERTIFRlc3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNC
AATO9XJZ1obuF/KC1OVM9I6c6veyZJEOpgPxmxblyEwS3OVWrZ0R4jdbTkJnE/0+
Amk5B3oZiwU3wFIh/Hr9hssvo0IwQDAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB
/wQEAwIBBjAdBgNVHQ4EFgQUJGTDziby3JlTPyDuYVFIOr9dkXAwCgYIKoZIzj0E
AwIDSAAwRQIhAO3LmqFLj5nxUyA/ySd7gppJHAWJoDCeFaRss9InOa3nAiBp71F8
9ypu2/7NYSuqvYhnwFM5LmO7BJqwXs0/VCtynA==
-----END CERTIFICATE-----
";

#[cfg(feature = "security")]
const TEST_IDENTITY_CERT_PEM: &[u8] = b"-----BEGIN CERTIFICATE-----
MIIBUzCB+wIUVtOX/1W9zPFG9xSv6P0hXZ9ID3cwCgYIKoZIzj0EAwIwKjEUMBIG
A1UEAwwLRERTIFRlc3QgQ0ExEjAQBgNVBAoMCUhERFMgVGVzdDAeFw0yNjAyMTYx
NzIzMTFaFw0zNjAyMTQxNzIzMTFaMDAxGjAYBgNVBAMMEUREUyBUZXN0IElkZW50
aXR5MRIwEAYDVQQKDAlIRERTIFRlc3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNC
AAT+LKRWNqdi7BXab4XximPpsPGCKNHI3Y7AdV1BmL8TB71TaXtxBTKzwLLOIFWr
6uL5+6+jgJn0tzSu2y4SNGuoMAoGCCqGSM49BAMCA0cAMEQCIGbPVeZh2L82ES6V
6LPj3SL8g4KwS76Qch767nvK1q6OAiBfhCEoP34wjeMD2qV+Rr2A2Yt7yGyFcrXX
HqLYfo4sLg==
-----END CERTIFICATE-----
";

#[cfg(feature = "security")]
const TEST_IDENTITY_KEY_PEM: &[u8] = b"-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg4P+WmHbV9UQ1g6V8
DWE1CB0aqNhkqAYW1bLqsMqN4TGhRANCAAT+LKRWNqdi7BXab4XximPpsPGCKNHI
3Y7AdV1BmL8TB71TaXtxBTKzwLLOIFWr6uL5+6+jgJn0tzSu2y4SNGuo
-----END PRIVATE KEY-----
";

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
fn test_x509_plugin_validate_identity() {
    let (config, _cert, _key, _ca) = create_mock_config();
    let plugin = X509AuthenticationPlugin::new(&config).expect("Plugin creation should succeed");
    let identity = plugin.validate_identity();
    assert!(identity.is_ok(), "Identity validation should succeed");
}

#[test]
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
