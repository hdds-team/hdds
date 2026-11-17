// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! In-process test PKI for the TCP-TLS proofs.
//!
//! Generated with rcgen at test start (no files, no network, no expiry rot):
//!
//! - `ca_a` signs `server_a` (SAN `localhost` + `127.0.0.1`) and `client_a`
//! - `ca_b` signs `client_b`
//! - `crl_a_empty`, `crl_a_revoking_client_a` and `crl_a_expired` are issued by `ca_a`
//!
//! Single source for every TLS/mTLS test in this crate: add material here, never
//! copy PEM blobs into a test file.

use std::sync::OnceLock;

use rcgen::{
    date_time_ymd, BasicConstraints, Certificate, CertificateParams,
    CertificateRevocationListParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyIdMethod, KeyPair, KeyUsagePurpose, RevocationReason, RevokedCertParams, SerialNumber,
};

/// Serial number of `client_a`, listed in `crl_a_revoking_client_a`.
pub(crate) const CLIENT_A_SERIAL: u64 = 0x1001;
/// Serial number of `client_b`.
pub(crate) const CLIENT_B_SERIAL: u64 = 0x2001;

/// PEM material for the two-CA test PKI.
#[derive(Debug, Clone)]
pub(crate) struct TestPki {
    pub ca_a_cert: Vec<u8>,
    pub server_a_cert: Vec<u8>,
    pub server_a_key: Vec<u8>,
    pub client_a_cert: Vec<u8>,
    pub client_a_key: Vec<u8>,
    pub ca_b_cert: Vec<u8>,
    pub client_b_cert: Vec<u8>,
    pub client_b_key: Vec<u8>,
    /// CRL from CA-A with no revoked certificate (revocation checking active).
    pub crl_a_empty: Vec<u8>,
    /// CRL from CA-A revoking `client_a`.
    pub crl_a_revoking_client_a: Vec<u8>,
    /// CRL from CA-A whose `nextUpdate` is in the past (stale).
    pub crl_a_expired: Vec<u8>,
}

struct Issuer {
    cert: Certificate,
    key: KeyPair,
}

fn dn(common_name: &str) -> DistinguishedName {
    let mut dn = DistinguishedName::new();
    dn.push(DnType::OrganizationName, "HDDS test PKI");
    dn.push(DnType::CommonName, common_name);
    dn
}

fn make_ca(common_name: &str, serial: u64) -> Issuer {
    let key = KeyPair::generate().expect("rcgen key generation");
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("ca params");
    params.distinguished_name = dn(common_name);
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::CrlSign,
    ];
    params.serial_number = Some(SerialNumber::from(serial));
    let cert = params.self_signed(&key).expect("self-signed CA");
    Issuer { cert, key }
}

fn make_leaf(
    common_name: &str,
    sans: &[&str],
    eku: ExtendedKeyUsagePurpose,
    serial: u64,
    issuer: &Issuer,
) -> (Certificate, KeyPair) {
    let key = KeyPair::generate().expect("rcgen key generation");
    let sans: Vec<String> = sans.iter().map(|s| (*s).to_string()).collect();
    let mut params = CertificateParams::new(sans).expect("leaf params");
    params.distinguished_name = dn(common_name);
    params.is_ca = IsCa::ExplicitNoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![eku];
    params.serial_number = Some(SerialNumber::from(serial));
    params.use_authority_key_identifier_extension = true;
    let cert = params
        .signed_by(&key, &issuer.cert, &issuer.key)
        .expect("leaf signed by CA");
    (cert, key)
}

fn make_crl(
    issuer: &Issuer,
    revoked: Vec<RevokedCertParams>,
    this_update: (i32, u8, u8),
    next_update: (i32, u8, u8),
    number: u64,
) -> Vec<u8> {
    CertificateRevocationListParams {
        this_update: date_time_ymd(this_update.0, this_update.1, this_update.2),
        next_update: date_time_ymd(next_update.0, next_update.1, next_update.2),
        crl_number: SerialNumber::from(number),
        issuing_distribution_point: None,
        revoked_certs: revoked,
        key_identifier_method: KeyIdMethod::Sha256,
    }
    .signed_by(&issuer.cert, &issuer.key)
    .expect("CRL signed by CA")
    .pem()
    .expect("CRL PEM")
    .into_bytes()
}

impl TestPki {
    /// Generate a fresh PKI.
    pub(crate) fn generate() -> Self {
        let ca_a = make_ca("HDDS Test CA A", 0xA);
        let ca_b = make_ca("HDDS Test CA B", 0xB);

        let (server_a, server_a_key) = make_leaf(
            "server-a",
            &["localhost", "127.0.0.1"],
            ExtendedKeyUsagePurpose::ServerAuth,
            0x0101,
            &ca_a,
        );
        let (client_a, client_a_key) = make_leaf(
            "client-a",
            &[],
            ExtendedKeyUsagePurpose::ClientAuth,
            CLIENT_A_SERIAL,
            &ca_a,
        );
        let (client_b, client_b_key) = make_leaf(
            "client-b",
            &[],
            ExtendedKeyUsagePurpose::ClientAuth,
            CLIENT_B_SERIAL,
            &ca_b,
        );

        let revoked_client_a = RevokedCertParams {
            serial_number: SerialNumber::from(CLIENT_A_SERIAL),
            revocation_time: date_time_ymd(2024, 1, 2),
            reason_code: Some(RevocationReason::KeyCompromise),
            invalidity_date: None,
        };

        Self {
            ca_a_cert: ca_a.cert.pem().into_bytes(),
            server_a_cert: server_a.pem().into_bytes(),
            server_a_key: server_a_key.serialize_pem().into_bytes(),
            client_a_cert: client_a.pem().into_bytes(),
            client_a_key: client_a_key.serialize_pem().into_bytes(),
            ca_b_cert: ca_b.cert.pem().into_bytes(),
            client_b_cert: client_b.pem().into_bytes(),
            client_b_key: client_b_key.serialize_pem().into_bytes(),
            crl_a_empty: make_crl(&ca_a, Vec::new(), (2024, 1, 1), (2099, 1, 1), 1),
            crl_a_revoking_client_a: make_crl(
                &ca_a,
                vec![revoked_client_a],
                (2024, 1, 1),
                (2099, 1, 1),
                2,
            ),
            crl_a_expired: make_crl(&ca_a, Vec::new(), (2020, 1, 1), (2021, 1, 1), 3),
        }
    }

    /// Process-wide PKI shared by every test (generated once).
    pub(crate) fn shared() -> &'static TestPki {
        static PKI: OnceLock<TestPki> = OnceLock::new();
        PKI.get_or_init(TestPki::generate)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, UnixTime};
    use rustls::RootCertStore;
    use std::sync::Arc;

    fn root_store(ca_pem: &[u8]) -> RootCertStore {
        let mut store = RootCertStore::empty();
        for cert in CertificateDer::pem_slice_iter(ca_pem) {
            store.add(cert.expect("CA PEM parses")).expect("CA added");
        }
        store
    }

    fn verify_client(ca_pem: &[u8], leaf_pem: &[u8]) -> Result<(), rustls::Error> {
        use rustls::server::WebPkiClientVerifier;

        let verifier = WebPkiClientVerifier::builder_with_provider(
            Arc::new(root_store(ca_pem)),
            Arc::new(rustls::crypto::ring::default_provider()),
        )
        .build()
        .expect("verifier builds");
        let leaf = CertificateDer::from_pem_slice(leaf_pem).expect("leaf PEM parses");
        verifier
            .verify_client_cert(&leaf, &[], UnixTime::now())
            .map(|_| ())
    }

    #[test]
    fn generated_chain_verifies_against_own_ca_only() {
        let pki = TestPki::shared();
        assert!(verify_client(&pki.ca_a_cert, &pki.client_a_cert).is_ok());
        assert!(verify_client(&pki.ca_b_cert, &pki.client_b_cert).is_ok());
        assert!(verify_client(&pki.ca_a_cert, &pki.client_b_cert).is_err());
        assert!(verify_client(&pki.ca_b_cert, &pki.client_a_cert).is_err());
        // Keys parse as PKCS#8.
        assert!(PrivateKeyDer::from_pem_slice(&pki.client_a_key).is_ok());
        assert!(PrivateKeyDer::from_pem_slice(&pki.server_a_key).is_ok());
    }

    #[test]
    fn server_cert_carries_loopback_ip_san() {
        use rustls::client::danger::ServerCertVerifier;
        use rustls::client::WebPkiServerVerifier;
        use rustls::pki_types::ServerName;

        let pki = TestPki::shared();
        let verifier = WebPkiServerVerifier::builder_with_provider(
            Arc::new(root_store(&pki.ca_a_cert)),
            Arc::new(rustls::crypto::ring::default_provider()),
        )
        .build()
        .expect("server verifier builds");
        let leaf = CertificateDer::from_pem_slice(&pki.server_a_cert).expect("server PEM");
        for name in ["127.0.0.1", "localhost"] {
            let server_name = ServerName::try_from(name.to_string()).expect("server name");
            verifier
                .verify_server_cert(&leaf, &[], &server_name, &[], UnixTime::now())
                .unwrap_or_else(|e| panic!("server cert must be valid for {name}: {e}"));
        }
        let wrong = ServerName::try_from("example.invalid".to_string()).expect("server name");
        assert!(verifier
            .verify_server_cert(&leaf, &[], &wrong, &[], UnixTime::now())
            .is_err());
    }

    #[test]
    fn crls_parse_and_name_client_a_only() {
        use rustls::pki_types::CertificateRevocationListDer;

        let pki = TestPki::shared();
        for crl in [
            &pki.crl_a_empty,
            &pki.crl_a_revoking_client_a,
            &pki.crl_a_expired,
        ] {
            let parsed: Vec<_> = CertificateRevocationListDer::pem_slice_iter(crl)
                .collect::<Result<_, _>>()
                .expect("CRL PEM parses");
            assert_eq!(parsed.len(), 1);
        }
        assert_ne!(pki.crl_a_empty, pki.crl_a_revoking_client_a);
    }
}
