// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! One certificate revocation check, for every path that needs one.
//!
//! # Why this is its own module
//!
//! Two places need a CRL check: the handshake deciding whether to trust a
//! REMOTE peer, and the authentication plugin validating the LOCAL identity.
//!
//! Putting the check here rather than in either caller is deliberate. Two
//! copies of one rule are rarely symmetric: one gets fixed while the
//! identical line sits untouched in the other.
//!
//! # What a CRL has to prove before it is believed
//!
//! A revocation list is a signed statement by a CA about the certificates
//! that CA issued. Three things follow:
//!
//! 1. **It must come from the certificate's issuer.** A list from some other
//!    CA says nothing about this certificate, so it cannot prove it is not
//!    revoked. The CRL's `issuer` name is matched against the certificate's.
//! 2. **Its signature must verify against that issuer's key.** The name is a
//!    string anyone can write; the signature is not. A list that names the
//!    right issuer and fails to verify is forged or corrupt, and either way it
//!    is refused - it is never "not applicable".
//! 3. **It must be current.** See the stale-CRL rule below.
//!
//! The caller passes the ISSUER certificate it has already authenticated the
//! leaf against, so the trust anchor the CRL is verified with is the one the
//! chain was built on, not a second lookup that could disagree with the first.

/// The revocation list in force, shared by every reader of it: the handshake
/// machine, which re-reads the file into it, and the authentication plugin,
/// which judges the local identity against it. `None` when revocation is not
/// checked.
pub(crate) type ListInForce = std::sync::Arc<parking_lot::Mutex<Option<Vec<u8>>>>;

#[cfg(feature = "security")]
use crate::security::SecurityError;

/// Refuse `cert` if a current, authentic CRL from `issuer` lists its serial.
///
/// `crl_bytes` is a PEM bundle of one or more `X509 CRL` blocks, or a single
/// DER-encoded CRL. Every block is parsed; a block that does not parse fails
/// the check rather than being skipped, because a corrupt entry hiding the
/// real one is exactly how a check gets quietly disabled.
///
/// Every CRL whose issuer name matches the certificate's issuer must verify
/// against `issuer`'s public key. Among those, the newest (latest `nextUpdate`)
/// must be current. The certificate is refused if ANY authentic matching CRL
/// lists its serial: a revocation is a statement the CA made, and an older
/// list carrying it is still that statement.
///
/// If no CRL in the bundle names this issuer the check FAILS. Revocation is
/// on, so "I have no list from this CA" is "I cannot prove this certificate is
/// not revoked", and that is a refusal, not a pass.
///
/// # The stale-CRL rule
///
/// A CRL past its `nextUpdate` is refused, and so is one that carries no
/// `nextUpdate` at all. Stale revocation data cannot prove non-revocation: the
/// certificate in front of us may have been revoked after the list was issued,
/// and a list that never promises to be superseded can never be known to be
/// current. Accepting either would quietly turn "I do not know" into "it is
/// fine", which is the whole failure this function exists to prevent.
///
/// # The clock
///
/// A system clock that reads before the Unix epoch is an error, not zero.
/// With `now = 0` every CRL ever issued is current and every certificate is
/// "not yet valid"; the first version of this function silently took that
/// path, which is the kind of fail-open a broken RTC must never produce.
#[cfg(feature = "security")]
pub(crate) fn check(
    cert: &x509_parser::certificate::X509Certificate,
    issuer: &x509_parser::certificate::X509Certificate,
    crl_bytes: &[u8],
) -> Result<(), SecurityError> {
    let listing = examine(cert, issuer, crl_bytes)?;
    if let Some(reason) = listing.stale {
        return Err(SecurityError::CertificateInvalid(reason));
    }
    if let Some(reason) = listing.revoked {
        return Err(SecurityError::CertificateInvalid(reason));
    }
    Ok(())
}

/// The two answers a current revocation list can give about one certificate,
/// as `examine` reports them. Both can be absent: the certificate is not listed
/// and the list is current.
#[cfg(feature = "security")]
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Listing {
    /// Why no current list vouches for the certificate: the newest list is past
    /// its nextUpdate. Not a revocation; a caller decides what it is worth.
    pub(crate) stale: Option<String>,
    /// Why the certificate is revoked: a list authentic from its issuer, and
    /// current, lists its serial.
    pub(crate) revoked: Option<String>,
}

/// What the revocation lists say about `cert`, issued by `issuer`, with the
/// same refusals as `check` except the two answers, which are reported rather
/// than refused. An `Err` is still a refusal to judge at all: no authentic list
/// from the issuer, a list not signed by the issuer's key, or no nextUpdate.
#[cfg(feature = "security")]
pub(crate) fn examine(
    cert: &x509_parser::certificate::X509Certificate,
    issuer: &x509_parser::certificate::X509Certificate,
    crl_bytes: &[u8],
) -> Result<Listing, SecurityError> {
    use x509_parser::prelude::FromDer;
    use x509_parser::revocation_list::CertificateRevocationList;

    if cert.issuer() != issuer.subject() {
        return Err(SecurityError::CertificateInvalid(format!(
            "revocation check asked with the wrong issuer: certificate issued by [{}], \
             CA given is [{}]",
            cert.issuer(),
            issuer.subject()
        )));
    }

    let now = unix_now_seconds()?;

    let ders = crl_ders(crl_bytes)?;

    let mut matching = 0usize;
    let mut newest_next_update: Option<i64> = None;
    let mut revoked_by: Option<String> = None;
    let serial = cert.tbs_certificate.raw_serial();

    for (index, der) in ders.iter().enumerate() {
        let (_, crl) = CertificateRevocationList::from_der(der).map_err(|e| {
            SecurityError::CertificateInvalid(format!(
                "failed to parse CRL #{} in the revocation list: {:?}",
                index + 1,
                e
            ))
        })?;

        if crl.issuer() != cert.issuer() {
            continue;
        }
        matching += 1;

        // The name matched; only the signature can tell this list from one an
        // attacker wrote with the same name in it.
        crl.verify_signature(issuer.public_key()).map_err(|e| {
            SecurityError::CertificateInvalid(format!(
                "CRL #{} names issuer [{}] but its signature does not verify against that \
                 CA's key ({:?}): forged or corrupt, refused",
                index + 1,
                crl.issuer(),
                e
            ))
        })?;

        match crl.next_update() {
            Some(next) => {
                let next = next.timestamp();
                if newest_next_update.is_none_or(|n| next > n) {
                    newest_next_update = Some(next);
                }
            }
            None => {
                return Err(SecurityError::CertificateInvalid(format!(
                    "CRL #{} carries no nextUpdate, so it can never be known to be current",
                    index + 1
                )));
            }
        }

        if revoked_by.is_none()
            && crl
                .iter_revoked_certificates()
                .any(|revoked| revoked.raw_serial() == serial)
        {
            revoked_by = Some(format!("CRL #{}", index + 1));
        }
    }

    if matching == 0 {
        return Err(SecurityError::CertificateInvalid(format!(
            "no CRL in the revocation list was issued by [{}], the issuer of this certificate; \
             a list that says nothing about that CA cannot prove the certificate is not revoked",
            cert.issuer()
        )));
    }

    let stale = newest_next_update.filter(|next| *next < now).map(|next| {
        format!(
            "the newest CRL from [{}] expired at {}; stale revocation data cannot prove \
                 this certificate is not revoked",
            cert.issuer(),
            x509_parser::time::ASN1Time::from_timestamp(next)
                .map(|t| t.to_string())
                .unwrap_or_else(|_| next.to_string())
        )
    });
    let revoked = revoked_by.map(|which| {
        format!(
            "certificate is REVOKED (serial {}, listed in {})",
            cert.tbs_certificate.raw_serial_as_string(),
            which
        )
    });
    Ok(Listing { stale, revoked })
}

/// A `pub(crate)` trait for where the revocation list is read from, so that the
/// machine can re-read it on a periodic pass and tests can move its clock and
/// its content.
#[cfg(feature = "security")]
pub(crate) trait RevocationFile: Send + Sync {
    /// The modification time of the file's current content.
    fn modified(&self) -> std::io::Result<std::time::SystemTime>;
    /// The file's content.
    fn read(&self) -> std::io::Result<Vec<u8>>;
}

/// A revocation list held in a file on disk.
#[cfg(feature = "security")]
pub(crate) struct FileRevocation(pub(crate) std::path::PathBuf);

#[cfg(feature = "security")]
impl RevocationFile for FileRevocation {
    fn modified(&self) -> std::io::Result<std::time::SystemTime> {
        std::fs::metadata(&self.0)?.modified()
    }

    fn read(&self) -> std::io::Result<Vec<u8>> {
        std::fs::read(&self.0)
    }
}

/// Whether `crl_bytes` may replace the revocation list in force: every
/// `X509 CRL` block in it parses, and carries the signature of the CA in
/// `issuers_pem` whose name is the block's issuer.
///
/// Currency is not judged here. A list past its nextUpdate is accepted, and
/// `examine` reports it as stale, which refuses new handshakes on it while
/// leaving the sessions already standing as they are.
#[cfg(feature = "security")]
pub(crate) fn accept_list(crl_bytes: &[u8], issuers_pem: &[u8]) -> Result<(), SecurityError> {
    use x509_parser::prelude::FromDer;
    use x509_parser::revocation_list::CertificateRevocationList;

    let blocks = ::pem::parse_many(issuers_pem).map_err(|e| {
        SecurityError::CertificateInvalid(format!("failed to parse CA certs: {}", e))
    })?;
    let issuers: Vec<x509_parser::certificate::X509Certificate> = blocks
        .iter()
        .filter_map(|block| {
            x509_parser::certificate::X509Certificate::from_der(block.contents())
                .ok()
                .map(|(_, ca)| ca)
        })
        .collect();

    let ders = crl_ders(crl_bytes)?;
    for (index, der) in ders.iter().enumerate() {
        let (_, crl) = CertificateRevocationList::from_der(der).map_err(|e| {
            SecurityError::CertificateInvalid(format!(
                "failed to parse CRL #{} in the revocation list: {:?}",
                index + 1,
                e
            ))
        })?;
        let Some(ca) = issuers.iter().find(|ca| ca.subject() == crl.issuer()) else {
            return Err(SecurityError::CertificateInvalid(format!(
                "CRL #{} is issued by [{}], which is not a CA in the trust store",
                index + 1,
                crl.issuer()
            )));
        };
        crl.verify_signature(ca.public_key()).map_err(|e| {
            SecurityError::CertificateInvalid(format!(
                "CRL #{} names issuer [{}] but its signature does not verify against that \
                 CA's key ({:?}): forged or corrupt, refused",
                index + 1,
                crl.issuer(),
                e
            ))
        })?;
    }
    Ok(())
}

/// The current time in the unit ASN.1 validity fields are compared in, shared
/// by the certificate validity windows and the CRL currency check.
///
/// A clock before the Unix epoch or beyond `i64` is an ERROR, not zero: with
/// `now = 0` every certificate ever issued is "not yet valid" and every CRL is
/// current, which is a verdict about the clock dressed up as one about the
/// certificate. A broken RTC must be named, not judged around.
#[cfg(feature = "security")]
pub(crate) fn unix_now_seconds() -> Result<i64, SecurityError> {
    let since_epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| {
            SecurityError::CertificateInvalid(format!(
                "system clock is before the Unix epoch ({}); certificate validity cannot be \
                 judged without a trustworthy time",
                e
            ))
        })?;
    i64::try_from(since_epoch.as_secs()).map_err(|_| {
        SecurityError::CertificateInvalid(
            "system clock is beyond the range of an ASN.1 time; certificate validity cannot \
             be judged"
                .to_string(),
        )
    })
}

/// The DER bodies of every CRL in `bytes`: all `X509 CRL` PEM blocks, or the
/// bytes themselves when they are not PEM at all.
///
/// A PEM input that holds blocks of OTHER kinds only (a CA bundle handed in by
/// mistake, say) is refused by name rather than falling through to the DER
/// path, where it would fail to parse with a message about ASN.1 that tells
/// the operator nothing about what they did.
#[cfg(feature = "security")]
fn crl_ders(bytes: &[u8]) -> Result<Vec<Vec<u8>>, SecurityError> {
    // A parse error here means "not PEM", which is the DER path below.
    let blocks = ::pem::parse_many(bytes).unwrap_or_default();
    if blocks.is_empty() {
        return Ok(vec![bytes.to_vec()]);
    }
    let crls: Vec<Vec<u8>> = blocks
        .iter()
        .filter(|b| b.tag() == "X509 CRL")
        .map(|b| b.contents().to_vec())
        .collect();
    if crls.is_empty() {
        let tags: Vec<&str> = blocks.iter().map(|b| b.tag()).collect();
        return Err(SecurityError::CertificateInvalid(format!(
            "the revocation list holds no `X509 CRL` PEM block (found: {}); this is not a CRL",
            tags.join(", ")
        )));
    }
    Ok(crls)
}

#[cfg(all(test, feature = "security"))]
mod tests {
    use super::{accept_list, check, examine, Listing};
    use crate::security::test_pki::{
        REVOCATION_CA_PEM, REVOCATION_CRL_PEM, REVOCATION_EMPTY_CRL_PEM,
        REVOCATION_EXPIRED_CRL_PEM, REVOCATION_FORGED_CRL_PEM, REVOCATION_GOOD_IDENTITY_PEM,
        REVOCATION_OTHER_ISSUER_CRL_PEM, REVOCATION_REVOKED_IDENTITY_PEM,
    };
    use x509_parser::certificate::X509Certificate;
    use x509_parser::prelude::FromDer;

    fn der(pem: &[u8]) -> Vec<u8> {
        ::pem::parse(pem)
            .expect("fixture is PEM")
            .contents()
            .to_vec()
    }

    fn cert(der: &[u8]) -> X509Certificate<'_> {
        X509Certificate::from_der(der).expect("fixture is X.509").1
    }

    fn message(result: Result<(), crate::security::SecurityError>) -> String {
        format!("{}", result.expect_err("must be refused"))
    }

    /// The forged list names the right issuer and lists nobody. A serial-only
    /// check accepts it; this one must see the wrong signature.
    #[test]
    fn a_crl_signed_by_an_impostor_with_the_right_name_is_refused() {
        let (ca, leaf) = (der(REVOCATION_CA_PEM), der(REVOCATION_REVOKED_IDENTITY_PEM));
        let text = message(check(&cert(&leaf), &cert(&ca), REVOCATION_FORGED_CRL_PEM));
        assert!(text.contains("signature does not verify"), "got: {}", text);
        assert!(text.contains("forged or corrupt"), "got: {}", text);
    }

    /// An honest list from a different CA says nothing about this issuer's
    /// certificates, so it cannot clear one of them.
    #[test]
    fn a_crl_from_another_issuer_proves_nothing_and_is_refused() {
        let (ca, leaf) = (der(REVOCATION_CA_PEM), der(REVOCATION_GOOD_IDENTITY_PEM));
        let text = message(check(
            &cert(&leaf),
            &cert(&ca),
            REVOCATION_OTHER_ISSUER_CRL_PEM,
        ));
        assert!(
            text.contains("no CRL in the revocation list was issued by"),
            "got: {}",
            text
        );
    }

    /// A bundle: the other issuer's list first, then the real one. The real
    /// one must be found behind the first block, and it must still decide.
    #[test]
    fn a_bundle_is_searched_past_its_first_block() {
        let (ca, revoked, good) = (
            der(REVOCATION_CA_PEM),
            der(REVOCATION_REVOKED_IDENTITY_PEM),
            der(REVOCATION_GOOD_IDENTITY_PEM),
        );
        let mut bundle = REVOCATION_OTHER_ISSUER_CRL_PEM.to_vec();
        bundle.extend_from_slice(REVOCATION_CRL_PEM);

        let text = message(check(&cert(&revoked), &cert(&ca), &bundle));
        assert!(text.contains("REVOKED"), "got: {}", text);
        assert!(
            text.contains("CRL #2"),
            "the second block must be the one cited: {}",
            text
        );

        check(&cert(&good), &cert(&ca), &bundle).expect("serial 02 is in no list");
    }

    /// Two authentic lists from the same issuer: the empty one and the one
    /// that revokes serial 01. The revocation stands whichever comes first.
    #[test]
    fn a_revocation_in_any_authentic_list_stands() {
        let (ca, revoked) = (der(REVOCATION_CA_PEM), der(REVOCATION_REVOKED_IDENTITY_PEM));
        let mut bundle = REVOCATION_EMPTY_CRL_PEM.to_vec();
        bundle.extend_from_slice(REVOCATION_CRL_PEM);
        let text = message(check(&cert(&revoked), &cert(&ca), &bundle));
        assert!(text.contains("REVOKED"), "got: {}", text);
    }

    /// A CA bundle handed in as the CRL is named for what it is, not reported
    /// as an ASN.1 parse failure.
    #[test]
    fn a_pem_file_with_no_crl_block_is_refused_by_name() {
        let (ca, leaf) = (der(REVOCATION_CA_PEM), der(REVOCATION_GOOD_IDENTITY_PEM));
        let text = message(check(&cert(&leaf), &cert(&ca), REVOCATION_CA_PEM));
        assert!(
            text.contains("holds no `X509 CRL` PEM block"),
            "got: {}",
            text
        );
        assert!(
            text.contains("CERTIFICATE"),
            "the tags found must be named: {}",
            text
        );
    }

    /// A DER CRL, not PEM, takes the single-DER path.
    #[test]
    fn a_der_crl_is_accepted_as_is() {
        let (ca, revoked) = (der(REVOCATION_CA_PEM), der(REVOCATION_REVOKED_IDENTITY_PEM));
        let crl_der = der(REVOCATION_CRL_PEM);
        let text = message(check(&cert(&revoked), &cert(&ca), &crl_der));
        assert!(text.contains("REVOKED"), "got: {}", text);
    }

    /// Asking with the wrong CA is a caller bug and is refused, never silently
    /// re-resolved.
    #[test]
    fn the_wrong_issuer_certificate_is_refused_up_front() {
        let (other_ca, leaf) = (
            der(crate::security::test_pki::TEST_CA_CERT_PEM),
            der(REVOCATION_GOOD_IDENTITY_PEM),
        );
        let text = message(check(&cert(&leaf), &cert(&other_ca), REVOCATION_CRL_PEM));
        assert!(text.contains("wrong issuer"), "got: {}", text);
    }

    /// A listed certificate is revoked, and the list is current: the two answers
    /// come back separately, and `check` refuses on the first.
    #[test]
    fn examine_reports_a_listed_certificate_as_revoked_on_a_current_list() {
        let answer = examine(
            &cert(&der(REVOCATION_REVOKED_IDENTITY_PEM)),
            &cert(&der(REVOCATION_CA_PEM)),
            REVOCATION_CRL_PEM,
        )
        .expect("the list is authentic and names the certificate");
        assert!(answer.revoked.is_some(), "listed: {:?}", answer);
        assert_eq!(answer.stale, None, "the list is current");
    }

    /// A stale list is reported as stale, not as a revocation: it cannot prove the
    /// certificate is fine, and it does not prove the certificate is revoked.
    #[test]
    fn examine_reports_a_stale_list_as_stale_and_not_as_a_revocation() {
        let answer = examine(
            &cert(&der(REVOCATION_GOOD_IDENTITY_PEM)),
            &cert(&der(REVOCATION_CA_PEM)),
            REVOCATION_EXPIRED_CRL_PEM,
        )
        .expect("the list is authentic, merely out of date");
        assert!(answer.stale.is_some(), "past its nextUpdate: {:?}", answer);
        assert_eq!(answer.revoked, None, "a stale list revokes nobody");
    }

    /// A current list that names nobody from the certificate's issuer gives no answer.
    #[test]
    fn examine_of_an_unlisted_certificate_on_a_current_list_has_no_answer() {
        let answer = examine(
            &cert(&der(REVOCATION_GOOD_IDENTITY_PEM)),
            &cert(&der(REVOCATION_CA_PEM)),
            REVOCATION_EMPTY_CRL_PEM,
        )
        .expect("the empty list is authentic");
        assert_eq!(answer, Listing::default());
    }

    #[test]
    fn accept_list_takes_a_current_list_from_a_trusted_ca() {
        accept_list(REVOCATION_CRL_PEM, REVOCATION_CA_PEM).expect("authentic, from the CA");
    }

    /// Currency is not a condition of accepting a list: a stale one replaces the
    /// list in force, and refuses only the handshakes that need a current list.
    #[test]
    fn accept_list_takes_a_stale_but_authentic_list() {
        accept_list(REVOCATION_EXPIRED_CRL_PEM, REVOCATION_CA_PEM)
            .expect("the signature verifies; currency is judged by examine");
    }

    #[test]
    fn accept_list_refuses_a_forged_list() {
        let text = message(accept_list(REVOCATION_FORGED_CRL_PEM, REVOCATION_CA_PEM));
        assert!(text.contains("forged"), "got: {}", text);
    }

    #[test]
    fn accept_list_refuses_a_list_from_an_issuer_outside_the_bundle() {
        let text = message(accept_list(
            REVOCATION_OTHER_ISSUER_CRL_PEM,
            REVOCATION_CA_PEM,
        ));
        assert!(
            text.contains("not a CA in the trust store"),
            "got: {}",
            text
        );
    }

    #[test]
    fn accept_list_refuses_bytes_that_are_not_a_crl() {
        let text = message(accept_list(
            b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n",
            REVOCATION_CA_PEM,
        ));
        assert!(text.contains("no `X509 CRL`"), "got: {}", text);
    }
}
