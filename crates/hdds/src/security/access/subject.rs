// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Grant selection for DDS-Security v1.1 9.4.3.
//!
//! `validate_local_permissions` "shall check the subject name in the Identity
//! Certificate matches the one from the Signed Permissions document", and a
//! grant is only in force inside its own `<validity>` window. A permissions
//! document that verifies perfectly but was issued to somebody else, or that
//! expired in 2021, must not grant anything -- otherwise one valid document
//! leaked from any participant in the domain is a universal key.
//!
//! Two small parsers live here because the crate has neither: an RFC 4514
//! distinguished-name comparison and an `xs:dateTime` reader. Neither pulls a
//! dependency.

use crate::security::SecurityError;

/// A distinguished name broken into normalised attribute/value pairs.
///
/// Comparison is order-insensitive and whitespace-insensitive on purpose:
/// `x509_parser` prints `CN=..., O=...` while an OpenSSL-produced permissions
/// file commonly writes `emailAddress=..., CN=..., OU=..., O=..., ST=..., C=...`,
/// and both name the same subject. Attribute TYPES compare case-insensitively
/// (RFC 4514 4); VALUES compare case-sensitively, which is the stricter of the
/// two readings and the one that cannot widen what a document grants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DistinguishedName {
    attributes: Vec<(String, String)>,
}

impl DistinguishedName {
    /// Parse an RFC 4514 string form.
    ///
    /// Handles both RFC 4514 escape forms -- `\\,` for a special character and
    /// `\\2C` for a hex pair -- so that two spellings of the same name compare
    /// equal and, more importantly, two DIFFERENT names never collapse onto one
    /// another. An empty or attribute-less string, or an escape sequence whose
    /// bytes are not UTF-8, yields `None`.
    pub fn parse(text: &str) -> Option<Self> {
        let mut attributes = Vec::new();
        for rdn in split_unescaped(text, ',') {
            for attribute in split_unescaped(&rdn, '+') {
                let (key, value) = attribute.split_once('=')?;
                let key = normalise_attribute_type(key.trim());
                // RFC 4514 2.4 also allows `#` followed by the BER encoding of
                // the value. Comparing that spelling as a literal string would
                // silently fail to match the same name written normally, so it
                // is refused outright: an error naming an unreadable subject is
                // recoverable, a subject that quietly matches nothing is not.
                if value.trim_start().starts_with('#') {
                    return None;
                }
                let value = collapse_whitespace(&unescape(value)?);
                if key.is_empty() || value.is_empty() {
                    return None;
                }
                attributes.push((key, value));
            }
        }
        if attributes.is_empty() {
            return None;
        }
        attributes.sort();
        Some(Self { attributes })
    }

    /// The name a certificate carries, read from its DER RDN sequence: each
    /// attribute's type OID and decoded value, as the issuer encoded them
    /// (DDS Security v1.1 Sec.9.4.1.3, the subject name of the identity
    /// certificate).
    ///
    /// Never from a printed form of the name. A printer that does not escape
    /// (x509-parser's does not) turns a common name `bob, O=Admin` into the
    /// text `CN=bob, O=Admin`, which re-parses as TWO attributes: the name
    /// of another subject, whose grants it would then select. An attribute
    /// whose value is not a string, or an empty name, yields `None`.
    pub fn from_x509_name(name: &x509_parser::x509::X509Name<'_>) -> Option<Self> {
        let mut attributes = Vec::new();
        for rdn in name.iter_rdn() {
            for attribute in rdn.iter() {
                let key = normalise_attribute_type(&attribute.attr_type().to_id_string());
                let value = collapse_whitespace(attribute.as_str().ok()?);
                if value.is_empty() {
                    return None;
                }
                attributes.push((key, value));
            }
        }
        if attributes.is_empty() {
            return None;
        }
        attributes.sort();
        Some(Self { attributes })
    }

    /// True when both names carry exactly the same attribute set.
    pub fn matches(&self, other: &Self) -> bool {
        self.attributes == other.attributes
    }
}

impl std::fmt::Display for DistinguishedName {
    /// The normalised attributes, RFC 4514 style with `,` `+` `=` `\\`
    /// escaped: for messages, never for comparison.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (i, (key, value)) in self.attributes.iter().enumerate() {
            if i > 0 {
                f.write_str(",")?;
            }
            write!(f, "{}=", key)?;
            for ch in value.chars() {
                if matches!(ch, ',' | '+' | '=' | '\\' | '"' | '<' | '>' | ';') {
                    f.write_str("\\")?;
                }
                write!(f, "{}", ch)?;
            }
        }
        Ok(())
    }
}

/// The subject name of the certificate `cert_bytes` (PEM, or raw DER), read
/// from its DER RDN sequence (`DistinguishedName::from_x509_name`).
///
/// # Errors
///
/// `SecurityError::CertificateInvalid` when the bytes are no certificate or
/// its subject is not a name of string attributes.
pub(crate) fn certificate_subject(cert_bytes: &[u8]) -> Result<DistinguishedName, SecurityError> {
    use x509_parser::pem::parse_x509_pem;

    let der_owned;
    let der: &[u8] = match parse_x509_pem(cert_bytes) {
        Ok((_, pem)) => {
            der_owned = pem.contents;
            &der_owned
        }
        Err(_) => cert_bytes,
    };
    let (_, cert) = x509_parser::parse_x509_certificate(der).map_err(|err| {
        SecurityError::CertificateInvalid(format!(
            "identity certificate does not parse as PEM or DER: {:?}",
            err
        ))
    })?;
    DistinguishedName::from_x509_name(cert.subject()).ok_or_else(|| {
        SecurityError::CertificateInvalid(format!(
            "identity certificate subject '{}' carries an attribute that is not a string",
            cert.subject()
        ))
    })
}

/// Map the aliases a distinguished name may use to one spelling.
fn normalise_attribute_type(key: &str) -> String {
    let lowered = key.trim().to_ascii_lowercase();
    match lowered.as_str() {
        // OpenSSL writes emailAddress, x509-parser writes emailAddress too, but
        // "E" and the OID form both turn up in vendor documents.
        "e" | "email" | "emailaddress" | "1.2.840.113549.1.9.1" => "emailaddress".to_string(),
        "cn" | "commonname" | "2.5.4.3" => "cn".to_string(),
        "o" | "organizationname" | "2.5.4.10" => "o".to_string(),
        "ou" | "organizationalunitname" | "2.5.4.11" => "ou".to_string(),
        "l" | "localityname" | "2.5.4.7" => "l".to_string(),
        "st" | "stateorprovincename" | "2.5.4.8" => "st".to_string(),
        "c" | "countryname" | "2.5.4.6" => "c".to_string(),
        "street" | "streetaddress" | "2.5.4.9" => "street".to_string(),
        "serialnumber" | "2.5.4.5" => "serialnumber".to_string(),
        "sn" | "surname" | "2.5.4.4" => "sn".to_string(),
        "title" | "2.5.4.12" => "title".to_string(),
        "givenname" | "2.5.4.42" => "givenname".to_string(),
        "initials" | "2.5.4.43" => "initials".to_string(),
        "generationqualifier" | "2.5.4.44" => "generationqualifier".to_string(),
        "dnqualifier" | "2.5.4.46" => "dnqualifier".to_string(),
        "pseudonym" | "2.5.4.65" => "pseudonym".to_string(),
        "postalcode" | "2.5.4.17" => "postalcode".to_string(),
        "dc" | "domaincomponent" | "0.9.2342.19200300.100.1.25" => "dc".to_string(),
        "uid" | "userid" | "0.9.2342.19200300.100.1.1" => "uid".to_string(),
        other => other.to_string(),
    }
}

/// Split on `separator`, honouring RFC 4514 backslash escapes.
fn split_unescaped(text: &str, separator: char) -> Vec<String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut escaped = false;
    for ch in text.chars() {
        if escaped {
            current.push('\\');
            current.push(ch);
            escaped = false;
        } else if ch == '\\' {
            escaped = true;
        } else if ch == separator {
            parts.push(std::mem::take(&mut current));
        } else {
            current.push(ch);
        }
    }
    if escaped {
        current.push('\\');
    }
    parts.push(current);
    parts
}

/// Undo RFC 4514 escaping.
///
/// Two forms exist and both must be decoded: `\\` followed by one special
/// character, and `\\` followed by a HEX PAIR naming one byte. Dropping the
/// backslash of the hex form and keeping its digits -- which is what a naive
/// reader does -- makes `CN=A\\2CB` (one attribute whose value is `A,B`) compare
/// equal to `CN=A2CB`, so two different subjects would share one grant. Returns
/// `None` when the decoded bytes are not UTF-8.
fn unescape(text: &str) -> Option<String> {
    let mut out: Vec<u8> = Vec::with_capacity(text.len());
    let bytes = text.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] != b'\\' {
            out.push(bytes[i]);
            i += 1;
            continue;
        }
        // A trailing backslash escapes nothing; drop it, as the RFC leaves the
        // sequence undefined and there is nothing to widen a comparison with.
        if i + 1 >= bytes.len() {
            break;
        }
        match (
            hex_value(bytes[i + 1]),
            bytes.get(i + 2).copied().and_then(hex_value),
        ) {
            (Some(high), Some(low)) => {
                out.push(high * 16 + low);
                i += 3;
            }
            _ => {
                out.push(bytes[i + 1]);
                i += 2;
            }
        }
    }
    String::from_utf8(out).ok()
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn collapse_whitespace(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Parse an `xs:dateTime` into seconds since the Unix epoch.
///
/// Accepts `YYYY-MM-DDThh:mm:ss` with an optional fractional part and an
/// optional `Z` or `+hh:mm` / `-hh:mm` offset. A value with no offset is read
/// as UTC, which is how every DDS-Security permissions file on disk is written.
pub fn parse_xs_datetime(text: &str) -> Option<i64> {
    let text = text.trim();
    // Every byte position below is an index into the string, so a multi-byte
    // character anywhere in the value would slice through a character and
    // PANIC. An xs:dateTime is ASCII by definition; anything else is simply
    // unreadable, which is the answer this function already gives.
    if !text.is_ascii() {
        return None;
    }
    let bytes = text.as_bytes();
    if bytes.len() < 19 || bytes[4] != b'-' || bytes[7] != b'-' {
        return None;
    }
    if bytes[10] != b'T' && bytes[10] != b't' && bytes[10] != b' ' {
        return None;
    }
    if bytes[13] != b':' || bytes[16] != b':' {
        return None;
    }
    let year: i64 = text[0..4].parse().ok()?;
    let month: u32 = text[5..7].parse().ok()?;
    let day: u32 = text[8..10].parse().ok()?;
    let hour: i64 = text[11..13].parse().ok()?;
    let minute: i64 = text[14..16].parse().ok()?;
    let second: i64 = text[17..19].parse().ok()?;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    if hour > 23 || minute > 59 || second > 60 {
        return None;
    }

    let mut rest = &text[19..];
    if let Some(stripped) = rest.strip_prefix('.') {
        let digits = stripped
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(stripped.len());
        if digits == 0 {
            return None;
        }
        rest = &stripped[digits..];
    }

    let offset_seconds = match rest {
        "" | "Z" | "z" => 0,
        _ => {
            let sign = match rest.as_bytes()[0] {
                b'+' => 1,
                b'-' => -1,
                _ => return None,
            };
            if rest.len() != 6 || rest.as_bytes()[3] != b':' {
                return None;
            }
            let offset_hours: i64 = rest[1..3].parse().ok()?;
            let offset_minutes: i64 = rest[4..6].parse().ok()?;
            if offset_hours > 23 || offset_minutes > 59 {
                return None;
            }
            sign * (offset_hours * 3600 + offset_minutes * 60)
        }
    };

    let days = days_from_civil(year, month, day)?;
    Some(days * 86_400 + hour * 3600 + minute * 60 + second - offset_seconds)
}

/// Days between 1970-01-01 and the given date, by Howard Hinnant's algorithm.
fn days_from_civil(year: i64, month: u32, day: u32) -> Option<i64> {
    let month = month as i64;
    let day = day as i64;
    let year = if month <= 2 { year - 1 } else { year };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let day_of_year = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    Some(era * 146_097 + day_of_era - 719_468)
}

/// Keep only the grants that name `identity_dn` and are in force at `now_unix`.
///
/// # Errors
///
/// Returns `SecurityError::ConfigError` when the identity's DN cannot be
/// parsed, or when no grant survives: a permissions document that grants this
/// participant nothing is a configuration mistake, and silently running with an
/// empty rule set would deny every endpoint later with no explanation.
pub(crate) fn select_grants_for_subject(
    grants: Vec<super::Grant>,
    identity_dn: &str,
    now_unix: i64,
) -> Result<Vec<super::Grant>, SecurityError> {
    let identity = DistinguishedName::parse(identity_dn).ok_or_else(|| {
        SecurityError::ConfigError(format!(
            "identity certificate subject '{}' is not a readable distinguished name",
            identity_dn
        ))
    })?;
    select_grants_for_name(grants, &identity, now_unix)
}

/// [`select_grants_for_subject`] for a name already read, from a
/// certificate's DER (`DistinguishedName::from_x509_name`).
pub(crate) fn select_grants_for_name(
    grants: Vec<super::Grant>,
    identity: &DistinguishedName,
    now_unix: i64,
) -> Result<Vec<super::Grant>, SecurityError> {
    let identity_dn = identity.to_string();
    let total = grants.len();
    let mut wrong_subject = 0usize;
    let mut out_of_validity = 0usize;
    let mut selected = Vec::new();

    for grant in grants {
        let subject = match DistinguishedName::parse(&grant.subject_name) {
            Some(dn) => dn,
            None => {
                wrong_subject += 1;
                continue;
            }
        };
        if !subject.matches(identity) {
            wrong_subject += 1;
            continue;
        }
        if !grant_is_in_force(&grant, now_unix)? {
            out_of_validity += 1;
            continue;
        }
        selected.push(grant);
    }

    if selected.is_empty() {
        return Err(SecurityError::ConfigError(format!(
            "permissions document has no grant in force for this participant: subject \
             '{}', {} grant(s) read, {} for another subject, {} outside their validity \
             window (DDS-Security v1.1 9.4.3)",
            identity_dn, total, wrong_subject, out_of_validity
        )));
    }
    Ok(selected)
}

fn grant_is_in_force(grant: &super::Grant, now_unix: i64) -> Result<bool, SecurityError> {
    let not_before = parse_xs_datetime(&grant.validity.not_before).ok_or_else(|| {
        SecurityError::ConfigError(format!(
            "grant for '{}' has an unreadable not_before '{}'",
            grant.subject_name, grant.validity.not_before
        ))
    })?;
    let not_after = parse_xs_datetime(&grant.validity.not_after).ok_or_else(|| {
        SecurityError::ConfigError(format!(
            "grant for '{}' has an unreadable not_after '{}'",
            grant.subject_name, grant.validity.not_after
        ))
    })?;
    Ok(now_unix >= not_before && now_unix <= not_after)
}

/// A self-signed certificate whose subject is the one common name given.
#[cfg(test)]
pub(crate) fn certificate_named(common_name: &str) -> Vec<u8> {
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("params");
    let mut name = rcgen::DistinguishedName::new();
    name.push(rcgen::DnType::CommonName, common_name);
    params.distinguished_name = name;
    let key = rcgen::KeyPair::generate().expect("key");
    params
        .self_signed(&key)
        .expect("certificate")
        .pem()
        .into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::access::{Grant, Validity};

    fn grant(subject: &str, not_before: &str, not_after: &str) -> Grant {
        Grant {
            subject_name: subject.to_string(),
            validity: Validity {
                not_before: not_before.to_string(),
                not_after: not_after.to_string(),
            },
            rules: Vec::new(),
            default_allow: false,
        }
    }

    const NOW: i64 = 1_780_272_000; // 2026-06-01T00:00:00Z

    /// DDS Security v1.1 Sec.9.4.1.3: a grant applies to the subject name
    /// of the identity certificate. A certificate whose ONE attribute is the
    /// common name `bob, O=Admin` names neither `CN=bob,O=Admin` (two
    /// attributes) nor `CN=bob`, and is named by the grant that escapes the
    /// comma.
    #[test]
    fn a_comma_in_a_certificate_name_takes_no_other_subjects_grant() {
        let cert = certificate_named("bob, O=Admin");
        let identity = certificate_subject(&cert).expect("the subject is read");

        let refused = select_grants_for_name(
            vec![
                grant(
                    "CN=bob,O=Admin",
                    "2020-01-01T00:00:00",
                    "2036-01-01T00:00:00",
                ),
                grant("CN=bob", "2020-01-01T00:00:00", "2036-01-01T00:00:00"),
            ],
            &identity,
            NOW,
        );
        assert!(
            refused.is_err(),
            "a common name holding a comma selected another subject's grant"
        );

        let selected = select_grants_for_name(
            vec![grant(
                "CN=bob\\, O=Admin",
                "2020-01-01T00:00:00",
                "2036-01-01T00:00:00",
            )],
            &identity,
            NOW,
        )
        .expect("the grant naming the escaped common name is this subject's");
        assert_eq!(selected.len(), 1);
    }

    /// The same subject written in another attribute order, with other spacing,
    /// is the same subject.
    #[test]
    fn dn_compare_is_order_and_whitespace_insensitive() {
        let a = DistinguishedName::parse("CN=DDS Test Identity, O=HDDS Test").expect("a");
        let b = DistinguishedName::parse("O=HDDS Test,CN=DDS Test Identity").expect("b");
        let c =
            DistinguishedName::parse("  cn = DDS  Test   Identity ,  o = HDDS Test  ").expect("c");
        assert!(a.matches(&b));
        assert!(a.matches(&c));
    }

    /// A different subject, and a subset of the attributes, are both refused.
    #[test]
    fn dn_compare_rejects_a_different_or_partial_subject() {
        let identity = DistinguishedName::parse("CN=DDS Test Identity, O=HDDS Test").expect("id");
        let other = DistinguishedName::parse("CN=Somebody Else, O=HDDS Test").expect("other");
        let partial = DistinguishedName::parse("CN=DDS Test Identity").expect("partial");
        assert!(!identity.matches(&other));
        assert!(!identity.matches(&partial));
    }

    /// Values keep their case; only attribute types are case-folded.
    #[test]
    fn dn_values_are_case_sensitive() {
        let a = DistinguishedName::parse("CN=DDS Test Identity").expect("a");
        let b = DistinguishedName::parse("cn=dds test identity").expect("b");
        assert!(!a.matches(&b));
    }

    /// The alias spellings vendor documents use name the same attribute.
    #[test]
    fn dn_attribute_aliases_are_folded() {
        let a = DistinguishedName::parse("emailAddress=me@example.com, CN=Someone").expect("a");
        let b = DistinguishedName::parse("E=me@example.com, commonName=Someone").expect("b");
        assert!(a.matches(&b));
    }

    /// A hex escape names a byte; keeping its digits would merge two subjects.
    #[test]
    fn dn_hex_escape_does_not_collide_with_its_literal_spelling() {
        // `A\2CB` is ONE attribute whose value is `A,B`.
        let escaped = DistinguishedName::parse("CN=A\\2CB").expect("escaped form parses");
        let literal = DistinguishedName::parse("CN=A2CB").expect("literal form parses");
        assert!(
            !escaped.matches(&literal),
            "a hex escape must not decode to its own spelling"
        );
        let comma = DistinguishedName::parse("CN=A\\,B").expect("special-character form parses");
        assert!(
            escaped.matches(&comma),
            "both RFC 4514 escape forms name the same value"
        );
    }

    /// Hex escapes are decoded, including multi-byte UTF-8 sequences.
    #[test]
    fn dn_hex_escapes_are_decoded() {
        let escaped = DistinguishedName::parse("CN=Caf\\C3\\A9").expect("escaped form parses");
        let plain = DistinguishedName::parse("CN=Caf\u{e9}").expect("plain form parses");
        assert!(escaped.matches(&plain));
    }

    /// The hexstring value form is refused rather than compared literally.
    #[test]
    fn dn_hexstring_value_is_refused() {
        assert_eq!(DistinguishedName::parse("CN=#0C0141"), None);
    }

    /// An escape whose bytes are not UTF-8 is refused, never mangled.
    #[test]
    fn dn_with_an_unusable_hex_escape_is_refused() {
        assert_eq!(DistinguishedName::parse("CN=A\\FF"), None);
    }

    /// Every shape a permissions file writes its validity in.
    #[test]
    fn validity_parses_xs_datetime_with_and_without_offset() {
        assert_eq!(parse_xs_datetime("1970-01-01T00:00:00"), Some(0));
        assert_eq!(parse_xs_datetime("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(parse_xs_datetime("2026-06-01T00:00:00"), Some(NOW));
        assert_eq!(parse_xs_datetime("2026-06-01T00:00:00.500Z"), Some(NOW));
        // 01:00 local at +01:00 is midnight UTC.
        assert_eq!(parse_xs_datetime("2026-06-01T01:00:00+01:00"), Some(NOW));
        assert_eq!(parse_xs_datetime("2026-05-31T23:00:00-01:00"), Some(NOW));
        // A leap day, and the century rule.
        assert_eq!(parse_xs_datetime("2000-02-29T00:00:00Z"), Some(951_782_400));
    }

    /// Anything that is not an xs:dateTime is refused rather than defaulted.
    #[test]
    fn validity_refuses_unreadable_dates() {
        assert_eq!(parse_xs_datetime(""), None);
        assert_eq!(parse_xs_datetime("2026-06-01"), None);
        assert_eq!(parse_xs_datetime("2026-13-01T00:00:00Z"), None);
        assert_eq!(parse_xs_datetime("2026-06-01T25:00:00Z"), None);
        assert_eq!(parse_xs_datetime("2026-06-01T00:00:00+0100"), None);
        assert_eq!(parse_xs_datetime("not a date at all"), None);
    }

    /// A non-ASCII byte is unreadable, and must not slice through a character.
    #[test]
    fn validity_with_a_non_ascii_byte_is_an_error() {
        // Both of these used to panic: byte 17..19 and 19.. cut inside the
        // multi-byte character.
        assert_eq!(parse_xs_datetime("2026-06-01T00:00:0\u{e9}"), None);
        assert_eq!(parse_xs_datetime("2026-06-01T00:00:00\u{2013}01:00"), None);
    }

    /// An unreadable date reaches the caller as an error, not as a panic.
    #[test]
    fn non_ascii_validity_is_a_config_error_not_a_panic() {
        let grants = vec![grant(
            "CN=X",
            "2020-01-01T00:00:00",
            "2036-01-01T00:00:0\u{e9}",
        )];
        let err = select_grants_for_subject(grants, "CN=X", NOW)
            .expect_err("a non-ASCII date must be refused");
        assert!(err.to_string().contains("not_after"), "{}", err);
    }

    /// A grant issued to another participant is not applied.
    #[test]
    fn grant_for_other_subject_is_not_applied() {
        let grants = vec![grant(
            "CN=Somebody Else, O=HDDS Test",
            "2020-01-01T00:00:00",
            "2036-01-01T00:00:00",
        )];
        let err = select_grants_for_subject(grants, "CN=DDS Test Identity, O=HDDS Test", NOW)
            .expect_err("a grant for another subject must not be applied");
        assert!(err.to_string().contains("for another subject"), "{}", err);
    }

    /// A grant whose window has closed is not applied.
    #[test]
    fn expired_grant_is_not_applied() {
        let grants = vec![grant(
            "CN=DDS Test Identity, O=HDDS Test",
            "2020-01-01T00:00:00",
            "2021-01-01T00:00:00",
        )];
        let err = select_grants_for_subject(grants, "CN=DDS Test Identity, O=HDDS Test", NOW)
            .expect_err("an expired grant must not be applied");
        assert!(
            err.to_string().contains("outside their validity"),
            "{}",
            err
        );
    }

    /// A document that grants this participant nothing is an error.
    #[test]
    fn no_matching_grant_is_config_error() {
        let err = select_grants_for_subject(Vec::new(), "CN=DDS Test Identity", NOW)
            .expect_err("an empty selection must be an error");
        assert!(err.to_string().contains("no grant in force"), "{}", err);
    }

    /// The matching, in-force grant is the one that survives.
    #[test]
    fn matching_grant_in_its_window_is_selected() {
        let grants = vec![
            grant(
                "CN=Somebody Else, O=HDDS Test",
                "2020-01-01T00:00:00",
                "2036-01-01T00:00:00",
            ),
            grant(
                "CN=DDS Test Identity, O=HDDS Test",
                "2020-01-01T00:00:00",
                "2036-01-01T00:00:00",
            ),
        ];
        let selected = select_grants_for_subject(grants, "CN=DDS Test Identity, O=HDDS Test", NOW)
            .expect("the matching grant must be selected");
        assert_eq!(selected.len(), 1);
        assert_eq!(
            selected[0].subject_name,
            "CN=DDS Test Identity, O=HDDS Test"
        );
    }

    /// An unreadable validity is an error, never an open window.
    #[test]
    fn unreadable_validity_is_an_error() {
        let grants = vec![grant("CN=X", "yesterday", "tomorrow")];
        let err = select_grants_for_subject(grants, "CN=X", NOW)
            .expect_err("an unreadable date must not be treated as valid");
        assert!(err.to_string().contains("not_before"), "{}", err);
    }
}
