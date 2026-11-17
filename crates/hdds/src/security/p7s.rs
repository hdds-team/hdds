// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! PKCS#7 / S/MIME envelope splitter for DDS-Security v1.1 governance and
//! permissions documents (section 9.4.1).
//!
//! The spec allows two envelope shapes for a signed document, and HDDS parses
//! both:
//!
//! - S/MIME `multipart/signed` (RFC 5751): the XML travels as the first body
//!   part, the CMS SignedData blob as a base64 `application/pkcs7-signature`
//!   part. This is the shape every vendor toolchain on disk produces.
//! - DER PKCS#7 SignedData (RFC 5652) with the document attached, i.e. with
//!   `eContent` present. A DER envelope with no `eContent` is a signature over
//!   a document it does not carry, so it can never be a document source and is
//!   refused.
//!
//! Plain, unsigned XML is recognised as a third shape so the caller can refuse
//! it by policy with a message that says what is wrong.
//!
//! # This module performs no cryptographic check
//!
//! [`parse_envelope`] only splits the envelope. It returns the three things a
//! verifier needs -- the document (`xml`), the exact bytes the signature covers
//! (`signed_content`), and the CMS blob (`cms_der`) -- and nothing it returns
//! is trustworthy until a caller has verified `cms_der` over `signed_content`
//! against the configured Permissions CA.

use crate::security::SecurityError;
use base64::{engine::general_purpose, Engine as _};
use x509_parser::der_parser::asn1_rs::{Any, Class, FromDer, Tag};

/// OID `1.2.840.113549.1.7.2` (id-signedData), content bytes only.
const OID_SIGNED_DATA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02];

/// Which of the three shapes a document arrived in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EnvelopeKind {
    /// Bare XML with no signature anywhere.
    Plain,
    /// S/MIME `multipart/signed` (RFC 5751).
    SMime,
    /// DER PKCS#7 SignedData carrying its own `eContent`.
    DerAttached,
}

/// A split, still unverified signed document.
#[derive(Debug, Clone)]
pub(crate) struct SignedEnvelope {
    /// Which shape the bytes arrived in.
    pub(crate) kind: EnvelopeKind,
    /// The document itself, ready for the XML parser.
    pub(crate) xml: Vec<u8>,
    /// The exact byte sequence the signature covers.
    ///
    /// For S/MIME this is the first body part INCLUDING its MIME sub-headers,
    /// canonicalised to CRLF, with the line break that precedes the closing
    /// delimiter excluded (RFC 5751 3.1.1 by way of RFC 2046 5.1.1). For
    /// attached DER it is the `eContent` octets. Empty for [`EnvelopeKind::Plain`].
    pub(crate) signed_content: Vec<u8>,
    /// The DER-encoded CMS `ContentInfo`. Empty for [`EnvelopeKind::Plain`].
    pub(crate) cms_der: Vec<u8>,
}

/// Split a governance or permissions file into document, signed bytes and CMS blob.
///
/// # Errors
///
/// Returns `SecurityError::ConfigError` if the envelope is malformed, if an
/// S/MIME envelope carries no signature part, or if a DER envelope carries no
/// document.
pub(crate) fn parse_envelope(bytes: &[u8]) -> Result<SignedEnvelope, SecurityError> {
    if bytes.starts_with(b"MIME-Version:") || bytes.starts_with(b"Content-Type:") {
        parse_smime(bytes)
    } else if bytes.first() == Some(&0x30) {
        parse_der_pkcs7(bytes)
    } else {
        Ok(SignedEnvelope {
            kind: EnvelopeKind::Plain,
            xml: bytes.to_vec(),
            signed_content: Vec::new(),
            cms_der: Vec::new(),
        })
    }
}

fn cfg_err(msg: impl Into<String>) -> SecurityError {
    SecurityError::ConfigError(msg.into())
}

// ---------------------------------------------------------------------------
// S/MIME multipart/signed (RFC 5751)
// ---------------------------------------------------------------------------

fn parse_smime(bytes: &[u8]) -> Result<SignedEnvelope, SecurityError> {
    let boundary = parse_boundary(bytes)
        .ok_or_else(|| cfg_err("S/MIME envelope missing boundary parameter in Content-Type"))?;

    // RFC 2046 5.1.1: the delimiter is "--" followed by the boundary value.
    let mut delimiter = Vec::with_capacity(boundary.len() + 2);
    delimiter.extend_from_slice(b"--");
    delimiter.extend_from_slice(&boundary);

    // segments[0] is the preamble; each following segment is a body part, and
    // the last one is whatever trails the closing delimiter.
    let segments = split_on(bytes, &delimiter);
    if segments.len() < 3 {
        return Err(cfg_err(
            "S/MIME envelope needs a content part and a signature part",
        ));
    }

    let content_part = trim_part(segments[1]);
    if content_part.is_empty() {
        return Err(cfg_err("S/MIME content part is empty"));
    }
    let signed_content = canonicalize_crlf(content_part);

    let (headers, body) = split_headers(content_part);
    let xml = trim_trailing_eol(body).to_vec();
    if xml.is_empty() {
        return Err(cfg_err("S/MIME content part carries no document"));
    }
    let _ = headers;

    let cms_der = smime_signature_der(&segments[2..])?;

    Ok(SignedEnvelope {
        kind: EnvelopeKind::SMime,
        xml,
        signed_content,
        cms_der,
    })
}

/// Locate the `application/pkcs7-signature` part and base64-decode it.
fn smime_signature_der(parts: &[&[u8]]) -> Result<Vec<u8>, SecurityError> {
    for part in parts {
        let part = trim_part(part);
        if part.is_empty() {
            continue;
        }
        let (headers, body) = split_headers(part);
        if !header_names_a_pkcs7_signature(headers) {
            continue;
        }
        let mut b64 = Vec::with_capacity(body.len());
        b64.extend(body.iter().copied().filter(|b| !b.is_ascii_whitespace()));
        if b64.is_empty() {
            return Err(cfg_err("S/MIME signature part is empty"));
        }
        return general_purpose::STANDARD
            .decode(&b64)
            .map_err(|e| cfg_err(format!("S/MIME signature part is not valid base64: {}", e)));
    }
    Err(cfg_err(
        "S/MIME envelope has no application/pkcs7-signature part",
    ))
}

fn header_names_a_pkcs7_signature(headers: &[u8]) -> bool {
    let lowered: Vec<u8> = headers.iter().map(u8::to_ascii_lowercase).collect();
    find_subslice(&lowered, b"application/pkcs7-signature").is_some()
        || find_subslice(&lowered, b"application/x-pkcs7-signature").is_some()
}

/// Read the `boundary` parameter out of the envelope's own header block.
///
/// Only the header block is scanned: a body part is free to contain the word
/// `boundary=` and must not be able to redirect the split.
fn parse_boundary(bytes: &[u8]) -> Option<Vec<u8>> {
    let header_block = match find_blank_line(bytes) {
        Some((start, _)) => &bytes[..start],
        None => bytes,
    };
    let pos = find_subslice(header_block, b"boundary=")?;
    let rest = &header_block[pos + b"boundary=".len()..];
    // The value ends at the closing quote, or at ';', CR or LF when unquoted.
    if let Some(inner) = rest.strip_prefix(b"\"") {
        let end = inner.iter().position(|&b| b == b'"')?;
        Some(inner[..end].to_vec())
    } else {
        let end = rest
            .iter()
            .position(|&b| b == b';' || b == b'\r' || b == b'\n')
            .unwrap_or(rest.len());
        let value = trim_ascii(&rest[..end]);
        if value.is_empty() {
            None
        } else {
            Some(value.to_vec())
        }
    }
}

/// Strip the line break that follows the opening delimiter and the one that
/// precedes the next delimiter.
///
/// RFC 2046 5.1.1: both breaks belong to the delimiter lines, not to the part,
/// which is exactly why the digest of a signed part excludes them.
fn trim_part(part: &[u8]) -> &[u8] {
    // Transport padding may sit between the boundary and its line break.
    let mut start = 0;
    while start < part.len() && (part[start] == b' ' || part[start] == b'\t') {
        start += 1;
    }
    let part = &part[start..];
    let part = if let Some(rest) = part.strip_prefix(b"\r\n") {
        rest
    } else if let Some(rest) = part.strip_prefix(b"\n") {
        rest
    } else {
        part
    };
    strip_one_trailing_eol(part)
}

fn strip_one_trailing_eol(bytes: &[u8]) -> &[u8] {
    if let Some(rest) = bytes.strip_suffix(b"\r\n") {
        rest
    } else if let Some(rest) = bytes.strip_suffix(b"\n") {
        rest
    } else {
        bytes
    }
}

fn trim_trailing_eol(bytes: &[u8]) -> &[u8] {
    let mut end = bytes.len();
    while end > 0 && (bytes[end - 1] == b'\r' || bytes[end - 1] == b'\n') {
        end -= 1;
    }
    &bytes[..end]
}

/// Split a body part into its MIME sub-header block and its body.
///
/// A part is allowed to carry no sub-headers at all: openssl 3.x emits exactly
/// that shape, so the blank line inside such a part's own content must not be
/// mistaken for the header separator (the document would come back empty). The
/// header block is therefore only recognised when the part's first line really
/// is a header field.
fn split_headers(part: &[u8]) -> (&[u8], &[u8]) {
    if !starts_with_header_field(part) {
        return (&[], part);
    }
    match find_blank_line(part) {
        Some((headers_end, body_start)) => (&part[..headers_end], &part[body_start..]),
        None => (&[], part),
    }
}

/// True when the first line is `field-name ":" ...` per RFC 5322 2.2.
///
/// `<` is refused even though RFC 5322 would allow it in a field name. Without
/// that, a document whose first element carries a namespace prefix
/// (`<dds:permissions ...>`, no XML declaration) reads as a header field
/// because of the colon, and a blank line further down the document would then
/// be taken for the header separator and truncate what the XML parser sees.
/// The signature still covers the whole part either way, so this is about
/// handing the parser the document the signer meant, not about forgery.
fn starts_with_header_field(part: &[u8]) -> bool {
    for &b in part {
        match b {
            b':' => return true,
            b'<' => return false,
            // field-name is one or more printable US-ASCII characters other
            // than colon; a space or a line break ends the candidate.
            0x21..=0x7e => {}
            _ => return false,
        }
    }
    false
}

/// Offsets of the first blank line: `(end of the block before it, start after it)`.
fn find_blank_line(bytes: &[u8]) -> Option<(usize, usize)> {
    if let Some(pos) = find_subslice(bytes, b"\r\n\r\n") {
        // A lone "\n\n" could sit earlier; the earlier one wins.
        if let Some(lf) = find_subslice(bytes, b"\n\n") {
            if lf < pos {
                return Some((lf, lf + 2));
            }
        }
        return Some((pos, pos + 4));
    }
    find_subslice(bytes, b"\n\n").map(|pos| (pos, pos + 2))
}

/// Normalise every line break to CRLF, as RFC 5751 3.1.1 requires before hashing.
fn canonicalize_crlf(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len() + bytes.len() / 8);
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'\r' => {
                out.extend_from_slice(b"\r\n");
                if bytes.get(i + 1) == Some(&b'\n') {
                    i += 1;
                }
            }
            b'\n' => out.extend_from_slice(b"\r\n"),
            b => out.push(b),
        }
        i += 1;
    }
    out
}

fn trim_ascii(bytes: &[u8]) -> &[u8] {
    let mut start = 0;
    let mut end = bytes.len();
    while start < end && bytes[start].is_ascii_whitespace() {
        start += 1;
    }
    while end > start && bytes[end - 1].is_ascii_whitespace() {
        end -= 1;
    }
    &bytes[start..end]
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn split_on<'a>(haystack: &'a [u8], needle: &[u8]) -> Vec<&'a [u8]> {
    let mut out = Vec::new();
    let mut rest = haystack;
    while let Some(pos) = find_subslice(rest, needle) {
        out.push(&rest[..pos]);
        rest = &rest[pos + needle.len()..];
    }
    out.push(rest);
    out
}

// ---------------------------------------------------------------------------
// DER PKCS#7 SignedData (RFC 5652)
//
//   ContentInfo ::= SEQUENCE {
//     contentType  OBJECT IDENTIFIER (id-signedData),
//     content      [0] EXPLICIT SignedData }
//   SignedData ::= SEQUENCE {
//     version CMSVersion, digestAlgorithms SET OF ...,
//     encapContentInfo EncapsulatedContentInfo, ... }
//   EncapsulatedContentInfo ::= SEQUENCE {
//     eContentType OBJECT IDENTIFIER,
//     eContent     [0] EXPLICIT OCTET STRING OPTIONAL }
//
// Only the document is located here. Every algorithm and signer field is left
// to the verifier, which re-parses the same bytes.
// ---------------------------------------------------------------------------

fn parse_der_pkcs7(data: &[u8]) -> Result<SignedEnvelope, SecurityError> {
    let (content_info, _) = der_next(data, "ContentInfo")?;
    expect(
        &content_info,
        Class::Universal,
        Tag::Sequence,
        "ContentInfo",
    )?;

    let (content_type, rest) = der_next(content_info.data, "contentType")?;
    expect(&content_type, Class::Universal, Tag::Oid, "contentType")?;
    if content_type.data != OID_SIGNED_DATA {
        return Err(cfg_err(
            "DER PKCS#7: contentType is not id-signedData (1.2.840.113549.1.7.2)",
        ));
    }

    let (content, _) = der_next(rest, "content [0]")?;
    expect(&content, Class::ContextSpecific, Tag(0), "content [0]")?;

    let (signed_data, _) = der_next(content.data, "SignedData")?;
    expect(&signed_data, Class::Universal, Tag::Sequence, "SignedData")?;

    let (version, rest) = der_next(signed_data.data, "SignedData.version")?;
    expect(
        &version,
        Class::Universal,
        Tag::Integer,
        "SignedData.version",
    )?;

    let (digest_algorithms, rest) = der_next(rest, "digestAlgorithms")?;
    expect(
        &digest_algorithms,
        Class::Universal,
        Tag::Set,
        "digestAlgorithms",
    )?;

    let (encap, _) = der_next(rest, "encapContentInfo")?;
    expect(&encap, Class::Universal, Tag::Sequence, "encapContentInfo")?;

    let (_e_content_type, rest) = der_next(encap.data, "eContentType")?;
    if rest.is_empty() {
        return Err(cfg_err(
            "DER PKCS#7: detached SignedData carries no eContent, so it carries no document",
        ));
    }

    let (e_content, _) = der_next(rest, "eContent [0]")?;
    expect(&e_content, Class::ContextSpecific, Tag(0), "eContent [0]")?;

    // EXPLICIT [0] wrapping an OCTET STRING is what every encoder in reach
    // emits; an IMPLICIT primitive tag is accepted as the octets themselves.
    let document = if e_content.header.constructed() {
        let (octets, _) = der_next(e_content.data, "eContent OCTET STRING")?;
        expect(
            &octets,
            Class::Universal,
            Tag::OctetString,
            "eContent OCTET STRING",
        )?;
        octets.data.to_vec()
    } else {
        e_content.data.to_vec()
    };

    if document.is_empty() {
        return Err(cfg_err("DER PKCS#7: eContent is empty"));
    }

    Ok(SignedEnvelope {
        kind: EnvelopeKind::DerAttached,
        xml: document.clone(),
        signed_content: document,
        cms_der: data.to_vec(),
    })
}

fn der_next<'a>(input: &'a [u8], what: &str) -> Result<(Any<'a>, &'a [u8]), SecurityError> {
    Any::from_der(input)
        .map(|(rest, any)| (any, rest))
        .map_err(|e| cfg_err(format!("DER PKCS#7: cannot read {}: {:?}", what, e)))
}

fn expect(any: &Any<'_>, class: Class, tag: Tag, what: &str) -> Result<(), SecurityError> {
    if any.class() != class || any.tag() != tag {
        return Err(cfg_err(format!(
            "DER PKCS#7: {} has unexpected tag {:?}/{:?}",
            what,
            any.class(),
            any.tag()
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::test_pki::{
        FASTDDS_PERMISSIONS_CANONICAL_SHA256, FASTDDS_PERMISSIONS_SMIME,
        PERMISSIONS_EC_ATTACHED_DER, PERMISSIONS_EC_DETACHED_DER,
        PERMISSIONS_EC_NO_SUBHEADERS_SMIME, PERMISSIONS_EC_SMIME,
    };
    use ring::digest::{digest, SHA256};

    const PLAIN_XML: &[u8] = b"<?xml version=\"1.0\"?><dds><governance/></dds>";

    /// The document bytes only. Production code always goes through
    /// `parse_envelope` so the signature material travels with the document;
    /// these structural tests do not care about it.
    fn extract_xml(bytes: &[u8]) -> Result<Vec<u8>, SecurityError> {
        parse_envelope(bytes).map(|envelope| envelope.xml)
    }

    /// Plain XML passes through unchanged, and is reported as unsigned.
    #[test]
    fn test_parse_plain_xml_passes_through() {
        let result = extract_xml(PLAIN_XML).expect("plain XML should pass through");
        assert_eq!(result, PLAIN_XML);
        let envelope = parse_envelope(PLAIN_XML).expect("plain XML is a known shape");
        assert_eq!(envelope.kind, EnvelopeKind::Plain);
        assert!(envelope.cms_der.is_empty());
    }

    /// S/MIME multipart/signed envelope: XML extracted from first body part.
    ///
    /// The fixture below is a minimal valid S/MIME wrapper around PLAIN_XML.
    /// Boundary is `----TEST`, signature part contains a dummy base64 blob.
    #[test]
    fn test_parse_smime_p7s_extracts_xml() {
        // Constructed by hand; boundary must not appear in the content.
        let smime = concat!(
            "MIME-Version: 1.0\r\n",
            "Content-Type: multipart/signed; protocol=\"application/x-pkcs7-signature\"; ",
            "micalg=\"sha-256\"; boundary=\"----TEST0001\"\r\n",
            "\r\n",
            "This is an S/MIME signed message\r\n",
            "\r\n",
            "------TEST0001\r\n",
            "Content-Type: text/plain\r\n",
            "\r\n",
            "<?xml version=\"1.0\"?><dds><governance/></dds>",
            "\r\n",
            "------TEST0001\r\n",
            "Content-Type: application/x-pkcs7-signature; name=\"smime.p7s\"\r\n",
            "Content-Transfer-Encoding: base64\r\n",
            "Content-Disposition: attachment; filename=\"smime.p7s\"\r\n",
            "\r\n",
            "AAAA\r\n",
            "\r\n",
            "------TEST0001--\r\n",
        );

        let result = extract_xml(smime.as_bytes()).expect("S/MIME extraction should succeed");
        let xml = std::str::from_utf8(&result).expect("result must be valid UTF-8");
        assert!(
            xml.contains("<dds>"),
            "extracted XML must contain <dds> tag; got: {:?}",
            xml
        );
        assert!(
            !xml.contains("AAAA"),
            "signature blob must not appear in extracted XML"
        );
    }

    /// S/MIME with LF-only line endings (non-CRLF variant).
    #[test]
    fn test_parse_smime_lf_only() {
        let smime = concat!(
            "MIME-Version: 1.0\n",
            "Content-Type: multipart/signed; boundary=\"----LFTST\"\n",
            "\n",
            "------LFTST\n",
            "Content-Type: text/plain\n",
            "\n",
            "<?xml version=\"1.0\"?><perms/>",
            "\n",
            "------LFTST\n",
            "Content-Type: application/x-pkcs7-signature\n",
            "\n",
            "c2ln\n",
            "------LFTST--\n",
        );

        let result = extract_xml(smime.as_bytes()).expect("LF-only S/MIME must succeed");
        let xml = std::str::from_utf8(&result).expect("must be valid UTF-8");
        assert!(xml.contains("<perms/>"), "got: {:?}", xml);
    }

    /// DER PKCS#7 SignedData: a minimal but structurally valid DER blob
    /// encoding a SignedData that wraps the 4-byte payload `<ok>`.
    ///
    /// The hex was computed by hand to follow RFC 5652 section 5 and locked
    /// here. It does NOT contain a valid signature; only the structural
    /// navigation is tested.
    #[test]
    fn test_parse_der_p7s_extracts_xml() {
        // OCTET STRING wrapping b"<ok>"
        let octet_str: &[u8] = &[0x04, 0x04, 0x3c, 0x6f, 0x6b, 0x3e];

        // [0] EXPLICIT wrapping OCTET STRING
        let ec_ctx: Vec<u8> = {
            let mut v = vec![0xa0_u8, octet_str.len() as u8];
            v.extend_from_slice(octet_str);
            v
        };

        // eContentType OID placeholder: 06 03 55 04 03
        let oid_eci: &[u8] = &[0x06, 0x03, 0x55, 0x04, 0x03];

        // encapContentInfo SEQUENCE
        let eci_inner_len = oid_eci.len() + ec_ctx.len();
        let eci: Vec<u8> = {
            let mut v = vec![0x30_u8, eci_inner_len as u8];
            v.extend_from_slice(oid_eci);
            v.extend_from_slice(&ec_ctx);
            v
        };

        // digestAlgorithms SET (empty)
        let da: &[u8] = &[0x31, 0x00];

        // version INTEGER 1
        let ver: &[u8] = &[0x02, 0x01, 0x01];

        // SignedData SEQUENCE
        let sd_inner_len = ver.len() + da.len() + eci.len();
        let sd: Vec<u8> = {
            let mut v = vec![0x30_u8, sd_inner_len as u8];
            v.extend_from_slice(ver);
            v.extend_from_slice(da);
            v.extend_from_slice(&eci);
            v
        };

        // [0] EXPLICIT wrapping SignedData
        let ctx: Vec<u8> = {
            let mut v = vec![0xa0_u8, sd.len() as u8];
            v.extend_from_slice(&sd);
            v
        };

        // OID signedData 1.2.840.113549.1.7.2
        let oid_ci: &[u8] = &[
            0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02,
        ];

        // ContentInfo SEQUENCE
        let ci_inner_len = oid_ci.len() + ctx.len();
        let ci: Vec<u8> = {
            let mut v = vec![0x30_u8, ci_inner_len as u8];
            v.extend_from_slice(oid_ci);
            v.extend_from_slice(&ctx);
            v
        };

        let result = extract_xml(&ci).expect("DER PKCS#7 extraction should succeed");
        assert_eq!(result, b"<ok>", "extracted payload mismatch");
    }

    /// The canonical signed bytes of a document HDDS did not produce hash to the
    /// value that document's own messageDigest attribute carries.
    #[test]
    fn smime_canonical_content_hash_matches_fastdds_message_digest() {
        let envelope = parse_envelope(FASTDDS_PERMISSIONS_SMIME).expect("vendor S/MIME parses");
        let hash = digest(&SHA256, &envelope.signed_content);
        assert_eq!(
            hash.as_ref(),
            &FASTDDS_PERMISSIONS_CANONICAL_SHA256[..],
            "canonicalization drifted from the value the vendor signed"
        );
        assert!(
            envelope
                .signed_content
                .starts_with(b"Content-Type: text/plain\r\n\r\n"),
            "the signed bytes must include the MIME sub-headers"
        );
        assert!(
            !envelope.cms_der.is_empty(),
            "signature part must be decoded"
        );
    }

    /// The same document with LF or CRLF line endings canonicalizes identically.
    #[test]
    fn smime_lf_and_crlf_inputs_canonicalize_identically() {
        let lf = FASTDDS_PERMISSIONS_SMIME.to_vec();
        let mut crlf = Vec::with_capacity(lf.len() * 2);
        for &b in &lf {
            if b == b'\n' {
                crlf.extend_from_slice(b"\r\n");
            } else {
                crlf.push(b);
            }
        }
        let a = parse_envelope(&lf).expect("LF form parses");
        let b = parse_envelope(&crlf).expect("CRLF form parses");
        assert_eq!(a.signed_content, b.signed_content);
        assert_eq!(a.cms_der, b.cms_der);
    }

    /// An S/MIME envelope without a signature part is refused.
    #[test]
    fn smime_missing_signature_part_is_error() {
        let smime = concat!(
            "MIME-Version: 1.0\r\n",
            "Content-Type: multipart/signed; boundary=\"----NOSIG\"\r\n",
            "\r\n",
            "------NOSIG\r\n",
            "Content-Type: text/plain\r\n",
            "\r\n",
            "<dds/>\r\n",
            "------NOSIG\r\n",
            "Content-Type: text/plain\r\n",
            "\r\n",
            "not a signature\r\n",
            "------NOSIG--\r\n",
        );
        let err = parse_envelope(smime.as_bytes()).expect_err("no signature part must be refused");
        assert!(
            err.to_string().contains("pkcs7-signature"),
            "message must say what is missing: {}",
            err
        );
    }

    /// A part carrying no MIME sub-headers is still read whole.
    ///
    /// openssl 3.x emits this shape, and the blank line inside the document
    /// must not be mistaken for the header separator.
    #[test]
    fn smime_part_without_subheaders_keeps_the_whole_document() {
        let envelope =
            parse_envelope(PERMISSIONS_EC_NO_SUBHEADERS_SMIME).expect("header-less part parses");
        assert!(
            envelope.xml.starts_with(b"<?xml"),
            "document must start at the XML declaration"
        );
        assert!(
            envelope.xml.ends_with(b"</dds>"),
            "document must run to the closing tag"
        );
        assert_eq!(
            strip_one_trailing_eol(&envelope.signed_content),
            &envelope.xml[..],
            "with no sub-headers the signed bytes are the document plus its own final CRLF"
        );
    }

    /// A DER envelope with no eContent carries no document and is refused.
    #[test]
    fn der_detached_signed_data_is_error() {
        let err = parse_envelope(PERMISSIONS_EC_DETACHED_DER)
            .expect_err("detached DER must not be accepted as a document source");
        assert!(
            err.to_string().contains("eContent"),
            "message must say the document is missing: {}",
            err
        );
    }

    /// A DER envelope with eContent yields both the document and the CMS blob.
    #[test]
    fn der_attached_signed_data_extracts_content() {
        let envelope =
            parse_envelope(PERMISSIONS_EC_ATTACHED_DER).expect("attached DER must parse");
        assert_eq!(envelope.kind, EnvelopeKind::DerAttached);
        assert!(envelope.xml.starts_with(b"<?xml"));
        assert_eq!(envelope.signed_content, envelope.xml);
        assert_eq!(envelope.cms_der, PERMISSIONS_EC_ATTACHED_DER);
    }

    /// A prefixed root element is not a MIME header, even though it has a colon.
    #[test]
    fn a_namespace_prefixed_root_element_is_not_a_header_field() {
        let smime = concat!(
            "MIME-Version: 1.0\r\n",
            "Content-Type: multipart/signed; boundary=\"----NSTEST\"\r\n",
            "\r\n",
            "------NSTEST\r\n",
            "<dds:permissions>\r\n",
            "\r\n",
            "<dds:grant/></dds:permissions>\r\n",
            "------NSTEST\r\n",
            "Content-Type: application/x-pkcs7-signature\r\n",
            "\r\n",
            "c2ln\r\n",
            "------NSTEST--\r\n",
        );
        let envelope = parse_envelope(smime.as_bytes()).expect("the part parses");
        assert!(
            envelope.xml.starts_with(b"<dds:permissions>"),
            "the document must start at its root element, not after the blank line"
        );
        assert!(
            envelope.xml.ends_with(b"</dds:permissions>"),
            "the whole document must survive"
        );
    }

    /// The boundary is read from the envelope header, never from a body part.
    #[test]
    fn boundary_is_read_from_the_envelope_header_only() {
        let smime = concat!(
            "MIME-Version: 1.0\r\n",
            "Content-Type: multipart/signed; boundary=\"----REAL\"\r\n",
            "\r\n",
            "------REAL\r\n",
            "Content-Type: text/plain\r\n",
            "\r\n",
            "<dds>boundary=\"----FAKE\"</dds>\r\n",
            "------REAL\r\n",
            "Content-Type: application/x-pkcs7-signature\r\n",
            "\r\n",
            "c2ln\r\n",
            "------REAL--\r\n",
        );
        let envelope = parse_envelope(smime.as_bytes()).expect("real boundary must win");
        assert_eq!(envelope.xml, b"<dds>boundary=\"----FAKE\"</dds>");
    }

    /// Every fixture parses as an envelope; the tampered ones must fail later,
    /// in the verifier, not here.
    #[test]
    fn signed_fixtures_parse_as_envelopes() {
        use crate::security::test_pki::{
            GOVERNANCE_EC_SMIME, PERMISSIONS_EXPIRED_CA_SMIME, PERMISSIONS_EXPIRED_GRANT_SMIME,
            PERMISSIONS_NOATTR_SMIME, PERMISSIONS_OTHER_CA_SMIME, PERMISSIONS_OTHER_SUBJECT_SMIME,
            PERMISSIONS_RSA_SMIME, PERMISSIONS_TAMPERED_SMIME,
        };
        for (name, bytes) in [
            ("governance_ec", GOVERNANCE_EC_SMIME),
            ("permissions_ec", PERMISSIONS_EC_SMIME),
            ("permissions_rsa", PERMISSIONS_RSA_SMIME),
            ("permissions_tampered", PERMISSIONS_TAMPERED_SMIME),
            ("permissions_other_ca", PERMISSIONS_OTHER_CA_SMIME),
            ("permissions_expired_ca", PERMISSIONS_EXPIRED_CA_SMIME),
            ("permissions_noattr", PERMISSIONS_NOATTR_SMIME),
            ("permissions_other_subject", PERMISSIONS_OTHER_SUBJECT_SMIME),
            ("permissions_expired_grant", PERMISSIONS_EXPIRED_GRANT_SMIME),
        ] {
            let envelope = parse_envelope(bytes)
                .unwrap_or_else(|e| panic!("fixture {} must parse as an envelope: {}", name, e));
            assert_eq!(envelope.kind, EnvelopeKind::SMime, "fixture {}", name);
            assert!(!envelope.cms_der.is_empty(), "fixture {}", name);
            assert!(envelope.xml.starts_with(b"<?xml"), "fixture {}", name);
        }
    }
}
