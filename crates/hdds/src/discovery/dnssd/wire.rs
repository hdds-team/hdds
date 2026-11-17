// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Minimal DNS wire codec (RFC 1035 + RFC 2782 SRV + RFC 6891 EDNS0).
//!
//! Only what DNS-SD peer discovery needs: encode one question, decode one
//! response, understand `A`, `AAAA` and `SRV` resource records. Everything
//! else decodes as [`RecordData::Other`] and is ignored.
//!
//! # Why in-tree instead of a resolver crate
//!
//! DNS-SD must also serve the zero-dependency deployments the `k8s`
//! feature targets, so the `dns-sd` feature is `[]`: no crate is added to
//! anybody's build, in the same spirit as `discovery/k8s.rs`. The scope
//! here is one question and one answer over UDP; a general resolver stack
//! (zone transfers, DNSSEC validation, async runtimes, TCP fallback) is a
//! much larger surface than the ~450 lines below, and none of it is used.
//!
//! # Hostile input
//!
//! Every read is bounds-checked and returns [`WireError`]; the decoder
//! never panics, never allocates from an attacker-controlled count, and
//! rejects compression pointers that do not move strictly backwards (the
//! only way a pointer chain can loop). `decoder_survives_every_truncation`
//! and `rejects_pointer_loops_and_hostile_names` pin that.

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

/// `TYPE`/`QTYPE` of an IPv4 address record.
pub const TYPE_A: u16 = 1;
/// `TYPE`/`QTYPE` of an IPv6 address record.
pub const TYPE_AAAA: u16 = 28;
/// `TYPE` of a canonical-name alias record.
pub const TYPE_CNAME: u16 = 5;
/// `TYPE`/`QTYPE` of a service locator record (RFC 2782).
pub const TYPE_SRV: u16 = 33;
/// `TYPE` of the EDNS0 pseudo-record (RFC 6891).
pub const TYPE_OPT: u16 = 41;
/// `CLASS`/`QCLASS` IN (internet).
pub const CLASS_IN: u16 = 1;

/// UDP payload size advertised in the EDNS0 OPT record.
///
/// The resolver is UDP-only: a response larger than this is truncated by
/// the server (`TC`), which the resolver reports as an error instead of
/// retrying over TCP. 4096 bytes hold tens of SRV records with their glue.
pub const EDNS_UDP_PAYLOAD: u16 = 4096;

/// Header flag: this message is a response (`QR`).
pub const FLAG_QR: u16 = 0x8000;
/// Header flag: the answer is authoritative (`AA`).
pub const FLAG_AA: u16 = 0x0400;
/// Header flag: the answer was truncated (`TC`).
pub const FLAG_TC: u16 = 0x0200;
/// Header flag: recursion desired (`RD`).
pub const FLAG_RD: u16 = 0x0100;

/// `RCODE` 0: no error.
pub const RCODE_NOERROR: u16 = 0;
/// `RCODE` 3: the queried name does not exist.
pub const RCODE_NXDOMAIN: u16 = 3;

/// A DNS name is at most 255 bytes on the wire (RFC 1035 section 2.3.4).
const MAX_NAME_WIRE_LEN: usize = 255;
/// A single label is at most 63 bytes (the two top bits mark a pointer).
const MAX_LABEL_LEN: usize = 63;
/// Upper bound on pointer hops while reading one name.
const MAX_POINTER_HOPS: usize = 16;
/// Header size in bytes.
const HEADER_LEN: usize = 12;

/// Everything the codec refuses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireError {
    /// A label is empty, over 63 bytes, or not printable ASCII.
    BadLabel(String),
    /// The encoded name would exceed 255 bytes.
    NameTooLong(usize),
    /// The message ends inside a field that had to be read.
    Truncated {
        /// Offset the read started at.
        offset: usize,
        /// Bytes the read needed.
        needed: usize,
        /// Bytes the message has.
        len: usize,
    },
    /// A compression pointer does not move strictly backwards, or a name
    /// needed more than 16 hops.
    PointerLoop(usize),
    /// A label length byte uses a reserved 0b01 / 0b10 prefix.
    ReservedLabelType(u8),
    /// `RDLENGTH` claims more bytes than the message holds, or a record's
    /// data does not fit in the length it declared.
    BadRdata(String),
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadLabel(label) => write!(f, "invalid DNS label: {}", label),
            Self::NameTooLong(len) => {
                write!(f, "encoded DNS name is {} bytes, the limit is 255", len)
            }
            Self::Truncated {
                offset,
                needed,
                len,
            } => write!(
                f,
                "message truncated: {} bytes needed at offset {}, message is {} bytes",
                needed, offset, len
            ),
            Self::PointerLoop(offset) => {
                write!(
                    f,
                    "compression pointer at offset {} does not terminate",
                    offset
                )
            }
            Self::ReservedLabelType(byte) => {
                write!(f, "reserved DNS label type 0x{:02x}", byte)
            }
            Self::BadRdata(reason) => write!(f, "invalid RDATA: {}", reason),
        }
    }
}

impl std::error::Error for WireError {}

/// SRV record payload (RFC 2782).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SrvData {
    /// Lower is preferred.
    pub priority: u16,
    /// Relative weight among equal priorities.
    pub weight: u16,
    /// Port the service listens on.
    pub port: u16,
    /// Host name serving it, normalised (lower-case, no trailing dot).
    pub target: String,
}

/// Decoded resource record payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordData {
    /// `A`: IPv4 address.
    A(Ipv4Addr),
    /// `AAAA`: IPv6 address.
    Aaaa(Ipv6Addr),
    /// `SRV`: service locator.
    Srv(SrvData),
    /// `CNAME`: the canonical name this owner is an alias of, normalised.
    ///
    /// Decoded because an answer record is only accepted when its OWNER
    /// name is the queried name or a canonical name reached from it: a
    /// resolver that cannot read the alias chain would have to accept
    /// records owned by any name at all.
    Cname(String),
    /// Any other type, kept only as its numeric type.
    Other(u16),
}

/// One resource record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceRecord {
    /// Owner name, normalised (lower-case, no trailing dot).
    pub name: String,
    /// Record type.
    pub rtype: u16,
    /// Record class.
    pub rclass: u16,
    /// Time to live, in seconds.
    pub ttl: u32,
    /// Decoded payload.
    pub data: RecordData,
}

/// A decoded DNS message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    /// Message ID, echoed by the responder.
    pub id: u16,
    /// Header flags word.
    pub flags: u16,
    /// Questions: (normalised name, qtype, qclass).
    pub questions: Vec<(String, u16, u16)>,
    /// Answer section.
    pub answers: Vec<ResourceRecord>,
    /// Authority section.
    pub authorities: Vec<ResourceRecord>,
    /// Additional section (SRV glue lives here).
    pub additionals: Vec<ResourceRecord>,
}

impl Message {
    /// `QR` bit: this message is a response.
    pub fn is_response(&self) -> bool {
        self.flags & FLAG_QR != 0
    }

    /// `TC` bit: the responder had more to say than fitted in the datagram.
    pub fn is_truncated(&self) -> bool {
        self.flags & FLAG_TC != 0
    }

    /// `RCODE`: the low four bits of the flags word.
    pub fn rcode(&self) -> u16 {
        self.flags & 0x000F
    }

    /// Answer records of one type, in wire order.
    pub fn answers_of_type(&self, rtype: u16) -> impl Iterator<Item = &ResourceRecord> {
        self.answers.iter().filter(move |r| r.rtype == rtype)
    }
}

/// Lower-case, no trailing dot: the comparison form for names.
///
/// DNS names are case-insensitive (RFC 4343), so every name this codec
/// produces or compares goes through here.
pub fn normalise_name(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
}

/// Encode a standard query for one question, with an EDNS0 OPT record
/// advertising [`EDNS_UDP_PAYLOAD`] when `edns` is set.
///
/// Recursion is requested (`RD`): DNS-SD peer discovery asks a configured
/// resolver, not an authoritative server.
pub fn encode_query(id: u16, name: &str, qtype: u16, edns: bool) -> Result<Vec<u8>, WireError> {
    let qname = encode_name(name)?;
    let mut out = Vec::with_capacity(HEADER_LEN + qname.len() + 4 + 11);
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&FLAG_RD.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    out.extend_from_slice(&u16::from(edns).to_be_bytes()); // ARCOUNT
    out.extend_from_slice(&qname);
    out.extend_from_slice(&qtype.to_be_bytes());
    out.extend_from_slice(&CLASS_IN.to_be_bytes());
    if edns {
        // OPT pseudo-record: root name, TYPE=OPT, CLASS=UDP payload size,
        // TTL=extended rcode/version/flags (all zero), RDLENGTH=0.
        out.push(0);
        out.extend_from_slice(&TYPE_OPT.to_be_bytes());
        out.extend_from_slice(&EDNS_UDP_PAYLOAD.to_be_bytes());
        out.extend_from_slice(&0u32.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
    }
    Ok(out)
}

/// Encode a name as uncompressed length-prefixed labels.
///
/// Rejects an empty label, a label over 63 bytes, a non-printable-ASCII
/// byte and a total encoding over 255 bytes, so a caller-supplied service
/// or zone can never produce a malformed question.
pub fn encode_name(name: &str) -> Result<Vec<u8>, WireError> {
    let normalised = normalise_name(name);
    let mut out = Vec::with_capacity(normalised.len() + 2);
    if !normalised.is_empty() {
        for label in normalised.split('.') {
            let bytes = label.as_bytes();
            if bytes.is_empty() || bytes.len() > MAX_LABEL_LEN {
                return Err(WireError::BadLabel(label.to_string()));
            }
            if bytes.iter().any(|b| !(0x21..=0x7E).contains(b)) {
                return Err(WireError::BadLabel(label.to_string()));
            }
            // The guard above bounds the label at MAX_LABEL_LEN (63), so
            // this conversion cannot fail as the code stands. It is written
            // as a conversion and not as `as u8` so that the prefix stays
            // honest if that constant ever moves: a cast turns a 256-byte
            // label into a length of ZERO, which a reader takes for the root
            // label, so the name ends early and the packet is malformed with
            // no error raised anywhere. `a_label_length_prefix_is_never_wrapped`
            // measures the emitted byte rather than trusting the argument.
            let length =
                u8::try_from(bytes.len()).map_err(|_| WireError::BadLabel(label.to_string()))?;
            out.push(length);
            out.extend_from_slice(bytes);
        }
    }
    out.push(0);
    if out.len() > MAX_NAME_WIRE_LEN {
        return Err(WireError::NameTooLong(out.len()));
    }
    Ok(out)
}

/// Decode a message (query or response).
pub fn decode_message(bytes: &[u8]) -> Result<Message, WireError> {
    if bytes.len() < HEADER_LEN {
        return Err(WireError::Truncated {
            offset: 0,
            needed: HEADER_LEN,
            len: bytes.len(),
        });
    }
    let id = read_u16(bytes, 0)?;
    let flags = read_u16(bytes, 2)?;
    let qdcount = read_u16(bytes, 4)?;
    let ancount = read_u16(bytes, 6)?;
    let nscount = read_u16(bytes, 8)?;
    let arcount = read_u16(bytes, 10)?;

    let mut offset = HEADER_LEN;
    // Counts come from the wire: never pre-allocate from them.
    let mut questions = Vec::new();
    for _ in 0..qdcount {
        let (name, next) = read_name(bytes, offset)?;
        let qtype = read_u16(bytes, next)?;
        let qclass = read_u16(bytes, next + 2)?;
        questions.push((name, qtype, qclass));
        offset = next + 4;
    }

    let answers = read_records(bytes, &mut offset, ancount)?;
    let authorities = read_records(bytes, &mut offset, nscount)?;
    let additionals = read_records(bytes, &mut offset, arcount)?;

    Ok(Message {
        id,
        flags,
        questions,
        answers,
        authorities,
        additionals,
    })
}

fn read_records(
    bytes: &[u8],
    offset: &mut usize,
    count: u16,
) -> Result<Vec<ResourceRecord>, WireError> {
    let mut records = Vec::new();
    for _ in 0..count {
        let (name, next) = read_name(bytes, *offset)?;
        let rtype = read_u16(bytes, next)?;
        let rclass = read_u16(bytes, next + 2)?;
        let ttl = read_u32(bytes, next + 4)?;
        let rdlength = usize::from(read_u16(bytes, next + 8)?);
        let rdata_start = next + 10;
        let rdata_end = rdata_start
            .checked_add(rdlength)
            .ok_or_else(|| WireError::BadRdata("RDLENGTH overflows the offset".to_string()))?;
        if rdata_end > bytes.len() {
            return Err(WireError::BadRdata(format!(
                "RDLENGTH {} at offset {} runs past the {} byte message",
                rdlength,
                rdata_start,
                bytes.len()
            )));
        }
        let data = decode_rdata(bytes, rtype, rdata_start, rdata_end)?;
        records.push(ResourceRecord {
            name,
            rtype,
            rclass,
            ttl,
            data,
        });
        *offset = rdata_end;
    }
    Ok(records)
}

fn decode_rdata(
    bytes: &[u8],
    rtype: u16,
    start: usize,
    end: usize,
) -> Result<RecordData, WireError> {
    let len = end - start;
    match rtype {
        TYPE_A => {
            if len != 4 {
                return Err(WireError::BadRdata(format!("A record with {} bytes", len)));
            }
            let octets = bytes
                .get(start..end)
                .ok_or_else(|| WireError::BadRdata("A record out of range".to_string()))?;
            Ok(RecordData::A(Ipv4Addr::new(
                octets[0], octets[1], octets[2], octets[3],
            )))
        }
        TYPE_AAAA => {
            if len != 16 {
                return Err(WireError::BadRdata(format!(
                    "AAAA record with {} bytes",
                    len
                )));
            }
            let mut octets = [0u8; 16];
            let slice = bytes
                .get(start..end)
                .ok_or_else(|| WireError::BadRdata("AAAA record out of range".to_string()))?;
            octets.copy_from_slice(slice);
            Ok(RecordData::Aaaa(Ipv6Addr::from(octets)))
        }
        TYPE_CNAME => {
            // The alias target MAY be compressed into the rest of the
            // message, but its bytes must stay inside this RDATA.
            let (target, target_end) = read_name(bytes, start)?;
            if target_end > end {
                return Err(WireError::BadRdata(
                    "CNAME target name runs past RDLENGTH".to_string(),
                ));
            }
            Ok(RecordData::Cname(target))
        }
        TYPE_SRV => {
            if len < 7 {
                return Err(WireError::BadRdata(format!(
                    "SRV record with {} bytes, 7 is the minimum",
                    len
                )));
            }
            // The target name MAY use a compression pointer into the rest
            // of the message, but the bytes it occupies must stay inside
            // this record's own RDATA.
            let (target, target_end) = read_name(bytes, start + 6)?;
            if target_end > end {
                return Err(WireError::BadRdata(
                    "SRV target name runs past RDLENGTH".to_string(),
                ));
            }
            Ok(RecordData::Srv(SrvData {
                priority: read_u16(bytes, start)?,
                weight: read_u16(bytes, start + 2)?,
                port: read_u16(bytes, start + 4)?,
                target,
            }))
        }
        other => Ok(RecordData::Other(other)),
    }
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, WireError> {
    match bytes.get(offset..offset.saturating_add(2)) {
        Some(&[high, low]) => Ok(u16::from_be_bytes([high, low])),
        _ => Err(WireError::Truncated {
            offset,
            needed: 2,
            len: bytes.len(),
        }),
    }
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, WireError> {
    match bytes.get(offset..offset.saturating_add(4)) {
        Some(&[a, b, c, d]) => Ok(u32::from_be_bytes([a, b, c, d])),
        _ => Err(WireError::Truncated {
            offset,
            needed: 4,
            len: bytes.len(),
        }),
    }
}

/// Read a (possibly compressed) name.
///
/// Returns the normalised name and the offset just past the name IN THE
/// ORIGINAL STREAM: a compression pointer ends the name after its own two
/// bytes, whatever it points at. A pointer must move strictly backwards,
/// which makes a loop impossible; the hop count is bounded as well so a
/// long backwards chain cannot cost more than 16 reads.
fn read_name(bytes: &[u8], start: usize) -> Result<(String, usize), WireError> {
    let mut labels: Vec<String> = Vec::new();
    let mut wire_len = 1usize; // the terminating root label
    let mut offset = start;
    let mut end_after: Option<usize> = None;
    let mut hops = 0usize;

    loop {
        let length = *bytes.get(offset).ok_or(WireError::Truncated {
            offset,
            needed: 1,
            len: bytes.len(),
        })?;
        match length & 0xC0 {
            0x00 => {
                if length == 0 {
                    offset += 1;
                    break;
                }
                let label_start = offset + 1;
                let label_end = label_start + usize::from(length);
                let label = bytes
                    .get(label_start..label_end)
                    .ok_or(WireError::Truncated {
                        offset: label_start,
                        needed: usize::from(length),
                        len: bytes.len(),
                    })?;
                wire_len += 1 + label.len();
                if wire_len > MAX_NAME_WIRE_LEN {
                    return Err(WireError::NameTooLong(wire_len));
                }
                labels.push(String::from_utf8_lossy(label).to_ascii_lowercase());
                offset = label_end;
            }
            0xC0 => {
                let pointer = usize::from(read_u16(bytes, offset)? & 0x3FFF);
                if end_after.is_none() {
                    end_after = Some(offset + 2);
                }
                hops += 1;
                if pointer >= offset || hops > MAX_POINTER_HOPS {
                    return Err(WireError::PointerLoop(offset));
                }
                offset = pointer;
            }
            _ => return Err(WireError::ReservedLabelType(length)),
        }
    }

    Ok((labels.join("."), end_after.unwrap_or(offset)))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The exact bytes RFC 1035 section 4 prescribes for a recursive SRV
    /// question with an RFC 6891 OPT record, written out by hand.
    #[test]
    fn encodes_srv_query_matching_a_hand_built_rfc1035_vector() {
        let query = encode_query(0xBEEF, "_hdds._udp.Example.Test.", TYPE_SRV, true)
            .expect("a legal service name encodes");

        #[rustfmt::skip]
        let expected: Vec<u8> = vec![
            0xBE, 0xEF,             // ID
            0x01, 0x00,             // QR=0 OPCODE=0 RD=1
            0x00, 0x01,             // QDCOUNT = 1
            0x00, 0x00,             // ANCOUNT = 0
            0x00, 0x00,             // NSCOUNT = 0
            0x00, 0x01,             // ARCOUNT = 1 (the OPT record)
            5, b'_', b'h', b'd', b'd', b's',
            4, b'_', b'u', b'd', b'p',
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
            4, b't', b'e', b's', b't',
            0,                      // root label
            0x00, 0x21,             // QTYPE = SRV (33)
            0x00, 0x01,             // QCLASS = IN
            0,                      // OPT owner name = root
            0x00, 0x29,             // TYPE = OPT (41)
            0x10, 0x00,             // CLASS = 4096 byte UDP payload
            0x00, 0x00, 0x00, 0x00, // TTL = extended rcode / version / flags
            0x00, 0x00,             // RDLENGTH = 0
        ];
        assert_eq!(query, expected);

        // Without EDNS0 the OPT record and its ARCOUNT are gone.
        let plain = encode_query(0xBEEF, "_hdds._udp.example.test", TYPE_SRV, false)
            .expect("encodes without EDNS0");
        assert_eq!(plain.len(), expected.len() - 11);
        assert_eq!(&plain[10..12], &[0x00, 0x00], "ARCOUNT must be 0");
        assert_eq!(&plain[..10], &expected[..10]);
    }

    #[test]
    fn encode_name_refuses_labels_a_server_would_reject() {
        assert!(encode_name("a..b").is_err(), "empty label");
        assert!(
            encode_name(&format!("{}.test", "x".repeat(64))).is_err(),
            "64 byte label"
        );
        assert!(
            encode_name(&format!("{}.test", "x".repeat(63))).is_ok(),
            "63 byte label"
        );
        assert!(encode_name("host name.test").is_err(), "space in a label");
        assert!(encode_name("h\u{e9}te.test").is_err(), "non-ASCII byte");
        // 255 bytes is the wire limit for the whole name.
        let long = vec!["abcdefghij"; 26].join(".");
        assert!(matches!(encode_name(&long), Err(WireError::NameTooLong(_))));
        // The root name encodes to a single zero byte.
        assert_eq!(encode_name("."), Ok(vec![0]));
    }

    /// The length prefix written in front of a label is that label's real
    /// length, and a label no `u8` can describe is refused instead of
    /// wrapped.
    ///
    /// This measures the EMITTED BYTE, not just `is_ok`/`is_err`: the
    /// failure being guarded against is a silent one. A 256-byte label
    /// truncated to a prefix of 0 reads back as the root label, so the
    /// name ends there and the rest of the question is parsed as whatever
    /// field comes next - a malformed packet nobody reports.
    #[test]
    fn a_label_length_prefix_is_never_wrapped() {
        for width in [1usize, 9, 62, MAX_LABEL_LEN] {
            let label = "x".repeat(width);
            let encoded = encode_name(&label).expect("a legal label encodes");
            let prefix = u8::try_from(width).expect("the loop only uses legal widths");
            assert_eq!(
                encoded.first().copied(),
                Some(prefix),
                "the prefix of a {}-byte label",
                width
            );
            assert_eq!(encoded.len(), width + 2, "prefix + label + root");
            assert_eq!(encoded.last().copied(), Some(0), "root label");
        }

        // One byte past the label limit, and past what a u8 holds: both
        // are refused, and neither emits a zero-length prefix.
        for width in [MAX_LABEL_LEN + 1, 255, 256, 300] {
            let label = "x".repeat(width);
            assert!(
                matches!(encode_name(&label), Err(WireError::BadLabel(_))),
                "a {}-byte label was not refused",
                width
            );
        }

        // The 255-byte whole-name limit, measured on both sides of the
        // boundary: 3 labels of 63 and one of 61 cost 4 * 1 + 250 + 1 = 255.
        let at_limit = [
            "x".repeat(MAX_LABEL_LEN),
            "y".repeat(MAX_LABEL_LEN),
            "z".repeat(MAX_LABEL_LEN),
            "w".repeat(61),
        ]
        .join(".");
        assert_eq!(
            encode_name(&at_limit).map(|wire| wire.len()),
            Ok(MAX_NAME_WIRE_LEN)
        );
        let one_over = at_limit + "w";
        assert_eq!(
            encode_name(&one_over),
            Err(WireError::NameTooLong(MAX_NAME_WIRE_LEN + 1))
        );
    }

    /// A response built the way a real server builds one: the SRV owner
    /// name is a pointer back to the question, and each target's `A`
    /// record rides in the additional section.
    fn golden_srv_response() -> Vec<u8> {
        let mut wire = Vec::new();
        wire.extend_from_slice(&0x1234u16.to_be_bytes());
        wire.extend_from_slice(&(FLAG_QR | FLAG_RD | FLAG_AA).to_be_bytes());
        wire.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
        wire.extend_from_slice(&2u16.to_be_bytes()); // ANCOUNT
        wire.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
        wire.extend_from_slice(&2u16.to_be_bytes()); // ARCOUNT
        let question = encode_name("_hdds._udp.example.test").expect("question name");
        wire.extend_from_slice(&question);
        wire.extend_from_slice(&TYPE_SRV.to_be_bytes());
        wire.extend_from_slice(&CLASS_IN.to_be_bytes());

        // Two SRV answers whose owner name is a pointer to offset 12.
        let mut targets = Vec::new();
        for (priority, port, target) in [
            (10u16, 7410u16, "node-a.example.test"),
            (20u16, 7412u16, "node-b.example.test"),
        ] {
            wire.extend_from_slice(&0xC00Cu16.to_be_bytes());
            wire.extend_from_slice(&TYPE_SRV.to_be_bytes());
            wire.extend_from_slice(&CLASS_IN.to_be_bytes());
            wire.extend_from_slice(&60u32.to_be_bytes());
            let name = encode_name(target).expect("target name");
            wire.extend_from_slice(&((6 + name.len()) as u16).to_be_bytes());
            wire.extend_from_slice(&priority.to_be_bytes());
            wire.extend_from_slice(&5u16.to_be_bytes()); // weight
            wire.extend_from_slice(&port.to_be_bytes());
            wire.extend_from_slice(&name);
            targets.push(target);
        }
        // Glue: one A and one AAAA in the additional section.
        wire.extend_from_slice(&encode_name(targets[0]).expect("glue name"));
        wire.extend_from_slice(&TYPE_A.to_be_bytes());
        wire.extend_from_slice(&CLASS_IN.to_be_bytes());
        wire.extend_from_slice(&60u32.to_be_bytes());
        wire.extend_from_slice(&4u16.to_be_bytes());
        wire.extend_from_slice(&[192, 0, 2, 1]);
        wire.extend_from_slice(&encode_name(targets[1]).expect("glue name"));
        wire.extend_from_slice(&TYPE_AAAA.to_be_bytes());
        wire.extend_from_slice(&CLASS_IN.to_be_bytes());
        wire.extend_from_slice(&60u32.to_be_bytes());
        wire.extend_from_slice(&16u16.to_be_bytes());
        wire.extend_from_slice(&Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2).octets());
        wire
    }

    #[test]
    fn decodes_srv_answers_with_compression_pointers_and_a_aaaa_glue() {
        let message = decode_message(&golden_srv_response()).expect("the golden answer decodes");
        assert_eq!(message.id, 0x1234);
        assert!(message.is_response());
        assert!(!message.is_truncated());
        assert_eq!(message.rcode(), RCODE_NOERROR);
        assert_eq!(
            message.questions,
            vec![("_hdds._udp.example.test".to_string(), TYPE_SRV, CLASS_IN)]
        );

        let srv: Vec<_> = message.answers_of_type(TYPE_SRV).collect();
        assert_eq!(srv.len(), 2);
        // The compressed owner name resolved back to the question name.
        assert_eq!(srv[0].name, "_hdds._udp.example.test");
        assert_eq!(srv[0].ttl, 60);
        assert_eq!(
            srv[0].data,
            RecordData::Srv(SrvData {
                priority: 10,
                weight: 5,
                port: 7410,
                target: "node-a.example.test".to_string(),
            })
        );
        assert_eq!(
            srv[1].data,
            RecordData::Srv(SrvData {
                priority: 20,
                weight: 5,
                port: 7412,
                target: "node-b.example.test".to_string(),
            })
        );

        assert_eq!(message.additionals.len(), 2);
        assert_eq!(message.additionals[0].name, "node-a.example.test");
        assert_eq!(
            message.additionals[0].data,
            RecordData::A(Ipv4Addr::new(192, 0, 2, 1))
        );
        assert_eq!(
            message.additionals[1].data,
            RecordData::Aaaa(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2))
        );
    }

    /// Every prefix of a valid answer must produce an error, never a panic
    /// and never a silent partial message.
    #[test]
    fn decoder_survives_every_truncation_of_a_valid_answer() {
        let golden = golden_srv_response();
        for len in 0..golden.len() {
            let result = decode_message(&golden[..len]);
            assert!(
                result.is_err(),
                "a {} byte prefix of a {} byte answer decoded as a whole message",
                len,
                golden.len()
            );
        }
        assert!(decode_message(&golden).is_ok());

        // Every single-byte mutation must also be rejected or decoded, but
        // never panic.
        for index in 0..golden.len() {
            for value in [0x00u8, 0x3F, 0xC0, 0xFF] {
                let mut mutated = golden.clone();
                mutated[index] = value;
                let _ = decode_message(&mutated);
            }
        }
    }

    #[test]
    fn rejects_pointer_loops_and_hostile_names() {
        // A pointer to itself.
        let mut wire = vec![0u8; HEADER_LEN];
        wire[5] = 1; // QDCOUNT = 1
        wire.extend_from_slice(&0xC00Cu16.to_be_bytes());
        wire.extend_from_slice(&TYPE_A.to_be_bytes());
        wire.extend_from_slice(&CLASS_IN.to_be_bytes());
        assert_eq!(decode_message(&wire), Err(WireError::PointerLoop(12)));

        // A forward pointer (offset 12 -> 14) is refused for the same
        // reason: only strictly backwards pointers can terminate.
        let mut forward = vec![0u8; HEADER_LEN];
        forward[5] = 1;
        forward.extend_from_slice(&0xC00Eu16.to_be_bytes());
        forward.extend_from_slice(&[0]);
        forward.extend_from_slice(&TYPE_A.to_be_bytes());
        forward.extend_from_slice(&CLASS_IN.to_be_bytes());
        assert_eq!(decode_message(&forward), Err(WireError::PointerLoop(12)));

        // Reserved label type 0b10.
        let mut reserved = vec![0u8; HEADER_LEN];
        reserved[5] = 1;
        reserved.push(0x80);
        assert_eq!(
            decode_message(&reserved),
            Err(WireError::ReservedLabelType(0x80))
        );

        // An RDLENGTH larger than the message.
        let mut long_rdata = vec![0u8; HEADER_LEN];
        long_rdata[7] = 1; // ANCOUNT = 1
        long_rdata.push(0); // root owner name
        long_rdata.extend_from_slice(&TYPE_A.to_be_bytes());
        long_rdata.extend_from_slice(&CLASS_IN.to_be_bytes());
        long_rdata.extend_from_slice(&0u32.to_be_bytes());
        long_rdata.extend_from_slice(&4000u16.to_be_bytes());
        assert!(matches!(
            decode_message(&long_rdata),
            Err(WireError::BadRdata(_))
        ));

        // An SRV target that escapes its own RDLENGTH.
        let mut short_srv = vec![0u8; HEADER_LEN];
        short_srv[7] = 1;
        short_srv.push(0);
        short_srv.extend_from_slice(&TYPE_SRV.to_be_bytes());
        short_srv.extend_from_slice(&CLASS_IN.to_be_bytes());
        short_srv.extend_from_slice(&0u32.to_be_bytes());
        short_srv.extend_from_slice(&7u16.to_be_bytes()); // claims 7 bytes
        short_srv.extend_from_slice(&[0, 10, 0, 5, 0x1C, 0xF2]); // priority/weight/port
        short_srv.extend_from_slice(&encode_name("node.example.test").expect("name"));
        assert!(matches!(
            decode_message(&short_srv),
            Err(WireError::BadRdata(_))
        ));

        // A name whose labels sum past 255 bytes.
        let mut long_name = vec![0u8; HEADER_LEN];
        long_name[5] = 1;
        for _ in 0..6 {
            long_name.push(63);
            long_name.extend_from_slice(&[b'x'; 63]);
        }
        long_name.push(0);
        long_name.extend_from_slice(&TYPE_A.to_be_bytes());
        long_name.extend_from_slice(&CLASS_IN.to_be_bytes());
        assert!(matches!(
            decode_message(&long_name),
            Err(WireError::NameTooLong(_))
        ));
    }

    /// The alias chain is decoded, and a target that escapes its own
    /// RDLENGTH is refused like any other overrunning name.
    #[test]
    fn decodes_cname_and_refuses_a_target_past_its_rdlength() {
        let target = encode_name("canonical.example.test").expect("name");
        let mut wire = vec![0u8; HEADER_LEN];
        wire[7] = 1; // ANCOUNT = 1
        wire.extend_from_slice(&encode_name("alias.example.test").expect("name"));
        wire.extend_from_slice(&TYPE_CNAME.to_be_bytes());
        wire.extend_from_slice(&CLASS_IN.to_be_bytes());
        wire.extend_from_slice(&60u32.to_be_bytes());
        wire.extend_from_slice(&(target.len() as u16).to_be_bytes());
        wire.extend_from_slice(&target);
        let message = decode_message(&wire).expect("a CNAME decodes");
        assert_eq!(message.answers[0].name, "alias.example.test");
        assert_eq!(
            message.answers[0].data,
            RecordData::Cname("canonical.example.test".to_string())
        );

        // Same record, RDLENGTH one byte short of its own target.
        let mut short = vec![0u8; HEADER_LEN];
        short[7] = 1;
        short.extend_from_slice(&encode_name("alias.example.test").expect("name"));
        short.extend_from_slice(&TYPE_CNAME.to_be_bytes());
        short.extend_from_slice(&CLASS_IN.to_be_bytes());
        short.extend_from_slice(&60u32.to_be_bytes());
        short.extend_from_slice(&((target.len() - 1) as u16).to_be_bytes());
        short.extend_from_slice(&target);
        assert!(matches!(
            decode_message(&short),
            Err(WireError::BadRdata(_))
        ));
    }

    #[test]
    fn unknown_record_types_decode_as_other_and_are_skipped() {
        let mut wire = vec![0u8; HEADER_LEN];
        wire[7] = 2; // ANCOUNT = 2
                     // A TXT record (16) we do not model, then the SRV we want.
        wire.extend_from_slice(&encode_name("example.test").expect("name"));
        wire.extend_from_slice(&16u16.to_be_bytes());
        wire.extend_from_slice(&CLASS_IN.to_be_bytes());
        wire.extend_from_slice(&0u32.to_be_bytes());
        wire.extend_from_slice(&3u16.to_be_bytes());
        wire.extend_from_slice(&[2, b'h', b'i']);
        wire.extend_from_slice(&encode_name("example.test").expect("name"));
        wire.extend_from_slice(&TYPE_SRV.to_be_bytes());
        wire.extend_from_slice(&CLASS_IN.to_be_bytes());
        wire.extend_from_slice(&0u32.to_be_bytes());
        let target = encode_name("node.example.test").expect("name");
        wire.extend_from_slice(&((6 + target.len()) as u16).to_be_bytes());
        wire.extend_from_slice(&[0, 1, 0, 1, 0x1C, 0xF2]);
        wire.extend_from_slice(&target);

        let message = decode_message(&wire).expect("decodes past the unknown type");
        assert_eq!(message.answers.len(), 2);
        assert_eq!(message.answers[0].data, RecordData::Other(16));
        assert_eq!(message.answers_of_type(TYPE_SRV).count(), 1);
    }

    #[test]
    fn normalise_name_is_case_and_trailing_dot_insensitive() {
        assert_eq!(
            normalise_name("Node-A.Example.TEST."),
            "node-a.example.test"
        );
        assert_eq!(normalise_name("node-a.example.test"), "node-a.example.test");
        assert_eq!(normalise_name("."), "");
    }
}
