// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

#![allow(dead_code)] // Consumers gated behind `security` cargo feature.

//! DataHolder Wire Format
//!
//! Serializes and parses DDS Security v1.1 `DataHolder` (sec. 7.2.4) carried
//! in `PID_IDENTITY_TOKEN` (0x1001) and `PID_PERMISSIONS_TOKEN` (0x1002)
//! parameter list values within SPDP `ParticipantBuiltinTopicDataSecure`.
//!
//! # Wire Format
//!
//! Little-endian CDR matching the surrounding `PL_CDR_LE` SPDP payload.
//! Strings are encoded per RTPS v2.5 sec. 10.2 string CDR: `u32 length
//! (including trailing NUL) + bytes + NUL + zero-pad to 4-byte boundary`.
//! Sequences follow the OMG CDR rules: `u32 count + elements`.
//!
//! ```text
//! DataHolder {
//!     string                     class_id;
//!     sequence<Property_t>       properties;
//!     sequence<BinaryProperty_t> binary_properties;
//! }
//!
//! Property_t {
//!     string  name;
//!     string  value;
//!     // propagate is NOT serialized (see below)
//! }
//!
//! BinaryProperty_t {
//!     string          name;
//!     sequence<octet> value;      // u32 length + bytes + zero-pad to 4
//!     // propagate is NOT serialized (see below)
//! }
//! ```
//!
//! # `propagate` is not on the wire
//!
//! DDS Security v1.1 sec. 7.2.1.1 and sec. 7.2.2.1 declare `propagate` non-serialized,
//! and sec. 7.4.1.4 says the serialization shall omit it: the flag is a local
//! instruction about WHETHER to send the property, not a field to send. This
//! codec therefore writes no 4-byte CDR boolean after a property and expects
//! none back: such a word would put 4 extra octets per property between us
//! and every conformant peer, and a golden vector taken from our own encoder
//! would not reveal it (hence the foreign-toolchain vector in the tests).
//!
//! So `propagate` does what it means: a property with `propagate = false`
//! is left OUT of the serialized holder, and every property that comes back
//! from [`parse_data_holder`] was propagated by definition.

use crate::protocol::discovery::types::wire_u32;
use crate::protocol::discovery::ParseError;

/// Parsed `DataHolder` (DDS Security v1.1 sec. 7.2.4).
///
/// Returned by [`parse_data_holder`] for downstream consumption by the
/// `SecurityValidatorAdapter`.
///
/// The third tuple element is `propagate`. It is NOT a wire field (see the
/// module docs): on the way out it decides whether the property is written at
/// all, and on the way in it is `true` for every property present, because a
/// property that reached us was propagated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DataHolder {
    pub class_id: String,
    pub properties: Vec<(String, String, bool)>,
    pub binary_properties: Vec<(String, Vec<u8>, bool)>,
}

/// CDR string (RTPS v2.5 sec. 10.2): 4-byte length including trailing NUL, the
/// string bytes, the NUL terminator, and zero padding up to a 4-byte
/// boundary.
fn write_cdr_string(buf: &mut Vec<u8>, value: &str) -> Result<(), ParseError> {
    let bytes = value.as_bytes();
    let len_with_nul = wire_u32(bytes.len() + 1)?;
    buf.extend_from_slice(&len_with_nul.to_le_bytes());
    buf.extend_from_slice(bytes);
    buf.push(0);
    while !buf.len().is_multiple_of(4) {
        buf.push(0);
    }
    Ok(())
}

/// CDR octet sequence: 4-byte length, raw bytes, zero padding to a 4-byte
/// boundary.
fn write_cdr_octet_sequence(buf: &mut Vec<u8>, value: &[u8]) -> Result<(), ParseError> {
    let len = wire_u32(value.len())?;
    buf.extend_from_slice(&len.to_le_bytes());
    buf.extend_from_slice(value);
    while !buf.len().is_multiple_of(4) {
        buf.push(0);
    }
    Ok(())
}

/// Serialize a `DataHolder` ready for inclusion as the value of a
/// `PID_IDENTITY_TOKEN` or `PID_PERMISSIONS_TOKEN` parameter.
///
/// # Arguments
/// - `class_id`: token class identifier
/// - `properties`: textual `Property_t` entries `(name, value, propagate)`;
///   an entry with `propagate = false` is OMITTED, which is what the flag
///   means (DDS Security v1.1 sec. 7.2.1.1). It is never written to the wire.
/// - `binary_properties`: binary `BinaryProperty_t` entries
///   `(name, octets, propagate)`, same rule
pub(crate) fn serialize_data_holder(
    class_id: &str,
    properties: &[(String, String, bool)],
    binary_properties: &[(String, Vec<u8>, bool)],
) -> Result<Vec<u8>, ParseError> {
    // Every length prefix below is a 32-bit CDR field. `wire_u32` refuses
    // what does not fit instead of wrapping it: a DataHolder whose length
    // word lies is a token no peer can parse, and this function must not
    // produce one silently for any input past u32::MAX.
    let mut buf = Vec::with_capacity(64);

    write_cdr_string(&mut buf, class_id)?;

    // Only propagating properties are written, and the flag itself is not.
    let sent: Vec<&(String, String, bool)> = properties.iter().filter(|(_, _, p)| *p).collect();
    let prop_count = wire_u32(sent.len())?;
    buf.extend_from_slice(&prop_count.to_le_bytes());
    for (name, value, _) in sent {
        write_cdr_string(&mut buf, name)?;
        write_cdr_string(&mut buf, value)?;
    }

    let sent_bin: Vec<&(String, Vec<u8>, bool)> =
        binary_properties.iter().filter(|(_, _, p)| *p).collect();
    let bin_count = wire_u32(sent_bin.len())?;
    buf.extend_from_slice(&bin_count.to_le_bytes());
    for (name, value, _) in sent_bin {
        write_cdr_string(&mut buf, name)?;
        write_cdr_octet_sequence(&mut buf, value)?;
    }

    Ok(buf)
}

/// Read a CDR string (u32 LE length including NUL, bytes, NUL, padding to 4).
fn read_cdr_string(buf: &[u8], offset: &mut usize) -> Option<String> {
    if offset.checked_add(4)? > buf.len() {
        return None;
    }
    let len = u32::from_le_bytes([
        buf[*offset],
        buf[*offset + 1],
        buf[*offset + 2],
        buf[*offset + 3],
    ]) as usize;
    *offset += 4;
    // CHECKED: `offset + len` is attacker-controlled on both terms. On a
    // 32-bit usize a wire length of 0xFFFFFFFF wrapped the sum, the bound
    // test passed, and `&buf[offset..end]` panicked on the SPDP receive
    // thread.
    if len == 0 || offset.checked_add(len)? > buf.len() {
        return None;
    }
    // String bytes include the trailing NUL.
    let end = *offset + len - 1;
    let text = std::str::from_utf8(&buf[*offset..end]).ok()?.to_string();
    *offset += len;
    // Pad to 4-byte boundary.
    while !(*offset).is_multiple_of(4) {
        *offset += 1;
    }
    Some(text)
}

/// Read a CDR octet sequence (u32 LE length, bytes, padding to 4).
fn read_cdr_octet_sequence(buf: &[u8], offset: &mut usize) -> Option<Vec<u8>> {
    if offset.checked_add(4)? > buf.len() {
        return None;
    }
    let len = u32::from_le_bytes([
        buf[*offset],
        buf[*offset + 1],
        buf[*offset + 2],
        buf[*offset + 3],
    ]) as usize;
    *offset += 4;
    // CHECKED, same reason as read_cdr_string.
    if offset.checked_add(len)? > buf.len() {
        return None;
    }
    let bytes = buf[*offset..*offset + len].to_vec();
    *offset += len;
    while !(*offset).is_multiple_of(4) {
        *offset += 1;
    }
    Some(bytes)
}

/// Read a CDR boolean (1 byte value + 3 bytes padding).
/// Read a CDR `u32` little-endian.
fn read_u32_le(buf: &[u8], offset: &mut usize) -> Option<u32> {
    if offset.checked_add(4)? > buf.len() {
        return None;
    }
    let v = u32::from_le_bytes([
        buf[*offset],
        buf[*offset + 1],
        buf[*offset + 2],
        buf[*offset + 3],
    ]);
    *offset += 4;
    Some(v)
}

/// Parse a CDR-encoded `DataHolder` from the value of a
/// `PID_IDENTITY_TOKEN` or `PID_PERMISSIONS_TOKEN` parameter.
///
/// Returns `None` if any field is truncated or malformed. Caller is
/// expected to log a warning and reject the offending participant.
pub(crate) fn parse_data_holder(bytes: &[u8]) -> Option<DataHolder> {
    let mut offset = 0;

    let class_id = read_cdr_string(bytes, &mut offset)?;

    let prop_count = read_u32_le(bytes, &mut offset)?;
    if prop_count > 64 {
        // Hard cap. A legitimate IdentityToken has 4 properties and a
        // PermissionsToken has 2; anything beyond a couple dozen is a
        // sign of a malformed payload or a hostile peer.
        return None;
    }
    let mut properties = Vec::with_capacity(prop_count as usize);
    for _ in 0..prop_count {
        let name = read_cdr_string(bytes, &mut offset)?;
        let value = read_cdr_string(bytes, &mut offset)?;
        // `propagate` is not a wire field; a property that arrived was
        // propagated (see the module docs).
        properties.push((name, value, true));
    }

    let bin_count = read_u32_le(bytes, &mut offset)?;
    if bin_count > 64 {
        return None;
    }
    let mut binary_properties = Vec::with_capacity(bin_count as usize);
    for _ in 0..bin_count {
        let name = read_cdr_string(bytes, &mut offset)?;
        let value = read_cdr_octet_sequence(bytes, &mut offset)?;
        binary_properties.push((name, value, true));
    }

    Some(DataHolder {
        class_id,
        properties,
        binary_properties,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialize_empty_data_holder() {
        let bytes = serialize_data_holder("DDS:Auth:PKI-DH:1.0", &[], &[]).expect("encode");
        let class_len = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
        assert_eq!(class_len, "DDS:Auth:PKI-DH:1.0".len() + 1);

        let class_end = 4 + class_len;
        let aligned = (class_end + 3) & !3;
        let prop_count = u32::from_le_bytes([
            bytes[aligned],
            bytes[aligned + 1],
            bytes[aligned + 2],
            bytes[aligned + 3],
        ]);
        let bin_count = u32::from_le_bytes([
            bytes[aligned + 4],
            bytes[aligned + 5],
            bytes[aligned + 6],
            bytes[aligned + 7],
        ]);
        assert_eq!(prop_count, 0);
        assert_eq!(bin_count, 0);
        assert_eq!(bytes.len() % 4, 0);
    }

    #[test]
    fn serialize_with_property_and_binary() {
        let properties = vec![("dds.perm_ca.sn".to_string(), "CN=PermCA".to_string(), true)];
        let binary_properties = vec![(
            "dds.cert.der".to_string(),
            vec![0x30u8, 0x82, 0x00, 0x10],
            true,
        )];
        let bytes = serialize_data_holder(
            "DDS:Access:Permissions:1.0",
            &properties,
            &binary_properties,
        )
        .expect("encode");
        assert!(!bytes.is_empty());
        assert_eq!(bytes.len() % 4, 0);

        // Class id field comes first.
        let class_len = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
        assert_eq!(class_len, "DDS:Access:Permissions:1.0".len() + 1);
    }

    #[test]
    fn cdr_string_padding_alignment() {
        let mut buf = Vec::new();
        write_cdr_string(&mut buf, "abc").expect("encode");
        // 4 (length) + 3 (bytes) + 1 (NUL) = 8 bytes, already aligned.
        assert_eq!(buf.len(), 8);
        assert_eq!(&buf[0..4], &4u32.to_le_bytes());
        assert_eq!(&buf[4..7], b"abc");
        assert_eq!(buf[7], 0);
    }

    #[test]
    fn cdr_string_padding_unaligned() {
        let mut buf = Vec::new();
        write_cdr_string(&mut buf, "ab").expect("encode");
        // 4 + 2 + 1 = 7, padded to 8.
        assert_eq!(buf.len(), 8);
        assert_eq!(buf[6], 0);
        assert_eq!(buf[7], 0);
    }

    #[test]
    fn cdr_octet_sequence_pads_to_four() {
        let mut buf = Vec::new();
        write_cdr_octet_sequence(&mut buf, &[0x01, 0x02, 0x03]).expect("encode");
        // 4 + 3 = 7, padded to 8.
        assert_eq!(buf.len(), 8);
        assert_eq!(&buf[0..4], &3u32.to_le_bytes());
        assert_eq!(&buf[4..7], &[0x01, 0x02, 0x03]);
        assert_eq!(buf[7], 0);
    }

    #[test]
    fn data_holder_class_id_only_round_trips_byte_for_byte() {
        // Golden vector: DataHolder { "id", [], [] }.
        let bytes = serialize_data_holder("id", &[], &[]).expect("encode");
        let expected: Vec<u8> = vec![
            // class_id string length = len("id") + 1 = 3
            0x03, 0x00, 0x00, 0x00, b'i', b'd', 0x00, 0x00, // padded to 8
            // properties count = 0
            0x00, 0x00, 0x00, 0x00, // binary_properties count = 0
            0x00, 0x00, 0x00, 0x00,
        ];
        assert_eq!(bytes, expected);
    }

    /// Golden vector for a realistic IdentityToken DataHolder, taken from a
    /// FOREIGN toolchain.
    ///
    /// These 88 bytes were produced by eProsima **Fast-CDR 2.2.5**
    /// (`libfastcdr.so.2.2.5`), not by the code under test: a fixture from our
    /// own encoder ratifies our own layout, which would hide a
    /// non-conformant `propagate` word.
    /// The generator is a small C++ program over Fast-CDR
    /// (`cdr << string << count << name << value ...`).
    ///
    /// One deliberate difference: Fast-CDR leaves whatever was in the buffer
    /// in its alignment padding (0x7F, 0x68 0x5F, 0x2F in the raw dump); HDDS
    /// zero-fills. CDR padding content is undefined and every reader skips it,
    /// so the pad bytes are zeroed here and everything else is byte-for-byte.
    #[test]
    fn identity_token_golden_vector_from_fastcdr() {
        let properties = vec![
            ("dds.cert.sn".to_string(), "CN=X".to_string(), true),
            ("dds.cert.algo".to_string(), "EC".to_string(), true),
        ];
        let bytes = serialize_data_holder("DDS:Auth:PKI-DH:1.0", &properties, &[]).expect("encode");

        let expected: Vec<u8> = vec![
            // class_id "DDS:Auth:PKI-DH:1.0" + NUL = 20, already aligned
            0x14, 0x00, 0x00, 0x00, b'D', b'D', b'S', b':', b'A', b'u', b't', b'h', b':', b'P',
            b'K', b'I', b'-', b'D', b'H', b':', b'1', b'.', b'0', 0x00,
            // properties count = 2
            0x02, 0x00, 0x00, 0x00, // property[0] name "dds.cert.sn" + NUL = 12
            0x0C, 0x00, 0x00, 0x00, b'd', b'd', b's', b'.', b'c', b'e', b'r', b't', b'.', b's',
            b'n', 0x00,
            // property[0] value "CN=X" + NUL = 5, padded to 8. NO propagate word.
            0x05, 0x00, 0x00, 0x00, b'C', b'N', b'=', b'X', 0x00, 0x00, 0x00, 0x00,
            // property[1] name "dds.cert.algo" + NUL = 14, padded to 16
            0x0E, 0x00, 0x00, 0x00, b'd', b'd', b's', b'.', b'c', b'e', b'r', b't', b'.', b'a',
            b'l', b'g', b'o', 0x00, 0x00, 0x00,
            // property[1] value "EC" + NUL = 3, padded to 4
            0x03, 0x00, 0x00, 0x00, b'E', b'C', 0x00, 0x00,
            // binary_properties count = 0
            0x00, 0x00, 0x00, 0x00,
        ];
        assert_eq!(expected.len(), 88, "the Fast-CDR dump is 88 bytes");
        assert_eq!(
            bytes, expected,
            "HDDS must emit the same DataHolder bytes as Fast-CDR"
        );
    }

    /// The same, with a binary property last, where the two encoders differ
    /// by trailing alignment: Fast-CDR stops after the last octet (101 bytes),
    /// HDDS pads the holder to a 4-byte boundary (104). The pad is required by
    /// the enclosing ParameterList, whose `parameterLength` is a multiple of
    /// four, and no reader looks past the last field - so this is stated, not
    /// hidden.
    #[test]
    fn binary_property_holder_matches_fastcdr_up_to_trailing_pad() {
        let properties = vec![("dds.perm_ca.sn".to_string(), "O=HDDS".to_string(), true)];
        let binary_properties = vec![(
            "dds.perm.digest".to_string(),
            vec![0xDE, 0xAD, 0xBE, 0xEF, 0x01],
            true,
        )];
        let bytes = serialize_data_holder(
            "DDS:Access:Permissions:1.0",
            &properties,
            &binary_properties,
        )
        .expect("encode");

        let foreign: Vec<u8> = vec![
            // class_id "DDS:Access:Permissions:1.0" + NUL = 27, padded to 28
            0x1B, 0x00, 0x00, 0x00, b'D', b'D', b'S', b':', b'A', b'c', b'c', b'e', b's', b's',
            b':', b'P', b'e', b'r', b'm', b'i', b's', b's', b'i', b'o', b'n', b's', b':', b'1',
            b'.', b'0', 0x00, 0x00, // properties count = 1
            0x01, 0x00, 0x00, 0x00, // name "dds.perm_ca.sn" + NUL = 15, padded to 16
            0x0F, 0x00, 0x00, 0x00, b'd', b'd', b's', b'.', b'p', b'e', b'r', b'm', b'_', b'c',
            b'a', b'.', b's', b'n', 0x00, 0x00, // value "O=HDDS" + NUL = 7, padded to 8
            0x07, 0x00, 0x00, 0x00, b'O', b'=', b'H', b'D', b'D', b'S', 0x00, 0x00,
            // binary_properties count = 1
            0x01, 0x00, 0x00, 0x00, // name "dds.perm.digest" + NUL = 16
            0x10, 0x00, 0x00, 0x00, b'd', b'd', b's', b'.', b'p', b'e', b'r', b'm', b'.', b'd',
            b'i', b'g', b'e', b's', b't', 0x00,
            // octet sequence, 5 bytes, no propagate word
            0x05, 0x00, 0x00, 0x00, 0xDE, 0xAD, 0xBE, 0xEF, 0x01,
        ];
        assert_eq!(foreign.len(), 101, "the Fast-CDR dump is 101 bytes");
        assert_eq!(&bytes[..foreign.len()], &foreign[..]);
        assert_eq!(&bytes[foreign.len()..], &[0x00, 0x00, 0x00]);
        assert_eq!(bytes.len() % 4, 0);
    }

    /// A property marked `propagate = false` is not sent: that is what the
    /// flag means (DDS Security v1.1 sec. 7.2.1.1), and it is never a wire field.
    #[test]
    fn a_non_propagating_property_is_omitted() {
        let properties = vec![
            ("kept".to_string(), "yes".to_string(), true),
            ("secret".to_string(), "no".to_string(), false),
        ];
        let binary_properties = vec![
            ("bin.kept".to_string(), vec![1u8, 2], true),
            ("bin.secret".to_string(), vec![3u8, 4], false),
        ];
        let bytes = serialize_data_holder("c", &properties, &binary_properties).expect("encode");
        let text = String::from_utf8_lossy(&bytes).to_string();
        assert!(text.contains("kept"), "the propagating property is sent");
        assert!(!text.contains("secret"), "the other one is not: {}", text);

        let parsed = parse_data_holder(&bytes).expect("parses");
        assert_eq!(parsed.properties.len(), 1);
        assert_eq!(parsed.binary_properties.len(), 1);
        assert_eq!(parsed.properties[0].0, "kept");
        assert!(parsed.properties[0].2, "what came back was propagated");
        assert_eq!(parsed.binary_properties[0].0, "bin.kept");
        assert!(parsed.binary_properties[0].2);
    }

    #[test]
    fn parse_data_holder_round_trips_properties() {
        // Both propagate: a non-propagating property is not on the wire and
        // so cannot round-trip (see `a_non_propagating_property_is_omitted`).
        let properties = vec![
            ("dds.cert.sn".to_string(), "CN=A".to_string(), true),
            ("dds.cert.algo".to_string(), "RSA-2048".to_string(), true),
        ];
        let bytes = serialize_data_holder("DDS:Auth:PKI-DH:1.0", &properties, &[]).expect("encode");

        let parsed = parse_data_holder(&bytes).expect("DataHolder should parse");
        assert_eq!(parsed.class_id, "DDS:Auth:PKI-DH:1.0");
        assert_eq!(parsed.properties, properties);
        assert!(parsed.binary_properties.is_empty());
    }

    #[test]
    fn parse_data_holder_round_trips_binary_properties() {
        let binary_properties = vec![(
            "dds.cert.der".to_string(),
            vec![0x30, 0x82, 0x01, 0x23, 0x45],
            true,
        )];
        let bytes =
            serialize_data_holder("DDS:Auth:PKI-DH:1.0", &[], &binary_properties).expect("encode");
        let parsed = parse_data_holder(&bytes).expect("DataHolder should parse");
        assert_eq!(parsed.class_id, "DDS:Auth:PKI-DH:1.0");
        assert!(parsed.properties.is_empty());
        assert_eq!(parsed.binary_properties, binary_properties);
    }

    #[test]
    fn parse_data_holder_rejects_truncated_input() {
        // Just the class_id length, no class_id bytes.
        let bytes = vec![0xFFu8, 0xFF, 0xFF, 0xFF];
        assert!(parse_data_holder(&bytes).is_none());

        // Empty buffer.
        assert!(parse_data_holder(&[]).is_none());

        // Class id len reasonable, but truncated before properties count.
        let mut bytes = Vec::new();
        write_cdr_string(&mut bytes, "DDS:Auth:PKI-DH:1.0").expect("encode");
        assert!(parse_data_holder(&bytes).is_none());
    }

    #[test]
    fn parse_data_holder_rejects_pathological_counts() {
        // class_id "x" + huge properties count.
        let mut bytes = Vec::new();
        write_cdr_string(&mut bytes, "x").expect("encode");
        bytes.extend_from_slice(&u32::MAX.to_le_bytes());
        assert!(parse_data_holder(&bytes).is_none());
    }

    /// Both count caps, at the boundary and on both sides of it. The
    /// binary-property cap is checked as well, because `Vec::with_capacity` of
    /// `u32::MAX` 56-byte tuples is a 223 GiB request: a real allocation
    /// below `isize::MAX`, so it aborts on a 16-64 GiB host and merely
    /// succeeds lazily on a much larger one - a locally green test and a
    /// deployment that dies.
    #[test]
    fn both_count_caps_hold_at_their_boundary() {
        // 64 properties is admitted (the payload is then truncated, which is
        // a different refusal); 65 is refused before any allocation.
        let holder_with = |prop_count: u32, bin_count: u32| {
            let mut bytes = Vec::new();
            write_cdr_string(&mut bytes, "x").expect("encode");
            bytes.extend_from_slice(&prop_count.to_le_bytes());
            if prop_count == 0 {
                bytes.extend_from_slice(&bin_count.to_le_bytes());
            }
            bytes
        };
        // prop_count: 64 passes the cap and dies on truncation; 65 is capped.
        assert!(parse_data_holder(&holder_with(64, 0)).is_none());
        assert!(parse_data_holder(&holder_with(65, 0)).is_none());
        assert!(parse_data_holder(&holder_with(u32::MAX, 0)).is_none());
        // bin_count, the cap that had no test: same three cases.
        assert!(parse_data_holder(&holder_with(0, 64)).is_none());
        assert!(parse_data_holder(&holder_with(0, 65)).is_none());
        assert!(parse_data_holder(&holder_with(0, u32::MAX)).is_none());
        // And the well-formed shape at the boundary still parses: 0 and 0.
        let holder = parse_data_holder(&holder_with(0, 0)).expect("empty holder parses");
        assert_eq!(holder.class_id, "x");
    }

    /// A wire length that would overflow `offset + len` is refused, not
    /// wrapped: on a 32-bit usize a wrapped sum would slice backwards and
    /// panic on the SPDP receive thread.
    #[test]
    fn a_length_that_would_overflow_the_offset_is_refused() {
        let mut bytes = Vec::new();
        write_cdr_string(&mut bytes, "x").expect("encode");
        bytes.extend_from_slice(&1u32.to_le_bytes()); // one property
        bytes.extend_from_slice(&u32::MAX.to_le_bytes()); // its name length
        bytes.extend_from_slice(b"junk");
        assert!(parse_data_holder(&bytes).is_none());

        let mut bytes = Vec::new();
        write_cdr_string(&mut bytes, "x").expect("encode");
        bytes.extend_from_slice(&0u32.to_le_bytes()); // no properties
        bytes.extend_from_slice(&1u32.to_le_bytes()); // one binary property
        write_cdr_string(&mut bytes, "n").expect("encode");
        bytes.extend_from_slice(&u32::MAX.to_le_bytes()); // its octet length
        bytes.extend_from_slice(b"junk");
        assert!(parse_data_holder(&bytes).is_none());
    }
}
