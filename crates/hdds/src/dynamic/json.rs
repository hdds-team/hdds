// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! JSON projection of dynamically decoded samples (feature `json`).
//!
//! One implementation for every bridge that has to hand a DDS sample to
//! something JSON-shaped: the WebSocket bridge (`tools/hdds-ws`), the
//! InfluxDB sink, and anything else that follows. It lives here rather than
//! privately inside `hdds-ws`, so that every bridge can reuse it and it can
//! be tested in isolation.
//!
//! The projection is lossy on purpose and says where:
//! - `LongDouble` becomes `null` rather than a rounded `f64`, because a
//!   silently wrong number is worse than an absent one;
//! - `u64` / `i64` keep full precision in the JSON number, which a JavaScript
//!   consumer will round; a base64 fallback exists for opaque payloads only;
//! - unions project to their active branch, enums to their label.

use std::sync::Arc;

use serde_json::{json, Map, Value};

use super::{decode_dynamic_with_version, DynamicValue, TypeDescriptor};
use crate::dds::CdrVersion;

/// Decode CDR bytes with a discovered [`TypeDescriptor`] and project to JSON.
///
/// Falls back to [`raw_cdr_to_json`] when the bytes do not match the
/// descriptor, so a bridge keeps forwarding samples instead of stalling on
/// one bad type.
pub fn cdr_to_json_dynamic(cdr_bytes: &[u8], descriptor: &Arc<TypeDescriptor>) -> Value {
    cdr_to_json_dynamic_with_version(cdr_bytes, descriptor, CdrVersion::Xcdr1)
}

/// Decode a headerless CDR body with its actual wire encoding version.
/// Use the version returned by `RawDataReader::try_take_raw_with_encoding`.
pub fn cdr_to_json_dynamic_with_version(
    cdr_bytes: &[u8],
    descriptor: &Arc<TypeDescriptor>,
    version: CdrVersion,
) -> Value {
    match decode_dynamic_with_version(cdr_bytes, descriptor, version) {
        Ok(data) => dynamic_value_to_json(data.value()),
        Err(_) => raw_cdr_to_json(cdr_bytes),
    }
}

/// Project a [`DynamicValue`] onto JSON.
pub fn dynamic_value_to_json(value: &DynamicValue) -> Value {
    match value {
        DynamicValue::Bool(b) => Value::Bool(*b),
        DynamicValue::U8(n) => json!(*n),
        DynamicValue::U16(n) => json!(*n),
        DynamicValue::U32(n) => json!(*n),
        DynamicValue::U64(n) => json!(*n),
        DynamicValue::I8(n) => json!(*n),
        DynamicValue::I16(n) => json!(*n),
        DynamicValue::I32(n) => json!(*n),
        DynamicValue::I64(n) => json!(*n),
        DynamicValue::F32(n) => json!(*n),
        DynamicValue::F64(n) => json!(*n),
        // 128-bit float has no JSON number: report absence, never a rounded
        // value that would read as measured data.
        DynamicValue::LongDouble(_) => Value::Null,
        DynamicValue::Char(c) => json!(c.to_string()),
        DynamicValue::String(s) => Value::String(s.clone()),
        DynamicValue::WString(s) => Value::String(s.clone()),
        DynamicValue::Struct(fields) => {
            let mut obj = Map::new();
            for (name, val) in fields {
                obj.insert(name.clone(), dynamic_value_to_json(val));
            }
            Value::Object(obj)
        }
        DynamicValue::Sequence(items) | DynamicValue::Array(items) => {
            Value::Array(items.iter().map(dynamic_value_to_json).collect())
        }
        DynamicValue::Enum(_, name) => Value::String(name.clone()),
        DynamicValue::Union(_, _, value) => dynamic_value_to_json(value),
        DynamicValue::Null => Value::Null,
    }
}

/// Best-effort projection when no TypeObject is available.
///
/// Recognises the ROS 2 `std_msgs/String` shape (4-byte length, bytes, NUL)
/// and otherwise reports the payload as base64 with its length. The `_raw`
/// field is always present, so a consumer can always recover the bytes.
pub fn raw_cdr_to_json(cdr_bytes: &[u8]) -> Value {
    if cdr_bytes.is_empty() {
        return Value::Null;
    }
    let base64_payload = base64_encode(cdr_bytes);

    if cdr_bytes.len() >= 4 {
        let str_len =
            u32::from_le_bytes([cdr_bytes[0], cdr_bytes[1], cdr_bytes[2], cdr_bytes[3]]) as usize;
        // Checked, not `str_len + 4`: the length comes off the wire, and on a
        // 32-bit target a value near u32::MAX wraps, passes the comparison,
        // and panics in the slice below.
        if str_len > 0
            && str_len
                .checked_add(4)
                .is_some_and(|end| end <= cdr_bytes.len())
        {
            if let Ok(s) = std::str::from_utf8(&cdr_bytes[4..4 + str_len.saturating_sub(1)]) {
                return json!({ "data": s, "_raw": base64_payload });
            }
        }
    }

    json!({ "_raw": base64_payload, "_bytes": cdr_bytes.len() })
}

/// Standard base64 with padding. Small and local: the crate does not take a
/// base64 dependency for one encoder.
pub fn base64_encode(data: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::with_capacity(data.len().div_ceil(3) * 4);

    for chunk in data.chunks(3) {
        let b0 = chunk[0] as usize;
        let b1 = chunk.get(1).copied().unwrap_or(0) as usize;
        let b2 = chunk.get(2).copied().unwrap_or(0) as usize;

        result.push(CHARS[b0 >> 2] as char);
        result.push(CHARS[((b0 & 0x03) << 4) | (b1 >> 4)] as char);
        if chunk.len() > 1 {
            result.push(CHARS[((b1 & 0x0F) << 2) | (b2 >> 6)] as char);
        } else {
            result.push('=');
        }
        if chunk.len() > 2 {
            result.push(CHARS[b2 & 0x3F] as char);
        } else {
            result.push('=');
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_version_controls_u64_alignment_and_appendable_framing() {
        use crate::dynamic::{
            type_descriptor_from_xtypes, type_descriptor_to_xtypes, Extensibility, FieldDescriptor,
            PrimitiveKind,
        };
        let descriptor = TypeDescriptor::struct_type(
            "Stamp",
            vec![
                FieldDescriptor::new(
                    "id",
                    Arc::new(TypeDescriptor::primitive("u32", PrimitiveKind::U32)),
                ),
                FieldDescriptor::new(
                    "time",
                    Arc::new(TypeDescriptor::primitive("u64", PrimitiveKind::U64)),
                ),
            ],
        );
        let timestamp = 1234567890123u64;
        let expected = json!({"id": 7, "time": timestamp});
        let mut xcdr2 = 7u32.to_le_bytes().to_vec();
        xcdr2.extend_from_slice(&timestamp.to_le_bytes());
        let mut xcdr1 = 7u32.to_le_bytes().to_vec();
        xcdr1.extend_from_slice(&[0; 4]);
        xcdr1.extend_from_slice(&timestamp.to_le_bytes());
        let final_desc = Arc::new(descriptor.clone().with_extensibility(Extensibility::Final));
        assert_eq!(
            cdr_to_json_dynamic_with_version(&xcdr1, &final_desc, CdrVersion::Xcdr1),
            expected
        );
        assert_eq!(
            cdr_to_json_dynamic_with_version(&xcdr2, &final_desc, CdrVersion::Xcdr2),
            expected
        );
        assert!(cdr_to_json_dynamic(&xcdr2, &final_desc)
            .get("_raw")
            .is_some());
        let appendable = descriptor.with_extensibility(Extensibility::Appendable);
        let type_object = type_descriptor_to_xtypes(&appendable).unwrap();
        let discovered = type_descriptor_from_xtypes(&type_object);
        assert_eq!(discovered.extensibility, Extensibility::Appendable);
        let mut delimited = 12u32.to_le_bytes().to_vec();
        delimited.extend_from_slice(&xcdr2);
        assert_eq!(
            cdr_to_json_dynamic_with_version(&delimited, &discovered, CdrVersion::Xcdr2),
            expected
        );
        assert_eq!(
            cdr_to_json_dynamic_with_version(&xcdr1, &discovered, CdrVersion::Xcdr1),
            expected
        );
    }

    #[test]
    fn primitives_and_containers_project_as_expected() {
        assert_eq!(
            dynamic_value_to_json(&DynamicValue::Bool(true)),
            json!(true)
        );
        assert_eq!(dynamic_value_to_json(&DynamicValue::U32(7)), json!(7));
        assert_eq!(dynamic_value_to_json(&DynamicValue::F64(2.5)), json!(2.5));
        assert_eq!(
            dynamic_value_to_json(&DynamicValue::String("hi".to_string())),
            json!("hi")
        );
        assert_eq!(
            dynamic_value_to_json(&DynamicValue::Sequence(vec![
                DynamicValue::I32(1),
                DynamicValue::I32(2)
            ])),
            json!([1, 2])
        );
        assert_eq!(
            dynamic_value_to_json(&DynamicValue::Struct(std::collections::HashMap::from([
                ("id".to_string(), DynamicValue::U32(3)),
                ("name".to_string(), DynamicValue::String("s".to_string())),
            ]))),
            json!({"id": 3, "name": "s"})
        );
    }

    #[test]
    fn long_double_is_null_not_a_rounded_zero() {
        // The hdds-ws version returned 0.0 here, which a dashboard would plot
        // as a measurement.
        assert_eq!(
            dynamic_value_to_json(&DynamicValue::LongDouble(
                [0xAA; super::super::LONG_DOUBLE_SIZE]
            )),
            Value::Null
        );
    }

    #[test]
    fn raw_fallback_recognises_a_ros_string_and_always_keeps_the_bytes() {
        let mut cdr = Vec::new();
        cdr.extend_from_slice(&6u32.to_le_bytes());
        cdr.extend_from_slice(b"hello");
        cdr.push(0);
        let json = raw_cdr_to_json(&cdr);
        assert_eq!(json["data"], "hello");
        assert!(json["_raw"].is_string());

        let opaque = raw_cdr_to_json(&[0xFF, 0xFE, 0xFD]);
        assert_eq!(opaque["_bytes"], 3);
        assert!(opaque["_raw"].is_string());

        assert_eq!(raw_cdr_to_json(&[]), Value::Null);
    }

    /// A wire length near `u32::MAX` must not be added to an offset without
    /// a check: on a 32-bit target the sum wraps, the bound test passes and
    /// the slice panics. Harmless on 64-bit, fatal where the sink runs on an
    /// embedded gateway.
    #[test]
    fn a_hostile_string_length_is_projected_as_opaque_bytes() {
        for len in [u32::MAX, u32::MAX - 3, 0x8000_0000, 0xFFFF_FFFC] {
            let mut cdr = len.to_le_bytes().to_vec();
            cdr.extend_from_slice(b"short");
            let value = raw_cdr_to_json(&cdr);
            assert!(
                value.get("data").is_none(),
                "length {} was treated as a string",
                len
            );
            assert_eq!(value["_bytes"], 9);
        }
    }

    #[test]
    fn base64_matches_the_reference_vectors() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foob"), "Zm9vYg==");
        assert_eq!(base64_encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
    }
}
