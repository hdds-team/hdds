// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Integration tests for dynamic types module.

use super::*;
use std::sync::Arc;

// ---------------------------------------------------------------------------
// Union CDR roundtrip tests
// ---------------------------------------------------------------------------

/// Build a union type with U8 discriminator and several primitive cases.
fn make_u8_disc_union() -> Arc<TypeDescriptor> {
    let disc = Arc::new(TypeDescriptor::primitive("", PrimitiveKind::U8));
    let cases = vec![
        UnionCase::new(
            "x1",
            vec![1],
            Arc::new(TypeDescriptor::primitive("", PrimitiveKind::U8)),
        ),
        UnionCase::new(
            "x6",
            vec![6],
            Arc::new(TypeDescriptor::primitive("", PrimitiveKind::I16)),
        ),
        UnionCase::new(
            "x7",
            vec![7],
            Arc::new(TypeDescriptor::primitive("", PrimitiveKind::I32)),
        ),
        UnionCase::new(
            "x10",
            vec![10],
            Arc::new(TypeDescriptor::primitive("", PrimitiveKind::F32)),
        ),
    ];
    Arc::new(TypeDescriptor::new(
        "Test::union_primitives_final",
        TypeKind::Union(UnionDescriptor::new(disc, cases)),
    ))
}

/// Build a union type with U32 discriminator (mirrors union_1 in OMG corpus).
fn make_u32_disc_union() -> Arc<TypeDescriptor> {
    let disc = Arc::new(TypeDescriptor::primitive("", PrimitiveKind::U32));
    let cases = vec![
        UnionCase::new(
            "x1",
            vec![1],
            Arc::new(TypeDescriptor::primitive("", PrimitiveKind::I16)),
        ),
        UnionCase::new(
            "x2",
            vec![2],
            Arc::new(TypeDescriptor::primitive("", PrimitiveKind::I32)),
        ),
        UnionCase::new(
            "x3",
            vec![3],
            Arc::new(TypeDescriptor::primitive("", PrimitiveKind::I32)),
        ),
    ];
    Arc::new(TypeDescriptor::new(
        "Test::union_1",
        TypeKind::Union(UnionDescriptor::new(disc, cases)),
    ))
}

#[test]
fn union_u8_disc_roundtrip_u8_case() {
    let td = make_u8_disc_union();
    // discriminator 0x01, case x1 = u8 value 42
    let val = DynamicValue::Union(0x01, "x1".to_string(), Box::new(DynamicValue::U8(42)));
    let data = DynamicData::from_value(&td, val).expect("from_value");
    let encoded = encode_dynamic(&data).expect("encode");
    // Expect: 1 byte disc (0x01) + 1 byte value (42) = 2 bytes (no padding for U8)
    assert_eq!(&encoded, &[0x01, 42]);
    let decoded = decode_dynamic(&encoded, &td).expect("decode");
    match decoded.value() {
        DynamicValue::Union(d, case, inner) => {
            assert_eq!(*d, 1);
            assert_eq!(case, "x1");
            assert!(matches!(**inner, DynamicValue::U8(42)));
        }
        v => panic!("expected Union, got {:?}", v),
    }
}

#[test]
fn union_u8_disc_roundtrip_i32_case() {
    let td = make_u8_disc_union();
    // discriminator 0x07, case x7 = i32 value 123
    let val = DynamicValue::Union(0x07, "x7".to_string(), Box::new(DynamicValue::I32(123)));
    let data = DynamicData::from_value(&td, val).expect("from_value");
    let encoded = encode_dynamic(&data).expect("encode");
    // Expect: 1 byte disc (0x07) + 3 bytes padding (align 4) + 4 bytes i32
    assert_eq!(encoded.len(), 8);
    assert_eq!(encoded[0], 0x07);
    assert_eq!(&encoded[4..], &123i32.to_le_bytes());
    let decoded = decode_dynamic(&encoded, &td).expect("decode");
    match decoded.value() {
        DynamicValue::Union(d, case, inner) => {
            assert_eq!(*d, 7);
            assert_eq!(case, "x7");
            assert!(matches!(**inner, DynamicValue::I32(123)));
        }
        v => panic!("expected Union, got {:?}", v),
    }
}

#[test]
fn union_u32_disc_roundtrip() {
    let td = make_u32_disc_union();
    // discriminator 2, case x2 = i32 value -5
    let val = DynamicValue::Union(2, "x2".to_string(), Box::new(DynamicValue::I32(-5)));
    let data = DynamicData::from_value(&td, val).expect("from_value");
    let encoded = encode_dynamic(&data).expect("encode");
    // Expect: 4 bytes disc (u32=2) + 4 bytes i32 = 8 bytes
    assert_eq!(encoded.len(), 8);
    assert_eq!(u32::from_le_bytes(encoded[..4].try_into().unwrap()), 2u32);
    assert_eq!(i32::from_le_bytes(encoded[4..].try_into().unwrap()), -5i32);
    let decoded = decode_dynamic(&encoded, &td).expect("decode");
    match decoded.value() {
        DynamicValue::Union(d, case, inner) => {
            assert_eq!(*d, 2);
            assert_eq!(case, "x2");
            assert!(matches!(**inner, DynamicValue::I32(-5)));
        }
        v => panic!("expected Union, got {:?}", v),
    }
}

#[test]
fn union_descriptor_to_xtypes_emits_union_type_object() {
    use crate::xtypes::CompleteTypeObject;
    let td = make_u32_disc_union();
    let type_obj = type_descriptor_to_xtypes(&td).expect("must emit CompleteTypeObject");
    match type_obj {
        CompleteTypeObject::Union(u) => {
            assert_eq!(u.header.detail.type_name, "Test::union_1");
            assert_eq!(u.member_seq.len(), 3);
            assert_eq!(u.member_seq[0].detail.name, "x1");
            assert_eq!(u.member_seq[1].detail.name, "x2");
            assert_eq!(u.member_seq[2].detail.name, "x3");
        }
        other => panic!("expected Union type object, got {:?}", other),
    }
}

#[test]
fn test_full_workflow() {
    // 1. Build type descriptor at runtime
    let sensor_type = Arc::new(
        TypeDescriptorBuilder::new("SensorReading")
            .field("sensor_id", PrimitiveKind::U32)
            .field("temperature", PrimitiveKind::F64)
            .field("humidity", PrimitiveKind::F32)
            .field("timestamp", PrimitiveKind::U64)
            .string_field("location")
            .build(),
    );

    // 2. Create and populate data
    let mut data = DynamicData::new(&sensor_type);
    data.set("sensor_id", 42u32).expect("set sensor_id");
    data.set("temperature", 23.5f64).expect("set temperature");
    data.set("humidity", 65.0f32).expect("set humidity");
    data.set("timestamp", 1702900000u64).expect("set timestamp");
    data.set("location", "Building A").expect("set location");

    // 3. Verify data
    assert_eq!(data.get::<u32>("sensor_id").unwrap(), 42);
    assert_eq!(data.get::<f64>("temperature").unwrap(), 23.5);
    assert_eq!(data.get::<f32>("humidity").unwrap(), 65.0);
    assert_eq!(data.get::<u64>("timestamp").unwrap(), 1702900000);
    assert_eq!(data.get::<String>("location").unwrap(), "Building A");

    // 4. Encode to CDR
    let encoded = encode_dynamic(&data).expect("encode");
    assert!(!encoded.is_empty());

    // 5. Decode from CDR
    let decoded = decode_dynamic(&encoded, &sensor_type).expect("decode");
    assert_eq!(decoded.get::<u32>("sensor_id").unwrap(), 42);
    assert_eq!(decoded.get::<f64>("temperature").unwrap(), 23.5);
    assert_eq!(decoded.get::<String>("location").unwrap(), "Building A");
}

#[test]
fn test_complex_nested_types() {
    // Define nested types
    let vector3_type = Arc::new(
        TypeDescriptorBuilder::new("Vector3")
            .field("x", PrimitiveKind::F64)
            .field("y", PrimitiveKind::F64)
            .field("z", PrimitiveKind::F64)
            .build(),
    );

    let pose_type = Arc::new(
        TypeDescriptorBuilder::new("Pose")
            .nested_field("position", vector3_type.clone())
            .nested_field("orientation", vector3_type.clone())
            .build(),
    );

    // Create data
    let mut data = DynamicData::new(&pose_type);

    // Set nested values manually
    if let DynamicValue::Struct(ref mut fields) = data.value_mut() {
        let mut position = std::collections::HashMap::new();
        position.insert("x".to_string(), DynamicValue::F64(1.0));
        position.insert("y".to_string(), DynamicValue::F64(2.0));
        position.insert("z".to_string(), DynamicValue::F64(3.0));
        fields.insert("position".to_string(), DynamicValue::Struct(position));

        let mut orientation = std::collections::HashMap::new();
        orientation.insert("x".to_string(), DynamicValue::F64(0.0));
        orientation.insert("y".to_string(), DynamicValue::F64(0.0));
        orientation.insert("z".to_string(), DynamicValue::F64(1.0));
        fields.insert("orientation".to_string(), DynamicValue::Struct(orientation));
    }

    // Encode and decode
    let encoded = encode_dynamic(&data).expect("encode");
    let decoded = decode_dynamic(&encoded, &pose_type).expect("decode");

    let pos = decoded.get_field("position").unwrap();
    assert_eq!(pos.get_field("x").and_then(|v| v.as_f64()), Some(1.0));
    assert_eq!(pos.get_field("y").and_then(|v| v.as_f64()), Some(2.0));
    assert_eq!(pos.get_field("z").and_then(|v| v.as_f64()), Some(3.0));
}

#[test]
#[cfg(feature = "dynamic-types")]
fn test_enum_type() {
    use crate::dynamic::builder::EnumBuilder;

    let status_type = Arc::new(
        EnumBuilder::new("Status")
            .variant("UNKNOWN")
            .variant("ACTIVE")
            .variant("INACTIVE")
            .variant("ERROR")
            .build(),
    );

    let msg_type = Arc::new(
        TypeDescriptorBuilder::new("StatusMessage")
            .field("id", PrimitiveKind::U32)
            .field_with_type("status", status_type)
            .build(),
    );

    let mut data = DynamicData::new(&msg_type);
    data.set("id", 1u32).expect("set id");

    // Set enum value
    if let DynamicValue::Struct(ref mut fields) = data.value_mut() {
        fields.insert(
            "status".to_string(),
            DynamicValue::Enum(1, "ACTIVE".to_string()),
        );
    }

    let encoded = encode_dynamic(&data).expect("encode");
    let decoded = decode_dynamic(&encoded, &msg_type).expect("decode");

    let status = decoded.get_field("status").unwrap();
    assert_eq!(status.enum_variant(), Some("ACTIVE"));
    assert_eq!(status.enum_value(), Some(1));
}

#[test]
fn test_sequence_operations() {
    let list_type = Arc::new(
        TypeDescriptorBuilder::new("IntList")
            .sequence_field("values", PrimitiveKind::I32)
            .build(),
    );

    let mut data = DynamicData::new(&list_type);

    // Build sequence manually
    if let DynamicValue::Struct(ref mut fields) = data.value_mut() {
        fields.insert(
            "values".to_string(),
            DynamicValue::Sequence(vec![
                DynamicValue::I32(10),
                DynamicValue::I32(20),
                DynamicValue::I32(30),
            ]),
        );
    }

    let encoded = encode_dynamic(&data).expect("encode");
    let decoded = decode_dynamic(&encoded, &list_type).expect("decode");

    let values = decoded.get_field("values").unwrap();
    let seq = values.as_sequence().unwrap();
    assert_eq!(seq.len(), 3);
    assert_eq!(seq[0].as_i32(), Some(10));
    assert_eq!(seq[1].as_i32(), Some(20));
    assert_eq!(seq[2].as_i32(), Some(30));
}

#[test]
fn test_array_type() {
    let matrix_type = Arc::new(
        TypeDescriptorBuilder::new("Matrix2x2")
            .array_field("data", PrimitiveKind::F32, 4)
            .build(),
    );

    let mut data = DynamicData::new(&matrix_type);

    // Set array values
    if let DynamicValue::Struct(ref mut fields) = data.value_mut() {
        fields.insert(
            "data".to_string(),
            DynamicValue::Array(vec![
                DynamicValue::F32(1.0),
                DynamicValue::F32(0.0),
                DynamicValue::F32(0.0),
                DynamicValue::F32(1.0),
            ]),
        );
    }

    let encoded = encode_dynamic(&data).expect("encode");
    let decoded = decode_dynamic(&encoded, &matrix_type).expect("decode");

    let arr = decoded.get_field("data").unwrap();
    let elements = arr.as_sequence().unwrap();
    assert_eq!(elements.len(), 4);
    assert_eq!(elements[0].as_f32(), Some(1.0));
    assert_eq!(elements[3].as_f32(), Some(1.0));
}

#[test]
fn test_type_introspection() {
    let desc = TypeDescriptorBuilder::new("TestStruct")
        .field("a", PrimitiveKind::I32)
        .field("b", PrimitiveKind::F64)
        .string_field("c")
        .sequence_field("d", PrimitiveKind::U8)
        .build();

    assert_eq!(desc.name, "TestStruct");
    assert!(desc.is_struct());

    let fields = desc.fields().unwrap();
    assert_eq!(fields.len(), 4);

    assert_eq!(desc.field_index("a"), Some(0));
    assert_eq!(desc.field_index("b"), Some(1));
    assert_eq!(desc.field_index("c"), Some(2));
    assert_eq!(desc.field_index("d"), Some(3));
    assert_eq!(desc.field_index("e"), None);
}

#[test]
fn test_empty_string() {
    let desc = Arc::new(
        TypeDescriptorBuilder::new("Message")
            .string_field("text")
            .build(),
    );

    let mut data = DynamicData::new(&desc);
    data.set("text", "").unwrap();

    let encoded = encode_dynamic(&data).expect("encode");
    let decoded = decode_dynamic(&encoded, &desc).expect("decode");

    assert_eq!(decoded.get::<String>("text").unwrap(), "");
}

#[test]
fn test_unicode_string() {
    let desc = Arc::new(
        TypeDescriptorBuilder::new("UnicodeMessage")
            .string_field("text")
            .build(),
    );

    let mut data = DynamicData::new(&desc);
    data.set("text", "Hello \u{4e16}\u{754c}! [*]").unwrap();

    let encoded = encode_dynamic(&data).expect("encode");
    let decoded = decode_dynamic(&encoded, &desc).expect("decode");

    assert_eq!(
        decoded.get::<String>("text").unwrap(),
        "Hello \u{4e16}\u{754c}! [*]"
    );
}

#[test]
fn test_large_sequence_roundtrip() {
    let desc = Arc::new(
        TypeDescriptorBuilder::new("LargeSeq")
            .sequence_field("values", PrimitiveKind::U32)
            .build(),
    );

    let mut data = DynamicData::new(&desc);
    if let DynamicValue::Struct(ref mut fields) = data.value_mut() {
        let mut seq = Vec::with_capacity(4096);
        for i in 0..4096u32 {
            seq.push(DynamicValue::U32(i));
        }
        fields.insert("values".to_string(), DynamicValue::Sequence(seq));
    }

    let encoded = encode_dynamic(&data).expect("encode");
    let decoded = decode_dynamic(&encoded, &desc).expect("decode");

    let values = decoded.get_field("values").unwrap();
    let seq = values.as_sequence().unwrap();
    assert_eq!(seq.len(), 4096);
    assert_eq!(seq[0].as_u32(), Some(0));
    assert_eq!(seq[4095].as_u32(), Some(4095));
}

// ---------------------------------------------------------------------------
// TryConstructKind tests
// ---------------------------------------------------------------------------

/// Build CDR bytes for a struct containing a single i32 sequence.
/// `values` are encoded as a CDR sequence (4-byte len header + elements).
fn encode_seq_struct(values: &[i32]) -> Vec<u8> {
    let mut buf = Vec::new();
    let len = values.len() as u32;
    buf.extend(&len.to_le_bytes());
    for &v in values {
        buf.extend(&v.to_le_bytes());
    }
    buf
}

#[test]
fn test_tryconstruct_discard_sequence_over_bound_returns_error() {
    // Subscriber type: sequence<int32, max=10> with tryConstruct=Discard.
    let i32_type = Arc::new(TypeDescriptor::primitive("int32", PrimitiveKind::I32));
    let seq_type = Arc::new(TypeDescriptor::new(
        "",
        TypeKind::Sequence(SequenceDescriptor::bounded(i32_type, 10)),
    ));
    let field = FieldDescriptor::new("x1", seq_type).with_try_construct(TryConstructKind::Discard);
    let desc = Arc::new(TypeDescriptor::struct_type(
        "seq_int32x10_discard",
        vec![field],
    ));

    // Publisher sends 20 elements.
    let cdr = encode_seq_struct(&(0..20i32).collect::<Vec<_>>());
    let result = decode_dynamic(&cdr, &desc);
    assert!(
        result.is_err(),
        "Discard policy should return error when sequence exceeds bound"
    );
}

#[test]
fn test_tryconstruct_trim_sequence_over_bound_truncates() {
    // Subscriber type: sequence<int32, max=10> with tryConstruct=Trim.
    let i32_type = Arc::new(TypeDescriptor::primitive("int32", PrimitiveKind::I32));
    let seq_type = Arc::new(TypeDescriptor::new(
        "",
        TypeKind::Sequence(SequenceDescriptor::bounded(i32_type, 10)),
    ));
    let field = FieldDescriptor::new("x1", seq_type).with_try_construct(TryConstructKind::Trim);
    let desc = Arc::new(TypeDescriptor::struct_type(
        "seq_int32x10_trim",
        vec![field],
    ));

    // Publisher sends 20 elements [0..19].
    let cdr = encode_seq_struct(&(0..20i32).collect::<Vec<_>>());
    let decoded = decode_dynamic(&cdr, &desc).expect("Trim should succeed");
    let field_val = decoded.get_field("x1").expect("field x1");
    let seq = field_val.as_sequence().expect("sequence");
    // Only first 10 elements kept.
    assert_eq!(seq.len(), 10, "Trim should truncate to local bound");
    assert_eq!(seq[0].as_i32(), Some(0));
    assert_eq!(seq[9].as_i32(), Some(9));
}

#[test]
fn test_tryconstruct_use_default_sequence_over_bound_returns_empty() {
    // Subscriber type: sequence<int32, max=10> with tryConstruct=UseDefault.
    let i32_type = Arc::new(TypeDescriptor::primitive("int32", PrimitiveKind::I32));
    let seq_type = Arc::new(TypeDescriptor::new(
        "",
        TypeKind::Sequence(SequenceDescriptor::bounded(i32_type, 10)),
    ));
    let field =
        FieldDescriptor::new("x1", seq_type).with_try_construct(TryConstructKind::UseDefault);
    let desc = Arc::new(TypeDescriptor::struct_type(
        "seq_int32x10_default",
        vec![field],
    ));

    // Publisher sends 20 elements.
    let cdr = encode_seq_struct(&(0..20i32).collect::<Vec<_>>());
    let decoded = decode_dynamic(&cdr, &desc).expect("UseDefault should succeed");
    let field_val = decoded.get_field("x1").expect("field x1");
    let seq = field_val.as_sequence().expect("sequence");
    // UseDefault: return empty sequence.
    assert_eq!(seq.len(), 0, "UseDefault should return empty sequence");
}

#[test]
fn test_tryconstruct_field_descriptor_roundtrip() {
    // Verify TryConstructKind survives a FieldDescriptor build + read.
    let i32_type = Arc::new(TypeDescriptor::primitive("int32", PrimitiveKind::I32));
    let seq_type = Arc::new(TypeDescriptor::new(
        "",
        TypeKind::Sequence(SequenceDescriptor::bounded(i32_type, 5)),
    ));
    let fd_discard =
        FieldDescriptor::new("f", seq_type.clone()).with_try_construct(TryConstructKind::Discard);
    let fd_trim =
        FieldDescriptor::new("f", seq_type.clone()).with_try_construct(TryConstructKind::Trim);
    let fd_default =
        FieldDescriptor::new("f", seq_type).with_try_construct(TryConstructKind::UseDefault);

    assert_eq!(fd_discard.try_construct, TryConstructKind::Discard);
    assert_eq!(fd_trim.try_construct, TryConstructKind::Trim);
    assert_eq!(fd_default.try_construct, TryConstructKind::UseDefault);
}

#[test]
fn test_tryconstruct_within_bound_always_succeeds() {
    // Even with Discard policy, sequences within the bound are accepted.
    let i32_type = Arc::new(TypeDescriptor::primitive("int32", PrimitiveKind::I32));
    let seq_type = Arc::new(TypeDescriptor::new(
        "",
        TypeKind::Sequence(SequenceDescriptor::bounded(i32_type, 20)),
    ));
    let field = FieldDescriptor::new("x1", seq_type).with_try_construct(TryConstructKind::Discard);
    let desc = Arc::new(TypeDescriptor::struct_type("within_bound", vec![field]));

    // Send 10 elements (within bound of 20).
    let cdr = encode_seq_struct(&(0..10i32).collect::<Vec<_>>());
    let decoded = decode_dynamic(&cdr, &desc).expect("within-bound decode must succeed");
    let field_val = decoded.get_field("x1").expect("field x1");
    let seq = field_val.as_sequence().expect("sequence");
    assert_eq!(seq.len(), 10);
}

// ---------------------------------------------------------------------------
// Enum TryConstruct CDR decode tests (DDS-XTypes v1.3 sec. 7.5.1.4)
// ---------------------------------------------------------------------------

/// Build an enum type descriptor with the given variants.
/// The first call-site variant is optionally marked as defaultLiteral.
fn make_enum_desc(name: &str, variants: Vec<EnumVariant>) -> Arc<TypeDescriptor> {
    Arc::new(TypeDescriptor::new(
        name,
        TypeKind::Enum(EnumDescriptor::new(variants)),
    ))
}

/// Encode a single u32 enum value as 4-byte LE into a struct-shaped CDR buffer.
/// For a Final struct with one enum field there is no DHEADER prefix, so the
/// raw bytes are exactly the 4-byte enum value.
fn encode_enum_struct(val: u32) -> Vec<u8> {
    val.to_le_bytes().to_vec()
}

#[test]
fn test_decode_enum_unknown_value_use_default_falls_back() {
    // Subscriber type has E2 = {VAL1=0 (default)}.
    // Publisher sends value 2, which is not in E2.
    // With UseDefault the decoder must substitute the default literal VAL1=0.
    let e2 = make_enum_desc(
        "Test::E2",
        vec![EnumVariant::new("VAL1", 0).with_default_literal()],
    );
    let field = FieldDescriptor::new("x1", e2).with_try_construct(TryConstructKind::UseDefault);
    let desc = Arc::new(TypeDescriptor::struct_type(
        "Test::struct_enum_2_default",
        vec![field],
    ));

    let cdr = encode_enum_struct(2);
    let decoded =
        decode_dynamic(&cdr, &desc).expect("UseDefault must succeed on unknown enum value");
    let fv = decoded.get_field("x1").expect("field x1");
    assert_eq!(
        fv.enum_value(),
        Some(0),
        "UseDefault should return default literal value"
    );
    assert_eq!(
        fv.enum_variant(),
        Some("VAL1"),
        "UseDefault should return default literal name"
    );
}

#[test]
fn test_decode_enum_unknown_value_discard_returns_err() {
    // Subscriber type has E2 = {VAL1=0}.
    // Publisher sends value 2, which is not in E2.
    // With Discard the decoder must return an error causing sample rejection.
    let e2 = make_enum_desc(
        "Test::E2",
        vec![EnumVariant::new("VAL1", 0).with_default_literal()],
    );
    let field = FieldDescriptor::new("x1", e2).with_try_construct(TryConstructKind::Discard);
    let desc = Arc::new(TypeDescriptor::struct_type(
        "Test::struct_enum_2_discard",
        vec![field],
    ));

    let cdr = encode_enum_struct(2);
    let result = decode_dynamic(&cdr, &desc);
    assert!(
        result.is_err(),
        "Discard policy must return error on unknown enum value"
    );
}

#[test]
fn test_decode_enum_known_value_passes() {
    // Subscriber type has E1 = {VAL1=0, VAL2=1, VAL3=2}.
    // Publisher sends value 2, which IS in E1.
    // The policy is irrelevant; the known value must pass through unchanged.
    let e1 = make_enum_desc(
        "Test::E1",
        vec![
            EnumVariant::new("VAL1", 0),
            EnumVariant::new("VAL2", 1),
            EnumVariant::new("VAL3", 2),
        ],
    );
    let field = FieldDescriptor::new("x1", e1).with_try_construct(TryConstructKind::UseDefault);
    let desc = Arc::new(TypeDescriptor::struct_type(
        "Test::struct_enum_1",
        vec![field],
    ));

    let cdr = encode_enum_struct(2);
    let decoded = decode_dynamic(&cdr, &desc).expect("known value must succeed");
    let fv = decoded.get_field("x1").expect("field x1");
    assert_eq!(
        fv.enum_value(),
        Some(2),
        "known enum value must be returned verbatim"
    );
    assert_eq!(
        fv.enum_variant(),
        Some("VAL3"),
        "known enum variant name must be returned"
    );
}

// ---------------------------------------------------------------------------
// Union extensibility framing tests (wave D)
//
// Expected bodies follow DDS-XTypes v1.3 section 7.4 (XCDR1 PL_CDR
// parameter list, XCDR2 DHEADER + EMHEADER list); each byte is annotated.
// ---------------------------------------------------------------------------

/// union_primitives_mutable shape: uint8 discriminator, x5 = char8 at
/// declaration position 5 (wire member id 5).
fn make_mutable_u8_disc_union() -> Arc<TypeDescriptor> {
    let disc = Arc::new(TypeDescriptor::primitive("", PrimitiveKind::U8));
    let cases = vec![
        UnionCase::new(
            "x1",
            vec![1],
            Arc::new(TypeDescriptor::primitive("", PrimitiveKind::U8)),
        ),
        UnionCase::new(
            "x2",
            vec![2],
            Arc::new(TypeDescriptor::primitive("", PrimitiveKind::U16)),
        ),
        UnionCase::new(
            "x3",
            vec![3],
            Arc::new(TypeDescriptor::primitive("", PrimitiveKind::U32)),
        ),
        UnionCase::new(
            "x4",
            vec![4],
            Arc::new(TypeDescriptor::primitive("", PrimitiveKind::U64)),
        ),
        UnionCase::new(
            "x5",
            vec![5],
            Arc::new(TypeDescriptor::primitive("", PrimitiveKind::Char)),
        ),
    ];
    Arc::new(
        TypeDescriptor::new(
            "Test::union_primitives_mutable",
            TypeKind::Union(UnionDescriptor::new(disc, cases)),
        )
        .with_extensibility(Extensibility::Mutable),
    )
}

/// union_mutable_a shape: uint32 discriminator, x3 = int64 at declaration
/// position 3 (wire member id 3).
fn make_mutable_u32_disc_union() -> Arc<TypeDescriptor> {
    let disc = Arc::new(TypeDescriptor::primitive("", PrimitiveKind::U32));
    let cases = vec![
        UnionCase::new(
            "x1",
            vec![1],
            Arc::new(TypeDescriptor::primitive("", PrimitiveKind::I16)),
        ),
        UnionCase::new(
            "x2",
            vec![2],
            Arc::new(TypeDescriptor::primitive("", PrimitiveKind::I32)),
        ),
        UnionCase::new(
            "x3",
            vec![3],
            Arc::new(TypeDescriptor::primitive("", PrimitiveKind::I64)),
        ),
        UnionCase::new(
            "x4",
            vec![4],
            Arc::new(TypeDescriptor::primitive("", PrimitiveKind::U16)),
        ),
        UnionCase::new(
            "x5",
            vec![5],
            Arc::new(TypeDescriptor::primitive("", PrimitiveKind::U32)),
        ),
    ];
    Arc::new(
        TypeDescriptor::new(
            "Test::union_mutable_a",
            TypeKind::Union(UnionDescriptor::new(disc, cases)),
        )
        .with_extensibility(Extensibility::Mutable),
    )
}

/// union_primitives_appendable shape (uint8 disc, char8 branch at slot 5).
fn make_appendable_u8_disc_union() -> Arc<TypeDescriptor> {
    let disc = Arc::new(TypeDescriptor::primitive("", PrimitiveKind::U8));
    let cases = vec![
        UnionCase::new(
            "x1",
            vec![1],
            Arc::new(TypeDescriptor::primitive("", PrimitiveKind::U8)),
        ),
        UnionCase::new(
            "x5",
            vec![5],
            Arc::new(TypeDescriptor::primitive("", PrimitiveKind::Char)),
        ),
    ];
    Arc::new(
        TypeDescriptor::new(
            "Test::union_primitives_appendable",
            TypeKind::Union(UnionDescriptor::new(disc, cases)),
        )
        .with_extensibility(Extensibility::Appendable),
    )
}

fn roundtrip_union(
    td: &Arc<TypeDescriptor>,
    disc: i64,
    case: &str,
    inner: DynamicValue,
    version: crate::dds::CdrVersion,
) -> Vec<u8> {
    let val = DynamicValue::Union(disc, case.to_string(), Box::new(inner.clone()));
    let data = DynamicData::from_value(td, val).expect("from_value");
    let encoded = encode_dynamic_with_version(&data, version).expect("encode");
    let decoded = decode_dynamic_with_version(&encoded, td, version).expect("decode");
    match decoded.value() {
        DynamicValue::Union(d, c, i) => {
            assert_eq!(*d, disc, "discriminator roundtrip");
            assert_eq!(c, case, "case name roundtrip");
            assert_eq!(**i, inner, "branch value roundtrip");
        }
        v => panic!("expected Union, got {:?}", v),
    }
    encoded
}

#[test]
fn union_mutable_xcdr2_wire_exact_u8_char() {
    // Mutable union, uint8 disc=5, x5='q', XCDR2:
    //   DHEADER 0d, EMHEADER 0x8000_0000 (M=1 LC=0 id=0), 05, pad3,
    //   EMHEADER 0x0000_0005 (M=0 LC=0 id=5), 41.
    let td = make_mutable_u8_disc_union();
    let encoded = roundtrip_union(
        &td,
        5,
        "x5",
        DynamicValue::Char('q'),
        crate::dds::CdrVersion::Xcdr2,
    );
    let expected: Vec<u8> = vec![
        0x0d, 0x00, 0x00, 0x00, // DHEADER = 13
        0x00, 0x00, 0x00, 0x80, // EMHEADER disc: M=1, LC=0, id=0
        0x05, 0x00, 0x00, 0x00, // disc value + align pad
        0x05, 0x00, 0x00, 0x00, // EMHEADER branch: M=0, LC=0, id=5
        0x71, // 'q'
    ];
    assert_eq!(encoded, expected, "union body must match the XTypes layout");
}

#[test]
fn union_mutable_xcdr2_wire_exact_u32_i64() {
    // Mutable union, uint32 disc=3, x3 int64=-0x0102030405060708, XCDR2:
    //   DHEADER 0x14, EMHEADER 0xA000_0000 (M=1 LC=2 id=0), disc u32,
    //   EMHEADER 0x3000_0003 (M=0 LC=3 id=3), int64.
    let td = make_mutable_u32_disc_union();
    let encoded = roundtrip_union(
        &td,
        3,
        "x3",
        DynamicValue::I64(-0x0102_0304_0506_0708),
        crate::dds::CdrVersion::Xcdr2,
    );
    let expected: Vec<u8> = vec![
        0x14, 0x00, 0x00, 0x00, // DHEADER = 20
        0x00, 0x00, 0x00, 0xa0, // EMHEADER disc: M=1, LC=2, id=0
        0x03, 0x00, 0x00, 0x00, // disc value
        0x03, 0x00, 0x00, 0x30, // EMHEADER branch: M=0, LC=3, id=3
        0xf8, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, // int64 -0x0102030405060708
    ];
    assert_eq!(encoded, expected, "union body must match the XTypes layout");
}

#[test]
fn union_mutable_xcdr1_wire_exact_u8_char() {
    // Mutable union, uint8 disc=5, x5='q', XCDR1:
    //   pid 0x4000 len 1, value 05 pad3; pid 0x0005 len 1, value 71 pad3;
    //   list end. Declared length is exact (7.4.1.2), stream padded.
    //   HDDS ends the list with 0x7F02 (PID_LIST_END with its
    //   must-understand flag, Table 34).
    let td = make_mutable_u8_disc_union();
    let encoded = roundtrip_union(
        &td,
        5,
        "x5",
        DynamicValue::Char('q'),
        crate::dds::CdrVersion::Xcdr1,
    );
    let expected: Vec<u8> = vec![
        0x00, 0x40, 0x01, 0x00, // pid 0x4000 (id 0 | MU), len 1
        0x05, 0x00, 0x00, 0x00, // disc value + pad
        0x05, 0x00, 0x01, 0x00, // pid 5, len 1
        0x71, 0x00, 0x00, 0x00, // 'q' + pad
        0x02, 0x7f, 0x00, 0x00, // PID_LIST_END | FLAG_MUST_UNDERSTAND
    ];
    assert_eq!(encoded, expected, "list end per Table 34");
}

#[test]
fn union_mutable_xcdr1_wire_exact_u32_i64() {
    // Mutable union, uint32 disc=3, x3 int64=-0x0102030405060708, XCDR1:
    //   pid 0x4000 len 4 disc; pid 0x0003 len 8 int64; PID_LIST_END, which
    //   HDDS writes 0x7F02 (Table 34).
    let td = make_mutable_u32_disc_union();
    let encoded = roundtrip_union(
        &td,
        3,
        "x3",
        DynamicValue::I64(-0x0102_0304_0506_0708),
        crate::dds::CdrVersion::Xcdr1,
    );
    let expected: Vec<u8> = vec![
        0x00, 0x40, 0x04, 0x00, // pid 0x4000 (id 0 | MU), len 4
        0x03, 0x00, 0x00, 0x00, // disc value
        0x03, 0x00, 0x08, 0x00, // pid 3, len 8
        0xf8, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, // int64 -0x0102030405060708
        0x02, 0x7f, 0x00, 0x00, // PID_LIST_END | FLAG_MUST_UNDERSTAND
    ];
    assert_eq!(encoded, expected, "list end per Table 34");
}

#[test]
fn union_appendable_xcdr2_wire_exact() {
    // Appendable union, uint8 disc=5, x5='q', XCDR2:
    //   DHEADER 02, 05, 71 (D_CDR2: DHEADER + Final-style body).
    let td = make_appendable_u8_disc_union();
    let encoded = roundtrip_union(
        &td,
        5,
        "x5",
        DynamicValue::Char('q'),
        crate::dds::CdrVersion::Xcdr2,
    );
    let expected: Vec<u8> = vec![0x02, 0x00, 0x00, 0x00, 0x05, 0x71];
    assert_eq!(encoded, expected, "union body must match the XTypes layout");
}

#[test]
fn union_appendable_xcdr1_stays_plain_cdr() {
    // XCDR1 appendable union is PLAIN CDR: byte-identical to the Final
    // encoding (this is why x1 final/appendable union cells already pass).
    let td = make_appendable_u8_disc_union();
    let encoded = roundtrip_union(
        &td,
        5,
        "x5",
        DynamicValue::Char('A'),
        crate::dds::CdrVersion::Xcdr1,
    );
    assert_eq!(encoded, vec![0x05, 0x41], "no framing under XCDR1");
}

#[test]
fn union_final_framing_unchanged_by_wave_d() {
    // Final unions must stay raw disc+branch in both versions.
    let disc = Arc::new(TypeDescriptor::primitive("", PrimitiveKind::U8));
    let cases = vec![UnionCase::new(
        "x1",
        vec![1],
        Arc::new(TypeDescriptor::primitive("", PrimitiveKind::U8)),
    )];
    let td = Arc::new(
        TypeDescriptor::new(
            "Test::union_final",
            TypeKind::Union(UnionDescriptor::new(disc, cases)),
        )
        .with_extensibility(Extensibility::Final),
    );
    for version in [crate::dds::CdrVersion::Xcdr1, crate::dds::CdrVersion::Xcdr2] {
        let encoded = roundtrip_union(&td, 1, "x1", DynamicValue::U8(42), version);
        assert_eq!(encoded, vec![0x01, 42]);
    }
}

#[test]
fn union_mutable_default_case_roundtrip_both_versions() {
    // union_mutable_a_default shape: labeled x5 (slot 0, id 1), default xd
    // (slot 1, id 2). An unmatched discriminator selects the default case,
    // whose wire member id is its 1-based declaration position.
    let disc = Arc::new(TypeDescriptor::primitive("", PrimitiveKind::U32));
    let labeled = UnionCase::new(
        "x5",
        vec![5],
        Arc::new(TypeDescriptor::primitive("", PrimitiveKind::U32)),
    );
    let default_case = UnionCase::new(
        "xd",
        vec![],
        Arc::new(TypeDescriptor::primitive("", PrimitiveKind::U32)),
    );
    let td = Arc::new(
        TypeDescriptor::new(
            "Test::union_mutable_a_default",
            TypeKind::Union(
                UnionDescriptor::new(disc, vec![labeled]).with_default_at(default_case, 1),
            ),
        )
        .with_extensibility(Extensibility::Mutable),
    );
    for version in [crate::dds::CdrVersion::Xcdr1, crate::dds::CdrVersion::Xcdr2] {
        let encoded = roundtrip_union(&td, 99, "xd", DynamicValue::U32(7), version);
        // Branch must travel under member id 2 (default case slot 1 -> id 2).
        match version {
            crate::dds::CdrVersion::Xcdr1 => {
                // pid header at offset 8: id 2, len 4.
                assert_eq!(&encoded[8..12], &[0x02, 0x00, 0x04, 0x00]);
            }
            crate::dds::CdrVersion::Xcdr2 => {
                // EMHEADER at offset 12: M=0, LC=2, id=2.
                assert_eq!(&encoded[12..16], &[0x02, 0x00, 0x00, 0x20]);
            }
        }
    }
}

#[test]
fn union_mutable_decode_skips_unknown_member_and_tolerates_order() {
    // Reader must skip an unknown member id whose must-understand flag is
    // clear, refuse the sample when it is set (DDS-XTypes 1.3
    // 7.2.2.4.4.4.6), and accept the branch before the discriminator
    // (two-pass id matching).
    let td = make_mutable_u32_disc_union();
    let x2 = |unknown_emheader: u32| {
        // XCDR2: branch (id 3) first, unknown id 9, then disc (id 0).
        let mut body: Vec<u8> = Vec::new();
        body.extend(&0x3000_0003u32.to_le_bytes()); // EMHEADER id 3, LC=3
        body.extend(&123i64.to_le_bytes());
        body.extend(&unknown_emheader.to_le_bytes()); // EMHEADER unknown id 9, LC=2
        body.extend(&0xdead_beefu32.to_le_bytes());
        body.extend(&0xA000_0000u32.to_le_bytes()); // EMHEADER disc id 0, MU, LC=2
        body.extend(&3u32.to_le_bytes());
        let mut wire: Vec<u8> = Vec::new();
        wire.extend(&(body.len() as u32).to_le_bytes());
        wire.extend(&body);
        wire
    };
    let decoded = decode_dynamic_with_version(&x2(0x2000_0009), &td, crate::dds::CdrVersion::Xcdr2)
        .expect("decode");
    match decoded.value() {
        DynamicValue::Union(d, c, i) => {
            assert_eq!(*d, 3);
            assert_eq!(c, "x3");
            assert!(matches!(**i, DynamicValue::I64(123)));
        }
        v => panic!("expected Union, got {:?}", v),
    }
    assert!(
        decode_dynamic_with_version(&x2(0xA000_0009), &td, crate::dds::CdrVersion::Xcdr2).is_err(),
        "an unknown must-understand member discards the sample"
    );

    // XCDR1: same layout as a PL list.
    let x1 = |unknown_pid_high: u8| {
        let mut wire1: Vec<u8> = Vec::new();
        wire1.extend(&[0x03, 0x00, 0x08, 0x00]); // pid 3, len 8
        wire1.extend(&123i64.to_le_bytes());
        wire1.extend(&[0x09, unknown_pid_high, 0x04, 0x00]); // pid 9, len 4 (unknown)
        wire1.extend(&0xdead_beefu32.to_le_bytes());
        wire1.extend(&[0x00, 0x40, 0x04, 0x00]); // pid 0 | MU, len 4 (disc)
        wire1.extend(&3u32.to_le_bytes());
        wire1.extend(&[0x02, 0x3f, 0x00, 0x00]); // list end, 1.4.x shape
        wire1
    };
    let decoded =
        decode_dynamic_with_version(&x1(0x00), &td, crate::dds::CdrVersion::Xcdr1).expect("decode");
    match decoded.value() {
        DynamicValue::Union(d, c, i) => {
            assert_eq!(*d, 3);
            assert_eq!(c, "x3");
            assert!(matches!(**i, DynamicValue::I64(123)));
        }
        v => panic!("expected Union, got {:?}", v),
    }
    assert!(
        decode_dynamic_with_version(&x1(0x40), &td, crate::dds::CdrVersion::Xcdr1).is_err(),
        "an unknown must-understand member discards the sample"
    );
}

#[test]
fn union_mutable_inside_struct_field_gets_pl_framing() {
    // A mutable union nested (via TypeKind::Nested) inside a FINAL struct
    // must still travel as a parameter list (the Nested arm carries the
    // union descriptor's extensibility).
    let union_td = make_mutable_u8_disc_union();
    let field = FieldDescriptor::new(
        "u",
        Arc::new(TypeDescriptor::new("", TypeKind::Nested(union_td.clone()))),
    );
    let struct_td = Arc::new(
        TypeDescriptor::struct_type("Test::S", vec![field])
            .with_extensibility(Extensibility::Final),
    );
    let mut map = std::collections::HashMap::new();
    map.insert(
        "u".to_string(),
        DynamicValue::Union(5, "x5".to_string(), Box::new(DynamicValue::Char('A'))),
    );
    let data = DynamicData::from_value(&struct_td, DynamicValue::Struct(map)).expect("from_value");
    let encoded =
        encode_dynamic_with_version(&data, crate::dds::CdrVersion::Xcdr2).expect("encode");
    // Struct is FINAL so the payload starts directly with the union DHEADER.
    assert_eq!(
        &encoded[..8],
        &[0x0d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80],
        "union field must carry DHEADER + MU discriminator EMHEADER"
    );
    let decoded = decode_dynamic_with_version(&encoded, &struct_td, crate::dds::CdrVersion::Xcdr2)
        .expect("decode");
    match decoded.get_field("u").expect("field u") {
        DynamicValue::Union(d, c, i) => {
            assert_eq!(*d, 5);
            assert_eq!(c, "x5");
            assert!(matches!(**i, DynamicValue::Char('A')));
        }
        v => panic!("expected Union field, got {:?}", v),
    }
}

#[test]
fn union_mutable_disc_only_when_no_case_matches() {
    // Encoder with an unmatched discriminator and no default case emits only
    // the discriminator member; decoder yields disc + Null.
    let td = make_mutable_u32_disc_union();
    let val = DynamicValue::Union(42, String::new(), Box::new(DynamicValue::Null));
    let data = DynamicData::from_value(&td, val).expect("from_value");
    for version in [crate::dds::CdrVersion::Xcdr1, crate::dds::CdrVersion::Xcdr2] {
        let encoded = encode_dynamic_with_version(&data, version).expect("encode");
        let decoded = decode_dynamic_with_version(&encoded, &td, version).expect("decode");
        match decoded.value() {
            DynamicValue::Union(d, c, i) => {
                assert_eq!(*d, 42);
                assert!(c.is_empty());
                assert!(matches!(**i, DynamicValue::Null));
            }
            v => panic!("expected Union, got {:?}", v),
        }
    }
}

// ---------------------------------------------------------------------------
// Enum and bitmask holder width (DDS-XTypes 1.3 7.4.3.5.3 rules 5 and 6)
// ---------------------------------------------------------------------------

fn holder_enum(underlying: PrimitiveKind, bitmask: bool) -> Arc<TypeDescriptor> {
    let variants = vec![EnumVariant::new("A", 0), EnumVariant::new("B", 3)];
    let e = if bitmask {
        EnumDescriptor::new_bitmask(variants)
    } else {
        EnumDescriptor::new(variants)
    };
    Arc::new(TypeDescriptor::new(
        "E",
        TypeKind::Enum(e.with_underlying(underlying)),
    ))
}

/// `{ E e; octet t; }`: the enum takes its holder's width, so the octet
/// follows at offset 1, 2, 4 or (XCDR2, aligned at 4) 8; and it decodes back.
#[test]
fn enum_and_bitmask_are_encoded_in_their_holder_width() {
    for (underlying, bitmask, width) in [
        (PrimitiveKind::I8, false, 1),
        (PrimitiveKind::I16, false, 2),
        (PrimitiveKind::U32, false, 4),
        (PrimitiveKind::U8, true, 1),
        (PrimitiveKind::U16, true, 2),
        (PrimitiveKind::U64, true, 8),
    ] {
        let e = holder_enum(underlying, bitmask);
        let t = Arc::new(
            TypeDescriptor::struct_type(
                "S",
                vec![
                    FieldDescriptor::new("e", Arc::clone(&e)),
                    FieldDescriptor::new(
                        "t",
                        Arc::new(TypeDescriptor::primitive("t", PrimitiveKind::U8)),
                    ),
                ],
            )
            .with_extensibility(Extensibility::Final),
        );
        let mut data = DynamicData::new(&t);
        data.set("e", DynamicValue::Enum(3, "B".into())).expect("e");
        data.set("t", 0x55u8).expect("t");
        let bytes =
            encode_dynamic_with_version(&data, crate::dds::CdrVersion::Xcdr2).expect("encode");
        assert_eq!(bytes.len(), width + 1, "{underlying:?}: {bytes:02x?}");
        assert_eq!(bytes[0], 3, "{underlying:?}");
        assert_eq!(bytes[width], 0x55, "{underlying:?}");
        let back =
            decode_dynamic_with_version(&bytes, &t, crate::dds::CdrVersion::Xcdr2).expect("decode");
        assert_eq!(
            back.get_field("e").expect("e"),
            &DynamicValue::Enum(3, "B".into()),
            "{underlying:?}"
        );
    }
}

/// An 8 or 16-bit enum holder is signed (Int8, Int16): a negative literal
/// value survives the round trip.
#[test]
fn a_negative_literal_in_a_small_enum_holder_round_trips() {
    let e = Arc::new(TypeDescriptor::new(
        "E",
        TypeKind::Enum(
            EnumDescriptor::new(vec![EnumVariant::new("NEG", -2), EnumVariant::new("Z", 0)])
                .with_underlying(PrimitiveKind::I8),
        ),
    ));
    let t = Arc::new(
        TypeDescriptor::struct_type("S", vec![FieldDescriptor::new("e", Arc::clone(&e))])
            .with_extensibility(Extensibility::Final),
    );
    let mut data = DynamicData::new(&t);
    data.set("e", DynamicValue::Enum(-2, "NEG".into()))
        .expect("e");
    let bytes = encode_dynamic_with_version(&data, crate::dds::CdrVersion::Xcdr2).expect("encode");
    assert_eq!(bytes, vec![0xfe]);
    let back =
        decode_dynamic_with_version(&bytes, &t, crate::dds::CdrVersion::Xcdr2).expect("decode");
    assert_eq!(
        back.get_field("e").expect("e"),
        &DynamicValue::Enum(-2, "NEG".into())
    );
}

// ---------------------------------------------------------------------------
// Sequential member ids: previous + 1 (DDS-XTypes 1.3 7.3.1.2.1.1)
// ---------------------------------------------------------------------------

fn i32_desc() -> Arc<TypeDescriptor> {
    Arc::new(TypeDescriptor::primitive("i32", PrimitiveKind::I32))
}

/// `{ long a; @id(10) long b; long c; }`, given extensibility.
fn mixed_ids(ext: Extensibility) -> Arc<TypeDescriptor> {
    Arc::new(
        TypeDescriptor::struct_type(
            "Mixed",
            vec![
                FieldDescriptor::new("a", i32_desc()),
                FieldDescriptor::new("b", i32_desc()).with_id(10),
                FieldDescriptor::new("c", i32_desc()),
            ],
        )
        .with_extensibility(ext),
    )
}

/// The member after an explicit `@id(10)` is 11, not its declaration index 2.
#[test]
fn struct_member_ids_follow_the_previous_member() {
    let Some(crate::xtypes::CompleteTypeObject::Struct(st)) =
        type_descriptor_to_xtypes(&mixed_ids(Extensibility::Mutable))
    else {
        panic!("struct type object");
    };
    let ids: Vec<u32> = st.member_seq.iter().map(|m| m.common.member_id).collect();
    assert_eq!(ids, vec![0, 10, 11]);
}

/// The same ids head each member of a mutable sample: XCDR2 EMHEADERs and
/// XCDR1 parameter ids, and the sample decodes back.
#[test]
fn mutable_encodings_carry_the_sequential_ids() {
    let t = mixed_ids(Extensibility::Mutable);
    let mut data = DynamicData::new(&t);
    data.set("a", 1i32).expect("a");
    data.set("b", 2i32).expect("b");
    data.set("c", 3i32).expect("c");

    let x2 = encode_dynamic_with_version(&data, crate::dds::CdrVersion::Xcdr2).expect("xcdr2");
    // DHEADER, then (EMHEADER LC=2 | id, value) three times.
    let emheader_ids: Vec<u32> = [4usize, 12, 20]
        .iter()
        .map(|&o| u32::from_le_bytes([x2[o], x2[o + 1], x2[o + 2], x2[o + 3]]) & 0x0FFF_FFFF)
        .collect();
    assert_eq!(emheader_ids, vec![0, 10, 11]);
    let back = decode_dynamic_with_version(&x2, &t, crate::dds::CdrVersion::Xcdr2).expect("dec2");
    assert_eq!(back.get_field("c").expect("c"), &DynamicValue::I32(3));

    let x1 = encode_dynamic_with_version(&data, crate::dds::CdrVersion::Xcdr1).expect("xcdr1");
    // (u16 pid, u16 len, value) three times.
    let pids: Vec<u16> = [0usize, 8, 16]
        .iter()
        .map(|&o| u16::from_le_bytes([x1[o], x1[o + 1]]) & 0x3FFF)
        .collect();
    assert_eq!(pids, vec![0, 10, 11]);
    let back = decode_dynamic_with_version(&x1, &t, crate::dds::CdrVersion::Xcdr1).expect("dec1");
    assert_eq!(back.get_field("c").expect("c"), &DynamicValue::I32(3));
}

/// Union cases follow the same rule after the discriminator (member 0):
/// `x`, `@id(10) y`, `z` are 1, 10, 11.
#[test]
fn union_member_ids_follow_the_previous_member() {
    let disc = Arc::new(TypeDescriptor::primitive("d", PrimitiveKind::I32));
    let u = UnionDescriptor::new(
        disc,
        vec![
            UnionCase::single("x", 0, i32_desc()),
            UnionCase::single("y", 1, i32_desc()).with_member_id(10),
            UnionCase::single("z", 2, i32_desc()),
        ],
    );
    let t = TypeDescriptor::new("U", TypeKind::Union(u));
    let Some(crate::xtypes::CompleteTypeObject::Union(ut)) = type_descriptor_to_xtypes(&t) else {
        panic!("union type object");
    };
    let ids: Vec<u32> = ut.member_seq.iter().map(|m| m.common.member_id).collect();
    assert_eq!(ids, vec![1, 10, 11]);
}

/// An `@autoid(HASH)` mutable struct heads each member with the id its
/// TypeObject announces (the name hash), in XCDR2 EMHEADERs, and decodes
/// back in both versions.
#[test]
fn an_autoid_hash_struct_encodes_the_ids_it_announces() {
    let t = Arc::new(
        TypeDescriptor::struct_type(
            "Hashed",
            vec![
                FieldDescriptor::new("alpha", i32_desc()),
                FieldDescriptor::new("beta", i32_desc()),
            ],
        )
        .with_extensibility(Extensibility::Mutable)
        .with_autoid_hash(),
    );
    let Some(crate::xtypes::CompleteTypeObject::Struct(st)) = type_descriptor_to_xtypes(&t) else {
        panic!("struct type object");
    };
    let announced: Vec<u32> = st.member_seq.iter().map(|m| m.common.member_id).collect();
    assert!(
        announced.iter().all(|id| *id > 1),
        "hash ids: {announced:?}"
    );

    let mut data = DynamicData::new(&t);
    data.set("alpha", 1i32).expect("alpha");
    data.set("beta", 2i32).expect("beta");
    let x2 = encode_dynamic_with_version(&data, crate::dds::CdrVersion::Xcdr2).expect("xcdr2");
    let on_wire: Vec<u32> = [4usize, 12]
        .iter()
        .map(|&o| u32::from_le_bytes([x2[o], x2[o + 1], x2[o + 2], x2[o + 3]]) & 0x0FFF_FFFF)
        .collect();
    assert_eq!(on_wire, announced);
    for version in [crate::dds::CdrVersion::Xcdr2, crate::dds::CdrVersion::Xcdr1] {
        let bytes = encode_dynamic_with_version(&data, version).expect("encode");
        let back = decode_dynamic_with_version(&bytes, &t, version).expect("decode");
        assert_eq!(
            back.get_field("beta").expect("beta"),
            &DynamicValue::I32(2),
            "{version:?}"
        );
    }
}

/// `{ long a; @hashid("foo") long b; long c; }` without `@autoid(HASH)`.
fn hashid_sequential(ext: Extensibility) -> Arc<TypeDescriptor> {
    Arc::new(
        TypeDescriptor::struct_type(
            "HashidSeq",
            vec![
                FieldDescriptor::new("a", i32_desc()),
                FieldDescriptor::new("b", i32_desc()).with_hashid_name("foo"),
                FieldDescriptor::new("c", i32_desc()),
            ],
        )
        .with_extensibility(ext),
    )
}

/// `@hashid` assigns the member id explicitly whatever the `@autoid`
/// (DDS-XTypes 1.3 7.3.1.2.1.1), and the next sequential member follows it.
/// The values are the ones Cyclone DDS 0.11 idlc announces for
/// `@final struct FinHashidSeq { long a; @hashid("foo") long b; long c; }`.
#[test]
fn a_hashid_member_takes_its_hash_without_autoid_hash() {
    let Some(crate::xtypes::CompleteTypeObject::Struct(st)) =
        type_descriptor_to_xtypes(&hashid_sequential(Extensibility::Final))
    else {
        panic!("struct type object");
    };
    let ids: Vec<u32> = st.member_seq.iter().map(|m| m.common.member_id).collect();
    assert_eq!(ids, vec![0, 0x0b18_bdac, 0x0b18_bdad]);
}

/// `@hashid` without a parameter, or with the empty string, hashes the
/// member's own name (7.3.1.2.1.1), under either `@autoid`.
#[test]
fn an_empty_hashid_hashes_the_member_name() {
    for autoid_hash in [false, true] {
        let mut d = TypeDescriptor::struct_type(
            "EmptyHashid",
            vec![FieldDescriptor::new("x", i32_desc()).with_hashid_name("")],
        );
        if autoid_hash {
            d = d.with_autoid_hash();
        }
        let Some(crate::xtypes::CompleteTypeObject::Struct(st)) =
            type_descriptor_to_xtypes(&Arc::new(d))
        else {
            panic!("struct type object");
        };
        // Cyclone DDS 0.11 idlc: `@hashid long x;` is member 0x01e4d49d.
        assert_eq!(
            st.member_seq[0].common.member_id, 0x01e4_d49d,
            "{autoid_hash}"
        );
    }
}

/// A descriptor read from a received TypeObject carries both the member id
/// it was announced with and its `hash_id` annotation: the announced id is
/// kept, whatever the annotation.
#[test]
fn an_explicit_id_wins_over_hashid() {
    let t = Arc::new(TypeDescriptor::struct_type(
        "Received",
        vec![
            FieldDescriptor::new("a", i32_desc())
                .with_id(7)
                .with_hashid_name("foo"),
            FieldDescriptor::new("b", i32_desc()),
        ],
    ));
    let Some(crate::xtypes::CompleteTypeObject::Struct(st)) = type_descriptor_to_xtypes(&t) else {
        panic!("struct type object");
    };
    let ids: Vec<u32> = st.member_seq.iter().map(|m| m.common.member_id).collect();
    assert_eq!(ids, vec![7, 8]);
}

/// The mutable encodings head the `@hashid` member with the id the
/// TypeObject announces, and the sample decodes back in both versions.
#[test]
fn mutable_encodings_carry_the_hashid_member_id() {
    let t = hashid_sequential(Extensibility::Mutable);
    let mut data = DynamicData::new(&t);
    data.set("a", 1i32).expect("a");
    data.set("b", 2i32).expect("b");
    data.set("c", 3i32).expect("c");

    let x2 = encode_dynamic_with_version(&data, crate::dds::CdrVersion::Xcdr2).expect("xcdr2");
    let emheader_ids: Vec<u32> = [4usize, 12, 20]
        .iter()
        .map(|&o| u32::from_le_bytes([x2[o], x2[o + 1], x2[o + 2], x2[o + 3]]) & 0x0FFF_FFFF)
        .collect();
    assert_eq!(emheader_ids, vec![0, 0x0b18_bdac, 0x0b18_bdad]);
    for version in [crate::dds::CdrVersion::Xcdr2, crate::dds::CdrVersion::Xcdr1] {
        let bytes = encode_dynamic_with_version(&data, version).expect("encode");
        let back = decode_dynamic_with_version(&bytes, &t, version).expect("decode");
        assert_eq!(
            back.get_field("b").expect("b"),
            &DynamicValue::I32(2),
            "{version:?}"
        );
        assert_eq!(
            back.get_field("c").expect("c"),
            &DynamicValue::I32(3),
            "{version:?}"
        );
    }
}

/// A 16-bit enum holder is signed (Int16): a negative literal round trips
/// in two bytes.
#[test]
fn a_negative_literal_in_a_16_bit_enum_holder_round_trips() {
    let e = Arc::new(TypeDescriptor::new(
        "E16",
        TypeKind::Enum(
            EnumDescriptor::new(vec![
                EnumVariant::new("NEG", -300),
                EnumVariant::new("Z", 0),
            ])
            .with_underlying(PrimitiveKind::I16),
        ),
    ));
    let t = Arc::new(
        TypeDescriptor::struct_type("S", vec![FieldDescriptor::new("e", Arc::clone(&e))])
            .with_extensibility(Extensibility::Final),
    );
    let mut data = DynamicData::new(&t);
    data.set("e", DynamicValue::Enum(-300, "NEG".into()))
        .expect("e");
    let bytes = encode_dynamic_with_version(&data, crate::dds::CdrVersion::Xcdr2).expect("encode");
    assert_eq!(bytes, (-300i16).to_le_bytes().to_vec());
    let back =
        decode_dynamic_with_version(&bytes, &t, crate::dds::CdrVersion::Xcdr2).expect("decode");
    assert_eq!(
        back.get_field("e").expect("e"),
        &DynamicValue::Enum(-300, "NEG".into())
    );
}

/// XCDR1 `sequence<E8, 2>` (TRIM) read from four elements: the two beyond
/// the bound are skipped at their one-byte holder width, so the member
/// after the sequence is read where it is.
#[test]
fn excess_small_enum_elements_are_skipped_at_their_width() {
    let e8 = holder_enum(PrimitiveKind::I8, false);
    let u8_t = Arc::new(TypeDescriptor::primitive("t", PrimitiveKind::U8));
    let writer_type = Arc::new(TypeDescriptor::struct_type(
        "W",
        vec![
            FieldDescriptor::new(
                "s",
                Arc::new(TypeDescriptor::new(
                    "S4",
                    TypeKind::Sequence(SequenceDescriptor::bounded(Arc::clone(&e8), 4)),
                )),
            ),
            FieldDescriptor::new("t", Arc::clone(&u8_t)),
        ],
    ));
    let reader_type = Arc::new(TypeDescriptor::struct_type(
        "W",
        vec![
            FieldDescriptor::new(
                "s",
                Arc::new(TypeDescriptor::new(
                    "S2",
                    TypeKind::Sequence(SequenceDescriptor::bounded(Arc::clone(&e8), 2)),
                )),
            )
            .with_try_construct(TryConstructKind::Trim),
            FieldDescriptor::new("t", u8_t),
        ],
    ));
    let mut data = DynamicData::new(&writer_type);
    data.set(
        "s",
        DynamicValue::Sequence(vec![DynamicValue::Enum(3, "B".into()); 4]),
    )
    .expect("s");
    data.set("t", 0x55u8).expect("t");
    let bytes = encode_dynamic_with_version(&data, crate::dds::CdrVersion::Xcdr1).expect("encode");
    assert_eq!(bytes, vec![4, 0, 0, 0, 3, 3, 3, 3, 0x55]);
    let back = decode_dynamic_with_version(&bytes, &reader_type, crate::dds::CdrVersion::Xcdr1)
        .expect("decode");
    assert_eq!(back.get_field("t").expect("t"), &DynamicValue::U8(0x55));
    assert_eq!(
        back.get_field("s").expect("s"),
        &DynamicValue::Sequence(vec![DynamicValue::Enum(3, "B".into()); 2])
    );
}

/// A descriptor that names no extensibility is appendable: "In the event
/// that the representation of a given type does not indicate the type's
/// extensibility kind, the type shall be considered appendable" (DDS-XTypes
/// 1.3 7.3.1.2.1.8). Under XCDR2 the body is DELIMITED_CDR, a DHEADER before
/// the members; under XCDR1 it is PLAIN_CDR, no DHEADER (7.4.3.1, Table 35).
/// The same holds for a union.
#[test]
fn an_unannotated_type_is_appendable() {
    let st = Arc::new(TypeDescriptor::struct_type(
        "S",
        vec![FieldDescriptor::new(
            "a",
            Arc::new(TypeDescriptor::primitive("", PrimitiveKind::I32)),
        )],
    ));
    assert_eq!(st.extensibility, Extensibility::Appendable);
    assert_eq!(Extensibility::default(), Extensibility::Appendable);
    let mut data = DynamicData::new(&st);
    data.set("a", 7i32).expect("a");
    assert_eq!(
        encode_dynamic_with_version(&data, crate::dds::CdrVersion::Xcdr2).expect("x2"),
        vec![4, 0, 0, 0, 7, 0, 0, 0]
    );
    assert_eq!(
        encode_dynamic_with_version(&data, crate::dds::CdrVersion::Xcdr1).expect("x1"),
        vec![7, 0, 0, 0]
    );

    let disc = Arc::new(TypeDescriptor::primitive("", PrimitiveKind::U8));
    let cases = vec![UnionCase::new(
        "x1",
        vec![1],
        Arc::new(TypeDescriptor::primitive("", PrimitiveKind::U8)),
    )];
    let un = Arc::new(TypeDescriptor::new(
        "U",
        TypeKind::Union(UnionDescriptor::new(disc, cases)),
    ));
    assert_eq!(un.extensibility, Extensibility::Appendable);
    assert_eq!(
        roundtrip_union(
            &un,
            1,
            "x1",
            DynamicValue::U8(42),
            crate::dds::CdrVersion::Xcdr2
        ),
        vec![2, 0, 0, 0, 1, 42]
    );
    assert_eq!(
        roundtrip_union(
            &un,
            1,
            "x1",
            DynamicValue::U8(42),
            crate::dds::CdrVersion::Xcdr1
        ),
        vec![1, 42]
    );
}
