// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Integration tests for dynamic types module.

use super::*;
use std::sync::Arc;

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
    data.set("text", "Hello 世界! [*]").unwrap();

    let encoded = encode_dynamic(&data).expect("encode");
    let decoded = decode_dynamic(&encoded, &desc).expect("decode");

    assert_eq!(decoded.get::<String>("text").unwrap(), "Hello 世界! [*]");
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
