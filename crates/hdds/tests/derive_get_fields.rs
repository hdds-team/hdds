// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Regression guard for `#[derive(hdds::DDS)]` field extraction.
//!
//! The derive did not generate `get_fields`, so every derived type reported
//! no fields to a `ContentFilteredTopic` and every sample was rejected (see
//! `content_filtered_topic.rs`'s module doc for the failure mode). This
//! covers every field kind the derive supports (primitives, `String`) and
//! confirms `Vec<u8>` is intentionally excluded (not a filterable scalar).
//!
//! No DDS participant, writer or reader: pure `get_fields()` and
//! `FilterEvaluator` calls.

use hdds::filter::{parse_expression, FilterEvaluator};
use hdds::{DdsTrait, FieldValue};
use std::sync::{Arc, RwLock};

#[derive(hdds::DDS, Debug)]
struct AllKinds {
    a_i8: i8,
    a_i16: i16,
    a_i32: i32,
    a_i64: i64,
    a_u8: u8,
    a_u16: u16,
    a_u32: u32,
    a_u64: u64,
    a_f32: f32,
    a_f64: f64,
    a_bool: bool,
    a_string: String,
    a_bytes: Vec<u8>,
}

fn sample() -> AllKinds {
    AllKinds {
        a_i8: -1,
        a_i16: -2,
        a_i32: -3,
        a_i64: -4,
        a_u8: 5,
        a_u16: 6,
        a_u32: 7,
        a_u64: 8,
        a_f32: 1.5,
        a_f64: 2.5,
        a_bool: true,
        a_string: "hello".to_string(),
        a_bytes: vec![1, 2, 3],
    }
}

#[test]
fn get_fields_maps_every_supported_scalar_kind() {
    let fields = sample().get_fields();

    assert_eq!(
        fields.len(),
        12,
        "one entry per field except the Vec<u8> field"
    );
    assert_eq!(fields.get("a_i8"), Some(&FieldValue::from_i64(-1)));
    assert_eq!(fields.get("a_i16"), Some(&FieldValue::from_i64(-2)));
    assert_eq!(fields.get("a_i32"), Some(&FieldValue::from_i64(-3)));
    assert_eq!(fields.get("a_i64"), Some(&FieldValue::from_i64(-4)));
    assert_eq!(fields.get("a_u8"), Some(&FieldValue::from_u64(5)));
    assert_eq!(fields.get("a_u16"), Some(&FieldValue::from_u64(6)));
    assert_eq!(fields.get("a_u32"), Some(&FieldValue::from_u64(7)));
    assert_eq!(fields.get("a_u64"), Some(&FieldValue::from_u64(8)));
    assert_eq!(fields.get("a_f32"), Some(&FieldValue::from_f32(1.5)));
    assert_eq!(fields.get("a_f64"), Some(&FieldValue::from_f64(2.5)));
    assert_eq!(fields.get("a_bool"), Some(&FieldValue::Boolean(true)));
    assert_eq!(
        fields.get("a_string"),
        Some(&FieldValue::from_string("hello"))
    );
}

#[test]
fn get_fields_excludes_byte_vec() {
    let fields = sample().get_fields();
    assert!(
        !fields.contains_key("a_bytes"),
        "Vec<u8> is not a filterable scalar"
    );
}

/// Minimal derived type dedicated to exercising the public filter
/// evaluator entry point against a real, derive-generated `get_fields`.
#[derive(hdds::DDS, Debug)]
struct Reading {
    value: i32,
}

fn make_evaluator(expr: &str) -> FilterEvaluator {
    let expression = Arc::new(parse_expression(expr).unwrap());
    let parameters = Arc::new(RwLock::new(Vec::new()));
    FilterEvaluator::new(expression, parameters)
}

#[test]
fn filter_evaluator_reads_derived_get_fields() {
    let evaluator = make_evaluator("value > 40");
    let low = Reading { value: 10 };
    let high = Reading { value: 50 };

    assert!(
        !evaluator.matches(&low.get_fields()).unwrap(),
        "value=10 must not match value > 40"
    );
    assert!(
        evaluator.matches(&high.get_fields()).unwrap(),
        "value=50 must match value > 40"
    );
}
