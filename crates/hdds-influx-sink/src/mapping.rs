// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! DDS sample field mapping to InfluxDB tags and fields.
//!
//! Maps JSON-like DDS samples to InfluxDB-compatible tag and field sets
//! based on a configured list of field names.

use crate::influx::FieldValue;

/// Pair of InfluxDB tag set and field set extracted from a DDS sample.
type TagsAndFields = (Vec<(String, String)>, Vec<(String, FieldValue)>);

/// Maps DDS sample fields to InfluxDB tags and fields.
///
/// Tags are always extracted as strings (InfluxDB tags are strings).
/// Fields are extracted with their natural JSON type preserved.
pub struct FieldMapper {
    /// Field names to extract as InfluxDB tags.
    tag_fields: Vec<String>,
    /// Field names to extract as InfluxDB fields (values).
    value_fields: Vec<String>,
}

impl FieldMapper {
    /// Create a new mapper with the given tag and field names.
    pub fn new(tags: Vec<String>, fields: Vec<String>) -> Self {
        Self {
            tag_fields: tags,
            value_fields: fields,
        }
    }

    /// Map a JSON DDS sample to InfluxDB tags and fields.
    ///
    /// - Tags are extracted as `(key, value_string)` pairs.
    ///   Missing or null tag fields are silently skipped.
    /// - Fields are extracted as `(key, FieldValue)` pairs with type inference.
    ///   Missing or null fields are silently skipped.
    ///
    /// Supports nested fields using dot notation (e.g., `"location.lat"`).
    pub fn map_sample(
        &self,
        sample_json: &serde_json::Value,
    ) -> TagsAndFields {
        let mut tags = Vec::new();
        let mut fields = Vec::new();

        // Extract tags (always as strings)
        for tag_name in &self.tag_fields {
            if let Some(val) = resolve_field(sample_json, tag_name) {
                if let Some(s) = json_to_string(val) {
                    tags.push((tag_name.clone(), s));
                }
            }
        }

        // Extract fields (preserve types)
        for field_name in &self.value_fields {
            if let Some(val) = resolve_field(sample_json, field_name) {
                if let Some(fv) = json_to_field_value(val) {
                    fields.push((field_name.clone(), fv));
                }
            }
        }

        (tags, fields)
    }
}

/// Resolve a potentially dot-separated field path in a JSON value.
///
/// For example, `"location.lat"` resolves `json["location"]["lat"]`.
fn resolve_field<'a>(json: &'a serde_json::Value, path: &str) -> Option<&'a serde_json::Value> {
    let mut current = json;
    for part in path.split('.') {
        current = current.get(part)?;
    }
    Some(current)
}

/// Convert a JSON value to a string representation for use as an InfluxDB tag.
fn json_to_string(val: &serde_json::Value) -> Option<String> {
    match val {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        serde_json::Value::Bool(b) => Some(b.to_string()),
        serde_json::Value::Null => None,
        // Arrays and objects are not valid tag values
        _ => None,
    }
}

/// Convert a JSON value to an InfluxDB FieldValue with type inference.
fn json_to_field_value(val: &serde_json::Value) -> Option<FieldValue> {
    match val {
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Some(FieldValue::Integer(i))
            } else { n.as_f64().map(FieldValue::Float) }
        }
        serde_json::Value::String(s) => Some(FieldValue::String(s.clone())),
        serde_json::Value::Bool(b) => Some(FieldValue::Boolean(*b)),
        serde_json::Value::Null => None,
        // Arrays and objects are not valid field values
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_map_sample_basic() {
        let mapper = FieldMapper::new(
            vec!["sensor_id".to_string()],
            vec!["value".to_string()],
        );

        let sample = json!({
            "sensor_id": "sensor-42",
            "value": 23.5,
            "extra": "ignored"
        });

        let (tags, fields) = mapper.map_sample(&sample);

        assert_eq!(tags.len(), 1);
        assert_eq!(tags[0].0, "sensor_id");
        assert_eq!(tags[0].1, "sensor-42");

        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].0, "value");
        match &fields[0].1 {
            FieldValue::Float(v) => assert!((v - 23.5).abs() < f64::EPSILON),
            other => panic!("expected Float, got {:?}", other),
        }
    }

    #[test]
    fn test_map_sample_missing_field_handled_gracefully() {
        let mapper = FieldMapper::new(
            vec!["sensor_id".to_string(), "missing_tag".to_string()],
            vec!["value".to_string(), "missing_field".to_string()],
        );

        let sample = json!({
            "sensor_id": "sensor-1",
            "value": 100
        });

        let (tags, fields) = mapper.map_sample(&sample);

        // Only the present fields should appear
        assert_eq!(tags.len(), 1);
        assert_eq!(tags[0].0, "sensor_id");
        assert_eq!(tags[0].1, "sensor-1");

        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].0, "value");
        match &fields[0].1 {
            FieldValue::Integer(v) => assert_eq!(*v, 100),
            other => panic!("expected Integer, got {:?}", other),
        }
    }

    #[test]
    fn test_map_sample_nested_fields() {
        let mapper = FieldMapper::new(
            vec!["meta.region".to_string()],
            vec!["location.lat".to_string(), "location.lon".to_string()],
        );

        let sample = json!({
            "meta": { "region": "eu-west" },
            "location": { "lat": 48.8566, "lon": 2.3522 }
        });

        let (tags, fields) = mapper.map_sample(&sample);

        assert_eq!(tags.len(), 1);
        assert_eq!(tags[0].1, "eu-west");

        assert_eq!(fields.len(), 2);
        match &fields[0].1 {
            FieldValue::Float(v) => assert!((v - 48.8566).abs() < 0.0001),
            other => panic!("expected Float, got {:?}", other),
        }
        match &fields[1].1 {
            FieldValue::Float(v) => assert!((v - 2.3522).abs() < 0.0001),
            other => panic!("expected Float, got {:?}", other),
        }
    }

    #[test]
    fn test_map_sample_all_types() {
        let mapper = FieldMapper::new(
            vec![],
            vec![
                "f".to_string(),
                "i".to_string(),
                "s".to_string(),
                "b".to_string(),
            ],
        );

        let sample = json!({
            "f": 1.5,
            "i": 42,
            "s": "hello",
            "b": true
        });

        let (tags, fields) = mapper.map_sample(&sample);
        assert!(tags.is_empty());
        assert_eq!(fields.len(), 4);

        match &fields[0].1 {
            FieldValue::Float(v) => assert!((v - 1.5).abs() < f64::EPSILON),
            other => panic!("expected Float, got {:?}", other),
        }
        match &fields[1].1 {
            FieldValue::Integer(v) => assert_eq!(*v, 42),
            other => panic!("expected Integer, got {:?}", other),
        }
        match &fields[2].1 {
            FieldValue::String(v) => assert_eq!(v, "hello"),
            other => panic!("expected String, got {:?}", other),
        }
        match &fields[3].1 {
            FieldValue::Boolean(v) => assert!(*v),
            other => panic!("expected Boolean, got {:?}", other),
        }
    }

    #[test]
    fn test_map_sample_null_and_objects_skipped() {
        let mapper = FieldMapper::new(
            vec!["null_tag".to_string(), "obj_tag".to_string()],
            vec!["null_field".to_string(), "arr_field".to_string()],
        );

        let sample = json!({
            "null_tag": null,
            "obj_tag": {"nested": true},
            "null_field": null,
            "arr_field": [1, 2, 3]
        });

        let (tags, fields) = mapper.map_sample(&sample);
        assert!(tags.is_empty());
        assert!(fields.is_empty());
    }
}
