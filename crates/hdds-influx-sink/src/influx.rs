// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! InfluxDB v2 Line Protocol writer.
//!
//! Line Protocol format:
//! ```text
//! measurement,tag1=val1,tag2=val2 field1=val1,field2=val2 timestamp_ns
//! ```
//!
//! See: <https://docs.influxdata.com/influxdb/v2/reference/syntax/line-protocol/>

use std::fmt;

/// A value that can be stored in an InfluxDB field.
#[derive(Debug, Clone)]
pub enum FieldValue {
    /// 64-bit floating point.
    Float(f64),
    /// 64-bit signed integer.
    Integer(i64),
    /// UTF-8 string.
    String(String),
    /// Boolean value.
    Boolean(bool),
}

impl FieldValue {
    /// Format this value for InfluxDB Line Protocol.
    ///
    /// - Float: written as-is (e.g., `3.14`)
    /// - Integer: suffixed with `i` (e.g., `42i`)
    /// - String: quoted with double quotes, inner quotes escaped (e.g., `"hello"`)
    /// - Boolean: `true` or `false`
    pub fn to_line_protocol(&self) -> String {
        match self {
            FieldValue::Float(v) => format!("{}", v),
            FieldValue::Integer(v) => format!("{}i", v),
            FieldValue::String(v) => {
                let escaped = v.replace('\\', "\\\\").replace('"', "\\\"");
                format!("\"{}\"", escaped)
            }
            FieldValue::Boolean(v) => {
                if *v {
                    "true".to_string()
                } else {
                    "false".to_string()
                }
            }
        }
    }
}

impl fmt::Display for FieldValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_line_protocol())
    }
}

/// InfluxDB v2 Line Protocol writer.
///
/// Accumulates points in an internal buffer and produces Line Protocol strings
/// when flushed.
pub struct LineProtocolWriter {
    buffer: Vec<String>,
}

impl LineProtocolWriter {
    /// Create a new empty writer.
    pub fn new() -> Self {
        Self { buffer: Vec::new() }
    }

    /// Write a single point in Line Protocol format.
    ///
    /// # Arguments
    /// - `measurement` - The measurement name
    /// - `tags` - Tag key-value pairs (indexed, for filtering)
    /// - `fields` - Field key-value pairs (actual data)
    /// - `timestamp_ns` - Timestamp in nanoseconds since Unix epoch
    ///
    /// # Panics
    /// Panics if `fields` is empty (InfluxDB requires at least one field).
    pub fn write_point(
        &mut self,
        measurement: &str,
        tags: &[(&str, &str)],
        fields: &[(&str, FieldValue)],
        timestamp_ns: u64,
    ) {
        assert!(!fields.is_empty(), "InfluxDB requires at least one field");

        let mut line = escape_measurement(measurement);

        // Append tags (sorted by key for canonical form)
        let mut sorted_tags: Vec<_> = tags.iter().collect();
        sorted_tags.sort_by_key(|(k, _)| *k);
        for (key, value) in &sorted_tags {
            line.push(',');
            line.push_str(&escape_tag_key(key));
            line.push('=');
            line.push_str(&escape_tag_value(value));
        }

        // Space separator before fields
        line.push(' ');

        // Append fields
        for (i, (key, value)) in fields.iter().enumerate() {
            if i > 0 {
                line.push(',');
            }
            line.push_str(&escape_field_key(key));
            line.push('=');
            line.push_str(&value.to_line_protocol());
        }

        // Space separator before timestamp
        line.push(' ');
        line.push_str(&timestamp_ns.to_string());

        self.buffer.push(line);
    }

    /// Flush the buffer, returning all accumulated lines.
    pub fn flush(&mut self) -> Vec<String> {
        std::mem::take(&mut self.buffer)
    }

    /// Get the current number of buffered lines.
    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    /// Check if the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }
}

impl Default for LineProtocolWriter {
    fn default() -> Self {
        Self::new()
    }
}

/// Escape measurement name per Line Protocol spec.
/// Spaces and commas must be escaped with backslash.
fn escape_measurement(s: &str) -> String {
    s.replace(',', "\\,").replace(' ', "\\ ")
}

/// Escape tag key per Line Protocol spec.
/// Commas, equals signs, and spaces must be escaped.
fn escape_tag_key(s: &str) -> String {
    s.replace(',', "\\,")
        .replace('=', "\\=")
        .replace(' ', "\\ ")
}

/// Escape tag value per Line Protocol spec.
/// Commas, equals signs, and spaces must be escaped.
fn escape_tag_value(s: &str) -> String {
    s.replace(',', "\\,")
        .replace('=', "\\=")
        .replace(' ', "\\ ")
}

/// Escape field key per Line Protocol spec.
/// Commas, equals signs, and spaces must be escaped.
fn escape_field_key(s: &str) -> String {
    s.replace(',', "\\,")
        .replace('=', "\\=")
        .replace(' ', "\\ ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_field_value_float() {
        let v = FieldValue::Float(3.15);
        assert_eq!(v.to_line_protocol(), "3.15");
    }

    #[test]
    fn test_field_value_integer() {
        let v = FieldValue::Integer(42);
        assert_eq!(v.to_line_protocol(), "42i");
    }

    #[test]
    fn test_field_value_string() {
        let v = FieldValue::String("hello world".to_string());
        assert_eq!(v.to_line_protocol(), "\"hello world\"");
    }

    #[test]
    fn test_field_value_string_with_quotes() {
        let v = FieldValue::String("say \"hi\"".to_string());
        assert_eq!(v.to_line_protocol(), "\"say \\\"hi\\\"\"");
    }

    #[test]
    fn test_field_value_boolean() {
        assert_eq!(FieldValue::Boolean(true).to_line_protocol(), "true");
        assert_eq!(FieldValue::Boolean(false).to_line_protocol(), "false");
    }

    #[test]
    fn test_line_protocol_simple_point() {
        let mut writer = LineProtocolWriter::new();
        writer.write_point(
            "temperature",
            &[],
            &[("value", FieldValue::Float(23.5))],
            1_000_000_000,
        );

        let lines = writer.flush();
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0], "temperature value=23.5 1000000000");
    }

    #[test]
    fn test_line_protocol_with_tags() {
        let mut writer = LineProtocolWriter::new();
        writer.write_point(
            "temperature",
            &[("sensor", "A1"), ("location", "room1")],
            &[("value", FieldValue::Float(23.5))],
            1_000_000_000,
        );

        let lines = writer.flush();
        assert_eq!(lines.len(), 1);
        // Tags are sorted alphabetically by key
        assert_eq!(
            lines[0],
            "temperature,location=room1,sensor=A1 value=23.5 1000000000"
        );
    }

    #[test]
    fn test_line_protocol_multiple_fields() {
        let mut writer = LineProtocolWriter::new();
        writer.write_point(
            "weather",
            &[("station", "north")],
            &[
                ("temp", FieldValue::Float(22.1)),
                ("humidity", FieldValue::Integer(65)),
                ("ok", FieldValue::Boolean(true)),
            ],
            2_000_000_000,
        );

        let lines = writer.flush();
        assert_eq!(lines.len(), 1);
        assert_eq!(
            lines[0],
            "weather,station=north temp=22.1,humidity=65i,ok=true 2000000000"
        );
    }

    #[test]
    fn test_line_protocol_escape_special_chars() {
        let mut writer = LineProtocolWriter::new();
        writer.write_point(
            "my measurement",
            &[("tag key", "tag,value")],
            &[("field=key", FieldValue::String("hello \"world\"".to_string()))],
            3_000_000_000,
        );

        let lines = writer.flush();
        assert_eq!(lines.len(), 1);
        assert_eq!(
            lines[0],
            "my\\ measurement,tag\\ key=tag\\,value field\\=key=\"hello \\\"world\\\"\" 3000000000"
        );
    }

    #[test]
    fn test_writer_len_and_empty() {
        let mut writer = LineProtocolWriter::new();
        assert!(writer.is_empty());
        assert_eq!(writer.len(), 0);

        writer.write_point(
            "m",
            &[],
            &[("f", FieldValue::Integer(1))],
            1,
        );
        assert!(!writer.is_empty());
        assert_eq!(writer.len(), 1);

        writer.flush();
        assert!(writer.is_empty());
    }
}
