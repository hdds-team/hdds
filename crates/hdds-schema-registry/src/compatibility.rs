// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

use crate::registry::SchemaFormat;

// ---------------------------------------------------------------------------
// Compatibility level
// ---------------------------------------------------------------------------

/// Describes how two schema versions relate to each other.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Compatibility {
    /// Both forward and backward compatible (e.g. identical schemas).
    Full,
    /// New schema can read data written by old schema.
    Backward,
    /// Old schema can read data written by new schema.
    Forward,
    /// The schemas are incompatible.
    Breaking,
}

// ---------------------------------------------------------------------------
// CompatibilityResult
// ---------------------------------------------------------------------------

/// Detailed result of a compatibility check between two schemas.
#[derive(Debug, Clone)]
pub struct CompatibilityResult {
    /// Overall compatibility level.
    pub compatibility: Compatibility,
    /// Human-readable details about what changed.
    pub details: Vec<String>,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Check compatibility between an old and a new schema version.
///
/// The analysis is intentionally simplified: it works on a line-by-line
/// structural diff of field declarations.  A full implementation would
/// use a proper IDL/JSON parser -- that is left for a future iteration.
pub fn check_compatibility(
    old: &str,
    new: &str,
    format: SchemaFormat,
) -> CompatibilityResult {
    match format {
        SchemaFormat::Idl4 => check_idl4_compatibility(old, new),
        SchemaFormat::Json => check_json_compatibility(old, new),
        SchemaFormat::XTypesHash => CompatibilityResult {
            compatibility: if old == new {
                Compatibility::Full
            } else {
                Compatibility::Breaking
            },
            details: vec!["XTypesHash comparison is binary".to_string()],
        },
    }
}

// ---------------------------------------------------------------------------
// IDL4 simplified compatibility checker
// ---------------------------------------------------------------------------

/// Lightweight field descriptor extracted from IDL text.
#[derive(Debug, Clone, PartialEq, Eq)]
struct IdlField {
    type_name: String,
    field_name: String,
}

/// Very simple IDL field extractor.
///
/// Recognises declarations of the form `<type> <name>;` inside a struct
/// body.  Works with both multi-line and single-line struct definitions
/// (e.g. `struct S { long x; string y; };`).
///
/// This is intentionally naive -- real IDL parsing is done elsewhere.
fn extract_idl_fields(schema: &str) -> Vec<IdlField> {
    let mut fields = Vec::new();

    // Normalise: strip everything up to and including the first '{',
    // and everything from the last '}' onward.  This isolates the
    // field body regardless of whether the struct is on one line or many.
    let body = match (schema.find('{'), schema.rfind('}')) {
        (Some(open), Some(close)) if open < close => &schema[open + 1..close],
        _ => schema,
    };

    // Split on ';' so that single-line structs are handled correctly.
    for statement in body.split(';') {
        let trimmed = statement.trim();
        if trimmed.is_empty() {
            continue;
        }

        // Skip keywords that may appear inside the body.
        if trimmed.starts_with("//")
            || trimmed.starts_with("struct")
            || trimmed.starts_with("module")
        {
            continue;
        }

        // Strip possible default value: "type name = value"
        let without_default = match trimmed.find('=') {
            Some(idx) => trimmed[..idx].trim(),
            None => trimmed,
        };

        let parts: Vec<&str> = without_default.split_whitespace().collect();
        if parts.len() >= 2 {
            fields.push(IdlField {
                type_name: parts[0].to_string(),
                field_name: parts[1].to_string(),
            });
        }
    }

    fields
}

fn check_idl4_compatibility(old: &str, new: &str) -> CompatibilityResult {
    let old_fields = extract_idl_fields(old);
    let new_fields = extract_idl_fields(new);

    // Identical
    if old_fields == new_fields {
        return CompatibilityResult {
            compatibility: Compatibility::Full,
            details: vec!["schemas are identical".to_string()],
        };
    }

    let mut details = Vec::new();
    let mut has_added = false;
    let mut has_removed = false;
    let mut has_type_change = false;

    // Build maps for lookup.
    let old_map: std::collections::HashMap<&str, &str> = old_fields
        .iter()
        .map(|f| (f.field_name.as_str(), f.type_name.as_str()))
        .collect();
    let new_map: std::collections::HashMap<&str, &str> = new_fields
        .iter()
        .map(|f| (f.field_name.as_str(), f.type_name.as_str()))
        .collect();

    // Fields added in new.
    for nf in &new_fields {
        if !old_map.contains_key(nf.field_name.as_str()) {
            details.push(format!("added field: {} {}", nf.type_name, nf.field_name));
            has_added = true;
        }
    }

    // Fields removed in new.
    for of in &old_fields {
        if !new_map.contains_key(of.field_name.as_str()) {
            details.push(format!("removed field: {} {}", of.type_name, of.field_name));
            has_removed = true;
        }
    }

    // Fields with changed type.
    for of in &old_fields {
        if let Some(&new_type) = new_map.get(of.field_name.as_str()) {
            if new_type != of.type_name {
                details.push(format!(
                    "changed type of {}: {} -> {}",
                    of.field_name, of.type_name, new_type
                ));
                has_type_change = true;
            }
        }
    }

    let compatibility = if has_type_change {
        Compatibility::Breaking
    } else if has_added && has_removed {
        // Both added and removed -- treat as breaking.
        Compatibility::Breaking
    } else if has_added {
        Compatibility::Backward
    } else if has_removed {
        Compatibility::Forward
    } else {
        // Field order change only -- treat as full.
        Compatibility::Full
    };

    CompatibilityResult {
        compatibility,
        details,
    }
}

// ---------------------------------------------------------------------------
// JSON simplified compatibility checker
// ---------------------------------------------------------------------------

fn check_json_compatibility(old: &str, new: &str) -> CompatibilityResult {
    // For JSON schemas we do a simple key-set diff on the top-level object.
    let old_keys = extract_json_keys(old);
    let new_keys = extract_json_keys(new);

    if old_keys == new_keys {
        return CompatibilityResult {
            compatibility: Compatibility::Full,
            details: vec!["JSON schemas are identical (same keys)".to_string()],
        };
    }

    let mut details = Vec::new();
    let mut has_added = false;
    let mut has_removed = false;

    for k in &new_keys {
        if !old_keys.contains(k) {
            details.push(format!("added key: {}", k));
            has_added = true;
        }
    }

    for k in &old_keys {
        if !new_keys.contains(k) {
            details.push(format!("removed key: {}", k));
            has_removed = true;
        }
    }

    let compatibility = if has_added && has_removed {
        Compatibility::Breaking
    } else if has_added {
        Compatibility::Backward
    } else if has_removed {
        Compatibility::Forward
    } else {
        Compatibility::Full
    };

    CompatibilityResult {
        compatibility,
        details,
    }
}

/// Very naive JSON top-level key extractor (avoids pulling in a full parser
/// for this lightweight check).
fn extract_json_keys(json: &str) -> Vec<String> {
    // Use serde_json to properly parse.
    match serde_json::from_str::<serde_json::Value>(json) {
        Ok(serde_json::Value::Object(map)) => {
            let mut keys: Vec<String> = map.keys().cloned().collect();
            keys.sort();
            keys
        }
        _ => Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identical_schemas_are_full() {
        let schema = "struct Sensor {\n  long id;\n  string name;\n};";
        let result = check_compatibility(schema, schema, SchemaFormat::Idl4);
        assert_eq!(result.compatibility, Compatibility::Full);
    }

    #[test]
    fn adding_field_is_backward() {
        let old = "struct Sensor {\n  long id;\n};";
        let new = "struct Sensor {\n  long id;\n  string name;\n};";
        let result = check_compatibility(old, new, SchemaFormat::Idl4);
        assert_eq!(result.compatibility, Compatibility::Backward);
        assert!(result.details.iter().any(|d| d.contains("added field")));
    }

    #[test]
    fn removing_field_is_forward() {
        let old = "struct Sensor {\n  long id;\n  string name;\n};";
        let new = "struct Sensor {\n  long id;\n};";
        let result = check_compatibility(old, new, SchemaFormat::Idl4);
        assert_eq!(result.compatibility, Compatibility::Forward);
        assert!(result.details.iter().any(|d| d.contains("removed field")));
    }

    #[test]
    fn changing_type_is_breaking() {
        let old = "struct Sensor {\n  long id;\n};";
        let new = "struct Sensor {\n  string id;\n};";
        let result = check_compatibility(old, new, SchemaFormat::Idl4);
        assert_eq!(result.compatibility, Compatibility::Breaking);
        assert!(result.details.iter().any(|d| d.contains("changed type")));
    }

    #[test]
    fn add_and_remove_is_breaking() {
        let old = "struct S {\n  long x;\n};";
        let new = "struct S {\n  long y;\n};";
        let result = check_compatibility(old, new, SchemaFormat::Idl4);
        assert_eq!(result.compatibility, Compatibility::Breaking);
    }

    #[test]
    fn json_identical_is_full() {
        let json = r#"{"id": "long", "name": "string"}"#;
        let result = check_compatibility(json, json, SchemaFormat::Json);
        assert_eq!(result.compatibility, Compatibility::Full);
    }

    #[test]
    fn json_added_key_is_backward() {
        let old = r#"{"id": "long"}"#;
        let new = r#"{"id": "long", "name": "string"}"#;
        let result = check_compatibility(old, new, SchemaFormat::Json);
        assert_eq!(result.compatibility, Compatibility::Backward);
    }

    #[test]
    fn xtypes_hash_different_is_breaking() {
        let result = check_compatibility("abc123", "def456", SchemaFormat::XTypesHash);
        assert_eq!(result.compatibility, Compatibility::Breaking);
    }
}
