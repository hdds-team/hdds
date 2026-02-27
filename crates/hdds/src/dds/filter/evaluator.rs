// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Filter Expression Evaluator
//!
//! Evaluates parsed filter expressions against sample field values.

use super::parser::{Expression, Operator, Value};
use super::FilterError;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// Evaluates filter expressions against sample data.
///
/// The evaluator holds a reference to the parsed expression and parameters,
/// and can evaluate the filter against a map of field values.
#[derive(Clone)]
pub struct FilterEvaluator {
    expression: Arc<Expression>,
    parameters: Arc<RwLock<Vec<String>>>,
}

impl FilterEvaluator {
    /// Create a new evaluator.
    pub fn new(expression: Arc<Expression>, parameters: Arc<RwLock<Vec<String>>>) -> Self {
        Self {
            expression,
            parameters,
        }
    }

    /// Evaluate the filter against field values.
    ///
    /// # Arguments
    ///
    /// * `fields` - Map of field name to field value
    ///
    /// # Returns
    ///
    /// Returns `Ok(true)` if the sample matches, `Ok(false)` if not,
    /// or an error if evaluation fails.
    pub fn matches(&self, fields: &HashMap<String, FieldValue>) -> Result<bool, FilterError> {
        let params = self
            .parameters
            .read()
            .map_err(|_| FilterError::TypeMismatch("Failed to read parameters".to_string()))?;
        self.evaluate(&self.expression, fields, &params)
    }

    /// Evaluate with explicit parameters (for testing).
    pub fn matches_with_params(
        &self,
        fields: &HashMap<String, FieldValue>,
        params: &[String],
    ) -> Result<bool, FilterError> {
        self.evaluate(&self.expression, fields, params)
    }

    fn evaluate(
        &self,
        expr: &Expression,
        fields: &HashMap<String, FieldValue>,
        params: &[String],
    ) -> Result<bool, FilterError> {
        match expr {
            Expression::True => Ok(true),

            Expression::Comparison { left, op, right } => {
                let left_val = self.resolve_value(left, fields, params)?;
                let right_val = self.resolve_value(right, fields, params)?;
                self.compare(&left_val, *op, &right_val)
            }

            Expression::And(left, right) => {
                let l = self.evaluate(left, fields, params)?;
                if !l {
                    return Ok(false); // Short-circuit
                }
                self.evaluate(right, fields, params)
            }

            Expression::Or(left, right) => {
                let l = self.evaluate(left, fields, params)?;
                if l {
                    return Ok(true); // Short-circuit
                }
                self.evaluate(right, fields, params)
            }

            Expression::Not(inner) => {
                let val = self.evaluate(inner, fields, params)?;
                Ok(!val)
            }
        }
    }

    fn resolve_value(
        &self,
        value: &Value,
        fields: &HashMap<String, FieldValue>,
        params: &[String],
    ) -> Result<FieldValue, FilterError> {
        match value {
            Value::Integer(n) => Ok(FieldValue::Integer(*n)),
            Value::Float(f) => Ok(FieldValue::Float(*f)),
            Value::String(s) => Ok(FieldValue::String(s.clone())),
            Value::Boolean(b) => Ok(FieldValue::Boolean(*b)),

            Value::Parameter(idx) => {
                let param_str = params
                    .get(*idx)
                    .ok_or(FilterError::ParameterOutOfRange(*idx))?;
                // Try to parse as number first, then fall back to string
                if let Ok(n) = param_str.parse::<i64>() {
                    Ok(FieldValue::Integer(n))
                } else if let Ok(f) = param_str.parse::<f64>() {
                    Ok(FieldValue::Float(f))
                } else if param_str.eq_ignore_ascii_case("true") {
                    Ok(FieldValue::Boolean(true))
                } else if param_str.eq_ignore_ascii_case("false") {
                    Ok(FieldValue::Boolean(false))
                } else {
                    Ok(FieldValue::String(param_str.clone()))
                }
            }

            Value::Field(name) => fields
                .get(name)
                .cloned()
                .ok_or_else(|| FilterError::UnknownField(name.clone())),
        }
    }

    fn compare(
        &self,
        left: &FieldValue,
        op: Operator,
        right: &FieldValue,
    ) -> Result<bool, FilterError> {
        use FieldValue::*;

        // Handle LIKE separately
        if matches!(op, Operator::Like) {
            return self.compare_like(left, right);
        }

        // Promote types if needed (int -> float for mixed comparisons)
        let (left, right) = self.coerce_types(left, right)?;

        match (&left, &right) {
            (Integer(a), Integer(b)) => Ok(self.compare_ord(*a, op, *b)),
            (Float(a), Float(b)) => Ok(self.compare_float(*a, op, *b)),
            (String(a), String(b)) => Ok(self.compare_ord(a, op, b)),
            (Boolean(a), Boolean(b)) => match op {
                Operator::Eq => Ok(a == b),
                Operator::Ne => Ok(a != b),
                _ => Err(FilterError::TypeMismatch(
                    "Boolean only supports = and <>".to_string(),
                )),
            },
            _ => Err(FilterError::TypeMismatch(format!(
                "Cannot compare {:?} with {:?}",
                left, right
            ))),
        }
    }

    fn coerce_types(
        &self,
        left: &FieldValue,
        right: &FieldValue,
    ) -> Result<(FieldValue, FieldValue), FilterError> {
        use FieldValue::*;

        match (left, right) {
            // Int + Float -> Float + Float
            (Integer(a), Float(b)) => Ok((Float(*a as f64), Float(*b))),
            (Float(a), Integer(b)) => Ok((Float(*a), Float(*b as f64))),
            // Same types - no coercion needed
            _ => Ok((left.clone(), right.clone())),
        }
    }

    fn compare_ord<T: Ord>(&self, a: T, op: Operator, b: T) -> bool {
        match op {
            Operator::Gt => a > b,
            Operator::Lt => a < b,
            Operator::Ge => a >= b,
            Operator::Le => a <= b,
            Operator::Eq => a == b,
            Operator::Ne => a != b,
            Operator::Like => false, // Handled separately
        }
    }

    fn compare_float(&self, a: f64, op: Operator, b: f64) -> bool {
        const EPSILON: f64 = 1e-9;
        match op {
            Operator::Gt => a > b,
            Operator::Lt => a < b,
            Operator::Ge => a >= b || (a - b).abs() < EPSILON,
            Operator::Le => a <= b || (a - b).abs() < EPSILON,
            Operator::Eq => (a - b).abs() < EPSILON,
            Operator::Ne => (a - b).abs() >= EPSILON,
            Operator::Like => false,
        }
    }

    fn compare_like(&self, left: &FieldValue, right: &FieldValue) -> Result<bool, FilterError> {
        let (text, pattern) = match (left, right) {
            (FieldValue::String(t), FieldValue::String(p)) => (t, p),
            _ => {
                return Err(FilterError::TypeMismatch(
                    "LIKE requires string operands".to_string(),
                ))
            }
        };

        // Simple character-by-character matching (no regex dependency)
        Ok(simple_like_match(text, pattern))
    }
}

/// Simple LIKE pattern matching without regex.
///
/// Supports:
/// - `%` matches any sequence of characters (including empty)
/// - `_` matches any single character
fn simple_like_match(text: &str, pattern: &str) -> bool {
    let text_chars: Vec<char> = text.chars().collect();
    let pattern_chars: Vec<char> = pattern.chars().collect();

    fn matches(text: &[char], pattern: &[char]) -> bool {
        match (text.is_empty(), pattern.is_empty()) {
            (true, true) => true,
            (_, true) => false,
            (true, false) => pattern.iter().all(|&c| c == '%'),
            (false, false) => {
                match pattern[0] {
                    '%' => {
                        // % matches zero or more characters
                        matches(text, &pattern[1..]) || matches(&text[1..], pattern)
                    }
                    '_' => {
                        // _ matches exactly one character
                        matches(&text[1..], &pattern[1..])
                    }
                    c => {
                        // Exact match
                        text[0] == c && matches(&text[1..], &pattern[1..])
                    }
                }
            }
        }
    }

    matches(&text_chars, &pattern_chars)
}

/// Runtime field value for filter evaluation.
#[derive(Debug, Clone, PartialEq)]
pub enum FieldValue {
    /// Integer value
    Integer(i64),
    /// Floating point value
    Float(f64),
    /// String value
    String(String),
    /// Boolean value
    Boolean(bool),
    /// Unsigned integer (for sensor_id, etc.)
    Unsigned(u64),
}

impl FieldValue {
    /// Create from i32
    pub fn from_i32(v: i32) -> Self {
        FieldValue::Integer(v as i64)
    }

    /// Create from u32
    pub fn from_u32(v: u32) -> Self {
        FieldValue::Unsigned(v as u64)
    }

    /// Create from i64
    pub fn from_i64(v: i64) -> Self {
        FieldValue::Integer(v)
    }

    /// Create from u64
    pub fn from_u64(v: u64) -> Self {
        FieldValue::Unsigned(v)
    }

    /// Create from f32
    pub fn from_f32(v: f32) -> Self {
        FieldValue::Float(v as f64)
    }

    /// Create from f64
    pub fn from_f64(v: f64) -> Self {
        FieldValue::Float(v)
    }

    /// Create from bool
    pub fn from_bool(v: bool) -> Self {
        FieldValue::Boolean(v)
    }

    /// Create from string
    pub fn from_string(v: impl Into<String>) -> Self {
        FieldValue::String(v.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dds::filter::parse_expression;
    use std::sync::RwLock;

    fn make_evaluator(expr: &str, params: Vec<String>) -> FilterEvaluator {
        let expression = Arc::new(parse_expression(expr).unwrap());
        let parameters = Arc::new(RwLock::new(params));
        FilterEvaluator::new(expression, parameters)
    }

    #[test]
    fn test_simple_comparison() {
        let eval = make_evaluator("temperature > 25", vec![]);
        let mut fields = HashMap::new();
        fields.insert("temperature".to_string(), FieldValue::Float(30.0));
        assert!(eval.matches(&fields).unwrap());

        fields.insert("temperature".to_string(), FieldValue::Float(20.0));
        assert!(!eval.matches(&fields).unwrap());
    }

    #[test]
    fn test_parameter_substitution() {
        let eval = make_evaluator("value > %0", vec!["100".to_string()]);
        let mut fields = HashMap::new();

        fields.insert("value".to_string(), FieldValue::Integer(150));
        assert!(eval.matches(&fields).unwrap());

        fields.insert("value".to_string(), FieldValue::Integer(50));
        assert!(!eval.matches(&fields).unwrap());
    }

    #[test]
    fn test_and_expression() {
        let eval = make_evaluator("a > 10 AND b < 20", vec![]);
        let mut fields = HashMap::new();

        fields.insert("a".to_string(), FieldValue::Integer(15));
        fields.insert("b".to_string(), FieldValue::Integer(10));
        assert!(eval.matches(&fields).unwrap());

        fields.insert("a".to_string(), FieldValue::Integer(5)); // a <= 10
        assert!(!eval.matches(&fields).unwrap());
    }

    #[test]
    fn test_or_expression() {
        let eval = make_evaluator("a > 100 OR b = 1", vec![]);
        let mut fields = HashMap::new();

        fields.insert("a".to_string(), FieldValue::Integer(50));
        fields.insert("b".to_string(), FieldValue::Integer(1));
        assert!(eval.matches(&fields).unwrap()); // b = 1

        fields.insert("b".to_string(), FieldValue::Integer(0));
        assert!(!eval.matches(&fields).unwrap()); // neither true
    }

    #[test]
    fn test_not_expression() {
        let eval = make_evaluator("NOT value = 0", vec![]);
        let mut fields = HashMap::new();

        fields.insert("value".to_string(), FieldValue::Integer(1));
        assert!(eval.matches(&fields).unwrap());

        fields.insert("value".to_string(), FieldValue::Integer(0));
        assert!(!eval.matches(&fields).unwrap());
    }

    #[test]
    fn test_string_comparison() {
        let eval = make_evaluator("name = 'sensor1'", vec![]);
        let mut fields = HashMap::new();

        fields.insert(
            "name".to_string(),
            FieldValue::String("sensor1".to_string()),
        );
        assert!(eval.matches(&fields).unwrap());

        fields.insert(
            "name".to_string(),
            FieldValue::String("sensor2".to_string()),
        );
        assert!(!eval.matches(&fields).unwrap());
    }

    #[test]
    fn test_float_comparison() {
        let pi = std::f64::consts::PI;
        let eval = make_evaluator(&format!("value >= {pi}"), vec![]);
        let mut fields = HashMap::new();

        fields.insert("value".to_string(), FieldValue::Float(pi));
        assert!(eval.matches(&fields).unwrap());

        fields.insert("value".to_string(), FieldValue::Float(pi - 0.01));
        assert!(!eval.matches(&fields).unwrap());
    }

    #[test]
    fn test_int_float_coercion() {
        let eval = make_evaluator("value > 10", vec![]);
        let mut fields = HashMap::new();

        // Float field compared with int literal
        fields.insert("value".to_string(), FieldValue::Float(15.5));
        assert!(eval.matches(&fields).unwrap());
    }

    #[test]
    fn test_like_pattern() {
        assert!(simple_like_match("hello", "hello"));
        assert!(simple_like_match("hello", "h%"));
        assert!(simple_like_match("hello", "%o"));
        assert!(simple_like_match("hello", "%ell%"));
        assert!(simple_like_match("hello", "h_llo"));
        assert!(!simple_like_match("hello", "world"));
        assert!(!simple_like_match("hello", "h_o")); // _ only matches one char
    }

    #[test]
    fn test_unknown_field() {
        let eval = make_evaluator("nonexistent > 0", vec![]);
        let fields = HashMap::new();
        assert!(matches!(
            eval.matches(&fields),
            Err(FilterError::UnknownField(_))
        ));
    }

    #[test]
    fn test_parameter_out_of_range() {
        let eval = make_evaluator("value > %5", vec!["1".to_string()]);
        let mut fields = HashMap::new();
        fields.insert("value".to_string(), FieldValue::Integer(10));
        assert!(matches!(
            eval.matches(&fields),
            Err(FilterError::ParameterOutOfRange(5))
        ));
    }
}
