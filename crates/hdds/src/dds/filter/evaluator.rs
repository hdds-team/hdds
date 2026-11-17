// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Filter Expression Evaluator
//!
//! Evaluates parsed filter expressions against sample field values.

use super::parser::{Expression, Operator, Value};
use super::FilterError;
use std::cmp::Ordering;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

pub(super) fn validate_expression_parameters(
    expr: &Expression,
    params: &[String],
) -> Result<(), FilterError> {
    match expr {
        Expression::Comparison { left, right, .. } => {
            validate_operand_parameters([left, right], params)
        }
        Expression::Between { low, high, .. } => validate_operand_parameters([low, high], params),
        Expression::And(items) | Expression::Or(items) => items
            .iter()
            .try_for_each(|item| validate_expression_parameters(item, params)),
        Expression::Not(inner) => validate_expression_parameters(inner, params),
        Expression::True => Ok(()),
    }
}

fn validate_operand_parameters(
    operands: [&Value; 2],
    params: &[String],
) -> Result<(), FilterError> {
    for value in operands {
        if let Value::Parameter(index) = value {
            parse_parameter(
                params
                    .get(*index)
                    .ok_or(FilterError::ParameterOutOfRange(*index))?,
            )?;
        }
    }
    Ok(())
}

/// Parse a hexadecimal INTEGERVALUE parameter (`0x` prefix, optional sign).
/// Returns `None` when the text is not hexadecimal syntax at all.
fn parse_hex_parameter(param_str: &str) -> Option<Result<FieldValue, FilterError>> {
    let negative = param_str.starts_with('-');
    let unsigned_text = param_str.strip_prefix(['+', '-']).unwrap_or(param_str);
    let digits = unsigned_text
        .strip_prefix("0x")
        .or_else(|| unsigned_text.strip_prefix("0X"))?;
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Some(Err(FilterError::TypeMismatch(
            "Hexadecimal parameter must be 0x followed by hexadecimal digits".to_string(),
        )));
    }
    let Ok(magnitude) = u64::from_str_radix(digits, 16) else {
        return Some(Err(FilterError::TypeMismatch(
            "Integer parameter out of range".to_string(),
        )));
    };
    Some(if negative {
        i64::try_from(i128::from(magnitude).checked_neg().unwrap_or(i128::MIN))
            .map(FieldValue::Integer)
            .map_err(|_| FilterError::TypeMismatch("Integer parameter out of range".to_string()))
    } else {
        Ok(match i64::try_from(magnitude) {
            Ok(n) => FieldValue::Integer(n),
            Err(_) => FieldValue::Unsigned(magnitude),
        })
    })
}

/// Parse one expression parameter (the text behind `%n`).
///
/// The Annex B `Parameter` token forms are accepted: INTEGERVALUE (decimal or
/// `0x` hexadecimal, optional sign), FLOATVALUE (point and exponent), and the
/// single-quoted CHARVALUE / STRING / ENUMERATEDVALUE forms, which are
/// unquoted here. Beyond Annex B, and kept for compatibility: unquoted text
/// is a string, `TRUE`/`FALSE` are booleans, and `inf`/`infinity`/`nan` are
/// the IEEE non-finite values.
fn parse_parameter(param_str: &str) -> Result<FieldValue, FilterError> {
    let unsigned_text = param_str.strip_prefix(['+', '-']).unwrap_or(param_str);
    let is_integer = !unsigned_text.is_empty() && unsigned_text.bytes().all(|b| b.is_ascii_digit());
    // Try to parse as number first, then fall back to string.
    if let Some(hex) = parse_hex_parameter(param_str) {
        hex
    } else if let Ok(n) = param_str.parse::<i64>() {
        Ok(FieldValue::Integer(n))
    } else if let Ok(n) = param_str.parse::<u64>() {
        Ok(FieldValue::Unsigned(n))
    } else if is_integer {
        Err(FilterError::TypeMismatch(
            "Integer parameter out of range".to_string(),
        ))
    } else if let Ok(f) = param_str.parse::<f64>() {
        // Explicit IEEE infinity is supported, but an overflowing
        // finite-looking parameter must not silently become infinity.
        if f.is_infinite()
            && !unsigned_text.eq_ignore_ascii_case("inf")
            && !unsigned_text.eq_ignore_ascii_case("infinity")
        {
            Err(FilterError::TypeMismatch(
                "Floating parameter out of range".to_string(),
            ))
        } else {
            Ok(FieldValue::Float(f))
        }
    } else if param_str.eq_ignore_ascii_case("true") {
        Ok(FieldValue::Boolean(true))
    } else if param_str.eq_ignore_ascii_case("false") {
        Ok(FieldValue::Boolean(false))
    } else {
        // Annex B STRING: opened by a left (grave) or right (apostrophe)
        // quote, closed by a right quote. Strip that pair, so `color = 'RED'`
        // matches a sample whose color field is the bare string "RED".
        // Beyond Annex B: a matching pair of double quotes is stripped too,
        // and unquoted text is the string itself.
        let stripped = if (param_str.starts_with(['\'', '`']) && param_str.ends_with('\''))
            || (param_str.starts_with('"') && param_str.ends_with('"'))
        {
            if param_str.len() >= 2 {
                &param_str[1..param_str.len() - 1]
            } else {
                param_str
            }
        } else {
            param_str
        };
        Ok(FieldValue::String(stripped.to_string()))
    }
}

/// A resolved operand with its provenance. Coercions (CHARVALUE to code
/// point, `0`/`1`/`'TRUE'` to boolean) apply to a literal or parameter
/// compared with a typed field; a field value is never coerced.
struct Operand {
    value: FieldValue,
    from_field: bool,
}

impl Operand {
    fn field(value: FieldValue) -> Self {
        Self {
            value,
            from_field: true,
        }
    }

    fn literal(value: FieldValue) -> Self {
        Self {
            value,
            from_field: false,
        }
    }
}

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

    /// Validate every referenced parameter without evaluating sample fields.
    pub fn validate_parameters(&self) -> Result<(), FilterError> {
        let params = self
            .parameters
            .read()
            .map_err(|_| FilterError::TypeMismatch("Failed to read parameters".into()))?;
        validate_expression_parameters(&self.expression, &params)
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

            // BetweenPredicate: `low <= field AND field <= high`, bounds
            // inclusive as in SQL; `NOT BETWEEN` is its two-valued negation
            // (Annex B does not define the bounds, see the module doc). Both
            // bounds are checked so a type error in either is always reported.
            Expression::Between {
                field,
                low,
                high,
                negated,
            } => {
                let field_val = Operand::field(
                    fields
                        .get(field)
                        .cloned()
                        .ok_or_else(|| FilterError::UnknownField(field.clone()))?,
                );
                let low_val = self.resolve_value(low, fields, params)?;
                let high_val = self.resolve_value(high, fields, params)?;
                let above_low = self.compare(&field_val, Operator::Ge, &low_val)?;
                let below_high = self.compare(&field_val, Operator::Le, &high_val)?;
                Ok((above_low && below_high) != *negated)
            }

            // Left to right with short-circuit: an operand after the deciding
            // one is not evaluated, so its unknown field or type error is
            // not reported (see the module doc).
            Expression::And(items) => {
                for item in items {
                    if !self.evaluate(item, fields, params)? {
                        return Ok(false);
                    }
                }
                Ok(true)
            }

            Expression::Or(items) => {
                for item in items {
                    if self.evaluate(item, fields, params)? {
                        return Ok(true);
                    }
                }
                Ok(false)
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
    ) -> Result<Operand, FilterError> {
        Ok(match value {
            Value::Integer(n) => Operand::literal(FieldValue::Integer(*n)),
            Value::Unsigned(n) => Operand::literal(FieldValue::Unsigned(*n)),
            Value::Float(f) => Operand::literal(FieldValue::Float(*f)),
            Value::String(s) => Operand::literal(FieldValue::String(s.clone())),
            Value::Boolean(b) => Operand::literal(FieldValue::Boolean(*b)),

            Value::Parameter(idx) => Operand::literal(parse_parameter(
                params
                    .get(*idx)
                    .ok_or(FilterError::ParameterOutOfRange(*idx))?,
            )?),

            Value::Field(name) => Operand::field(
                fields
                    .get(name)
                    .cloned()
                    .ok_or_else(|| FilterError::UnknownField(name.clone()))?,
            ),
        })
    }

    fn compare(&self, left: &Operand, op: Operator, right: &Operand) -> Result<bool, FilterError> {
        use FieldValue::*;

        // Handle LIKE separately
        if matches!(op, Operator::Like) {
            return self.compare_like(&left.value, &right.value);
        }

        // A coercion reads a LITERAL (or parameter) in the type of the FIELD
        // it is compared with; the value of a field is never reinterpreted.
        let literal_vs_field = !left.from_field && right.from_field;
        let field_vs_literal = left.from_field && !right.from_field;

        match (&left.value, &right.value) {
            (Integer(a), Integer(b)) => Ok(self.compare_ord(*a, op, *b)),
            (Unsigned(a), Unsigned(b)) => Ok(self.compare_ord(*a, op, *b)),
            // i128 represents both full integer domains without wrapping or
            // losing low bits through an intermediate floating-point value.
            (Unsigned(a), Integer(b)) => Ok(self.compare_ord(i128::from(*a), op, i128::from(*b))),
            (Integer(a), Unsigned(b)) => Ok(self.compare_ord(i128::from(*a), op, i128::from(*b))),
            (Integer(a), Float(b)) => {
                Ok(self.compare_ordering(compare_integer_float(i128::from(*a), *b), op))
            }
            (Unsigned(a), Float(b)) => {
                Ok(self.compare_ordering(compare_integer_float(i128::from(*a), *b), op))
            }
            (Float(a), Integer(b)) => Ok(self.compare_ordering(
                compare_integer_float(i128::from(*b), *a).map(Ordering::reverse),
                op,
            )),
            (Float(a), Unsigned(b)) => Ok(self.compare_ordering(
                compare_integer_float(i128::from(*b), *a).map(Ordering::reverse),
                op,
            )),
            (Float(a), Float(b)) => Ok(self.compare_ordering(a.partial_cmp(b), op)),
            (String(a), String(b)) => Ok(self.compare_ord(a, op, b)),
            (Boolean(a), Boolean(b)) => self.compare_bool(*a, op, *b),
            // CHARVALUE against an integer-typed field: an IDL char reaches
            // the field map as its code (u8/i8), so a one-character quoted
            // LITERAL compares by code point. A longer STRING has no integer
            // reading, and a string FIELD is never read as a number.
            (Integer(_) | Unsigned(_), String(text)) if field_vs_literal => {
                let code = Operand::literal(Unsigned(char_code(text)?));
                self.compare(left, op, &code)
            }
            (String(text), Integer(_) | Unsigned(_)) if literal_vs_field => {
                let code = Operand::literal(Unsigned(char_code(text)?));
                self.compare(&code, op, right)
            }
            // Boolean FIELDS: Annex B has no boolean literal, so a boolean
            // field compares with the TRUE/FALSE extension, INTEGERVALUE 0/1
            // or the quoted labels 'TRUE'/'FALSE' (case-insensitive). A
            // string or integer field never reads as a boolean.
            (Boolean(a), Integer(_) | Unsigned(_) | String(_)) if field_vs_literal => {
                self.compare_bool(*a, op, bool_literal(&right.value)?)
            }
            (Integer(_) | Unsigned(_) | String(_), Boolean(b)) if literal_vs_field => {
                self.compare_bool(bool_literal(&left.value)?, op, *b)
            }
            _ => Err(FilterError::TypeMismatch(format!(
                "Cannot compare {:?} with {:?}",
                left.value, right.value
            ))),
        }
    }

    fn compare_bool(&self, a: bool, op: Operator, b: bool) -> Result<bool, FilterError> {
        match op {
            Operator::Eq => Ok(a == b),
            Operator::Ne => Ok(a != b),
            _ => Err(FilterError::TypeMismatch(
                "Boolean only supports = and <>".to_string(),
            )),
        }
    }

    fn compare_ord<T: Ord>(&self, a: T, op: Operator, b: T) -> bool {
        self.compare_ordering(Some(a.cmp(&b)), op)
    }

    fn compare_ordering(&self, ordering: Option<Ordering>, op: Operator) -> bool {
        match op {
            Operator::Gt => ordering == Some(Ordering::Greater),
            Operator::Lt => ordering == Some(Ordering::Less),
            Operator::Ge => matches!(ordering, Some(Ordering::Greater | Ordering::Equal)),
            Operator::Le => matches!(ordering, Some(Ordering::Less | Ordering::Equal)),
            Operator::Eq => ordering == Some(Ordering::Equal),
            // IEEE unordered values (NaN) compare unequal; ordered relations
            // are false. No implicit epsilon changes equality or ordering.
            Operator::Ne => ordering != Some(Ordering::Equal),
            Operator::Like => false, // Handled separately
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

/// Code point of a CHARVALUE: exactly one character between the quotes.
fn char_code(text: &str) -> Result<u64, FilterError> {
    let mut chars = text.chars();
    match (chars.next(), chars.next()) {
        (Some(ch), None) => Ok(u64::from(u32::from(ch))),
        _ => Err(FilterError::TypeMismatch(format!(
            "Cannot compare an integer field with the string {text:?}; only a one-character CHARVALUE compares by code point"
        ))),
    }
}

/// Boolean reading of a Parameter compared with a boolean field: INTEGERVALUE
/// 0/1 or the labels 'TRUE'/'FALSE' (any case).
fn bool_literal(value: &FieldValue) -> Result<bool, FilterError> {
    match value {
        FieldValue::Boolean(b) => Ok(*b),
        FieldValue::Integer(0) | FieldValue::Unsigned(0) => Ok(false),
        FieldValue::Integer(1) | FieldValue::Unsigned(1) => Ok(true),
        FieldValue::String(text) if text.eq_ignore_ascii_case("true") => Ok(true),
        FieldValue::String(text) if text.eq_ignore_ascii_case("false") => Ok(false),
        other => Err(FilterError::TypeMismatch(format!(
            "Cannot compare a boolean field with {other:?}; use TRUE, FALSE, 1, 0, 'TRUE' or 'FALSE'"
        ))),
    }
}

/// Compare an i64/u64 value with binary64 without rounding the integer.
/// Every caller constructs `integer` from i64 or u64, so it is in the interval
/// [i64::MIN, u64::MAX]. The bounds below are exactly representable powers of two.
fn compare_integer_float(integer: i128, float: f64) -> Option<Ordering> {
    if float.is_nan() {
        return None;
    }
    if float < -9_223_372_036_854_775_808.0 {
        return Some(Ordering::Greater);
    }
    if float >= 18_446_744_073_709_551_616.0 {
        return Some(Ordering::Less);
    }

    // Now float is finite and in the supported integer range. Converting its
    // integral part to i128 loses only its fraction, never an integer bit.
    let truncated = float as i128;
    match integer.cmp(&truncated) {
        Ordering::Equal => {
            // For equal integral parts, a positive fraction makes float larger;
            // a negative fraction makes it smaller. Both signed zeros are equal.
            float.fract().partial_cmp(&0.0).map(Ordering::reverse)
        }
        ordering => Some(ordering),
    }
}

/// SQL `like` matching: `%` any sequence, `_` exactly one Unicode scalar,
/// every other character (backslash included) literal; case-sensitive.
///
/// Iterative two-pointer wildcard matching: on a mismatch the scan resumes
/// after the most recent `%`, one text character further. Each text position
/// is revisited at most once per `%`, so the cost is O(n * m) and there is
/// no recursion. Annex B defines neither the wildcards nor an escape.
fn simple_like_match(text: &str, pattern: &str) -> bool {
    let text: Vec<char> = text.chars().collect();
    let pattern: Vec<char> = pattern.chars().collect();
    let mut t = 0;
    let mut p = 0;
    // Position after the last `%` seen, and the text position it matched.
    let mut resume: Option<(usize, usize)> = None;

    while t < text.len() {
        match pattern.get(p) {
            Some('%') => {
                p += 1;
                resume = Some((p, t));
            }
            Some(&pc) if pc == '_' || pc == text[t] => {
                t += 1;
                p += 1;
            }
            _ => match resume {
                Some((after_percent, matched_to)) => {
                    // Let the `%` absorb one more text character.
                    p = after_percent;
                    t = matched_to + 1;
                    resume = Some((after_percent, t));
                }
                None => return false,
            },
        }
    }
    // Only trailing `%`s can match the exhausted text.
    pattern[p..].iter().all(|&pc| pc == '%')
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
    fn unsigned_comparisons_preserve_integer_boundaries() {
        let fields = HashMap::from([
            ("zero".to_string(), FieldValue::Unsigned(0)),
            ("max".to_string(), FieldValue::Unsigned(u64::MAX)),
            ("previous".to_string(), FieldValue::Unsigned(u64::MAX - 1)),
            ("signed_max".to_string(), FieldValue::Integer(i64::MAX)),
            ("negative".to_string(), FieldValue::Integer(i64::MIN)),
        ]);
        for (expression, expected) in [
            ("zero = 0", true),
            ("zero >= 0", true),
            ("zero < negative", false),
            ("negative < zero", true),
            ("max > signed_max", true),
            ("max = 18446744073709551615", true),
            ("previous = 18446744073709551615", false),
            ("signed_max < max", true),
            ("max = previous", false),
            ("max <> previous", true),
            ("max > previous", true),
            ("previous <= max", true),
            ("max <= signed_max", false),
            ("zero < 0.5", true),
            ("0.5 > zero", true),
        ] {
            assert_eq!(
                make_evaluator(expression, vec![]).matches(&fields).unwrap(),
                expected,
                "{expression}"
            );
        }
    }

    #[test]
    fn unsigned_parameters_keep_all_64_bits() {
        let eval = make_evaluator("value = %0", vec![u64::MAX.to_string()]);
        let mut fields = HashMap::from([("value".to_string(), FieldValue::Unsigned(u64::MAX))]);
        assert!(eval.matches(&fields).unwrap());
        fields.insert("value".to_string(), FieldValue::Unsigned(u64::MAX - 1));
        assert!(!eval.matches(&fields).unwrap());
        for parameter in [
            "18446744073709551616",
            "+18446744073709551616",
            "-9223372036854775809",
        ] {
            assert!(make_evaluator("value = %0", vec![parameter.to_string()])
                .matches(&fields)
                .is_err());
        }
    }

    #[test]
    fn mixed_numeric_comparisons_do_not_round_integers() {
        let fields = HashMap::from([
            ("large".to_string(), FieldValue::Unsigned(u64::MAX)),
            (
                "power".to_string(),
                FieldValue::Float(18_446_744_073_709_551_616.0),
            ),
            (
                "integer".to_string(),
                FieldValue::Integer(9_007_199_254_740_993),
            ),
            (
                "rounded".to_string(),
                FieldValue::Float(9_007_199_254_740_992.0),
            ),
            ("zero".to_string(), FieldValue::Unsigned(0)),
            ("negative".to_string(), FieldValue::Float(-0.0000000005)),
        ]);
        for (expression, expected) in [
            ("large = power", false),
            ("large < power", true),
            ("power > large", true),
            ("integer = rounded", false),
            ("integer > rounded", true),
            ("rounded < integer", true),
            ("zero = negative", false),
            ("zero > negative", true),
            ("zero <= negative", false),
        ] {
            assert_eq!(
                make_evaluator(expression, vec![]).matches(&fields).unwrap(),
                expected,
                "{expression}"
            );
        }
    }

    #[test]
    fn nonfinite_comparisons_follow_ieee_and_overflow_is_rejected() {
        let mut fields = HashMap::from([("value".to_string(), FieldValue::Float(f64::NAN))]);
        for (expression, expected) in [
            ("value = value", false),
            ("value <> value", true),
            ("NOT (value = value)", true),
            ("value > 0", false),
            ("NOT (value > 0)", true),
            ("value <= 0", false),
        ] {
            assert_eq!(
                make_evaluator(expression, vec![]).matches(&fields).unwrap(),
                expected,
                "{expression}"
            );
        }
        fields.insert("value".to_string(), FieldValue::Float(f64::INFINITY));
        for parameter in ["inf", "+Infinity", "INF"] {
            assert!(make_evaluator("value = %0", vec![parameter.to_string()])
                .matches(&fields)
                .unwrap());
        }
        assert!(!make_evaluator("value = %0", vec!["NaN".to_string()])
            .matches(&fields)
            .unwrap());
        assert!(make_evaluator("value <> %0", vec!["NaN".to_string()])
            .matches(&fields)
            .unwrap());
        for parameter in ["1e400", "-1e400"] {
            assert!(make_evaluator("value = %0", vec![parameter.to_string()])
                .matches(&fields)
                .is_err());
        }
    }

    #[test]
    fn boolean_literals_match_boolean_fields() {
        let fields = HashMap::from([("enabled".to_string(), FieldValue::Boolean(true))]);
        for (expression, expected) in [
            ("enabled = TRUE", true),
            ("enabled = FALSE", false),
            ("TRUE = enabled", true),
            ("enabled = FALSE OR (NOT enabled = FALSE)", true),
        ] {
            assert_eq!(
                make_evaluator(expression, vec![]).matches(&fields).unwrap(),
                expected
            );
        }
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

    /// The `"%a" * n + "b"` family against `"a" * n` made the recursive
    /// matcher explore 2^n alternatives before failing; the iterative
    /// two-pointer algorithm is O(n * m). One second is three orders of
    /// magnitude above the fixed cost in debug builds.
    #[test]
    fn like_pathological_pattern_is_polynomial() {
        let text = "a".repeat(30);
        let pattern = format!("{}b", "%a".repeat(30));
        let started = std::time::Instant::now();
        assert!(!simple_like_match(&text, &pattern));
        assert!(simple_like_match(&text, &"%a".repeat(30)));
        assert!(simple_like_match(&format!("{text}b"), &pattern));
        assert!(
            started.elapsed() < std::time::Duration::from_secs(1),
            "{:?}",
            started.elapsed()
        );
        // Wildcards versus literal characters that look like wildcards.
        assert!(simple_like_match("50%", "50%"));
        assert!(simple_like_match("50%", "50_"));
        assert!(!simple_like_match("50", "50_"));
        assert!(simple_like_match("a\\b", "a\\b"));
        assert!(!simple_like_match("ab", "a\\b"));
        assert!(simple_like_match("", "%%"));
        assert!(!simple_like_match("", "_"));
        assert!(simple_like_match("caf\u{e9}", "caf_"));
    }

    /// Errors surface only from the operands that are evaluated: AND/OR
    /// short-circuit left to right (documented in the module doc).
    #[test]
    fn short_circuit_hides_errors_in_unevaluated_operands() {
        let fields = HashMap::from([("x".to_string(), FieldValue::Integer(65))]);
        assert_eq!(
            make_evaluator("x = 1 AND missing = 0", vec![]).matches(&fields),
            Ok(false)
        );
        assert_eq!(
            make_evaluator("x = 65 OR missing = 0", vec![]).matches(&fields),
            Ok(true)
        );
        assert!(matches!(
            make_evaluator("missing = 0 AND x = 1", vec![]).matches(&fields),
            Err(FilterError::UnknownField(_))
        ));
        assert!(matches!(
            make_evaluator("x = 65 AND x = 'ab'", vec![]).matches(&fields),
            Err(FilterError::TypeMismatch(_))
        ));
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
