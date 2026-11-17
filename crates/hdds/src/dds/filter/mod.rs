// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Content Filter Expression Parser and Evaluator
//!
//! Implements DDS 1.4 Annex B "Syntax for Queries and Filters" for the
//! ContentFilteredTopic `filter_expression` (`FilterExpression ::= Condition`,
//! [`parse_expression`]) and the QueryCondition `query_expression`
//! (`QueryExpression ::= {Condition}{'ORDER BY' (FIELDNAME // ',')}`,
//! [`parse_query_expression`]).
//!
//! # Grammar coverage (Annex B, B.2)
//!
//! Implemented in full: `Condition` (`AND`, `OR`, `NOT`, parentheses),
//! `Predicate`, the three `ComparisonPredicate` productions,
//! `BetweenPredicate` (`BETWEEN` and `NOT BETWEEN`), `RelOp` (`=`, `>`, `>=`,
//! `<`, `<=`, `<>`, `like`), `Range`, `Parameter`, and the tokens FIELDNAME
//! (dots, unlimited depth), INTEGERVALUE (optional sign, decimal or `0x`
//! hexadecimal, `i64::MIN..=u64::MAX`), FLOATVALUE (optional sign, `.`,
//! `e` exponent, binary64), CHARVALUE, STRING (left or right quote opener,
//! right quote closer, no new-line, no escapes), ENUMERATEDVALUE and
//! PARAMETER (`%0`..`%99`). `QueryExpression` accepts an optional
//! `Condition` and an `ORDER BY` FIELDNAME list, returned in
//! [`QueryExpression::order_by`].
//!
//! Not implemented: `TopicExpression` with `SelectFrom`, `Aggregation`,
//! `SubjectFieldSpec`, `Selection`, `JoinItem`, `NaturalJoin`, `Where` and
//! the TOPICNAME token. They belong to the MultiTopic class (DDS 1.4
//! 2.2.2.3.4, optional), which HDDS does not provide. `ORDER BY` is parsed
//! and returned; no read path orders samples by it.
//!
//! Every string outside the grammar is a [`FilterError::ParseError`] naming
//! the rule or token violated: double-quoted strings, a bare `TRUE`/`FALSE`
//! condition, a literal on both sides of a `RelOp`, array indexes, `%100`
//! and above, `NOT LIKE`, `IN`, `IS NULL`.
//!
//! # Source text and canonical form
//!
//! [`ContentFilter::expression`] (and `ContentFilteredTopic::filter_expression`,
//! `hdds_filter_get_expression`) return the expression exactly as specified at
//! creation, as DDS 1.4 2.2.2.3.3.2 defines `filter_expression`.
//! [`ContentFilter::canonical_expression`] (and
//! `hdds_filter_get_canonical_expression`) return the parsed expression
//! rendered back to text (`Display` on [`Expression`]): upper-case keywords,
//! Annex B operator spellings, decimal integers, single-quoted literals,
//! minimal parentheses. In this release neither form is announced or sent on
//! the wire: ContentFilterProperty is not announced and filtering is applied
//! reader-side only. The canonical text is strictly Annex B except for the
//! boolean literals `TRUE`/`FALSE`, which have no Annex B spelling (see
//! Extensions).
//!
//! # Extensions beyond Annex B
//!
//! - `!=` and `==` are accepted as local aliases of `<>` and `=` (the
//!   released C header documents `!=`). They exist only in the source text;
//!   the canonical form always reads `<>` and `=`. Parameter values are
//!   never rewritten: a parameter string containing `!=` is compared as is.
//! - Annex B has no boolean token. `TRUE` and `FALSE` (any case) are
//!   accepted as a `Parameter` on one side of a `ComparisonPredicate` with a
//!   boolean field (`enabled = TRUE`), as other DDS implementations accept
//!   them; they are refused inside a `Range` and as a bare Condition. The
//!   canonical text keeps them as `TRUE`/`FALSE`: it is Annex B in every
//!   other respect, but an expression using this extension has no Annex B
//!   spelling and a strict foreign parser may reject it. Within Annex B a
//!   boolean field also compares with INTEGERVALUE `0`/`1` and with the
//!   quoted labels `'TRUE'`/`'FALSE'` (case-insensitive).
//!
//! # Choices where Annex B is silent
//!
//! - Precedence: `NOT` binds tighter than `AND`, `AND` tighter than `OR`
//!   (SQL); parentheses override.
//! - Keywords are case-insensitive (B.2 prints `like` in lower case and the
//!   other keywords in upper case). FIELDNAMEs are case-sensitive.
//! - A FIELDNAME component is an IDL identifier (IDL 4.2 7.2.3): an ASCII
//!   letter followed by ASCII letters, digits or `_`, with at most one
//!   leading escape underscore that is not part of the name (`_leading`
//!   names the member `leading`, `_9` and `__x` are rejected). Annex B
//!   reserves no word for FIELDNAME: `order = 1` and `x = between` parse,
//!   position decides. Two spellings are keywords by position and need the
//!   escape to name a member: `NOT` at the start of a Condition, and
//!   `TRUE`/`FALSE` where a Parameter is expected (`_not = 1`, `x = _true`).
//!   The canonical form re-escapes every keyword-spelled component. Array
//!   indexes are not defined by Annex B and are rejected.
//! - A dotted FIELDNAME is looked up as one key of the `get_fields` map
//!   (`"pos.x"`); a type exposes nested members under their dotted path.
//! - `BETWEEN` is inclusive: `low <= field AND field <= high`, bounds in that
//!   order (a reversed range matches nothing). `NOT BETWEEN` is its
//!   two-valued negation.
//! - `like`: SQL-92 wildcards, `%` any sequence, `_` one character, no
//!   escape character, case-sensitive, string operands only.
//! - CHARVALUE, STRING and ENUMERATEDVALUE are one token; the field type
//!   decides. Against a string field the quoted text compares as a string
//!   (an enumeration field exposes its label as a string). Against an
//!   integer field a one-character literal compares by code point (an IDL
//!   char is carried as its code); a longer literal is a type error.
//!   Coercions read a literal or parameter in the type of the FIELD it is
//!   compared with; a field value is never reinterpreted, so a string field
//!   compared with an integer or a boolean is a type error.
//! - The ASCII left quote is the grave accent: `` `abc' `` and `'abc'` are
//!   the same STRING. The STRING exclusions (new-line, right quote) do not
//!   apply to a CHARVALUE: `'''` is a quoted apostrophe and `'<LF>'` a
//!   quoted new-line.
//! - INTEGERVALUE: `0X` is accepted with `0x`, a sign may precede `0x`,
//!   leading zeros are decimal. FLOATVALUE: `E` with `e`; `1.` and `.5` are
//!   accepted. PARAMETER: the index is the decimal value, `%07` is `%7`.
//! - Representability (a policy, not the grammar): a digit series outside
//!   `i64::MIN..=u64::MAX` is still FLOATVALUE syntax (point and exponent
//!   are optional) and is read as binary64; a FLOATVALUE that does not fit a
//!   finite binary64 (`1e400`) is rejected; a hexadecimal literal has no
//!   FLOATVALUE derivation and must fit 64 bits. Parameter values keep the
//!   stricter rule: an integral-looking parameter outside the integer range
//!   is rejected rather than rounded, so a 64-bit identifier never degrades
//!   silently.
//! - Parameter values (the strings behind `%n`) use the same token forms,
//!   plus: unquoted text is a string, `inf`/`infinity`/`nan` are IEEE
//!   values, `TRUE`/`FALSE` are booleans.
//! - A type mismatch (string vs number, ordered boolean) or an unknown field
//!   is an evaluation error, never `false`, in the operand that is actually
//!   evaluated. `AND` and `OR` short-circuit left to right, so an operand
//!   after the deciding one is not evaluated and its error is not reported:
//!   with `x = 65`, `x = 1 AND missing = 0` is `false`, while
//!   `missing = 0 AND x = 1` is an error. Parameter validation
//!   ([`ContentFilter::try_set_parameters`]) covers every branch.
//!
//! # Resource limits
//!
//! Parsing refuses nesting deeper than [`MAX_NESTING_DEPTH`] levels of
//! parentheses or `NOT`, and more than [`MAX_NODE_COUNT`] predicates and
//! connectives, with a `ParseError`. `AND`/`OR` chains are flat vectors
//! ([`Expression::And`], [`Expression::Or`]), so only nesting recurses, and
//! the depth bound covers parsing, rendering, validation, evaluation and
//! drop alike. No input can overflow the stack.
//!
//! # Numeric comparisons
//!
//! Comparisons order the represented values without first rounding integers
//! to floats. Float equality has no implicit epsilon. Signed zeros are equal;
//! infinities are ordered; NaN is unequal to every value and all ordered
//! comparisons with NaN are false. This is a two-valued IEEE policy.
//! Float syntax is rounded to binary64 when parsed; use integer syntax for
//! exact integer thresholds. Numeric parameters accept explicit NaN/inf/infinity
//! spellings, but a finite-looking parameter that overflows is rejected.
//!
//! # Example
//!
//! ```ignore
//! let filter = ContentFilter::new("temperature > %0 AND humidity < %1")?;
//! filter.try_set_parameters(vec!["25.0".to_string(), "80".to_string()])?;
//! ```

#[cfg(test)]
mod annex_b_vectors;
mod evaluator;
mod parser;

pub use evaluator::{FieldValue, FilterEvaluator};
pub use parser::{
    parse_expression, parse_query_expression, Expression, Operator, QueryExpression, Value,
    MAX_NESTING_DEPTH, MAX_NODE_COUNT,
};

use std::sync::{Arc, RwLock};

/// Content filter for SQL-like filtering of DDS samples.
///
/// Holds the filter expression and parameters. Can be attached to a
/// ContentFilteredTopic or DataReader to filter incoming samples.
#[derive(Debug, Clone)]
pub struct ContentFilter {
    /// The expression exactly as specified at creation (DDS 1.4 2.2.2.3.3.2).
    expression_str: String,

    /// The parsed expression rendered back to canonical Annex B text (not
    /// announced or sent on the wire in this release).
    canonical: String,

    /// Parsed expression tree
    expression: Arc<Expression>,

    /// Runtime parameters (substituted for %0, %1, etc.)
    parameters: Arc<RwLock<Vec<String>>>,

    /// Optional filter name (for debugging)
    name: Option<String>,
}

impl ContentFilter {
    /// Create a new ContentFilter from a filter expression.
    ///
    /// # Arguments
    ///
    /// * `expression` - SQL-like filter expression (e.g., "temperature > %0")
    ///
    /// # Returns
    ///
    /// Returns `Ok(ContentFilter)` if expression is valid, `Err` otherwise.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let filter = ContentFilter::new("value > %0 AND value < %1")?;
    /// ```
    pub fn new(expression: &str) -> Result<Self, FilterError> {
        let parsed = parse_expression(expression)?;
        Ok(Self {
            expression_str: expression.to_string(),
            canonical: parsed.to_string(),
            expression: Arc::new(parsed),
            parameters: Arc::new(RwLock::new(Vec::new())),
            name: None,
        })
    }

    /// Create a new ContentFilter with initial parameters.
    pub fn with_parameters(expression: &str, parameters: Vec<String>) -> Result<Self, FilterError> {
        let filter = Self::new(expression)?;
        filter.try_set_parameters(parameters)?;
        Ok(filter)
    }

    /// Set parameters using the legacy unit-returning interface.
    ///
    /// Invalid updates leave the old values unchanged and emit a warning.
    /// Use try_set_parameters to receive configuration errors directly.
    pub fn set_parameters(&mut self, params: Vec<String>) {
        if let Err(error) = self.try_set_parameters(params) {
            log::warn!("Filter parameter update rejected: {error}");
        }
    }

    /// Validate and atomically replace parameters shared with existing evaluators.
    ///
    /// Every referenced position must exist, even in a short-circuited branch.
    /// Numeric overflow is rejected before mutation. Field names and operand
    /// compatibility require sample schema information and are checked on evaluation.
    pub fn try_set_parameters(&self, params: Vec<String>) -> Result<(), FilterError> {
        evaluator::validate_expression_parameters(&self.expression, &params)?;
        let mut guard = self
            .parameters
            .write()
            .map_err(|_| FilterError::TypeMismatch("Failed to update parameters".into()))?;
        *guard = params;
        Ok(())
    }

    /// Get current filter parameters.
    pub fn parameters(&self) -> Vec<String> {
        self.parameters
            .read()
            .map(|g| g.clone())
            .unwrap_or_default()
    }

    /// Get the filter expression exactly as specified at creation.
    ///
    /// DDS 1.4 2.2.2.3.3.2 defines `filter_expression` as the expression
    /// specified when the ContentFilteredTopic was created; aliases such as
    /// `!=` are returned as written. Use [`ContentFilter::canonical_expression`]
    /// for the form to announce or persist.
    pub fn expression(&self) -> &str {
        &self.expression_str
    }

    /// Get the filter expression in canonical DDS 1.4 Annex B form.
    ///
    /// The parsed expression rendered back to text: `!=` reads `<>`, `==`
    /// reads `=`, keywords are upper-case, integers decimal, minimal
    /// parentheses. It is the form a future ContentFilterProperty announcement
    /// would carry; in this release neither form reaches the wire (filtering is
    /// reader-side only). The boolean literals `TRUE`/`FALSE` are the one
    /// extension it can contain, Annex B having no boolean spelling.
    pub fn canonical_expression(&self) -> &str {
        &self.canonical
    }

    /// Set an optional name for this filter.
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Get the filter name.
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// Create an evaluator for this filter.
    ///
    /// The evaluator can be used to test if samples match the filter.
    pub fn evaluator(&self) -> FilterEvaluator {
        FilterEvaluator::new(Arc::clone(&self.expression), Arc::clone(&self.parameters))
    }
}

/// Errors that can occur during filter operations.
#[derive(Debug, Clone, PartialEq)]
pub enum FilterError {
    /// Invalid filter expression syntax.
    ParseError(String),
    /// Unknown field name in expression.
    UnknownField(String),
    /// Parameter index out of range.
    ParameterOutOfRange(usize),
    /// Type mismatch during evaluation.
    TypeMismatch(String),
    /// Empty expression.
    EmptyExpression,
}

impl std::fmt::Display for FilterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FilterError::ParseError(msg) => write!(f, "Filter parse error: {}", msg),
            FilterError::UnknownField(name) => write!(f, "Unknown field: {}", name),
            FilterError::ParameterOutOfRange(idx) => write!(f, "Parameter %{} not provided", idx),
            FilterError::TypeMismatch(msg) => write!(f, "Type mismatch: {}", msg),
            FilterError::EmptyExpression => write!(f, "Empty filter expression"),
        }
    }
}

impl std::error::Error for FilterError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_parameters_preserve_existing_evaluators() {
        use std::collections::HashMap;
        let mut filter = ContentFilter::with_parameters("value > %0", vec!["40".into()]).unwrap();
        let evaluator = filter.evaluator();
        let fields = HashMap::from([("value".into(), FieldValue::Integer(50))]);
        for params in [
            vec![],
            vec!["1e400".into()],
            vec!["18446744073709551616".into()],
        ] {
            assert!(filter.try_set_parameters(params.clone()).is_err());
            assert_eq!(filter.parameters(), vec!["40"]);
            filter.set_parameters(params);
            assert!(evaluator.matches(&fields).unwrap());
        }
        filter.try_set_parameters(vec!["60".into()]).unwrap();
        assert!(!evaluator.matches(&fields).unwrap());
        // %1 sits in a branch that would short-circuit; it is validated anyway.
        assert!(
            ContentFilter::with_parameters("value > %0 OR value > %1", vec!["0".into()]).is_err()
        );
        assert!(ContentFilter::with_parameters("value = %0", vec!["'1e400'".into()]).is_ok());
    }

    #[test]
    fn test_content_filter_creation() {
        let filter = ContentFilter::new("temperature > %0").unwrap();
        assert_eq!(filter.expression(), "temperature > %0");
    }

    #[test]
    fn aliases_keep_the_source_text_and_canonicalize_separately() {
        use std::collections::HashMap;
        // (a) '!=' parses and evaluates exactly like '<>'.
        let alias = ContentFilter::new("x != 3 AND y == 4").unwrap();
        let canonical = ContentFilter::new("x <> 3 AND y = 4").unwrap();
        for (x, y) in [(3, 4), (2, 4), (3, 5), (2, 5)] {
            let fields = HashMap::from([
                ("x".to_string(), FieldValue::Integer(x)),
                ("y".to_string(), FieldValue::Integer(y)),
            ]);
            assert_eq!(
                alias.evaluator().matches(&fields),
                canonical.evaluator().matches(&fields),
                "x={x} y={y}"
            );
        }
        assert!(alias
            .evaluator()
            .matches(&HashMap::from([
                ("x".to_string(), FieldValue::Integer(2)),
                ("y".to_string(), FieldValue::Integer(4)),
            ]))
            .unwrap());
        // (b) DDS 1.4 2.2.2.3.3.2: `filter_expression` is "the expression
        // specified at creation", so the getter returns the source text
        // unchanged.
        assert_eq!(alias.expression(), "x != 3 AND y == 4");
        assert_eq!(canonical.expression(), "x <> 3 AND y = 4");
        // The canonical form is the Annex B spelling for both.
        assert_eq!(alias.canonical_expression(), "x <> 3 AND y = 4");
        assert_eq!(canonical.canonical_expression(), "x <> 3 AND y = 4");
        // (c) Parameter strings are data, never rewritten.
        let filter =
            ContentFilter::with_parameters("name == %0", vec!["a != b".to_string()]).unwrap();
        assert_eq!(filter.parameters(), vec!["a != b"]);
        assert_eq!(filter.expression(), "name == %0");
        assert_eq!(filter.canonical_expression(), "name = %0");
        let fields = HashMap::from([("name".to_string(), FieldValue::String("a != b".into()))]);
        assert!(filter.evaluator().matches(&fields).unwrap());
    }

    /// The three inputs that crashed the process with SIGSEGV before the
    /// nesting limits and the n-ary AND/OR representation: 20000 nested
    /// parentheses, 20000 NOTs, and a 50000-term AND chain. They run on the
    /// default test-thread stack; parse, render, re-parse, validate, evaluate
    /// and drop must all complete.
    #[test]
    fn pathological_nesting_and_chains_never_overflow_the_stack() {
        use std::collections::HashMap;
        let fields = HashMap::from([("x".to_string(), FieldValue::Integer(1))]);
        let deep_parens = format!("{}x = 1{}", "(".repeat(20_000), ")".repeat(20_000));
        let deep_not = format!("{}x = 1", "NOT ".repeat(20_000));
        let long_chain = vec!["x = 1"; 50_000].join(" AND ");
        for (input, accepted) in [(deep_parens, false), (deep_not, false), (long_chain, true)] {
            match ContentFilter::new(&input) {
                Ok(filter) => {
                    assert!(accepted, "{} bytes accepted", input.len());
                    let reparsed = parse_expression(filter.canonical_expression()).unwrap();
                    assert_eq!(reparsed.to_string(), filter.canonical_expression());
                    assert_eq!(filter.evaluator().matches(&fields), Ok(true));
                }
                Err(FilterError::ParseError(message)) => {
                    assert!(!accepted, "{} bytes rejected: {message}", input.len());
                    assert!(message.contains("nesting"), "{message}");
                }
                Err(other) => panic!("{other}"),
            }
        }
    }

    #[test]
    fn test_content_filter_with_parameters() {
        let filter =
            ContentFilter::with_parameters("temperature > %0", vec!["25.0".to_string()]).unwrap();
        assert_eq!(filter.parameters(), vec!["25.0".to_string()]);
    }

    #[test]
    fn test_content_filter_set_parameters() {
        let mut filter = ContentFilter::new("value > %0").unwrap();
        filter.set_parameters(vec!["100".to_string()]);
        assert_eq!(filter.parameters(), vec!["100".to_string()]);
    }

    #[test]
    fn test_content_filter_with_name() {
        let filter = ContentFilter::new("x > 0")
            .unwrap()
            .with_name("positive_filter");
        assert_eq!(filter.name(), Some("positive_filter"));
    }

    #[test]
    fn test_invalid_expression() {
        let result = ContentFilter::new("invalid @@@ expression");
        assert!(result.is_err());
    }
}
