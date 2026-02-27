// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Content Filter Expression Parser and Evaluator
//!
//! Implements SQL-like filter expressions per DDS v1.4 specification.
//!
//! # Supported Syntax
//!
//! ```text
//! expression ::= condition
//!              | expression AND expression
//!              | expression OR expression
//!              | NOT expression
//!              | '(' expression ')'
//!
//! condition  ::= field_name operator value
//!
//! operator   ::= '>' | '<' | '>=' | '<=' | '=' | '<>' | '!='
//!
//! value      ::= parameter | literal
//! parameter  ::= '%' digit+
//! literal    ::= integer | float | string
//! ```
//!
//! # Example
//!
//! ```ignore
//! let filter = ContentFilter::new("temperature > %0 AND humidity < %1")?;
//! filter.set_parameters(vec!["25.0".to_string(), "80".to_string()]);
//! ```

mod evaluator;
mod parser;

pub use evaluator::{FieldValue, FilterEvaluator};
pub use parser::{parse_expression, Expression, Operator, Value};

use std::sync::{Arc, RwLock};

/// Content filter for SQL-like filtering of DDS samples.
///
/// Holds the filter expression and parameters. Can be attached to a
/// ContentFilteredTopic or DataReader to filter incoming samples.
#[derive(Debug, Clone)]
pub struct ContentFilter {
    /// Original filter expression string
    expression_str: String,

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
            expression: Arc::new(parsed),
            parameters: Arc::new(RwLock::new(Vec::new())),
            name: None,
        })
    }

    /// Create a new ContentFilter with initial parameters.
    pub fn with_parameters(expression: &str, parameters: Vec<String>) -> Result<Self, FilterError> {
        let mut filter = Self::new(expression)?;
        filter.set_parameters(parameters);
        Ok(filter)
    }

    /// Set the filter parameters.
    ///
    /// Parameters are substituted for %0, %1, etc. in the expression.
    pub fn set_parameters(&mut self, params: Vec<String>) {
        if let Ok(mut guard) = self.parameters.write() {
            *guard = params;
        }
    }

    /// Get current filter parameters.
    pub fn parameters(&self) -> Vec<String> {
        self.parameters
            .read()
            .map(|g| g.clone())
            .unwrap_or_default()
    }

    /// Get the filter expression string.
    pub fn expression(&self) -> &str {
        &self.expression_str
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
    fn test_content_filter_creation() {
        let filter = ContentFilter::new("temperature > %0").unwrap();
        assert_eq!(filter.expression(), "temperature > %0");
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
