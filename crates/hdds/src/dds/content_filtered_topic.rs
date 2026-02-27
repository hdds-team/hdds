// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! ContentFilteredTopic - filtered view of a Topic
//!
//! A ContentFilteredTopic is a specialized Topic that filters incoming samples
//! based on a SQL-like expression. Only samples matching the filter are delivered
//! to DataReaders created from this topic.
//!
//! # DDS v1.4 Specification
//!
//! Per DDS v1.4 Section 2.2.2.7.2:
//! - ContentFilteredTopic is a specialization of TopicDescription
//! - Has a related_topic (the underlying Topic)
//! - Has a filter_expression (SQL-like WHERE clause)
//! - Has expression_parameters (substitution values for %0, %1, etc.)
//!
//! # Example
//!
//! ```ignore
//! use hdds::{Participant, QoS};
//!
//! #[derive(hdds::DDS)]
//! struct Temperature {
//!     sensor_id: u32,
//!     value: f64,
//! }
//!
//! let participant = Participant::builder("app").build()?;
//!
//! // Create filtered topic: only temperatures > 25.0
//! let filtered_topic = participant.create_content_filtered_topic::<Temperature>(
//!     "high_temp",
//!     "sensors/temperature",
//!     "value > %0",
//!     vec!["25.0".to_string()],
//! )?;
//!
//! // Create reader from filtered topic
//! let reader = filtered_topic.reader().build()?;
//!
//! // Only receives samples where value > 25.0
//! while let Some(sample) = reader.take()? {
//!     println!("High temp: {}", sample.value);
//! }
//! ```

use super::filter::{ContentFilter, FilterError, FilterEvaluator};
use super::reader::ReaderBuilder;
use super::DDS;
use std::sync::Arc;

/// A filtered view of a DDS Topic.
///
/// ContentFilteredTopic allows creating DataReaders that only receive samples
/// matching a filter expression. The filtering is applied at the receiver side,
/// after deserialization but before delivery to the application.
///
/// # Type Parameter
///
/// * `T` - The data type (must implement [`DDS`])
///
/// # Filter Expression Syntax
///
/// The filter expression uses a SQL-like syntax:
///
/// ```text
/// expression ::= condition
///              | expression AND expression
///              | expression OR expression
///              | NOT expression
///              | '(' expression ')'
///
/// condition  ::= field_name operator value
///
/// operator   ::= '>' | '<' | '>=' | '<=' | '=' | '<>' | '!='
///
/// value      ::= parameter | literal
/// parameter  ::= '%' digit+
/// literal    ::= integer | float | 'string'
/// ```
///
/// # Example
///
/// ```ignore
/// // Filter: temperature > 25 AND humidity < 80
/// let filtered = participant.create_content_filtered_topic::<SensorData>(
///     "hot_dry",
///     "sensors",
///     "temperature > %0 AND humidity < %1",
///     vec!["25.0".to_string(), "80".to_string()],
/// )?;
/// ```
pub struct ContentFilteredTopic<T: DDS> {
    /// Name of this filtered topic (for identification)
    name: String,

    /// Name of the related (underlying) topic
    related_topic_name: String,

    /// Content filter specification
    filter: ContentFilter,

    /// Parent participant for creating readers
    participant: Arc<crate::Participant>,

    _phantom: core::marker::PhantomData<T>,
}

impl<T: DDS> ContentFilteredTopic<T> {
    /// Create a new ContentFilteredTopic.
    ///
    /// # Arguments
    ///
    /// * `name` - Name for this filtered topic
    /// * `related_topic_name` - Name of the underlying topic
    /// * `filter_expression` - SQL-like filter expression
    /// * `expression_parameters` - Values for %0, %1, etc.
    /// * `participant` - Parent participant
    ///
    /// # Returns
    ///
    /// Returns `Ok(ContentFilteredTopic)` if the filter expression is valid.
    pub fn new(
        name: impl Into<String>,
        related_topic_name: impl Into<String>,
        filter_expression: &str,
        expression_parameters: Vec<String>,
        participant: Arc<crate::Participant>,
    ) -> Result<Self, FilterError> {
        let filter = ContentFilter::with_parameters(filter_expression, expression_parameters)?;

        Ok(Self {
            name: name.into(),
            related_topic_name: related_topic_name.into(),
            filter,
            participant,
            _phantom: core::marker::PhantomData,
        })
    }

    /// Get the name of this filtered topic.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get the name of the related (underlying) topic.
    pub fn related_topic_name(&self) -> &str {
        &self.related_topic_name
    }

    /// Get the filter expression string.
    pub fn filter_expression(&self) -> &str {
        self.filter.expression()
    }

    /// Get the current expression parameters.
    pub fn expression_parameters(&self) -> Vec<String> {
        self.filter.parameters()
    }

    /// Set new expression parameters.
    ///
    /// This allows changing the filter parameters at runtime without
    /// creating a new ContentFilteredTopic.
    pub fn set_expression_parameters(&mut self, params: Vec<String>) {
        self.filter.set_parameters(params);
    }

    /// Get the content filter.
    pub fn filter(&self) -> &ContentFilter {
        &self.filter
    }

    /// Create a filter evaluator for this topic.
    pub fn evaluator(&self) -> FilterEvaluator {
        self.filter.evaluator()
    }

    /// Create a builder for a DataReader bound to this filtered topic.
    ///
    /// The returned ReaderBuilder will have the content filter attached,
    /// causing the reader to only receive samples matching the filter.
    pub fn reader(&self) -> ReaderBuilder<T> {
        ReaderBuilder::new(self.related_topic_name.clone())
            .with_participant(Arc::clone(&self.participant))
            .with_content_filter(self.filter.evaluator())
    }
}

impl<T: DDS> std::fmt::Debug for ContentFilteredTopic<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ContentFilteredTopic")
            .field("name", &self.name)
            .field("related_topic", &self.related_topic_name)
            .field("filter", &self.filter.expression())
            .field("parameters", &self.filter.parameters())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Note: Full integration tests require a Participant, which is tested
    // in the integration test suite. Here we just test the basic structure.

    #[test]
    fn test_filter_expression_parsing() {
        // Valid expressions
        assert!(ContentFilter::new("x > 1").is_ok());
        assert!(ContentFilter::new("x > %0 AND y < %1").is_ok());
        assert!(ContentFilter::new("name = 'test'").is_ok());

        // Invalid expressions
        assert!(ContentFilter::new("").is_err());
        assert!(ContentFilter::new("@@invalid").is_err());
    }

    #[test]
    fn test_content_filter_parameters() {
        let mut filter =
            ContentFilter::with_parameters("value > %0", vec!["100".to_string()]).unwrap();

        assert_eq!(filter.parameters(), vec!["100".to_string()]);

        filter.set_parameters(vec!["200".to_string()]);
        assert_eq!(filter.parameters(), vec!["200".to_string()]);
    }
}
