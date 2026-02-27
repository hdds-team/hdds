// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Filtering for recording and replay.
//!
//! Supports include/exclude patterns for topics and types.

use std::collections::HashSet;

/// Topic name filter.
#[derive(Debug, Clone)]
pub struct TopicFilter {
    mode: FilterMode,
    patterns: HashSet<String>,
}

/// Type name filter.
#[derive(Debug, Clone)]
pub struct TypeFilter {
    mode: FilterMode,
    patterns: HashSet<String>,
}

/// Filter mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FilterMode {
    /// Include only matching patterns.
    Include,
    /// Exclude matching patterns.
    Exclude,
}

impl TopicFilter {
    /// Create an include filter (only record matching topics).
    pub fn include(topics: Vec<String>) -> Self {
        Self {
            mode: FilterMode::Include,
            patterns: topics.into_iter().collect(),
        }
    }

    /// Create an exclude filter (record all except matching topics).
    pub fn exclude(topics: Vec<String>) -> Self {
        Self {
            mode: FilterMode::Exclude,
            patterns: topics.into_iter().collect(),
        }
    }

    /// Check if a topic name matches the filter.
    pub fn matches(&self, topic: &str) -> bool {
        let is_match = self.patterns.iter().any(|p| Self::pattern_match(p, topic));

        match self.mode {
            FilterMode::Include => is_match,
            FilterMode::Exclude => !is_match,
        }
    }

    /// Simple wildcard pattern matching.
    /// Supports:
    /// - `*` matches any substring
    /// - Exact match otherwise
    fn pattern_match(pattern: &str, topic: &str) -> bool {
        if pattern == "*" {
            return true;
        }

        if pattern.contains('*') {
            // Simple prefix/suffix matching
            if pattern.starts_with('*') && pattern.ends_with('*') {
                let middle = &pattern[1..pattern.len() - 1];
                topic.contains(middle)
            } else if let Some(suffix) = pattern.strip_prefix('*') {
                topic.ends_with(suffix)
            } else if let Some(prefix) = pattern.strip_suffix('*') {
                topic.starts_with(prefix)
            } else {
                // Complex pattern - split on *
                let parts: Vec<&str> = pattern.split('*').collect();
                if parts.len() != 2 {
                    return pattern == topic;
                }
                topic.starts_with(parts[0]) && topic.ends_with(parts[1])
            }
        } else {
            pattern == topic
        }
    }

    /// Get the patterns in this filter.
    pub fn patterns(&self) -> &HashSet<String> {
        &self.patterns
    }

    /// Check if this is an include filter.
    pub fn is_include(&self) -> bool {
        self.mode == FilterMode::Include
    }
}

impl TypeFilter {
    /// Create an include filter (only record matching types).
    pub fn include(types: Vec<String>) -> Self {
        Self {
            mode: FilterMode::Include,
            patterns: types.into_iter().collect(),
        }
    }

    /// Create an exclude filter (record all except matching types).
    pub fn exclude(types: Vec<String>) -> Self {
        Self {
            mode: FilterMode::Exclude,
            patterns: types.into_iter().collect(),
        }
    }

    /// Check if a type name matches the filter.
    pub fn matches(&self, type_name: &str) -> bool {
        let is_match = self
            .patterns
            .iter()
            .any(|p| Self::pattern_match(p, type_name));

        match self.mode {
            FilterMode::Include => is_match,
            FilterMode::Exclude => !is_match,
        }
    }

    /// Simple wildcard pattern matching (same as TopicFilter).
    fn pattern_match(pattern: &str, name: &str) -> bool {
        if pattern == "*" {
            return true;
        }

        if pattern.contains('*') {
            if pattern.starts_with('*') && pattern.ends_with('*') {
                let middle = &pattern[1..pattern.len() - 1];
                name.contains(middle)
            } else if let Some(suffix) = pattern.strip_prefix('*') {
                name.ends_with(suffix)
            } else if let Some(prefix) = pattern.strip_suffix('*') {
                name.starts_with(prefix)
            } else {
                let parts: Vec<&str> = pattern.split('*').collect();
                if parts.len() != 2 {
                    return pattern == name;
                }
                name.starts_with(parts[0]) && name.ends_with(parts[1])
            }
        } else {
            pattern == name
        }
    }

    /// Get the patterns in this filter.
    pub fn patterns(&self) -> &HashSet<String> {
        &self.patterns
    }

    /// Check if this is an include filter.
    pub fn is_include(&self) -> bool {
        self.mode == FilterMode::Include
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_topic_filter_include_exact() {
        let filter = TopicFilter::include(vec!["Temperature".into(), "Pressure".into()]);

        assert!(filter.matches("Temperature"));
        assert!(filter.matches("Pressure"));
        assert!(!filter.matches("Humidity"));
    }

    #[test]
    fn test_topic_filter_exclude_exact() {
        let filter = TopicFilter::exclude(vec!["rt/debug".into()]);

        assert!(filter.matches("Temperature"));
        assert!(!filter.matches("rt/debug"));
    }

    #[test]
    fn test_topic_filter_wildcard_prefix() {
        let filter = TopicFilter::include(vec!["rt/*".into()]);

        assert!(filter.matches("rt/topic1"));
        assert!(filter.matches("rt/topic2/sub"));
        assert!(!filter.matches("other/topic"));
    }

    #[test]
    fn test_topic_filter_wildcard_suffix() {
        let filter = TopicFilter::include(vec!["*/Temperature".into()]);

        assert!(filter.matches("sensor/Temperature"));
        assert!(filter.matches("room1/Temperature"));
        assert!(!filter.matches("Temperature"));
        assert!(!filter.matches("sensor/Pressure"));
    }

    #[test]
    fn test_topic_filter_wildcard_contains() {
        let filter = TopicFilter::include(vec!["*sensor*".into()]);

        assert!(filter.matches("room/sensor/temp"));
        assert!(filter.matches("sensor_data"));
        assert!(!filter.matches("actuator"));
    }

    #[test]
    fn test_topic_filter_wildcard_all() {
        let filter = TopicFilter::include(vec!["*".into()]);

        assert!(filter.matches("anything"));
        assert!(filter.matches(""));
    }

    #[test]
    fn test_type_filter_include() {
        let filter = TypeFilter::include(vec!["sensor_msgs/*".into()]);

        assert!(filter.matches("sensor_msgs/Temperature"));
        assert!(filter.matches("sensor_msgs/Imu"));
        assert!(!filter.matches("std_msgs/String"));
    }

    #[test]
    fn test_type_filter_exclude() {
        let filter = TypeFilter::exclude(vec!["*Debug*".into()]);

        assert!(filter.matches("sensor_msgs/Temperature"));
        assert!(!filter.matches("internal/DebugInfo"));
    }

    #[test]
    fn test_topic_filter_pattern_middle() {
        let filter = TopicFilter::include(vec!["rt/*/status".into()]);

        assert!(filter.matches("rt/robot1/status"));
        assert!(filter.matches("rt/node/status"));
        assert!(!filter.matches("rt/robot1/cmd"));
    }
}
