// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Log filtering by level, participant, and topic.

use serde::{Deserialize, Serialize};

/// Log severity levels (compatible with ROS 2 rcl_interfaces/Log).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[repr(u8)]
#[derive(Default)]
pub enum LogLevel {
    /// Unset/unknown level.
    Unset = 0,
    /// Debug messages for development.
    Debug = 10,
    /// Informational messages.
    #[default]
    Info = 20,
    /// Warning messages.
    Warn = 30,
    /// Error messages.
    Error = 40,
    /// Fatal/critical errors.
    Fatal = 50,
}

impl LogLevel {
    /// Get level name as string.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Unset => "UNSET",
            Self::Debug => "DEBUG",
            Self::Info => "INFO",
            Self::Warn => "WARN",
            Self::Error => "ERROR",
            Self::Fatal => "FATAL",
        }
    }

    /// Parse level from string (case-insensitive).
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_uppercase().as_str() {
            "UNSET" => Some(Self::Unset),
            "DEBUG" => Some(Self::Debug),
            "INFO" => Some(Self::Info),
            "WARN" | "WARNING" => Some(Self::Warn),
            "ERROR" | "ERR" => Some(Self::Error),
            "FATAL" | "CRITICAL" => Some(Self::Fatal),
            _ => None,
        }
    }

    /// Get numeric value for syslog priority calculation.
    pub fn syslog_severity(&self) -> u8 {
        match self {
            Self::Unset => 7, // Debug
            Self::Debug => 7, // Debug
            Self::Info => 6,  // Informational
            Self::Warn => 4,  // Warning
            Self::Error => 3, // Error
            Self::Fatal => 2, // Critical
        }
    }
}

impl std::fmt::Display for LogLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Log filter configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogFilter {
    /// Minimum log level to include.
    pub min_level: LogLevel,
    /// Participant GUID pattern (glob-style, e.g., "01.0f.*").
    pub participant_pattern: Option<String>,
    /// Topic name pattern (glob-style, e.g., "rt/*").
    pub topic_pattern: Option<String>,
    /// Node name pattern (for ROS 2 logs).
    pub node_pattern: Option<String>,
    /// Message content pattern (regex).
    pub message_pattern: Option<String>,
}

impl Default for LogFilter {
    fn default() -> Self {
        Self {
            min_level: LogLevel::Info,
            participant_pattern: None,
            topic_pattern: None,
            node_pattern: None,
            message_pattern: None,
        }
    }
}

impl LogFilter {
    /// Create a filter that accepts all logs.
    pub fn all() -> Self {
        Self {
            min_level: LogLevel::Unset,
            ..Default::default()
        }
    }

    /// Create a filter for a minimum level.
    pub fn min_level(level: LogLevel) -> Self {
        Self {
            min_level: level,
            ..Default::default()
        }
    }

    /// Check if a log entry passes this filter.
    pub fn matches(&self, entry: &super::LogEntry) -> bool {
        // Level check
        if entry.level < self.min_level {
            return false;
        }

        // Participant pattern check
        if let Some(ref pattern) = self.participant_pattern {
            if !glob_match(pattern, &entry.participant_id) {
                return false;
            }
        }

        // Topic pattern check
        if let Some(ref pattern) = self.topic_pattern {
            if let Some(ref topic) = entry.topic {
                if !glob_match(pattern, topic) {
                    return false;
                }
            }
        }

        // Node pattern check
        if let Some(ref pattern) = self.node_pattern {
            if let Some(ref node) = entry.node_name {
                if !glob_match(pattern, node) {
                    return false;
                }
            }
        }

        // Message pattern check (simple contains for now)
        if let Some(ref pattern) = self.message_pattern {
            if !entry.message.contains(pattern) {
                return false;
            }
        }

        true
    }
}

/// Simple glob-style pattern matching.
/// Supports: * (any chars), ? (single char)
fn glob_match(pattern: &str, text: &str) -> bool {
    let mut pattern_chars = pattern.chars().peekable();
    let mut text_chars = text.chars().peekable();

    while let Some(p) = pattern_chars.next() {
        match p {
            '*' => {
                // Skip consecutive stars
                while pattern_chars.peek() == Some(&'*') {
                    pattern_chars.next();
                }

                // If star is at end, match everything
                if pattern_chars.peek().is_none() {
                    return true;
                }

                // Try matching from each position
                let remaining_pattern: String = pattern_chars.collect();
                while text_chars.peek().is_some() {
                    let remaining_text: String = text_chars.clone().collect();
                    if glob_match(&remaining_pattern, &remaining_text) {
                        return true;
                    }
                    text_chars.next();
                }
                // Also try with empty remaining text
                return glob_match(&remaining_pattern, "");
            }
            '?' => {
                // Must match exactly one character
                if text_chars.next().is_none() {
                    return false;
                }
            }
            c => {
                // Must match exact character
                if text_chars.next() != Some(c) {
                    return false;
                }
            }
        }
    }

    // Pattern exhausted - text must also be exhausted
    text_chars.peek().is_none()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_level_ordering() {
        assert!(LogLevel::Debug < LogLevel::Info);
        assert!(LogLevel::Info < LogLevel::Warn);
        assert!(LogLevel::Warn < LogLevel::Error);
        assert!(LogLevel::Error < LogLevel::Fatal);
    }

    #[test]
    fn test_log_level_from_str() {
        assert_eq!(LogLevel::parse("debug"), Some(LogLevel::Debug));
        assert_eq!(LogLevel::parse("INFO"), Some(LogLevel::Info));
        assert_eq!(LogLevel::parse("Warning"), Some(LogLevel::Warn));
        assert_eq!(LogLevel::parse("ERR"), Some(LogLevel::Error));
        assert_eq!(LogLevel::parse("invalid"), None);
    }

    #[test]
    fn test_glob_match_exact() {
        assert!(glob_match("hello", "hello"));
        assert!(!glob_match("hello", "world"));
        assert!(!glob_match("hello", "hello!"));
    }

    #[test]
    fn test_glob_match_star() {
        assert!(glob_match("*", "anything"));
        assert!(glob_match("*", ""));
        assert!(glob_match("hello*", "hello"));
        assert!(glob_match("hello*", "hello world"));
        assert!(glob_match("*world", "hello world"));
        assert!(glob_match("hello*world", "hello big world"));
        assert!(!glob_match("hello*world", "hello big moon"));
    }

    #[test]
    fn test_glob_match_question() {
        assert!(glob_match("h?llo", "hello"));
        assert!(glob_match("h?llo", "hallo"));
        assert!(!glob_match("h?llo", "hllo"));
        assert!(!glob_match("h?llo", "heello"));
    }

    #[test]
    fn test_glob_match_combined() {
        assert!(glob_match("rt/*", "rt/rosout"));
        assert!(glob_match("rt/*", "rt/topic/nested"));
        assert!(glob_match("*/rosout", "rt/rosout"));
        assert!(glob_match("rt/ros?ut", "rt/rosout"));
    }

    #[test]
    fn test_filter_level() {
        use super::super::LogEntry;

        let filter = LogFilter::min_level(LogLevel::Warn);

        let debug_entry = LogEntry {
            level: LogLevel::Debug,
            message: "test".to_string(),
            participant_id: "test".to_string(),
            ..Default::default()
        };

        let warn_entry = LogEntry {
            level: LogLevel::Warn,
            message: "test".to_string(),
            participant_id: "test".to_string(),
            ..Default::default()
        };

        assert!(!filter.matches(&debug_entry));
        assert!(filter.matches(&warn_entry));
    }
}
