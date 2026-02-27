// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Transformations for topic names and QoS policies.

use crate::config::{QosTransformConfig, TopicRemap};

/// Topic name transformer.
#[derive(Debug, Clone)]
pub struct TopicTransform {
    remaps: Vec<TopicRemap>,
}

impl TopicTransform {
    /// Create a new topic transformer.
    pub fn new(remaps: Vec<TopicRemap>) -> Self {
        Self { remaps }
    }

    /// Transform a topic name.
    ///
    /// Returns the remapped name if a match is found, otherwise returns the original.
    pub fn transform(&self, topic: &str) -> String {
        for remap in &self.remaps {
            if let Some(transformed) = remap.apply(topic) {
                return transformed;
            }
        }
        topic.to_string()
    }

    /// Check if any remapping applies to this topic.
    pub fn has_remap(&self, topic: &str) -> bool {
        self.remaps.iter().any(|r| r.apply(topic).is_some())
    }
}

impl Default for TopicTransform {
    fn default() -> Self {
        Self::new(Vec::new())
    }
}

/// QoS policy transformer.
#[derive(Debug, Clone, Default)]
pub struct QosTransform {
    config: Option<QosTransformConfig>,
}

impl QosTransform {
    /// Create a new QoS transformer.
    pub fn new(config: Option<QosTransformConfig>) -> Self {
        Self { config }
    }

    /// Check if this transformer has any active transformations.
    pub fn is_active(&self) -> bool {
        self.config.is_some()
    }

    /// Get reliability override.
    pub fn reliability(&self) -> Option<Reliability> {
        self.config.as_ref().and_then(|c| {
            c.reliability.as_ref().and_then(|r| match r.as_str() {
                "reliable" => Some(Reliability::Reliable),
                "best_effort" => Some(Reliability::BestEffort),
                _ => None,
            })
        })
    }

    /// Get durability override.
    pub fn durability(&self) -> Option<Durability> {
        self.config.as_ref().and_then(|c| {
            c.durability.as_ref().and_then(|d| match d.as_str() {
                "volatile" => Some(Durability::Volatile),
                "transient_local" => Some(Durability::TransientLocal),
                "transient" => Some(Durability::Transient),
                "persistent" => Some(Durability::Persistent),
                _ => None,
            })
        })
    }

    /// Get history depth override.
    pub fn history_depth(&self) -> Option<u32> {
        self.config.as_ref().and_then(|c| c.history_depth)
    }

    /// Get deadline override in microseconds.
    pub fn deadline_us(&self) -> Option<u64> {
        self.config.as_ref().and_then(|c| c.deadline_us)
    }

    /// Get lifespan override in microseconds.
    pub fn lifespan_us(&self) -> Option<u64> {
        self.config.as_ref().and_then(|c| c.lifespan_us)
    }
}

/// Reliability QoS kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reliability {
    BestEffort,
    Reliable,
}

/// Durability QoS kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Durability {
    Volatile,
    TransientLocal,
    Transient,
    Persistent,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_topic_transform_exact() {
        let transform = TopicTransform::new(vec![TopicRemap::new("Temperature", "Vehicle/Temp")]);

        assert_eq!(transform.transform("Temperature"), "Vehicle/Temp");
        assert_eq!(transform.transform("Pressure"), "Pressure");
    }

    #[test]
    fn test_topic_transform_pattern() {
        let transform = TopicTransform::new(vec![TopicRemap::new("Sensor/*", "Vehicle/*")]);

        assert_eq!(
            transform.transform("Sensor/Temperature"),
            "Vehicle/Temperature"
        );
        assert_eq!(
            transform.transform("Other/Temperature"),
            "Other/Temperature"
        );
    }

    #[test]
    fn test_topic_transform_multiple() {
        let transform = TopicTransform::new(vec![
            TopicRemap::new("Temperature", "Engine/Temperature"),
            TopicRemap::new("Sensor/*", "Vehicle/*"),
        ]);

        // First match wins
        assert_eq!(transform.transform("Temperature"), "Engine/Temperature");
        assert_eq!(transform.transform("Sensor/Pressure"), "Vehicle/Pressure");
    }

    #[test]
    fn test_qos_transform_reliability() {
        let config = QosTransformConfig {
            reliability: Some("reliable".into()),
            ..Default::default()
        };
        let transform = QosTransform::new(Some(config));

        assert_eq!(transform.reliability(), Some(Reliability::Reliable));
    }

    #[test]
    fn test_qos_transform_durability() {
        let config = QosTransformConfig {
            durability: Some("transient_local".into()),
            ..Default::default()
        };
        let transform = QosTransform::new(Some(config));

        assert_eq!(transform.durability(), Some(Durability::TransientLocal));
    }

    #[test]
    fn test_qos_transform_inactive() {
        let transform = QosTransform::default();
        assert!(!transform.is_active());
        assert_eq!(transform.reliability(), None);
        assert_eq!(transform.durability(), None);
    }
}
