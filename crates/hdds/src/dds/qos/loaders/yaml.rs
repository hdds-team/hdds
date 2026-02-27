// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! YAML QoS profile loader.
//!
//! Provides YAML-based configuration for QoS profiles with a clean, human-friendly format.
//!
//! # Example YAML
//!
//! ```yaml
//! # qos_profiles.yaml
//! profiles:
//!   reliable_sensor:
//!     reliability: RELIABLE
//!     durability: TRANSIENT_LOCAL
//!     history:
//!       kind: KEEP_LAST
//!       depth: 100
//!     deadline:
//!       period_ms: 1000
//!
//!   best_effort_telemetry:
//!     reliability: BEST_EFFORT
//!     durability: VOLATILE
//!     liveliness:
//!       kind: AUTOMATIC
//!       lease_duration_ms: 5000
//! ```

use crate::dds::qos::*;
use crate::qos::ResourceLimits;
use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::time::Duration;

/// YAML QoS profile loader.
pub struct YamlLoader;

/// Root YAML document structure.
#[derive(Debug, Deserialize)]
pub struct YamlQosDocument {
    /// Named QoS profiles.
    #[serde(default)]
    pub profiles: HashMap<String, YamlQosProfile>,

    /// Default profile name (optional).
    #[serde(default)]
    pub default_profile: Option<String>,
}

/// A single QoS profile in YAML format.
#[derive(Debug, Deserialize, Default)]
#[serde(default)]
pub struct YamlQosProfile {
    /// Reliability: RELIABLE or BEST_EFFORT
    pub reliability: Option<String>,

    /// Durability: VOLATILE, TRANSIENT_LOCAL, or PERSISTENT
    pub durability: Option<String>,

    /// History configuration
    pub history: Option<YamlHistory>,

    /// Liveliness configuration
    pub liveliness: Option<YamlLiveliness>,

    /// Ownership: SHARED or EXCLUSIVE
    pub ownership: Option<String>,

    /// Ownership strength (for EXCLUSIVE ownership)
    pub ownership_strength: Option<i32>,

    /// Destination order: BY_RECEPTION_TIMESTAMP or BY_SOURCE_TIMESTAMP
    pub destination_order: Option<String>,

    /// Presentation configuration
    pub presentation: Option<YamlPresentation>,

    /// Deadline configuration
    pub deadline: Option<YamlDeadline>,

    /// Lifespan configuration
    pub lifespan: Option<YamlLifespan>,

    /// Latency budget configuration
    pub latency_budget: Option<YamlLatencyBudget>,

    /// Time-based filter configuration
    pub time_based_filter: Option<YamlTimeBasedFilter>,

    /// Partition names
    pub partition: Option<Vec<String>>,

    /// User data (UTF-8 string or base64)
    pub user_data: Option<String>,

    /// Group data (UTF-8 string or base64)
    pub group_data: Option<String>,

    /// Topic data (UTF-8 string or base64)
    pub topic_data: Option<String>,

    /// Resource limits
    pub resource_limits: Option<YamlResourceLimits>,

    /// Writer data lifecycle
    pub writer_data_lifecycle: Option<YamlWriterDataLifecycle>,

    /// Reader data lifecycle
    pub reader_data_lifecycle: Option<YamlReaderDataLifecycle>,

    /// Entity factory
    pub entity_factory: Option<YamlEntityFactory>,

    /// Transport priority
    pub transport_priority: Option<i32>,
}

/// History QoS in YAML.
#[derive(Debug, Deserialize)]
pub struct YamlHistory {
    /// KEEP_LAST or KEEP_ALL
    pub kind: String,
    /// Depth for KEEP_LAST
    #[serde(default = "default_history_depth")]
    pub depth: u32,
}

fn default_history_depth() -> u32 {
    1
}

/// Liveliness QoS in YAML.
#[derive(Debug, Deserialize)]
pub struct YamlLiveliness {
    /// AUTOMATIC, MANUAL_BY_PARTICIPANT, or MANUAL_BY_TOPIC
    pub kind: String,
    /// Lease duration in milliseconds
    #[serde(default)]
    pub lease_duration_ms: Option<u64>,
    /// Lease duration in seconds (alternative)
    #[serde(default)]
    pub lease_duration_secs: Option<u64>,
}

/// Presentation QoS in YAML.
#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct YamlPresentation {
    /// INSTANCE, TOPIC, or GROUP
    pub access_scope: String,
    pub coherent_access: bool,
    pub ordered_access: bool,
}

impl Default for YamlPresentation {
    fn default() -> Self {
        Self {
            access_scope: "INSTANCE".to_string(),
            coherent_access: false,
            ordered_access: false,
        }
    }
}

/// Deadline QoS in YAML.
#[derive(Debug, Deserialize)]
pub struct YamlDeadline {
    /// Period in milliseconds
    #[serde(default)]
    pub period_ms: Option<u64>,
    /// Period in seconds (alternative)
    #[serde(default)]
    pub period_secs: Option<u64>,
}

/// Lifespan QoS in YAML.
#[derive(Debug, Deserialize)]
pub struct YamlLifespan {
    /// Duration in milliseconds
    #[serde(default)]
    pub duration_ms: Option<u64>,
    /// Duration in seconds (alternative)
    #[serde(default)]
    pub duration_secs: Option<u64>,
}

/// Latency budget QoS in YAML.
#[derive(Debug, Deserialize)]
pub struct YamlLatencyBudget {
    /// Duration in milliseconds
    #[serde(default)]
    pub duration_ms: Option<u64>,
    /// Duration in microseconds (alternative for fine-grained control)
    #[serde(default)]
    pub duration_us: Option<u64>,
}

/// Time-based filter QoS in YAML.
#[derive(Debug, Deserialize)]
pub struct YamlTimeBasedFilter {
    /// Minimum separation in milliseconds
    #[serde(default)]
    pub minimum_separation_ms: Option<u64>,
}

/// Resource limits QoS in YAML.
#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct YamlResourceLimits {
    pub max_samples: i32,
    pub max_instances: i32,
    pub max_samples_per_instance: i32,
}

impl Default for YamlResourceLimits {
    fn default() -> Self {
        Self {
            max_samples: -1,              // UNLIMITED
            max_instances: -1,            // UNLIMITED
            max_samples_per_instance: -1, // UNLIMITED
        }
    }
}

/// Writer data lifecycle QoS in YAML.
#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct YamlWriterDataLifecycle {
    pub autodispose_unregistered_instances: bool,
}

impl Default for YamlWriterDataLifecycle {
    fn default() -> Self {
        Self {
            autodispose_unregistered_instances: true,
        }
    }
}

/// Reader data lifecycle QoS in YAML.
#[derive(Debug, Deserialize)]
pub struct YamlReaderDataLifecycle {
    /// Autopurge nowriter samples delay in milliseconds
    #[serde(default)]
    pub autopurge_nowriter_samples_delay_ms: Option<u64>,
    /// Autopurge disposed samples delay in milliseconds
    #[serde(default)]
    pub autopurge_disposed_samples_delay_ms: Option<u64>,
}

/// Entity factory QoS in YAML.
#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct YamlEntityFactory {
    pub autoenable_created_entities: bool,
}

impl Default for YamlEntityFactory {
    fn default() -> Self {
        Self {
            autoenable_created_entities: true,
        }
    }
}

impl YamlLoader {
    /// Load QoS profiles from a YAML file.
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<YamlQosDocument, String> {
        crate::trace_fn!("YamlLoader::load_from_file");
        let yaml_content =
            fs::read_to_string(path).map_err(|e| format!("Failed to read YAML file: {}", e))?;
        Self::parse_yaml(&yaml_content)
    }

    /// Parse YAML content.
    pub fn parse_yaml(yaml_content: &str) -> Result<YamlQosDocument, String> {
        crate::trace_fn!("YamlLoader::parse_yaml");
        serde_yaml::from_str(yaml_content).map_err(|e| format!("Failed to parse YAML: {}", e))
    }

    /// Get QoS by profile name.
    pub fn get_profile(doc: &YamlQosDocument, name: &str) -> Result<QoS, String> {
        let profile = doc
            .profiles
            .get(name)
            .ok_or_else(|| format!("Profile '{}' not found", name))?;
        Self::profile_to_qos(profile)
    }

    /// Get default QoS from document.
    pub fn get_default_profile(doc: &YamlQosDocument) -> Result<QoS, String> {
        if let Some(ref default_name) = doc.default_profile {
            Self::get_profile(doc, default_name)
        } else if let Some((_, profile)) = doc.profiles.iter().next() {
            Self::profile_to_qos(profile)
        } else {
            Ok(QoS::default())
        }
    }

    /// Convert YAML profile to QoS.
    pub fn profile_to_qos(profile: &YamlQosProfile) -> Result<QoS, String> {
        let mut qos = QoS::default();

        // Reliability
        if let Some(ref rel) = profile.reliability {
            qos.reliability = match rel.to_uppercase().as_str() {
                "RELIABLE" => Reliability::Reliable,
                "BEST_EFFORT" => Reliability::BestEffort,
                other => return Err(format!("Invalid reliability: {}", other)),
            };
        }

        // Durability
        if let Some(ref dur) = profile.durability {
            qos.durability = match dur.to_uppercase().as_str() {
                "VOLATILE" => Durability::Volatile,
                "TRANSIENT_LOCAL" => Durability::TransientLocal,
                "PERSISTENT" => Durability::Persistent,
                other => return Err(format!("Invalid durability: {}", other)),
            };
        }

        // History
        if let Some(ref hist) = profile.history {
            qos.history = match hist.kind.to_uppercase().as_str() {
                "KEEP_LAST" => History::KeepLast(hist.depth),
                "KEEP_ALL" => History::KeepAll,
                other => return Err(format!("Invalid history kind: {}", other)),
            };
        }

        // Liveliness
        if let Some(ref liv) = profile.liveliness {
            let kind = match liv.kind.to_uppercase().as_str() {
                "AUTOMATIC" => LivelinessKind::Automatic,
                "MANUAL_BY_PARTICIPANT" => LivelinessKind::ManualByParticipant,
                "MANUAL_BY_TOPIC" => LivelinessKind::ManualByTopic,
                other => return Err(format!("Invalid liveliness kind: {}", other)),
            };

            let lease_duration = if let Some(ms) = liv.lease_duration_ms {
                Duration::from_millis(ms)
            } else if let Some(secs) = liv.lease_duration_secs {
                Duration::from_secs(secs)
            } else {
                Duration::MAX
            };

            qos.liveliness = Liveliness::new(kind, lease_duration);
        }

        // Ownership
        if let Some(ref own) = profile.ownership {
            qos.ownership = match own.to_uppercase().as_str() {
                "SHARED" => Ownership::shared(),
                "EXCLUSIVE" => Ownership::exclusive(),
                other => return Err(format!("Invalid ownership: {}", other)),
            };
        }

        // Ownership strength
        if let Some(strength) = profile.ownership_strength {
            qos.ownership_strength = OwnershipStrength::new(strength);
        }

        // Destination order
        if let Some(ref order) = profile.destination_order {
            qos.destination_order = match order.to_uppercase().as_str() {
                "BY_RECEPTION_TIMESTAMP" => DestinationOrder::by_reception_timestamp(),
                "BY_SOURCE_TIMESTAMP" => DestinationOrder::by_source_timestamp(),
                other => return Err(format!("Invalid destination order: {}", other)),
            };
        }

        // Presentation
        if let Some(ref pres) = profile.presentation {
            let access_scope = match pres.access_scope.to_uppercase().as_str() {
                "INSTANCE" => PresentationAccessScope::Instance,
                "TOPIC" => PresentationAccessScope::Topic,
                "GROUP" => PresentationAccessScope::Group,
                other => return Err(format!("Invalid presentation access scope: {}", other)),
            };
            qos.presentation =
                Presentation::new(access_scope, pres.coherent_access, pres.ordered_access);
        }

        // Deadline
        if let Some(ref deadline) = profile.deadline {
            let period = if let Some(ms) = deadline.period_ms {
                Duration::from_millis(ms)
            } else if let Some(secs) = deadline.period_secs {
                Duration::from_secs(secs)
            } else {
                Duration::MAX
            };
            qos.deadline = Deadline::new(period);
        }

        // Lifespan
        if let Some(ref lifespan) = profile.lifespan {
            let duration = if let Some(ms) = lifespan.duration_ms {
                Duration::from_millis(ms)
            } else if let Some(secs) = lifespan.duration_secs {
                Duration::from_secs(secs)
            } else {
                Duration::MAX
            };
            qos.lifespan = Lifespan::new(duration);
        }

        // Latency budget
        if let Some(ref latency) = profile.latency_budget {
            let duration = if let Some(us) = latency.duration_us {
                Duration::from_micros(us)
            } else if let Some(ms) = latency.duration_ms {
                Duration::from_millis(ms)
            } else {
                Duration::ZERO
            };
            qos.latency_budget = LatencyBudget::new(duration);
        }

        // Time-based filter
        if let Some(ref tbf) = profile.time_based_filter {
            let min_sep = tbf
                .minimum_separation_ms
                .map(Duration::from_millis)
                .unwrap_or(Duration::ZERO);
            qos.time_based_filter = TimeBasedFilter::new(min_sep);
        }

        // Partition
        if let Some(ref names) = profile.partition {
            if !names.is_empty() {
                qos.partition = Partition::new(names.clone());
            }
        }

        // User data
        if let Some(ref data) = profile.user_data {
            qos.user_data = UserData::new(data.as_bytes().to_vec());
        }

        // Group data
        if let Some(ref data) = profile.group_data {
            qos.group_data = GroupData::new(data.as_bytes().to_vec());
        }

        // Topic data
        if let Some(ref data) = profile.topic_data {
            qos.topic_data = TopicData::new(data.as_bytes().to_vec());
        }

        // Resource limits
        if let Some(ref limits) = profile.resource_limits {
            // Convert i32 (-1 = UNLIMITED) to usize
            let max_samples = if limits.max_samples < 0 {
                usize::MAX
            } else {
                limits.max_samples as usize
            };
            let max_instances = if limits.max_instances < 0 {
                usize::MAX
            } else {
                limits.max_instances as usize
            };
            let max_per_instance = if limits.max_samples_per_instance < 0 {
                usize::MAX
            } else {
                limits.max_samples_per_instance as usize
            };

            qos.resource_limits = ResourceLimits {
                max_samples,
                max_instances,
                max_samples_per_instance: max_per_instance,
                ..Default::default()
            };
        }

        // Writer data lifecycle
        if let Some(ref lifecycle) = profile.writer_data_lifecycle {
            qos.writer_data_lifecycle = if lifecycle.autodispose_unregistered_instances {
                WriterDataLifecycle::auto_dispose()
            } else {
                WriterDataLifecycle::manual_dispose()
            };
        }

        // Reader data lifecycle
        if let Some(ref lifecycle) = profile.reader_data_lifecycle {
            let nowriter_delay_us = lifecycle
                .autopurge_nowriter_samples_delay_ms
                .map(|ms| (ms as i64) * 1000) // ms to us
                .unwrap_or(i64::MAX);
            let disposed_delay_us = lifecycle
                .autopurge_disposed_samples_delay_ms
                .map(|ms| (ms as i64) * 1000)
                .unwrap_or(i64::MAX);
            qos.reader_data_lifecycle = ReaderDataLifecycle {
                autopurge_nowriter_samples_delay_us: nowriter_delay_us,
                autopurge_disposed_samples_delay_us: disposed_delay_us,
            };
        }

        // Entity factory
        if let Some(ref factory) = profile.entity_factory {
            qos.entity_factory = if factory.autoenable_created_entities {
                EntityFactory::auto_enable()
            } else {
                EntityFactory::manual_enable()
            };
        }

        // Transport priority
        if let Some(priority) = profile.transport_priority {
            qos.transport_priority = TransportPriority { value: priority };
        }

        Ok(qos)
    }

    /// Load a single QoS profile directly from file.
    ///
    /// If profile_name is None, uses the default profile.
    pub fn load_qos<P: AsRef<Path>>(path: P, profile_name: Option<&str>) -> Result<QoS, String> {
        let doc = Self::load_from_file(path)?;
        match profile_name {
            Some(name) => Self::get_profile(&doc, name),
            None => Self::get_default_profile(&doc),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_minimal_yaml() {
        let yaml = r#"
profiles:
  test:
    reliability: RELIABLE
    durability: TRANSIENT_LOCAL
"#;

        let doc = YamlLoader::parse_yaml(yaml).expect("valid YAML should parse");
        assert!(doc.profiles.contains_key("test"));

        let qos = YamlLoader::get_profile(&doc, "test").expect("profile should exist");
        assert!(matches!(qos.reliability, Reliability::Reliable));
        assert!(matches!(qos.durability, Durability::TransientLocal));
    }

    #[test]
    fn test_parse_full_qos_yaml() {
        let yaml = r#"
default_profile: sensor_reliable

profiles:
  sensor_reliable:
    reliability: RELIABLE
    durability: TRANSIENT_LOCAL
    history:
      kind: KEEP_LAST
      depth: 100
    liveliness:
      kind: AUTOMATIC
      lease_duration_ms: 5000
    deadline:
      period_ms: 1000
    ownership: SHARED
    presentation:
      access_scope: TOPIC
      coherent_access: true
      ordered_access: false
    partition:
      - sensors
      - building_a
    transport_priority: 10

  telemetry_fast:
    reliability: BEST_EFFORT
    durability: VOLATILE
    history:
      kind: KEEP_LAST
      depth: 1
    latency_budget:
      duration_us: 100
"#;

        let doc = YamlLoader::parse_yaml(yaml).expect("valid YAML should parse");
        assert_eq!(doc.profiles.len(), 2);
        assert_eq!(doc.default_profile, Some("sensor_reliable".to_string()));

        // Test default profile
        let default_qos = YamlLoader::get_default_profile(&doc).expect("default profile");
        assert!(matches!(default_qos.reliability, Reliability::Reliable));
        assert!(matches!(default_qos.history, History::KeepLast(100)));
        assert_eq!(default_qos.deadline.period, Duration::from_millis(1000));
        assert_eq!(default_qos.partition.names, vec!["sensors", "building_a"]);
        assert_eq!(default_qos.transport_priority.value, 10);

        // Test specific profile
        let fast_qos = YamlLoader::get_profile(&doc, "telemetry_fast").expect("fast profile");
        assert!(matches!(fast_qos.reliability, Reliability::BestEffort));
        assert!(matches!(fast_qos.durability, Durability::Volatile));
        assert_eq!(fast_qos.latency_budget.duration, Duration::from_micros(100));
    }

    #[test]
    fn test_case_insensitive() {
        let yaml = r#"
profiles:
  test:
    reliability: reliable
    durability: transient_local
    ownership: exclusive
    destination_order: by_source_timestamp
"#;

        let doc = YamlLoader::parse_yaml(yaml).expect("parse");
        let qos = YamlLoader::get_profile(&doc, "test").expect("profile");

        assert!(matches!(qos.reliability, Reliability::Reliable));
        assert!(matches!(qos.durability, Durability::TransientLocal));
        assert!(matches!(qos.ownership.kind, OwnershipKind::Exclusive));
        assert!(matches!(
            qos.destination_order.kind,
            DestinationOrderKind::BySourceTimestamp
        ));
    }

    #[test]
    fn test_resource_limits() {
        let yaml = r#"
profiles:
  limited:
    resource_limits:
      max_samples: 1000
      max_instances: 10
      max_samples_per_instance: 100
"#;

        let doc = YamlLoader::parse_yaml(yaml).expect("parse");
        let qos = YamlLoader::get_profile(&doc, "limited").expect("profile");

        assert_eq!(qos.resource_limits.max_samples, 1000);
        assert_eq!(qos.resource_limits.max_instances, 10);
        assert_eq!(qos.resource_limits.max_samples_per_instance, 100);
    }

    #[test]
    fn test_lifecycle_policies() {
        let yaml = r#"
profiles:
  lifecycle_test:
    writer_data_lifecycle:
      autodispose_unregistered_instances: false
    reader_data_lifecycle:
      autopurge_nowriter_samples_delay_ms: 5000
      autopurge_disposed_samples_delay_ms: 10000
    entity_factory:
      autoenable_created_entities: false
"#;

        let doc = YamlLoader::parse_yaml(yaml).expect("parse");
        let qos = YamlLoader::get_profile(&doc, "lifecycle_test").expect("profile");

        assert!(!qos.writer_data_lifecycle.autodispose_unregistered_instances);
        // ReaderDataLifecycle uses microseconds internally
        assert_eq!(
            qos.reader_data_lifecycle
                .autopurge_nowriter_samples_delay_us,
            5_000_000
        ); // 5000ms = 5,000,000us
        assert_eq!(
            qos.reader_data_lifecycle
                .autopurge_disposed_samples_delay_us,
            10_000_000
        ); // 10000ms = 10,000,000us
        assert!(!qos.entity_factory.autoenable_created_entities);
    }

    #[test]
    fn test_empty_document() {
        let yaml = r#"
profiles: {}
"#;

        let doc = YamlLoader::parse_yaml(yaml).expect("parse");
        assert!(doc.profiles.is_empty());

        let qos = YamlLoader::get_default_profile(&doc).expect("default");
        // Should return default QoS
        assert!(matches!(qos.reliability, Reliability::BestEffort));
    }

    #[test]
    fn test_invalid_reliability() {
        let yaml = r#"
profiles:
  bad:
    reliability: INVALID_VALUE
"#;

        let doc = YamlLoader::parse_yaml(yaml).expect("parse");
        let result = YamlLoader::get_profile(&doc, "bad");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid reliability"));
    }

    #[test]
    fn test_profile_not_found() {
        let yaml = r#"
profiles:
  existing: {}
"#;

        let doc = YamlLoader::parse_yaml(yaml).expect("parse");
        let result = YamlLoader::get_profile(&doc, "nonexistent");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not found"));
    }
}
