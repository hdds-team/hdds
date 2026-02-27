// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! QoS profile registry with named profiles loaded from YAML files.
//!
//! Provides a registry of named QoS profiles that can be loaded from YAML files
//! and hot-reloaded at runtime. Supports the simplified YAML format with
//! shorthand keys like `reliability`, `history_depth`, `deadline_ms`, etc.
//!
//! # DDS Spec Mutability Constraints
//!
//! Per the DDS specification, QoS policies have mutability constraints:
//!
//! **MUTABLE** (can be changed at runtime via hot-reload):
//! - Deadline, LatencyBudget, TransportPriority, Lifespan, Partition, TimeBasedFilter
//!
//! **IMMUTABLE** (set at entity creation, cannot be changed):
//! - Durability, Reliability, History, Ownership, DestinationOrder, ResourceLimits
//!
//! When hot-reloading, immutable policy changes are logged and skipped.
//!
//! # Example
//!
//! ```rust,ignore
//! use hdds::dds::qos::profiles::QosProfileRegistry;
//! use std::path::Path;
//!
//! let registry = QosProfileRegistry::new();
//! registry.load_from_yaml(Path::new("qos_profiles.yaml")).unwrap();
//!
//! let qos = registry.get("high_reliability").unwrap();
//! ```

use crate::dds::qos::loaders::yaml::{YamlLoader, YamlQosDocument};
use crate::dds::qos::QoS;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use crate::dds::qos::{
    Deadline, Durability, History, LatencyBudget, Lifespan, Partition, Reliability,
    TimeBasedFilter, TransportPriority,
};

/// A named QoS profile combining a name with its QoS configuration.
#[derive(Debug, Clone)]
pub struct QosProfile {
    /// Profile name (as defined in the YAML file).
    pub name: String,
    /// The QoS configuration for this profile.
    pub qos: QoS,
}

/// Result of a hot-reload operation, detailing what changed.
#[derive(Debug, Clone)]
pub struct ReloadResult {
    /// Profiles that were updated with new values.
    pub profiles_updated: Vec<String>,
    /// New profiles that were added.
    pub profiles_added: Vec<String>,
    /// Profiles that were removed (no longer in the file).
    pub profiles_removed: Vec<String>,
    /// Any errors encountered during reload (non-fatal).
    pub errors: Vec<String>,
}

impl ReloadResult {
    /// Check if any changes were detected.
    pub fn has_changes(&self) -> bool {
        !self.profiles_updated.is_empty()
            || !self.profiles_added.is_empty()
            || !self.profiles_removed.is_empty()
    }

    /// Total number of changes (additions + updates + removals).
    pub fn total_changes(&self) -> usize {
        self.profiles_updated.len() + self.profiles_added.len() + self.profiles_removed.len()
    }
}

/// DDS QoS policy mutability classification per the DDS specification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyMutability {
    /// Policy can be changed at runtime (hot-reload safe).
    Mutable,
    /// Policy is set at entity creation and cannot be changed.
    Immutable,
}

/// Known DDS QoS policy names for mutability classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyKind {
    Deadline,
    LatencyBudget,
    TransportPriority,
    Lifespan,
    Partition,
    TimeBasedFilter,
    Durability,
    Reliability,
    History,
    Ownership,
    DestinationOrder,
    ResourceLimits,
}

impl PolicyKind {
    /// Get the mutability classification for this policy.
    pub fn mutability(&self) -> PolicyMutability {
        match self {
            // MUTABLE policies (DDS spec allows runtime changes)
            PolicyKind::Deadline
            | PolicyKind::LatencyBudget
            | PolicyKind::TransportPriority
            | PolicyKind::Lifespan
            | PolicyKind::Partition
            | PolicyKind::TimeBasedFilter => PolicyMutability::Mutable,

            // IMMUTABLE policies (DDS spec: set at creation only)
            PolicyKind::Durability
            | PolicyKind::Reliability
            | PolicyKind::History
            | PolicyKind::Ownership
            | PolicyKind::DestinationOrder
            | PolicyKind::ResourceLimits => PolicyMutability::Immutable,
        }
    }

    /// Check if this policy can be hot-reloaded.
    pub fn is_mutable(&self) -> bool {
        self.mutability() == PolicyMutability::Mutable
    }
}

/// Intermediate representation of a simplified YAML profile for serde parsing.
///
/// This supports the shorthand YAML format with flat keys like `reliability`,
/// `history_depth`, `deadline_ms`, etc., in addition to the full `YamlQosProfile`
/// format from the existing loader.
#[derive(Debug, serde::Deserialize, Default)]
#[serde(default)]
struct SimplifiedProfile {
    /// Reliability: "reliable" or "best_effort"
    reliability: Option<String>,
    /// Durability: "volatile", "transient_local", "persistent"
    durability: Option<String>,
    /// History: "keep_all" or unset (defaults to keep_last with history_depth)
    history: Option<String>,
    /// History depth for keep_last (shorthand)
    history_depth: Option<u32>,
    /// Deadline period in milliseconds (shorthand)
    deadline_ms: Option<u64>,
    /// Lifespan duration in milliseconds (shorthand)
    lifespan_ms: Option<u64>,
    /// Transport priority value (shorthand)
    transport_priority: Option<i32>,
    /// Latency budget in milliseconds (shorthand)
    latency_budget_ms: Option<u64>,
    /// Time-based filter minimum separation in milliseconds (shorthand)
    time_based_filter_ms: Option<u64>,
    /// Partition names
    partition: Option<Vec<String>>,
}

/// Root document for the simplified YAML profile format.
#[derive(Debug, serde::Deserialize)]
struct SimplifiedDocument {
    #[serde(default)]
    profiles: HashMap<String, SimplifiedProfile>,
}

/// QoS profile registry -- stores named profiles loaded from YAML files.
///
/// Thread-safe via `RwLock`. Multiple readers can access profiles concurrently,
/// while writes (load, reload) are serialized.
pub struct QosProfileRegistry {
    profiles: Arc<RwLock<HashMap<String, QoS>>>,
    /// Paths of loaded files (for reload support)
    loaded_files: Arc<RwLock<Vec<PathBuf>>>,
}

impl QosProfileRegistry {
    /// Create a new, empty profile registry.
    pub fn new() -> Self {
        Self {
            profiles: Arc::new(RwLock::new(HashMap::new())),
            loaded_files: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Load QoS profiles from a YAML file.
    ///
    /// The file can use either the simplified format (shorthand keys) or the
    /// full `YamlQosProfile` format. Both are supported.
    ///
    /// Returns the number of profiles loaded.
    pub fn load_from_yaml(&self, path: &Path) -> Result<usize, String> {
        let yaml_content =
            fs::read_to_string(path).map_err(|e| format!("Failed to read YAML file: {}", e))?;

        let new_profiles = Self::parse_profiles(&yaml_content)?;
        let count = new_profiles.len();

        {
            let mut profiles = self
                .profiles
                .write()
                .map_err(|e| format!("Lock poisoned: {}", e))?;
            for (name, qos) in new_profiles {
                profiles.insert(name, qos);
            }
        }

        // Track the loaded file path for reload
        {
            let mut files = self
                .loaded_files
                .write()
                .map_err(|e| format!("Lock poisoned: {}", e))?;
            let canonical = path.to_path_buf();
            if !files.contains(&canonical) {
                files.push(canonical);
            }
        }

        Ok(count)
    }

    /// Get a QoS profile by name. Returns `None` if not found.
    pub fn get(&self, name: &str) -> Option<QoS> {
        let profiles = self.profiles.read().ok()?;
        profiles.get(name).cloned()
    }

    /// List all profile names in the registry.
    pub fn list_profiles(&self) -> Vec<String> {
        match self.profiles.read() {
            Ok(profiles) => {
                let mut names: Vec<String> = profiles.keys().cloned().collect();
                names.sort();
                names
            }
            Err(_) => Vec::new(),
        }
    }

    /// Reload all previously loaded files and compute a diff.
    ///
    /// This re-reads every YAML file that was loaded via `load_from_yaml`
    /// and returns a `ReloadResult` describing what changed.
    pub fn reload(&self) -> Result<ReloadResult, String> {
        let files: Vec<PathBuf> = {
            let f = self
                .loaded_files
                .read()
                .map_err(|e| format!("Lock poisoned: {}", e))?;
            f.clone()
        };

        if files.is_empty() {
            return Ok(ReloadResult {
                profiles_updated: Vec::new(),
                profiles_added: Vec::new(),
                profiles_removed: Vec::new(),
                errors: Vec::new(),
            });
        }

        // Collect old profile names for diff
        let old_names: Vec<String> = {
            let profiles = self
                .profiles
                .read()
                .map_err(|e| format!("Lock poisoned: {}", e))?;
            profiles.keys().cloned().collect()
        };

        // Parse all files
        let mut new_profiles = HashMap::new();
        let mut errors = Vec::new();

        for file in &files {
            match fs::read_to_string(file) {
                Ok(yaml_content) => match Self::parse_profiles(&yaml_content) {
                    Ok(parsed) => {
                        for (name, qos) in parsed {
                            new_profiles.insert(name, qos);
                        }
                    }
                    Err(e) => {
                        errors.push(format!("Parse error in {}: {}", file.display(), e));
                    }
                },
                Err(e) => {
                    errors.push(format!("Read error for {}: {}", file.display(), e));
                }
            }
        }

        // If all files failed to parse, keep old config
        if !errors.is_empty() && new_profiles.is_empty() {
            return Ok(ReloadResult {
                profiles_updated: Vec::new(),
                profiles_added: Vec::new(),
                profiles_removed: Vec::new(),
                errors,
            });
        }

        // Compute diff
        let new_name_set: std::collections::HashSet<&String> = new_profiles.keys().collect();
        let old_name_set: std::collections::HashSet<&String> = old_names.iter().collect();

        let profiles_added: Vec<String> = new_name_set
            .difference(&old_name_set)
            .map(|s| (*s).clone())
            .collect();

        let profiles_removed: Vec<String> = old_name_set
            .difference(&new_name_set)
            .map(|s| (*s).clone())
            .collect();

        // For existing profiles, mark as updated (we always overwrite)
        let profiles_updated: Vec<String> = new_name_set
            .intersection(&old_name_set)
            .map(|s| (*s).clone())
            .collect();

        // Apply changes
        {
            let mut profiles = self
                .profiles
                .write()
                .map_err(|e| format!("Lock poisoned: {}", e))?;
            *profiles = new_profiles;
        }

        Ok(ReloadResult {
            profiles_updated,
            profiles_added,
            profiles_removed,
            errors,
        })
    }

    /// Parse profiles from YAML content.
    ///
    /// Tries the simplified format first, then falls back to the full
    /// `YamlQosDocument` format.
    fn parse_profiles(yaml_content: &str) -> Result<HashMap<String, QoS>, String> {
        // Try simplified format first
        if let Ok(doc) = serde_yaml::from_str::<SimplifiedDocument>(yaml_content) {
            if !doc.profiles.is_empty() {
                let mut result = HashMap::new();
                for (name, profile) in &doc.profiles {
                    let qos = Self::simplified_to_qos(profile)?;
                    result.insert(name.clone(), qos);
                }
                return Ok(result);
            }
        }

        // Fall back to full YamlQosDocument format
        let doc: YamlQosDocument = YamlLoader::parse_yaml(yaml_content)?;
        let mut result = HashMap::new();
        for (name, profile) in &doc.profiles {
            let qos = YamlLoader::profile_to_qos(profile)?;
            result.insert(name.clone(), qos);
        }
        Ok(result)
    }

    /// Convert a simplified profile to a QoS instance.
    fn simplified_to_qos(profile: &SimplifiedProfile) -> Result<QoS, String> {
        let mut qos = QoS::default();

        // Reliability
        if let Some(ref rel) = profile.reliability {
            qos.reliability = match rel.to_lowercase().as_str() {
                "reliable" => Reliability::Reliable,
                "best_effort" => Reliability::BestEffort,
                other => return Err(format!("Invalid reliability: {}", other)),
            };
        }

        // Durability
        if let Some(ref dur) = profile.durability {
            qos.durability = match dur.to_lowercase().as_str() {
                "volatile" => Durability::Volatile,
                "transient_local" => Durability::TransientLocal,
                "persistent" => Durability::Persistent,
                other => return Err(format!("Invalid durability: {}", other)),
            };
        }

        // History (string or depth)
        match (&profile.history, profile.history_depth) {
            (Some(h), _) if h.to_lowercase() == "keep_all" => {
                qos.history = History::KeepAll;
            }
            (Some(h), depth) if h.to_lowercase() == "keep_last" => {
                qos.history = History::KeepLast(depth.unwrap_or(1));
            }
            (Some(h), _) => {
                return Err(format!("Invalid history kind: {}", h));
            }
            (None, Some(depth)) => {
                qos.history = History::KeepLast(depth);
            }
            (None, None) => {}
        }

        // Deadline (shorthand: deadline_ms)
        if let Some(ms) = profile.deadline_ms {
            qos.deadline = Deadline::new(Duration::from_millis(ms));
        }

        // Lifespan (shorthand: lifespan_ms)
        if let Some(ms) = profile.lifespan_ms {
            qos.lifespan = Lifespan::new(Duration::from_millis(ms));
        }

        // Transport priority
        if let Some(priority) = profile.transport_priority {
            qos.transport_priority = TransportPriority { value: priority };
        }

        // Latency budget (shorthand: latency_budget_ms)
        if let Some(ms) = profile.latency_budget_ms {
            qos.latency_budget = LatencyBudget::new(Duration::from_millis(ms));
        }

        // Time-based filter (shorthand: time_based_filter_ms)
        if let Some(ms) = profile.time_based_filter_ms {
            qos.time_based_filter = TimeBasedFilter::new(Duration::from_millis(ms));
        }

        // Partition
        if let Some(ref names) = profile.partition {
            if !names.is_empty() {
                qos.partition = Partition::new(names.clone());
            }
        }

        Ok(qos)
    }

    /// Get the list of immutable policy changes between two QoS configurations.
    ///
    /// Returns a list of policy names that differ between `old` and `new` and are
    /// classified as immutable by the DDS spec.
    pub fn detect_immutable_changes(old: &QoS, new: &QoS) -> Vec<&'static str> {
        let mut changes = Vec::new();

        if !matches!(
            (&old.reliability, &new.reliability),
            (Reliability::Reliable, Reliability::Reliable)
                | (Reliability::BestEffort, Reliability::BestEffort)
        ) {
            changes.push("Reliability");
        }

        if old.durability != new.durability {
            changes.push("Durability");
        }

        if !history_eq(&old.history, &new.history) {
            changes.push("History");
        }

        if old.ownership.kind != new.ownership.kind {
            changes.push("Ownership");
        }

        if old.destination_order.kind != new.destination_order.kind {
            changes.push("DestinationOrder");
        }

        if old.resource_limits.max_samples != new.resource_limits.max_samples
            || old.resource_limits.max_instances != new.resource_limits.max_instances
            || old.resource_limits.max_samples_per_instance
                != new.resource_limits.max_samples_per_instance
        {
            changes.push("ResourceLimits");
        }

        changes
    }
}

impl Default for QosProfileRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Compare two History values for equality.
fn history_eq(a: &History, b: &History) -> bool {
    match (a, b) {
        (History::KeepAll, History::KeepAll) => true,
        (History::KeepLast(da), History::KeepLast(db)) => da == db,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    // Helper: create a temp file with content, return its path
    fn write_temp_yaml(content: &str) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().expect("create temp file");
        f.write_all(content.as_bytes()).expect("write temp file");
        f.flush().expect("flush temp file");
        f
    }

    // --- Test 1: Parse valid YAML profile ---
    #[test]
    fn test_parse_valid_yaml_profile() {
        let yaml = r#"
profiles:
  high_reliability:
    reliability: reliable
    history: keep_all
    deadline_ms: 100
"#;
        let file = write_temp_yaml(yaml);
        let registry = QosProfileRegistry::new();
        let count = registry
            .load_from_yaml(file.path())
            .expect("should parse valid YAML");
        assert_eq!(count, 1);

        let qos = registry
            .get("high_reliability")
            .expect("profile should exist");
        assert!(matches!(qos.reliability, Reliability::Reliable));
        assert!(matches!(qos.history, History::KeepAll));
        assert_eq!(qos.deadline.period, Duration::from_millis(100));
    }

    // --- Test 2: Parse multiple profiles from one file ---
    #[test]
    fn test_parse_multiple_profiles() {
        let yaml = r#"
profiles:
  high_reliability:
    reliability: reliable
    history: keep_all
    deadline_ms: 100

  sensor_stream:
    reliability: best_effort
    history_depth: 10
    deadline_ms: 500
    transport_priority: 5

  transient_data:
    reliability: reliable
    durability: transient_local
    history_depth: 50
    lifespan_ms: 60000
"#;
        let file = write_temp_yaml(yaml);
        let registry = QosProfileRegistry::new();
        let count = registry
            .load_from_yaml(file.path())
            .expect("should parse multiple profiles");
        assert_eq!(count, 3);

        let qos1 = registry.get("high_reliability").expect("profile exists");
        assert!(matches!(qos1.reliability, Reliability::Reliable));

        let qos2 = registry.get("sensor_stream").expect("profile exists");
        assert!(matches!(qos2.reliability, Reliability::BestEffort));
        assert!(matches!(qos2.history, History::KeepLast(10)));
        assert_eq!(qos2.transport_priority.value, 5);

        let qos3 = registry.get("transient_data").expect("profile exists");
        assert!(matches!(qos3.durability, Durability::TransientLocal));
        assert_eq!(qos3.lifespan.duration, Duration::from_millis(60000));
    }

    // --- Test 3: Get profile by name ---
    #[test]
    fn test_get_profile_by_name() {
        let yaml = r#"
profiles:
  my_profile:
    reliability: reliable
    deadline_ms: 200
"#;
        let file = write_temp_yaml(yaml);
        let registry = QosProfileRegistry::new();
        registry.load_from_yaml(file.path()).unwrap();

        assert!(registry.get("my_profile").is_some());
        assert!(registry.get("nonexistent").is_none());
    }

    // --- Test 4: List profiles ---
    #[test]
    fn test_list_profiles() {
        let yaml = r#"
profiles:
  alpha:
    reliability: reliable
  beta:
    reliability: best_effort
  gamma:
    durability: volatile
"#;
        let file = write_temp_yaml(yaml);
        let registry = QosProfileRegistry::new();
        registry.load_from_yaml(file.path()).unwrap();

        let names = registry.list_profiles();
        assert_eq!(names.len(), 3);
        // list_profiles returns sorted
        assert_eq!(names, vec!["alpha", "beta", "gamma"]);
    }

    // --- Test 5: Reload detects changes ---
    #[test]
    fn test_reload_detects_changes() {
        let yaml_v1 = r#"
profiles:
  sensor:
    reliability: best_effort
    deadline_ms: 500
"#;
        let file = write_temp_yaml(yaml_v1);
        let registry = QosProfileRegistry::new();
        registry.load_from_yaml(file.path()).unwrap();

        let qos_before = registry.get("sensor").unwrap();
        assert_eq!(qos_before.deadline.period, Duration::from_millis(500));

        // Overwrite with new content
        let yaml_v2 = r#"
profiles:
  sensor:
    reliability: best_effort
    deadline_ms: 200
"#;
        fs::write(file.path(), yaml_v2).expect("overwrite yaml");

        let result = registry.reload().expect("reload should succeed");
        assert!(result.has_changes());
        assert!(result.profiles_updated.contains(&"sensor".to_string()));

        let qos_after = registry.get("sensor").unwrap();
        assert_eq!(qos_after.deadline.period, Duration::from_millis(200));
    }

    // --- Test 6: Reload detects additions ---
    #[test]
    fn test_reload_detects_additions() {
        let yaml_v1 = r#"
profiles:
  existing:
    reliability: reliable
"#;
        let file = write_temp_yaml(yaml_v1);
        let registry = QosProfileRegistry::new();
        registry.load_from_yaml(file.path()).unwrap();
        assert_eq!(registry.list_profiles().len(), 1);

        // Add a new profile
        let yaml_v2 = r#"
profiles:
  existing:
    reliability: reliable
  new_profile:
    reliability: best_effort
    deadline_ms: 100
"#;
        fs::write(file.path(), yaml_v2).expect("overwrite yaml");

        let result = registry.reload().expect("reload should succeed");
        assert!(result.profiles_added.contains(&"new_profile".to_string()));
        assert_eq!(registry.list_profiles().len(), 2);
        assert!(registry.get("new_profile").is_some());
    }

    // --- Test 7: Reload detects removals ---
    #[test]
    fn test_reload_detects_removals() {
        let yaml_v1 = r#"
profiles:
  keep_me:
    reliability: reliable
  remove_me:
    reliability: best_effort
"#;
        let file = write_temp_yaml(yaml_v1);
        let registry = QosProfileRegistry::new();
        registry.load_from_yaml(file.path()).unwrap();
        assert_eq!(registry.list_profiles().len(), 2);

        // Remove one profile
        let yaml_v2 = r#"
profiles:
  keep_me:
    reliability: reliable
"#;
        fs::write(file.path(), yaml_v2).expect("overwrite yaml");

        let result = registry.reload().expect("reload should succeed");
        assert!(result.profiles_removed.contains(&"remove_me".to_string()));
        assert_eq!(registry.list_profiles().len(), 1);
        assert!(registry.get("remove_me").is_none());
    }

    // --- Test 8: Invalid YAML keeps old config ---
    #[test]
    fn test_invalid_yaml_keeps_old_config() {
        let yaml_v1 = r#"
profiles:
  sensor:
    reliability: reliable
    deadline_ms: 500
"#;
        let file = write_temp_yaml(yaml_v1);
        let registry = QosProfileRegistry::new();
        registry.load_from_yaml(file.path()).unwrap();

        // Corrupt the file
        fs::write(file.path(), "{{{{ not valid yaml at all ::::").expect("corrupt file");

        let result = registry.reload().expect("reload returns Ok with errors");
        assert!(!result.errors.is_empty());

        // Old config should still be accessible
        let qos = registry.get("sensor").expect("old profile still available");
        assert!(matches!(qos.reliability, Reliability::Reliable));
    }

    // --- Test 9: Unknown fields ignored gracefully ---
    #[test]
    fn test_unknown_fields_ignored() {
        let yaml = r#"
profiles:
  my_profile:
    reliability: reliable
    unknown_field: "some value"
    another_weird_field: 42
    deadline_ms: 100
"#;
        let file = write_temp_yaml(yaml);
        let registry = QosProfileRegistry::new();
        let count = registry
            .load_from_yaml(file.path())
            .expect("should parse with unknown fields");
        assert_eq!(count, 1);

        let qos = registry.get("my_profile").expect("profile exists");
        assert!(matches!(qos.reliability, Reliability::Reliable));
        assert_eq!(qos.deadline.period, Duration::from_millis(100));
    }

    // --- Test 10: Mutable vs immutable policy classification ---
    #[test]
    fn test_mutable_vs_immutable_policy() {
        // Mutable policies
        assert!(PolicyKind::Deadline.is_mutable());
        assert!(PolicyKind::LatencyBudget.is_mutable());
        assert!(PolicyKind::TransportPriority.is_mutable());
        assert!(PolicyKind::Lifespan.is_mutable());
        assert!(PolicyKind::Partition.is_mutable());
        assert!(PolicyKind::TimeBasedFilter.is_mutable());

        // Immutable policies
        assert!(!PolicyKind::Durability.is_mutable());
        assert!(!PolicyKind::Reliability.is_mutable());
        assert!(!PolicyKind::History.is_mutable());
        assert!(!PolicyKind::Ownership.is_mutable());
        assert!(!PolicyKind::DestinationOrder.is_mutable());
        assert!(!PolicyKind::ResourceLimits.is_mutable());

        // Verify enum values
        assert_eq!(PolicyKind::Deadline.mutability(), PolicyMutability::Mutable);
        assert_eq!(
            PolicyKind::Durability.mutability(),
            PolicyMutability::Immutable
        );
    }

    // --- Test 11: Detect immutable changes ---
    #[test]
    fn test_detect_immutable_changes() {
        let qos1 = QoS::reliable();
        let qos2 = QoS::best_effort();

        let changes = QosProfileRegistry::detect_immutable_changes(&qos1, &qos2);
        assert!(changes.contains(&"Reliability"));

        // Same QoS: no immutable changes
        let qos3 = QoS::reliable();
        let changes2 = QosProfileRegistry::detect_immutable_changes(&qos1, &qos3);
        assert!(changes2.is_empty());
    }

    // --- Test 12: Simplified profile format with all shorthand keys ---
    #[test]
    fn test_simplified_format_all_keys() {
        let yaml = r#"
profiles:
  full_test:
    reliability: reliable
    durability: transient_local
    history: keep_last
    history_depth: 25
    deadline_ms: 100
    lifespan_ms: 5000
    transport_priority: 10
    latency_budget_ms: 50
    time_based_filter_ms: 200
    partition:
      - sensors
      - building_a
"#;
        let file = write_temp_yaml(yaml);
        let registry = QosProfileRegistry::new();
        registry.load_from_yaml(file.path()).unwrap();

        let qos = registry.get("full_test").expect("profile exists");
        assert!(matches!(qos.reliability, Reliability::Reliable));
        assert!(matches!(qos.durability, Durability::TransientLocal));
        assert!(matches!(qos.history, History::KeepLast(25)));
        assert_eq!(qos.deadline.period, Duration::from_millis(100));
        assert_eq!(qos.lifespan.duration, Duration::from_millis(5000));
        assert_eq!(qos.transport_priority.value, 10);
        assert_eq!(qos.latency_budget.duration, Duration::from_millis(50));
        assert_eq!(
            qos.time_based_filter.minimum_separation,
            Duration::from_millis(200)
        );
        assert_eq!(qos.partition.names, vec!["sensors", "building_a"]);
    }

    // --- Test 13: Empty registry ---
    #[test]
    fn test_empty_registry() {
        let registry = QosProfileRegistry::new();
        assert!(registry.list_profiles().is_empty());
        assert!(registry.get("anything").is_none());

        // Reload with no files loaded
        let result = registry.reload().expect("reload empty");
        assert!(!result.has_changes());
        assert_eq!(result.total_changes(), 0);
    }

    // --- Test 14: ReloadResult helper methods ---
    #[test]
    fn test_reload_result_helpers() {
        let empty = ReloadResult {
            profiles_updated: Vec::new(),
            profiles_added: Vec::new(),
            profiles_removed: Vec::new(),
            errors: Vec::new(),
        };
        assert!(!empty.has_changes());
        assert_eq!(empty.total_changes(), 0);

        let with_changes = ReloadResult {
            profiles_updated: vec!["a".to_string()],
            profiles_added: vec!["b".to_string(), "c".to_string()],
            profiles_removed: vec!["d".to_string()],
            errors: Vec::new(),
        };
        assert!(with_changes.has_changes());
        assert_eq!(with_changes.total_changes(), 4);
    }
}
