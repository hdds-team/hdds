// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

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
