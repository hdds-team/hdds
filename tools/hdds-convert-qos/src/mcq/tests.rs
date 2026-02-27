// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

#![allow(clippy::expect_used)]

use super::*;

#[test]
fn parse_sample_profile_smoke() {
    let yaml = include_str!("../../../../configs/rti_6x_sample_01.mcq.yaml");
    let mcq = Mcq::from_yaml(yaml);

    match mcq {
        Ok(m) => {
            assert_eq!(m.metadata.source, "rti@6.1");
            assert_eq!(m.datawriter_qos.len(), 1);
            assert_eq!(m.datareader_qos.len(), 1);
        }
        Err(errors) => {
            for e in &errors {
                eprintln!("{e:?}");
            }
            panic!("Validation failed with {} errors", errors.len());
        }
    }
}

#[test]
fn validation_requires_blocking_time_for_reliable_writer() {
    let yaml = r#"
metadata:
  source: test
  source_file: test.xml
  profile_name: test
  conformance_profile: core
  oracle_version: "0.1"
  creation_date: "2025-10-27"
participant_qos:
  discovery:
    initial_peers: ["udpv4://239.255.0.1"]
    accept_unknown_peers: false
    participant_liveliness_lease_duration_ns: 3000000000
  transport_builtin:
    mask: [UDPv4]
datawriter_qos:
  - topic_filter: "test"
    reliability:
      kind: Reliable
    durability:
      kind: Volatile
    history:
      kind: KeepLast
      depth: 1
    resource_limits:
      max_samples: 100
      max_instances: 1
      max_samples_per_instance: 100
    liveliness:
      kind: Automatic
    ownership:
      kind: Shared
"#;

    let result = Mcq::from_yaml(yaml);
    assert!(result.is_err());

    if let Err(errors) = result {
        assert!(errors.iter().any(|e| matches!(
            e,
            ValidationError::Critical { field, .. } if field.contains("max_blocking_time")
        )));
    }
}

#[test]
fn normalize_is_idempotent_and_sorts() {
    let yaml = include_str!("../../../../configs/rti_6x_sample_01.mcq.yaml");
    let mut mcq = Mcq::from_yaml(yaml).expect("parse failed");

    mcq.normalize();
    mcq.normalize();

    for i in 1..mcq.datawriter_qos.len() {
        assert!(mcq.datawriter_qos[i - 1].topic_filter <= mcq.datawriter_qos[i].topic_filter);
    }
}
