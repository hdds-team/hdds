// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! RTI 6.x XML -> MCQ Loader (MVP)
//!
//! Parses RTI Connext DDS 6.x `USER_QOS_PROFILES.xml` format and converts to MCQ canonical format.

use crate::mcq::{
    DataReaderQos, DataWriterQos, Discovery, Durability, DurabilityKind, History, HistoryKind,
    Liveliness, LivelinessKind, Mcq, Metadata, Ownership, OwnershipKind, ParticipantQos,
    ReaderResourceLimits, Reliability, ReliabilityKind, ResourceLimits, TransportBuiltin,
    TransportKind,
};
use anyhow::{anyhow, bail, Context, Result};
use roxmltree::Document;
use std::collections::HashMap;

pub struct RtiLoader;

impl RtiLoader {
    /// Detect vendor from XML header/root element
    pub fn detect_vendor(xml: &str) -> Result<String> {
        let doc = Document::parse(xml).context("Failed to parse XML for vendor detection")?;

        let root = doc.root_element();

        // Check for RTI-specific attributes/namespace
        if root.tag_name().name() == "dds" {
            // Check version attribute or xmlns
            if let Some(version) = root.attribute("version") {
                if version.starts_with("6.") {
                    return Ok(format!("rti@{version}"));
                }
            }

            // Fallback: check xmlns
            if root
                .namespaces()
                .any(|ns| ns.uri().contains("rti.com") || ns.uri().contains("rtps"))
            {
                return Ok("rti@6.x".to_string());
            }
        }

        bail!("Could not detect RTI vendor signature in XML");
    }

    /// Parse RTI XML file and convert to MCQ
    pub fn parse_xml(xml_content: &str) -> Result<Mcq> {
        let doc = Document::parse(xml_content).context("Failed to parse RTI XML")?;

        let root = doc.root_element();

        // Find qos_profile node
        let qos_profile = root
            .descendants()
            .find(|n| n.tag_name().name() == "qos_profile")
            .ok_or_else(|| anyhow!("No qos_profile found in XML"))?;

        // Extract metadata
        let metadata = Self::extract_metadata(&doc, &qos_profile);

        // Extract participant QoS
        let participant_qos = Self::extract_participant_qos(&qos_profile)?;

        // Extract datawriter QoS
        let datawriter_qos = Self::extract_datawriter_qos(&qos_profile)?;

        // Extract datareader QoS
        let datareader_qos = Self::extract_datareader_qos(&qos_profile)?;

        Ok(Mcq {
            metadata,
            participant_qos,
            datawriter_qos,
            datareader_qos,
            extensions: HashMap::new(),
        })
    }

    fn extract_metadata(doc: &Document, qos_profile: &roxmltree::Node) -> Metadata {
        let version = doc.root_element().attribute("version").unwrap_or("6.0.0");

        let profile_name = qos_profile.attribute("name").unwrap_or("DefaultProfile");

        Metadata {
            source: format!("rti@{version}"),
            source_file: "converted.xml".to_string(),
            profile_name: profile_name.to_string(),
            conformance_profile: "core".to_string(),
            oracle_version: "0.1".to_string(),
            creation_date: chrono::Utc::now().format("%Y-%m-%d").to_string(),
        }
    }

    // @audit-ok: Sequential XML parsing (cyclo 20, cogni 2) - linear extraction without complex branching
    fn extract_participant_qos(qos_profile: &roxmltree::Node) -> Result<ParticipantQos> {
        let participant_node = qos_profile
            .descendants()
            .find(|n| n.tag_name().name() == "participant_qos")
            .ok_or_else(|| anyhow!("No participant_qos found"))?;

        // Extract discovery
        let discovery_node = participant_node
            .descendants()
            .find(|n| n.tag_name().name() == "discovery")
            .ok_or_else(|| anyhow!("No discovery found in participant_qos"))?;

        let initial_peers: Vec<String> = discovery_node
            .descendants()
            .filter(|n| n.tag_name().name() == "element")
            .filter_map(|n| n.text())
            .map(std::string::ToString::to_string)
            .collect();

        let accept_unknown_peers = discovery_node
            .descendants()
            .find(|n| n.tag_name().name() == "accept_unknown_peers")
            .and_then(|n| n.text())
            .is_some_and(|s| s.trim() == "true");

        let participant_liveliness_lease_duration_ns = discovery_node
            .descendants()
            .find(|n| n.tag_name().name() == "participant_liveliness_lease_duration")
            .map(|n| Self::parse_duration(&n))
            .transpose()?
            .unwrap_or(5_000_000_000); // 5s default

        let discovery = Discovery {
            initial_peers,
            accept_unknown_peers,
            participant_liveliness_lease_duration_ns,
        };

        // Extract transport_builtin
        let transport_node = participant_node
            .descendants()
            .find(|n| n.tag_name().name() == "transport_builtin");

        let mask = if let Some(transport) = transport_node {
            transport
                .descendants()
                .filter(|n| n.tag_name().name() == "mask")
                .filter_map(|n| n.text())
                .filter_map(|s| Self::parse_transport_kind(s.trim()))
                .collect()
        } else {
            vec![TransportKind::UDPv4]
        };

        let transport_builtin = TransportBuiltin { mask };

        Ok(ParticipantQos {
            discovery,
            transport_builtin,
        })
    }

    // @audit-ok: Sequential XML parsing (cyclo 19, cogni 1) - linear field extraction without complex logic
    fn extract_datawriter_qos(qos_profile: &roxmltree::Node) -> Result<Vec<DataWriterQos>> {
        let mut result = Vec::new();

        for dw_node in qos_profile
            .descendants()
            .filter(|n| n.tag_name().name() == "datawriter_qos")
        {
            let topic_filter = dw_node.attribute("topic_filter").unwrap_or("*").to_string();

            let reliability = Self::extract_reliability(&dw_node)?;
            let durability = Self::extract_durability(&dw_node)?;
            let history = Self::extract_history(&dw_node)?;
            let resource_limits = Self::extract_resource_limits(&dw_node)?;
            let liveliness = Self::extract_liveliness(&dw_node)?;

            let latency_budget_ns = dw_node
                .descendants()
                .find(|n| n.tag_name().name() == "latency_budget")
                .and_then(|n| n.descendants().find(|n| n.tag_name().name() == "duration"))
                .map(|n| Self::parse_duration(&n))
                .transpose()?;

            let deadline_ns = dw_node
                .descendants()
                .find(|n| n.tag_name().name() == "deadline")
                .and_then(|n| n.descendants().find(|n| n.tag_name().name() == "period"))
                .map(|n| Self::parse_duration(&n))
                .transpose()?;

            let ownership = Self::extract_ownership(&dw_node)?;

            result.push(DataWriterQos {
                topic_filter,
                reliability,
                durability,
                history,
                resource_limits,
                liveliness,
                latency_budget_ns,
                deadline_ns,
                ownership,
            });
        }

        Ok(result)
    }

    // @audit-ok: Sequential XML parsing (cyclo 16, cogni 1) - linear field extraction without complex logic
    fn extract_datareader_qos(qos_profile: &roxmltree::Node) -> Result<Vec<DataReaderQos>> {
        let mut result = Vec::new();

        for dr_node in qos_profile
            .descendants()
            .filter(|n| n.tag_name().name() == "datareader_qos")
        {
            let topic_filter = dr_node.attribute("topic_filter").unwrap_or("*").to_string();

            let reliability = Self::extract_reliability(&dr_node)?;
            let durability = Self::extract_durability(&dr_node)?;
            let history = Self::extract_history(&dr_node)?;

            let time_based_filter_ns = dr_node
                .descendants()
                .find(|n| n.tag_name().name() == "time_based_filter")
                .and_then(|n| {
                    n.descendants()
                        .find(|n| n.tag_name().name() == "minimum_separation")
                })
                .map(|n| Self::parse_duration(&n))
                .transpose()?;

            let reader_resource_limits = dr_node
                .descendants()
                .find(|n| n.tag_name().name() == "reader_resource_limits")
                .map_or(ReaderResourceLimits { max_samples: 8192 }, |n| {
                    let max_samples = n
                        .descendants()
                        .find(|nn| nn.tag_name().name() == "max_samples")
                        .and_then(|nn| nn.text())
                        .and_then(|s| s.trim().parse().ok())
                        .unwrap_or(8192);
                    ReaderResourceLimits { max_samples }
                });

            result.push(DataReaderQos {
                topic_filter,
                reliability,
                durability,
                history,
                time_based_filter_ns,
                reader_resource_limits,
            });
        }

        Ok(result)
    }

    // ========== Helper Functions ==========

    fn extract_reliability(node: &roxmltree::Node) -> Result<Reliability> {
        let rel_node = node
            .descendants()
            .find(|n| n.tag_name().name() == "reliability");

        if let Some(rel) = rel_node {
            let kind_str = rel
                .descendants()
                .find(|n| n.tag_name().name() == "kind")
                .and_then(|n| n.text())
                .unwrap_or("BEST_EFFORT_RELIABILITY_QOS");

            let kind = match kind_str.trim() {
                "RELIABLE_RELIABILITY_QOS" => ReliabilityKind::Reliable,
                _ => ReliabilityKind::BestEffort,
            };

            let max_blocking_time_ns = rel
                .descendants()
                .find(|n| n.tag_name().name() == "max_blocking_time")
                .map(|n| Self::parse_duration(&n))
                .transpose()?;

            Ok(Reliability {
                kind,
                max_blocking_time_ns,
            })
        } else {
            Ok(Reliability {
                kind: ReliabilityKind::BestEffort,
                max_blocking_time_ns: None,
            })
        }
    }

    #[allow(clippy::unnecessary_wraps)]
    fn extract_durability(node: &roxmltree::Node) -> Result<Durability> {
        let kind_str = node
            .descendants()
            .find(|n| n.tag_name().name() == "durability")
            .and_then(|n| n.descendants().find(|n| n.tag_name().name() == "kind"))
            .and_then(|n| n.text())
            .unwrap_or("VOLATILE_DURABILITY_QOS");

        let kind = match kind_str.trim() {
            "PERSISTENT_DURABILITY_QOS" => DurabilityKind::Persistent,
            "TRANSIENT_LOCAL_DURABILITY_QOS" => DurabilityKind::TransientLocal,
            "TRANSIENT_DURABILITY_QOS" => DurabilityKind::Transient,
            _ => DurabilityKind::Volatile,
        };

        Ok(Durability { kind })
    }

    #[allow(clippy::unnecessary_wraps)]
    fn extract_history(node: &roxmltree::Node) -> Result<History> {
        let hist_node = node
            .descendants()
            .find(|n| n.tag_name().name() == "history");

        if let Some(hist) = hist_node {
            let kind_str = hist
                .descendants()
                .find(|n| n.tag_name().name() == "kind")
                .and_then(|n| n.text())
                .unwrap_or("KEEP_LAST_HISTORY_QOS");

            let kind = match kind_str.trim() {
                "KEEP_ALL_HISTORY_QOS" => HistoryKind::KeepAll,
                _ => HistoryKind::KeepLast,
            };

            let depth = hist
                .descendants()
                .find(|n| n.tag_name().name() == "depth")
                .and_then(|n| n.text())
                .and_then(|s| s.trim().parse().ok());

            Ok(History { kind, depth })
        } else {
            Ok(History {
                kind: HistoryKind::KeepLast,
                depth: Some(1),
            })
        }
    }

    #[allow(clippy::unnecessary_wraps)]
    // @audit-ok: Sequential XML parsing (cyclo 12, cogni 2) - linear field extraction with defaults
    fn extract_resource_limits(node: &roxmltree::Node) -> Result<ResourceLimits> {
        let rl_node = node
            .descendants()
            .find(|n| n.tag_name().name() == "resource_limits");

        if let Some(rl) = rl_node {
            let max_samples = rl
                .descendants()
                .find(|n| n.tag_name().name() == "max_samples")
                .and_then(|n| n.text())
                .and_then(|s| s.trim().parse().ok())
                .unwrap_or(100);

            let max_instances = rl
                .descendants()
                .find(|n| n.tag_name().name() == "max_instances")
                .and_then(|n| n.text())
                .and_then(|s| s.trim().parse().ok())
                .unwrap_or(1);

            let max_samples_per_instance = rl
                .descendants()
                .find(|n| n.tag_name().name() == "max_samples_per_instance")
                .and_then(|n| n.text())
                .and_then(|s| s.trim().parse().ok())
                .unwrap_or(100);

            Ok(ResourceLimits {
                max_samples,
                max_instances,
                max_samples_per_instance,
            })
        } else {
            Ok(ResourceLimits {
                max_samples: 100,
                max_instances: 1,
                max_samples_per_instance: 100,
            })
        }
    }

    fn extract_liveliness(node: &roxmltree::Node) -> Result<Liveliness> {
        let liv_node = node
            .descendants()
            .find(|n| n.tag_name().name() == "liveliness");

        if let Some(liv) = liv_node {
            let kind_str = liv
                .descendants()
                .find(|n| n.tag_name().name() == "kind")
                .and_then(|n| n.text())
                .unwrap_or("AUTOMATIC_LIVELINESS_QOS");

            let kind = match kind_str.trim() {
                "MANUAL_BY_PARTICIPANT_LIVELINESS_QOS" => LivelinessKind::ManualByParticipant,
                "MANUAL_BY_TOPIC_LIVELINESS_QOS" => LivelinessKind::ManualByTopic,
                _ => LivelinessKind::Automatic,
            };

            let lease_duration_ns = liv
                .descendants()
                .find(|n| n.tag_name().name() == "lease_duration")
                .map(|n| Self::parse_duration(&n))
                .transpose()?;

            Ok(Liveliness {
                kind,
                lease_duration_ns,
            })
        } else {
            Ok(Liveliness {
                kind: LivelinessKind::Automatic,
                lease_duration_ns: None,
            })
        }
    }

    #[allow(clippy::unnecessary_wraps)]
    fn extract_ownership(node: &roxmltree::Node) -> Result<Ownership> {
        let kind_str = node
            .descendants()
            .find(|n| n.tag_name().name() == "ownership")
            .and_then(|n| n.descendants().find(|n| n.tag_name().name() == "kind"))
            .and_then(|n| n.text())
            .unwrap_or("SHARED_OWNERSHIP_QOS");

        let kind = match kind_str.trim() {
            "EXCLUSIVE_OWNERSHIP_QOS" => OwnershipKind::Exclusive,
            _ => OwnershipKind::Shared,
        };

        Ok(Ownership { kind })
    }

    /// Parse RTI duration (sec + nanosec) -> nanoseconds
    #[allow(clippy::unnecessary_wraps)]
    fn parse_duration(duration_node: &roxmltree::Node) -> Result<u64> {
        let sec: u64 = duration_node
            .descendants()
            .find(|n| n.tag_name().name() == "sec")
            .and_then(|n| n.text())
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0);

        let nanosec: u64 = duration_node
            .descendants()
            .find(|n| n.tag_name().name() == "nanosec")
            .and_then(|n| n.text())
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0);

        Ok(sec * 1_000_000_000 + nanosec)
    }

    fn parse_transport_kind(s: &str) -> Option<TransportKind> {
        match s {
            "UDPv4" => Some(TransportKind::UDPv4),
            "UDPv6" => Some(TransportKind::UDPv6),
            "TCPv4" => Some(TransportKind::TCPv4),
            "TCPv6" => Some(TransportKind::TCPv6),
            "SHMEM" => Some(TransportKind::SHMEM),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_vendor_rti() {
        let xml = r#"<?xml version="1.0"?>
<dds version="6.1.0">
</dds>"#;

        let vendor = RtiLoader::detect_vendor(xml).expect("Should detect RTI");
        assert!(vendor.starts_with("rti@6."));
    }

    #[test]
    fn test_parse_rti_sample_01() {
        let xml = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/rti_6x_sample_01.xml"
        ))
        .expect("Sample XML not found — place test fixture in tests/fixtures/");

        let mcq = RtiLoader::parse_xml(&xml).expect("Parse failed");

        assert_eq!(mcq.metadata.source, "rti@6.1.0");
        assert_eq!(mcq.metadata.profile_name, "HighReliabilityProfile");
        assert_eq!(mcq.datawriter_qos.len(), 1);
        assert_eq!(mcq.datareader_qos.len(), 1);
    }
}
