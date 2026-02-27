// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! FastDDS XML profile loader.
//!
//!
//! Parses FastDDS XML profiles and converts to HDDS QoS.

use crate::dds::qos::*;
use roxmltree::Document;
use std::fs;
use std::path::Path;
use std::time::Duration;

use super::common::parse_duration;

pub struct FastDdsLoader;

impl FastDdsLoader {
    /// Load QoS from FastDDS XML file.
    ///
    /// Searches for the first `<data_writer>` or `<data_reader>` profile with `is_default_profile="true"`.
    /// If no default profile is found, uses the first profile.
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<QoS, String> {
        crate::trace_fn!("FastDdsLoader::load_from_file");
        let xml_content =
            fs::read_to_string(path).map_err(|e| format!("Failed to read XML file: {}", e))?;
        Self::parse_xml(&xml_content)
    }

    /// Parse FastDDS XML content and extract QoS.
    pub fn parse_xml(xml_content: &str) -> Result<QoS, String> {
        crate::trace_fn!("FastDdsLoader::parse_xml");
        let doc =
            Document::parse(xml_content).map_err(|e| format!("Failed to parse XML: {}", e))?;

        let root = doc.root_element();

        // Find <profiles> element
        let profiles = root
            .descendants()
            .find(|n| n.tag_name().name() == "profiles")
            .ok_or("No <profiles> element found")?;

        // Find data_writer or data_reader profile
        let profile = profiles
            .children()
            .filter(|n| {
                n.is_element()
                    && (n.tag_name().name() == "data_writer"
                        || n.tag_name().name() == "data_reader")
            })
            .find(|n| {
                n.attribute("is_default_profile")
                    .map(|v| v == "true")
                    .unwrap_or(false)
            })
            .or_else(|| {
                profiles.children().find(|n| {
                    n.is_element()
                        && (n.tag_name().name() == "data_writer"
                            || n.tag_name().name() == "data_reader")
                })
            })
            .ok_or("No data_writer or data_reader profile found")?;

        Self::extract_qos(&profile)
    }

    fn extract_qos(profile: &roxmltree::Node) -> Result<QoS, String> {
        let mut qos = QoS::default();

        // Find <qos> element
        let qos_node = profile.descendants().find(|n| n.tag_name().name() == "qos");

        if let Some(qos_elem) = qos_node {
            // Parse reliability
            if let Some(rel) = qos_elem
                .descendants()
                .find(|n| n.tag_name().name() == "reliability")
            {
                if let Some(kind) = rel
                    .descendants()
                    .find(|n| n.tag_name().name() == "kind")
                    .and_then(|n| n.text())
                {
                    qos.reliability = match kind.trim() {
                        "RELIABLE" => Reliability::Reliable,
                        "BEST_EFFORT" => Reliability::BestEffort,
                        _ => Reliability::BestEffort,
                    };
                }
            }

            // Parse durability
            if let Some(dur) = qos_elem
                .descendants()
                .find(|n| n.tag_name().name() == "durability")
            {
                if let Some(kind) = dur
                    .descendants()
                    .find(|n| n.tag_name().name() == "kind")
                    .and_then(|n| n.text())
                {
                    qos.durability = match kind.trim() {
                        "VOLATILE" => Durability::Volatile,
                        "TRANSIENT_LOCAL" => Durability::TransientLocal,
                        "TRANSIENT" => Durability::TransientLocal, // Map to TransientLocal (HDDS doesn't support Transient)
                        "PERSISTENT" => Durability::Persistent,
                        _ => Durability::Volatile,
                    };
                }
            }

            // Parse liveliness
            if let Some(liv) = qos_elem
                .descendants()
                .find(|n| n.tag_name().name() == "liveliness")
            {
                if let Some(kind) = liv
                    .descendants()
                    .find(|n| n.tag_name().name() == "kind")
                    .and_then(|n| n.text())
                {
                    let kind = match kind.trim() {
                        "AUTOMATIC" => LivelinessKind::Automatic,
                        "MANUAL_BY_PARTICIPANT" => LivelinessKind::ManualByParticipant,
                        "MANUAL_BY_TOPIC" => LivelinessKind::ManualByTopic,
                        _ => LivelinessKind::Automatic,
                    };

                    let lease_duration = liv
                        .descendants()
                        .find(|n| n.tag_name().name() == "lease_duration")
                        .map(|n| {
                            let sec = n
                                .descendants()
                                .find(|n| n.tag_name().name() == "sec")
                                .and_then(|n| n.text());
                            let ns = n
                                .descendants()
                                .find(|n| n.tag_name().name() == "nanosec")
                                .and_then(|n| n.text());
                            parse_duration(sec, ns)
                        })
                        .unwrap_or(Duration::MAX);

                    qos.liveliness = Liveliness::new(kind, lease_duration);
                }
            }

            // Parse ownership
            if let Some(own) = qos_elem
                .descendants()
                .find(|n| n.tag_name().name() == "ownership")
            {
                if let Some(kind) = own
                    .descendants()
                    .find(|n| n.tag_name().name() == "kind")
                    .and_then(|n| n.text())
                {
                    qos.ownership = match kind.trim() {
                        "SHARED" => Ownership::shared(),
                        "EXCLUSIVE" => Ownership::exclusive(),
                        _ => Ownership::shared(),
                    };
                }
            }

            // Parse ownership strength
            if let Some(strength) = qos_elem
                .descendants()
                .find(|n| n.tag_name().name() == "ownershipStrength")
            {
                if let Some(value) = strength
                    .descendants()
                    .find(|n| n.tag_name().name() == "value")
                    .and_then(|n| n.text())
                    .and_then(|t| t.trim().parse::<i32>().ok())
                {
                    qos.ownership_strength = OwnershipStrength::new(value);
                }
            }

            // Parse destination_order
            if let Some(dest_order) = qos_elem
                .descendants()
                .find(|n| n.tag_name().name() == "destination_order")
            {
                if let Some(kind) = dest_order
                    .descendants()
                    .find(|n| n.tag_name().name() == "kind")
                    .and_then(|n| n.text())
                {
                    qos.destination_order = match kind.trim() {
                        "BY_RECEPTION_TIMESTAMP" => DestinationOrder::by_reception_timestamp(),
                        "BY_SOURCE_TIMESTAMP" => DestinationOrder::by_source_timestamp(),
                        _ => DestinationOrder::by_reception_timestamp(),
                    };
                }
            }

            // Parse presentation
            if let Some(pres) = qos_elem
                .descendants()
                .find(|n| n.tag_name().name() == "presentation")
            {
                let access_scope = pres
                    .descendants()
                    .find(|n| n.tag_name().name() == "access_scope")
                    .and_then(|n| n.text())
                    .map(|s| match s.trim() {
                        "INSTANCE" => PresentationAccessScope::Instance,
                        "TOPIC" => PresentationAccessScope::Topic,
                        "GROUP" => PresentationAccessScope::Group,
                        _ => PresentationAccessScope::Instance,
                    })
                    .unwrap_or(PresentationAccessScope::Instance);

                let coherent_access = pres
                    .descendants()
                    .find(|n| n.tag_name().name() == "coherent_access")
                    .and_then(|n| n.text())
                    .map(|s| s.trim() == "true")
                    .unwrap_or(false);

                let ordered_access = pres
                    .descendants()
                    .find(|n| n.tag_name().name() == "ordered_access")
                    .and_then(|n| n.text())
                    .map(|s| s.trim() == "true")
                    .unwrap_or(false);

                qos.presentation = Presentation::new(access_scope, coherent_access, ordered_access);
            }

            // Parse deadline
            if let Some(deadline) = qos_elem
                .descendants()
                .find(|n| n.tag_name().name() == "deadline")
            {
                let period = deadline
                    .descendants()
                    .find(|n| n.tag_name().name() == "period")
                    .map(|n| {
                        let sec = n
                            .descendants()
                            .find(|n| n.tag_name().name() == "sec")
                            .and_then(|n| n.text());
                        let ns = n
                            .descendants()
                            .find(|n| n.tag_name().name() == "nanosec")
                            .and_then(|n| n.text());
                        parse_duration(sec, ns)
                    })
                    .unwrap_or(Duration::MAX);

                qos.deadline = Deadline::new(period);
            }

            // Parse lifespan
            if let Some(lifespan) = qos_elem
                .descendants()
                .find(|n| n.tag_name().name() == "lifespan")
            {
                let duration = lifespan
                    .descendants()
                    .find(|n| n.tag_name().name() == "duration")
                    .map(|n| {
                        let sec = n
                            .descendants()
                            .find(|n| n.tag_name().name() == "sec")
                            .and_then(|n| n.text());
                        let ns = n
                            .descendants()
                            .find(|n| n.tag_name().name() == "nanosec")
                            .and_then(|n| n.text());
                        parse_duration(sec, ns)
                    })
                    .unwrap_or(Duration::MAX);

                qos.lifespan = Lifespan::new(duration);
            }

            // Parse latencyBudget
            if let Some(latency) = qos_elem
                .descendants()
                .find(|n| n.tag_name().name() == "latencyBudget")
            {
                let duration = latency
                    .descendants()
                    .find(|n| n.tag_name().name() == "duration")
                    .map(|n| {
                        let sec = n
                            .descendants()
                            .find(|n| n.tag_name().name() == "sec")
                            .and_then(|n| n.text());
                        let ns = n
                            .descendants()
                            .find(|n| n.tag_name().name() == "nanosec")
                            .and_then(|n| n.text());
                        parse_duration(sec, ns)
                    })
                    .unwrap_or(Duration::ZERO);

                qos.latency_budget = LatencyBudget::new(duration);
            }

            // Parse timeBasedFilter
            if let Some(tbf) = qos_elem
                .descendants()
                .find(|n| n.tag_name().name() == "timeBasedFilter")
            {
                let min_sep = tbf
                    .descendants()
                    .find(|n| n.tag_name().name() == "minimum_separation")
                    .map(|n| {
                        let sec = n
                            .descendants()
                            .find(|n| n.tag_name().name() == "sec")
                            .and_then(|n| n.text());
                        let ns = n
                            .descendants()
                            .find(|n| n.tag_name().name() == "nanosec")
                            .and_then(|n| n.text());
                        parse_duration(sec, ns)
                    })
                    .unwrap_or(Duration::ZERO);

                qos.time_based_filter = TimeBasedFilter::new(min_sep);
            }

            // Parse partition
            if let Some(part) = qos_elem
                .descendants()
                .find(|n| n.tag_name().name() == "partition")
            {
                let names: Vec<String> = part
                    .descendants()
                    .filter(|n| n.tag_name().name() == "name")
                    .filter_map(|n| n.text())
                    .map(|s| s.to_string())
                    .collect();

                if !names.is_empty() {
                    qos.partition = Partition::new(names);
                }
            }

            // Parse userData, groupData, topicData
            if let Some(user_data) = qos_elem
                .descendants()
                .find(|n| n.tag_name().name() == "userData")
            {
                let values: Vec<u8> = user_data
                    .descendants()
                    .filter(|n| n.tag_name().name() == "value")
                    .filter_map(|n| n.text())
                    .flat_map(|s| s.as_bytes().to_vec())
                    .collect();

                if !values.is_empty() {
                    qos.user_data = UserData::new(values);
                }
            }

            if let Some(group_data) = qos_elem
                .descendants()
                .find(|n| n.tag_name().name() == "groupData")
            {
                let values: Vec<u8> = group_data
                    .descendants()
                    .filter(|n| n.tag_name().name() == "value")
                    .filter_map(|n| n.text())
                    .flat_map(|s| s.as_bytes().to_vec())
                    .collect();

                if !values.is_empty() {
                    qos.group_data = GroupData::new(values);
                }
            }

            if let Some(topic_data) = qos_elem
                .descendants()
                .find(|n| n.tag_name().name() == "topicData")
            {
                let values: Vec<u8> = topic_data
                    .descendants()
                    .filter(|n| n.tag_name().name() == "value")
                    .filter_map(|n| n.text())
                    .flat_map(|s| s.as_bytes().to_vec())
                    .collect();

                if !values.is_empty() {
                    qos.topic_data = TopicData::new(values);
                }
            }
        }

        // Parse <topic><historyQos> (FastDDS stores history in topic, not qos)
        if let Some(topic) = profile
            .descendants()
            .find(|n| n.tag_name().name() == "topic")
        {
            if let Some(history_qos) = topic
                .descendants()
                .find(|n| n.tag_name().name() == "historyQos")
            {
                let kind = history_qos
                    .descendants()
                    .find(|n| n.tag_name().name() == "kind")
                    .and_then(|n| n.text())
                    .unwrap_or("KEEP_LAST");

                let depth = history_qos
                    .descendants()
                    .find(|n| n.tag_name().name() == "depth")
                    .and_then(|n| n.text())
                    .and_then(|t| t.trim().parse::<u32>().ok())
                    .unwrap_or(100);

                qos.history = match kind.trim() {
                    "KEEP_ALL" => History::KeepAll,
                    "KEEP_LAST" => History::KeepLast(depth),
                    _ => History::KeepLast(depth),
                };
            }
        }

        Ok(qos)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_minimal_qos() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<dds xmlns="http://www.eprosima.com/XMLSchemas/fastRTPS_Profiles">
  <profiles>
    <data_writer profile_name="test" is_default_profile="true">
      <qos>
        <reliability><kind>RELIABLE</kind></reliability>
        <durability><kind>TRANSIENT_LOCAL</kind></durability>
      </qos>
      <topic>
        <historyQos><kind>KEEP_LAST</kind><depth>10</depth></historyQos>
      </topic>
    </data_writer>
  </profiles>
</dds>"#;

        let qos = FastDdsLoader::parse_xml(xml).expect("valid FastDDS XML should parse");

        assert!(matches!(qos.reliability, Reliability::Reliable));
        assert!(matches!(qos.durability, Durability::TransientLocal));
        assert!(matches!(qos.history, History::KeepLast(10)));
    }

    #[test]
    fn test_parse_keep_all_history() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<dds xmlns="http://www.eprosima.com/XMLSchemas/fastRTPS_Profiles">
  <profiles>
    <data_reader profile_name="test" is_default_profile="true">
      <qos>
        <reliability><kind>BEST_EFFORT</kind></reliability>
      </qos>
      <topic>
        <historyQos><kind>KEEP_ALL</kind></historyQos>
      </topic>
    </data_reader>
  </profiles>
</dds>"#;

        let qos = FastDdsLoader::parse_xml(xml).expect("valid FastDDS XML should parse");

        assert!(matches!(qos.reliability, Reliability::BestEffort));
        assert!(matches!(qos.history, History::KeepAll));
    }
}
