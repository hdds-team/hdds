// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Topic registry for endpoint discovery and matching.
//!
//!
//! Maps topic names to lists of discovered endpoints. Used by the matcher
//! to find compatible local/remote endpoint pairs for data delivery.

use super::endpoint::{EndpointInfo, EndpointKind};
use crate::core::discovery::{Matcher, GUID};
use crate::xtypes::CompleteTypeObject;
use std::collections::HashMap;

/// Topic registry for endpoint discovery.
///
/// Maps topic names to discovered endpoints (Writers and Readers).
/// Enables efficient lookup for endpoint matching.
#[derive(Debug, Clone)]
pub struct TopicRegistry {
    /// Map: topic_name -> `Vec<EndpointInfo>`
    topics: HashMap<String, Vec<EndpointInfo>>,
}

impl Default for TopicRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl TopicRegistry {
    /// Create new empty TopicRegistry.
    #[must_use]
    pub fn new() -> Self {
        crate::trace_fn!("TopicRegistry::new");
        Self {
            topics: HashMap::new(),
        }
    }

    /// Insert or update endpoint in registry.
    ///
    /// If endpoint already exists (same GUID), replace it.
    /// Otherwise, append to topic's endpoint list.
    ///
    /// # Arguments
    /// - `endpoint`: EndpointInfo to insert
    ///
    /// # Returns
    /// `true` if a new endpoint was inserted, `false` if an existing endpoint was updated.
    pub fn insert(&mut self, endpoint: EndpointInfo) -> bool {
        crate::trace_fn!("TopicRegistry::insert");
        let endpoints = self.topics.entry(endpoint.topic_name.clone()).or_default();

        if let Some(existing) = endpoints
            .iter_mut()
            .find(|e| e.endpoint_guid == endpoint.endpoint_guid)
        {
            *existing = endpoint;
            false
        } else {
            endpoints.push(endpoint);
            true
        }
    }

    /// Update endpoints with a matching type name to include a TypeObject.
    ///
    /// Returns the number of endpoints updated.
    pub fn update_type_object_for_type(
        &mut self,
        type_name: &str,
        type_object: &CompleteTypeObject,
    ) -> usize {
        let mut updated = 0;
        for endpoints in self.topics.values_mut() {
            for endpoint in endpoints.iter_mut() {
                if endpoint.type_name == type_name && endpoint.type_object.is_none() {
                    endpoint.type_object = Some(type_object.clone());
                    updated += 1;
                }
            }
        }
        updated
    }

    /// Find all writers for a topic.
    pub fn find_writers(&self, topic_name: &str) -> Vec<EndpointInfo> {
        crate::trace_fn!("TopicRegistry::find_writers");
        self.topics
            .get(topic_name)
            .map(|endpoints| {
                endpoints
                    .iter()
                    .filter(|e| e.kind == EndpointKind::Writer)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Find all readers for a topic.
    pub fn find_readers(&self, topic_name: &str) -> Vec<EndpointInfo> {
        crate::trace_fn!("TopicRegistry::find_readers");
        self.topics
            .get(topic_name)
            .map(|endpoints| {
                endpoints
                    .iter()
                    .filter(|e| e.kind == EndpointKind::Reader)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Find compatible writers for a topic (Phase 10 - XTypes v1.3 Integration).
    ///
    /// Filters writers by structural type compatibility using TypeObject EquivalenceHash.
    /// Falls back to type_name matching for legacy interoperability.
    pub fn find_compatible_writers(
        &self,
        topic_name: &str,
        local_type_object: Option<&CompleteTypeObject>,
        local_type_name: &str,
    ) -> Vec<EndpointInfo> {
        crate::trace_fn!("TopicRegistry::find_compatible_writers");
        // Non-invasive diagnostics: when HDDS_INTEROP_DIAGNOSTICS=1, run
        // DiagnosticMatcher in parallel to existing Matcher logic. This
        // does not alter behaviour; it only records mismatch reports.
        let mut diag_matcher = if crate::interop::diagnostics_enabled() {
            let profile_id = crate::interop::WireProfileId::from_context(
                topic_name,
                local_type_object.is_some(),
            );
            let rules = profile_id.matching_rules();
            Some(crate::interop::matching::DiagnosticMatcher::new(rules))
        } else {
            None
        };

        let result = self
            .topics
            .get(topic_name)
            .map(|endpoints| {
                endpoints
                    .iter()
                    .filter(|e| e.kind == EndpointKind::Writer)
                    .filter(|e| {
                        // Existing matching logic (unchanged)
                        let compatible = Matcher::is_type_compatible(
                            local_type_object,
                            e.type_object.as_ref(),
                            local_type_name,
                            &e.type_name,
                        );

                        // Optional diagnostics
                        if let Some(matcher) = diag_matcher.as_mut() {
                            use crate::interop::matching::{
                                EndpointInfo as DiagEndpointInfo, RemoteEndpointInfo,
                            };

                            // Local endpoint info (reader) for diagnostics
                            let local_info = DiagEndpointInfo {
                                topic_name: topic_name.to_string(),
                                type_name: local_type_name.to_string(),
                                type_object: local_type_object.map(|_| Vec::new()),
                                qos: Vec::new(),
                            };

                            // Remote endpoint info (writer) for diagnostics
                            let remote_info = RemoteEndpointInfo {
                                guid_prefix: {
                                    let bytes = e.participant_guid.as_bytes();
                                    let mut prefix = [0u8; 12];
                                    prefix.copy_from_slice(&bytes[..12]);
                                    prefix
                                },
                                topic_name: e.topic_name.clone(),
                                type_name: e.type_name.clone(),
                                type_object: e.type_object.as_ref().map(|_| Vec::new()),
                                qos: Vec::new(),
                            };

                            // We ignore the MatchResult for now and rely on
                            // the existing Matcher; this is diagnostics only.
                            let _ = matcher.check_match(&local_info, &remote_info);
                        }

                        compatible
                    })
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();

        // Flush diagnostics to global collector (if any)
        if let Some(mut matcher) = diag_matcher {
            let reports = matcher.drain_reports();
            for report in reports {
                crate::interop::get_diagnostics().add_report(report);
            }
        }

        result
    }

    /// Find compatible readers for a topic (Phase 10 - XTypes v1.3 Integration).
    ///
    /// Filters readers by structural type compatibility using TypeObject EquivalenceHash.
    /// Falls back to type_name matching for legacy interoperability.
    pub fn find_compatible_readers(
        &self,
        topic_name: &str,
        local_type_object: Option<&CompleteTypeObject>,
        local_type_name: &str,
    ) -> Vec<EndpointInfo> {
        crate::trace_fn!("TopicRegistry::find_compatible_readers");
        let mut diag_matcher = if crate::interop::diagnostics_enabled() {
            let profile_id = crate::interop::WireProfileId::from_context(
                topic_name,
                local_type_object.is_some(),
            );
            let rules = profile_id.matching_rules();
            Some(crate::interop::matching::DiagnosticMatcher::new(rules))
        } else {
            None
        };

        let result = self
            .topics
            .get(topic_name)
            .map(|endpoints| {
                endpoints
                    .iter()
                    .filter(|e| e.kind == EndpointKind::Reader)
                    .filter(|e| {
                        let compatible = Matcher::is_type_compatible(
                            local_type_object,
                            e.type_object.as_ref(),
                            local_type_name,
                            &e.type_name,
                        );

                        if let Some(matcher) = diag_matcher.as_mut() {
                            use crate::interop::matching::{
                                EndpointInfo as DiagEndpointInfo, RemoteEndpointInfo,
                            };

                            let local_info = DiagEndpointInfo {
                                topic_name: topic_name.to_string(),
                                type_name: local_type_name.to_string(),
                                type_object: local_type_object.map(|_| Vec::new()),
                                qos: Vec::new(),
                            };

                            let remote_info = RemoteEndpointInfo {
                                guid_prefix: {
                                    let bytes = e.participant_guid.as_bytes();
                                    let mut prefix = [0u8; 12];
                                    prefix.copy_from_slice(&bytes[..12]);
                                    prefix
                                },
                                topic_name: e.topic_name.clone(),
                                type_name: e.type_name.clone(),
                                type_object: e.type_object.as_ref().map(|_| Vec::new()),
                                qos: Vec::new(),
                            };

                            let _ = matcher.check_match(&local_info, &remote_info);
                        }

                        compatible
                    })
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();

        if let Some(mut matcher) = diag_matcher {
            let reports = matcher.drain_reports();
            for report in reports {
                crate::interop::get_diagnostics().add_report(report);
            }
        }

        result
    }

    /// Remove all endpoints for a participant.
    ///
    /// Called when participant lease expires.
    /// Matches by GUID prefix (first 12 bytes) to handle entity_id variations.
    ///
    /// # Arguments
    /// - `participant_guid`: Participant GUID to remove
    ///
    /// # Returns
    /// Number of endpoints removed.
    pub fn remove_participant(&mut self, participant_guid: &GUID) -> usize {
        crate::trace_fn!("TopicRegistry::remove_participant");
        let mut removed = 0;
        let participant_prefix = &participant_guid.as_bytes()[..12];

        for endpoints in self.topics.values_mut() {
            let before_len = endpoints.len();
            endpoints.retain(|endpoint| {
                &endpoint.participant_guid.as_bytes()[..12] != participant_prefix
            });
            removed += before_len - endpoints.len();
        }

        removed
    }

    /// Get all topic names currently in the registry.
    ///
    /// Returns a vector of topic names for iteration.
    /// Used for live topic discovery.
    #[must_use]
    pub fn get_all_topic_names(&self) -> Vec<String> {
        crate::trace_fn!("TopicRegistry::get_all_topic_names");
        self.topics.keys().cloned().collect()
    }
}

#[cfg(test)]
mod tests;
