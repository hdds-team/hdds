// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Topic registry for endpoint discovery and matching.
//!
//!
//! Maps topic names to lists of discovered endpoints. Used by the matcher
//! to find compatible local/remote endpoint pairs for data delivery.

use super::endpoint::{EndpointInfo, EndpointKind};
use crate::core::discovery::{Matcher, GUID};
use crate::dds::qos::QoS;
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
    /// The incarnation given to the last record that entered
    /// (`EndpointInfo::incarnation`). Never reused, a removal included.
    last_incarnation: u64,
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
            last_incarnation: 0,
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
        self.insert_with_incarnation(endpoint).0
    }

    /// [`Self::insert`], returning also the incarnation of the record now
    /// held (`EndpointInfo::incarnation`): a new one for an endpoint that was
    /// not held, the record's own for an update of it. The incarnation
    /// `endpoint` carries is ignored.
    pub(crate) fn insert_with_incarnation(&mut self, mut endpoint: EndpointInfo) -> (bool, u64) {
        crate::trace_fn!("TopicRegistry::insert");
        let endpoints = self.topics.entry(endpoint.topic_name.clone()).or_default();

        if let Some(existing) = endpoints
            .iter_mut()
            .find(|e| e.endpoint_guid == endpoint.endpoint_guid)
        {
            endpoint.incarnation = existing.incarnation;
            *existing = endpoint;
            (false, existing.incarnation)
        } else {
            self.last_incarnation += 1;
            endpoint.incarnation = self.last_incarnation;
            endpoints.push(endpoint);
            (true, self.last_incarnation)
        }
    }

    /// Give `endpoint`, about to replace its own record, the TypeObject that
    /// record learned after its discovery (a TypeLookup answer), when
    /// `endpoint` carries none and announces the same COMPLETE hash
    /// (`announced_hash`) the record was resolved for.
    pub(crate) fn keep_learned_type_object(
        &self,
        endpoint: &mut EndpointInfo,
        announced_hash: impl Fn(&EndpointInfo) -> Option<crate::xtypes::EquivalenceHash>,
    ) {
        if endpoint.type_object.is_some() {
            return;
        }
        let Some(hash) = announced_hash(endpoint) else {
            return;
        };
        if let Some(known) = self.endpoint(&endpoint.topic_name, &endpoint.endpoint_guid) {
            if announced_hash(known) == Some(hash) {
                endpoint.type_object = known.type_object.clone();
            }
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

    /// Give `type_object` to every REMOTE endpoint that has no TypeObject yet
    /// and that `applies` selects, and return the endpoints updated (as
    /// updated).
    ///
    /// Remote means outside `local_prefix`: a local endpoint's type is the
    /// one its code declares, never one a peer answered a TypeLookup with.
    pub(crate) fn update_remote_type_objects(
        &mut self,
        local_prefix: &[u8; 12],
        applies: impl Fn(&EndpointInfo) -> bool,
        type_object: &CompleteTypeObject,
    ) -> Vec<EndpointInfo> {
        let mut updated = Vec::new();
        for endpoints in self.topics.values_mut() {
            for endpoint in endpoints.iter_mut() {
                if endpoint.type_object.is_none()
                    && endpoint.endpoint_guid.prefix != *local_prefix
                    && applies(endpoint)
                {
                    endpoint.type_object = Some(type_object.clone());
                    updated.push(endpoint.clone());
                }
            }
        }
        updated
    }

    /// The endpoint `endpoint_guid` on `topic_name`, when registered.
    pub(crate) fn endpoint(&self, topic_name: &str, endpoint_guid: &GUID) -> Option<&EndpointInfo> {
        self.topics
            .get(topic_name)
            .and_then(|endpoints| endpoints.iter().find(|e| e.endpoint_guid == *endpoint_guid))
    }

    /// Whether the endpoint `endpoint_guid` is registered on `topic_name`.
    pub(crate) fn contains(&self, topic_name: &str, endpoint_guid: &GUID) -> bool {
        self.topics
            .get(topic_name)
            .is_some_and(|endpoints| endpoints.iter().any(|e| e.endpoint_guid == *endpoint_guid))
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

    /// The readers of a topic, borrowed: what [`Self::find_readers`]
    /// returns, without cloning a whole `EndpointInfo` (its QoS and type
    /// object) per reader.
    pub(crate) fn readers(&self, topic_name: &str) -> impl Iterator<Item = &EndpointInfo> {
        self.topics
            .get(topic_name)
            .into_iter()
            .flatten()
            .filter(|e| e.kind == EndpointKind::Reader)
    }

    /// Find all endpoints whose GUID prefix matches the given prefix.
    /// Used to replay endpoint notifications when a participant is promoted from probation.
    pub fn find_endpoints_by_prefix(&self, prefix: &[u8]) -> Vec<EndpointInfo> {
        let mut result = Vec::new();
        for endpoints in self.topics.values() {
            for ep in endpoints {
                if ep.endpoint_guid.as_bytes()[..12] == *prefix {
                    result.push(ep.clone());
                }
            }
        }
        result
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
        local_qos: &QoS,
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

        // Effective TypeConsistencyEnforcement from local QoS; None = spec default.
        let local_policy = local_qos.type_consistency.as_ref();

        let result = self
            .topics
            .get(topic_name)
            .map(|endpoints| {
                endpoints
                    .iter()
                    .filter(|e| e.kind == EndpointKind::Writer)
                    .filter(|e| {
                        // Type compatibility check per DDS-XTypes v1.3 sec. 7.5.1.
                        // is_type_compatible_with_policy(arg1, arg2) internally calls
                        // is_assignable_to_with_policy(writer=arg1, reader=arg2).
                        // In find_compatible_writers: local is the reader, e is the writer.
                        // Pass (writer=e, reader=local) to preserve correct assignability
                        // direction per XTypes v1.3 sec. 7.5.1.1 (writer assignable to reader).
                        let compatible = Matcher::is_type_compatible_with_policy(
                            e.type_object.as_ref(),
                            local_type_object,
                            &e.type_name,
                            local_type_name,
                            local_policy,
                        );

                        if !compatible && local_type_object.is_some() && e.type_object.is_some() {
                            log::debug!(
                                "[MATCH-TYPE] Structural type incompatibility: local='{}' remote='{}' on topic '{}'",
                                local_type_name, e.type_name, topic_name
                            );
                        }

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
                    .filter(|e| {
                        // QoS compatibility check (RxO per DDS v1.4 Sec.2.2.3)
                        // local_qos = reader QoS, e.qos = writer QoS
                        let qos_ok = Matcher::is_compatible(local_qos, &e.qos);
                        if !qos_ok {
                            log::debug!(
                                "[MATCH-QOS] Rejected: reader QoS incompatible with writer {} on '{}'",
                                e.endpoint_guid, topic_name
                            );
                        }
                        qos_ok
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
        local_qos: &QoS,
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
                        // Type compatibility check: local is the writer, e is the reader.
                        // is_type_compatible_with_policy(writer, reader) -- writer first,
                        // reader second -- per XTypes v1.3 sec. 7.5.1.1 assignability direction.
                        // TypeConsistencyEnforcement is READER-side per XTypes v1.3 sec. 7.6.3.4:
                        // use e.qos.type_consistency (the remote reader), not local_qos.
                        let reader_policy = e.qos.type_consistency.as_ref();
                        let compatible = Matcher::is_type_compatible_with_policy(
                            local_type_object,
                            e.type_object.as_ref(),
                            local_type_name,
                            &e.type_name,
                            reader_policy,
                        );

                        if !compatible && local_type_object.is_some() && e.type_object.is_some() {
                            log::debug!(
                                "[MATCH-TYPE] Structural type incompatibility: local='{}' remote='{}' on topic '{}'",
                                local_type_name, e.type_name, topic_name
                            );
                        }

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
                    .filter(|e| {
                        // QoS compatibility check (RxO per DDS v1.4 Sec.2.2.3)
                        // e.qos = reader QoS, local_qos = writer QoS
                        let qos_ok = Matcher::is_compatible(&e.qos, local_qos);
                        if !qos_ok {
                            log::debug!(
                                "[MATCH-QOS] Rejected: writer QoS incompatible with reader {} on '{}'",
                                e.endpoint_guid, topic_name
                            );
                        }
                        qos_ok
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

    /// Remove every endpoint whose GUID `is_gone` selects, and return them.
    ///
    /// The removal and the snapshot of what was removed are one pass, so a
    /// caller announcing the removals announces exactly the endpoints that
    /// left, whether it selected a whole participant or a single endpoint.
    pub(crate) fn remove_endpoints_where(
        &mut self,
        is_gone: impl Fn(&GUID) -> bool,
    ) -> Vec<EndpointInfo> {
        crate::trace_fn!("TopicRegistry::remove_endpoints_where");
        let mut removed = Vec::new();
        for endpoints in self.topics.values_mut() {
            let mut kept = Vec::with_capacity(endpoints.len());
            for endpoint in endpoints.drain(..) {
                if is_gone(&endpoint.endpoint_guid) {
                    removed.push(endpoint);
                } else {
                    kept.push(endpoint);
                }
            }
            *endpoints = kept;
        }
        removed
    }

    /// The writers of the group `group` of participant `prefix` (a remote
    /// Publisher, RTPS v2.5 Sec.8.7.5): the EntityIds of every writer whose
    /// announcement names that group, sorted and unique.
    #[must_use]
    pub fn publisher_roster(&self, prefix: &[u8; 12], group: [u8; 4]) -> Vec<[u8; 4]> {
        let mut roster: Vec<[u8; 4]> = self
            .topics
            .values()
            .flatten()
            .filter(|e| {
                e.kind == EndpointKind::Writer
                    && e.group_entity_id == Some(group)
                    && e.endpoint_guid.prefix == *prefix
            })
            .map(|e| e.endpoint_guid.entity_id)
            .collect();
        roster.sort_unstable();
        roster.dedup();
        roster
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
