// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// MCQ root structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Mcq {
    pub metadata: Metadata,
    pub participant_qos: ParticipantQos,
    #[serde(default)]
    pub datawriter_qos: Vec<DataWriterQos>,
    #[serde(default)]
    pub datareader_qos: Vec<DataReaderQos>,
    #[serde(default)]
    pub extensions: HashMap<String, serde_yaml::Value>,
}

/// Metadata about MCQ file source and conformance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Metadata {
    pub source: String,
    pub source_file: String,
    pub profile_name: String,
    pub conformance_profile: String,
    pub oracle_version: String,
    pub creation_date: String,
}

/// Participant `QoS`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParticipantQos {
    pub discovery: Discovery,
    pub transport_builtin: TransportBuiltin,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Discovery {
    pub initial_peers: Vec<String>,
    pub accept_unknown_peers: bool,
    pub participant_liveliness_lease_duration_ns: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransportBuiltin {
    pub mask: Vec<TransportKind>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[allow(clippy::upper_case_acronyms)]
pub enum TransportKind {
    UDPv4,
    UDPv6,
    TCPv4,
    TCPv6,
    SHMEM,
}

/// `DataWriter` `QoS`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataWriterQos {
    pub topic_filter: String,
    pub reliability: Reliability,
    pub durability: Durability,
    pub history: History,
    pub resource_limits: ResourceLimits,
    pub liveliness: Liveliness,
    #[serde(default)]
    pub latency_budget_ns: Option<u64>,
    #[serde(default)]
    pub deadline_ns: Option<u64>,
    pub ownership: Ownership,
}

/// `DataReader` `QoS`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataReaderQos {
    pub topic_filter: String,
    pub reliability: Reliability,
    pub durability: Durability,
    pub history: History,
    #[serde(default)]
    pub time_based_filter_ns: Option<u64>,
    pub reader_resource_limits: ReaderResourceLimits,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reliability {
    pub kind: ReliabilityKind,
    #[serde(default)]
    pub max_blocking_time_ns: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReliabilityKind {
    Reliable,
    BestEffort,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Durability {
    pub kind: DurabilityKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DurabilityKind {
    Persistent,
    TransientLocal,
    Transient,
    Volatile,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct History {
    pub kind: HistoryKind,
    #[serde(default)]
    pub depth: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HistoryKind {
    KeepLast,
    KeepAll,
}

/// Resource limits for DDS entities (DDS spec compliant naming).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(clippy::struct_field_names)]
pub struct ResourceLimits {
    pub max_samples: i32,
    pub max_instances: i32,
    pub max_samples_per_instance: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Liveliness {
    pub kind: LivelinessKind,
    #[serde(default)]
    pub lease_duration_ns: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LivelinessKind {
    Automatic,
    ManualByParticipant,
    ManualByTopic,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ownership {
    pub kind: OwnershipKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OwnershipKind {
    Shared,
    Exclusive,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReaderResourceLimits {
    pub max_samples: i32,
}
