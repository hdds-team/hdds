// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! HDDS-backed DDS interface implementation.

use crate::dds_interface::{
    DataReader, DataWriter, DdsInterface, DiscoveredReader, DiscoveredWriter, DiscoveryCallback,
    DurabilityKind, ReceivedSample,
};
use crate::store::RetentionPolicy;
use anyhow::{anyhow, Result};
use hdds::core::discovery::multicast::{DiscoveryListener, EndpointInfo, EndpointKind};
use hdds::dds::qos::Durability;
use hdds::{Participant, QoS, RawDataReader, RawRelayWriter};
use std::sync::Arc;
use std::time::Duration;

/// HDDS-backed implementation of the persistence DDS interface.
pub struct HddsDdsInterface {
    participant: Arc<Participant>,
    discovery: Arc<hdds::core::discovery::multicast::DiscoveryFsm>,
}

impl HddsDdsInterface {
    /// Create a new HDDS-backed DDS interface.
    pub fn new(participant: Arc<Participant>) -> Result<Self> {
        let discovery = participant
            .discovery()
            .ok_or_else(|| anyhow!("Discovery not initialized"))?;

        Ok(Self {
            participant,
            discovery,
        })
    }
}

struct HddsDataReader {
    inner: RawDataReader,
    topic: String,
    type_name: String,
    writer_orders: Arc<WriterOrderMap>,
}

impl DataReader for HddsDataReader {
    fn take(&self) -> Result<Vec<ReceivedSample>> {
        let samples = self
            .inner
            .try_take_raw_with_info_and_encoding()
            .map_err(|e| anyhow!("RawDataReader capture failed: {:?}", e))?;

        let writer_orders = self.writer_orders.lock().unwrap();
        Ok(samples
            .into_iter()
            .map(|(payload, info, version)| ReceivedSample {
                topic: self.topic.clone(),
                type_name: self.type_name.clone(),
                payload,
                writer_guid: info.writer_guid.unwrap_or([0; 16]),
                instance_handle: info.instance_handle.0,
                sequence: info.sequence_number,
                timestamp_ns: info.reception_timestamp_ns,
                source_timestamp_ns: info.source_timestamp_ns,
                destination_order_by_source: writer_orders
                    .get(&info.writer_guid.unwrap_or([0; 16]))
                    .copied()
                    .unwrap_or(false),
                representation: version.representation_code(),
            })
            .collect())
    }

    fn read(&self) -> Result<Vec<ReceivedSample>> {
        self.take()
    }

    fn topic(&self) -> &str {
        &self.topic
    }

    fn type_name(&self) -> &str {
        &self.type_name
    }
}

struct HddsDataWriter {
    // One real raw writer per DATA_REPRESENTATION this topic carries,
    // each offering exactly that one (hdds::RawRelayWriter): a plain
    // RawDataWriter resolves and freezes ONE representation at creation,
    // which is exactly the item 6 defect once a durability replay has to
    // carry more than one. RawRelayWriter self-synchronizes writes with
    // its own internal lock, same as the Mutex<RawDataWriter> this
    // replaces.
    inner: RawRelayWriter,
    topic: String,
    type_name: String,
}

impl DataWriter for HddsDataWriter {
    fn write(&self, payload: &[u8]) -> Result<()> {
        self.inner
            .relay_write(payload, hdds::CdrVersion::Xcdr1)
            .map_err(|e| anyhow!("RawRelayWriter::relay_write failed: {:?}", e))
    }

    fn write_with_timestamp(&self, payload: &[u8], timestamp_ns: u64) -> Result<()> {
        self.write_sample(
            payload,
            timestamp_ns,
            hdds::CdrVersion::Xcdr1.representation_code(),
        )
    }

    fn write_sample(&self, payload: &[u8], timestamp_ns: u64, representation: u16) -> Result<()> {
        let version = hdds::CdrVersion::from_representation_code(representation)
            .unwrap_or(hdds::CdrVersion::Xcdr1);
        self.inner
            .relay_write_with_key_and_timestamp(payload, version, None, timestamp_ns)
            .map_err(|e| anyhow!("RawRelayWriter::relay_write failed: {:?}", e))
    }

    fn write_sample_with_key(
        &self,
        payload: &[u8],
        timestamp_ns: u64,
        representation: u16,
        instance_handle: [u8; 16],
    ) -> Result<()> {
        let version = hdds::CdrVersion::from_representation_code(representation)
            .unwrap_or(hdds::CdrVersion::Xcdr1);
        self.inner
            .relay_write_with_key_and_timestamp(
                payload,
                version,
                Some(instance_handle),
                timestamp_ns,
            )
            .map_err(|e| anyhow!("RawRelayWriter::relay_write_with_key failed: {:?}", e))
    }

    fn topic(&self) -> &str {
        &self.topic
    }

    fn type_name(&self) -> &str {
        &self.type_name
    }
}

type WriterOrderMap = std::sync::Mutex<std::collections::HashMap<[u8; 16], bool>>;

struct WriterOrders(std::sync::Weak<WriterOrderMap>);

impl DiscoveryListener for WriterOrders {
    fn on_endpoint_discovered(&self, endpoint: EndpointInfo) {
        if !matches!(endpoint.kind, EndpointKind::Writer) {
            return;
        }
        if let Some(orders) = self.0.upgrade() {
            orders.lock().unwrap().insert(
                endpoint.endpoint_guid.as_bytes(),
                endpoint.qos.destination_order.uses_source_timestamp(),
            );
        }
    }
}

struct HddsDiscoveryBridge {
    callback: Arc<dyn DiscoveryCallback>,
}

impl DiscoveryListener for HddsDiscoveryBridge {
    fn on_endpoint_discovered(&self, endpoint: EndpointInfo) {
        let durability = durability_kind_from_qos(endpoint.qos.durability);
        match endpoint.kind {
            EndpointKind::Reader => {
                self.callback.on_reader_discovered(DiscoveredReader {
                    guid: endpoint.endpoint_guid.as_bytes(),
                    topic: endpoint.topic_name,
                    type_name: endpoint.type_name,
                    durability,
                });
            }
            EndpointKind::Writer => {
                self.callback.on_writer_discovered(DiscoveredWriter {
                    guid: endpoint.endpoint_guid.as_bytes(),
                    topic: endpoint.topic_name,
                    type_name: endpoint.type_name,
                    durability,
                    retention_hint: retention_hint_from_qos(&endpoint.qos),
                });
            }
        }
    }
}

impl DdsInterface for HddsDdsInterface {
    fn create_reader(
        &self,
        topic: &str,
        type_name: &str,
        durability: DurabilityKind,
    ) -> Result<Box<dyn DataReader>> {
        let qos = qos_for_durability(durability);
        // Retain the offer after endpoint retirement, until queued samples
        // have been captured. Register before taking the initial snapshot.
        let writer_orders = Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
        let orders = Arc::new(WriterOrders(Arc::downgrade(&writer_orders)));
        self.discovery.register_listener(orders.clone());
        for (_, (writers, _)) in self.discovery.get_all_topics() {
            for writer in writers {
                orders.on_endpoint_discovered(writer);
            }
        }

        let reader = self
            .participant
            .create_raw_reader_with_type(topic, type_name, Some(qos), None, None)
            .map_err(|e| anyhow!("create_raw_reader_with_type failed: {:?}", e))?;

        Ok(Box::new(HddsDataReader {
            inner: reader,
            writer_orders,
            topic: topic.to_string(),
            type_name: type_name.to_string(),
        }))
    }

    fn create_writer(
        &self,
        topic: &str,
        type_name: &str,
        durability: DurabilityKind,
    ) -> Result<Box<dyn DataWriter>> {
        self.create_writer_with_destination_order(topic, type_name, durability, false)
    }

    fn create_writer_with_destination_order(
        &self,
        topic: &str,
        type_name: &str,
        durability: DurabilityKind,
        by_source: bool,
    ) -> Result<Box<dyn DataWriter>> {
        let mut qos = qos_for_durability(durability);
        if by_source {
            qos.destination_order = hdds::dds::qos::DestinationOrder::by_source_timestamp();
        }
        // Retiring the service's replay writer must not dispose the original
        // application's durable instances (DDS v1.4 Sec.2.2.3.4/2.2.3.21).
        qos.writer_data_lifecycle.autodispose_unregistered_instances = false;

        // No representation known yet at creation time (this writer
        // backs a durability replay target; which representations it
        // will carry are learned per-sample, from the recovered
        // Sample::representation of what it replays). No eager hint:
        // every representation this writer ever carries is created
        // lazily, on its own first sample.
        let writer = RawRelayWriter::new(
            Arc::clone(&self.participant),
            topic,
            type_name,
            Some(qos),
            None,
            None,
        )
        .map_err(|e| anyhow!("RawRelayWriter::new failed: {:?}", e))?;

        Ok(Box::new(HddsDataWriter {
            inner: writer,
            topic: topic.to_string(),
            type_name: type_name.to_string(),
        }))
    }

    fn discovered_readers(&self, topic_pattern: &str) -> Result<Vec<DiscoveredReader>> {
        let topics = self.discovery.get_all_topics();
        let mut readers = Vec::new();

        for (topic, (_writers, discovered_readers)) in topics {
            if !crate::dds_interface::topic_matches(topic_pattern, &topic) {
                continue;
            }
            for reader in discovered_readers {
                readers.push(DiscoveredReader {
                    guid: reader.endpoint_guid.as_bytes(),
                    topic: reader.topic_name,
                    type_name: reader.type_name,
                    durability: durability_kind_from_qos(reader.qos.durability),
                });
            }
        }

        Ok(readers)
    }

    fn discovered_writers(&self, topic_pattern: &str) -> Result<Vec<DiscoveredWriter>> {
        let topics = self.discovery.get_all_topics();
        let mut writers = Vec::new();

        for (topic, (discovered_writers, _readers)) in topics {
            if !crate::dds_interface::topic_matches(topic_pattern, &topic) {
                continue;
            }
            for writer in discovered_writers {
                writers.push(DiscoveredWriter {
                    guid: writer.endpoint_guid.as_bytes(),
                    topic: writer.topic_name,
                    type_name: writer.type_name,
                    durability: durability_kind_from_qos(writer.qos.durability),
                    retention_hint: retention_hint_from_qos(&writer.qos),
                });
            }
        }

        Ok(writers)
    }

    fn wait_for_discovery(&self, timeout: Duration) -> Result<bool> {
        std::thread::sleep(timeout);
        Ok(false)
    }

    fn register_discovery_callback(&self, callback: Arc<dyn DiscoveryCallback>) -> Result<()> {
        let listener = Arc::new(HddsDiscoveryBridge { callback });
        self.discovery.register_listener(listener);
        Ok(())
    }

    fn guid(&self) -> [u8; 16] {
        self.participant.guid().as_bytes()
    }
}

fn qos_for_durability(durability: DurabilityKind) -> QoS {
    match durability {
        DurabilityKind::Volatile => QoS::reliable().volatile().keep_all(),
        DurabilityKind::TransientLocal => QoS::reliable().transient_local().keep_all(),
        DurabilityKind::Transient => QoS::reliable().transient().keep_all(),
        DurabilityKind::Persistent => QoS::reliable().persistent().keep_all(),
    }
}

fn durability_kind_from_qos(durability: Durability) -> DurabilityKind {
    match durability {
        Durability::Volatile => DurabilityKind::Volatile,
        Durability::TransientLocal => DurabilityKind::TransientLocal,
        Durability::Transient => DurabilityKind::Transient,
        Durability::Persistent => DurabilityKind::Persistent,
    }
}

/// Derive this service's retention policy from a discovered writer's QoS.
///
/// DDS v1.4 Sec.2.2.3.4 (DURABILITY): TRANSIENT_LOCAL's late-joiner data is
/// the DataWriter's own HISTORY, served directly by the writer -- never a
/// job for this external persistence service. Sec.2.2.3.5
/// (DURABILITY_SERVICE) scopes the service to TRANSIENT and PERSISTENT
/// only. A writer of any other durability (including TRANSIENT_LOCAL)
/// gets no retention hint from this function.
///
/// DDS v1.4 Sec.2.2.3.5 gives the service its own HISTORY and
/// RESOURCE_LIMITS through DURABILITY_SERVICE. The writer's HISTORY and
/// RESOURCE_LIMITS must not reduce the service's independent retention.
/// The default service policy is meaningful: KEEP_LAST(1), unlimited limits.
fn retention_hint_from_qos(qos: &hdds::dds::qos::QoS) -> Option<RetentionPolicy> {
    if !matches!(
        qos.durability,
        Durability::Transient | Durability::Persistent
    ) {
        return None;
    }

    let service = &qos.durability_service;
    let mut per_instance = service.history_depth as usize;
    if service.max_samples_per_instance > 0 {
        per_instance = per_instance.min(service.max_samples_per_instance as usize);
    }

    Some(RetentionPolicy {
        keep_count_per_instance: per_instance,
        max_samples_total: service.max_samples.max(0) as usize,
        max_instances: service.max_instances.max(0) as usize,
        max_age_ns: None,
        max_bytes: None,
    })
}

#[cfg(test)]
mod retention_hint_tests {
    use super::*;
    use crate::sqlite::SqliteStore;
    use crate::store::{PersistenceStore, Sample};
    use hdds::dds::qos::DurabilityService;

    /// DDS v1.4 Sec.2.2.3.4: only TRANSIENT and PERSISTENT use the service.
    #[test]
    fn transient_local_gets_no_retention_hint() {
        let qos = QoS::reliable().transient_local().keep_last(50);
        assert!(retention_hint_from_qos(&qos).is_none());
    }

    #[test]
    fn volatile_gets_no_retention_hint() {
        let qos = QoS::reliable().volatile().keep_last(50);
        assert!(retention_hint_from_qos(&qos).is_none());
    }

    /// DDS v1.4 Sec.2.2.3.5: the service has its own history, independent
    /// of the writer's history and resource limits.
    #[test]
    fn durability_service_history_survives_a_smaller_writer_history() {
        let mut qos = QoS::reliable().persistent().keep_last(1);
        qos.resource_limits.max_samples = 1;
        qos.resource_limits.max_samples_per_instance = 1;
        qos.durability_service = DurabilityService::keep_last(10, -1, -1, -1);
        let policy = retention_hint_from_qos(&qos).unwrap();
        let store = SqliteStore::new_in_memory().unwrap();
        for sequence in 1..=10 {
            store
                .save(&Sample {
                    topic: "keyed/topic".to_string(),
                    type_name: "Keyed".to_string(),
                    payload: vec![sequence as u8],
                    timestamp_ns: sequence,
                    sequence,
                    source_guid: [1; 16],
                    instance_handle: [2; 16],
                    source_timestamp_ns: None,
                    destination_order_by_source: false,
                    representation: 0,
                })
                .unwrap();
        }
        store
            .apply_retention_policy("keyed/topic", &policy)
            .unwrap();
        assert_eq!(store.load("keyed/topic").unwrap().len(), 10);
        assert_eq!(policy.max_samples_total, 0);
    }

    /// DDS v1.4 Sec.2.2.3.5 and the QoS defaults table: default is a
    /// configured KEEP_LAST(1), even when the writer uses KEEP_ALL.
    #[test]
    fn explicit_default_durability_service_keeps_one_per_instance() {
        let mut qos = QoS::reliable().persistent().keep_all();
        qos.durability_service = DurabilityService::default();
        let policy = retention_hint_from_qos(&qos).unwrap();
        assert_eq!(policy.keep_count_per_instance, 1);
        assert_eq!(policy.max_samples_total, 0);
        assert_eq!(policy.max_instances, 0);
    }

    /// DDS v1.4 Sec.2.2.3.5: each service resource limit has its own axis.
    #[test]
    fn durability_service_resource_limits_remain_independent() {
        let mut qos = QoS::reliable().persistent().keep_last(1);
        qos.resource_limits.max_instances = 1;
        qos.durability_service = DurabilityService::keep_last(5, 1000, 4, 8);
        let policy = retention_hint_from_qos(&qos).unwrap();
        assert_eq!(policy.keep_count_per_instance, 5);
        assert_eq!(policy.max_samples_total, 1000);
        assert_eq!(policy.max_instances, 4);
    }
}

#[cfg(test)]
mod durability_tests {
    use super::*;

    /// DDS v1.4 Sec.2.2.3.4: discovery and service entities preserve all
    /// four kinds, including the separate TRANSIENT compatibility level.
    #[test]
    fn all_four_durability_kinds_round_trip_and_keep_their_order() {
        let kinds = [
            (DurabilityKind::Volatile, Durability::Volatile),
            (DurabilityKind::TransientLocal, Durability::TransientLocal),
            (DurabilityKind::Transient, Durability::Transient),
            (DurabilityKind::Persistent, Durability::Persistent),
        ];
        for (rank, (kind, wire_kind)) in kinds.into_iter().enumerate() {
            assert_eq!(durability_kind_from_qos(wire_kind), kind);
            assert_eq!(qos_for_durability(kind).durability, wire_kind);
            assert_eq!(kind.rank(), rank as u8);
            assert_eq!(kind.is_durable(), rank > 0);
        }
    }
}
