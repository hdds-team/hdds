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
use hdds::dds::qos::{Durability, DurabilityService, History};
use hdds::{Participant, QoS, RawDataReader, RawDataWriter};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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
}

impl DataReader for HddsDataReader {
    fn take(&self) -> Result<Vec<ReceivedSample>> {
        let samples = self
            .inner
            .try_take_raw()
            .map_err(|e| anyhow!("RawDataReader::try_take_raw failed: {:?}", e))?;

        Ok(samples
            .into_iter()
            .map(|sample| ReceivedSample {
                topic: self.topic.clone(),
                type_name: self.type_name.clone(),
                payload: sample.payload,
                writer_guid: sample.writer_guid.as_bytes(),
                sequence: sample.sequence_number.unwrap_or(0),
                timestamp_ns: system_time_to_ns(sample.reception_timestamp),
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
    inner: Mutex<RawDataWriter>,
    topic: String,
    type_name: String,
}

impl DataWriter for HddsDataWriter {
    fn write(&self, payload: &[u8]) -> Result<()> {
        let writer = match self.inner.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        writer
            .write_raw(payload)
            .map_err(|e| anyhow!("RawDataWriter::write_raw failed: {:?}", e))
    }

    fn write_with_timestamp(&self, payload: &[u8], _timestamp_ns: u64) -> Result<()> {
        self.write(payload)
    }

    fn topic(&self) -> &str {
        &self.topic
    }

    fn type_name(&self) -> &str {
        &self.type_name
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

        let reader = self
            .participant
            .create_raw_reader_with_type(topic, type_name, Some(qos), None)
            .map_err(|e| anyhow!("create_raw_reader_with_type failed: {:?}", e))?;

        Ok(Box::new(HddsDataReader {
            inner: reader,
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
        let qos = qos_for_durability(durability);

        let writer = self
            .participant
            .create_raw_writer_with_type(topic, type_name, Some(qos), None)
            .map_err(|e| anyhow!("create_raw_writer_with_type failed: {:?}", e))?;

        Ok(Box::new(HddsDataWriter {
            inner: Mutex::new(writer),
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

fn system_time_to_ns(time: SystemTime) -> u64 {
    match time.duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_nanos() as u64,
        Err(_) => 0,
    }
}

fn qos_for_durability(durability: DurabilityKind) -> QoS {
    match durability {
        DurabilityKind::Volatile => QoS::reliable().volatile().keep_all(),
        DurabilityKind::TransientLocal => QoS::reliable().transient_local().keep_all(),
        DurabilityKind::Persistent => QoS::reliable().persistent().keep_all(),
    }
}

fn durability_kind_from_qos(durability: Durability) -> DurabilityKind {
    match durability {
        Durability::Volatile => DurabilityKind::Volatile,
        Durability::TransientLocal => DurabilityKind::TransientLocal,
        Durability::Persistent => DurabilityKind::Persistent,
    }
}

fn retention_hint_from_qos(qos: &hdds::dds::qos::QoS) -> Option<RetentionPolicy> {
    if !matches!(
        qos.durability,
        Durability::TransientLocal | Durability::Persistent
    ) {
        return None;
    }

    let mut keep_count: Option<usize> = None;
    let mut apply_limit = |limit: usize| {
        if limit == 0 {
            return;
        }
        keep_count = Some(match keep_count {
            Some(existing) => existing.min(limit),
            None => limit,
        });
    };

    match qos.history {
        History::KeepLast(depth) if depth > 0 => apply_limit(depth as usize),
        History::KeepAll => {
            if qos.resource_limits.max_samples > 0 {
                apply_limit(qos.resource_limits.max_samples);
            }
        }
        _ => {}
    }

    if qos.resource_limits.max_samples > 0 {
        apply_limit(qos.resource_limits.max_samples);
    }

    if qos.durability_service != DurabilityService::default() {
        if qos.durability_service.history_depth > 0 {
            apply_limit(qos.durability_service.history_depth as usize);
        }
        if qos.durability_service.max_samples > 0 {
            apply_limit(qos.durability_service.max_samples as usize);
        }
    }

    keep_count.map(|keep_count| RetentionPolicy {
        keep_count,
        max_age_ns: None,
        max_bytes: None,
    })
}
