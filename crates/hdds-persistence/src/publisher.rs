// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Late-joiner publisher
//!
//! Detects new readers and replays historical samples.
//!
//! # Operation
//!
//! 1. Monitor for new DataReaders via discovery
//! 2. When a TRANSIENT or PERSISTENT reader joins, query stored history
//! 3. Replay historical samples to the new reader via DataWriter

use crate::config::Config;
use crate::dds_interface::{
    DataWriter, DdsInterface, DiscoveredReader, DiscoveredWriter, DiscoveryCallback, DurabilityKind,
};
use crate::store::{PersistenceStore, Sample};
use anyhow::Result;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::sync::RwLock;

/// Late-joiner publisher
///
/// Monitors for new DataReaders and replays historical data to them.
pub struct LateJoinerPublisher<S: PersistenceStore, D: DdsInterface> {
    config: Config,
    store: Arc<RwLock<S>>,
    dds: Arc<D>,
    /// Readers we've already replayed to
    replayed_readers: HashSet<[u8; 16]>,
    /// Writers keyed by topic and the original destination-order offer.
    writers: HashMap<(String, bool), WriterState>,
    /// Statistics
    stats: PublisherStats,
}

struct WriterState {
    durability: DurabilityKind,
    writer: Box<dyn DataWriter>,
}

type ReplayCallback = Box<dyn Fn(&Sample) + Send + Sync>;

/// Publisher statistics
#[derive(Debug, Default, Clone)]
pub struct PublisherStats {
    /// Total readers discovered
    pub readers_discovered: u64,
    /// Readers that requested replay
    pub readers_replayed: u64,
    /// Total samples replayed
    pub samples_replayed: u64,
    /// Replay errors
    pub replay_errors: u64,
}

#[allow(dead_code)]
enum DiscoveryEvent {
    Reader(DiscoveredReader),
    Writer(DiscoveredWriter),
}

struct DiscoveryBridge {
    tx: mpsc::Sender<DiscoveryEvent>,
}

impl DiscoveryCallback for DiscoveryBridge {
    fn on_reader_discovered(&self, reader: DiscoveredReader) {
        if self.tx.try_send(DiscoveryEvent::Reader(reader)).is_err() {
            tracing::debug!("Dropping reader discovery event (channel full)");
        }
    }

    fn on_reader_removed(&self, _guid: [u8; 16]) {}

    fn on_writer_discovered(&self, writer: DiscoveredWriter) {
        if self.tx.try_send(DiscoveryEvent::Writer(writer)).is_err() {
            tracing::debug!("Dropping writer discovery event (channel full)");
        }
    }

    fn on_writer_removed(&self, _guid: [u8; 16]) {}
}

impl<S: PersistenceStore + Send + Sync, D: DdsInterface> LateJoinerPublisher<S, D> {
    /// Create a new late-joiner publisher
    pub fn new(config: Config, store: Arc<RwLock<S>>, dds: Arc<D>) -> Self {
        Self {
            config,
            store,
            dds,
            replayed_readers: HashSet::new(),
            writers: HashMap::new(),
            stats: PublisherStats::default(),
        }
    }

    /// Get publisher statistics
    pub fn stats(&self) -> &PublisherStats {
        &self.stats
    }

    /// Run the publisher
    pub async fn run(mut self) -> Result<()> {
        tracing::info!(
            "LateJoinerPublisher started for topics: {}",
            self.config.topic_filter
        );

        let (event_tx, mut event_rx) = mpsc::channel(128);
        let bridge = Arc::new(DiscoveryBridge { tx: event_tx });
        self.dds.register_discovery_callback(bridge)?;

        // Initial snapshot
        self.discover_and_replay().await?;

        loop {
            tokio::select! {
                Some(event) = event_rx.recv() => {
                    if let DiscoveryEvent::Reader(reader) = event {
                        if let Err(e) = self.handle_reader_discovered(reader).await {
                            tracing::error!("Discovery/replay error: {}", e);
                        }
                    }
                }
            }
        }
    }

    /// Discover new readers and replay history to them
    async fn discover_and_replay(&mut self) -> Result<()> {
        let readers = self.dds.discovered_readers(&self.config.topic_filter)?;

        for reader in readers {
            self.handle_reader_discovered(reader).await?;
        }

        Ok(())
    }

    async fn handle_reader_discovered(&mut self, reader: DiscoveredReader) -> Result<()> {
        // Skip if we've already replayed to this reader
        if self.replayed_readers.contains(&reader.guid) {
            return Ok(());
        }

        self.stats.readers_discovered += 1;

        if !self.should_replay(&reader)? {
            self.replayed_readers.insert(reader.guid);
            return Ok(());
        }

        tracing::info!("New durable reader discovered for topic: {}", reader.topic);

        // Replay history
        match self.replay_to_reader(&reader).await {
            Ok(count) => {
                self.stats.readers_replayed += 1;
                self.stats.samples_replayed += count as u64;
                tracing::info!(
                    "Replayed {} samples to reader {} for topic {}",
                    count,
                    hex(&reader.guid[0..4]),
                    reader.topic
                );
            }
            Err(e) => {
                self.stats.replay_errors += 1;
                tracing::error!(
                    "Failed to replay to reader {}: {}",
                    hex(&reader.guid[0..4]),
                    e
                );
            }
        }

        self.replayed_readers.insert(reader.guid);
        Ok(())
    }

    fn should_replay(&self, reader: &DiscoveredReader) -> Result<bool> {
        match reader.durability {
            DurabilityKind::Volatile => {
                tracing::debug!(
                    "Skipping volatile reader {} for topic {}",
                    hex(&reader.guid[0..4]),
                    reader.topic
                );
                return Ok(false);
            }
            DurabilityKind::TransientLocal => {
                tracing::debug!(
                    "Skipping transient-local reader {} for topic {} (writer handles replay)",
                    hex(&reader.guid[0..4]),
                    reader.topic
                );
                return Ok(false);
            }
            DurabilityKind::Transient | DurabilityKind::Persistent => {}
        }

        Ok(true)
    }

    /// Replay historical samples to a specific reader
    async fn replay_to_reader(&mut self, reader: &DiscoveredReader) -> Result<usize> {
        // Query store for historical samples first
        let mut samples = {
            let store = self.store.read().await;
            store.query_range(&reader.topic, 0, u64::MAX)?
        };

        // A live compatible original writer serves its own durable history.
        // Other writers on the topic cannot cover data from a departed writer.
        let live_writers: HashSet<_> = self
            .dds
            .discovered_writers(&reader.topic)?
            .into_iter()
            .filter(|writer| {
                writer.topic == reader.topic
                    && writer.type_name == reader.type_name
                    && writer.durability.rank() >= reader.durability.rank()
            })
            .map(|writer| writer.guid)
            .collect();
        samples.retain(|sample| !live_writers.contains(&sample.source_guid));

        if samples.is_empty() {
            tracing::debug!("No historical samples for topic {}", reader.topic);
            return Ok(0);
        }

        // Replay samples in order
        let mut replayed = 0;
        for sample in &samples {
            match self.write_stored_sample(sample, &reader.type_name, reader.durability) {
                Ok(()) => {
                    replayed += 1;
                    tracing::trace!(
                        "Replayed sample seq={} to topic {}",
                        sample.sequence,
                        sample.topic
                    );
                }
                Err(e) => {
                    tracing::warn!("Failed to replay sample seq={}: {}", sample.sequence, e);
                }
            }
        }

        Ok(replayed)
    }

    // Each sample keeps its original offer. Promoting reception-ordered
    // samples to a source-ordered writer would match readers the original
    // writer could not serve (DDS v1.4 Sec.2.2.3.17).
    fn write_stored_sample(
        &mut self,
        sample: &Sample,
        type_name: &str,
        durability: DurabilityKind,
    ) -> Result<()> {
        self.get_or_create_writer(
            &sample.topic,
            type_name,
            durability,
            sample.destination_order_by_source,
        )?
        .write_sample_with_key(
            &sample.payload,
            sample.source_timestamp_ns.unwrap_or(sample.timestamp_ns),
            sample.representation,
            sample.instance_handle,
        )
    }

    /// Get or create a DataWriter for a topic and destination-order offer.
    fn get_or_create_writer(
        &mut self,
        topic: &str,
        type_name: &str,
        durability: DurabilityKind,
        by_source: bool,
    ) -> Result<&dyn DataWriter> {
        let entry = self.writers.entry((topic.to_string(), by_source));
        let state = match entry {
            std::collections::hash_map::Entry::Vacant(slot) => {
                let writer = self.dds.create_writer_with_destination_order(
                    topic, type_name, durability, by_source,
                )?;
                tracing::info!(
                    "Created writer for topic: {} (durability={:?})",
                    topic,
                    durability
                );
                slot.insert(WriterState { durability, writer })
            }
            std::collections::hash_map::Entry::Occupied(mut slot) => {
                if slot.get().durability.rank() < durability.rank() {
                    let writer = self.dds.create_writer_with_destination_order(
                        topic, type_name, durability, by_source,
                    )?;
                    tracing::info!(
                        "Upgraded writer for topic: {} (durability={:?})",
                        topic,
                        durability
                    );
                    *slot.get_mut() = WriterState { durability, writer };
                }
                slot.into_mut()
            }
        };

        Ok(state.writer.as_ref())
    }

    /// Manually trigger replay for a topic (for testing)
    pub async fn replay_topic(&mut self, topic: &str, type_name: &str) -> Result<usize> {
        // Load samples first
        let samples = {
            let store = self.store.read().await;
            store.load(topic)?
        };

        if samples.is_empty() {
            return Ok(0);
        }

        let mut replayed = 0;
        for sample in &samples {
            if self
                .write_stored_sample(sample, type_name, DurabilityKind::TransientLocal)
                .is_ok()
            {
                replayed += 1;
            }
        }

        self.stats.samples_replayed += replayed as u64;
        Ok(replayed)
    }
}

// ============================================================================
// Standalone mode (without DDS - for testing and CLI)
// ============================================================================

/// Standalone late-joiner publisher that replays via callback
pub struct StandalonePublisher<S: PersistenceStore> {
    config: Config,
    store: Arc<RwLock<S>>,
    /// Callback for replayed samples
    on_replay: Option<ReplayCallback>,
    stats: PublisherStats,
}

impl<S: PersistenceStore + Send + Sync> StandalonePublisher<S> {
    /// Create a new standalone publisher
    pub fn new(config: Config, store: Arc<RwLock<S>>) -> Self {
        Self {
            config,
            store,
            on_replay: None,
            stats: PublisherStats::default(),
        }
    }

    /// Set callback for replayed samples
    pub fn on_replay<F>(mut self, callback: F) -> Self
    where
        F: Fn(&Sample) + Send + Sync + 'static,
    {
        self.on_replay = Some(Box::new(callback));
        self
    }

    /// Get statistics
    pub fn stats(&self) -> &PublisherStats {
        &self.stats
    }

    /// Replay all samples matching topic filter
    pub async fn replay_all(&mut self) -> Result<usize> {
        let store = self.store.read().await;
        let samples = store.query_range(&self.config.topic_filter, 0, u64::MAX)?;

        let mut replayed = 0;
        for sample in &samples {
            if let Some(ref callback) = self.on_replay {
                callback(sample);
            }
            replayed += 1;
            self.stats.samples_replayed += 1;
        }

        tracing::info!(
            "Replayed {} samples for pattern {}",
            replayed,
            self.config.topic_filter
        );

        Ok(replayed)
    }

    /// Replay samples for a specific topic
    pub async fn replay_topic(&mut self, topic: &str) -> Result<usize> {
        let store = self.store.read().await;
        let samples = store.load(topic)?;

        let mut replayed = 0;
        for sample in &samples {
            if let Some(ref callback) = self.on_replay {
                callback(sample);
            }
            replayed += 1;
            self.stats.samples_replayed += 1;
        }

        tracing::info!("Replayed {} samples for topic {}", replayed, topic);

        Ok(replayed)
    }

    /// Replay samples in a time range
    pub async fn replay_range(&mut self, topic: &str, start_ns: u64, end_ns: u64) -> Result<usize> {
        let store = self.store.read().await;
        let samples = store.query_range(topic, start_ns, end_ns)?;

        let mut replayed = 0;
        for sample in &samples {
            if let Some(ref callback) = self.on_replay {
                callback(sample);
            }
            replayed += 1;
            self.stats.samples_replayed += 1;
        }

        tracing::info!(
            "Replayed {} samples for topic {} in range [{}, {}]",
            replayed,
            topic,
            start_ns,
            end_ns
        );

        Ok(replayed)
    }
}

/// Helper: format bytes as hex
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dds_interface::{DiscoveredReader, DurabilityKind, MockDdsInterface};
    use crate::sqlite::SqliteStore;

    #[test]
    fn test_late_joiner_publisher_creation() {
        let config = Config::builder().topic_filter("State/*").build();

        let store = SqliteStore::new_in_memory().unwrap();
        let store = Arc::new(RwLock::new(store));

        let dds = Arc::new(MockDdsInterface::new());

        let publisher = LateJoinerPublisher::new(config, store, dds);
        assert_eq!(publisher.stats.readers_discovered, 0);
    }

    #[tokio::test]
    async fn test_discover_and_replay() {
        let config = Config::builder().topic_filter("State/*").build();

        let store = SqliteStore::new_in_memory().unwrap();

        // Add some historical samples
        for i in 0..5 {
            let sample = Sample {
                topic: "State/Temperature".to_string(),
                type_name: "Temperature".to_string(),
                payload: vec![i as u8],
                timestamp_ns: i * 1000,
                sequence: i,
                source_guid: [0xAA; 16],
                source_timestamp_ns: None,
                destination_order_by_source: false,
                representation: 0,
                instance_handle: [0u8; 16],
            };
            store.save(&sample).unwrap();
        }

        let store = Arc::new(RwLock::new(store));
        let dds = Arc::new(MockDdsInterface::new());

        // Add a mock reader
        dds.add_reader(DiscoveredReader {
            guid: [0x01; 16],
            topic: "State/Temperature".to_string(),
            type_name: "Temperature".to_string(),
            durability: DurabilityKind::Persistent,
        });

        let mut publisher = LateJoinerPublisher::new(config, store, dds);

        // Run discovery
        publisher.discover_and_replay().await.unwrap();

        assert_eq!(publisher.stats.readers_discovered, 1);
        assert_eq!(publisher.stats.readers_replayed, 1);
        assert_eq!(publisher.stats.samples_replayed, 5);
    }

    /// DDS v1.4 Sec.2.2.3.4: the service handles TRANSIENT and
    /// PERSISTENT; TRANSIENT_LOCAL history belongs to the live writer.
    #[test]
    fn service_replay_distinguishes_transient_from_transient_local() {
        let store = Arc::new(RwLock::new(SqliteStore::new_in_memory().unwrap()));
        let dds = Arc::new(MockDdsInterface::new());
        let publisher = LateJoinerPublisher::new(Config::default(), store, dds);
        for (durability, expected) in [
            (DurabilityKind::Volatile, false),
            (DurabilityKind::TransientLocal, false),
            (DurabilityKind::Transient, true),
            (DurabilityKind::Persistent, true),
        ] {
            assert_eq!(
                publisher
                    .should_replay(&DiscoveredReader {
                        guid: [1; 16],
                        topic: "service_history".to_string(),
                        type_name: "State".to_string(),
                        durability,
                    })
                    .unwrap(),
                expected,
                "service replay for {durability:?}"
            );
        }
    }

    /// DDS v1.4 Sec.2.2.3.4: service history outlives a TRANSIENT writer.
    /// DDS v1.4 Sec.2.2.2.5.5/2.2.3.17: source time and the compatible
    /// destination-order offer survive capture, database reopen and replay.
    #[tokio::test]
    async fn source_timestamp_and_offer_survive_capture_storage_and_late_replay() {
        use crate::hdds_interface::HddsDdsInterface;
        use hdds::api::DDS as DdsTrait;
        use hdds::{Participant, QoS, TransportMode};

        #[derive(hdds::DDS, Debug, Clone, PartialEq)]
        struct State {
            value: u32,
        }

        let domain = loop {
            let lease = hdds::test_support::domains::unique_domain();
            if (200..=230).contains(&lease.id()) {
                break lease;
            }
        };
        let participant = Participant::builder("transient_service_replay")
            .domain_id(domain.id())
            .with_transport(TransportMode::UdpMulticast)
            .build()
            .unwrap();
        let dds = Arc::new(HddsDdsInterface::new(Arc::clone(&participant)).unwrap());
        let topic_name = "transient_service_state";
        let type_name = <State as DdsTrait>::type_descriptor().type_name;
        let topic = participant.topic::<State>(topic_name).unwrap();
        let mut writer_qos = QoS::reliable()
            .transient()
            .keep_all()
            .destination_order(hdds::dds::qos::DestinationOrder::by_source_timestamp());
        writer_qos
            .writer_data_lifecycle
            .autodispose_unregistered_instances = false;
        let writer = topic.writer().qos(writer_qos.clone()).build().unwrap();
        let reception_writer = topic
            .writer()
            .qos(
                writer_qos
                    .destination_order(hdds::dds::qos::DestinationOrder::by_reception_timestamp()),
            )
            .build()
            .unwrap();
        let capture = dds
            .create_reader(topic_name, type_name, DurabilityKind::Transient)
            .unwrap();
        let expected = State { value: 42 };
        // A non-binary fractional second also checks that replay does not
        // lose an additional nanosecond on each Time_t conversion.
        const T1: u64 = 1_123_456_788;
        writer.write_w_timestamp(&expected, T1 + 1).unwrap();
        const T2: u64 = 2_000_000_000;
        reception_writer
            .write_w_timestamp(&State { value: 99 }, T2)
            .unwrap();
        // The offer must remain available after the original endpoint leaves,
        // until its queued samples have been captured.
        drop(writer);
        drop(reception_writer);
        let received = capture.take().unwrap();
        assert_eq!(
            received.len(),
            2,
            "the service receives both writers' values"
        );
        assert_eq!(received[0].source_timestamp_ns, Some(T1));
        assert!(received[0].destination_order_by_source);
        assert_eq!(received[1].source_timestamp_ns, Some(T2));
        assert!(!received[1].destination_order_by_source);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("history.db");
        let store = SqliteStore::new(path.to_str().unwrap()).unwrap();
        for sample in received {
            store.save(&sample.into()).unwrap();
        }
        drop(store);
        let store = SqliteStore::new(path.to_str().unwrap()).unwrap();
        let stored = store.load(topic_name).unwrap();
        assert_eq!(stored[0].source_timestamp_ns, Some(T1));
        assert!(stored[0].destination_order_by_source);
        drop(capture);
        assert!(dds.discovered_writers(topic_name).unwrap().is_empty());

        let late_reader = topic
            .reader()
            .qos(
                QoS::reliable()
                    .transient()
                    .keep_all()
                    .destination_order(hdds::dds::qos::DestinationOrder::by_source_timestamp()),
            )
            .build()
            .unwrap();
        assert!(late_reader.take().unwrap().is_none());
        let mut publisher = LateJoinerPublisher::new(
            Config::builder().topic_filter(topic_name).build(),
            Arc::new(RwLock::new(store)),
            dds,
        );
        publisher.discover_and_replay().await.unwrap();

        let (value, info) = late_reader.take_with_info().unwrap().expect("late replay");
        assert_eq!(value, Some(expected));
        assert_eq!(info.source_timestamp_ns, Some(T1));
        assert!(late_reader.take().unwrap().is_none());
        assert_eq!(
            publisher.writers[&(topic_name.to_string(), true)].durability,
            DurabilityKind::Transient
        );
    }

    /// DDS v1.4 Sec.2.2.3.4: a live writer does not replace the service's
    /// retained history from a different writer that has already left.
    #[tokio::test]
    async fn transient_replay_covers_departed_writers_beside_a_live_writer() {
        use crate::hdds_interface::HddsDdsInterface;
        use hdds::api::DDS as DdsTrait;
        use hdds::{Participant, QoS, TransportMode};

        #[derive(hdds::DDS, Debug, Clone, PartialEq)]
        struct KeyedState {
            #[key]
            key: u32,
            value: u32,
        }
        let domain = loop {
            let lease = hdds::test_support::domains::unique_domain();
            if (200..=230).contains(&lease.id()) {
                break lease;
            }
        };
        let participant = Participant::builder("transient_multiwriter_replay")
            .domain_id(domain.id())
            .with_transport(TransportMode::UdpMulticast)
            .build()
            .unwrap();
        let dds = Arc::new(HddsDdsInterface::new(participant.clone()).unwrap());
        let name = "transient_multiwriter_replay";
        let type_name = KeyedState::type_descriptor().type_name;
        let topic = participant.topic::<KeyedState>(name).unwrap();
        let mut qos = QoS::reliable().transient().keep_all();
        qos.writer_data_lifecycle.autodispose_unregistered_instances = false;
        let w1 = topic.writer().qos(qos.clone()).build().unwrap();
        let w2 = topic.writer().qos(qos).build().unwrap();
        let capture = dds
            .create_reader(name, type_name, DurabilityKind::Transient)
            .unwrap();
        let a = KeyedState { key: 1, value: 10 };
        let b = KeyedState { key: 2, value: 20 };
        w1.write(&a).unwrap();
        w2.write(&b).unwrap();
        let store = SqliteStore::new_in_memory().unwrap();
        let received = capture.take().unwrap();
        assert_eq!(received.len(), 2);
        let live = dds.discovered_writers(name).unwrap();
        for sample in received {
            assert!(live.iter().any(|writer| writer.guid == sample.writer_guid));
            store.save(&sample.into()).unwrap();
        }
        drop(capture);
        drop(w1);
        assert_eq!(dds.discovered_writers(name).unwrap().len(), 1);
        let reader = topic
            .reader()
            .qos(QoS::reliable().transient().keep_all())
            .build()
            .unwrap();
        // The live writer's own replay is synchronous on local delivery.
        assert_eq!(reader.take().unwrap(), Some(b.clone()));
        assert!(reader.take().unwrap().is_none());
        let mut publisher = LateJoinerPublisher::new(
            Config::builder().topic_filter(name).build(),
            Arc::new(RwLock::new(store)),
            dds,
        );
        publisher.discover_and_replay().await.unwrap();
        assert_eq!(
            publisher.stats.samples_replayed, 1,
            "only departed W1 needs service replay"
        );
        assert_eq!(reader.take().unwrap(), Some(a));
        assert!(
            reader.take().unwrap().is_none(),
            "live W2 must not be replayed twice"
        );
        drop(w2);
    }

    /// RTPS v2.5 Sec.9.6.4.8 and DDS v1.4 Sec.2.2.3.18: replay
    /// preserves the stored keys, including for opaque KEEP_LAST readers.
    #[tokio::test]
    async fn replay_keeps_stored_instances_distinct_at_depth_one() {
        use crate::hdds_interface::HddsDdsInterface;
        use hdds::api::DDS as DdsTrait;
        use hdds::{CdrVersion, Participant, QoS, TransportMode};

        #[derive(hdds::DDS, Debug, Clone, PartialEq)]
        struct KeyedState {
            #[key]
            key: u32,
            value: u32,
        }

        let domain = loop {
            let lease = hdds::test_support::domains::unique_domain();
            if (200..=230).contains(&lease.id()) {
                break lease;
            }
        };
        let participant = Participant::builder("keyed_service_replay")
            .domain_id(domain.id())
            .with_transport(TransportMode::UdpMulticast)
            .build()
            .unwrap();
        let name = "keyed_service_replay";
        let type_name = KeyedState::type_descriptor().type_name;
        let topic = participant.topic::<KeyedState>(name).unwrap();
        let qos = QoS::reliable().transient_local().keep_last(1);
        let typed = topic.reader().qos(qos.clone()).build().unwrap();
        let raw = participant
            .create_raw_reader_with_type(name, type_name, Some(qos), None, None)
            .unwrap();
        let store = SqliteStore::new_in_memory().unwrap();
        let expected = [
            KeyedState { key: 1, value: 10 },
            KeyedState { key: 2, value: 20 },
        ];
        for (i, value) in expected.iter().enumerate() {
            let mut payload = vec![0; 64];
            let size = value.encode(&mut payload, CdrVersion::Xcdr1).unwrap();
            payload.truncate(size);
            store
                .save(&Sample {
                    topic: name.to_string(),
                    type_name: type_name.to_string(),
                    payload,
                    timestamp_ns: i as u64,
                    sequence: i as u64 + 1,
                    source_guid: [0xA1; 16],
                    instance_handle: value.compute_key(),
                    source_timestamp_ns: None,
                    destination_order_by_source: false,
                    representation: CdrVersion::Xcdr1.representation_code(),
                })
                .unwrap();
        }
        let dds = Arc::new(HddsDdsInterface::new(participant.clone()).unwrap());
        let mut publisher =
            LateJoinerPublisher::new(Config::default(), Arc::new(RwLock::new(store)), dds);
        assert_eq!(publisher.replay_topic(name, type_name).await.unwrap(), 2);
        let samples = raw.try_take_raw_with_info_and_encoding().unwrap();
        assert_eq!(samples.len(), 2, "each stored key has its own depth budget");
        for value in &expected {
            assert!(samples
                .iter()
                .any(
                    |(bytes, info, version)| info.instance_handle.0 == value.compute_key()
                        && KeyedState::decode(bytes, *version).unwrap() == *value
                ));
        }
        let mut values = Vec::new();
        while let Some(value) = typed.take().unwrap() {
            values.push(value);
        }
        assert_eq!(values.len(), 2);
        assert!(expected.iter().all(|value| values.contains(value)));

        // DDS v1.4 Sec.2.2.3.4/2.2.3.21: retiring a replay writer must
        // not dispose the original application's durable instances.
        drop(publisher);
        let mut unregistered = 0;
        while let Some((value, info)) = typed.take_with_info().unwrap() {
            assert!(value.is_none());
            assert_eq!(
                info.instance_state,
                hdds::api::InstanceState::NotAliveNoWriters
            );
            unregistered += 1;
        }
        assert_eq!(unregistered, 2);
    }

    #[tokio::test]
    async fn test_skip_volatile_readers() {
        let config = Config::builder().topic_filter("*").build();

        let store = SqliteStore::new_in_memory().unwrap();
        let store = Arc::new(RwLock::new(store));
        let dds = Arc::new(MockDdsInterface::new());

        // Add a volatile reader
        dds.add_reader(DiscoveredReader {
            guid: [0x02; 16],
            topic: "test/topic".to_string(),
            type_name: "Test".to_string(),
            durability: DurabilityKind::Volatile,
        });

        let mut publisher = LateJoinerPublisher::new(config, store, dds);
        publisher.discover_and_replay().await.unwrap();

        // Reader was discovered but not replayed (because it's volatile)
        assert_eq!(publisher.stats.readers_discovered, 1);
        assert_eq!(publisher.stats.readers_replayed, 0);
    }

    #[tokio::test]
    async fn test_standalone_publisher() {
        let config = Config::builder().topic_filter("*").build();

        let store = SqliteStore::new_in_memory().unwrap();

        // Add samples
        for i in 0..3 {
            let sample = Sample {
                topic: "test/topic".to_string(),
                type_name: "Test".to_string(),
                payload: vec![i as u8],
                timestamp_ns: i * 1000,
                sequence: i,
                source_guid: [0xBB; 16],
                source_timestamp_ns: None,
                destination_order_by_source: false,
                representation: 0,
                instance_handle: [0u8; 16],
            };
            store.save(&sample).unwrap();
        }

        let store = Arc::new(RwLock::new(store));

        let replayed_samples = Arc::new(std::sync::Mutex::new(Vec::new()));
        let replayed_clone = Arc::clone(&replayed_samples);

        let mut publisher = StandalonePublisher::new(config, store).on_replay(move |sample| {
            replayed_clone.lock().unwrap().push(sample.sequence);
        });

        let count = publisher.replay_all().await.unwrap();
        assert_eq!(count, 3);

        let replayed = replayed_samples.lock().unwrap();
        assert_eq!(replayed.len(), 3);
        assert!(replayed.contains(&0));
        assert!(replayed.contains(&1));
        assert!(replayed.contains(&2));
    }

    #[tokio::test]
    async fn test_replay_range() {
        let config = Config::builder().topic_filter("*").build();

        let store = SqliteStore::new_in_memory().unwrap();

        // Add samples at different times
        for i in 0..10 {
            let sample = Sample {
                topic: "test/topic".to_string(),
                type_name: "Test".to_string(),
                payload: vec![i as u8],
                timestamp_ns: i * 1000,
                sequence: i,
                source_guid: [0xCC; 16],
                source_timestamp_ns: None,
                destination_order_by_source: false,
                representation: 0,
                instance_handle: [0u8; 16],
            };
            store.save(&sample).unwrap();
        }

        let store = Arc::new(RwLock::new(store));

        let mut publisher = StandalonePublisher::new(config, store);

        // Replay only samples in range [2000, 5000]
        let count = publisher
            .replay_range("test/topic", 2000, 5000)
            .await
            .unwrap();
        assert_eq!(count, 4); // Samples at 2000, 3000, 4000, 5000
    }

    #[test]
    fn test_hex() {
        assert_eq!(hex(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
        assert_eq!(hex(&[0x01, 0x02]), "0102");
    }
}
