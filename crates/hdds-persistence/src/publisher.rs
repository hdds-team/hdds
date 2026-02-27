// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Late-joiner publisher
//!
//! Detects new readers and replays historical samples.
//!
//! # Operation
//!
//! 1. Monitor for new DataReaders via discovery
//! 2. When a TRANSIENT_LOCAL reader joins, query store for historical samples
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
    /// Writers we've created (by topic)
    writers: HashMap<String, WriterState>,
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
            DurabilityKind::Persistent => {}
        }

        let writers = self.dds.discovered_writers(&reader.topic)?;
        let has_viable_writer = writers
            .iter()
            .any(|writer| writer.durability.rank() >= reader.durability.rank());

        if has_viable_writer {
            tracing::debug!(
                "Skipping persistence replay for topic {} (durable writer present)",
                reader.topic
            );
            return Ok(false);
        }

        Ok(true)
    }

    /// Replay historical samples to a specific reader
    async fn replay_to_reader(&mut self, reader: &DiscoveredReader) -> Result<usize> {
        // Query store for historical samples first
        let samples = {
            let store = self.store.read().await;
            store.query_range(&reader.topic, 0, u64::MAX)?
        };

        if samples.is_empty() {
            tracing::debug!("No historical samples for topic {}", reader.topic);
            return Ok(0);
        }

        // Get or create writer for this topic
        let writer =
            self.get_or_create_writer(&reader.topic, &reader.type_name, reader.durability)?;

        // Replay samples in order
        let mut replayed = 0;
        for sample in &samples {
            match writer.write_with_timestamp(&sample.payload, sample.timestamp_ns) {
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

    /// Get or create a DataWriter for a topic
    fn get_or_create_writer(
        &mut self,
        topic: &str,
        type_name: &str,
        durability: DurabilityKind,
    ) -> Result<&dyn DataWriter> {
        let entry = self.writers.entry(topic.to_string());
        let state = match entry {
            std::collections::hash_map::Entry::Vacant(slot) => {
                let writer = self.dds.create_writer(topic, type_name, durability)?;
                tracing::info!(
                    "Created writer for topic: {} (durability={:?})",
                    topic,
                    durability
                );
                slot.insert(WriterState { durability, writer })
            }
            std::collections::hash_map::Entry::Occupied(mut slot) => {
                if slot.get().durability.rank() < durability.rank() {
                    let writer = self.dds.create_writer(topic, type_name, durability)?;
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

        // Get or create writer
        let writer = self.get_or_create_writer(topic, type_name, DurabilityKind::TransientLocal)?;

        let mut replayed = 0;
        for sample in &samples {
            if writer
                .write_with_timestamp(&sample.payload, sample.timestamp_ns)
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
