// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Durability subscriber
//!
//! Subscribes to TRANSIENT/PERSISTENT topics and stores samples.
//!
//! # Operation
//!
//! 1. Discover writers matching topic filter
//! 2. Create DataReaders for each matching topic
//! 3. Poll readers and store received samples
//! 4. Apply retention policy periodically

use crate::config::Config;
use crate::dds_interface::{
    DataReader, DdsInterface, DiscoveredReader, DiscoveredWriter, DiscoveryCallback,
};
use crate::store::{PersistenceStore, RetentionPolicy, Sample};
use anyhow::Result;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::sync::RwLock;
use tokio::time::interval;

/// Durability subscriber
///
/// Subscribes to topics matching the filter and persists all received samples.
pub struct DurabilitySubscriber<S: PersistenceStore, D: DdsInterface> {
    config: Config,
    store: Arc<RwLock<S>>,
    dds: Arc<D>,
    /// Active readers by topic
    readers: HashMap<String, Box<dyn DataReader>>,
    /// Known writers (to detect new ones)
    known_writers: HashSet<[u8; 16]>,
    /// Topics we've created readers for
    subscribed_topics: HashSet<String>,
    /// Per-topic retention hint derived from writer durability settings.
    retention_hints: HashMap<String, usize>,
    /// Statistics
    stats: SubscriberStats,
}

/// Subscriber statistics
#[derive(Debug, Default, Clone)]
pub struct SubscriberStats {
    /// Total samples received
    pub samples_received: u64,
    /// Total samples stored
    pub samples_stored: u64,
    /// Storage errors
    pub storage_errors: u64,
    /// Writers discovered
    pub writers_discovered: u64,
    /// Topics subscribed
    pub topics_subscribed: u64,
}

#[allow(dead_code)]
enum DiscoveryEvent {
    Writer(DiscoveredWriter),
    Reader(DiscoveredReader),
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

impl<S: PersistenceStore + Send + Sync, D: DdsInterface> DurabilitySubscriber<S, D> {
    /// Create a new durability subscriber
    pub fn new(config: Config, store: Arc<RwLock<S>>, dds: Arc<D>) -> Self {
        Self {
            config,
            store,
            dds,
            readers: HashMap::new(),
            known_writers: HashSet::new(),
            subscribed_topics: HashSet::new(),
            retention_hints: HashMap::new(),
            stats: SubscriberStats::default(),
        }
    }

    /// Get subscriber statistics
    pub fn stats(&self) -> &SubscriberStats {
        &self.stats
    }

    /// Run the subscriber
    pub async fn run(mut self) -> Result<()> {
        tracing::info!(
            "DurabilitySubscriber started for topics: {}",
            self.config.topic_filter
        );

        let (event_tx, mut event_rx) = mpsc::channel(128);
        let bridge = Arc::new(DiscoveryBridge { tx: event_tx });
        self.dds.register_discovery_callback(bridge)?;

        // Initial snapshot
        self.discover_and_subscribe().await?;

        // Polling intervals
        let mut sample_interval = interval(Duration::from_millis(100));
        let mut retention_interval = interval(Duration::from_secs(60));

        loop {
            tokio::select! {
                // Poll for samples (high frequency)
                _ = sample_interval.tick() => {
                    self.poll_samples().await?;
                }
                Some(event) = event_rx.recv() => {
                    if let DiscoveryEvent::Writer(writer) = event {
                        self.handle_writer_discovered(writer)?;
                    }
                }

                // Apply retention policy (low frequency)
                _ = retention_interval.tick() => {
                    self.apply_retention().await?;
                }
            }
        }
    }

    /// Discover writers and create readers for matching topics
    async fn discover_and_subscribe(&mut self) -> Result<()> {
        let writers = self.dds.discovered_writers(&self.config.topic_filter)?;

        for writer in writers {
            self.handle_writer_discovered(writer)?;
        }

        Ok(())
    }

    fn handle_writer_discovered(&mut self, writer: DiscoveredWriter) -> Result<()> {
        // Skip if we already know this writer
        if self.known_writers.contains(&writer.guid) {
            return Ok(());
        }

        // Only subscribe to durable writers
        if !writer.durability.is_durable() && !self.config.subscribe_volatile {
            tracing::debug!("Skipping volatile writer for topic {}", writer.topic);
            return Ok(());
        }

        self.known_writers.insert(writer.guid);
        self.stats.writers_discovered += 1;

        tracing::info!(
            "Discovered writer for topic: {} (type: {})",
            writer.topic,
            writer.type_name
        );

        if let Some(hint) = writer.retention_hint {
            self.update_retention_hint(&writer.topic, hint);
        }

        // Create reader if we haven't already
        if !self.subscribed_topics.contains(&writer.topic) {
            self.create_reader_for_topic(&writer)?;
        }

        Ok(())
    }

    /// Create a DataReader for a topic
    fn create_reader_for_topic(&mut self, writer: &DiscoveredWriter) -> Result<()> {
        let reader = self
            .dds
            .create_reader(&writer.topic, &writer.type_name, writer.durability)?;

        tracing::info!(
            "Created reader for topic: {} (type: {})",
            writer.topic,
            writer.type_name
        );

        self.readers.insert(writer.topic.clone(), reader);
        self.subscribed_topics.insert(writer.topic.clone());
        self.stats.topics_subscribed += 1;

        Ok(())
    }

    /// Poll all readers for new samples
    async fn poll_samples(&mut self) -> Result<()> {
        let store = self.store.read().await;

        for (topic, reader) in &self.readers {
            // Take samples (removes from reader cache)
            match reader.take() {
                Ok(samples) => {
                    for received in samples {
                        self.stats.samples_received += 1;

                        let sample = Sample {
                            topic: received.topic,
                            type_name: received.type_name,
                            payload: received.payload,
                            timestamp_ns: received.timestamp_ns,
                            sequence: received.sequence,
                            source_guid: received.writer_guid,
                        };

                        match store.save(&sample) {
                            Ok(()) => {
                                self.stats.samples_stored += 1;
                                tracing::trace!(
                                    "Stored sample: topic={}, seq={}",
                                    sample.topic,
                                    sample.sequence
                                );
                            }
                            Err(e) => {
                                self.stats.storage_errors += 1;
                                tracing::error!("Failed to store sample for {}: {}", topic, e);
                            }
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("Failed to take samples from {}: {}", topic, e);
                }
            }
        }

        Ok(())
    }

    /// Apply retention policy to all topics
    async fn apply_retention(&self) -> Result<()> {
        let store = self.store.read().await;

        for topic in &self.subscribed_topics {
            let policy = self.retention_policy_for_topic(topic);
            if policy.is_noop() {
                continue;
            }
            if let Err(e) = store.apply_retention_policy(topic, &policy) {
                tracing::warn!("Failed to apply retention to {}: {}", topic, e);
            }
        }

        tracing::debug!(
            "Applied retention policy ({} samples) to {} topics",
            self.config.retention_count,
            self.subscribed_topics.len()
        );

        Ok(())
    }

    fn retention_policy_for_topic(&self, topic: &str) -> RetentionPolicy {
        let mut policy = RetentionPolicy {
            keep_count: self.config.retention_count,
            max_age_ns: if self.config.retention_time_secs > 0 {
                Some(
                    self.config
                        .retention_time_secs
                        .saturating_mul(1_000_000_000),
                )
            } else {
                None
            },
            max_bytes: if self.config.retention_size_bytes > 0 {
                Some(self.config.retention_size_bytes)
            } else {
                None
            },
        };

        if let Some(keep_hint) = self.retention_hints.get(topic).copied() {
            if keep_hint > 0 {
                if policy.keep_count == 0 {
                    policy.keep_count = keep_hint;
                } else {
                    policy.keep_count = policy.keep_count.min(keep_hint);
                }
            }
        }

        policy
    }

    fn update_retention_hint(&mut self, topic: &str, hint: RetentionPolicy) {
        if hint.keep_count == 0 {
            return;
        }

        let entry = self
            .retention_hints
            .entry(topic.to_string())
            .or_insert(hint.keep_count);
        *entry = (*entry).max(hint.keep_count);
    }
}

// ============================================================================
// Standalone mode (without DDS - for testing and CLI)
// ============================================================================

/// Standalone durability subscriber that accepts samples via channel
pub struct StandaloneSubscriber<S: PersistenceStore> {
    config: Config,
    store: Arc<RwLock<S>>,
    rx: tokio::sync::mpsc::Receiver<Sample>,
    stats: SubscriberStats,
}

impl<S: PersistenceStore + Send + Sync> StandaloneSubscriber<S> {
    /// Create a new standalone subscriber
    ///
    /// Returns the subscriber and a sender for pushing samples.
    pub fn new(config: Config, store: Arc<RwLock<S>>) -> (Self, tokio::sync::mpsc::Sender<Sample>) {
        let (tx, rx) = tokio::sync::mpsc::channel(1000);

        let subscriber = Self {
            config,
            store,
            rx,
            stats: SubscriberStats::default(),
        };

        (subscriber, tx)
    }

    /// Get statistics
    pub fn stats(&self) -> &SubscriberStats {
        &self.stats
    }

    /// Run the standalone subscriber
    pub async fn run(mut self) -> Result<()> {
        tracing::info!(
            "StandaloneSubscriber started for topics: {}",
            self.config.topic_filter
        );

        let mut retention_interval = interval(Duration::from_secs(60));

        loop {
            tokio::select! {
                // Receive sample from channel
                Some(sample) = self.rx.recv() => {
                    self.stats.samples_received += 1;

                    // Check if topic matches filter
                    if !topic_matches(&self.config.topic_filter, &sample.topic) {
                        continue;
                    }

                    let store = self.store.read().await;
                    match store.save(&sample) {
                        Ok(()) => {
                            self.stats.samples_stored += 1;
                            tracing::trace!(
                                "Stored sample: topic={}, seq={}",
                                sample.topic,
                                sample.sequence
                            );
                        }
                        Err(e) => {
                            self.stats.storage_errors += 1;
                            tracing::error!("Failed to store sample: {}", e);
                        }
                    }
                }

                // Apply retention
                _ = retention_interval.tick() => {
                    self.apply_retention().await?;
                }

                else => break,
            }
        }

        Ok(())
    }

    /// Apply retention policy
    async fn apply_retention(&self) -> Result<()> {
        let policy = RetentionPolicy {
            keep_count: self.config.retention_count,
            max_age_ns: if self.config.retention_time_secs > 0 {
                Some(
                    self.config
                        .retention_time_secs
                        .saturating_mul(1_000_000_000),
                )
            } else {
                None
            },
            max_bytes: if self.config.retention_size_bytes > 0 {
                Some(self.config.retention_size_bytes)
            } else {
                None
            },
        };
        if policy.is_noop() {
            return Ok(());
        }

        let store = self.store.read().await;

        // Get unique topics from store
        let all_samples = store.query_range("*", 0, u64::MAX)?;
        let topics: HashSet<_> = all_samples.iter().map(|s| s.topic.clone()).collect();

        for topic in &topics {
            if let Err(e) = store.apply_retention_policy(topic, &policy) {
                tracing::warn!("Failed to apply retention to {}: {}", topic, e);
            }
        }

        Ok(())
    }
}

/// Check if a topic matches a pattern
fn topic_matches(pattern: &str, topic: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix("/*") {
        return topic.starts_with(prefix) && topic.len() > prefix.len();
    }
    pattern == topic
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dds_interface::MockDdsInterface;
    use crate::sqlite::SqliteStore;

    #[test]
    fn test_topic_matches() {
        assert!(topic_matches("*", "any/topic"));
        assert!(topic_matches("State/*", "State/Temperature"));
        assert!(!topic_matches("State/*", "Command/Set"));
        assert!(topic_matches("exact", "exact"));
        assert!(!topic_matches("exact", "other"));
    }

    #[tokio::test]
    async fn test_standalone_subscriber() {
        let config = Config::builder()
            .topic_filter("State/*")
            .retention_count(100)
            .build();

        let store = SqliteStore::new_in_memory().unwrap();
        let store = Arc::new(RwLock::new(store));

        let (subscriber, tx) = StandaloneSubscriber::new(config, Arc::clone(&store));

        // Send a sample
        let sample = Sample {
            topic: "State/Temperature".to_string(),
            type_name: "Temperature".to_string(),
            payload: vec![1, 2, 3],
            timestamp_ns: 1000,
            sequence: 1,
            source_guid: [0xAA; 16],
        };

        tx.send(sample).await.unwrap();

        // Run subscriber briefly
        let handle = tokio::spawn(async move {
            tokio::time::timeout(Duration::from_millis(200), subscriber.run()).await
        });

        // Wait a bit then drop sender to stop subscriber
        tokio::time::sleep(Duration::from_millis(100)).await;
        drop(tx);

        let _ = handle.await;

        // Verify sample was stored
        let store = store.read().await;
        let samples = store.load("State/Temperature").unwrap();
        assert_eq!(samples.len(), 1);
        assert_eq!(samples[0].sequence, 1);
    }

    #[test]
    fn test_durability_subscriber_creation() {
        let config = Config::builder()
            .topic_filter("State/*")
            .retention_count(100)
            .build();

        let store = SqliteStore::new_in_memory().unwrap();
        let store = Arc::new(RwLock::new(store));

        let dds = Arc::new(MockDdsInterface::new());

        let subscriber = DurabilitySubscriber::new(config, store, dds);
        assert_eq!(subscriber.stats.samples_received, 0);
    }

    #[tokio::test]
    async fn test_discover_and_subscribe() {
        use crate::dds_interface::{DiscoveredWriter, DurabilityKind};

        let config = Config::builder()
            .topic_filter("State/*")
            .subscribe_volatile(true)
            .build();

        let store = SqliteStore::new_in_memory().unwrap();
        let store = Arc::new(RwLock::new(store));

        let dds = Arc::new(MockDdsInterface::new());

        // Add a mock writer
        dds.add_writer(DiscoveredWriter {
            guid: [0x01; 16],
            topic: "State/Temperature".to_string(),
            type_name: "Temperature".to_string(),
            durability: DurabilityKind::TransientLocal,
            retention_hint: None,
        });

        let mut subscriber = DurabilitySubscriber::new(config, store, dds);

        // Run discovery
        subscriber.discover_and_subscribe().await.unwrap();

        assert_eq!(subscriber.stats.writers_discovered, 1);
        assert_eq!(subscriber.stats.topics_subscribed, 1);
        assert!(subscriber.subscribed_topics.contains("State/Temperature"));
    }
}
