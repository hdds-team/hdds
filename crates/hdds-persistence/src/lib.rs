// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! HDDS Persistence Service
//!
//! Provides TRANSIENT and PERSISTENT durability QoS support for DDS topics.
//!
//! # Features
//!
//! - **SQLite Backend** -- Zero-dependency, production-ready persistent storage
//! - **RocksDB Backend** -- High-performance embedded database (feature flag)
//! - **Late-joiner Support** -- Replay historical samples to new readers
//! - **Retention Policies** -- Time-based, count-based, and size-based limits
//!
//! # Architecture
//!
//! ```text
//! PersistenceService
//! +-- DurabilitySubscriber  (listens to TRANSIENT/PERSISTENT topics)
//! +-- LateJoinerPublisher   (replays history to new readers)
//! +-- PersistenceStore      (SQLite or RocksDB backend)
//! ```
//!
//! # Example
//!
//! ```ignore
//! use hdds_persistence::{PersistenceService, Config, SqliteStore};
//!
//! let config = Config::builder()
//!     .topic_filter("State/*")
//!     .retention_count(1000)
//!     .build();
//!
//! let store = SqliteStore::new("hdds_persist.db")?;
//! let service = PersistenceService::new(config, store);
//! service.run().await?;
//! ```

pub mod config;
pub mod dds_interface;
pub mod hdds_interface;
pub mod publisher;
pub mod sqlite;
pub mod store;
pub mod subscriber;

pub use config::Config;
pub use dds_interface::{
    DataReader, DataWriter, DdsInterface, DiscoveredReader, DiscoveredWriter, DurabilityKind,
    MockDdsInterface, ReceivedSample,
};
pub use hdds_interface::HddsDdsInterface;
pub use publisher::{LateJoinerPublisher, PublisherStats, StandalonePublisher};
pub use sqlite::SqliteStore;
pub use store::{PersistenceStore, Sample};
pub use subscriber::{DurabilitySubscriber, StandaloneSubscriber, SubscriberStats};

use anyhow::Result;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Persistence Service
///
/// Combines durability subscriber and late-joiner publisher to provide
/// TRANSIENT/PERSISTENT QoS support.
///
/// # Type Parameters
///
/// - `S` -- Storage backend (e.g., `SqliteStore`)
/// - `D` -- DDS interface implementation
pub struct PersistenceService<S: PersistenceStore, D: DdsInterface> {
    config: Config,
    store: Arc<RwLock<S>>,
    dds: Arc<D>,
}

impl<S: PersistenceStore + Send + Sync + 'static, D: DdsInterface + 'static>
    PersistenceService<S, D>
{
    /// Create a new persistence service
    pub fn new(config: Config, store: S, dds: D) -> Self {
        Self {
            config,
            store: Arc::new(RwLock::new(store)),
            dds: Arc::new(dds),
        }
    }

    /// Run the persistence service
    ///
    /// Starts durability subscriber and late-joiner publisher in parallel.
    pub async fn run(self) -> Result<()> {
        tracing::info!("Starting HDDS Persistence Service");
        tracing::info!("  Topics: {}", self.config.topic_filter);
        tracing::info!("  Retention: {} samples", self.config.retention_count);

        let subscriber = DurabilitySubscriber::new(
            self.config.clone(),
            Arc::clone(&self.store),
            Arc::clone(&self.dds),
        );

        let publisher = LateJoinerPublisher::new(
            self.config.clone(),
            Arc::clone(&self.store),
            Arc::clone(&self.dds),
        );

        // Run subscriber and publisher concurrently
        tokio::try_join!(subscriber.run(), publisher.run(),)?;

        Ok(())
    }
}

/// Standalone Persistence Service (without real DDS)
///
/// Uses channels for sample input/output, useful for testing and CLI tools.
pub struct StandalonePersistenceService<S: PersistenceStore> {
    config: Config,
    store: Arc<RwLock<S>>,
}

impl<S: PersistenceStore + Send + Sync + 'static> StandalonePersistenceService<S> {
    /// Create a new standalone persistence service
    pub fn new(config: Config, store: S) -> Self {
        Self {
            config,
            store: Arc::new(RwLock::new(store)),
        }
    }

    /// Get the store for direct access
    pub fn store(&self) -> Arc<RwLock<S>> {
        Arc::clone(&self.store)
    }

    /// Create a subscriber that accepts samples via channel
    pub fn create_subscriber(
        &self,
    ) -> (StandaloneSubscriber<S>, tokio::sync::mpsc::Sender<Sample>) {
        StandaloneSubscriber::new(self.config.clone(), Arc::clone(&self.store))
    }

    /// Create a publisher that replays via callback
    pub fn create_publisher(&self) -> StandalonePublisher<S> {
        StandalonePublisher::new(self.config.clone(), Arc::clone(&self.store))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_persistence_service_creation() {
        let config = Config::builder()
            .topic_filter("test/*")
            .retention_count(100)
            .build();

        let store = SqliteStore::new_in_memory().unwrap();
        let dds = MockDdsInterface::new();
        let _service = PersistenceService::new(config, store, dds);
    }

    #[test]
    fn test_standalone_service() {
        let config = Config::builder().topic_filter("State/*").build();

        let store = SqliteStore::new_in_memory().unwrap();
        let service = StandalonePersistenceService::new(config, store);

        let (_subscriber, _tx) = service.create_subscriber();
        let _publisher = service.create_publisher();
    }
}
