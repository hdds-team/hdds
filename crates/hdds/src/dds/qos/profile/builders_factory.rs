// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! QoS builder methods for factory policies (entity factory, lifecycle).

use super::super::{
    entity::EntityFactory,
    lifecycle::{ReaderDataLifecycle, WriterDataLifecycle},
    reliability::DurabilityService,
};
use super::structs::QoS;

impl QoS {
    /// Set ENTITY_FACTORY policy (v0.7.0+).
    ///
    /// Controls whether entities are automatically enabled when created.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use hdds::api::{QoS, EntityFactory};
    ///
    /// // Auto-enable entities (default)
    /// let qos = QoS::best_effort().entity_factory(EntityFactory::auto_enable());
    ///
    /// // Manual enable (entities created disabled)
    /// let qos_manual = QoS::best_effort().entity_factory(EntityFactory::manual_enable());
    /// ```
    pub fn entity_factory(mut self, factory: EntityFactory) -> Self {
        self.entity_factory = factory;
        self
    }

    /// Set ENTITY_FACTORY to auto-enable (default).
    ///
    /// Entities are automatically enabled when created.
    pub fn entity_factory_auto_enable(mut self) -> Self {
        self.entity_factory = EntityFactory::auto_enable();
        self
    }

    /// Set ENTITY_FACTORY to manual enable.
    ///
    /// Entities are created disabled and must be explicitly enabled.
    pub fn entity_factory_manual_enable(mut self) -> Self {
        self.entity_factory = EntityFactory::manual_enable();
        self
    }

    /// Set WRITER_DATA_LIFECYCLE policy (v0.7.0+).
    ///
    /// Controls automatic disposal of unregistered instances.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use hdds::api::{QoS, WriterDataLifecycle};
    ///
    /// // Auto-dispose unregistered instances (default)
    /// let qos = QoS::best_effort().writer_data_lifecycle(WriterDataLifecycle::auto_dispose());
    ///
    /// // Manual dispose (keep instances alive after unregister)
    /// let qos_manual = QoS::best_effort().writer_data_lifecycle(WriterDataLifecycle::manual_dispose());
    /// ```
    pub fn writer_data_lifecycle(mut self, lifecycle: WriterDataLifecycle) -> Self {
        self.writer_data_lifecycle = lifecycle;
        self
    }

    /// Set WRITER_DATA_LIFECYCLE to auto-dispose (default).
    ///
    /// Unregistered instances are automatically disposed.
    pub fn writer_data_lifecycle_auto_dispose(mut self) -> Self {
        self.writer_data_lifecycle = WriterDataLifecycle::auto_dispose();
        self
    }

    /// Set WRITER_DATA_LIFECYCLE to manual dispose.
    ///
    /// Unregistered instances remain alive until explicitly disposed.
    pub fn writer_data_lifecycle_manual_dispose(mut self) -> Self {
        self.writer_data_lifecycle = WriterDataLifecycle::manual_dispose();
        self
    }

    /// Set READER_DATA_LIFECYCLE QoS.
    ///
    /// Controls automatic purging of reader instances.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use hdds::api::{QoS, ReaderDataLifecycle};
    ///
    /// // Keep all instances indefinitely (default)
    /// let qos = QoS::best_effort().reader_data_lifecycle(ReaderDataLifecycle::keep_all());
    ///
    /// // Immediate cleanup
    /// let qos_cleanup = QoS::best_effort().reader_data_lifecycle(ReaderDataLifecycle::immediate_cleanup());
    ///
    /// // Custom delays (30 seconds)
    /// let qos_delay = QoS::best_effort().reader_data_lifecycle(ReaderDataLifecycle::from_secs(30, 30));
    /// ```
    pub fn reader_data_lifecycle(mut self, lifecycle: ReaderDataLifecycle) -> Self {
        self.reader_data_lifecycle = lifecycle;
        self
    }

    /// Set READER_DATA_LIFECYCLE to keep all instances indefinitely (default).
    ///
    /// Instances are never purged, even after all writers are gone or disposed.
    pub fn reader_data_lifecycle_keep_all(mut self) -> Self {
        self.reader_data_lifecycle = ReaderDataLifecycle::keep_all();
        self
    }

    /// Set READER_DATA_LIFECYCLE to immediate cleanup.
    ///
    /// Instances are purged as soon as they become NOT_ALIVE.
    pub fn reader_data_lifecycle_immediate_cleanup(mut self) -> Self {
        self.reader_data_lifecycle = ReaderDataLifecycle::immediate_cleanup();
        self
    }

    /// Set READER_DATA_LIFECYCLE with delays in seconds.
    ///
    /// # Arguments
    ///
    /// * `nowriter_delay_secs` - Delay before purging NOT_ALIVE_NO_WRITERS instances
    /// * `disposed_delay_secs` - Delay before purging NOT_ALIVE_DISPOSED instances
    pub fn reader_data_lifecycle_secs(
        mut self,
        nowriter_delay_secs: u32,
        disposed_delay_secs: u32,
    ) -> Self {
        self.reader_data_lifecycle =
            ReaderDataLifecycle::from_secs(nowriter_delay_secs, disposed_delay_secs);
        self
    }

    /// Set DURABILITY_SERVICE QoS.
    ///
    /// Configures history cache for TRANSIENT_LOCAL/PERSISTENT durability.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use hdds::api::{QoS, DurabilityService};
    ///
    /// // Keep last 100 samples for late-joiners
    /// let qos = QoS::best_effort()
    ///     .transient_local()
    ///     .durability_service(DurabilityService::keep_last(100, 1000, 10, 100));
    ///
    /// // With cleanup delay
    /// let qos_delay = QoS::reliable()
    ///     .transient_local()
    ///     .durability_service(DurabilityService::with_cleanup_delay_secs(60));
    /// ```
    pub fn durability_service(mut self, service: DurabilityService) -> Self {
        self.durability_service = service;
        self
    }

    /// Set DURABILITY_SERVICE for late-joiner support (KEEP_LAST).
    ///
    /// # Arguments
    ///
    /// * `history_depth` - Number of samples to keep (KEEP_LAST depth)
    /// * `max_samples` - Maximum total samples in history cache
    /// * `max_instances` - Maximum instances in history cache
    /// * `max_samples_per_instance` - Maximum samples per instance
    pub fn durability_service_keep_last(
        mut self,
        history_depth: u32,
        max_samples: i32,
        max_instances: i32,
        max_samples_per_instance: i32,
    ) -> Self {
        self.durability_service = DurabilityService::keep_last(
            history_depth,
            max_samples,
            max_instances,
            max_samples_per_instance,
        );
        self
    }

    /// Set DURABILITY_SERVICE with cleanup delay.
    ///
    /// # Arguments
    ///
    /// * `cleanup_delay_secs` - Cleanup delay in seconds.
    pub fn durability_service_cleanup_delay_secs(mut self, cleanup_delay_secs: u32) -> Self {
        self.durability_service = DurabilityService::with_cleanup_delay_secs(cleanup_delay_secs);
        self
    }
}
