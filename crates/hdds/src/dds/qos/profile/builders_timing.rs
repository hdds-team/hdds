// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! QoS builder methods for timing policies (deadline, latency, lifespan).

use super::super::{
    ordering::{DestinationOrder, Presentation},
    transport::TransportPriority,
    Deadline, LatencyBudget, Lifespan, TimeBasedFilter,
};
use super::structs::QoS;

impl QoS {
    /// Set deadline period (v0.5.0+).
    ///
    /// Specifies maximum time between samples.
    /// Deadline violations trigger missed deadline events.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use hdds::api::QoS;
    ///
    /// // Expect samples every 100ms
    /// let qos = QoS::best_effort().deadline_millis(100);
    /// ```
    pub fn deadline(mut self, deadline: Deadline) -> Self {
        self.deadline = deadline;
        self
    }

    /// Set deadline from milliseconds.
    pub fn deadline_millis(mut self, ms: u64) -> Self {
        self.deadline = Deadline::from_millis(ms);
        self
    }

    /// Set deadline from seconds.
    pub fn deadline_secs(mut self, secs: u64) -> Self {
        self.deadline = Deadline::from_secs(secs);
        self
    }

    /// Set lifespan duration (v0.6.0+).
    ///
    /// Specifies maximum sample validity duration.
    /// Samples older than lifespan are expired and discarded.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use hdds::api::QoS;
    ///
    /// // Samples expire after 5 seconds
    /// let qos = QoS::best_effort().lifespan_secs(5);
    /// ```
    pub fn lifespan(mut self, lifespan: Lifespan) -> Self {
        self.lifespan = lifespan;
        self
    }

    /// Set lifespan from milliseconds.
    pub fn lifespan_millis(mut self, ms: u64) -> Self {
        self.lifespan = Lifespan::from_millis(ms);
        self
    }

    /// Set lifespan from seconds.
    pub fn lifespan_secs(mut self, secs: u64) -> Self {
        self.lifespan = Lifespan::from_secs(secs);
        self
    }

    /// Set TIME_BASED_FILTER minimum separation (v0.6.0+).
    ///
    /// Controls the minimum time between accepted samples.
    /// Samples arriving faster than this rate are discarded by the reader.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use hdds::api::QoS;
    ///
    /// // Accept samples at most every 100ms (10 Hz max)
    /// let qos = QoS::best_effort().time_based_filter_millis(100);
    /// ```
    pub fn time_based_filter(mut self, filter: TimeBasedFilter) -> Self {
        self.time_based_filter = filter;
        self
    }

    /// Set TIME_BASED_FILTER from milliseconds.
    pub fn time_based_filter_millis(mut self, ms: u64) -> Self {
        self.time_based_filter = TimeBasedFilter::from_millis(ms);
        self
    }

    /// Set TIME_BASED_FILTER from seconds.
    pub fn time_based_filter_secs(mut self, secs: u64) -> Self {
        self.time_based_filter = TimeBasedFilter::from_secs(secs);
        self
    }

    /// Set DESTINATION_ORDER policy (v0.6.0+).
    ///
    /// Controls the order in which samples are presented to the reader.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use hdds::api::{QoS, DestinationOrder};
    ///
    /// // Order by reception timestamp (default, fastest)
    /// let qos = QoS::best_effort().destination_order(DestinationOrder::by_reception_timestamp());
    ///
    /// // Order by source timestamp (temporal consistency)
    /// let qos_source = QoS::best_effort().destination_order(DestinationOrder::by_source_timestamp());
    /// ```
    pub fn destination_order(mut self, order: DestinationOrder) -> Self {
        self.destination_order = order;
        self
    }

    /// Set DESTINATION_ORDER to BY_RECEPTION_TIMESTAMP (default).
    pub fn destination_order_by_reception(mut self) -> Self {
        self.destination_order = DestinationOrder::by_reception_timestamp();
        self
    }

    /// Set DESTINATION_ORDER to BY_SOURCE_TIMESTAMP.
    pub fn destination_order_by_source(mut self) -> Self {
        self.destination_order = DestinationOrder::by_source_timestamp();
        self
    }

    /// Set PRESENTATION policy (v0.6.0+).
    ///
    /// Controls how data is presented to the reader, including access scope,
    /// coherent changes, and ordered access.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use hdds::api::{QoS, Presentation};
    ///
    /// // Instance-level access (default)
    /// let qos = QoS::best_effort().presentation(Presentation::instance());
    ///
    /// // Topic-level coherent access
    /// let qos_topic = QoS::best_effort().presentation(Presentation::topic_coherent());
    ///
    /// // Group-level coherent and ordered access
    /// let qos_group = QoS::best_effort().presentation(Presentation::group_coherent_ordered());
    /// ```
    pub fn presentation(mut self, presentation: Presentation) -> Self {
        self.presentation = presentation;
        self
    }

    /// Set PRESENTATION to INSTANCE scope (default).
    pub fn presentation_instance(mut self) -> Self {
        self.presentation = Presentation::instance();
        self
    }

    /// Set PRESENTATION to TOPIC scope with coherent access.
    pub fn presentation_topic_coherent(mut self) -> Self {
        self.presentation = Presentation::topic_coherent();
        self
    }

    /// Set PRESENTATION to TOPIC scope with ordered access.
    pub fn presentation_topic_ordered(mut self) -> Self {
        self.presentation = Presentation::topic_ordered();
        self
    }

    /// Set PRESENTATION to GROUP scope with coherent access.
    pub fn presentation_group_coherent(mut self) -> Self {
        self.presentation = Presentation::group_coherent();
        self
    }

    /// Set PRESENTATION to GROUP scope with coherent and ordered access.
    pub fn presentation_group_coherent_ordered(mut self) -> Self {
        self.presentation = Presentation::group_coherent_ordered();
        self
    }

    /// Set LATENCY_BUDGET policy (v0.6.0+).
    ///
    /// Provides a hint to the DDS implementation about the desired maximum delay
    /// from writing to receiving. This is used for transport optimisation.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use hdds::api::{QoS, LatencyBudget};
    ///
    /// // Critical data: 10ms latency budget
    /// let qos = QoS::best_effort().latency_budget(LatencyBudget::from_millis(10));
    ///
    /// // No specific latency requirement (default)
    /// let qos_default = QoS::best_effort().latency_budget(LatencyBudget::zero());
    /// ```
    pub fn latency_budget(mut self, budget: LatencyBudget) -> Self {
        self.latency_budget = budget;
        self
    }

    /// Set LATENCY_BUDGET from milliseconds.
    pub fn latency_budget_millis(mut self, ms: u64) -> Self {
        self.latency_budget = LatencyBudget::from_millis(ms);
        self
    }

    /// Set LATENCY_BUDGET from seconds.
    pub fn latency_budget_secs(mut self, secs: u64) -> Self {
        self.latency_budget = LatencyBudget::from_secs(secs);
        self
    }

    /// Set TRANSPORT_PRIORITY with custom value.
    ///
    /// Higher values indicate more important data.
    pub fn transport_priority(mut self, value: i32) -> Self {
        self.transport_priority = TransportPriority { value };
        self
    }

    /// Set TRANSPORT_PRIORITY to high priority.
    ///
    /// Convenience method for high-priority data (value: 50).
    pub fn transport_priority_high(mut self) -> Self {
        self.transport_priority = TransportPriority::high();
        self
    }

    /// Set TRANSPORT_PRIORITY to low priority.
    ///
    /// Convenience method for background/bulk data (value: -50).
    pub fn transport_priority_low(mut self) -> Self {
        self.transport_priority = TransportPriority::low();
        self
    }

    /// Set TRANSPORT_PRIORITY to normal priority.
    ///
    /// Convenience method for default priority (value: 0).
    pub fn transport_priority_normal(mut self) -> Self {
        self.transport_priority = TransportPriority::normal();
        self
    }
}
