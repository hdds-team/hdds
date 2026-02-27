// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Route definition and statistics.

use crate::config::{RouteConfig, TopicSelection};
use crate::transform::{QosTransform, TopicTransform};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

/// A routing path between two DDS domains.
#[derive(Debug)]
pub struct Route {
    /// Source domain ID.
    pub from_domain: u32,

    /// Destination domain ID.
    pub to_domain: u32,

    /// Topic selection filter.
    pub topics: TopicSelection,

    /// Topic name transformer.
    pub topic_transform: TopicTransform,

    /// QoS transformer.
    pub qos_transform: QosTransform,

    /// Route statistics.
    pub stats: Arc<RouteStats>,
}

impl Route {
    /// Create a route from configuration.
    pub fn from_config(config: &RouteConfig) -> Self {
        Self {
            from_domain: config.from_domain,
            to_domain: config.to_domain,
            topics: config.topics.clone(),
            topic_transform: TopicTransform::new(config.remaps.clone()),
            qos_transform: QosTransform::new(config.qos_transform.clone()),
            stats: Arc::new(RouteStats::new(config.from_domain, config.to_domain)),
        }
    }

    /// Check if this route handles a given topic.
    pub fn matches_topic(&self, topic: &str) -> bool {
        self.topics.matches(topic)
    }

    /// Transform a topic name for routing.
    pub fn transform_topic(&self, topic: &str) -> String {
        self.topic_transform.transform(topic)
    }

    /// Record a routed message.
    pub fn record_message(&self, bytes: u64) {
        self.stats.messages_routed.fetch_add(1, Ordering::Relaxed);
        self.stats.bytes_routed.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Record a dropped message.
    pub fn record_dropped(&self) {
        self.stats.messages_dropped.fetch_add(1, Ordering::Relaxed);
    }

    /// Record an error.
    pub fn record_error(&self) {
        self.stats.errors.fetch_add(1, Ordering::Relaxed);
    }
}

/// Statistics for a route.
#[derive(Debug)]
pub struct RouteStats {
    /// Source domain.
    pub from_domain: u32,

    /// Destination domain.
    pub to_domain: u32,

    /// Messages successfully routed.
    pub messages_routed: AtomicU64,

    /// Bytes routed.
    pub bytes_routed: AtomicU64,

    /// Messages dropped (filtered).
    pub messages_dropped: AtomicU64,

    /// Errors encountered.
    pub errors: AtomicU64,

    /// Route creation time.
    pub created: Instant,
}

impl RouteStats {
    /// Create new stats.
    pub fn new(from_domain: u32, to_domain: u32) -> Self {
        Self {
            from_domain,
            to_domain,
            messages_routed: AtomicU64::new(0),
            bytes_routed: AtomicU64::new(0),
            messages_dropped: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            created: Instant::now(),
        }
    }

    /// Get snapshot of current stats.
    pub fn snapshot(&self) -> RouteStatsSnapshot {
        RouteStatsSnapshot {
            from_domain: self.from_domain,
            to_domain: self.to_domain,
            messages_routed: self.messages_routed.load(Ordering::Relaxed),
            bytes_routed: self.bytes_routed.load(Ordering::Relaxed),
            messages_dropped: self.messages_dropped.load(Ordering::Relaxed),
            errors: self.errors.load(Ordering::Relaxed),
            uptime_secs: self.created.elapsed().as_secs(),
        }
    }
}

/// Snapshot of route statistics.
#[derive(Debug, Clone)]
pub struct RouteStatsSnapshot {
    pub from_domain: u32,
    pub to_domain: u32,
    pub messages_routed: u64,
    pub bytes_routed: u64,
    pub messages_dropped: u64,
    pub errors: u64,
    pub uptime_secs: u64,
}

impl RouteStatsSnapshot {
    /// Calculate messages per second.
    pub fn messages_per_second(&self) -> f64 {
        if self.uptime_secs > 0 {
            self.messages_routed as f64 / self.uptime_secs as f64
        } else {
            0.0
        }
    }

    /// Calculate bytes per second.
    pub fn bytes_per_second(&self) -> f64 {
        if self.uptime_secs > 0 {
            self.bytes_routed as f64 / self.uptime_secs as f64
        } else {
            0.0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_route_from_config() {
        let config = RouteConfig::new(0, 1)
            .topics(TopicSelection::Include(vec!["Temperature".into()]))
            .remap("Temperature", "Vehicle/Temperature");

        let route = Route::from_config(&config);

        assert_eq!(route.from_domain, 0);
        assert_eq!(route.to_domain, 1);
        assert!(route.matches_topic("Temperature"));
        assert!(!route.matches_topic("Pressure"));
    }

    #[test]
    fn test_route_transform_topic() {
        let config = RouteConfig::new(0, 1).remap("Temperature", "Vehicle/Temperature");

        let route = Route::from_config(&config);

        assert_eq!(route.transform_topic("Temperature"), "Vehicle/Temperature");
        assert_eq!(route.transform_topic("Pressure"), "Pressure");
    }

    #[test]
    fn test_route_stats() {
        let route = Route::from_config(&RouteConfig::new(0, 1));

        route.record_message(100);
        route.record_message(200);
        route.record_dropped();
        route.record_error();

        let snapshot = route.stats.snapshot();
        assert_eq!(snapshot.messages_routed, 2);
        assert_eq!(snapshot.bytes_routed, 300);
        assert_eq!(snapshot.messages_dropped, 1);
        assert_eq!(snapshot.errors, 1);
    }
}
