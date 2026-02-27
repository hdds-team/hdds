// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Core router implementation.
//!
//! The Router manages DDS participants and routes messages between domains.

use crate::config::{RouteConfig, RouterConfig, TopicSelection};
use crate::route::{Route, RouteStats, RouteStatsSnapshot};
use crate::transform::{QosTransform, TopicTransform};
use hdds::dds::{
    Deadline, Durability as HddsDurability, History, Lifespan, QoS, Reliability as HddsReliability,
};
use hdds::{Participant, RawDataReader, RawDataWriter, TransportMode};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::sync::mpsc;

/// Router errors.
#[derive(Debug, Error)]
pub enum RouterError {
    #[error("Configuration error: {0}")]
    Config(#[from] crate::config::ConfigError),

    #[error("DDS error: {0}")]
    Dds(String),

    #[error("Route not found: domain {0} -> {1}")]
    RouteNotFound(u32, u32),

    #[error("Router not running")]
    NotRunning,

    #[error("Router already running")]
    AlreadyRunning,

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Message to be routed.
#[derive(Debug, Clone)]
pub struct RoutedMessage {
    /// Source domain.
    pub source_domain: u32,
    /// Original topic name.
    pub topic_name: String,
    /// Type name.
    pub type_name: String,
    /// Serialized payload.
    pub payload: Vec<u8>,
    /// Sequence number.
    pub sequence_number: u64,
    /// Writer GUID.
    pub writer_guid: String,
}

/// Handle to control the router.
#[derive(Clone)]
pub struct RouterHandle {
    running: Arc<AtomicBool>,
    stats_tx: Option<mpsc::Sender<StatsRequest>>,
}

impl RouterHandle {
    /// Check if router is running.
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }

    /// Request router to stop.
    pub fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
    }

    /// Get route statistics.
    pub async fn get_stats(&self) -> Result<Vec<RouteStatsSnapshot>, RouterError> {
        let (tx, mut rx) = mpsc::channel(1);
        if let Some(ref stats_tx) = self.stats_tx {
            stats_tx
                .send(StatsRequest { reply: tx })
                .await
                .map_err(|_| RouterError::NotRunning)?;
            rx.recv().await.ok_or(RouterError::NotRunning)
        } else {
            Err(RouterError::NotRunning)
        }
    }
}

struct StatsRequest {
    reply: mpsc::Sender<Vec<RouteStatsSnapshot>>,
}

const DISCOVERY_INTERVAL: Duration = Duration::from_secs(1);
const ROUTE_POLL_INTERVAL: Duration = Duration::from_millis(5);

#[derive(Clone)]
struct RouteRuntime {
    from_domain: u32,
    to_domain: u32,
    topics: TopicSelection,
    topic_transform: TopicTransform,
    qos_transform: QosTransform,
    stats: Arc<RouteStats>,
}

impl RouteRuntime {
    fn from_route(route: &Route) -> Self {
        Self {
            from_domain: route.from_domain,
            to_domain: route.to_domain,
            topics: route.topics.clone(),
            topic_transform: route.topic_transform.clone(),
            qos_transform: route.qos_transform.clone(),
            stats: route.stats.clone(),
        }
    }

    fn matches_topic(&self, topic: &str) -> bool {
        self.topics.matches(topic)
    }

    fn transform_topic(&self, topic: &str) -> String {
        self.topic_transform.transform(topic)
    }

    fn apply_qos_transform(&self, qos: &QoS) -> QoS {
        let mut out = qos.clone();

        if let Some(reliability) = self.qos_transform.reliability() {
            out.reliability = match reliability {
                crate::transform::Reliability::BestEffort => HddsReliability::BestEffort,
                crate::transform::Reliability::Reliable => HddsReliability::Reliable,
            };
        }

        if let Some(durability) = self.qos_transform.durability() {
            out.durability = match durability {
                crate::transform::Durability::Volatile => HddsDurability::Volatile,
                crate::transform::Durability::TransientLocal => HddsDurability::TransientLocal,
                crate::transform::Durability::Transient
                | crate::transform::Durability::Persistent => {
                    tracing::warn!(
                        "Durability {:?} not supported by HDDS; using TransientLocal",
                        durability
                    );
                    HddsDurability::TransientLocal
                }
            };
        }

        if let Some(depth) = self.qos_transform.history_depth() {
            if depth > 0 {
                out.history = History::KeepLast(depth);
            }
        }

        if let Some(deadline_us) = self.qos_transform.deadline_us() {
            out.deadline = Deadline::new(Duration::from_micros(deadline_us));
        }

        if let Some(lifespan_us) = self.qos_transform.lifespan_us() {
            out.lifespan = Lifespan::new(Duration::from_micros(lifespan_us));
        }

        out
    }

    fn record_message(&self, bytes: u64) {
        self.stats.messages_routed.fetch_add(1, Ordering::Relaxed);
        self.stats.bytes_routed.fetch_add(bytes, Ordering::Relaxed);
    }

    fn record_error(&self) {
        self.stats.errors.fetch_add(1, Ordering::Relaxed);
    }
}

struct RouteEndpoint {
    source_topic: String,
    dest_topic: String,
    reader: RawDataReader,
    writer: RawDataWriter,
}

/// DDS Routing Service.
pub struct Router {
    config: RouterConfig,
    routes: Vec<Route>,
    running: Arc<AtomicBool>,
    start_time: Option<Instant>,
}

impl Router {
    /// Create a new router from configuration.
    pub fn new(config: RouterConfig) -> Result<Self, RouterError> {
        config.validate()?;

        let mut routes = Vec::new();

        for route_config in &config.routes {
            // Create forward route
            routes.push(Route::from_config(route_config));

            // Create reverse route if bidirectional
            if route_config.bidirectional {
                let reverse_config = RouteConfig {
                    from_domain: route_config.to_domain,
                    to_domain: route_config.from_domain,
                    bidirectional: false,
                    topics: route_config.topics.clone(),
                    remaps: route_config
                        .remaps
                        .iter()
                        .map(|r| crate::config::TopicRemap {
                            from: r.to.clone(),
                            to: r.from.clone(),
                        })
                        .collect(),
                    qos_transform: route_config.qos_transform.clone(),
                };
                routes.push(Route::from_config(&reverse_config));
            }
        }

        Ok(Self {
            config,
            routes,
            running: Arc::new(AtomicBool::new(false)),
            start_time: None,
        })
    }

    /// Create a simple domain bridge.
    pub fn bridge(from_domain: u32, to_domain: u32) -> Result<Self, RouterError> {
        let config = RouterConfig::bridge(from_domain, to_domain);
        Self::new(config)
    }

    /// Create a bidirectional domain bridge.
    pub fn bidirectional_bridge(domain_a: u32, domain_b: u32) -> Result<Self, RouterError> {
        let config = RouterConfig::bidirectional_bridge(domain_a, domain_b);
        Self::new(config)
    }

    /// Get the router configuration.
    pub fn config(&self) -> &RouterConfig {
        &self.config
    }

    /// Get all routes.
    pub fn routes(&self) -> &[Route] {
        &self.routes
    }

    /// Get route statistics.
    pub fn route_stats(&self) -> Vec<RouteStatsSnapshot> {
        self.routes.iter().map(|r| r.stats.snapshot()).collect()
    }

    /// Find route for a message.
    pub fn find_route(&self, source_domain: u32, topic: &str) -> Option<&Route> {
        self.routes
            .iter()
            .find(|r| r.from_domain == source_domain && r.matches_topic(topic))
    }

    /// Route a message.
    pub fn route_message(&self, msg: &RoutedMessage) -> Result<Option<RoutedMessage>, RouterError> {
        let route = match self.find_route(msg.source_domain, &msg.topic_name) {
            Some(r) => r,
            None => return Ok(None), // No route for this message
        };

        // Transform topic name
        let dest_topic = route.transform_topic(&msg.topic_name);

        // Record stats
        route.record_message(msg.payload.len() as u64);

        // Create routed message
        let routed = RoutedMessage {
            source_domain: route.to_domain,
            topic_name: dest_topic,
            type_name: msg.type_name.clone(),
            payload: msg.payload.clone(),
            sequence_number: msg.sequence_number,
            writer_guid: msg.writer_guid.clone(),
        };

        Ok(Some(routed))
    }

    /// Start the router (async).
    ///
    /// Initializes DDS participants for each domain, discovers topics, and
    /// routes raw payloads between domains using per-route transforms.
    pub async fn run(&mut self) -> Result<RouterHandle, RouterError> {
        if self.running.load(Ordering::Relaxed) {
            return Err(RouterError::AlreadyRunning);
        }

        self.running.store(true, Ordering::Relaxed);
        self.start_time = Some(Instant::now());

        tracing::info!(
            "Router '{}' started with {} routes",
            self.config.name,
            self.routes.len()
        );

        for route in &self.routes {
            tracing::info!(
                "  Route: domain {} -> domain {} ({} topic transform)",
                route.from_domain,
                route.to_domain,
                if route.topic_transform.has_remap("*") {
                    "with"
                } else {
                    "no"
                }
            );
        }

        // Create stats channel
        let (stats_tx, mut stats_rx) = mpsc::channel::<StatsRequest>(10);
        let routes_for_stats: Vec<_> = self.routes.iter().map(|r| r.stats.clone()).collect();

        // Spawn stats handler
        tokio::spawn(async move {
            while let Some(req) = stats_rx.recv().await {
                let stats: Vec<_> = routes_for_stats.iter().map(|s| s.snapshot()).collect();
                let _ = req.reply.send(stats).await;
            }
        });

        let mut domains = HashSet::new();
        for route in &self.routes {
            domains.insert(route.from_domain);
            domains.insert(route.to_domain);
        }

        let mut participants = HashMap::new();
        for domain in domains {
            let participant = Participant::builder(&format!("hdds-router-{}", domain))
                .with_transport(TransportMode::UdpMulticast)
                .domain_id(domain)
                .build()
                .map_err(|e| RouterError::Dds(e.to_string()))?;
            participants.insert(domain, participant);
        }

        let runtime_routes: Vec<_> = self.routes.iter().map(RouteRuntime::from_route).collect();
        for route in runtime_routes {
            let from = participants
                .get(&route.from_domain)
                .ok_or(RouterError::RouteNotFound(
                    route.from_domain,
                    route.to_domain,
                ))?;
            let to = participants
                .get(&route.to_domain)
                .ok_or(RouterError::RouteNotFound(
                    route.from_domain,
                    route.to_domain,
                ))?;

            let route = Arc::new(route);
            let running = self.running.clone();
            let from = Arc::clone(from);
            let to = Arc::clone(to);

            tokio::spawn(async move {
                run_route(route, from, to, running).await;
            });
        }

        Ok(RouterHandle {
            running: self.running.clone(),
            stats_tx: Some(stats_tx),
        })
    }

    /// Stop the router.
    pub fn stop(&mut self) {
        self.running.store(false, Ordering::Relaxed);
        tracing::info!("Router '{}' stopped", self.config.name);
    }

    /// Check if router is running.
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }

    /// Get uptime in seconds.
    pub fn uptime_secs(&self) -> u64 {
        self.start_time.map(|t| t.elapsed().as_secs()).unwrap_or(0)
    }
}

/// Router with integrated DDS participants.
///
/// This struct provides the full routing functionality with actual
/// DDS domain participants. It's separated from the base Router
/// to allow testing without DDS dependencies.
pub struct IntegratedRouter {
    router: Router,
    // In a full implementation, this would contain:
    // participants: HashMap<u32, DomainParticipant>,
    // readers: HashMap<String, DataReader>,
    // writers: HashMap<String, DataWriter>,
}

impl IntegratedRouter {
    /// Create a new integrated router.
    pub fn new(config: RouterConfig) -> Result<Self, RouterError> {
        Ok(Self {
            router: Router::new(config)?,
        })
    }

    /// Get the underlying router.
    pub fn router(&self) -> &Router {
        &self.router
    }

    /// Get mutable reference to router.
    pub fn router_mut(&mut self) -> &mut Router {
        &mut self.router
    }

    /// Start the integrated router.
    ///
    /// Initializes DDS participants and starts routing.
    pub async fn start(&mut self) -> Result<RouterHandle, RouterError> {
        self.router.run().await
    }
}

async fn run_route(
    route: Arc<RouteRuntime>,
    from: Arc<Participant>,
    to: Arc<Participant>,
    running: Arc<AtomicBool>,
) {
    let mut endpoints: HashMap<String, RouteEndpoint> = HashMap::new();
    let mut last_discovery = Instant::now()
        .checked_sub(DISCOVERY_INTERVAL)
        .unwrap_or_else(Instant::now);

    while running.load(Ordering::Relaxed) {
        if last_discovery.elapsed() >= DISCOVERY_INTERVAL {
            match from.discover_topics() {
                Ok(topics) => {
                    for info in topics {
                        if info.publisher_count == 0 {
                            continue;
                        }

                        if !route.matches_topic(&info.name) {
                            continue;
                        }

                        if endpoints.contains_key(&info.name) {
                            continue;
                        }

                        let dest_topic = route.transform_topic(&info.name);
                        let reader_qos = info.qos.clone();
                        let writer_qos = route.apply_qos_transform(&info.qos);

                        let reader = match from.create_raw_reader_with_type(
                            &info.name,
                            &info.type_name,
                            Some(reader_qos),
                            info.type_object.clone(),
                        ) {
                            Ok(reader) => reader,
                            Err(err) => {
                                route.record_error();
                                tracing::warn!(
                                    "Failed to create raw reader for {}: {}",
                                    info.name,
                                    err
                                );
                                continue;
                            }
                        };

                        let writer = match to.create_raw_writer_with_type(
                            &dest_topic,
                            &info.type_name,
                            Some(writer_qos),
                            info.type_object.clone(),
                        ) {
                            Ok(writer) => writer,
                            Err(err) => {
                                route.record_error();
                                tracing::warn!(
                                    "Failed to create raw writer for {}: {}",
                                    dest_topic,
                                    err
                                );
                                continue;
                            }
                        };

                        tracing::info!(
                            "Route {} -> {}: {} ({})",
                            route.from_domain,
                            route.to_domain,
                            info.name,
                            info.type_name
                        );

                        endpoints.insert(
                            info.name.clone(),
                            RouteEndpoint {
                                source_topic: info.name,
                                dest_topic,
                                reader,
                                writer,
                            },
                        );
                    }
                }
                Err(err) => {
                    route.record_error();
                    tracing::warn!(
                        "Route {} -> {} discovery failed: {}",
                        route.from_domain,
                        route.to_domain,
                        err
                    );
                }
            }

            last_discovery = Instant::now();
        }

        for endpoint in endpoints.values() {
            match endpoint.reader.try_take_raw() {
                Ok(samples) => {
                    for sample in samples {
                        let payload_len = sample.payload.len() as u64;
                        if let Err(err) = endpoint.writer.write_raw(&sample.payload) {
                            route.record_error();
                            tracing::debug!(
                                "Route {} -> {} write failed for {}: {}",
                                route.from_domain,
                                route.to_domain,
                                endpoint.dest_topic,
                                err
                            );
                        } else {
                            route.record_message(payload_len);
                        }
                    }
                }
                Err(err) => {
                    route.record_error();
                    tracing::debug!(
                        "Route {} -> {} read failed for {}: {}",
                        route.from_domain,
                        route.to_domain,
                        endpoint.source_topic,
                        err
                    );
                }
            }
        }

        tokio::time::sleep(ROUTE_POLL_INTERVAL).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::TopicSelection;

    #[test]
    fn test_router_creation() {
        let router = Router::bridge(0, 1).expect("create router");
        assert_eq!(router.routes().len(), 1);
        assert_eq!(router.routes()[0].from_domain, 0);
        assert_eq!(router.routes()[0].to_domain, 1);
    }

    #[test]
    fn test_router_bidirectional() {
        let router = Router::bidirectional_bridge(0, 1).expect("create router");
        assert_eq!(router.routes().len(), 2);

        // Forward route
        assert!(router
            .routes()
            .iter()
            .any(|r| r.from_domain == 0 && r.to_domain == 1));
        // Reverse route
        assert!(router
            .routes()
            .iter()
            .any(|r| r.from_domain == 1 && r.to_domain == 0));
    }

    #[test]
    fn test_route_message() {
        let config = RouterConfig {
            routes: vec![RouteConfig::new(0, 1).remap("Temperature", "Vehicle/Temperature")],
            ..Default::default()
        };
        let router = Router::new(config).expect("create router");

        let msg = RoutedMessage {
            source_domain: 0,
            topic_name: "Temperature".into(),
            type_name: "sensor_msgs/Temperature".into(),
            payload: vec![1, 2, 3, 4],
            sequence_number: 1,
            writer_guid: "guid".into(),
        };

        let routed = router.route_message(&msg).expect("route").expect("some");
        assert_eq!(routed.source_domain, 1);
        assert_eq!(routed.topic_name, "Vehicle/Temperature");
    }

    #[test]
    fn test_route_no_match() {
        let config = RouterConfig {
            routes: vec![
                RouteConfig::new(0, 1).topics(TopicSelection::Include(vec!["Temperature".into()]))
            ],
            ..Default::default()
        };
        let router = Router::new(config).expect("create router");

        let msg = RoutedMessage {
            source_domain: 0,
            topic_name: "Pressure".into(), // Not in include list
            type_name: "sensor_msgs/Pressure".into(),
            payload: vec![1, 2, 3, 4],
            sequence_number: 1,
            writer_guid: "guid".into(),
        };

        let routed = router.route_message(&msg).expect("route");
        assert!(routed.is_none());
    }

    #[test]
    fn test_route_stats() {
        let router = Router::bridge(0, 1).expect("create router");

        let msg = RoutedMessage {
            source_domain: 0,
            topic_name: "Temperature".into(),
            type_name: "sensor_msgs/Temperature".into(),
            payload: vec![1, 2, 3, 4],
            sequence_number: 1,
            writer_guid: "guid".into(),
        };

        router.route_message(&msg).expect("route");
        router.route_message(&msg).expect("route");

        let stats = router.route_stats();
        assert_eq!(stats.len(), 1);
        assert_eq!(stats[0].messages_routed, 2);
        assert_eq!(stats[0].bytes_routed, 8); // 4 bytes * 2
    }

    #[tokio::test]
    async fn test_router_run_stop() {
        let mut router = Router::bridge(0, 1).expect("create router");

        assert!(!router.is_running());

        let handle = router.run().await.expect("run");
        assert!(router.is_running());
        assert!(handle.is_running());

        handle.stop();
        // Note: In real implementation, need to wait for stop
    }
}
