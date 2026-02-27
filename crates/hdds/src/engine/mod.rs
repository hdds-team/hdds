// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Consolidated data routing and event distribution engine
//!
//! This module combines the packet routing, topic demultiplexing, subscriber management,
//! and event hub into a unified engine for efficient data delivery.
//!
//! # Architecture
//!
//! ```text
//! MulticastListener -> RxRing.push()
//!       v
//! Router.pop() -> parse topic name / GUID
//!       v
//! TopicRegistry.get_topic()
//!       v
//! Topic.deliver() -> Subscriber.on_data()
//!       v
//! Hub.publish(Event) -> NxSPSC rings
//! ```
//!
//! # Components
//!
//! ## Router
//! - **Router**: Background thread routing RTPS packets from RxRing to subscribers
//! - **RouterMetrics**: Telemetry counters (packets routed, orphaned, errors, bytes)
//! - **route_data_packet()**: HOT PATH function for DATA packet routing
//!
//! ## Demux
//! - **TopicRegistry**: Thread-safe topic -> subscribers mapping with GUID routing
//! - **Topic**: Topic metadata and subscriber fanout with panic isolation
//! - **HeartbeatHandler/NackHandler**: Traits for reliability protocol callbacks
//!
//! ## Subscriber
//! - **Subscriber**: Trait for receiving topic data (callback pattern)
//! - **CallbackSubscriber**: Closure-based subscriber implementation
//!
//! ## Hub
//! - **Hub**: MPSC producer -> NxSPSC subscribers for system events
//! - **Event**: Discovery, matcher, QoS event types
//!
//! # Performance Notes
//!
//! - All HOT PATH functions marked with `#[inline]`
//! - Lock-free atomics for metrics (relaxed ordering)
//! - RwLock for topic registry (readers don't block each other)
//! - Panic isolation in delivery paths (one subscriber panic doesn't affect others)
//!
//! # Examples
//!
//! ```no_run
//! use hdds::engine::{Router, TopicRegistry, CallbackSubscriber};
//! use std::sync::Arc;
//!
//! // Create registry and register subscriber
//! let registry = Arc::new(TopicRegistry::new());
//! let subscriber = Arc::new(CallbackSubscriber::new(
//!     "sensor/temperature".to_string(),
//!     |topic, seq, data| {
//!         println!("Received seq {} on {}: {} bytes", seq, topic, data.len());
//!     },
//! ));
//! registry.register_subscriber(subscriber).unwrap();
//!
//! // Start router (requires RxRing and RxPool from multicast listener)
//! // let router = Router::start(ring, pool, registry)?;
//! ```

/// Packet demultiplexing and topic registry.
pub mod demux;
/// Event hub for routing notifications.
pub mod hub;
/// Core multicast router loop.
pub mod router;
/// Subscriber trait and callback adapter.
pub mod subscriber;
/// Unicast RTPS router entry points.
pub mod unicast_router;
/// Wake notifier primitives for engine threads.
pub mod wake;

// Re-export main types for convenience
pub use demux::{
    HeartbeatHandler, NackFragHandler, NackHandler, RegistryError, Topic, TopicRegistry,
};
pub use hub::{Event, Hub};
pub use router::{route_data_packet, RouteStatus, Router, RouterMetrics};
pub use subscriber::{CallbackSubscriber, Subscriber};
pub use unicast_router::{route_raw_rtps_message, UnicastRouteOutcome};
pub use wake::WakeNotifier;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::discovery::multicast::{PacketKind, RxMeta, RxPool};
    use crate::protocol::builder;
    use crossbeam::queue::ArrayQueue;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_engine_metrics_creation() {
        let metrics = RouterMetrics::new();
        let (routed, orphaned, errors, bytes, nack_frag, frag_timeouts, deduplicated) =
            metrics.snapshot();

        assert_eq!(routed, 0);
        assert_eq!(orphaned, 0);
        assert_eq!(errors, 0);
        assert_eq!(bytes, 0);
        assert_eq!(nack_frag, 0);
        assert_eq!(frag_timeouts, 0);
        assert_eq!(deduplicated, 0);
    }

    #[test]
    fn test_engine_metrics_update() {
        let metrics = RouterMetrics::new();

        metrics.packets_routed.fetch_add(10, Ordering::Relaxed);
        metrics.packets_orphaned.fetch_add(3, Ordering::Relaxed);
        metrics.delivery_errors.fetch_add(2, Ordering::Relaxed);
        metrics.bytes_delivered.fetch_add(4096, Ordering::Relaxed);

        let (routed, orphaned, errors, bytes, _, _, _) = metrics.snapshot();
        assert_eq!(routed, 10);
        assert_eq!(orphaned, 3);
        assert_eq!(errors, 2);
        assert_eq!(bytes, 4096);
    }

    #[test]
    fn test_route_data_packet_dropped_for_invalid_packet() {
        let registry = TopicRegistry::new();
        let metrics = RouterMetrics::new();

        let status = route_data_packet(&[0u8; 8], 8, None, &registry, &metrics);
        assert_eq!(status, RouteStatus::Dropped);
        assert_eq!(metrics.delivery_errors.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_route_data_packet_dropped_when_guid_unknown() {
        let registry = TopicRegistry::new();
        let metrics = RouterMetrics::new();

        // build_data_packet creates a packet with inline QoS containing topic name,
        // but extract_inline_qos() may not find it depending on packet structure.
        // When inline QoS extraction fails, the router falls back to GUID-based routing.
        // Since we haven't registered any GUID mapping, and the fallback env var is not set,
        // the packet is dropped with "writer GUID not announced via SEDP yet".
        let packet = builder::build_data_packet("missing/topic", 10, &[1, 2, 3]);
        assert!(!packet.is_empty());
        let status = route_data_packet(&packet, packet.len(), None, &registry, &metrics);

        // Dropped because:
        // 1. extract_inline_qos returns None (packet format doesn't match expected layout)
        // 2. GUID lookup fails (no SEDP mapping registered)
        // 3. Fallback disabled (HDDS_ROUTE_UNKNOWN_WRITER_TO_SINGLE_TOPIC not set)
        assert_eq!(status, RouteStatus::Dropped);
        assert_eq!(metrics.delivery_errors.load(Ordering::Relaxed), 1);
    }

    struct CountingHeartbeatHandler(Arc<AtomicUsize>);

    impl HeartbeatHandler for CountingHeartbeatHandler {
        fn on_heartbeat(&self, _heartbeat_bytes: &[u8]) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    struct CountingNackHandler(Arc<AtomicUsize>);

    impl NackHandler for CountingNackHandler {
        fn on_nack(&self, _nack_bytes: &[u8]) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn test_router_processes_heartbeat_packet() {
        let pool = Arc::new(RxPool::new(4, 128).expect("Pool creation should succeed"));
        let ring = Arc::new(ArrayQueue::new(8));
        let registry = Arc::new(TopicRegistry::new());
        let counter = Arc::new(AtomicUsize::new(0));
        registry.register_heartbeat_handler(Arc::new(CountingHeartbeatHandler(counter.clone())));

        let router = Router::start(Arc::clone(&ring), Arc::clone(&pool), Arc::clone(&registry))
            .expect("router start should succeed");

        let buffer_id = pool
            .acquire_for_listener()
            .expect("pool should have buffers");
        let meta = RxMeta::new(
            "127.0.0.1:7400".parse().expect("valid IP:port"),
            4,
            PacketKind::Heartbeat,
        );
        ring.push((meta, buffer_id))
            .expect("ring should have space");

        thread::sleep(Duration::from_millis(20));
        assert_eq!(counter.load(Ordering::SeqCst), 1);

        router.stop().expect("router stop should succeed");
    }

    #[test]
    fn test_router_processes_acknack_packet() {
        let pool = Arc::new(RxPool::new(4, 128).expect("Pool creation should succeed"));
        let ring = Arc::new(ArrayQueue::new(8));
        let registry = Arc::new(TopicRegistry::new());
        let counter = Arc::new(AtomicUsize::new(0));
        registry.register_nack_handler(Arc::new(CountingNackHandler(counter.clone())));

        let router = Router::start(Arc::clone(&ring), Arc::clone(&pool), Arc::clone(&registry))
            .expect("router start should succeed");

        let buffer_id = pool
            .acquire_for_listener()
            .expect("pool should have buffers");
        let meta = RxMeta::new(
            "127.0.0.1:7400".parse().expect("valid IP:port"),
            4,
            PacketKind::AckNack,
        );
        ring.push((meta, buffer_id))
            .expect("ring should have space");

        thread::sleep(Duration::from_millis(20));
        assert_eq!(counter.load(Ordering::SeqCst), 1);

        router.stop().expect("router stop should succeed");
    }

    #[test]
    fn test_router_handles_dropped_data_packet() {
        let pool = Arc::new(RxPool::new(4, 64).expect("Pool creation should succeed"));
        let ring = Arc::new(ArrayQueue::new(8));
        let registry = Arc::new(TopicRegistry::new());
        let router = Router::start(Arc::clone(&ring), Arc::clone(&pool), Arc::clone(&registry))
            .expect("router start should succeed");

        let buffer_id = pool
            .acquire_for_listener()
            .expect("pool should have buffers");
        // SAFETY: we obtained `pool_ptr` from `Arc::as_ptr`; there are no mutable references to the
        // underlying pool while this test runs, so casting to `*mut RxPool` to access the buffer is
        // sound. We only write within the reserved buffer bounds.
        unsafe {
            let pool_ptr = Arc::as_ptr(&pool);
            let buf = (*pool_ptr.cast_mut()).get_buffer_mut(buffer_id);
            buf[..8].copy_from_slice(&[0u8; 8]);
        }

        let meta = RxMeta::new(
            "127.0.0.1:7400".parse().expect("valid IP:port"),
            8,
            PacketKind::Data,
        );
        ring.push((meta, buffer_id))
            .expect("ring should have space");
        thread::sleep(Duration::from_millis(20));

        router.stop().expect("router stop should succeed");
    }

    #[test]
    fn test_topic_new() {
        let topic = Topic::new("test_topic".to_string(), Some("TestType".to_string()));
        assert_eq!(topic.name(), "test_topic");
        assert_eq!(topic.type_name(), Some("TestType"));
        assert_eq!(topic.subscriber_count(), 0);
    }

    #[test]
    fn test_topic_add_remove_and_deliver() {
        let mut topic = Topic::new("test".to_string(), None);
        let counter = Arc::new(AtomicUsize::new(0));
        let c = Arc::clone(&counter);

        let sub: Arc<dyn Subscriber> = Arc::new(CallbackSubscriber::new(
            "test".to_string(),
            move |topic, seq, data| {
                assert_eq!(topic, "test");
                assert_eq!(seq, 42);
                assert_eq!(data.len(), 3);
                c.fetch_add(1, Ordering::SeqCst);
            },
        ));

        topic.add_subscriber(Arc::clone(&sub));
        assert_eq!(topic.subscriber_count(), 1);

        let removed = topic.remove_subscriber("other");
        assert!(!removed);
        assert_eq!(topic.subscriber_count(), 1);

        let removed = topic.remove_subscriber("test");
        assert!(removed);
        assert_eq!(topic.subscriber_count(), 0);

        topic.add_subscriber(sub);
        let errors = topic.deliver(42, &[1, 2, 3]);
        assert_eq!(errors, 0);
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn test_topic_deliver_handles_panic() {
        let mut topic = Topic::new("panic".to_string(), None);
        let counter = Arc::new(AtomicUsize::new(0));
        let c = Arc::clone(&counter);

        let sub: Arc<dyn Subscriber> = Arc::new(CallbackSubscriber::new(
            "panic".to_string(),
            move |_, _, _| {
                c.fetch_add(1, Ordering::SeqCst);
                std::panic::panic_any("subscriber panic");
            },
        ));

        topic.add_subscriber(sub);
        let errors = topic.deliver(0, &[]);

        assert_eq!(errors, 1);
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn test_registry_topic_lifecycle() {
        let registry = TopicRegistry::new();
        registry
            .register_topic("test_topic".to_string(), None)
            .expect("topic registration should succeed");
        assert_eq!(registry.topic_count(), 1);

        // Idempotent registration
        registry
            .register_topic("test_topic".to_string(), None)
            .expect("idempotent registration should succeed");
        assert_eq!(registry.topic_count(), 1);

        let topic = registry.get_topic("test_topic").expect("topic must exist");
        assert_eq!(topic.name(), "test_topic");
    }

    #[test]
    fn test_registry_register_subscriber_auto_creates_topic() {
        let registry = TopicRegistry::new();
        let sub: Arc<dyn Subscriber> = Arc::new(CallbackSubscriber::new(
            "auto_topic".to_string(),
            |_, _, _| {},
        ));

        registry
            .register_subscriber(sub)
            .expect("subscriber registration should succeed");

        assert_eq!(registry.topic_count(), 1);
        let topic = registry
            .get_topic("auto_topic")
            .expect("auto-created topic should exist");
        assert_eq!(topic.subscriber_count(), 1);
    }

    #[test]
    fn test_registry_unregister_subscriber() {
        let registry = TopicRegistry::new();
        let sub: Arc<dyn Subscriber> =
            Arc::new(CallbackSubscriber::new("test".to_string(), |_, _, _| {}));

        registry
            .register_subscriber(sub)
            .expect("subscriber registration should succeed");

        let removed = registry
            .unregister_subscriber("test")
            .expect("unregister should succeed");
        assert!(removed);

        let removed_again = registry
            .unregister_subscriber("test")
            .expect("second unregister should succeed");
        assert!(!removed_again);
    }

    #[test]
    fn test_registry_handles_poisoned_locks() {
        let registry = TopicRegistry::new();
        let _ = std::panic::catch_unwind(|| {
            let _guard = registry
                .topics
                .write()
                .expect("lock acquisition for poison test");
            std::panic::panic_any("force poison");
        });

        registry
            .register_topic("recover_topic".to_string(), None)
            .expect("recover after poison");
        assert!(registry.get_topic("recover_topic").is_some());
    }
}
