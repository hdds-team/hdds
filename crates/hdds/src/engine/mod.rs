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

pub(crate) mod departures;
#[cfg(all(test, unix))]
mod departures_verify3_tests;
#[cfg(test)]
mod departures_verify_tests;
/// Event hub for routing notifications.
pub mod hub;
/// Core multicast router loop.
pub mod router;
/// Router spin-before-park policy and its counters.
mod router_spin;
/// Subscriber trait and callback adapter.
pub mod subscriber;
/// Unicast RTPS router entry points.
pub mod unicast_router;
/// Wake notifier primitives for engine threads.
pub mod wake;
pub(crate) mod writer_control;

// Re-export main types for convenience
pub use demux::{
    HeartbeatHandler, HeartbeatHandlerId, HeartbeatHandlerToken, NackFragHandler, NackHandler,
    NackHandlerId, RegistryError, StreamReply, Topic, TopicRegistry,
};
pub(crate) use demux::{NackHandlerToken, SubscriberToken};
pub use hub::{Event, Hub};
pub use router::{route_data_packet, RouteStatus, Router, RouterMetrics};
pub use subscriber::{
    CallbackSubscriber, DisposeKind, GroupChange, PayloadFraming, Subscriber, WriterDeparture,
};
pub use unicast_router::{
    route_raw_rtps_message, route_raw_rtps_message_from_stream, UnicastRouteOutcome,
};
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
        assert_eq!(
            metrics.missing_sequence_fallbacks.load(Ordering::Relaxed),
            0
        );
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
        fn on_heartbeat(
            &self,
            _heartbeat_bytes: &[u8],
            _origin: Option<crate::core::discovery::multicast::Origin>,
        ) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    struct CountingNackHandler(Arc<AtomicUsize>);

    impl NackHandler for CountingNackHandler {
        fn on_nack(&self, _nack_bytes: &[u8], _reader_guid: Option<[u8; 16]>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn test_router_processes_heartbeat_packet() {
        // A user writer's HEARTBEAT (s8.3.8.6) in the buffer the ring names:
        // the Router answers a HEARTBEAT it routes, and the reorder gate state
        // it carries is applied first (`engine::writer_control`).
        let mut raw = RxPool::new(4, 128).expect("Pool creation should succeed");
        let buffer_id = raw
            .acquire_for_listener()
            .expect("pool should have buffers");
        let mut datagram = Vec::with_capacity(52);
        datagram.extend_from_slice(b"RTPS");
        datagram.extend_from_slice(&[0x02, 0x05, 0x01, 0x0F]);
        datagram.extend_from_slice(&[0x0A; 12]);
        datagram.extend_from_slice(&[0x07, 0x01]); // HEARTBEAT, little-endian
        datagram.extend_from_slice(&28u16.to_le_bytes());
        datagram.extend_from_slice(&[0x00, 0x00, 0x01, 0x07]); // readerId
        datagram.extend_from_slice(&[0x00, 0x00, 0x01, 0x02]); // writerId
        datagram.extend_from_slice(&0i32.to_le_bytes());
        datagram.extend_from_slice(&1u32.to_le_bytes()); // firstSN 1
        datagram.extend_from_slice(&0i32.to_le_bytes());
        datagram.extend_from_slice(&1u32.to_le_bytes()); // lastSN 1
        datagram.extend_from_slice(&1i32.to_le_bytes()); // count
        raw.get_buffer_mut(buffer_id)[..datagram.len()].copy_from_slice(&datagram);
        let pool = Arc::new(raw);

        let ring = Arc::new(ArrayQueue::new(8));
        let registry = Arc::new(TopicRegistry::new());
        let counter = Arc::new(AtomicUsize::new(0));
        registry.register_heartbeat_handler(Arc::new(CountingHeartbeatHandler(counter.clone())));

        let router = Router::start(Arc::clone(&ring), Arc::clone(&pool), Arc::clone(&registry))
            .expect("router start should succeed");

        let meta = RxMeta::new(
            crate::core::discovery::multicast::Origin::direct(
                "127.0.0.1:7400".parse().expect("valid IP:port"),
            ),
            datagram.len(),
            PacketKind::Heartbeat,
        );
        ring.push((meta, buffer_id))
            .expect("ring should have space");

        thread::sleep(Duration::from_millis(20));
        assert_eq!(counter.load(Ordering::SeqCst), 1);

        router.stop().expect("router stop should succeed");
    }

    /// How many HEARTBEAT handler calls a user writer's HEARTBEAT, sent by
    /// `datagram_prefix`, causes when the Router's own prefix is `our_prefix`.
    fn heartbeat_handler_calls(
        our_prefix: [u8; 12],
        datagram_prefix: [u8; 12],
        writer: [u8; 4],
    ) -> usize {
        let mut raw = RxPool::new(4, 128).expect("Pool creation should succeed");
        let buffer_id = raw
            .acquire_for_listener()
            .expect("pool should have buffers");
        let mut datagram = Vec::with_capacity(52);
        datagram.extend_from_slice(b"RTPS");
        datagram.extend_from_slice(&[0x02, 0x05, 0x01, 0x0F]);
        datagram.extend_from_slice(&datagram_prefix);
        datagram.extend_from_slice(&[0x07, 0x01]);
        datagram.extend_from_slice(&28u16.to_le_bytes());
        datagram.extend_from_slice(&[0x00, 0x00, 0x01, 0x07]);
        datagram.extend_from_slice(&writer);
        datagram.extend_from_slice(&0i32.to_le_bytes());
        datagram.extend_from_slice(&1u32.to_le_bytes());
        datagram.extend_from_slice(&0i32.to_le_bytes());
        datagram.extend_from_slice(&1u32.to_le_bytes());
        datagram.extend_from_slice(&1i32.to_le_bytes());
        raw.get_buffer_mut(buffer_id)[..datagram.len()].copy_from_slice(&datagram);
        let pool = Arc::new(raw);
        let ring = Arc::new(ArrayQueue::new(8));
        let registry = Arc::new(TopicRegistry::new());
        let counter = Arc::new(AtomicUsize::new(0));
        registry.register_heartbeat_handler(Arc::new(CountingHeartbeatHandler(counter.clone())));
        let router = Router::start_with_transport(
            Arc::clone(&ring),
            Arc::clone(&pool),
            Arc::clone(&registry),
            None,
            our_prefix,
        )
        .expect("router start should succeed");
        let meta = RxMeta::new(
            crate::core::discovery::multicast::Origin::direct(
                "127.0.0.1:7400".parse().expect("valid IP:port"),
            ),
            datagram.len(),
            PacketKind::Heartbeat,
        );
        ring.push((meta, buffer_id))
            .expect("ring should have space");
        // A fixed sleep lost the race on a loaded machine: wait for the
        // Router to take the datagram (bounded), then leave it a grace
        // period to run the handler, or return as soon as it did.
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while !ring.is_empty() && std::time::Instant::now() < deadline {
            thread::sleep(Duration::from_millis(1));
        }
        let grace = std::time::Instant::now() + Duration::from_millis(50);
        while counter.load(Ordering::SeqCst) == 0 && std::time::Instant::now() < grace {
            thread::sleep(Duration::from_millis(1));
        }
        router.stop().expect("router stop should succeed");
        counter.load(Ordering::SeqCst)
    }

    /// Our own writer's HEARTBEAT, looped back by multicast, neither seeds
    /// nor is answered by the Router, as our own DATA is not routed; another
    /// participant's HEARTBEAT is.
    #[test]
    fn our_own_heartbeat_is_not_applied_or_answered() {
        const OURS: [u8; 12] = [0x55; 12];
        const THEIRS: [u8; 12] = [0x0A; 12];
        const USER: [u8; 4] = [0x00, 0x00, 0x01, 0x02];
        assert_eq!(
            heartbeat_handler_calls(OURS, OURS, USER),
            0,
            "own HEARTBEAT"
        );
        assert_eq!(
            heartbeat_handler_calls(OURS, THEIRS, USER),
            1,
            "peer HEARTBEAT"
        );
    }

    /// With no control thread the Router is the only answerer: a builtin
    /// writer's HEARTBEAT is answered too, as the Router always did.
    #[test]
    fn a_builtin_heartbeat_is_answered_without_a_control_thread() {
        const THEIRS: [u8; 12] = [0x0A; 12];
        const BUILTIN: [u8; 4] = [0x00, 0x00, 0x03, 0xC2];
        assert_eq!(heartbeat_handler_calls([0x55; 12], THEIRS, BUILTIN), 1);
    }

    #[test]
    fn unregister_heartbeat_handler_removes_exactly_that_entry() {
        let registry = Arc::new(TopicRegistry::new());
        let counter_a = Arc::new(AtomicUsize::new(0));
        let counter_b = Arc::new(AtomicUsize::new(0));
        let id_a = registry
            .register_heartbeat_handler(Arc::new(CountingHeartbeatHandler(counter_a.clone())));
        let _id_b = registry
            .register_heartbeat_handler(Arc::new(CountingHeartbeatHandler(counter_b.clone())));
        assert_eq!(registry.heartbeat_handler_count(), 2);

        registry.unregister_heartbeat_handler(id_a);
        assert_eq!(registry.heartbeat_handler_count(), 1);

        let packet = builder::build_heartbeat_packet(1, 1, 1);
        let panics = registry.deliver_heartbeat(&packet, None);
        assert_eq!(panics, 0, "no handler should panic");
        assert_eq!(
            counter_a.load(Ordering::SeqCst),
            0,
            "the removed handler must not be dispatched to"
        );
        assert_eq!(
            counter_b.load(Ordering::SeqCst),
            1,
            "the remaining handler must still be dispatched to"
        );
    }

    #[test]
    fn heartbeat_handler_token_unregisters_on_drop() {
        let registry = Arc::new(TopicRegistry::new());
        let counter = Arc::new(AtomicUsize::new(0));
        let id = registry
            .register_heartbeat_handler(Arc::new(CountingHeartbeatHandler(counter.clone())));
        let token = HeartbeatHandlerToken::new(&registry, id);
        assert_eq!(registry.heartbeat_handler_count(), 1);

        drop(token);
        assert_eq!(registry.heartbeat_handler_count(), 0);

        let packet = builder::build_heartbeat_packet(1, 1, 1);
        let panics = registry.deliver_heartbeat(&packet, None);
        assert_eq!(panics, 0, "no handler should panic");
        assert_eq!(
            counter.load(Ordering::SeqCst),
            0,
            "a dropped token's handler must not be dispatched to"
        );
    }

    /// Holds its own `HeartbeatHandlerToken` and drops it from inside
    /// `on_heartbeat`, exercising a reader that tears itself down in
    /// direct reaction to a heartbeat. `HeartbeatHandlerToken::drop`
    /// takes a write lock on `TopicRegistry::heartbeat_handlers`; if
    /// `deliver_heartbeat` still held its read guard across this
    /// callback, this would deadlock (same `RwLock`, reader-then-writer,
    /// same thread).
    struct SelfDroppingHeartbeatHandler {
        token: std::sync::Mutex<Option<HeartbeatHandlerToken>>,
        calls: Arc<AtomicUsize>,
    }

    impl HeartbeatHandler for SelfDroppingHeartbeatHandler {
        fn on_heartbeat(
            &self,
            _heartbeat_bytes: &[u8],
            _origin: Option<crate::core::discovery::multicast::Origin>,
        ) {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let token = self.token.lock().unwrap_or_else(|e| e.into_inner()).take();
            drop(token);
        }
    }

    #[test]
    fn a_handler_dropping_its_own_token_from_inside_on_heartbeat_does_not_deadlock() {
        let registry = Arc::new(TopicRegistry::new());
        let calls = Arc::new(AtomicUsize::new(0));
        let handler = Arc::new(SelfDroppingHeartbeatHandler {
            token: std::sync::Mutex::new(None),
            calls: Arc::clone(&calls),
        });
        let id =
            registry.register_heartbeat_handler(Arc::clone(&handler) as Arc<dyn HeartbeatHandler>);
        *handler.token.lock().unwrap_or_else(|e| e.into_inner()) =
            Some(HeartbeatHandlerToken::new(&registry, id));

        // Dispatch on a background thread with a watchdog timeout: a
        // deadlock here must fail the test fast instead of hanging the
        // whole suite forever.
        let packet = builder::build_heartbeat_packet(1, 1, 1);
        let registry_bg = Arc::clone(&registry);
        let (tx, rx) = std::sync::mpsc::channel();
        let _dispatch_thread = thread::spawn(move || {
            let panics = registry_bg.deliver_heartbeat(&packet, None);
            let _ = tx.send(panics);
        });

        match rx.recv_timeout(Duration::from_secs(2)) {
            Ok(panics) => assert_eq!(panics, 0, "no handler should panic"),
            Err(_) => panic!(
                "deliver_heartbeat deadlocked: a handler dropping its own token \
                 from inside on_heartbeat must not deadlock"
            ),
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            registry.heartbeat_handler_count(),
            0,
            "the self-drop from inside on_heartbeat must have unregistered the handler"
        );
    }

    /// Owns ANOTHER registration's token: destroying this handler
    /// unregisters that other handler through the same registry.
    struct TokenOwningHeartbeatHandler {
        // Never read: it exists to be DROPPED with this handler.
        _other: std::sync::Mutex<Option<HeartbeatHandlerToken>>,
    }

    impl HeartbeatHandler for TokenOwningHeartbeatHandler {
        fn on_heartbeat(
            &self,
            _heartbeat_bytes: &[u8],
            _origin: Option<crate::core::discovery::multicast::Origin>,
        ) {
        }
    }

    /// `unregister_heartbeat_handler` must not destroy the removed
    /// handler while it still holds the registry's write lock. The
    /// registry owns the FINAL reference here (the production shape: a
    /// `DataReader` keeps only its token, never a clone of the `Arc`), so
    /// removal runs the handler's destructor, which re-enters the same
    /// lock to unregister the token it owns. Watchdog-timed so a deadlock
    /// fails fast.
    #[test]
    fn unregistering_the_final_reference_of_a_handler_whose_drop_unregisters_another_does_not_deadlock(
    ) {
        let registry = Arc::new(TopicRegistry::new());
        let other_counter = Arc::new(AtomicUsize::new(0));
        let other_id = registry
            .register_heartbeat_handler(Arc::new(CountingHeartbeatHandler(other_counter.clone())));
        let other_token = HeartbeatHandlerToken::new(&registry, other_id);
        // No clone kept: the registry's Vec holds the only Arc.
        let owner_id = registry.register_heartbeat_handler(Arc::new(TokenOwningHeartbeatHandler {
            _other: std::sync::Mutex::new(Some(other_token)),
        }));
        assert_eq!(registry.heartbeat_handler_count(), 2);

        let registry_bg = Arc::clone(&registry);
        let (tx, rx) = std::sync::mpsc::channel();
        let _unregister_thread = thread::spawn(move || {
            registry_bg.unregister_heartbeat_handler(owner_id);
            let _ = tx.send(());
        });
        if rx.recv_timeout(Duration::from_secs(2)).is_err() {
            panic!(
                "unregister_heartbeat_handler deadlocked: the removed handler was destroyed \
                 under the registry's write lock and its destructor re-entered that lock"
            );
        }
        assert_eq!(
            registry.heartbeat_handler_count(),
            0,
            "both the removed handler and the one its destructor unregistered are gone"
        );
        let packet = builder::build_heartbeat_packet(1, 1, 1);
        let panics = registry.deliver_heartbeat(&packet, None);
        assert_eq!(panics, 0, "no handler should panic");
        assert_eq!(
            other_counter.load(Ordering::SeqCst),
            0,
            "the transitively unregistered handler must not be dispatched to"
        );
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
            crate::core::discovery::multicast::Origin::direct(
                "127.0.0.1:7400".parse().expect("valid IP:port"),
            ),
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
            crate::core::discovery::multicast::Origin::direct(
                "127.0.0.1:7400".parse().expect("valid IP:port"),
            ),
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
        let errors = topic.deliver(42, &[1, 2, 3], crate::dds::CdrVersion::Xcdr2);
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
        let errors = topic.deliver(0, &[], crate::dds::CdrVersion::Xcdr2);

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
    fn scoped_subscriber_token_removes_only_its_instance() {
        let registry = Arc::new(TopicRegistry::new());
        let first: Arc<dyn Subscriber> =
            Arc::new(CallbackSubscriber::new("shared".to_string(), |_, _, _| {}));
        let second: Arc<dyn Subscriber> =
            Arc::new(CallbackSubscriber::new("shared".to_string(), |_, _, _| {}));

        let first_token = registry
            .register_subscriber_scoped(first)
            .expect("first subscriber registration");
        let _second_token = registry
            .register_subscriber_scoped(second)
            .expect("second subscriber registration");
        assert_eq!(
            registry
                .get_topic("shared")
                .expect("shared topic")
                .subscriber_count(),
            2
        );

        drop(first_token);
        assert_eq!(
            registry
                .get_topic("shared")
                .expect("shared topic")
                .subscriber_count(),
            1
        );
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

    /// A HEARTBEAT or GAP whose readerId names one reader reaches that
    /// reader's subscriber alone (RTPS v2.5 Sec.8.3.8.4, 8.3.8.6), not even
    /// a subscriber that names no reader; ENTITYID_UNKNOWN reaches them all.
    #[test]
    fn an_addressed_heartbeat_or_gap_reaches_the_reader_it_names() {
        use std::sync::Mutex;

        type Log = Arc<Mutex<Vec<(&'static str, &'static str)>>>;
        struct Named(&'static str, Option<[u8; 4]>, Log);
        impl Subscriber for Named {
            fn on_data(&self, _: &str, _: u64, _: &[u8]) {}
            fn topic_name(&self) -> &str {
                "Addressed"
            }
            fn reader_entity_id(&self) -> Option<[u8; 4]> {
                self.1
            }
            fn on_writer_heartbeat(&self, _: [u8; 16], _: u64) {
                self.2.lock().expect("log").push((self.0, "hb"));
            }
            fn on_writer_gap(&self, _: [u8; 16], _: u64, _: u64, _: Vec<u64>) {
                self.2.lock().expect("log").push((self.0, "gap"));
            }
        }

        let log: Log = Arc::new(Mutex::new(Vec::new()));
        let mut topic = Topic::new("Addressed".to_string(), None);
        for (name, id) in [
            ("a", Some([0, 0, 1, 7])),
            ("b", Some([0, 0, 2, 7])),
            ("anonymous", None),
        ] {
            topic.add_subscriber(Arc::new(Named(name, id, Arc::clone(&log))));
        }
        let taken = |log: &Log| {
            let mut seen = std::mem::take(&mut *log.lock().expect("log"));
            seen.sort_unstable();
            seen
        };

        topic.deliver_writer_heartbeat_to([7; 16], 1, None, [0, 0, 1, 7]);
        topic.deliver_writer_gap_to([7; 16], 1, 2, vec![1], [0, 0, 2, 7], None);
        assert_eq!(taken(&log), vec![("a", "hb"), ("b", "gap")]);

        topic.deliver_writer_heartbeat([7; 16], 1);
        topic.deliver_writer_gap([7; 16], 1, 2, vec![1]);
        assert_eq!(
            taken(&log),
            vec![
                ("a", "gap"),
                ("a", "hb"),
                ("anonymous", "gap"),
                ("anonymous", "hb"),
                ("b", "gap"),
                ("b", "hb"),
            ]
        );
    }
}
