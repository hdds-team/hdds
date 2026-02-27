// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

    use super::*;

    #[test]
    fn test_type_id_from_name() {
        let id1 = TypeId::from_type_name("Temperature");
        let id2 = TypeId::from_type_name("Temperature");
        let id3 = TypeId::from_type_name("Humidity");

        assert_eq!(id1, id2);
        assert_ne!(id1, id3);
    }

    #[test]
    fn test_match_key() {
        let key1 = MatchKey::from_names("sensor/temp", "Temperature");
        let key2 = MatchKey::from_names("sensor/temp", "Temperature");
        let key3 = MatchKey::from_names("sensor/temp", "Humidity");
        let key4 = MatchKey::from_names("sensor/humidity", "Temperature");

        assert_eq!(key1, key2);
        assert_ne!(key1, key3); // different type
        assert_ne!(key1, key4); // different topic
    }

    #[test]
    fn test_domain_state_register_writer() {
        let domain = Arc::new(DomainState::new(0));
        let key = MatchKey::from_names("test/topic", "TestType");
        let guid = GUID::zero();
        let merger = Arc::new(TopicMerger::new());

        let token = domain.register_writer(key.clone(), guid, merger, Reliability::BestEffort);

        assert_eq!(domain.endpoint_count(), 1);
        assert_eq!(domain.endpoint_count_for_key(&key), 1);
        assert_eq!(domain.find_writers(&key).len(), 1);
        assert_eq!(domain.find_readers(&key).len(), 0);

        drop(token);

        assert_eq!(domain.endpoint_count(), 0);
    }

    #[test]
    fn test_domain_state_register_reader() {
        let domain = Arc::new(DomainState::new(0));
        let key = MatchKey::from_names("test/topic", "TestType");
        let guid = GUID::zero();
        let ring = Arc::new(IndexRing::with_capacity(1024));

        let token = domain.register_reader(
            key.clone(),
            guid,
            ring,
            Reliability::BestEffort,
            |_merger| {
                // Bind callback (not called since no writers)
            },
        );

        assert_eq!(domain.endpoint_count(), 1);
        assert_eq!(domain.endpoint_count_for_key(&key), 1);
        assert_eq!(domain.find_writers(&key).len(), 0);
        assert_eq!(domain.find_readers(&key).len(), 1);

        drop(token);

        assert_eq!(domain.endpoint_count(), 0);
    }

    #[test]
    fn test_auto_bind_writer_first() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let domain = Arc::new(DomainState::new(0));
        let key = MatchKey::from_names("test/topic", "TestType");

        // Register writer first (Reliable)
        let writer_guid = GUID::zero();
        let merger = Arc::new(TopicMerger::new());
        let _writer_token =
            domain.register_writer(key.clone(), writer_guid, merger, Reliability::Reliable);

        // Register reader (BestEffort) - should auto-bind (Reliable writer -> any reader OK)
        let bound = Arc::new(AtomicBool::new(false));
        let bound_clone = bound.clone();
        let reader_guid = GUID::new([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], [0, 0, 0, 1]);
        let ring = Arc::new(IndexRing::with_capacity(1024));

        let _reader_token = domain.register_reader(
            key.clone(),
            reader_guid,
            ring,
            Reliability::BestEffort,
            move |_| {
                bound_clone.store(true, Ordering::SeqCst);
            },
        );

        assert!(
            bound.load(Ordering::SeqCst),
            "Reader should auto-bind to existing writer"
        );
    }

    #[test]
    fn test_auto_bind_reader_first() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let domain = Arc::new(DomainState::new(0));
        let key = MatchKey::from_names("test/topic", "TestType");

        // Register reader first (BestEffort)
        let bound = Arc::new(AtomicBool::new(false));
        let bound_clone = bound.clone();
        let reader_guid = GUID::zero();
        let ring = Arc::new(IndexRing::with_capacity(1024));

        let _reader_token = domain.register_reader(
            key.clone(),
            reader_guid,
            ring,
            Reliability::BestEffort,
            move |_| {
                bound_clone.store(true, Ordering::SeqCst);
            },
        );

        assert!(
            !bound.load(Ordering::SeqCst),
            "Reader should not bind yet (no writer)"
        );

        // Register writer (BestEffort) - should trigger auto-bind callback
        let writer_guid = GUID::new([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], [0, 0, 0, 1]);
        let merger = Arc::new(TopicMerger::new());
        let _writer_token =
            domain.register_writer(key.clone(), writer_guid, merger, Reliability::BestEffort);

        assert!(
            bound.load(Ordering::SeqCst),
            "Reader should auto-bind when writer appears"
        );
    }

    /// Test: BestEffort writer + Reliable reader = NO BIND (QoS incompatible)
    #[test]
    fn test_qos_besteffort_writer_reliable_reader_no_bind() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let domain = Arc::new(DomainState::new(0));
        let key = MatchKey::from_names("test/topic", "TestType");

        // Register BestEffort writer first
        let writer_guid = GUID::zero();
        let merger = Arc::new(TopicMerger::new());
        let _writer_token =
            domain.register_writer(key.clone(), writer_guid, merger, Reliability::BestEffort);

        // Register Reliable reader - should NOT auto-bind (incompatible QoS)
        let bound = Arc::new(AtomicBool::new(false));
        let bound_clone = bound.clone();
        let reader_guid = GUID::new([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], [0, 0, 0, 1]);
        let ring = Arc::new(IndexRing::with_capacity(1024));

        let _reader_token = domain.register_reader(
            key.clone(),
            reader_guid,
            ring,
            Reliability::Reliable,
            move |_| {
                bound_clone.store(true, Ordering::SeqCst);
            },
        );

        assert!(
            !bound.load(Ordering::SeqCst),
            "Reliable reader should NOT bind to BestEffort writer"
        );
    }

    /// Test: Reliable writer + BestEffort reader = BIND (QoS compatible)
    #[test]
    fn test_qos_reliable_writer_besteffort_reader_binds() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let domain = Arc::new(DomainState::new(0));
        let key = MatchKey::from_names("test/topic", "TestType");

        // Register Reliable writer first
        let writer_guid = GUID::zero();
        let merger = Arc::new(TopicMerger::new());
        let _writer_token =
            domain.register_writer(key.clone(), writer_guid, merger, Reliability::Reliable);

        // Register BestEffort reader - should auto-bind (Reliable writer compatible with any reader)
        let bound = Arc::new(AtomicBool::new(false));
        let bound_clone = bound.clone();
        let reader_guid = GUID::new([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], [0, 0, 0, 1]);
        let ring = Arc::new(IndexRing::with_capacity(1024));

        let _reader_token = domain.register_reader(
            key.clone(),
            reader_guid,
            ring,
            Reliability::BestEffort,
            move |_| {
                bound_clone.store(true, Ordering::SeqCst);
            },
        );

        assert!(
            bound.load(Ordering::SeqCst),
            "BestEffort reader should bind to Reliable writer"
        );
    }

    /// Test: Reader first, then BestEffort writer - Reliable reader should NOT bind
    #[test]
    fn test_qos_reader_first_besteffort_writer_no_bind() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let domain = Arc::new(DomainState::new(0));
        let key = MatchKey::from_names("test/topic", "TestType");

        // Register Reliable reader first
        let bound = Arc::new(AtomicBool::new(false));
        let bound_clone = bound.clone();
        let reader_guid = GUID::zero();
        let ring = Arc::new(IndexRing::with_capacity(1024));

        let _reader_token = domain.register_reader(
            key.clone(),
            reader_guid,
            ring,
            Reliability::Reliable,
            move |_| {
                bound_clone.store(true, Ordering::SeqCst);
            },
        );

        // Register BestEffort writer - should NOT trigger auto-bind (incompatible QoS)
        let writer_guid = GUID::new([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], [0, 0, 0, 1]);
        let merger = Arc::new(TopicMerger::new());
        let _writer_token =
            domain.register_writer(key.clone(), writer_guid, merger, Reliability::BestEffort);

        assert!(
            !bound.load(Ordering::SeqCst),
            "Reliable reader should NOT bind when BestEffort writer appears"
        );
    }

    #[test]
    fn test_domain_registry_get_or_create() {
        let registry = DomainRegistry::global();

        let domain1 = registry.get_or_create(42);
        let domain2 = registry.get_or_create(42);

        assert!(Arc::ptr_eq(&domain1, &domain2));
        assert_eq!(domain1.domain_id, 42);
    }

    #[test]
    fn test_domain_registry_cleanup() {
        // Use a local registry for isolated test
        let registry = DomainRegistry::new();

        {
            let _domain = registry.get_or_create(99);
            assert_eq!(registry.active_domain_count(), 1);
        }

        // Domain dropped, weak ref should be dead
        registry.cleanup_expired();
        assert_eq!(registry.active_domain_count(), 0);
    }

    #[test]
    fn test_bind_token_unregisters_on_drop() {
        let domain = Arc::new(DomainState::new(0));
        let key = MatchKey::from_names("test/topic", "TestType");
        let guid = GUID::zero();
        let merger = Arc::new(TopicMerger::new());

        {
            let _token = domain.register_writer(key.clone(), guid, merger, Reliability::BestEffort);
            assert_eq!(domain.endpoint_count(), 1);
        }

        // Token dropped - endpoint should be unregistered
        assert_eq!(domain.endpoint_count(), 0);
    }

    #[test]
    fn test_multiple_writers_same_topic() {
        let domain = Arc::new(DomainState::new(0));
        let key = MatchKey::from_names("test/topic", "TestType");

        let guid1 = GUID::zero();
        let guid2 = GUID::new([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], [0, 0, 0, 1]);
        let merger1 = Arc::new(TopicMerger::new());
        let merger2 = Arc::new(TopicMerger::new());

        let _token1 = domain.register_writer(key.clone(), guid1, merger1, Reliability::BestEffort);
        let _token2 = domain.register_writer(key.clone(), guid2, merger2, Reliability::Reliable);

        assert_eq!(domain.endpoint_count_for_key(&key), 2);
        assert_eq!(domain.find_writers(&key).len(), 2);
    }

    /// Integration test: verify end-to-end intra-process data flow
    ///
    /// This test verifies that:
    /// 1. Writer registration populates the merger
    /// 2. Reader auto-binds to writer via callback
    /// 3. Data written to merger reaches the reader's ring
    #[test]
    fn test_intra_process_data_flow() {
        use crate::core::rt::{get_slab_pool, IndexEntry};

        // Initialize slab pool for data allocation
        let _ = crate::core::rt::init_slab_pool();

        let domain = Arc::new(DomainState::new(42));
        let key = MatchKey::from_names("sensor/temp", "Temperature");

        // Create writer's merger
        let writer_merger = Arc::new(TopicMerger::new());
        let writer_guid = GUID::zero();

        // Register writer (Reliable for this test)
        let _writer_token = domain.register_writer(
            key.clone(),
            writer_guid,
            writer_merger.clone(),
            Reliability::Reliable,
        );

        // Create reader's ring
        let reader_ring = Arc::new(IndexRing::with_capacity(16));
        let reader_guid = GUID::new([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], [0, 0, 0, 1]);

        // Track binding
        use std::sync::atomic::{AtomicUsize, Ordering};
        let bind_count = Arc::new(AtomicUsize::new(0));
        let bind_count_clone = bind_count.clone();

        // Clone ring for callback
        let ring_for_callback = reader_ring.clone();

        // Register reader (BestEffort) - should auto-bind to existing Reliable writer
        let _reader_token = domain.register_reader(
            key.clone(),
            reader_guid,
            reader_ring.clone(),
            Reliability::BestEffort,
            move |merger| {
                bind_count_clone.fetch_add(1, Ordering::SeqCst);

                // Create notification (no-op for test)
                let notify: Arc<dyn Fn() + Send + Sync> = Arc::new(|| {});

                // Register with merger
                let registration =
                    crate::core::rt::MergerReader::new(ring_for_callback.clone(), notify);
                merger.add_reader(registration);
            },
        );

        assert_eq!(
            bind_count.load(Ordering::SeqCst),
            1,
            "Reader should bind once to writer"
        );
        assert_eq!(
            writer_merger.reader_count(),
            1,
            "Writer merger should have 1 reader"
        );

        // Write data through merger
        let slab_pool = get_slab_pool();
        let data = b"Hello intra-process!";
        let (handle, buf) = slab_pool.reserve(data.len()).expect("slab reserve");
        buf[..data.len()].copy_from_slice(data);
        slab_pool.commit(handle, data.len());

        let entry = IndexEntry {
            seq: 1,
            handle,
            len: data.len() as u32,
            flags: 0x01,
            timestamp_ns: 0,
        };

        let push_ok = writer_merger.push(entry);
        assert!(push_ok, "Merger push should succeed");

        // Read data from reader's ring
        let received = reader_ring.pop();
        assert!(received.is_some(), "Reader should receive data");

        let received_entry = received.unwrap();
        assert_eq!(received_entry.seq, 1);
        assert_eq!(received_entry.len, data.len() as u32);

        // Verify data content
        let received_buf = slab_pool.get_buffer(received_entry.handle);
        assert_eq!(&received_buf[..data.len()], data);

        // Cleanup
        slab_pool.release(received_entry.handle);
    }
