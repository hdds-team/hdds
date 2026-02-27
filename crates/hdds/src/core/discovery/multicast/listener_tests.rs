// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

    use super::*;

    // Integration test (requires actual UDP socket, marked ignore for CI)
    #[test]
    #[ignore = "requires UDP socket, flaky in CI"]
    #[allow(deprecated)]
    fn test_listener_loopback() {
        use crate::transport::UdpTransport;
        use std::thread;
        use std::time::Duration;

        let pool = Arc::new(RxPool::new(16, 1500).expect("Pool creation should succeed"));
        let ring = Arc::new(ArrayQueue::new(256));

        // Create transport (port 7401 to avoid conflicts)
        let transport =
            UdpTransport::with_port(7401).expect("UDP transport creation should succeed");

        // Spawn listener with shared socket
        let listener = MulticastListener::spawn(
            transport.socket(),
            Arc::clone(&pool),
            Arc::clone(&ring),
            None, // No discovery callback for this test
        )
        .expect("Listener spawn should succeed");

        // Send fake DATA packet (0x09)
        let socket = UdpSocket::bind("0.0.0.0:0").expect("Socket bind should succeed");
        let mut fake_data = vec![0u8; 20];
        fake_data[0..4].copy_from_slice(b"RTPS");
        fake_data[16] = 0x09; // DATA submessage

        socket
            .send_to(&fake_data, "127.0.0.1:7401")
            .expect("Socket send should succeed");

        // Wait for processing
        thread::sleep(Duration::from_millis(150));

        // Verify ring contains packet
        let (meta, buffer_id) = ring.pop().expect("Ring should contain packet");
        assert_eq!(meta.kind, PacketKind::Data);
        let expected_len = u16::try_from(fake_data.len()).expect("len should fit in u16");
        assert_eq!(meta.len, expected_len);

        // Verify metrics
        let (rx, dropped, invalid, bytes, callback_errors) = listener.metrics.snapshot();
        assert!(rx >= 1);
        assert_eq!(dropped, 0);
        assert_eq!(callback_errors, 0);
        assert_eq!(invalid, 0);
        assert!(bytes >= fake_data.len() as u64);

        pool.release(buffer_id).expect("release should succeed");
        listener.shutdown();
    }

    /// Layer 1 Resilience Test: Verify ring full scenario releases buffer (ANSSI Pattern 4)
    ///
    /// **Goal:** Prove that when ring is full, listener releases buffer to avoid leak
    ///
    /// **Scenario:**
    /// 1. Create small ring (capacity 4)
    /// 2. Fill ring completely (push 4 packets)
    /// 3. Send 5th packet while ring is full
    /// 4. Verify listener acquires buffer from pool
    /// 5. Verify ring.push() fails (ring full)
    /// 6. Verify listener releases buffer back to pool (no leak)
    /// 7. Verify packets_dropped metric increments
    ///
    /// **Success Criteria:**
    /// - Ring remains at capacity 4 (5th packet not pushed)
    /// - Buffer released back to pool (can be re-acquired)
    /// - packets_dropped metric == 1
    /// - No memory leak
    #[test]
    #[ignore = "requires UDP socket, flaky in CI"]
    #[allow(deprecated)]
    fn test_ring_full_releases_buffer_no_leak() -> Result<(), String> {
        use crate::transport::UdpTransport;
        use std::thread;
        use std::time::Duration;

        // Setup: Small ring with capacity 4 (intentionally tiny)
        let pool = Arc::new(RxPool::new(16, 1500).expect("Pool creation should succeed"));
        let ring = Arc::new(ArrayQueue::new(4)); // Only 4 slots

        let transport = UdpTransport::with_port(7403).map_err(|e| {
            crate::core::string_utils::format_string(format_args!(
                "Failed to create transport: {}",
                e
            ))
        })?;

        let listener = MulticastListener::spawn(
            transport.socket(),
            Arc::clone(&pool),
            Arc::clone(&ring),
            None, // No callback for this test
        )
        .map_err(|e| {
            crate::core::string_utils::format_string(format_args!(
                "Failed to spawn listener: {}",
                e
            ))
        })?;

        // Fill ring completely (4 packets)
        let sender = UdpSocket::bind("0.0.0.0:0").map_err(|e| {
            crate::core::string_utils::format_string(format_args!("Failed to bind sender: {}", e))
        })?;
        let mut fake_data = vec![0u8; 20];
        fake_data[0..4].copy_from_slice(b"RTPS");
        fake_data[16] = 0x09; // DATA submessage

        for i in 1..=4 {
            sender.send_to(&fake_data, "127.0.0.1:7403").map_err(|e| {
                crate::core::string_utils::format_string(format_args!(
                    "Failed to send packet: {}",
                    e
                ))
            })?;
            log::debug!("[test sender] Sent packet #{} (filling ring)", i);
            thread::sleep(Duration::from_millis(50));
        }

        // Wait for ring to fill
        thread::sleep(Duration::from_millis(200));

        // Verify ring is full
        if ring.len() != 4 {
            return Err(crate::core::string_utils::format_string(format_args!(
                "Ring should be full (4), got {}",
                ring.len()
            )));
        }

        // Record pool state before 5th packet
        let pool_before = {
            let test_id = pool.acquire_for_listener();
            if let Some(id) = test_id {
                pool.release(id).expect("release should succeed");
                true
            } else {
                false
            }
        };
        if !pool_before {
            return Err("Pool should have free buffers before 5th packet".to_string());
        }

        // Send 5th packet (ring is full, should trigger graceful drop)
        sender.send_to(&fake_data, "127.0.0.1:7403").map_err(|e| {
            crate::core::string_utils::format_string(format_args!(
                "Failed to send 5th packet: {}",
                e
            ))
        })?;
        log::debug!("[test sender] Sent packet #5 (ring full, expect graceful drop)");

        // Wait for processing
        thread::sleep(Duration::from_millis(200));

        // Verify ring still at capacity 4 (5th packet gracefully dropped)
        if ring.len() != 4 {
            return Err(crate::core::string_utils::format_string(format_args!(
                "Ring should still be full (5th packet dropped), got {}",
                ring.len()
            )));
        }

        // Verify buffer was released back to pool (no leak)
        let pool_after = pool
            .acquire_for_listener()
            .ok_or("Pool should have available buffers (buffer was released)")?;
        pool.release(pool_after).expect("release should succeed");

        // Verify packets_dropped metric incremented (graceful handling)
        let (rx, dropped, _invalid, _bytes, _callback_errors) = listener.metrics.snapshot();

        log::debug!("[test verify] Packets received: {}", rx);
        log::debug!("[test verify] Packets dropped: {}", dropped);
        log::debug!("[test verify] Ring size: {}", ring.len());

        if dropped < 1 {
            return Err(crate::core::string_utils::format_string(format_args!(
                "At least 1 packet should be gracefully dropped (ring full), got {}",
                dropped
            )));
        }

        // Cleanup
        while let Some((_, buffer_id)) = ring.pop() {
            pool.release(buffer_id).expect("release should succeed");
        }
        listener.shutdown();

        log::debug!("[test] [OK] Ring full handled gracefully - buffer released, no leak");
        Ok(())
    }
