// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

    use super::*;
    use crate::transport::lowbw::crc::crc16_ccitt;

    #[test]
    fn test_loopback_link_basic() {
        let link = LoopbackLink::new();

        // Send frame
        let frame = b"Hello, LBW!";
        link.send(frame).expect("send");

        // Receive frame
        let mut buf = [0u8; 64];
        let n = link.recv(&mut buf).expect("recv");
        assert_eq!(&buf[..n], frame);

        // Stats
        let stats = link.stats();
        assert_eq!(stats.frames_sent, 1);
        assert_eq!(stats.frames_received, 1);
    }

    #[test]
    fn test_loopback_link_empty() {
        let link = LoopbackLink::new();
        let mut buf = [0u8; 64];

        let result = link.recv(&mut buf);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::WouldBlock);
    }

    #[test]
    fn test_loopback_link_multiple() {
        let link = LoopbackLink::new();

        // Send multiple frames
        link.send(b"Frame 1").expect("send");
        link.send(b"Frame 2").expect("send");
        link.send(b"Frame 3").expect("send");

        let mut buf = [0u8; 64];

        // Receive in LIFO order (stack)
        let n = link.recv(&mut buf).expect("recv");
        assert_eq!(&buf[..n], b"Frame 3");

        let n = link.recv(&mut buf).expect("recv");
        assert_eq!(&buf[..n], b"Frame 2");

        let n = link.recv(&mut buf).expect("recv");
        assert_eq!(&buf[..n], b"Frame 1");
    }

    #[test]
    fn test_simlink_perfect() {
        let link = SimLink::perfect();

        // Send frame
        let frame = b"Test frame";
        link.send(frame).expect("send");

        // Should be immediately available (no delay)
        let mut buf = [0u8; 64];
        let n = link.recv(&mut buf).expect("recv");
        assert_eq!(&buf[..n], frame);
    }

    #[test]
    fn test_simlink_loss() {
        let config = SimLinkConfig {
            loss_rate: 1.0, // 100% loss
            ..Default::default()
        };
        let link = SimLink::new(config);

        // Send frame
        link.send(b"Lost frame").expect("send");

        // Should be dropped
        let mut buf = [0u8; 64];
        let result = link.recv(&mut buf);
        assert!(result.is_err());

        let stats = link.stats();
        assert_eq!(stats.frames_dropped, 1);
    }

    #[test]
    fn test_simlink_partial_loss() {
        let config = SimLinkConfig {
            loss_rate: 0.5, // 50% loss
            ..Default::default()
        };
        let link = SimLink::new(config);
        link.set_seed(12345); // Reproducible

        // Send many frames
        let mut sent = 0;
        for _ in 0..100 {
            link.send(b"Test").expect("send");
            sent += 1;
        }

        // Receive all available
        let mut received = 0;
        let mut buf = [0u8; 64];
        while link.recv(&mut buf).is_ok() {
            received += 1;
        }

        let stats = link.stats();
        assert_eq!(stats.frames_sent + stats.frames_dropped, sent);
        // With 50% loss, expect roughly half received
        assert!(
            received > 20 && received < 80,
            "received {} frames",
            received
        );
    }

    #[test]
    fn test_simlink_delay() {
        let config = SimLinkConfig {
            delay_ms: 50,
            ..Default::default()
        };
        let link = SimLink::new(config);

        // Send frame
        let start = Instant::now();
        link.send(b"Delayed").expect("send");

        // Should not be immediately available
        let mut buf = [0u8; 64];
        let result = link.recv(&mut buf);
        assert!(result.is_err());

        // Wait for delivery
        std::thread::sleep(Duration::from_millis(60));
        let n = link.recv(&mut buf).expect("recv after delay");
        assert_eq!(&buf[..n], b"Delayed");

        let elapsed = start.elapsed();
        assert!(elapsed >= Duration::from_millis(50));
    }

    #[test]
    fn test_simlink_recv_timeout() {
        let config = SimLinkConfig {
            delay_ms: 100,
            ..Default::default()
        };
        let link = SimLink::new(config);

        // Send frame
        link.send(b"Delayed").expect("send");

        let mut buf = [0u8; 64];

        // Timeout too short
        let result = link.recv_timeout(&mut buf, Duration::from_millis(20));
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);

        // Timeout long enough
        let n = link
            .recv_timeout(&mut buf, Duration::from_millis(150))
            .expect("recv with timeout");
        assert_eq!(&buf[..n], b"Delayed");
    }

    #[test]
    fn test_simlink_corruption() {
        let config = SimLinkConfig {
            corruption_rate: 1.0, // Corrupt every byte
            ..Default::default()
        };
        let link = SimLink::new(config);
        link.set_seed(99999);

        // Send frame with known CRC
        let original = b"Test data for corruption";
        let original_crc = crc16_ccitt(original);

        link.send(original).expect("send");

        let mut buf = [0u8; 64];
        let n = link.recv(&mut buf).expect("recv");

        // Frame should be corrupted
        let received_crc = crc16_ccitt(&buf[..n]);
        assert_ne!(
            received_crc, original_crc,
            "CRC should differ after corruption"
        );

        let stats = link.stats();
        assert!(stats.frames_corrupted > 0);
    }

    #[test]
    fn test_simlink_queue_overflow() {
        let config = SimLinkConfig {
            queue_capacity: 3,
            delay_ms: 1000, // Long delay to fill queue
            ..Default::default()
        };
        let link = SimLink::new(config);

        // Fill queue
        for i in 0..5 {
            link.send(format!("Frame {}", i).as_bytes()).expect("send");
        }

        let stats = link.stats();
        assert_eq!(stats.frames_sent, 3); // Only 3 fit
        assert_eq!(stats.frames_dropped, 2); // 2 dropped due to overflow
    }

    #[test]
    fn test_simlink_presets() {
        // Just verify presets don't panic
        let _slow = SimLink::new(SimLinkConfig::slow_serial());
        let _sat = SimLink::new(SimLinkConfig::satellite());
        let _tac = SimLink::new(SimLinkConfig::tactical_radio());
    }

    #[test]
    fn test_link_stats_reset() {
        let link = LoopbackLink::new();

        link.send(b"Test").expect("send");
        let mut buf = [0u8; 64];
        let _ = link.recv(&mut buf);

        let stats = link.stats();
        assert_eq!(stats.frames_sent, 1);
        assert_eq!(stats.frames_received, 1);

        link.reset_stats();

        let stats = link.stats();
        assert_eq!(stats.frames_sent, 0);
        assert_eq!(stats.frames_received, 0);
    }
