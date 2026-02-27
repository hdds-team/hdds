// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

    use super::*;
    use crate::transport::lowbw::link::LoopbackLink;

    #[test]
    fn test_config_presets() {
        let slow = LowBwConfig::slow_serial();
        assert_eq!(slow.session.mtu, 256);
        assert_eq!(slow.scheduler.rate_bps, 9600);

        let sat = LowBwConfig::satellite();
        assert_eq!(sat.session.mtu, 512);
        assert!(sat.reliable.timeout_ms >= 2000);

        let radio = LowBwConfig::tactical_radio();
        assert_eq!(radio.delta.keyframe_redundancy, 3);

        let iot = LowBwConfig::iot_lora();
        assert_eq!(iot.session.mtu, 128);
        assert_eq!(iot.reliable.window_size, 1);

        let local = LowBwConfig::local_test();
        assert!(!local.compress_enabled);
    }

    #[test]
    fn test_transport_create() {
        let config = LowBwConfig::local_test();
        let link = Arc::new(LoopbackLink::new());
        let transport = LowBwTransport::new(config, link);

        assert!(!transport.is_connected());
        assert_eq!(transport.session_state(), SessionState::Idle);
    }

    #[test]
    fn test_register_streams() {
        let config = LowBwConfig::local_test();
        let link = Arc::new(LoopbackLink::new());
        let mut transport = LowBwTransport::new(config, link);

        // Register TX stream
        let tx_config = StreamConfig {
            topic_hash: 0x1234,
            type_hash: 0x5678,
            priority: Priority::P1,
            reliable: false,
            delta_enabled: false,
        };
        transport
            .register_tx_stream(StreamHandle(1), tx_config.clone())
            .unwrap();

        // Register RX stream
        transport
            .register_rx_stream(StreamHandle(1), tx_config)
            .unwrap();

        assert!(transport.tx_streams.contains_key(&StreamHandle(1)));
        assert!(transport.rx_streams.contains_key(&StreamHandle(1)));
    }

    #[test]
    fn test_send_unknown_stream() {
        let config = LowBwConfig::local_test();
        let link = Arc::new(LoopbackLink::new());
        let mut transport = LowBwTransport::new(config, link);

        let result = transport.send(StreamHandle(99), b"test", Priority::P1);
        assert!(matches!(result, Err(TransportError::UnknownStream(99))));
    }

    #[test]
    fn test_send_basic() {
        let config = LowBwConfig::local_test();
        let link = Arc::new(LoopbackLink::new());
        let mut transport = LowBwTransport::new(config, link);

        let stream_config = StreamConfig {
            priority: Priority::P1,
            ..Default::default()
        };
        transport
            .register_tx_stream(StreamHandle(1), stream_config)
            .unwrap();

        // Send data
        transport
            .send(StreamHandle(1), b"hello world", Priority::P1)
            .unwrap();

        assert!(transport.stats.p1_records > 0);
    }

    #[test]
    fn test_send_with_fragmentation() {
        let mut config = LowBwConfig::local_test();
        config.session.mtu = 32; // Force fragmentation

        let link = Arc::new(LoopbackLink::new());
        let mut transport = LowBwTransport::new(config, link);

        let stream_config = StreamConfig::default();
        transport
            .register_tx_stream(StreamHandle(1), stream_config)
            .unwrap();

        // Send large data that requires fragmentation
        let large_data = vec![0xAA; 100];
        transport
            .send(StreamHandle(1), &large_data, Priority::P1)
            .unwrap();

        assert!(transport.stats.fragments_sent > 1);
    }

    #[test]
    fn test_stats() {
        let config = LowBwConfig::local_test();
        let link = Arc::new(LoopbackLink::new());
        let mut transport = LowBwTransport::new(config, link);

        let stream_config = StreamConfig::default();
        transport
            .register_tx_stream(StreamHandle(1), stream_config)
            .unwrap();

        transport
            .send(StreamHandle(1), b"test1", Priority::P0)
            .unwrap();
        transport
            .send(StreamHandle(1), b"test2", Priority::P1)
            .unwrap();
        transport
            .send(StreamHandle(1), b"test3", Priority::P2)
            .unwrap();

        let stats = transport.stats();
        assert_eq!(stats.p0_records, 1);
        assert_eq!(stats.p1_records, 1);
        assert_eq!(stats.p2_records, 1);

        transport.reset_stats();
        let stats = transport.stats();
        assert_eq!(stats.p0_records, 0);
    }

    #[test]
    fn test_config_default() {
        let config = LowBwConfig::default();
        assert!(config.delta_enabled);
        assert!(config.compress_enabled);
    }

    #[test]
    fn test_stream_config_default() {
        let config = StreamConfig::default();
        assert_eq!(config.priority, Priority::P1);
        assert!(!config.reliable);
        assert!(!config.delta_enabled);
    }

    #[test]
    fn test_transport_error_display() {
        let err = TransportError::NotConnected;
        assert_eq!(format!("{}", err), "session not connected");

        let err = TransportError::UnknownStream(5);
        assert_eq!(format!("{}", err), "unknown stream 5");
    }
