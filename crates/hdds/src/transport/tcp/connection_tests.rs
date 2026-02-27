// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

    use super::*;
    use crate::transport::tcp::byte_stream::mock::MockStream;

    fn make_config() -> TcpConfig {
        TcpConfig {
            max_message_size: 1024,
            ..TcpConfig::enabled()
        }
    }

    #[test]
    fn test_connection_state_display() {
        assert_eq!(ConnectionState::Idle.to_string(), "Idle");
        assert_eq!(ConnectionState::Connecting.to_string(), "Connecting");
        assert_eq!(ConnectionState::Connected.to_string(), "Connected");
        assert_eq!(ConnectionState::Closed.to_string(), "Closed");
    }

    #[test]
    fn test_connection_state_queries() {
        assert!(ConnectionState::Connected.is_operational());
        assert!(!ConnectionState::Connecting.is_operational());

        assert!(ConnectionState::Closed.is_terminal());
        assert!(ConnectionState::Failed.is_terminal());
        assert!(!ConnectionState::Connected.is_terminal());

        assert!(ConnectionState::Connecting.is_connecting());
        assert!(ConnectionState::Reconnecting.is_connecting());
        assert!(!ConnectionState::Connected.is_connecting());
    }

    #[test]
    fn test_connection_new() {
        let stream = MockStream::new();
        let config = make_config();

        let conn = TcpConnection::new(
            Box::new(stream),
            "127.0.0.1:8080".parse().unwrap(),
            true,
            &config,
        )
        .unwrap();

        assert!(conn.is_connected());
        assert!(conn.is_initiator());
        assert_eq!(conn.state(), ConnectionState::Connected);
        assert!(conn.send_queue_is_empty());
    }

    #[test]
    fn test_connection_send_queue() {
        let stream = MockStream::new();
        let config = make_config();

        let mut conn = TcpConnection::new(
            Box::new(stream),
            "127.0.0.1:8080".parse().unwrap(),
            true,
            &config,
        )
        .unwrap();

        // Queue messages
        conn.send(b"hello").unwrap();
        conn.send(b"world").unwrap();

        assert_eq!(conn.send_queue_len(), 2);
        assert!(!conn.send_queue_is_empty());
    }

    #[test]
    fn test_connection_flush() {
        let stream = MockStream::new();
        let config = make_config();

        let mut conn = TcpConnection::new(
            Box::new(stream),
            "127.0.0.1:8080".parse().unwrap(),
            true,
            &config,
        )
        .unwrap();

        conn.send(b"test message").unwrap();
        let result = conn.flush().unwrap();

        assert_eq!(result, FlushResult::Complete);
        assert!(conn.send_queue_is_empty());
        assert_eq!(conn.stats().messages_sent, 1);
    }

    #[test]
    fn test_connection_recv() {
        let stream = MockStream::new();

        // Feed a framed message
        let frame = FrameCodec::encode(b"incoming data");
        stream.feed_read_data(&frame);

        let config = make_config();

        let mut conn = TcpConnection::new(
            Box::new(stream),
            "127.0.0.1:8080".parse().unwrap(),
            false,
            &config,
        )
        .unwrap();

        let msg = conn.recv().unwrap().unwrap();
        assert_eq!(msg, b"incoming data");
        assert_eq!(conn.stats().messages_received, 1);
    }

    #[test]
    fn test_connection_recv_all() {
        let stream = MockStream::new();

        // Feed multiple framed messages
        stream.feed_read_data(&FrameCodec::encode(b"msg1"));
        stream.feed_read_data(&FrameCodec::encode(b"msg2"));
        stream.feed_read_data(&FrameCodec::encode(b"msg3"));

        let config = make_config();

        let mut conn = TcpConnection::new(
            Box::new(stream),
            "127.0.0.1:8080".parse().unwrap(),
            false,
            &config,
        )
        .unwrap();

        let messages = conn.recv_all().unwrap();
        assert_eq!(messages.len(), 3);
        assert_eq!(messages[0], b"msg1");
        assert_eq!(messages[1], b"msg2");
        assert_eq!(messages[2], b"msg3");
    }

    #[test]
    fn test_connection_close() {
        let stream = MockStream::new();
        let config = make_config();

        let mut conn = TcpConnection::new(
            Box::new(stream),
            "127.0.0.1:8080".parse().unwrap(),
            true,
            &config,
        )
        .unwrap();

        conn.close();
        assert_eq!(conn.state(), ConnectionState::Closed);
        assert!(conn.state().is_terminal());
    }

    #[test]
    fn test_send_not_connected() {
        let stream = MockStream::new();
        let config = make_config();

        let mut conn =
            TcpConnection::connecting(Box::new(stream), "127.0.0.1:8080".parse().unwrap(), &config)
                .unwrap();

        let result = conn.send(b"test");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::NotConnected);
    }

    #[test]
    fn test_tie_breaker_local_smaller() {
        let local = [
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let remote = [
            0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        // Local is smaller, so local is the "server"
        // Keep if we're the acceptor (not initiator)
        assert!(should_keep_connection(&local, &remote, false));
        assert!(!should_keep_connection(&local, &remote, true));
    }

    #[test]
    fn test_tie_breaker_remote_smaller() {
        let local = [
            0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let remote = [
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        // Remote is smaller, so remote is the "server"
        // Keep if we initiated (we connected to the server)
        assert!(!should_keep_connection(&local, &remote, false));
        assert!(should_keep_connection(&local, &remote, true));
    }

    #[test]
    fn test_tie_breaker_equal() {
        let guid = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
        ];

        // Same GUID (shouldn't happen in practice)
        // Local is NOT smaller (equal), so we're not the server
        assert!(!should_keep_connection(&guid, &guid, false));
        assert!(should_keep_connection(&guid, &guid, true));
    }

    #[test]
    fn test_connection_stats() {
        let stream = MockStream::new();
        stream.feed_read_data(&FrameCodec::encode(b"test"));

        let config = make_config();

        let mut conn = TcpConnection::new(
            Box::new(stream),
            "127.0.0.1:8080".parse().unwrap(),
            true,
            &config,
        )
        .unwrap();

        conn.send(b"outgoing").unwrap();
        conn.flush().unwrap();
        conn.recv().unwrap();

        let stats = conn.stats();
        assert_eq!(stats.messages_sent, 1);
        assert_eq!(stats.messages_received, 1);
        assert!(stats.bytes_sent > 0);
        assert!(stats.bytes_received > 0);
        assert!(stats.last_send_time.is_some());
        assert!(stats.last_recv_time.is_some());
    }

    #[test]
    fn test_flush_result() {
        assert_eq!(FlushResult::Complete, FlushResult::Complete);
        assert_ne!(FlushResult::Complete, FlushResult::WouldBlock);
    }

    #[test]
    fn test_clear_send_queue() {
        let stream = MockStream::new();
        let config = make_config();

        let mut conn = TcpConnection::new(
            Box::new(stream),
            "127.0.0.1:8080".parse().unwrap(),
            true,
            &config,
        )
        .unwrap();

        conn.send(b"msg1").unwrap();
        conn.send(b"msg2").unwrap();

        assert!(!conn.send_queue_is_empty());

        conn.clear_send_queue();

        assert!(conn.send_queue_is_empty());
        assert_eq!(conn.stats().send_queue_depth, 0);
    }
