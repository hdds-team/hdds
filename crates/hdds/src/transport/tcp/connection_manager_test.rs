// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

use super::*;

fn make_guid(id: u8) -> GuidPrefix {
    [id, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
}

#[test]
fn test_pending_connection_outbound() {
    let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
    let guid = make_guid(1);
    let pending = PendingConnection::outbound(addr, 1, Some(guid));

    assert!(pending.is_initiator);
    assert_eq!(pending.addr, addr);
    assert_eq!(pending.conn_id, 1);
    assert_eq!(pending.expected_guid, Some(guid));
    assert_eq!(pending.attempt_count, 1);
}

#[test]
fn test_pending_connection_inbound() {
    let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
    let pending = PendingConnection::inbound(addr, 2);

    assert!(!pending.is_initiator);
    assert_eq!(pending.conn_id, 2);
    assert!(pending.expected_guid.is_none());
}

#[test]
fn test_pending_connection_timeout() {
    let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
    let pending = PendingConnection::outbound(addr, 1, None);

    // Not timed out immediately
    assert!(!pending.is_timeout(Duration::from_secs(1)));

    // Would time out with zero duration
    assert!(pending.is_timeout(Duration::ZERO));
}

#[test]
fn test_config_from_tcp_config() {
    let tcp_config = TcpConfig {
        connect_timeout: Duration::from_secs(10),
        reconnect_delay: Duration::from_secs(2),
        max_reconnect_attempts: 5,
        ..Default::default()
    };

    let config: ConnectionManagerConfig = (&tcp_config).into();

    assert_eq!(config.connect_timeout, Duration::from_secs(10));
    assert_eq!(config.reconnect_delay, Duration::from_secs(2));
    assert_eq!(config.max_reconnect_attempts, 5);
    assert!(config.auto_reconnect);
}

#[test]
fn test_connection_event_debug() {
    let guid = make_guid(1);

    let event = ConnectionEvent::Connected {
        remote_guid: guid,
        remote_addr: "127.0.0.1:8080".parse().unwrap(),
    };
    let _ = format!("{:?}", event);

    let event = ConnectionEvent::Disconnected {
        remote_guid: guid,
        reason: Some("test".to_string()),
    };
    let _ = format!("{:?}", event);

    let event = ConnectionEvent::MessageReceived {
        remote_guid: guid,
        payload: vec![1, 2, 3],
    };
    let _ = format!("{:?}", event);
}

#[test]
fn test_connection_info() {
    let info = ConnectionInfo {
        conn_id: 1,
        remote_addr: "127.0.0.1:8080".parse().unwrap(),
        remote_guid: make_guid(2),
        is_initiator: true,
        state: ConnectionState::Connected,
        connected_at: Instant::now(),
        messages_sent: 10,
        messages_received: 20,
        last_activity: Instant::now(),
    };

    assert_eq!(info.conn_id, 1);
    assert!(info.is_initiator);
    assert_eq!(info.messages_sent, 10);
}

// Integration tests would require I/O thread setup which is complex
// for unit tests. Focus on data structure tests here.
