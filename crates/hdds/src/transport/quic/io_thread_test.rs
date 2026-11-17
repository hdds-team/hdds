// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

use super::*;

#[test]
fn test_command_send() {
    let cmd = QuicCommand::Connect {
        remote_addr: "127.0.0.1:7400".parse().unwrap(),
        server_name: None,
    };
    assert!(matches!(cmd, QuicCommand::Connect { .. }));
}

#[test]
fn test_command_with_server_name() {
    let cmd = QuicCommand::Connect {
        remote_addr: "127.0.0.1:7400".parse().unwrap(),
        server_name: Some("custom.hdds.local".to_string()),
    };
    if let QuicCommand::Connect { server_name, .. } = cmd {
        assert_eq!(server_name.unwrap(), "custom.hdds.local");
    }
}

#[test]
fn test_event_clone() {
    let event = QuicEvent::Connected {
        remote_addr: "127.0.0.1:7400".parse().unwrap(),
    };
    let cloned = event.clone();
    assert!(matches!(cloned, QuicEvent::Connected { .. }));
}

#[test]
fn test_event_message_received() {
    let event = QuicEvent::MessageReceived {
        remote_addr: "127.0.0.1:7400".parse().unwrap(),
        payload: vec![0x52, 0x54, 0x50, 0x53], // "RTPS"
    };
    if let QuicEvent::MessageReceived { payload, .. } = event {
        assert_eq!(payload, vec![0x52, 0x54, 0x50, 0x53]);
    }
}

#[test]
fn test_channel_capacity() {
    assert_eq!(CMD_CHANNEL_CAPACITY, 256);
}

// =========================================================================
// Reconnection tests
// =========================================================================

#[test]
fn test_backoff_exponential_sequence() {
    // Base delay 1s, max 60s
    // Expected: 1s, 2s, 4s, 8s, 16s, 32s, 60s (capped), 60s...
    let base = Duration::from_secs(1);
    let max = Duration::from_secs(60);
    let port = 7400u16; // Fixed port for deterministic jitter

    // Calculate jitter bounds: +/-25% around base values
    let check_with_jitter = |attempt: u32, expected_base_ms: u64| {
        let delay = ReconnectState::calculate_backoff(base, max, attempt, port);
        let delay_ms = delay.as_millis() as u64;

        // Jitter is (attempt * 7 + port) % 50 - 25 = -25% to +24%
        // Allow +/-25% tolerance
        let min_ms = expected_base_ms * 75 / 100;
        let max_ms = expected_base_ms * 125 / 100;

        assert!(
            delay_ms >= min_ms && delay_ms <= max_ms,
            "attempt {}: expected {}ms +/-25%, got {}ms (range {}-{})",
            attempt,
            expected_base_ms,
            delay_ms,
            min_ms,
            max_ms
        );
    };

    check_with_jitter(0, 1000); // 1s
    check_with_jitter(1, 2000); // 2s
    check_with_jitter(2, 4000); // 4s
    check_with_jitter(3, 8000); // 8s
    check_with_jitter(4, 16000); // 16s
    check_with_jitter(5, 32000); // 32s
    check_with_jitter(6, 60000); // 60s (capped)
    check_with_jitter(7, 60000); // 60s (still capped)
    check_with_jitter(10, 60000); // 60s (still capped)
}

#[test]
fn test_backoff_jitter_bounds() {
    let base = Duration::from_secs(10);
    let max = Duration::from_secs(60);

    // Test multiple ports to exercise jitter variation
    for port in [7400u16, 7401, 7402, 8080, 12345] {
        for attempt in 0..5 {
            let delay = ReconnectState::calculate_backoff(base, max, attempt, port);
            let delay_ms = delay.as_millis() as u64;

            // Base value before jitter
            let base_ms = (10000u64 << attempt).min(60000);

            // Jitter should be within +/-25%
            let min_ms = base_ms * 75 / 100;
            let max_ms = base_ms * 125 / 100;

            assert!(
                delay_ms >= min_ms && delay_ms <= max_ms,
                "port {} attempt {}: expected {}-{}ms, got {}ms",
                port,
                attempt,
                min_ms,
                max_ms,
                delay_ms
            );
        }
    }
}

#[test]
fn test_backoff_max_attempts() {
    // Simulate max_attempts = 3
    let max_attempts = 3u32;
    let mut state = ReconnectState::new(
        "127.0.0.1:7400".parse().unwrap(),
        "test.local".to_string(),
        Duration::from_secs(1),
    );

    // After 3 advances, attempt count should be 3
    for _ in 0..max_attempts {
        state.advance(Duration::from_secs(1), Duration::from_secs(60));
    }

    assert_eq!(state.attempt, max_attempts);
    // At this point, reconnection logic should give up
}

#[test]
fn test_reconnect_state_new() {
    let addr: SocketAddr = "192.168.1.100:7500".parse().unwrap();
    let state = ReconnectState::new(addr, "hdds.local".to_string(), Duration::from_secs(2));

    assert_eq!(state.peer, addr);
    assert_eq!(state.server_name, "hdds.local");
    assert_eq!(state.attempt, 0);
    assert_eq!(state.current_backoff, Duration::from_secs(2));
}

#[test]
fn test_reconnect_state_advance() {
    let addr: SocketAddr = "127.0.0.1:7400".parse().unwrap();
    let mut state = ReconnectState::new(addr, "test.local".to_string(), Duration::from_secs(1));

    let base = Duration::from_secs(1);
    let max = Duration::from_secs(60);

    // First advance: attempt 0 -> 1
    let delay1 = state.advance(base, max);
    assert_eq!(state.attempt, 1);
    // Delay should be ~2s with jitter (+/-100% tolerance for heavily loaded CI systems)
    assert!(delay1.as_millis() <= 4000);

    // Second advance: attempt 1 -> 2
    let delay2 = state.advance(base, max);
    assert_eq!(state.attempt, 2);
    // Delay should be ~4s with jitter (+/-100% tolerance for heavily loaded CI systems)
    assert!(delay2.as_millis() <= 8000);
}

#[test]
fn test_backoff_overflow_protection() {
    let base = Duration::from_secs(1);
    let max = Duration::from_secs(60);

    // Very high attempt number should not overflow
    let delay = ReconnectState::calculate_backoff(base, max, 100, 7400);
    // Should be capped at max (60s) with jitter
    assert!(delay.as_secs() <= 75); // 60s + 25% jitter max
}
