// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

use super::*;
use crate::transport::lowbw::link::{LoopbackLink, LowBwLink, SimLink, SimLinkConfig};

#[test]
fn test_session_initial_state() {
    let session = Session::new(SessionConfig::default());
    assert_eq!(session.state(), SessionState::Idle);
    assert!(!session.is_established());
}

#[test]
fn test_session_start() {
    let mut session = Session::new(SessionConfig::default());
    session.start();

    assert_eq!(session.state(), SessionState::Connecting);
    assert!(session.poll_send().is_some()); // Should have HELLO queued
}

#[test]
fn test_session_hello_retry() {
    let config = SessionConfig {
        hello_interval: Duration::from_millis(10),
        hello_max_retries: 3,
        ..Default::default()
    };
    let mut session = Session::new(config);
    session.start();

    // Consume initial HELLO
    let _ = session.poll_send();

    // Wait and tick to trigger retry
    std::thread::sleep(Duration::from_millis(15));
    session.tick();

    assert_eq!(session.state(), SessionState::Connecting);
    assert!(session.poll_send().is_some()); // Should have retransmit
    assert_eq!(session.stats.hellos_sent, 2);
}

#[test]
fn test_session_max_retries() {
    let config = SessionConfig {
        hello_interval: Duration::from_millis(5),
        hello_max_retries: 2,
        ..Default::default()
    };
    let mut session = Session::new(config);
    session.start();

    // Exhaust retries
    for _ in 0..5 {
        let _ = session.poll_send();
        std::thread::sleep(Duration::from_millis(10));
        session.tick();
    }

    assert_eq!(session.state(), SessionState::Failed);
}

#[test]
fn test_session_handshake_loopback() {
    let link = LoopbackLink::new();

    let config = SessionConfig::default();
    let mut session_a = Session::new(config.clone());
    let mut session_b = Session::new(SessionConfig {
        node_id: 1,
        ..config
    });

    // A starts
    session_a.start();

    // A sends HELLO
    if let Some(frame) = session_a.poll_send() {
        link.send(&frame).expect("send");
    }

    // B receives HELLO
    let mut buf = [0u8; 256];
    let n = link.recv(&mut buf).expect("recv");
    session_b.on_receive(&buf[..n]).expect("process");

    // B should be established (passive open)
    assert!(session_b.is_established());

    // B sends response HELLO
    if let Some(frame) = session_b.poll_send() {
        link.send(&frame).expect("send");
    }

    // A receives response
    let n = link.recv(&mut buf).expect("recv");
    session_a.on_receive(&buf[..n]).expect("process");

    // A should be established
    assert!(session_a.is_established());

    // Check negotiated params
    let params_a = session_a.negotiated().expect("negotiated");
    let params_b = session_b.negotiated().expect("negotiated");

    assert_eq!(params_a.mtu, params_b.mtu);
    assert_eq!(params_a.remote_node_id, 1);
    assert_eq!(params_b.remote_node_id, 0);
}

#[test]
fn test_session_mtu_negotiation() {
    let link = LoopbackLink::new();

    let mut session_a = Session::new(SessionConfig {
        mtu: 512,
        ..Default::default()
    });
    let mut session_b = Session::new(SessionConfig {
        node_id: 1,
        mtu: 256,
        ..Default::default()
    });

    // Handshake
    session_a.start();

    if let Some(frame) = session_a.poll_send() {
        link.send(&frame).expect("send");
    }

    let mut buf = [0u8; 256];
    let n = link.recv(&mut buf).expect("recv");
    session_b.on_receive(&buf[..n]).expect("process");

    // Negotiated MTU should be min(512, 256) = 256
    assert_eq!(session_b.effective_mtu(), 256);
}

#[test]
fn test_session_feature_negotiation() {
    let link = LoopbackLink::new();

    let mut session_a = Session::new(SessionConfig {
        features: features::DELTA | features::COMPRESSION,
        ..Default::default()
    });
    let mut session_b = Session::new(SessionConfig {
        node_id: 1,
        features: features::DELTA | features::FRAGMENTATION,
        ..Default::default()
    });

    // Handshake
    session_a.start();

    if let Some(frame) = session_a.poll_send() {
        link.send(&frame).expect("send");
    }

    let mut buf = [0u8; 256];
    let n = link.recv(&mut buf).expect("recv");
    session_b.on_receive(&buf[..n]).expect("process");

    // Negotiated features should be intersection (DELTA only)
    let params = session_b.negotiated().expect("negotiated");
    assert_eq!(params.features, features::DELTA);
}

#[test]
fn test_session_reset() {
    let mut session = Session::new(SessionConfig::default());
    session.start();
    let _ = session.poll_send();

    session.reset();

    assert_eq!(session.state(), SessionState::Idle);
    assert!(session.negotiated().is_none());
}

#[test]
fn test_session_close() {
    let mut session = Session::new(SessionConfig::default());
    session.start();

    session.close();

    assert_eq!(session.state(), SessionState::Closed);
}

#[test]
fn test_session_under_loss() {
    // Test that session can establish under packet loss
    // With 30% loss both ways, we need many retries
    let config = SimLinkConfig {
        loss_rate: 0.30, // 30% loss
        ..Default::default()
    };
    let link_a_to_b = SimLink::new(config.clone());
    let link_b_to_a = SimLink::new(config);

    // Use deterministic seeds for reproducibility
    link_a_to_b.set_seed(42424242);
    link_b_to_a.set_seed(12121212);

    let session_config = SessionConfig {
        hello_interval: Duration::from_millis(10), // Fast retries
        hello_max_retries: 50,                     // Many retries to handle 30% loss
        ..Default::default()
    };

    let mut session_a = Session::new(session_config.clone());
    let mut session_b = Session::new(SessionConfig {
        node_id: 1,
        ..session_config
    });

    // B also starts (simultaneous open) for more robust connection
    session_a.start();
    session_b.start();

    let mut buf = [0u8; 256];
    let deadline = Instant::now() + Duration::from_secs(3);

    while Instant::now() < deadline {
        // A tick and maybe send
        session_a.tick();
        if let Some(frame) = session_a.poll_send() {
            let _ = link_a_to_b.send(&frame);
        }

        // B tick and maybe send
        session_b.tick();
        if let Some(frame) = session_b.poll_send() {
            let _ = link_b_to_a.send(&frame);
        }

        // B receive and process all available frames
        while let Ok(n) = link_a_to_b.recv(&mut buf) {
            let _ = session_b.on_receive(&buf[..n]);
        }

        // A receive and process all available frames
        while let Ok(n) = link_b_to_a.recv(&mut buf) {
            let _ = session_a.on_receive(&buf[..n]);
        }

        if session_a.is_established() && session_b.is_established() {
            break;
        }

        std::thread::sleep(Duration::from_millis(2));
    }

    // Both should be established despite loss
    assert!(
        session_a.is_established(),
        "Session A should be established (sent {} HELLOs)",
        session_a.stats.hellos_sent
    );
    assert!(
        session_b.is_established(),
        "Session B should be established (sent {} HELLOs)",
        session_b.stats.hellos_sent
    );

    // Should have needed retries (with 30% loss, expect several attempts)
    let total_hellos = session_a.stats.hellos_sent + session_b.stats.hellos_sent;
    assert!(
        total_hellos > 2,
        "Should have retried HELLOs (total: {})",
        total_hellos
    );
}
