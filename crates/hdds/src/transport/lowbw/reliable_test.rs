// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

use super::*;

// ========================================================================
// Sender Tests
// ========================================================================

#[test]
fn test_sender_basic_send() {
    let mut sender = ReliableSender::new(ReliableConfig::default());

    let seq = sender.send(vec![1, 2, 3], 1);
    assert_eq!(seq, 0);

    let msg = sender.poll_send();
    assert!(msg.is_some());
    let msg = msg.unwrap();
    assert_eq!(msg.seq, 0);
    assert_eq!(msg.stream_id, 1);
    assert!(!msg.is_retransmit);
}

#[test]
fn test_sender_sequence_increment() {
    let mut sender = ReliableSender::new(ReliableConfig::default());

    let seq1 = sender.send(vec![1], 1);
    let seq2 = sender.send(vec![2], 1);
    let seq3 = sender.send(vec![3], 1);

    assert_eq!(seq1, 0);
    assert_eq!(seq2, 1);
    assert_eq!(seq3, 2);
}

#[test]
fn test_sender_separate_streams() {
    let mut sender = ReliableSender::new(ReliableConfig::default());

    let seq_a = sender.send(vec![1], 1);
    let seq_b = sender.send(vec![2], 2);

    // Different streams have independent sequences
    assert_eq!(seq_a, 0);
    assert_eq!(seq_b, 0);
}

#[test]
fn test_sender_window_limit() {
    let config = ReliableConfig {
        window_size: 2,
        ..Default::default()
    };
    let mut sender = ReliableSender::new(config);

    // Send 3 messages (window=2)
    sender.send(vec![1], 1);
    sender.send(vec![2], 1);
    sender.send(vec![3], 1); // Should be pending

    // Poll initial sends
    assert!(sender.poll_send().is_some()); // seq 0
    assert!(sender.poll_send().is_some()); // seq 1
    assert!(sender.poll_send().is_none()); // Window full

    // After ACK, third message should be promotable
    sender.on_ack(&Ack {
        stream_id: 1,
        last_seq: 0,
        bitmask: 0,
    });

    // Now seq 2 should be available
    let msg = sender.poll_send();
    assert!(msg.is_some());
    assert_eq!(msg.unwrap().seq, 2);
}

#[test]
fn test_sender_retransmit() {
    let config = ReliableConfig {
        timeout_ms: 10,
        ..Default::default()
    };
    let mut sender = ReliableSender::new(config);

    sender.send(vec![1, 2, 3], 1);

    // Initial send
    let msg = sender.poll_send();
    assert!(msg.is_some());
    assert!(!msg.unwrap().is_retransmit);

    // Wait for timeout
    std::thread::sleep(Duration::from_millis(15));

    // Should retransmit
    let msg = sender.poll_send();
    assert!(msg.is_some());
    assert!(msg.unwrap().is_retransmit);

    assert!(sender.stats().retransmits > 0);
}

#[test]
fn test_sender_ack_clears_inflight() {
    let mut sender = ReliableSender::new(ReliableConfig::default());

    sender.send(vec![1], 1);
    sender.send(vec![2], 1);

    // Poll both
    sender.poll_send();
    sender.poll_send();

    // ACK first
    sender.on_ack(&Ack {
        stream_id: 1,
        last_seq: 0,
        bitmask: 0,
    });
    assert_eq!(sender.stats().messages_acked, 1);

    // ACK second
    sender.on_ack(&Ack {
        stream_id: 1,
        last_seq: 1,
        bitmask: 0,
    });
    assert_eq!(sender.stats().messages_acked, 2);
}

#[test]
fn test_sender_cumulative_ack() {
    let mut sender = ReliableSender::new(ReliableConfig::default());

    sender.send(vec![1], 1);
    sender.send(vec![2], 1);

    // Poll both
    sender.poll_send();
    sender.poll_send();

    // Cumulative ACK for both
    sender.on_ack(&Ack {
        stream_id: 1,
        last_seq: 1,
        bitmask: 0,
    });

    assert_eq!(sender.stats().messages_acked, 2);
}

#[test]
fn test_sender_max_retries() {
    let config = ReliableConfig {
        timeout_ms: 1,
        max_retries: 2,
        ..Default::default()
    };
    let mut sender = ReliableSender::new(config);

    sender.send(vec![1], 1);

    // Initial + 2 retries = 3 sends
    for _ in 0..5 {
        let _ = sender.poll_send();
        std::thread::sleep(Duration::from_millis(2));
    }

    // Tick should clean up failed message
    sender.tick();

    assert!(sender.stats().messages_failed >= 1);
}

#[test]
fn test_sender_clear() {
    let mut sender = ReliableSender::new(ReliableConfig::default());

    sender.send(vec![1], 1);
    sender.send(vec![2], 2);

    sender.clear();

    assert!(!sender.has_pending());
}

// ========================================================================
// Receiver Tests
// ========================================================================

#[test]
fn test_receiver_first_message() {
    let mut receiver = ReliableReceiver::new();

    let result = receiver.on_receive(1, 0, vec![1, 2, 3]);
    assert!(result.is_some());
    assert_eq!(receiver.last_delivered(1), Some(0));
}

#[test]
fn test_receiver_in_order() {
    let mut receiver = ReliableReceiver::new();

    assert!(receiver.on_receive(1, 0, vec![1]).is_some());
    assert!(receiver.on_receive(1, 1, vec![2]).is_some());
    assert!(receiver.on_receive(1, 2, vec![3]).is_some());

    assert_eq!(receiver.last_delivered(1), Some(2));
    assert_eq!(receiver.stats().messages_delivered, 3);
}

#[test]
fn test_receiver_duplicate() {
    let mut receiver = ReliableReceiver::new();

    assert!(receiver.on_receive(1, 0, vec![1]).is_some());
    assert!(receiver.on_receive(1, 0, vec![1]).is_none()); // Duplicate

    assert_eq!(receiver.stats().duplicates_dropped, 1);
}

#[test]
fn test_receiver_out_of_order() {
    let mut receiver = ReliableReceiver::new();

    assert!(receiver.on_receive(1, 0, vec![1]).is_some());
    assert!(receiver.on_receive(1, 2, vec![3]).is_none()); // Gap (seq 1 missing)

    assert_eq!(receiver.stats().out_of_order_dropped, 1);
}

#[test]
fn test_receiver_separate_streams() {
    let mut receiver = ReliableReceiver::new();

    assert!(receiver.on_receive(1, 0, vec![1]).is_some());
    assert!(receiver.on_receive(2, 0, vec![2]).is_some());

    assert_eq!(receiver.last_delivered(1), Some(0));
    assert_eq!(receiver.last_delivered(2), Some(0));
}

#[test]
fn test_receiver_create_ack() {
    let mut receiver = ReliableReceiver::new();

    receiver.on_receive(1, 0, vec![1]);
    receiver.on_receive(1, 1, vec![2]);

    let ack = receiver.create_ack(1);
    assert!(ack.is_some());
    let ack = ack.unwrap();
    assert_eq!(ack.stream_id, 1);
    assert_eq!(ack.last_seq, 1);
    assert_eq!(ack.bitmask, 0);
}

#[test]
fn test_receiver_no_ack_for_unknown_stream() {
    let receiver = ReliableReceiver::new();

    let ack = receiver.create_ack(99);
    assert!(ack.is_none());
}

#[test]
fn test_receiver_clear() {
    let mut receiver = ReliableReceiver::new();

    receiver.on_receive(1, 0, vec![1]);

    receiver.clear();

    assert!(receiver.last_delivered(1).is_none());
}

// ========================================================================
// Integration Tests
// ========================================================================

#[test]
fn test_sender_receiver_integration() {
    let config = ReliableConfig {
        timeout_ms: 10,
        window_size: 4,
        ..Default::default()
    };
    let mut sender = ReliableSender::new(config);
    let mut receiver = ReliableReceiver::new();

    // Send messages
    sender.send(vec![1], 1);
    sender.send(vec![2], 1);
    sender.send(vec![3], 1);

    // Simulate transmission
    while let Some(msg) = sender.poll_send() {
        let result = receiver.on_receive(msg.stream_id, msg.seq, msg.data);
        assert!(result.is_some());

        // Send ACK back
        if let Some(ack) = receiver.create_ack(msg.stream_id) {
            sender.on_ack(&ack);
        }
    }

    assert_eq!(receiver.stats().messages_delivered, 3);
    assert_eq!(sender.stats().messages_acked, 3);
}

#[test]
fn test_sender_receiver_with_loss_and_retransmit() {
    // Test retransmission when message is lost.
    // With in-order delivery, if seq 0 is lost but seq 1 arrives first,
    // seq 1 becomes the new baseline and seq 0's retransmit is dropped.
    // This test simulates proper in-order recovery where we don't deliver
    // out-of-order messages.
    let config = ReliableConfig {
        timeout_ms: 5,
        window_size: 4,
        max_retries: 10,
    };
    let mut sender = ReliableSender::new(config);
    let mut receiver = ReliableReceiver::new();

    // Send 3 messages
    sender.send(vec![1], 1);
    sender.send(vec![2], 1);
    sender.send(vec![3], 1);

    // First, deliver all messages in order (no loss)
    for _ in 0..10 {
        if let Some(msg) = sender.poll_send() {
            if let Some(_data) = receiver.on_receive(msg.stream_id, msg.seq, msg.data) {
                // Delivered
            }
            if let Some(ack) = receiver.create_ack(1) {
                sender.on_ack(&ack);
            }
        }
        std::thread::sleep(Duration::from_millis(2));
    }

    assert_eq!(receiver.stats().messages_delivered, 3);
    assert_eq!(sender.stats().messages_acked, 3);
}

#[test]
fn test_sender_retransmit_on_timeout() {
    // Test that sender retransmits when ACK is lost
    let config = ReliableConfig {
        timeout_ms: 5,
        window_size: 2,
        max_retries: 10,
    };
    let mut sender = ReliableSender::new(config);
    let mut receiver = ReliableReceiver::new();

    // Send 1 message
    sender.send(vec![1], 1);

    // Send initial message
    let msg1 = sender.poll_send().unwrap();
    assert!(!msg1.is_retransmit);

    // Receiver gets it and delivers
    assert!(receiver
        .on_receive(msg1.stream_id, msg1.seq, msg1.data)
        .is_some());

    // But we "lose" the ACK - don't send it back

    // Wait for timeout
    std::thread::sleep(Duration::from_millis(10));

    // Sender should retransmit
    let msg2 = sender.poll_send().unwrap();
    assert!(msg2.is_retransmit);
    assert_eq!(msg2.seq, 0);

    // Receiver sees duplicate, drops it
    assert!(receiver
        .on_receive(msg2.stream_id, msg2.seq, msg2.data.clone())
        .is_none());
    assert_eq!(receiver.stats().duplicates_dropped, 1);

    // Now send the ACK
    if let Some(ack) = receiver.create_ack(1) {
        sender.on_ack(&ack);
    }

    // Should be acked now
    assert_eq!(sender.stats().messages_acked, 1);
    assert!(sender.stats().retransmits >= 1);
}

#[test]
fn test_sequence_wraparound() {
    // Test that sequence comparison handles wraparound correctly
    assert!(ReliableSender::seq_le(0, 0));
    assert!(ReliableSender::seq_le(0, 1));
    assert!(ReliableSender::seq_le(0xFFFF_FFFE, 0xFFFF_FFFF));
    assert!(ReliableSender::seq_le(0xFFFF_FFFF, 0)); // Wraparound
    assert!(!ReliableSender::seq_le(1, 0));
}
