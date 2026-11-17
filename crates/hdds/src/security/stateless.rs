// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Minimal Participant-Stateless-Message channel (DDS Security v1.1 sec. 7.4.5).
//!
//! The `BuiltinParticipantStatelessMessageWriter` / `Reader` pair carries the
//! PKI-DH authentication handshake tokens BEFORE any crypto material has been
//! negotiated, so this channel is intentionally:
//!
//! - **BEST_EFFORT** -- no ACKNACK, no retransmission, no reliable bookkeeping
//! - **VOLATILE** -- no historical replay, no late-joiner catch-up
//! - **NO_KEY** -- single instance per writer/reader pair
//! - **PLAINTEXT** -- payload is the spec-defined handshake token CDR, not
//!   wrapped in `SecureSubMsg`
//!
//! Entity IDs (RTPS v2.3 sec. 9.4.5.3, big-endian on the wire):
//!
//! - writer 0x000201c3 (`RTPS_ENTITYID_BUILTIN_PARTICIPANT_STATELESS_MESSAGE_WRITER`)
//! - reader 0x000201c4 (`RTPS_ENTITYID_BUILTIN_PARTICIPANT_STATELESS_MESSAGE_READER`)
//!
//! # v1 scope
//!
//! This module provides the tunnel **plumbing** -- a `StatelessChannel` facade
//! that the participant builder hands to the eventual handshake driver. The
//! actual ParticipantStatelessMessage content (HandshakeRequest / Reply /
//! Final messages per DDS Security v1.1 sec. 9.3.3) is deliberately out of scope:
//! it lives in security gap #3 (handshake driver) which will consume the
//! `tx_tokens` / `rx_tokens` queues.
//!
//! # Threading
//!
//! `StatelessChannel` is `Send + Sync`; the queues are SPSC-friendly
//! `parking_lot::Mutex<VecDeque<_>>` wrappers, sized small (16 entries) since
//! the handshake state machine never has more than a few in-flight tokens per
//! peer.

use parking_lot::Mutex;
use std::collections::VecDeque;
use std::sync::Arc;

/// Maximum number of pending tokens per direction.
///
/// DDS Security v1.1 sec. 9.3.3 handshakes are 3 messages each way per peer; we
/// keep an order-of-magnitude headroom for re-sends and concurrent peers.
const STATELESS_QUEUE_DEPTH: usize = 16;

/// A single ParticipantStatelessMessage token ready for transmission or just
/// received from the wire.
///
/// v1 keeps this opaque (`Vec<u8>`); gap #3 (handshake driver) will introduce
/// a typed `ParticipantGenericMessage` per DDS Security v1.1 sec. 7.4.3.3 once
/// the token CDR encode / decode lands.
#[derive(Debug, Clone)]
pub struct StatelessToken {
    /// Remote participant GUID prefix (12 bytes). The handshake driver uses
    /// this to associate the token with an in-progress HandshakeHandle.
    pub remote_guid_prefix: [u8; 12],

    /// Opaque CDR bytes of the ParticipantStatelessMessage payload. v1 does
    /// not parse this -- gap #3 will.
    pub payload: Vec<u8>,
}

/// Stateless tunnel for DDS-Security authentication handshakes.
///
/// Owns two bounded queues:
///
/// - `tx_tokens` -- tokens the local handshake driver wants to publish on the
///   `BuiltinParticipantStatelessMessageWriter`. The discovery RTPS writer
///   thread drains this and emits DATA submessages to the remote
///   `BuiltinParticipantStatelessMessageReader`.
/// - `rx_tokens` -- tokens received on the local
///   `BuiltinParticipantStatelessMessageReader`. The discovery callback (gap
///   #3 will wire this in) pushes here; the handshake driver pops to advance
///   its PKI-DH state machine.
///
/// Both queues are `parking_lot::Mutex<VecDeque<_>>` and capped at
/// `STATELESS_QUEUE_DEPTH` to bound memory under adversarial flooding (per
/// DDS Security v1.1 sec. 7.4.5.3 implementations must not allow handshake
/// traffic to exhaust resources). Excess tokens are dropped on the floor;
/// gap #3 will surface back-pressure semantics if the spec calls for it.
#[derive(Debug, Clone)]
pub struct StatelessChannel {
    inner: Arc<StatelessChannelInner>,
}

#[derive(Debug)]
struct StatelessChannelInner {
    tx_tokens: Mutex<VecDeque<StatelessToken>>,
    rx_tokens: Mutex<VecDeque<StatelessToken>>,
}

impl StatelessChannel {
    /// Create an empty channel.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(StatelessChannelInner {
                tx_tokens: Mutex::new(VecDeque::with_capacity(STATELESS_QUEUE_DEPTH)),
                rx_tokens: Mutex::new(VecDeque::with_capacity(STATELESS_QUEUE_DEPTH)),
            }),
        }
    }

    /// Enqueue a token for transmission. Returns `true` if accepted, `false`
    /// if the queue was full and the token was dropped (BEST_EFFORT, see
    /// module doc).
    pub fn push_outgoing(&self, token: StatelessToken) -> bool {
        let mut guard = self.inner.tx_tokens.lock();
        if guard.len() >= STATELESS_QUEUE_DEPTH {
            log::warn!(
                "[security::stateless] outgoing queue full ({} >= {}), dropping token for {:02x?}",
                guard.len(),
                STATELESS_QUEUE_DEPTH,
                token.remote_guid_prefix
            );
            return false;
        }
        guard.push_back(token);
        true
    }

    /// Pop the next token to publish. Returns `None` if no token is pending.
    pub fn pop_outgoing(&self) -> Option<StatelessToken> {
        self.inner.tx_tokens.lock().pop_front()
    }

    /// Enqueue a token that just arrived on the wire. Returns `true` if
    /// accepted, `false` if the queue was full and the token was dropped.
    pub fn push_incoming(&self, token: StatelessToken) -> bool {
        let mut guard = self.inner.rx_tokens.lock();
        if guard.len() >= STATELESS_QUEUE_DEPTH {
            log::warn!(
                "[security::stateless] incoming queue full ({} >= {}), dropping token from {:02x?}",
                guard.len(),
                STATELESS_QUEUE_DEPTH,
                token.remote_guid_prefix
            );
            return false;
        }
        guard.push_back(token);
        true
    }

    /// Pop the next token the handshake driver should process.
    pub fn pop_incoming(&self) -> Option<StatelessToken> {
        self.inner.rx_tokens.lock().pop_front()
    }

    /// Current depth of the outgoing queue. Diagnostics only.
    pub fn outgoing_len(&self) -> usize {
        self.inner.tx_tokens.lock().len()
    }

    /// Current depth of the incoming queue. Diagnostics only.
    pub fn incoming_len(&self) -> usize {
        self.inner.rx_tokens.lock().len()
    }
}

impl Default for StatelessChannel {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(prefix_byte: u8) -> StatelessToken {
        StatelessToken {
            remote_guid_prefix: [prefix_byte; 12],
            payload: vec![0xDE, 0xAD, 0xBE, 0xEF],
        }
    }

    #[test]
    fn stateless_channel_fifo_outgoing() {
        let chan = StatelessChannel::new();
        assert!(chan.push_outgoing(sample(1)));
        assert!(chan.push_outgoing(sample(2)));
        let first = chan.pop_outgoing().expect("token");
        assert_eq!(first.remote_guid_prefix, [1u8; 12]);
        let second = chan.pop_outgoing().expect("token");
        assert_eq!(second.remote_guid_prefix, [2u8; 12]);
        assert!(chan.pop_outgoing().is_none());
    }

    #[test]
    fn stateless_channel_fifo_incoming() {
        let chan = StatelessChannel::new();
        assert!(chan.push_incoming(sample(7)));
        let got = chan.pop_incoming().expect("token");
        assert_eq!(got.remote_guid_prefix, [7u8; 12]);
        assert_eq!(got.payload, vec![0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn stateless_channel_caps_outgoing() {
        let chan = StatelessChannel::new();
        for i in 0..STATELESS_QUEUE_DEPTH {
            assert!(chan.push_outgoing(sample(i as u8)));
        }
        // 17th must be rejected.
        assert!(!chan.push_outgoing(sample(0xFF)));
        assert_eq!(chan.outgoing_len(), STATELESS_QUEUE_DEPTH);
    }

    #[test]
    fn stateless_channel_clone_shares_state() {
        let chan = StatelessChannel::new();
        let twin = chan.clone();
        assert!(chan.push_outgoing(sample(3)));
        assert_eq!(twin.outgoing_len(), 1);
        let popped = twin.pop_outgoing().expect("token");
        assert_eq!(popped.remote_guid_prefix, [3u8; 12]);
        assert_eq!(chan.outgoing_len(), 0);
    }
}
