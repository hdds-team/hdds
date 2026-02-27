// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

// XRCE session management.
//
// Each connected client has a `ClientSession` with its own set of streams
// (best-effort and reliable) and proxy DDS objects.

use std::collections::HashMap;
use std::time::Instant;

use crate::protocol::{
    AcknackPayload, HeartbeatPayload, ObjectKind, ReassemblyBuffer, XrceError,
};

// ---------------------------------------------------------------------------
// Stream state
// ---------------------------------------------------------------------------

/// Identifies the stream type by its id range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamKind {
    /// stream_id == 0: fire-and-forget.
    BestEffort,
    /// stream_id 1..=127: reliable delivery.
    Reliable,
}

impl StreamKind {
    pub fn from_stream_id(id: u8) -> Self {
        if id == 0 {
            Self::BestEffort
        } else {
            Self::Reliable
        }
    }
}

/// Per-stream state for a single client session.
#[derive(Debug)]
pub struct StreamState {
    pub kind: StreamKind,
    /// Next sequence number to send from the agent on this stream.
    pub next_send_seq: u16,
    /// Next expected inbound sequence number from the client.
    pub next_recv_seq: u16,
    /// Outbound messages awaiting acknowledgement (reliable only).
    /// Key = sequence number, Value = serialized submessage bytes.
    pub unacked: HashMap<u16, Vec<u8>>,
    /// Inbound reassembly buffers. Key = sequence number.
    pub reassembly: HashMap<u16, ReassemblyBuffer>,
}

impl StreamState {
    pub fn new(kind: StreamKind) -> Self {
        Self {
            kind,
            next_send_seq: 0,
            next_recv_seq: 0,
            unacked: HashMap::new(),
            reassembly: HashMap::new(),
        }
    }

    /// Allocate the next outbound sequence number.
    pub fn alloc_send_seq(&mut self) -> u16 {
        let seq = self.next_send_seq;
        self.next_send_seq = self.next_send_seq.wrapping_add(1);
        seq
    }

    /// Record an outbound message for potential retransmission.
    pub fn record_sent(&mut self, seq: u16, data: Vec<u8>) {
        if self.kind == StreamKind::Reliable {
            self.unacked.insert(seq, data);
        }
    }

    /// Process an ACKNACK from the client, removing acknowledged messages.
    /// Returns the list of sequence numbers that need retransmission.
    pub fn process_acknack(&mut self, ack: &AcknackPayload) -> Vec<u16> {
        // Everything before first_unacked_seq is acknowledged.
        let acked: Vec<u16> = self
            .unacked
            .keys()
            .copied()
            .filter(|&seq| seq_lt(seq, ack.first_unacked_seq))
            .collect();
        for seq in &acked {
            self.unacked.remove(seq);
        }

        // Bitmap: bit N set means first_unacked_seq + N is MISSING (needs retransmit).
        let mut retransmit = Vec::new();
        for bit in 0..16u16 {
            if ack.nack_bitmap & (1 << bit) != 0 {
                let seq = ack.first_unacked_seq.wrapping_add(bit);
                if self.unacked.contains_key(&seq) {
                    retransmit.push(seq);
                }
            }
        }
        retransmit
    }

    /// Generate a HEARTBEAT for this stream's current state.
    pub fn make_heartbeat(&self) -> HeartbeatPayload {
        let first = if self.unacked.is_empty() {
            self.next_send_seq
        } else {
            *self.unacked.keys().min().unwrap_or(&self.next_send_seq)
        };
        HeartbeatPayload {
            first_unacked_seq: first,
            last_seq: self.next_send_seq.wrapping_sub(1),
        }
    }

    /// Check if an inbound sequence number is the expected one for
    /// reliable in-order delivery.
    pub fn check_recv_seq(&mut self, seq: u16) -> bool {
        if self.kind == StreamKind::BestEffort {
            return true;
        }
        if seq == self.next_recv_seq {
            self.next_recv_seq = self.next_recv_seq.wrapping_add(1);
            true
        } else {
            false
        }
    }

    /// Generate an ACKNACK from the receiver side, reporting which
    /// sequences are missing between `first` and `last`.
    pub fn make_acknack(&self, first: u16, last: u16) -> AcknackPayload {
        // first_unacked_seq = next_recv_seq
        // bitmap: for each offset from next_recv_seq, if NOT received, set bit.
        // For simplicity we mark everything from next_recv_seq as nacked if below last.
        let mut bitmap = 0u16;
        for bit in 0..16u16 {
            let seq = self.next_recv_seq.wrapping_add(bit);
            if seq_lt(last, seq) {
                break;
            }
            // If we haven't received this one, mark it
            if seq != self.next_recv_seq && seq_lt(seq, first) {
                // before first -> already received
            } else {
                // We need it retransmitted
                bitmap |= 1 << bit;
            }
        }
        AcknackPayload {
            first_unacked_seq: self.next_recv_seq,
            nack_bitmap: bitmap,
        }
    }
}

/// Sequence number less-than with wrapping (half-space comparison).
fn seq_lt(a: u16, b: u16) -> bool {
    let diff = a.wrapping_sub(b);
    diff > 0x7FFF
}

// ---------------------------------------------------------------------------
// XRCE object (proxy entity)
// ---------------------------------------------------------------------------

/// An XRCE object representing a DDS entity created through the bridge.
#[derive(Debug, Clone)]
pub struct XrceObject {
    pub object_id: u16,
    pub kind: ObjectKind,
    /// Handle returned by ProxyBridge (opaque DDS entity id).
    pub bridge_handle: u32,
}

// ---------------------------------------------------------------------------
// Client session
// ---------------------------------------------------------------------------

/// State for one connected XRCE client.
#[derive(Debug)]
pub struct ClientSession {
    pub session_id: u8,
    pub client_key: [u8; 4],
    pub stream_states: HashMap<u8, StreamState>,
    pub objects: HashMap<u16, XrceObject>,
    pub last_activity: Instant,
}

impl ClientSession {
    /// Create a new session. The best-effort stream (id=0) is created automatically.
    pub fn new(session_id: u8, client_key: [u8; 4]) -> Self {
        let mut stream_states = HashMap::new();
        stream_states.insert(0, StreamState::new(StreamKind::BestEffort));
        Self {
            session_id,
            client_key,
            stream_states,
            objects: HashMap::new(),
            last_activity: Instant::now(),
        }
    }

    /// Touch the session (update last_activity).
    pub fn touch(&mut self) {
        self.last_activity = Instant::now();
    }

    /// Check if the session has timed out.
    pub fn is_expired(&self, timeout_ms: u64) -> bool {
        self.last_activity.elapsed().as_millis() as u64 > timeout_ms
    }

    /// Get or create a stream state.
    pub fn stream(&mut self, stream_id: u8) -> &mut StreamState {
        self.stream_states
            .entry(stream_id)
            .or_insert_with(|| {
                let kind = StreamKind::from_stream_id(stream_id);
                StreamState::new(kind)
            })
    }

    /// Add a proxy object.
    pub fn add_object(&mut self, obj: XrceObject) {
        self.objects.insert(obj.object_id, obj);
    }

    /// Remove a proxy object. Returns the removed object.
    pub fn remove_object(&mut self, object_id: u16) -> Option<XrceObject> {
        self.objects.remove(&object_id)
    }

    /// Look up a proxy object.
    pub fn get_object(&self, object_id: u16) -> Option<&XrceObject> {
        self.objects.get(&object_id)
    }
}

// ---------------------------------------------------------------------------
// Session table
// ---------------------------------------------------------------------------

/// Manages all client sessions with allocation and timeout eviction.
#[derive(Debug)]
pub struct SessionTable {
    pub sessions: HashMap<u8, ClientSession>,
    max_clients: usize,
    timeout_ms: u64,
    next_session_id: u8,
}

impl SessionTable {
    pub fn new(max_clients: usize, timeout_ms: u64) -> Self {
        Self {
            sessions: HashMap::new(),
            max_clients,
            timeout_ms,
            next_session_id: 1, // 0 is reserved
        }
    }

    /// Allocate a new session for the client. Returns the session_id.
    pub fn create_session(&mut self, client_key: [u8; 4]) -> Result<u8, XrceError> {
        if self.sessions.len() >= self.max_clients {
            return Err(XrceError::SessionFull);
        }
        // Find a free session_id (skip 0).
        let start = self.next_session_id;
        loop {
            let id = self.next_session_id;
            self.next_session_id = if self.next_session_id == 255 {
                1
            } else {
                self.next_session_id + 1
            };
            if let std::collections::hash_map::Entry::Vacant(e) = self.sessions.entry(id) {
                let session = ClientSession::new(id, client_key);
                e.insert(session);
                return Ok(id);
            }
            // Wrapped all the way around?
            if self.next_session_id == start {
                return Err(XrceError::SessionFull);
            }
        }
    }

    /// Get a mutable reference to a session.
    pub fn get_mut(&mut self, session_id: u8) -> Option<&mut ClientSession> {
        self.sessions.get_mut(&session_id)
    }

    /// Get an immutable reference to a session.
    pub fn get(&self, session_id: u8) -> Option<&ClientSession> {
        self.sessions.get(&session_id)
    }

    /// Remove expired sessions. Returns the list of removed session ids.
    pub fn evict_expired(&mut self) -> Vec<u8> {
        let timeout = self.timeout_ms;
        let expired: Vec<u8> = self
            .sessions
            .iter()
            .filter(|(_, s)| s.is_expired(timeout))
            .map(|(&id, _)| id)
            .collect();
        for id in &expired {
            self.sessions.remove(id);
        }
        expired
    }

    /// Number of active sessions.
    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    /// Check if empty.
    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }

    /// Remove a session by id.
    pub fn remove(&mut self, session_id: u8) -> Option<ClientSession> {
        self.sessions.remove(&session_id)
    }
}
