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
    SESSION_ID_WITHOUT_CLIENT_KEY,
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
    /// Bytes accumulated from FRAGMENT submessages on this stream, waiting
    /// for the chunk that carries `FLAG_LAST_FRAGMENT`.
    fragment_buffer: Vec<u8>,
}

impl StreamState {
    pub fn new(kind: StreamKind) -> Self {
        Self {
            kind,
            next_send_seq: 0,
            next_recv_seq: 0,
            unacked: HashMap::new(),
            reassembly: HashMap::new(),
            fragment_buffer: Vec::new(),
        }
    }

    /// Append one FRAGMENT chunk to this stream's reassembly buffer.
    ///
    /// Returns the reassembled message body once `last` is set, `None` while
    /// chunks are still expected.
    ///
    /// # Errors
    /// Returns [`XrceError::FragmentError`] and DROPS the partial message when
    /// the accumulated size would exceed `max_len`: an unbounded buffer is a
    /// remote memory-exhaustion lever, so the limit is enforced, not trusted.
    pub fn push_fragment(
        &mut self,
        data: &[u8],
        last: bool,
        max_len: usize,
    ) -> Result<Option<Vec<u8>>, XrceError> {
        if self.fragment_buffer.len() + data.len() > max_len {
            self.fragment_buffer.clear();
            return Err(XrceError::FragmentError(format!(
                "reassembled message would exceed {} bytes",
                max_len
            )));
        }
        self.fragment_buffer.extend_from_slice(data);
        if last {
            Ok(Some(std::mem::take(&mut self.fragment_buffer)))
        } else {
            Ok(None)
        }
    }

    /// Number of bytes currently held in the fragment reassembly buffer.
    pub fn pending_fragment_bytes(&self) -> usize {
        self.fragment_buffer.len()
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

    /// Accept an inbound sequence number on this stream, or refuse it as a
    /// duplicate / replay.
    ///
    /// This is deduplication, not in-order delivery: a sequence number at or
    /// beyond the expected one is accepted and moves the frontier, one behind
    /// it is refused. Refusing a gap outright would wedge the stream, because
    /// nothing on the agent side buffers out-of-order frames yet - see the
    /// crate documentation for what inbound reliability does and does not do.
    ///
    /// A best-effort stream (id 0) has no sequence contract and always
    /// accepts.
    pub fn accept_recv_seq(&mut self, seq: u16) -> bool {
        if self.kind == StreamKind::BestEffort {
            return true;
        }
        if seq_lt(seq, self.next_recv_seq) {
            return false;
        }
        self.next_recv_seq = seq.wrapping_add(1);
        true
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
    /// When the agent last sent a HEARTBEAT to this client.
    pub last_heartbeat: Instant,
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
            last_heartbeat: Instant::now(),
        }
    }

    /// True when `period_ms` has elapsed since the last agent HEARTBEAT.
    pub fn heartbeat_due(&self, period_ms: u64) -> bool {
        self.last_heartbeat.elapsed().as_millis() as u64 >= period_ms
    }

    /// Record that a HEARTBEAT has just been sent.
    pub fn mark_heartbeat_sent(&mut self) {
        self.last_heartbeat = Instant::now();
    }

    /// Reliable stream ids that currently hold unacknowledged messages.
    pub fn reliable_streams(&self) -> Vec<u8> {
        let mut ids: Vec<u8> = self
            .stream_states
            .iter()
            .filter(|(_, st)| st.kind == StreamKind::Reliable)
            .map(|(&id, _)| id)
            .collect();
        ids.sort_unstable();
        ids
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
        self.stream_states.entry(stream_id).or_insert_with(|| {
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
            // The agent hands out session ids in the "without client key"
            // range (DDS-XRCE 1.0: 0x80..=0xFF), so the 4-byte ClientKey is
            // bound once at CREATE_CLIENT and never repeated in a header.
            next_session_id: SESSION_ID_WITHOUT_CLIENT_KEY,
        }
    }

    /// Allocate a new session for the client. Returns the session_id.
    pub fn create_session(&mut self, client_key: [u8; 4]) -> Result<u8, XrceError> {
        if self.sessions.len() >= self.max_clients {
            return Err(XrceError::SessionFull);
        }
        // Find a free session_id inside 0x80..=0xFF.
        let start = self.next_session_id;
        loop {
            let id = self.next_session_id;
            self.next_session_id = if self.next_session_id == u8::MAX {
                SESSION_ID_WITHOUT_CLIENT_KEY
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

    /// Remove expired sessions and RETURN them, so the caller can release
    /// whatever each one owns outside this table (DDS entities, in the
    /// agent's case).
    pub fn take_expired(&mut self) -> Vec<ClientSession> {
        let timeout = self.timeout_ms;
        let expired: Vec<u8> = self
            .sessions
            .iter()
            .filter(|(_, s)| s.is_expired(timeout))
            .map(|(&id, _)| id)
            .collect();
        expired
            .into_iter()
            .filter_map(|id| self.sessions.remove(&id))
            .collect()
    }

    /// Remove expired sessions. Returns the list of removed session ids.
    ///
    /// Prefer [`SessionTable::take_expired`] when the removed sessions own
    /// anything that has to be released.
    pub fn evict_expired(&mut self) -> Vec<u8> {
        self.take_expired()
            .into_iter()
            .map(|s| s.session_id)
            .collect()
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
