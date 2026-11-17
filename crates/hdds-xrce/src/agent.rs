// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

// XRCE Agent main loop.
//
// Accepts XRCE clients over any transport, dispatches submessages
// to the appropriate session, and bridges operations to DDS via ProxyBridge.

use std::collections::HashMap;
use std::sync::Arc;

use crate::config::XrceAgentConfig;
use crate::protocol::{
    self, CreatePayload, DataPayload, HeartbeatPayload, MessageHeader, ObjectKind, StatusCode,
    StatusPayload, Submessage, XrceError, XrceMessage, SESSION_ID_WITHOUT_CLIENT_KEY,
};
use crate::proxy::ProxyBridge;
use crate::session::{SessionTable, XrceObject};
use crate::transport::{TransportAddr, XrceTransport};

/// The XRCE agent. Bridges resource-constrained clients to DDS.
pub struct XrceAgent {
    config: XrceAgentConfig,
    sessions: SessionTable,
    bridge: Arc<dyn ProxyBridge>,
    /// Maps TransportAddr -> session_id for routing replies.
    addr_map: HashMap<TransportAddr, u8>,
    /// Reverse of `addr_map`, so agent-initiated traffic (HEARTBEAT,
    /// retransmissions) knows where to go.
    session_addr: HashMap<u8, TransportAddr>,
    /// Submessages refused because they did not come from the address that
    /// opened the session (or carried the wrong ClientKey).
    denied_submessages: u64,
    /// Inbound messages dropped because they were larger than
    /// `config.max_message_size`.
    oversized_messages: u64,
}

impl XrceAgent {
    /// Create a new agent with the given configuration and DDS bridge.
    pub fn new(config: XrceAgentConfig, bridge: Arc<dyn ProxyBridge>) -> Result<Self, XrceError> {
        config.validate()?;
        let sessions = SessionTable::new(config.max_clients, config.session_timeout_ms);
        Ok(Self {
            config,
            sessions,
            bridge,
            addr_map: HashMap::new(),
            session_addr: HashMap::new(),
            denied_submessages: 0,
            oversized_messages: 0,
        })
    }

    /// Process one inbound raw datagram from a transport.
    /// Returns a list of (destination, reply_bytes) to send back.
    pub fn process_incoming(
        &mut self,
        from: &TransportAddr,
        data: &[u8],
    ) -> Vec<(TransportAddr, Vec<u8>)> {
        let mut replies: Vec<(TransportAddr, Vec<u8>)> = Vec::new();

        // Try to parse the message header first.
        let msg = match protocol::parse_message(data) {
            Ok(m) => m,
            Err(e) => {
                log::warn!("Failed to parse XRCE message: {}", e);
                return replies;
            }
        };

        self.dispatch(from, &msg.header, &msg.submessages, &mut replies);
        replies
    }

    /// Dispatch a parsed submessage list, resolving FRAGMENT chunks first.
    fn dispatch(
        &mut self,
        from: &TransportAddr,
        header: &MessageHeader,
        submessages: &[Submessage],
        replies: &mut Vec<(TransportAddr, Vec<u8>)>,
    ) {
        for submsg in submessages {
            if !matches!(submsg, Submessage::CreateClient(_)) && !self.is_authorized(from, header) {
                self.denied_submessages += 1;
                log::warn!(
                    "Refused a submessage for session {}: it did not come from the address that \
                     opened the session, or carried the wrong client key",
                    header.session_id
                );
                continue;
            }
            match submsg {
                Submessage::CreateClient(payload) => {
                    if let Some(r) = self.handle_create_client(from, header, payload) {
                        replies.push((from.clone(), r));
                    }
                }
                Submessage::Fragment(payload) => {
                    match self.handle_fragment(header, payload) {
                        Ok(Some(body)) => {
                            // The reassembled body is a submessage sequence.
                            match parse_submessage_sequence(&body) {
                                Ok(inner) => self.dispatch(from, header, &inner, replies),
                                Err(e) => log::warn!("Reassembled message is malformed: {}", e),
                            }
                        }
                        Ok(None) => {}
                        Err(e) => log::warn!("Fragment rejected: {}", e),
                    }
                }
                Submessage::Acknack(payload) => {
                    for frame in self.handle_acknack(header.session_id, header.stream_id, payload) {
                        replies.push((from.clone(), frame));
                    }
                }
                other => {
                    if let Some(reply) = self.handle_session_submessage(header, other) {
                        replies.push((from.clone(), reply));
                    }
                }
            }
        }
    }

    /// May this datagram act on the session named in its header?
    ///
    /// Admission is checked once, at CREATE_CLIENT. Every later submessage is
    /// bound to the address that opened the session and, on a session id in
    /// the keyed range, to the ClientKey the header must repeat. Without this
    /// the accepted-key list guards the door and leaves the window open: a
    /// stranger who guesses a session id (they are handed out from a known
    /// base) and an object id writes into the DDS domain through somebody
    /// else's session.
    ///
    /// A client whose source address changes - a NAT rebind - must open a new
    /// session. That is deliberate: not having to guess the address is the
    /// whole of the attack.
    fn is_authorized(&self, from: &TransportAddr, hdr: &MessageHeader) -> bool {
        let Some(session) = self.sessions.get(hdr.session_id) else {
            return false;
        };
        if self.session_addr.get(&hdr.session_id) != Some(from) {
            return false;
        }
        match hdr.client_key {
            Some(key) => key == session.client_key,
            // A header with no key is only legitimate on a session id in the
            // range that binds the key at CREATE_CLIENT time.
            None => hdr.session_id >= SESSION_ID_WITHOUT_CLIENT_KEY,
        }
    }

    /// Submessages refused by [`XrceAgent::is_authorized`] since start-up.
    pub fn denied_submessages(&self) -> u64 {
        self.denied_submessages
    }

    /// Inbound messages dropped for exceeding `max_message_size`.
    pub fn oversized_messages(&self) -> u64 {
        self.oversized_messages
    }

    /// Accumulate one FRAGMENT chunk. Returns the reassembled body when the
    /// chunk carrying `FLAG_LAST_FRAGMENT` arrives.
    fn handle_fragment(
        &mut self,
        header: &MessageHeader,
        payload: &protocol::FragmentPayload,
    ) -> Result<Option<Vec<u8>>, XrceError> {
        let max = self.config.max_reassembled_size;
        let session = self
            .sessions
            .get_mut(header.session_id)
            .ok_or(XrceError::SessionNotFound(header.session_id))?;
        session.touch();
        let stream = session.stream(header.stream_id);
        stream.push_fragment(&payload.data, payload.last, max)
    }

    /// Handle CREATE_CLIENT: check admission, allocate a session, send STATUS.
    fn handle_create_client(
        &mut self,
        from: &TransportAddr,
        hdr: &MessageHeader,
        payload: &protocol::CreateClientPayload,
    ) -> Option<Vec<u8>> {
        // Fail closed: an unknown ClientKey never gets a session.
        if !self.config.accepts_client_key(&payload.client_key) {
            log::warn!(
                "Refused CREATE_CLIENT: client key {:02x?} is not accepted",
                payload.client_key
            );
            // Answer on the client's own header: the request came in on a
            // keyed session id, so a reply minted on session 0 with no key
            // could not even be serialized.
            return status_only_message(hdr, 0, StatusCode::ErrDenied);
        }

        let result = self.sessions.create_session(payload.client_key);
        let (session_id, status) = match result {
            Ok(id) => {
                self.addr_map.insert(from.clone(), id);
                self.session_addr.insert(id, from.clone());
                log::info!("Client connected: session_id={}", id);
                (id, StatusCode::Ok)
            }
            Err(_) => {
                log::warn!("Cannot allocate session: table full");
                (0, StatusCode::ErrResources)
            }
        };

        if status == StatusCode::Ok {
            self.emit(
                session_id,
                0,
                Submessage::Status(StatusPayload {
                    related_object_id: 0,
                    status,
                }),
            )
        } else {
            status_only_message(hdr, 0, status)
        }
    }

    /// Dispatch a submessage within an existing session.
    ///
    /// The caller has already checked that this datagram is allowed to act on
    /// the session (see [`XrceAgent::is_authorized`]).
    fn handle_session_submessage(
        &mut self,
        hdr: &MessageHeader,
        submsg: &Submessage,
    ) -> Option<Vec<u8>> {
        let session_id = hdr.session_id;
        let stream_id = hdr.stream_id;

        // Touch the session to reset timeout.
        if let Some(session) = self.sessions.get_mut(session_id) {
            session.touch();
        } else {
            log::warn!("Submessage for unknown session {}", session_id);
            return None;
        }

        // Everything below changes state or writes into DDS, so a replayed
        // sequence number must not be executed twice on a reliable stream.
        // HEARTBEAT is control traffic and carries no payload sequence, so it
        // is not deduplicated.
        if matches!(
            submsg,
            Submessage::Create(_)
                | Submessage::Delete(_)
                | Submessage::WriteData(_)
                | Submessage::ReadData(_)
        ) {
            let accepted = self
                .sessions
                .get_mut(session_id)
                .map(|session| session.stream(stream_id).accept_recv_seq(hdr.sequence_nr))
                .unwrap_or(false);
            if !accepted {
                log::debug!(
                    "Dropped a replayed sequence number {} on session {} stream {}",
                    hdr.sequence_nr,
                    session_id,
                    stream_id
                );
                return None;
            }
        }

        match submsg {
            Submessage::Create(payload) => self.handle_create(session_id, stream_id, payload),
            Submessage::Delete(payload) => {
                self.handle_delete(session_id, stream_id, payload.object_id)
            }
            Submessage::WriteData(payload) => {
                self.handle_write_data(session_id, stream_id, payload)
            }
            Submessage::ReadData(payload) => self.handle_read_data(session_id, stream_id, payload),
            Submessage::Heartbeat(payload) => self.handle_heartbeat(session_id, stream_id, payload),
            _ => None,
        }
    }

    /// Handle CREATE submessage: create a DDS entity through the bridge.
    fn handle_create(
        &mut self,
        session_id: u8,
        stream_id: u8,
        payload: &CreatePayload,
    ) -> Option<Vec<u8>> {
        let result = match payload.kind {
            ObjectKind::Participant => self.bridge.create_participant(payload.parent_id),
            ObjectKind::Topic => {
                // Decode topic_name and type_name from string_data
                let (topic_name, type_name) =
                    decode_topic_strings(&payload.string_data).unwrap_or_default();
                let participant = self.find_bridge_handle(session_id, payload.parent_id);
                match participant {
                    Some(pid) => self.bridge.create_topic(pid, &topic_name, &type_name),
                    None => Err(XrceError::ObjectNotFound(payload.parent_id)),
                }
            }
            ObjectKind::Publisher | ObjectKind::Subscriber => {
                // Publisher/Subscriber are implicit in XRCE; succeed with dummy handle.
                Ok(payload.object_id as u32)
            }
            ObjectKind::DataWriter => {
                let (p_handle, t_handle) =
                    self.find_writer_reader_parents(session_id, payload.parent_id);
                match (p_handle, t_handle) {
                    (Some(p), Some(t)) => self.bridge.create_writer(p, t),
                    _ => Err(XrceError::ObjectNotFound(payload.parent_id)),
                }
            }
            ObjectKind::DataReader => {
                let (p_handle, t_handle) =
                    self.find_writer_reader_parents(session_id, payload.parent_id);
                match (p_handle, t_handle) {
                    (Some(p), Some(t)) => self.bridge.create_reader(p, t),
                    _ => Err(XrceError::ObjectNotFound(payload.parent_id)),
                }
            }
        };

        let status = match result {
            Ok(handle) => {
                if let Some(session) = self.sessions.get_mut(session_id) {
                    session.add_object(XrceObject {
                        object_id: payload.object_id,
                        kind: payload.kind,
                        bridge_handle: handle,
                    });
                }
                StatusCode::Ok
            }
            Err(e) => {
                log::warn!("CREATE failed for object {}: {}", payload.object_id, e);
                StatusCode::ErrInvalidData
            }
        };

        self.make_status_reply(session_id, stream_id, payload.object_id, status)
    }

    /// Handle DELETE submessage.
    fn handle_delete(&mut self, session_id: u8, stream_id: u8, object_id: u16) -> Option<Vec<u8>> {
        let status = if let Some(session) = self.sessions.get_mut(session_id) {
            if let Some(obj) = session.remove_object(object_id) {
                match self.bridge.delete_entity(obj.bridge_handle) {
                    Ok(()) => StatusCode::Ok,
                    Err(_) => StatusCode::ErrUnknownRef,
                }
            } else {
                StatusCode::ErrUnknownRef
            }
        } else {
            StatusCode::ErrUnknownRef
        };
        self.make_status_reply(session_id, stream_id, object_id, status)
    }

    /// Handle WRITE_DATA submessage.
    fn handle_write_data(
        &mut self,
        session_id: u8,
        stream_id: u8,
        payload: &protocol::WriteDataPayload,
    ) -> Option<Vec<u8>> {
        let status = if let Some(session) = self.sessions.get(session_id) {
            if let Some(obj) = session.get_object(payload.writer_id) {
                match self.bridge.write_data(obj.bridge_handle, &payload.data) {
                    Ok(()) => StatusCode::Ok,
                    Err(_) => StatusCode::ErrInvalidData,
                }
            } else {
                StatusCode::ErrUnknownRef
            }
        } else {
            StatusCode::ErrUnknownRef
        };
        self.make_status_reply(session_id, stream_id, payload.writer_id, status)
    }

    /// Handle READ_DATA submessage.
    fn handle_read_data(
        &mut self,
        session_id: u8,
        stream_id: u8,
        payload: &protocol::ReadDataPayload,
    ) -> Option<Vec<u8>> {
        let bridge_handle = self
            .sessions
            .get(session_id)
            .and_then(|s| s.get_object(payload.reader_id))
            .map(|o| o.bridge_handle);

        match bridge_handle {
            Some(handle) => match self.bridge.read_data(handle) {
                Ok(Some(data)) => self.emit(
                    session_id,
                    stream_id,
                    Submessage::Data(DataPayload {
                        reader_id: payload.reader_id,
                        data,
                    }),
                ),
                Ok(None) => {
                    // No data available; send empty status OK.
                    self.make_status_reply(session_id, stream_id, payload.reader_id, StatusCode::Ok)
                }
                Err(_) => self.make_status_reply(
                    session_id,
                    stream_id,
                    payload.reader_id,
                    StatusCode::ErrInvalidData,
                ),
            },
            None => self.make_status_reply(
                session_id,
                stream_id,
                payload.reader_id,
                StatusCode::ErrUnknownRef,
            ),
        }
    }

    /// Handle HEARTBEAT from client (only meaningful on reliable streams).
    fn handle_heartbeat(
        &mut self,
        session_id: u8,
        stream_id: u8,
        payload: &protocol::HeartbeatPayload,
    ) -> Option<Vec<u8>> {
        let acknack = {
            let session = self.sessions.get_mut(session_id)?;
            let stream = session.stream(stream_id);
            stream.make_acknack(payload.first_unacked_seq, payload.last_seq)
        };
        self.emit(session_id, stream_id, Submessage::Acknack(acknack))
    }

    /// Handle ACKNACK from a client: drop acknowledged frames and return the
    /// frames the client says it is missing, ready to be resent verbatim.
    fn handle_acknack(
        &mut self,
        session_id: u8,
        stream_id: u8,
        payload: &protocol::AcknackPayload,
    ) -> Vec<Vec<u8>> {
        let Some(session) = self.sessions.get_mut(session_id) else {
            return Vec::new();
        };
        session.touch();
        let stream = session.stream(stream_id);
        let retransmit = stream.process_acknack(payload);
        let mut frames = Vec::with_capacity(retransmit.len());
        for seq in retransmit {
            if let Some(frame) = stream.unacked.get(&seq) {
                log::debug!(
                    "Retransmitting session {} stream {} seq {}",
                    session_id,
                    stream_id,
                    seq
                );
                frames.push(frame.clone());
            }
        }
        frames
    }

    /// Build the HEARTBEAT frames due right now, with their destinations.
    ///
    /// A reliable stream with nothing outstanding stays silent.
    pub fn due_heartbeats(&mut self) -> Vec<(TransportAddr, Vec<u8>)> {
        let period = self.config.heartbeat_period_ms;
        let session_ids: Vec<u8> = self
            .sessions
            .sessions
            .iter()
            .filter(|(_, s)| s.heartbeat_due(period))
            .map(|(&id, _)| id)
            .collect();

        let mut out = Vec::new();
        for session_id in session_ids {
            let Some(addr) = self.session_addr.get(&session_id).cloned() else {
                continue;
            };
            let streams = match self.sessions.get(session_id) {
                Some(s) => s.reliable_streams(),
                None => continue,
            };
            let mut beats: Vec<(u8, HeartbeatPayload)> = Vec::new();
            if let Some(session) = self.sessions.get_mut(session_id) {
                for stream_id in streams {
                    let stream = session.stream(stream_id);
                    if stream.unacked.is_empty() {
                        continue;
                    }
                    beats.push((stream_id, stream.make_heartbeat()));
                }
                session.mark_heartbeat_sent();
            }
            for (stream_id, beat) in beats {
                // A HEARTBEAT is not itself a reliable payload: build it
                // without consuming a stream sequence number.
                let msg = XrceMessage {
                    header: MessageHeader::new(session_id, stream_id, 0),
                    submessages: vec![Submessage::Heartbeat(beat)],
                };
                if let Ok(bytes) = protocol::serialize_message(&msg) {
                    out.push((addr.clone(), bytes));
                }
            }
        }
        out
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /// Serialize one submessage on a session stream, allocating its sequence
    /// number and recording it for retransmission on reliable streams.
    fn emit(&mut self, session_id: u8, stream_id: u8, submsg: Submessage) -> Option<Vec<u8>> {
        let session = self.sessions.get_mut(session_id)?;
        let stream = session.stream(stream_id);
        let seq = stream.alloc_send_seq();
        let msg = XrceMessage {
            header: MessageHeader::new(session_id, stream_id, seq),
            submessages: vec![submsg],
        };
        let bytes = match protocol::serialize_message(&msg) {
            Ok(b) => b,
            Err(e) => {
                log::warn!("Cannot serialize reply for session {}: {}", session_id, e);
                return None;
            }
        };
        stream.record_sent(seq, bytes.clone());
        Some(bytes)
    }

    /// Build a STATUS reply message.
    fn make_status_reply(
        &mut self,
        session_id: u8,
        stream_id: u8,
        object_id: u16,
        status: StatusCode,
    ) -> Option<Vec<u8>> {
        self.emit(
            session_id,
            stream_id,
            Submessage::Status(StatusPayload {
                related_object_id: object_id,
                status,
            }),
        )
    }

    /// Find the bridge handle for an object in the session.
    fn find_bridge_handle(&self, session_id: u8, object_id: u16) -> Option<u32> {
        self.sessions
            .get(session_id)
            .and_then(|s| s.get_object(object_id))
            .map(|o| o.bridge_handle)
    }

    /// For DataWriter/DataReader creation we need both a participant and topic handle.
    /// `parent_id` for a writer/reader points to a publisher/subscriber or directly
    /// to a participant. We walk the object list to find them.
    fn find_writer_reader_parents(
        &self,
        session_id: u8,
        _parent_id: u16,
    ) -> (Option<u32>, Option<u32>) {
        let session = match self.sessions.get(session_id) {
            Some(s) => s,
            None => return (None, None),
        };
        // Find participant (kind=Participant) and topic (kind=Topic).
        let mut participant = None;
        let mut topic = None;
        for obj in session.objects.values() {
            match obj.kind {
                ObjectKind::Participant => participant = Some(obj.bridge_handle),
                ObjectKind::Topic => topic = Some(obj.bridge_handle),
                _ => {}
            }
        }
        (participant, topic)
    }

    /// Evict expired sessions. Returns removed session ids.
    ///
    /// A session owns real DDS entities - with the HDDS bridge, a participant
    /// with its threads and sockets, a topic and a writer or reader each. They
    /// are released here: dropping the session table entry alone would leave
    /// them live in the bridge for the lifetime of the process, so an agent
    /// whose clients reconnect after every timeout would accumulate
    /// participants until it died.
    pub fn evict_expired(&mut self) -> Vec<u8> {
        let expired_sessions = self.sessions.take_expired();
        let expired: Vec<u8> = expired_sessions.iter().map(|s| s.session_id).collect();
        for session in expired_sessions {
            for (object_id, object) in session.objects {
                if let Err(e) = self.bridge.delete_entity(object.bridge_handle) {
                    log::warn!(
                        "Session {} expired but object {} could not be released: {}",
                        session.session_id,
                        object_id,
                        e
                    );
                }
            }
        }
        // Clean the address maps in both directions.
        self.addr_map.retain(|_, sid| !expired.contains(sid));
        self.session_addr.retain(|sid, _| !expired.contains(sid));
        expired
    }

    /// Number of active sessions.
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// Get the configuration.
    pub fn config(&self) -> &XrceAgentConfig {
        &self.config
    }

    /// Get read-only access to the session table.
    pub fn sessions(&self) -> &SessionTable {
        &self.sessions
    }

    /// Run a single tick of the agent loop against a transport.
    /// Reads one message, processes it, sends replies, then emits any
    /// HEARTBEAT that has come due and evicts timed-out sessions.
    pub fn tick(&mut self, transport: &mut dyn XrceTransport) -> Result<(), XrceError> {
        // One byte more than the policy allows, so a datagram that exceeds
        // `max_message_size` is DETECTED rather than silently truncated into
        // a prefix the agent would then execute. (A UDP receive truncates
        // without telling anyone; the extra byte is the only signal std
        // gives.)
        let mut buf = vec![0u8; self.config.max_message_size + 1];
        match transport.recv(&mut buf) {
            Ok((n, _)) if n > self.config.max_message_size => {
                self.oversized_messages += 1;
                log::warn!(
                    "Dropped an inbound message larger than max_message_size ({} bytes)",
                    self.config.max_message_size
                );
            }
            Ok((n, from)) => {
                let replies = self.process_incoming(&from, &buf[..n]);
                for (addr, data) in replies {
                    if let Err(e) = transport.send(&addr, &data) {
                        log::warn!("Failed to send reply: {}", e);
                    }
                }
            }
            Err(XrceError::Io(_)) => {
                // Would-block or similar; not an error in non-blocking mode.
            }
            Err(e) => return Err(e),
        }

        for (addr, data) in self.due_heartbeats() {
            if let Err(e) = transport.send(&addr, &data) {
                log::warn!("Failed to send heartbeat: {}", e);
            }
        }

        // Evict timed-out sessions.
        let expired = self.evict_expired();
        for sid in expired {
            log::info!("Session {} timed out", sid);
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build a standalone STATUS message for a session that does not exist (yet):
/// refused admission, or a full session table.
fn status_only_message(
    request_header: &MessageHeader,
    object_id: u16,
    status: StatusCode,
) -> Option<Vec<u8>> {
    let mut header = *request_header;
    header.sequence_nr = 0;
    let msg = XrceMessage {
        header,
        submessages: vec![Submessage::Status(StatusPayload {
            related_object_id: object_id,
            status,
        })],
    };
    protocol::serialize_message(&msg).ok()
}

/// Parse a bare submessage sequence (no message header), as produced by
/// reassembling FRAGMENT chunks.
fn parse_submessage_sequence(body: &[u8]) -> Result<Vec<Submessage>, XrceError> {
    let mut offset = 0usize;
    let mut out = Vec::new();
    while offset < body.len() {
        let (submsg, consumed) = protocol::parse_submessage(&body[offset..])?;
        out.push(submsg);
        offset += consumed;
    }
    if out.is_empty() {
        return Err(XrceError::BufferTooShort);
    }
    Ok(out)
}

/// Decode topic_name + type_name from the string_data field of a CREATE payload.
fn decode_topic_strings(data: &[u8]) -> Option<(String, String)> {
    let (name, consumed) = protocol::decode_string(data).ok()?;
    let (type_name, _) = protocol::decode_string(&data[consumed..]).ok()?;
    Some((name, type_name))
}
