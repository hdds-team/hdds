// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

// XRCE Agent main loop.
//
// Accepts XRCE clients over any transport, dispatches submessages
// to the appropriate session, and bridges operations to DDS via ProxyBridge.

use std::sync::Arc;

use crate::config::XrceAgentConfig;
use crate::protocol::{
    self, CreatePayload, DataPayload, MessageHeader, ObjectKind,
    StatusCode, StatusPayload, Submessage, XrceError, XrceMessage,
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
    addr_map: std::collections::HashMap<TransportAddr, u8>,
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
            addr_map: std::collections::HashMap::new(),
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

        for submsg in &msg.submessages {
            match submsg {
                Submessage::CreateClient(payload) => {
                    let reply = self.handle_create_client(from, &msg.header, payload);
                    if let Some(r) = reply {
                        replies.push((from.clone(), r));
                    }
                }
                _ => {
                    // All other submessages require an existing session.
                    if let Some(reply) =
                        self.handle_session_submessage(from, &msg.header, submsg)
                    {
                        replies.push((from.clone(), reply));
                    }
                }
            }
        }

        replies
    }

    /// Handle CREATE_CLIENT: allocate a session and send STATUS back.
    fn handle_create_client(
        &mut self,
        from: &TransportAddr,
        _hdr: &MessageHeader,
        payload: &protocol::CreateClientPayload,
    ) -> Option<Vec<u8>> {
        let result = self.sessions.create_session(payload.client_key);
        let (session_id, status) = match result {
            Ok(id) => {
                self.addr_map.insert(from.clone(), id);
                log::info!("Client connected: session_id={}", id);
                (id, StatusCode::Ok)
            }
            Err(_) => {
                log::warn!("Cannot allocate session: table full");
                (0, StatusCode::ErrResources)
            }
        };

        let reply_submsg = Submessage::Status(StatusPayload {
            related_object_id: 0,
            status,
        });
        let reply = XrceMessage {
            header: MessageHeader {
                session_id,
                stream_id: 0,
                sequence_nr: 0,
            },
            submessages: vec![reply_submsg],
        };
        Some(protocol::serialize_message(&reply))
    }

    /// Dispatch a submessage within an existing session.
    fn handle_session_submessage(
        &mut self,
        _from: &TransportAddr,
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

        match submsg {
            Submessage::Create(payload) => {
                self.handle_create(session_id, stream_id, payload)
            }
            Submessage::Delete(payload) => {
                self.handle_delete(session_id, stream_id, payload.object_id)
            }
            Submessage::WriteData(payload) => {
                self.handle_write_data(session_id, stream_id, payload)
            }
            Submessage::ReadData(payload) => {
                self.handle_read_data(session_id, stream_id, payload)
            }
            Submessage::Heartbeat(payload) => {
                self.handle_heartbeat(session_id, stream_id, payload)
            }
            Submessage::Acknack(payload) => {
                self.handle_acknack(session_id, stream_id, payload);
                None
            }
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
            ObjectKind::Participant => {
                self.bridge.create_participant(payload.parent_id)
            }
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

        Some(self.make_status_reply(session_id, stream_id, payload.object_id, status))
    }

    /// Handle DELETE submessage.
    fn handle_delete(
        &mut self,
        session_id: u8,
        stream_id: u8,
        object_id: u16,
    ) -> Option<Vec<u8>> {
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
        Some(self.make_status_reply(session_id, stream_id, object_id, status))
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
        Some(self.make_status_reply(session_id, stream_id, payload.writer_id, status))
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
                Ok(Some(data)) => {
                    let data_submsg = Submessage::Data(DataPayload {
                        reader_id: payload.reader_id,
                        data,
                    });
                    let msg = XrceMessage {
                        header: MessageHeader {
                            session_id,
                            stream_id,
                            sequence_nr: 0,
                        },
                        submessages: vec![data_submsg],
                    };
                    Some(protocol::serialize_message(&msg))
                }
                Ok(None) => {
                    // No data available; send empty status OK.
                    Some(self.make_status_reply(
                        session_id,
                        stream_id,
                        payload.reader_id,
                        StatusCode::Ok,
                    ))
                }
                Err(_) => Some(self.make_status_reply(
                    session_id,
                    stream_id,
                    payload.reader_id,
                    StatusCode::ErrInvalidData,
                )),
            },
            None => Some(self.make_status_reply(
                session_id,
                stream_id,
                payload.reader_id,
                StatusCode::ErrUnknownRef,
            )),
        }
    }

    /// Handle HEARTBEAT from client (only meaningful on reliable streams).
    fn handle_heartbeat(
        &mut self,
        session_id: u8,
        stream_id: u8,
        payload: &protocol::HeartbeatPayload,
    ) -> Option<Vec<u8>> {
        if let Some(session) = self.sessions.get_mut(session_id) {
            let stream = session.stream(stream_id);
            let acknack = stream.make_acknack(
                payload.first_unacked_seq,
                payload.last_seq,
            );
            let reply_submsg = Submessage::Acknack(acknack);
            let msg = XrceMessage {
                header: MessageHeader {
                    session_id,
                    stream_id,
                    sequence_nr: 0,
                },
                submessages: vec![reply_submsg],
            };
            Some(protocol::serialize_message(&msg))
        } else {
            None
        }
    }

    /// Handle ACKNACK from client.
    fn handle_acknack(
        &mut self,
        session_id: u8,
        stream_id: u8,
        payload: &protocol::AcknackPayload,
    ) {
        if let Some(session) = self.sessions.get_mut(session_id) {
            let stream = session.stream(stream_id);
            let _retransmit = stream.process_acknack(payload);
            // FIXME(#xrce-reliability): retransmit the listed sequence numbers.
        }
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /// Build a STATUS reply message.
    fn make_status_reply(
        &self,
        session_id: u8,
        stream_id: u8,
        object_id: u16,
        status: StatusCode,
    ) -> Vec<u8> {
        let submsg = Submessage::Status(StatusPayload {
            related_object_id: object_id,
            status,
        });
        let msg = XrceMessage {
            header: MessageHeader {
                session_id,
                stream_id,
                sequence_nr: 0,
            },
            submessages: vec![submsg],
        };
        protocol::serialize_message(&msg)
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
    pub fn evict_expired(&mut self) -> Vec<u8> {
        let expired = self.sessions.evict_expired();
        // Clean addr_map
        self.addr_map.retain(|_, sid| !expired.contains(sid));
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
    /// Reads one message, processes it, sends replies.
    pub fn tick(&mut self, transport: &mut dyn XrceTransport) -> Result<(), XrceError> {
        let mut buf = vec![0u8; self.config.max_message_size];
        match transport.recv(&mut buf) {
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

/// Decode topic_name + type_name from the string_data field of a CREATE payload.
fn decode_topic_strings(data: &[u8]) -> Option<(String, String)> {
    let (name, consumed) = protocol::decode_string(data).ok()?;
    let (type_name, _) = protocol::decode_string(&data[consumed..]).ok()?;
    Some((name, type_name))
}
