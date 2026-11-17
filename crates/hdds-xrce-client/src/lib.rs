// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

#![no_std]
#![deny(unsafe_code)]

//! DDS-XRCE client for resource-constrained devices.
//!
//! `no_std`, no `alloc`, no dependencies: every message is built into a
//! caller-provided byte slice and every parse borrows from the caller's
//! receive buffer, so the crate allocates nothing at all. It compiles for
//! `thumbv7em-none-eabihf`; `scripts/xrce-size-gate.sh` measures what it
//! actually costs in flash and RAM.
//!
//! It speaks the same framing as the `hdds-xrce` agent (DDS-XRCE 1.0 message
//! header with the ClientKey rule, submessage ids, STATUS codes, FRAGMENT
//! flag). The agent-side test `client_agent_roundtrip.rs` drives this client
//! against a real [`hdds_xrce::XrceAgent`] and
//! `wire_constants_match_the_agent` fails the build if the two ever drift.
//!
//! ```
//! use hdds_xrce_client::{ObjectKind, XrceClient};
//!
//! let mut buf = [0u8; 128];
//! let mut client = XrceClient::new([0xDE, 0xAD, 0xBE, 0xEF]);
//! let n = client.create_client(&mut buf).unwrap();
//! assert!(n > 0);
//! let n = client
//!     .create_object(&mut buf, 1, ObjectKind::Participant, 0, &[])
//!     .unwrap();
//! assert!(n > 0);
//! ```

use core::mem::size_of;

// ---------------------------------------------------------------------------
// Wire constants (DDS-XRCE 1.0)
// ---------------------------------------------------------------------------

/// Minimum message header size.
pub const MESSAGE_HEADER_SIZE: usize = 4;
/// ClientKey size.
pub const CLIENT_KEY_SIZE: usize = 4;
/// Message header size when the ClientKey is present.
pub const MAX_MESSAGE_HEADER_SIZE: usize = MESSAGE_HEADER_SIZE + CLIENT_KEY_SIZE;
/// Submessage header size.
pub const SUBMESSAGE_HEADER_SIZE: usize = 4;
/// First session id that carries no ClientKey in the header.
pub const SESSION_ID_WITHOUT_CLIENT_KEY: u8 = 0x80;

/// Session id used for CREATE_CLIENT before the agent assigns one.
pub const SESSION_ID_UNASSIGNED: u8 = 0x00;

// Submessage ids.
pub const SUBMSG_CREATE_CLIENT: u8 = 0;
pub const SUBMSG_CREATE: u8 = 1;
pub const SUBMSG_GET_INFO: u8 = 2;
pub const SUBMSG_DELETE: u8 = 3;
pub const SUBMSG_STATUS_AGENT: u8 = 4;
pub const SUBMSG_STATUS: u8 = 5;
pub const SUBMSG_INFO: u8 = 6;
pub const SUBMSG_WRITE_DATA: u8 = 7;
pub const SUBMSG_READ_DATA: u8 = 8;
pub const SUBMSG_DATA: u8 = 9;
pub const SUBMSG_ACKNACK: u8 = 10;
pub const SUBMSG_HEARTBEAT: u8 = 11;
pub const SUBMSG_RESET: u8 = 12;
pub const SUBMSG_FRAGMENT: u8 = 13;
pub const SUBMSG_TIMESTAMP: u8 = 14;
pub const SUBMSG_TIMESTAMP_REPLY: u8 = 15;

/// Submessage flag: last fragment of a fragmented message.
pub const FLAG_LAST_FRAGMENT: u8 = 0x02;

// Status codes.
pub const STATUS_OK: u8 = 0x00;
pub const STATUS_OK_MATCHED: u8 = 0x01;
pub const STATUS_ERR_DDS_ERROR: u8 = 0x80;
pub const STATUS_ERR_MISMATCH: u8 = 0x81;
pub const STATUS_ERR_ALREADY_EXISTS: u8 = 0x82;
pub const STATUS_ERR_DENIED: u8 = 0x83;
pub const STATUS_ERR_UNKNOWN_REFERENCE: u8 = 0x84;
pub const STATUS_ERR_INVALID_DATA: u8 = 0x85;
pub const STATUS_ERR_INCOMPATIBLE: u8 = 0x86;
pub const STATUS_ERR_RESOURCES: u8 = 0x87;

// Object kinds.
pub const OBJ_PARTICIPANT: u8 = 0x01;
pub const OBJ_TOPIC: u8 = 0x02;
pub const OBJ_PUBLISHER: u8 = 0x03;
pub const OBJ_SUBSCRIBER: u8 = 0x04;
pub const OBJ_DATAWRITER: u8 = 0x05;
pub const OBJ_DATAREADER: u8 = 0x06;

/// Number of stream slots a client tracks (stream 0 plus three reliable
/// streams). Fixed: no allocation anywhere in this crate.
pub const MAX_STREAMS: usize = 4;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Every failure this crate can report. No allocation, no string payloads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientError {
    /// The caller's buffer is too small for the message being built.
    BufferTooSmall,
    /// The received bytes are shorter than the structure being parsed.
    Truncated,
    /// Unknown submessage id.
    UnknownSubmessage(u8),
    /// Unknown status code.
    UnknownStatus(u8),
    /// Unknown object kind.
    UnknownObjectKind(u8),
    /// The payload is larger than a single XRCE message can carry.
    PayloadTooLarge,
    /// A stream id outside the fixed stream table.
    UnknownStream(u8),
}

/// DDS entity kinds a client can ask the agent to create.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectKind {
    Participant,
    Topic,
    Publisher,
    Subscriber,
    DataWriter,
    DataReader,
}

impl ObjectKind {
    pub fn as_u8(self) -> u8 {
        match self {
            Self::Participant => OBJ_PARTICIPANT,
            Self::Topic => OBJ_TOPIC,
            Self::Publisher => OBJ_PUBLISHER,
            Self::Subscriber => OBJ_SUBSCRIBER,
            Self::DataWriter => OBJ_DATAWRITER,
            Self::DataReader => OBJ_DATAREADER,
        }
    }

    pub fn from_u8(v: u8) -> Result<Self, ClientError> {
        match v {
            OBJ_PARTICIPANT => Ok(Self::Participant),
            OBJ_TOPIC => Ok(Self::Topic),
            OBJ_PUBLISHER => Ok(Self::Publisher),
            OBJ_SUBSCRIBER => Ok(Self::Subscriber),
            OBJ_DATAWRITER => Ok(Self::DataWriter),
            OBJ_DATAREADER => Ok(Self::DataReader),
            other => Err(ClientError::UnknownObjectKind(other)),
        }
    }
}

/// What the agent just told this client. Borrows the receive buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientEvent<'a> {
    /// STATUS for a request.
    Status { object_id: u16, status: u8 },
    /// A sample from a DataReader.
    Data { reader_id: u16, payload: &'a [u8] },
    /// The agent reports what it has sent on a reliable stream.
    Heartbeat { first_unacked: u16, last: u16 },
    /// The agent asks for retransmission.
    Acknack { first_unacked: u16, bitmap: u16 },
    /// One chunk of a fragmented message.
    Fragment { last: bool, payload: &'a [u8] },
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

/// A DDS-XRCE client session.
///
/// The whole state is this struct: a ClientKey, the session id the agent
/// assigned, and one outbound sequence counter per stream slot.
#[derive(Debug, Clone, Copy)]
pub struct XrceClient {
    client_key: [u8; CLIENT_KEY_SIZE],
    session_id: u8,
    connected: bool,
    send_seq: [u16; MAX_STREAMS],
    recv_seq: [u16; MAX_STREAMS],
}

/// RAM cost of one client session, in bytes. Measured, not asserted:
/// `size_of::<XrceClient>()`.
pub const CLIENT_STATE_BYTES: usize = size_of::<XrceClient>();

impl XrceClient {
    /// Create a client for the given ClientKey. The key is the shared secret
    /// the agent's admission list is checked against.
    pub fn new(client_key: [u8; CLIENT_KEY_SIZE]) -> Self {
        Self {
            client_key,
            session_id: SESSION_ID_UNASSIGNED,
            connected: false,
            send_seq: [0; MAX_STREAMS],
            recv_seq: [0; MAX_STREAMS],
        }
    }

    /// Session id assigned by the agent (0 until CREATE_CLIENT is answered).
    pub fn session_id(&self) -> u8 {
        self.session_id
    }

    /// True once the agent has answered CREATE_CLIENT with a success status.
    pub fn is_connected(&self) -> bool {
        self.connected
    }

    /// Build a CREATE_CLIENT message into `buf`. Returns the message length.
    pub fn create_client(&mut self, buf: &mut [u8]) -> Result<usize, ClientError> {
        let key = self.client_key;
        let mut payload = [0u8; CLIENT_KEY_SIZE + 1];
        payload[..CLIENT_KEY_SIZE].copy_from_slice(&key);
        payload[CLIENT_KEY_SIZE] = 0;
        // CREATE_CLIENT always travels on the unassigned, keyed session id.
        self.build(
            buf,
            SESSION_ID_UNASSIGNED,
            0,
            SUBMSG_CREATE_CLIENT,
            0,
            |out| copy(out, &payload),
        )
    }

    /// Build a CREATE message for a DDS entity.
    ///
    /// `strings` is the already encoded name/type block for a Topic (see
    /// [`encode_string`]); pass an empty slice for the other kinds.
    pub fn create_object(
        &mut self,
        buf: &mut [u8],
        object_id: u16,
        kind: ObjectKind,
        parent_id: u16,
        strings: &[u8],
    ) -> Result<usize, ClientError> {
        let session_id = self.session_id;
        self.build(buf, session_id, 0, SUBMSG_CREATE, 0, |out| {
            let mut n = 0;
            n += copy(&mut out[n..], &object_id.to_le_bytes())?;
            n += copy(&mut out[n..], &[kind.as_u8()])?;
            n += copy(&mut out[n..], &parent_id.to_le_bytes())?;
            n += copy(&mut out[n..], strings)?;
            Ok(n)
        })
    }

    /// Build a DELETE message.
    pub fn delete_object(&mut self, buf: &mut [u8], object_id: u16) -> Result<usize, ClientError> {
        let session_id = self.session_id;
        self.build(buf, session_id, 0, SUBMSG_DELETE, 0, |out| {
            copy(out, &object_id.to_le_bytes())
        })
    }

    /// Build a WRITE_DATA message carrying an already serialized sample.
    pub fn write_data(
        &mut self,
        buf: &mut [u8],
        stream_id: u8,
        writer_id: u16,
        data: &[u8],
    ) -> Result<usize, ClientError> {
        let session_id = self.session_id;
        self.build(buf, session_id, stream_id, SUBMSG_WRITE_DATA, 0, |out| {
            let mut n = 0;
            n += copy(&mut out[n..], &writer_id.to_le_bytes())?;
            n += copy(&mut out[n..], data)?;
            Ok(n)
        })
    }

    /// Build a READ_DATA message.
    pub fn read_data(
        &mut self,
        buf: &mut [u8],
        reader_id: u16,
        max_samples: u16,
    ) -> Result<usize, ClientError> {
        let session_id = self.session_id;
        self.build(buf, session_id, 0, SUBMSG_READ_DATA, 0, |out| {
            let mut n = 0;
            n += copy(&mut out[n..], &reader_id.to_le_bytes())?;
            n += copy(&mut out[n..], &max_samples.to_le_bytes())?;
            Ok(n)
        })
    }

    /// Build a HEARTBEAT message for a reliable stream.
    pub fn heartbeat(
        &mut self,
        buf: &mut [u8],
        stream_id: u8,
        first_unacked: u16,
        last: u16,
    ) -> Result<usize, ClientError> {
        let session_id = self.session_id;
        self.build(buf, session_id, stream_id, SUBMSG_HEARTBEAT, 0, |out| {
            let mut n = 0;
            n += copy(&mut out[n..], &first_unacked.to_le_bytes())?;
            n += copy(&mut out[n..], &last.to_le_bytes())?;
            Ok(n)
        })
    }

    /// Build an ACKNACK message for a reliable stream.
    pub fn acknack(
        &mut self,
        buf: &mut [u8],
        stream_id: u8,
        first_unacked: u16,
        bitmap: u16,
    ) -> Result<usize, ClientError> {
        let session_id = self.session_id;
        self.build(buf, session_id, stream_id, SUBMSG_ACKNACK, 0, |out| {
            let mut n = 0;
            n += copy(&mut out[n..], &first_unacked.to_le_bytes())?;
            n += copy(&mut out[n..], &bitmap.to_le_bytes())?;
            Ok(n)
        })
    }

    /// Acknowledge everything received so far on `stream_id`.
    pub fn ack_all(&mut self, buf: &mut [u8], stream_id: u8) -> Result<usize, ClientError> {
        let next = self.recv_seq[stream_slot(stream_id)?];
        self.acknack(buf, stream_id, next, 0)
    }

    /// Parse one message from the agent.
    ///
    /// Only the first submessage is reported: the agent sends one submessage
    /// per message, and a fixed-buffer client has nowhere to queue the rest.
    pub fn process<'a>(&mut self, msg: &'a [u8]) -> Result<ClientEvent<'a>, ClientError> {
        if msg.len() < MESSAGE_HEADER_SIZE {
            return Err(ClientError::Truncated);
        }
        let session_id = msg[0];
        let stream_id = msg[1];
        let sequence_nr = u16::from_le_bytes([msg[2], msg[3]]);
        let header_len = if session_id < SESSION_ID_WITHOUT_CLIENT_KEY {
            MAX_MESSAGE_HEADER_SIZE
        } else {
            MESSAGE_HEADER_SIZE
        };
        if msg.len() < header_len + SUBMESSAGE_HEADER_SIZE {
            return Err(ClientError::Truncated);
        }
        let sub = &msg[header_len..];
        let id = sub[0];
        let flags = sub[1];
        let length = u16::from_le_bytes([sub[2], sub[3]]) as usize;
        if sub.len() < SUBMESSAGE_HEADER_SIZE + length {
            return Err(ClientError::Truncated);
        }
        let payload = &sub[SUBMESSAGE_HEADER_SIZE..SUBMESSAGE_HEADER_SIZE + length];

        if let Ok(slot) = stream_slot(stream_id) {
            self.recv_seq[slot] = sequence_nr.wrapping_add(1);
        }

        match id {
            SUBMSG_STATUS => {
                if payload.len() < 3 {
                    return Err(ClientError::Truncated);
                }
                let object_id = u16::from_le_bytes([payload[0], payload[1]]);
                let status = payload[2];
                if !self.connected && status_is_ok(status) {
                    // The agent answers CREATE_CLIENT on the session id it
                    // assigned; adopt it.
                    self.session_id = session_id;
                    self.connected = true;
                }
                Ok(ClientEvent::Status { object_id, status })
            }
            SUBMSG_DATA => {
                if payload.len() < 2 {
                    return Err(ClientError::Truncated);
                }
                Ok(ClientEvent::Data {
                    reader_id: u16::from_le_bytes([payload[0], payload[1]]),
                    payload: &payload[2..],
                })
            }
            SUBMSG_HEARTBEAT => {
                if payload.len() < 4 {
                    return Err(ClientError::Truncated);
                }
                Ok(ClientEvent::Heartbeat {
                    first_unacked: u16::from_le_bytes([payload[0], payload[1]]),
                    last: u16::from_le_bytes([payload[2], payload[3]]),
                })
            }
            SUBMSG_ACKNACK => {
                if payload.len() < 4 {
                    return Err(ClientError::Truncated);
                }
                Ok(ClientEvent::Acknack {
                    first_unacked: u16::from_le_bytes([payload[0], payload[1]]),
                    bitmap: u16::from_le_bytes([payload[2], payload[3]]),
                })
            }
            SUBMSG_FRAGMENT => Ok(ClientEvent::Fragment {
                last: flags & FLAG_LAST_FRAGMENT != 0,
                payload,
            }),
            other => Err(ClientError::UnknownSubmessage(other)),
        }
    }

    /// Build header + one submessage, letting `fill` write the payload.
    fn build<F>(
        &mut self,
        buf: &mut [u8],
        session_id: u8,
        stream_id: u8,
        submessage_id: u8,
        flags: u8,
        fill: F,
    ) -> Result<usize, ClientError>
    where
        F: FnOnce(&mut [u8]) -> Result<usize, ClientError>,
    {
        let slot = stream_slot(stream_id)?;
        let header_len = if session_id < SESSION_ID_WITHOUT_CLIENT_KEY {
            MAX_MESSAGE_HEADER_SIZE
        } else {
            MESSAGE_HEADER_SIZE
        };
        if buf.len() < header_len + SUBMESSAGE_HEADER_SIZE {
            return Err(ClientError::BufferTooSmall);
        }
        let seq = self.send_seq[slot];

        buf[0] = session_id;
        buf[1] = stream_id;
        buf[2..4].copy_from_slice(&seq.to_le_bytes());
        if header_len == MAX_MESSAGE_HEADER_SIZE {
            buf[MESSAGE_HEADER_SIZE..MAX_MESSAGE_HEADER_SIZE].copy_from_slice(&self.client_key);
        }

        let payload_len = fill(&mut buf[header_len + SUBMESSAGE_HEADER_SIZE..])?;
        if payload_len > u16::MAX as usize {
            return Err(ClientError::PayloadTooLarge);
        }
        buf[header_len] = submessage_id;
        buf[header_len + 1] = flags;
        buf[header_len + 2..header_len + 4].copy_from_slice(&(payload_len as u16).to_le_bytes());

        self.send_seq[slot] = seq.wrapping_add(1);
        Ok(header_len + SUBMESSAGE_HEADER_SIZE + payload_len)
    }
}

/// True for the two success status codes.
pub fn status_is_ok(status: u8) -> bool {
    status == STATUS_OK || status == STATUS_OK_MATCHED
}

/// Encode `s` as `[len_u16_le][utf8]` into `buf`. Returns the byte count.
pub fn encode_string(buf: &mut [u8], s: &str) -> Result<usize, ClientError> {
    let bytes = s.as_bytes();
    if bytes.len() > u16::MAX as usize {
        return Err(ClientError::PayloadTooLarge);
    }
    if buf.len() < 2 + bytes.len() {
        return Err(ClientError::BufferTooSmall);
    }
    buf[..2].copy_from_slice(&(bytes.len() as u16).to_le_bytes());
    buf[2..2 + bytes.len()].copy_from_slice(bytes);
    Ok(2 + bytes.len())
}

fn copy(out: &mut [u8], src: &[u8]) -> Result<usize, ClientError> {
    if out.len() < src.len() {
        return Err(ClientError::BufferTooSmall);
    }
    out[..src.len()].copy_from_slice(src);
    Ok(src.len())
}

fn stream_slot(stream_id: u8) -> Result<usize, ClientError> {
    let slot = stream_id as usize;
    if slot >= MAX_STREAMS {
        return Err(ClientError::UnknownStream(stream_id));
    }
    Ok(slot)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_state_fits_the_announced_ram_budget() {
        // The website announces "<20KB RAM" for DDS-XRCE. This is the
        // measurement behind that number on the client side: the session
        // state plus one 512-byte message buffer (the agent's default MTU).
        const MTU: usize = 512;
        let total = CLIENT_STATE_BYTES + MTU;
        assert!(
            total < 20 * 1024,
            "client RAM footprint {} bytes (state {} + MTU {})",
            total,
            CLIENT_STATE_BYTES,
            MTU
        );
        // The bound above is forty times the measurement, so it cannot catch
        // a regression. This one can: the state is a handful of scalars and
        // two small arrays, and it is meant to STAY that. Update the number
        // by hand when the struct genuinely changes.
        const MEASURED_STATE_CEILING: usize = 64;
        let state = CLIENT_STATE_BYTES;
        assert!(
            state <= MEASURED_STATE_CEILING,
            "the client session state grew to {} bytes (ceiling {}); \
             if that is intended, move the ceiling deliberately",
            CLIENT_STATE_BYTES,
            MEASURED_STATE_CEILING
        );
    }

    #[test]
    fn create_client_message_is_keyed_and_well_formed() {
        let mut buf = [0u8; 64];
        let mut client = XrceClient::new([0xDE, 0xAD, 0xBE, 0xEF]);
        let n = client.create_client(&mut buf).expect("build");
        assert_eq!(
            &buf[..n],
            &[
                0x00, 0x00, 0x00, 0x00, 0xDE, 0xAD, 0xBE, 0xEF, // header + key
                0x00, 0x00, 0x05, 0x00, // CREATE_CLIENT, flags 0, len 5
                0xDE, 0xAD, 0xBE, 0xEF, 0x00,
            ]
        );
    }

    #[test]
    fn a_too_small_buffer_is_an_error_not_a_panic() {
        let mut buf = [0u8; 4];
        let mut client = XrceClient::new([1, 2, 3, 4]);
        assert_eq!(
            client.create_client(&mut buf),
            Err(ClientError::BufferTooSmall)
        );
        let mut buf = [0u8; 13];
        assert_eq!(
            client.create_client(&mut buf),
            Err(ClientError::BufferTooSmall)
        );
    }

    #[test]
    fn status_adopts_the_agent_session_id() {
        let mut client = XrceClient::new([1, 2, 3, 4]);
        assert!(!client.is_connected());
        // session 0x82, stream 0, seq 0, STATUS(object 0) = OK
        let msg = [
            0x82, 0x00, 0x00, 0x00, 0x05, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00,
        ];
        match client.process(&msg).expect("parse") {
            ClientEvent::Status { object_id, status } => {
                assert_eq!(object_id, 0);
                assert_eq!(status, STATUS_OK);
            }
            other => panic!("unexpected {:?}", other),
        }
        assert!(client.is_connected());
        assert_eq!(client.session_id(), 0x82);
    }

    #[test]
    fn a_truncated_message_is_rejected() {
        let mut client = XrceClient::new([1, 2, 3, 4]);
        assert_eq!(client.process(&[0x82, 0x00]), Err(ClientError::Truncated));
        // Announced length longer than the bytes present.
        assert_eq!(
            client.process(&[0x82, 0x00, 0x00, 0x00, 0x09, 0x00, 0xFF, 0x00]),
            Err(ClientError::Truncated)
        );
    }
}
