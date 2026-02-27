// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

// DDS-XRCE v1.0 wire format parser/builder.
//
// All parsing is safe: malformed input returns Err, never panics.

use std::fmt;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors produced by the XRCE subsystem.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum XrceError {
    /// Not enough bytes to parse a header / payload.
    BufferTooShort,
    /// Unknown submessage id.
    UnknownSubmessageId(u8),
    /// Unknown object kind byte.
    UnknownObjectKind(u8),
    /// Unknown status code.
    UnknownStatusCode(u8),
    /// Payload length does not match the expected size.
    PayloadLengthMismatch,
    /// Session is full (max clients reached).
    SessionFull,
    /// Session not found for the given session_id.
    SessionNotFound(u8),
    /// Object not found for the given object_id.
    ObjectNotFound(u16),
    /// A transport-level I/O error (message only, not the original error).
    Io(String),
    /// Fragmentation / reassembly error.
    FragmentError(String),
    /// Bridge / proxy error forwarded from the DDS side.
    BridgeError(String),
    /// Session has timed out.
    SessionTimeout,
    /// Configuration validation error.
    ConfigError(String),
}

impl fmt::Display for XrceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BufferTooShort => write!(f, "buffer too short"),
            Self::UnknownSubmessageId(id) => write!(f, "unknown submessage id: 0x{:02x}", id),
            Self::UnknownObjectKind(k) => write!(f, "unknown object kind: 0x{:02x}", k),
            Self::UnknownStatusCode(c) => write!(f, "unknown status code: 0x{:02x}", c),
            Self::PayloadLengthMismatch => write!(f, "payload length mismatch"),
            Self::SessionFull => write!(f, "session table full"),
            Self::SessionNotFound(id) => write!(f, "session not found: {}", id),
            Self::ObjectNotFound(id) => write!(f, "object not found: {}", id),
            Self::Io(msg) => write!(f, "I/O error: {}", msg),
            Self::FragmentError(msg) => write!(f, "fragment error: {}", msg),
            Self::BridgeError(msg) => write!(f, "bridge error: {}", msg),
            Self::SessionTimeout => write!(f, "session timeout"),
            Self::ConfigError(msg) => write!(f, "config error: {}", msg),
        }
    }
}

impl std::error::Error for XrceError {}

impl From<std::io::Error> for XrceError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e.to_string())
    }
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// XRCE message header size in bytes.
pub const MESSAGE_HEADER_SIZE: usize = 4;

/// XRCE submessage header size in bytes.
pub const SUBMESSAGE_HEADER_SIZE: usize = 4;

// Submessage IDs
pub const SUBMSG_CREATE_CLIENT: u8 = 0x00;
pub const SUBMSG_CREATE: u8 = 0x01;
pub const SUBMSG_DELETE: u8 = 0x02;
pub const SUBMSG_STATUS: u8 = 0x05;
pub const SUBMSG_WRITE_DATA: u8 = 0x07;
pub const SUBMSG_READ_DATA: u8 = 0x08;
pub const SUBMSG_DATA: u8 = 0x09;
pub const SUBMSG_HEARTBEAT: u8 = 0x0D;
pub const SUBMSG_ACKNACK: u8 = 0x0E;

// Object kinds
pub const OBJ_PARTICIPANT: u8 = 0x01;
pub const OBJ_TOPIC: u8 = 0x02;
pub const OBJ_PUBLISHER: u8 = 0x03;
pub const OBJ_SUBSCRIBER: u8 = 0x04;
pub const OBJ_DATAWRITER: u8 = 0x05;
pub const OBJ_DATAREADER: u8 = 0x06;

// Status codes
pub const STATUS_OK: u8 = 0x00;
pub const STATUS_ERR_UNKNOWN_REF: u8 = 0x01;
pub const STATUS_ERR_INVALID_DATA: u8 = 0x02;
pub const STATUS_ERR_INCOMPATIBLE: u8 = 0x03;
pub const STATUS_ERR_RESOURCES: u8 = 0x04;

// ---------------------------------------------------------------------------
// Object kind enum
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ObjectKind {
    Participant = OBJ_PARTICIPANT,
    Topic = OBJ_TOPIC,
    Publisher = OBJ_PUBLISHER,
    Subscriber = OBJ_SUBSCRIBER,
    DataWriter = OBJ_DATAWRITER,
    DataReader = OBJ_DATAREADER,
}

impl ObjectKind {
    pub fn from_u8(v: u8) -> Result<Self, XrceError> {
        match v {
            OBJ_PARTICIPANT => Ok(Self::Participant),
            OBJ_TOPIC => Ok(Self::Topic),
            OBJ_PUBLISHER => Ok(Self::Publisher),
            OBJ_SUBSCRIBER => Ok(Self::Subscriber),
            OBJ_DATAWRITER => Ok(Self::DataWriter),
            OBJ_DATAREADER => Ok(Self::DataReader),
            _ => Err(XrceError::UnknownObjectKind(v)),
        }
    }

    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

// ---------------------------------------------------------------------------
// Status code enum
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum StatusCode {
    Ok = STATUS_OK,
    ErrUnknownRef = STATUS_ERR_UNKNOWN_REF,
    ErrInvalidData = STATUS_ERR_INVALID_DATA,
    ErrIncompatible = STATUS_ERR_INCOMPATIBLE,
    ErrResources = STATUS_ERR_RESOURCES,
}

impl StatusCode {
    pub fn from_u8(v: u8) -> Result<Self, XrceError> {
        match v {
            STATUS_OK => Ok(Self::Ok),
            STATUS_ERR_UNKNOWN_REF => Ok(Self::ErrUnknownRef),
            STATUS_ERR_INVALID_DATA => Ok(Self::ErrInvalidData),
            STATUS_ERR_INCOMPATIBLE => Ok(Self::ErrIncompatible),
            STATUS_ERR_RESOURCES => Ok(Self::ErrResources),
            _ => Err(XrceError::UnknownStatusCode(v)),
        }
    }

    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

// ---------------------------------------------------------------------------
// Message header
// ---------------------------------------------------------------------------

/// Top-level XRCE message header (4 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MessageHeader {
    pub session_id: u8,
    pub stream_id: u8,
    pub sequence_nr: u16,
}

impl MessageHeader {
    pub fn parse(buf: &[u8]) -> Result<Self, XrceError> {
        if buf.len() < MESSAGE_HEADER_SIZE {
            return Err(XrceError::BufferTooShort);
        }
        Ok(Self {
            session_id: buf[0],
            stream_id: buf[1],
            sequence_nr: u16::from_le_bytes([buf[2], buf[3]]),
        })
    }

    pub fn write_to(&self, buf: &mut Vec<u8>) {
        buf.push(self.session_id);
        buf.push(self.stream_id);
        buf.extend_from_slice(&self.sequence_nr.to_le_bytes());
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(MESSAGE_HEADER_SIZE);
        self.write_to(&mut buf);
        buf
    }
}

// ---------------------------------------------------------------------------
// Submessage header
// ---------------------------------------------------------------------------

/// Submessage header (4 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SubmessageHeader {
    pub submessage_id: u8,
    pub flags: u8,
    pub length: u16,
}

impl SubmessageHeader {
    pub fn parse(buf: &[u8]) -> Result<Self, XrceError> {
        if buf.len() < SUBMESSAGE_HEADER_SIZE {
            return Err(XrceError::BufferTooShort);
        }
        Ok(Self {
            submessage_id: buf[0],
            flags: buf[1],
            length: u16::from_le_bytes([buf[2], buf[3]]),
        })
    }

    pub fn write_to(&self, buf: &mut Vec<u8>) {
        buf.push(self.submessage_id);
        buf.push(self.flags);
        buf.extend_from_slice(&self.length.to_le_bytes());
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(SUBMESSAGE_HEADER_SIZE);
        self.write_to(&mut buf);
        buf
    }
}

// ---------------------------------------------------------------------------
// Submessage payloads
// ---------------------------------------------------------------------------

/// CREATE_CLIENT (0x00) - client key (4 bytes) + properties (u8)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateClientPayload {
    pub client_key: [u8; 4],
    pub properties: u8,
}

/// CREATE (0x01) - create a DDS entity on the agent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreatePayload {
    pub object_id: u16,
    pub kind: ObjectKind,
    /// Domain id (for participant), or parent object id.
    pub parent_id: u16,
    /// Topic name / type name encoded as length-prefixed strings.
    /// For PARTICIPANT: empty.
    /// For TOPIC: name + type_name.
    /// For PUBLISHER/SUBSCRIBER/WRITER/READER: may be empty.
    pub string_data: Vec<u8>,
}

/// DELETE (0x02)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeletePayload {
    pub object_id: u16,
}

/// WRITE_DATA (0x07)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteDataPayload {
    pub writer_id: u16,
    pub data: Vec<u8>,
}

/// READ_DATA (0x08)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadDataPayload {
    pub reader_id: u16,
    pub max_samples: u16,
}

/// DATA (0x09) - agent -> client
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataPayload {
    pub reader_id: u16,
    pub data: Vec<u8>,
}

/// STATUS (0x05)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatusPayload {
    pub related_object_id: u16,
    pub status: StatusCode,
}

/// HEARTBEAT (0x0D)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeartbeatPayload {
    pub first_unacked_seq: u16,
    pub last_seq: u16,
}

/// ACKNACK (0x0E)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AcknackPayload {
    pub first_unacked_seq: u16,
    /// Bitmask of missing sequence numbers relative to first_unacked_seq.
    pub nack_bitmap: u16,
}

// ---------------------------------------------------------------------------
// Unified submessage enum
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Submessage {
    CreateClient(CreateClientPayload),
    Create(CreatePayload),
    Delete(DeletePayload),
    WriteData(WriteDataPayload),
    ReadData(ReadDataPayload),
    Data(DataPayload),
    Status(StatusPayload),
    Heartbeat(HeartbeatPayload),
    Acknack(AcknackPayload),
}

// ---------------------------------------------------------------------------
// Full XRCE message
// ---------------------------------------------------------------------------

/// A complete XRCE message: one header + one or more submessages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XrceMessage {
    pub header: MessageHeader,
    pub submessages: Vec<Submessage>,
}

// ---------------------------------------------------------------------------
// Fragment header (prepended when message is fragmented)
// ---------------------------------------------------------------------------

/// Fragment header (4 bytes), prepended before submessage data when
/// the message exceeds the transport MTU.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FragmentHeader {
    pub fragment_nr: u16,
    pub total_fragments: u16,
}

pub const FRAGMENT_HEADER_SIZE: usize = 4;

impl FragmentHeader {
    pub fn parse(buf: &[u8]) -> Result<Self, XrceError> {
        if buf.len() < FRAGMENT_HEADER_SIZE {
            return Err(XrceError::BufferTooShort);
        }
        Ok(Self {
            fragment_nr: u16::from_le_bytes([buf[0], buf[1]]),
            total_fragments: u16::from_le_bytes([buf[2], buf[3]]),
        })
    }

    pub fn write_to(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.fragment_nr.to_le_bytes());
        buf.extend_from_slice(&self.total_fragments.to_le_bytes());
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(FRAGMENT_HEADER_SIZE);
        self.write_to(&mut buf);
        buf
    }
}

// ---------------------------------------------------------------------------
// Parsing helpers (little-endian)
// ---------------------------------------------------------------------------

fn read_u16_le(buf: &[u8], off: usize) -> Result<u16, XrceError> {
    if off + 2 > buf.len() {
        return Err(XrceError::BufferTooShort);
    }
    Ok(u16::from_le_bytes([buf[off], buf[off + 1]]))
}

// ---------------------------------------------------------------------------
// Submessage parsing
// ---------------------------------------------------------------------------

/// Parse a single submessage (header + payload) starting at `buf`.
/// Returns (submessage, bytes_consumed).
pub fn parse_submessage(buf: &[u8]) -> Result<(Submessage, usize), XrceError> {
    let hdr = SubmessageHeader::parse(buf)?;
    let payload_start = SUBMESSAGE_HEADER_SIZE;
    let payload_end = payload_start + hdr.length as usize;
    if buf.len() < payload_end {
        return Err(XrceError::BufferTooShort);
    }
    let payload = &buf[payload_start..payload_end];

    let submsg = match hdr.submessage_id {
        SUBMSG_CREATE_CLIENT => {
            if payload.len() < 5 {
                return Err(XrceError::PayloadLengthMismatch);
            }
            let mut client_key = [0u8; 4];
            client_key.copy_from_slice(&payload[0..4]);
            Submessage::CreateClient(CreateClientPayload {
                client_key,
                properties: payload[4],
            })
        }
        SUBMSG_CREATE => {
            if payload.len() < 5 {
                return Err(XrceError::PayloadLengthMismatch);
            }
            let object_id = u16::from_le_bytes([payload[0], payload[1]]);
            let kind = ObjectKind::from_u8(payload[2])?;
            let parent_id = u16::from_le_bytes([payload[3], payload[4]]);
            let string_data = if payload.len() > 5 {
                payload[5..].to_vec()
            } else {
                Vec::new()
            };
            Submessage::Create(CreatePayload {
                object_id,
                kind,
                parent_id,
                string_data,
            })
        }
        SUBMSG_DELETE => {
            if payload.len() < 2 {
                return Err(XrceError::PayloadLengthMismatch);
            }
            let object_id = u16::from_le_bytes([payload[0], payload[1]]);
            Submessage::Delete(DeletePayload { object_id })
        }
        SUBMSG_WRITE_DATA => {
            if payload.len() < 2 {
                return Err(XrceError::PayloadLengthMismatch);
            }
            let writer_id = u16::from_le_bytes([payload[0], payload[1]]);
            let data = payload[2..].to_vec();
            Submessage::WriteData(WriteDataPayload { writer_id, data })
        }
        SUBMSG_READ_DATA => {
            if payload.len() < 4 {
                return Err(XrceError::PayloadLengthMismatch);
            }
            let reader_id = u16::from_le_bytes([payload[0], payload[1]]);
            let max_samples = u16::from_le_bytes([payload[2], payload[3]]);
            Submessage::ReadData(ReadDataPayload {
                reader_id,
                max_samples,
            })
        }
        SUBMSG_DATA => {
            if payload.len() < 2 {
                return Err(XrceError::PayloadLengthMismatch);
            }
            let reader_id = u16::from_le_bytes([payload[0], payload[1]]);
            let data = payload[2..].to_vec();
            Submessage::Data(DataPayload { reader_id, data })
        }
        SUBMSG_STATUS => {
            if payload.len() < 3 {
                return Err(XrceError::PayloadLengthMismatch);
            }
            let related_object_id = u16::from_le_bytes([payload[0], payload[1]]);
            let status = StatusCode::from_u8(payload[2])?;
            Submessage::Status(StatusPayload {
                related_object_id,
                status,
            })
        }
        SUBMSG_HEARTBEAT => {
            if payload.len() < 4 {
                return Err(XrceError::PayloadLengthMismatch);
            }
            let first_unacked_seq = u16::from_le_bytes([payload[0], payload[1]]);
            let last_seq = u16::from_le_bytes([payload[2], payload[3]]);
            Submessage::Heartbeat(HeartbeatPayload {
                first_unacked_seq,
                last_seq,
            })
        }
        SUBMSG_ACKNACK => {
            if payload.len() < 4 {
                return Err(XrceError::PayloadLengthMismatch);
            }
            let first_unacked_seq = u16::from_le_bytes([payload[0], payload[1]]);
            let nack_bitmap = u16::from_le_bytes([payload[2], payload[3]]);
            Submessage::Acknack(AcknackPayload {
                first_unacked_seq,
                nack_bitmap,
            })
        }
        other => return Err(XrceError::UnknownSubmessageId(other)),
    };
    Ok((submsg, payload_end))
}

// ---------------------------------------------------------------------------
// Full message parsing
// ---------------------------------------------------------------------------

/// Parse a complete XRCE message (header + one or more submessages).
pub fn parse_message(buf: &[u8]) -> Result<XrceMessage, XrceError> {
    let header = MessageHeader::parse(buf)?;
    let mut offset = MESSAGE_HEADER_SIZE;
    let mut submessages = Vec::new();
    while offset < buf.len() {
        let (submsg, consumed) = parse_submessage(&buf[offset..])?;
        submessages.push(submsg);
        offset += consumed;
    }
    if submessages.is_empty() {
        return Err(XrceError::BufferTooShort);
    }
    Ok(XrceMessage {
        header,
        submessages,
    })
}

// ---------------------------------------------------------------------------
// Submessage serialization
// ---------------------------------------------------------------------------

/// Serialize a submessage (header + payload) into bytes.
pub fn serialize_submessage(submsg: &Submessage) -> Vec<u8> {
    let (id, payload) = match submsg {
        Submessage::CreateClient(p) => {
            let mut pl = Vec::with_capacity(5);
            pl.extend_from_slice(&p.client_key);
            pl.push(p.properties);
            (SUBMSG_CREATE_CLIENT, pl)
        }
        Submessage::Create(p) => {
            let mut pl = Vec::with_capacity(5 + p.string_data.len());
            pl.extend_from_slice(&p.object_id.to_le_bytes());
            pl.push(p.kind.as_u8());
            pl.extend_from_slice(&p.parent_id.to_le_bytes());
            pl.extend_from_slice(&p.string_data);
            (SUBMSG_CREATE, pl)
        }
        Submessage::Delete(p) => {
            let pl = p.object_id.to_le_bytes().to_vec();
            (SUBMSG_DELETE, pl)
        }
        Submessage::WriteData(p) => {
            let mut pl = Vec::with_capacity(2 + p.data.len());
            pl.extend_from_slice(&p.writer_id.to_le_bytes());
            pl.extend_from_slice(&p.data);
            (SUBMSG_WRITE_DATA, pl)
        }
        Submessage::ReadData(p) => {
            let mut pl = Vec::with_capacity(4);
            pl.extend_from_slice(&p.reader_id.to_le_bytes());
            pl.extend_from_slice(&p.max_samples.to_le_bytes());
            (SUBMSG_READ_DATA, pl)
        }
        Submessage::Data(p) => {
            let mut pl = Vec::with_capacity(2 + p.data.len());
            pl.extend_from_slice(&p.reader_id.to_le_bytes());
            pl.extend_from_slice(&p.data);
            (SUBMSG_DATA, pl)
        }
        Submessage::Status(p) => {
            let mut pl = Vec::with_capacity(3);
            pl.extend_from_slice(&p.related_object_id.to_le_bytes());
            pl.push(p.status.as_u8());
            (SUBMSG_STATUS, pl)
        }
        Submessage::Heartbeat(p) => {
            let mut pl = Vec::with_capacity(4);
            pl.extend_from_slice(&p.first_unacked_seq.to_le_bytes());
            pl.extend_from_slice(&p.last_seq.to_le_bytes());
            (SUBMSG_HEARTBEAT, pl)
        }
        Submessage::Acknack(p) => {
            let mut pl = Vec::with_capacity(4);
            pl.extend_from_slice(&p.first_unacked_seq.to_le_bytes());
            pl.extend_from_slice(&p.nack_bitmap.to_le_bytes());
            (SUBMSG_ACKNACK, pl)
        }
    };

    let hdr = SubmessageHeader {
        submessage_id: id,
        flags: 0,
        length: payload.len() as u16,
    };
    let mut out = Vec::with_capacity(SUBMESSAGE_HEADER_SIZE + payload.len());
    hdr.write_to(&mut out);
    out.extend_from_slice(&payload);
    out
}

/// Serialize a full message (header + submessages).
pub fn serialize_message(msg: &XrceMessage) -> Vec<u8> {
    let mut buf = Vec::new();
    msg.header.write_to(&mut buf);
    for sub in &msg.submessages {
        let sub_bytes = serialize_submessage(sub);
        buf.extend_from_slice(&sub_bytes);
    }
    buf
}

// ---------------------------------------------------------------------------
// Fragmentation helpers
// ---------------------------------------------------------------------------

/// Fragment a serialized payload into chunks of at most `max_payload` bytes.
/// Each fragment gets a FragmentHeader prepended.
/// `max_payload` is the maximum size of the data portion (excluding the
/// fragment header itself).
pub fn fragment_payload(data: &[u8], max_payload: usize) -> Result<Vec<Vec<u8>>, XrceError> {
    if max_payload == 0 {
        return Err(XrceError::FragmentError("max_payload must be > 0".into()));
    }
    if data.is_empty() {
        return Err(XrceError::FragmentError("empty payload".into()));
    }

    let total_fragments = data.len().div_ceil(max_payload);
    if total_fragments > u16::MAX as usize {
        return Err(XrceError::FragmentError("too many fragments".into()));
    }
    let total_fragments = total_fragments as u16;

    let mut fragments = Vec::with_capacity(total_fragments as usize);
    let mut offset = 0usize;
    let mut frag_nr = 0u16;
    while offset < data.len() {
        let end = std::cmp::min(offset + max_payload, data.len());
        let fh = FragmentHeader {
            fragment_nr: frag_nr,
            total_fragments,
        };
        let mut frag = Vec::with_capacity(FRAGMENT_HEADER_SIZE + (end - offset));
        fh.write_to(&mut frag);
        frag.extend_from_slice(&data[offset..end]);
        fragments.push(frag);
        offset = end;
        frag_nr += 1;
    }
    Ok(fragments)
}

/// Reassembly buffer. Collects fragments and produces the original payload
/// once all fragments have arrived.
#[derive(Debug)]
pub struct ReassemblyBuffer {
    total_fragments: u16,
    received: Vec<Option<Vec<u8>>>,
    received_count: u16,
}

impl ReassemblyBuffer {
    /// Create a new reassembly buffer for the given total fragment count.
    pub fn new(total_fragments: u16) -> Self {
        let mut received = Vec::with_capacity(total_fragments as usize);
        received.resize_with(total_fragments as usize, || None);
        Self {
            total_fragments,
            received,
            received_count: 0,
        }
    }

    /// Insert a fragment. Returns `true` if all fragments have been received.
    pub fn insert(&mut self, fragment_nr: u16, data: Vec<u8>) -> Result<bool, XrceError> {
        if fragment_nr >= self.total_fragments {
            return Err(XrceError::FragmentError(format!(
                "fragment_nr {} >= total {}",
                fragment_nr, self.total_fragments
            )));
        }
        let idx = fragment_nr as usize;
        if self.received[idx].is_none() {
            self.received_count += 1;
        }
        self.received[idx] = Some(data);
        Ok(self.received_count == self.total_fragments)
    }

    /// Check if a specific fragment has been received.
    pub fn has_fragment(&self, fragment_nr: u16) -> bool {
        (fragment_nr as usize) < self.received.len()
            && self.received[fragment_nr as usize].is_some()
    }

    /// Assemble the complete payload. Only valid when all fragments are present.
    pub fn assemble(&self) -> Result<Vec<u8>, XrceError> {
        if self.received_count < self.total_fragments {
            return Err(XrceError::FragmentError(format!(
                "missing fragments: have {}/{}",
                self.received_count, self.total_fragments
            )));
        }
        let mut payload = Vec::new();
        for slot in &self.received {
            match slot {
                Some(d) => payload.extend_from_slice(d),
                None => {
                    return Err(XrceError::FragmentError("internal: missing slot".into()));
                }
            }
        }
        Ok(payload)
    }

    /// Return the number of received fragments.
    pub fn received_count(&self) -> u16 {
        self.received_count
    }

    /// Return the total expected fragments.
    pub fn total_fragments(&self) -> u16 {
        self.total_fragments
    }
}

// ---------------------------------------------------------------------------
// Helper: encode a length-prefixed string for CREATE payloads (topic name etc.)
// ---------------------------------------------------------------------------

/// Encode a string as [len_u16_le][utf8_bytes].
pub fn encode_string(s: &str) -> Vec<u8> {
    let len = s.len() as u16;
    let mut buf = Vec::with_capacity(2 + s.len());
    buf.extend_from_slice(&len.to_le_bytes());
    buf.extend_from_slice(s.as_bytes());
    buf
}

/// Decode a length-prefixed string. Returns (string, bytes_consumed).
pub fn decode_string(buf: &[u8]) -> Result<(String, usize), XrceError> {
    let len = read_u16_le(buf, 0)? as usize;
    if buf.len() < 2 + len {
        return Err(XrceError::BufferTooShort);
    }
    let s = String::from_utf8_lossy(&buf[2..2 + len]).into_owned();
    Ok((s, 2 + len))
}
