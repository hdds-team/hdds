// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Automatic distribution of registered schemas over DDS (feature `dds`).
//!
//! Where this sits, plainly: the primary way an HDDS peer learns a type is
//! XTypes TypeLookup, which the engine speaks natively (`type-lookup`
//! feature) - the registry is not in that path and does not try to be. This
//! module is the fallback for the cases TypeLookup does not cover: IDL text,
//! JSON schema documents, and version history for peers that were not
//! present when the writer announced its TypeObject.
//!
//! Wire: topic `HDDS_SchemaRegistry`, reliable + transient-local, one sample
//! per registered version, payload
//!
//! ```text
//! u32 name_len | name | u32 version | u8 format | u64 hash | u32 content_len | content
//! ```
//!
//! all little-endian. The topic is not keyed: the raw API publishes opaque
//! payloads, so late joiners get the transient-local history rather than a
//! per-key latest value. Say it here rather than let a reader assume DDS
//! keying they do not get.

use std::sync::Arc;

use hdds::dds::{Participant, RawDataReader, RawDataWriter, TransportMode};
use hdds::QoS;

use crate::registry::{RegistryError, SchemaEntry, SchemaFormat, SchemaRegistry};

/// Topic every HDDS schema registry announces on.
pub const SCHEMA_TOPIC: &str = "HDDS_SchemaRegistry";

/// Type name announced for the topic.
pub const SCHEMA_TYPE_NAME: &str = "hdds::SchemaAnnouncement";

/// Errors from the distribution path.
#[derive(Debug)]
pub enum DistributionError {
    /// The DDS layer refused an operation.
    Dds(String),
    /// A received announcement could not be decoded.
    Malformed(String),
    /// The local registry refused the schema.
    Registry(RegistryError),
}

impl std::fmt::Display for DistributionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Dds(m) => write!(f, "DDS error: {}", m),
            Self::Malformed(m) => write!(f, "malformed schema announcement: {}", m),
            Self::Registry(e) => write!(f, "registry refused the schema: {}", e),
        }
    }
}

impl std::error::Error for DistributionError {}

impl From<RegistryError> for DistributionError {
    fn from(e: RegistryError) -> Self {
        Self::Registry(e)
    }
}

fn format_code(format: &SchemaFormat) -> u8 {
    match format {
        SchemaFormat::Idl4 => 0,
        SchemaFormat::Json => 1,
        SchemaFormat::XTypesHash => 2,
    }
}

fn format_from_code(code: u8) -> Result<SchemaFormat, DistributionError> {
    match code {
        0 => Ok(SchemaFormat::Idl4),
        1 => Ok(SchemaFormat::Json),
        2 => Ok(SchemaFormat::XTypesHash),
        other => Err(DistributionError::Malformed(format!(
            "unknown schema format code {}",
            other
        ))),
    }
}

/// Encode one announcement.
pub fn encode_announcement(entry: &SchemaEntry) -> Vec<u8> {
    let name = entry.name.as_bytes();
    let content = entry.content.as_bytes();
    let mut buf = Vec::with_capacity(4 + name.len() + 4 + 1 + 8 + 4 + content.len());
    buf.extend_from_slice(&(name.len() as u32).to_le_bytes());
    buf.extend_from_slice(name);
    buf.extend_from_slice(&entry.version.to_le_bytes());
    buf.push(format_code(&entry.format));
    buf.extend_from_slice(&entry.hash.to_le_bytes());
    buf.extend_from_slice(&(content.len() as u32).to_le_bytes());
    buf.extend_from_slice(content);
    buf
}

/// Ceiling on distinct schema names a subscriber will accept from the
/// domain. The ingest is unauthenticated, so it needs one.
pub const MAX_LOCAL_SCHEMAS: usize = 4096;

/// A decoded announcement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Announcement {
    pub name: String,
    pub version: u32,
    pub format: SchemaFormat,
    pub hash: u64,
    pub content: String,
}

/// Decode one announcement. Every length is checked against the buffer, so a
/// truncated or hostile sample is an error, never a panic.
pub fn decode_announcement(bytes: &[u8]) -> Result<Announcement, DistributionError> {
    fn need(bytes: &[u8], at: usize, len: usize) -> Result<(), DistributionError> {
        // Checked arithmetic, not `at + len`: `len` comes off the wire as a
        // u32, and on a 32-bit target 0xFFFFFFFF plus a small offset WRAPS.
        // The check would then pass and the slice below would panic in the
        // subscriber's poll loop, killing it for a sample any peer on the
        // domain can publish.
        if at.checked_add(len).is_none_or(|end| bytes.len() < end) {
            return Err(DistributionError::Malformed(format!(
                "need {} bytes at offset {}, have {}",
                len,
                at,
                bytes.len()
            )));
        }
        Ok(())
    }
    fn u32_at(bytes: &[u8], at: usize) -> Result<u32, DistributionError> {
        need(bytes, at, 4)?;
        Ok(u32::from_le_bytes([
            bytes[at],
            bytes[at + 1],
            bytes[at + 2],
            bytes[at + 3],
        ]))
    }

    // A bound on what one announcement may carry. Anything on the topic can
    // publish, so the decoder refuses absurd lengths before it allocates for
    // them rather than after.
    const MAX_FIELD_LEN: usize = 1 << 20;

    let mut off = 0;
    let name_len = u32_at(bytes, off)? as usize;
    if name_len > MAX_FIELD_LEN {
        return Err(DistributionError::Malformed(format!(
            "name length {} exceeds the {} byte limit",
            name_len, MAX_FIELD_LEN
        )));
    }
    off += 4;
    need(bytes, off, name_len)?;
    let name = String::from_utf8(bytes[off..off + name_len].to_vec())
        .map_err(|e| DistributionError::Malformed(format!("name is not UTF-8: {}", e)))?;
    off += name_len;

    let version = u32_at(bytes, off)?;
    off += 4;
    need(bytes, off, 1)?;
    let format = format_from_code(bytes[off])?;
    off += 1;
    need(bytes, off, 8)?;
    let mut hash_bytes = [0u8; 8];
    hash_bytes.copy_from_slice(&bytes[off..off + 8]);
    let hash = u64::from_le_bytes(hash_bytes);
    off += 8;

    let content_len = u32_at(bytes, off)? as usize;
    if content_len > MAX_FIELD_LEN {
        return Err(DistributionError::Malformed(format!(
            "content length {} exceeds the {} byte limit",
            content_len, MAX_FIELD_LEN
        )));
    }
    off += 4;
    need(bytes, off, content_len)?;
    let content = String::from_utf8(bytes[off..off + content_len].to_vec())
        .map_err(|e| DistributionError::Malformed(format!("content is not UTF-8: {}", e)))?;

    Ok(Announcement {
        name,
        version,
        format,
        hash,
        content,
    })
}

fn announcement_qos() -> QoS {
    QoS::reliable().transient_local().keep_all()
}

fn participant(domain_id: u32, name: &str) -> Result<Arc<Participant>, DistributionError> {
    Participant::builder(name)
        .domain_id(domain_id)
        .with_transport(TransportMode::UdpMulticast)
        .build()
        .map_err(|e| DistributionError::Dds(e.to_string()))
}

/// Publishes every registered schema version on [`SCHEMA_TOPIC`].
pub struct SchemaAnnouncer {
    _participant: Arc<Participant>,
    writer: RawDataWriter,
}

impl SchemaAnnouncer {
    /// Own a participant on `domain_id` and a writer on the schema topic.
    pub fn new(domain_id: u32, name: &str) -> Result<Self, DistributionError> {
        let participant = participant(domain_id, name)?;
        Self::on_participant(participant)
    }

    /// Reuse an existing participant.
    pub fn on_participant(participant: Arc<Participant>) -> Result<Self, DistributionError> {
        let writer = participant
            .create_raw_writer_with_type(
                SCHEMA_TOPIC,
                SCHEMA_TYPE_NAME,
                Some(announcement_qos()),
                None,
                None,
            )
            .map_err(|e| DistributionError::Dds(e.to_string()))?;
        Ok(Self {
            _participant: participant,
            writer,
        })
    }

    /// Announce one schema version.
    pub fn announce(&mut self, entry: &SchemaEntry) -> Result<(), DistributionError> {
        self.writer
            .write_raw(&encode_announcement(entry))
            .map_err(|e| DistributionError::Dds(e.to_string()))
    }

    /// Announce every version currently in `registry`.
    pub fn announce_all(&mut self, registry: &SchemaRegistry) -> Result<usize, DistributionError> {
        let mut count = 0;
        for name in registry.list_schemas() {
            for version in registry.list_versions(&name) {
                if let Some(entry) = registry.get_version(&name, version) {
                    self.announce(entry)?;
                    count += 1;
                }
            }
        }
        Ok(count)
    }
}

/// Hydrates a local registry from the announcements of other registries.
pub struct SchemaSubscriber {
    _participant: Arc<Participant>,
    reader: RawDataReader,
    registry: SchemaRegistry,
}

impl SchemaSubscriber {
    /// Own a participant on `domain_id` and a reader on the schema topic.
    pub fn new(domain_id: u32, name: &str) -> Result<Self, DistributionError> {
        let participant = participant(domain_id, name)?;
        Self::on_participant(participant)
    }

    /// Reuse an existing participant.
    pub fn on_participant(participant: Arc<Participant>) -> Result<Self, DistributionError> {
        let reader = participant
            .create_raw_reader_with_type(
                SCHEMA_TOPIC,
                SCHEMA_TYPE_NAME,
                Some(announcement_qos()),
                None,
                None,
            )
            .map_err(|e| DistributionError::Dds(e.to_string()))?;
        Ok(Self {
            _participant: participant,
            reader,
            registry: SchemaRegistry::new(),
        })
    }

    /// Take whatever arrived and fold it into the local registry.
    ///
    /// Returns how many announcements were applied. A duplicate (same content
    /// already registered) is counted as applied; a malformed sample is
    /// logged and skipped, never fatal, because one bad publisher must not
    /// stop the rest.
    ///
    /// This ingest is NOT authenticated: any participant on the domain can
    /// publish onto `HDDS_SchemaRegistry`, and the loopback-bind that guards
    /// the HTTP server does not apply to it. What it accepts is therefore
    /// bounded - [`MAX_LOCAL_SCHEMAS`] distinct names, and per-field limits
    /// inside [`decode_announcement`] - so a hostile publisher cannot grow
    /// the local registry without end.
    pub fn poll(&mut self) -> Result<usize, DistributionError> {
        let samples = self
            .reader
            .try_take_raw()
            .map_err(|e| DistributionError::Dds(e.to_string()))?;
        let mut applied = 0;
        for sample in samples {
            match decode_announcement(&sample.payload) {
                Ok(announcement) => {
                    if self.registry.schema_count() >= MAX_LOCAL_SCHEMAS
                        && self.registry.list_versions(&announcement.name).is_empty()
                    {
                        log::warn!(
                            "refusing schema {}: the local registry already holds {} names",
                            announcement.name,
                            MAX_LOCAL_SCHEMAS
                        );
                        continue;
                    }
                    match self.registry.register(
                        &announcement.name,
                        &announcement.content,
                        announcement.format,
                    ) {
                        Ok(_) | Err(RegistryError::DuplicateContent) => applied += 1,
                        Err(e) => {
                            log::warn!("schema {} refused locally: {}", announcement.name, e)
                        }
                    }
                }
                Err(e) => log::warn!("dropping a schema announcement: {}", e),
            }
        }
        Ok(applied)
    }

    /// The registry this subscriber fills.
    pub fn registry(&self) -> &SchemaRegistry {
        &self.registry
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry() -> SchemaEntry {
        let mut registry = SchemaRegistry::new();
        registry
            .register("Sensor", "struct Sensor { long id; };", SchemaFormat::Idl4)
            .expect("register");
        registry.get_latest("Sensor").expect("entry").clone()
    }

    #[test]
    fn announcement_round_trips() {
        let entry = entry();
        let decoded = decode_announcement(&encode_announcement(&entry)).expect("decode");
        assert_eq!(decoded.name, entry.name);
        assert_eq!(decoded.version, entry.version);
        assert_eq!(decoded.format, entry.format);
        assert_eq!(decoded.hash, entry.hash);
        assert_eq!(decoded.content, entry.content);
    }

    /// Anything on the domain can publish onto the announcement topic, so a
    /// hostile length must be an error, not a panic.
    ///
    /// `at + len` with `len` read off the wire as a u32 WRAPS at 32-bit usize
    /// width: the bound check then passes and the slice below it panics,
    /// inside the subscriber's poll loop. On
    /// arm-unknown-linux-gnueabihf (32-bit), unchecked arithmetic
    /// aborts with "attempt to add with overflow"; on x86-64 this test only
    /// guards the limits.
    #[test]
    fn a_hostile_announcement_length_is_an_error_not_a_panic() {
        for name_len in [u32::MAX, u32::MAX - 3, 0x8000_0000u32, 0x0010_0001] {
            let mut bytes = name_len.to_le_bytes().to_vec();
            bytes.extend_from_slice(b"Sensor");
            assert!(
                decode_announcement(&bytes).is_err(),
                "name length {} was accepted",
                name_len
            );
        }

        // The same on the content length, past a well-formed name.
        let mut bytes = 6u32.to_le_bytes().to_vec();
        bytes.extend_from_slice(b"Sensor");
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.push(0);
        bytes.extend_from_slice(&0u64.to_le_bytes());
        bytes.extend_from_slice(&u32::MAX.to_le_bytes());
        bytes.extend_from_slice(b"short");
        assert!(decode_announcement(&bytes).is_err());
    }

    #[test]
    fn a_truncated_announcement_is_an_error_not_a_panic() {
        let bytes = encode_announcement(&entry());
        for cut in 0..bytes.len() {
            assert!(
                decode_announcement(&bytes[..cut]).is_err(),
                "prefix of {} bytes decoded",
                cut
            );
        }
        // A length field that promises more than the buffer holds.
        let mut hostile = bytes.clone();
        hostile[0] = 0xFF;
        hostile[1] = 0xFF;
        assert!(decode_announcement(&hostile).is_err());
    }
}
