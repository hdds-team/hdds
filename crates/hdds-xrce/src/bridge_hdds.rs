// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! [`ProxyBridge`] backed by HDDS (feature `hdds`).
//!
//! This is what turns the agent from a protocol parser into the thing the
//! website describes: an MCU speaking XRCE over UDP, serial or TCP appears on
//! the DDS network as a real participant with real writers and readers.
//!
//! It goes through the public raw API (`create_raw_writer_with_type`,
//! `create_raw_reader_with_type`, `write_raw`, `try_take_raw`), so nothing
//! here touches the RTPS hot path and the client's declared type name is what
//! the endpoint announces in discovery. Payload bytes are passed through
//! untouched: the client owns its CDR.
//!
//! Security note, stated rather than assumed: the bridge writes into the
//! domain with the bridging participant's identity, so every XRCE client
//! inherits it. Admission is the ClientKey list on the agent
//! ([`crate::XrceAgentConfig::accepted_client_keys`]) plus the source-address
//! binding described in the crate documentation; there is no per-client DDS
//! identity, and a client that gets in gets the bridge's write access to the
//! whole domain.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use hdds::dds::{Participant, QoS, RawDataReader, RawDataWriter, TransportMode};

use crate::protocol::XrceError;
use crate::proxy::ProxyBridge;

/// A DDS entity the bridge created on behalf of a client.
///
/// The endpoint variants are boxed: a RawDataWriter is around a kilobyte and
/// this enum lives in a map with one entry per client object.
enum Entity {
    Participant(Arc<Participant>),
    Topic {
        participant: Arc<Participant>,
        name: String,
        type_name: String,
    },
    Writer(Box<RawDataWriter>),
    Reader(Box<RawDataReader>),
}

/// Bridges XRCE object operations onto HDDS entities.
pub struct HddsBridge {
    entities: Mutex<HashMap<u32, Entity>>,
    next_handle: AtomicU32,
    /// Domain used when a client asks for a participant. `None` = the domain
    /// the client requested in its CREATE payload.
    forced_domain: Option<u32>,
    participant_name: String,
}

impl HddsBridge {
    /// A bridge that honours the domain id each client asks for.
    pub fn new(participant_name: &str) -> Self {
        Self {
            entities: Mutex::new(HashMap::new()),
            next_handle: AtomicU32::new(1),
            forced_domain: None,
            participant_name: participant_name.to_string(),
        }
    }

    /// A bridge that puts every client on one domain, whatever they ask for.
    pub fn with_domain(participant_name: &str, domain_id: u32) -> Self {
        Self {
            forced_domain: Some(domain_id),
            ..Self::new(participant_name)
        }
    }

    fn alloc(&self) -> u32 {
        self.next_handle.fetch_add(1, Ordering::Relaxed)
    }

    fn insert(&self, entity: Entity) -> Result<u32, XrceError> {
        let handle = self.alloc();
        self.entities
            .lock()
            .map_err(|_| XrceError::BridgeError("entity table poisoned".into()))?
            .insert(handle, entity);
        Ok(handle)
    }

    /// Number of live DDS entities. Test and diagnostics helper.
    pub fn entity_count(&self) -> usize {
        self.entities.lock().map(|e| e.len()).unwrap_or(0)
    }
}

fn bridge_err(context: &str, e: impl std::fmt::Display) -> XrceError {
    XrceError::BridgeError(format!("{}: {}", context, e))
}

impl ProxyBridge for HddsBridge {
    fn create_participant(&self, domain_id: u16) -> Result<u32, XrceError> {
        let domain = self.forced_domain.unwrap_or(u32::from(domain_id));
        let participant = Participant::builder(&self.participant_name)
            .domain_id(domain)
            .with_transport(TransportMode::UdpMulticast)
            .build()
            .map_err(|e| bridge_err("create participant", e))?;
        self.insert(Entity::Participant(participant))
    }

    fn create_topic(
        &self,
        participant_id: u32,
        name: &str,
        type_name: &str,
    ) -> Result<u32, XrceError> {
        if name.is_empty() {
            return Err(XrceError::BridgeError("empty topic name".into()));
        }
        let participant = {
            let entities = self
                .entities
                .lock()
                .map_err(|_| XrceError::BridgeError("entity table poisoned".into()))?;
            match entities.get(&participant_id) {
                Some(Entity::Participant(p)) => Arc::clone(p),
                _ => return Err(XrceError::BridgeError("unknown participant".into())),
            }
        };
        // The client's declared type name is what discovery advertises; an
        // empty one would announce the raw-bytes placeholder and never match
        // a typed reader.
        let type_name = if type_name.is_empty() {
            return Err(XrceError::BridgeError("empty type name".into()));
        } else {
            type_name.to_string()
        };
        self.insert(Entity::Topic {
            participant,
            name: name.to_string(),
            type_name,
        })
    }

    fn create_writer(&self, _participant_id: u32, topic_id: u32) -> Result<u32, XrceError> {
        let (participant, name, type_name) = self.topic_parts(topic_id)?;
        // DDS-XRCE v1.0 Sec.7.7.1: every DataRepresentation format a
        // client WRITEs (SampleData, Sample, ...) carries its payload as
        // an XCDRSerializedBuffer, and "the XCDRSerializedBuffer
        // represents the bytes resulting from serializing the
        // application-specific data type that is being sent using the
        // XCDR version 2 rules defined in clause 7.4 of [DDS-XTYPES]".
        // The bytes `write_data` is given are therefore ALWAYS XCDR2,
        // for the life of this writer -- not the XCDR1 a default,
        // unconfigured RawBytes writer would otherwise resolve to
        // (RawBytes::encodes_xcdr1_natively() is true). Offering
        // anything but XCDR2 here would label genuinely-XCDR2 client
        // bytes as XCDR1 on the wire.
        let qos = QoS::default().data_representation_xcdr2();
        let writer = participant
            .create_raw_writer_with_type(&name, &type_name, Some(qos), None, None)
            .map_err(|e| bridge_err("create writer", e))?;
        self.insert(Entity::Writer(Box::new(writer)))
    }

    fn create_reader(&self, _participant_id: u32, topic_id: u32) -> Result<u32, XrceError> {
        let (participant, name, type_name) = self.topic_parts(topic_id)?;
        // Mirror of create_writer, agent-to-client direction: DDS-XRCE
        // v1.0 Sec.7.7.1/7.7.2 require every DataRepresentation the agent
        // sends to a client (read_data's reply) to carry an
        // XCDR-version-2-encoded payload too. This bridge never
        // re-encodes (it passes bytes through untouched, see the module
        // docs), so the only way to keep that promise is to never match
        // a DDS writer that offers anything but XCDR2: requesting XCDR2
        // only (instead of the default empty list, which would accept
        // EITHER representation) makes an XCDR1 source writer simply not
        // match this reader, rather than have its bytes forwarded to an
        // XRCE client mislabeled as XCDR2.
        let qos = QoS::default().data_representation_xcdr2();
        let reader = participant
            .create_raw_reader_with_type(&name, &type_name, Some(qos), None, None)
            .map_err(|e| bridge_err("create reader", e))?;
        self.insert(Entity::Reader(Box::new(reader)))
    }

    fn write_data(&self, writer_id: u32, data: &[u8]) -> Result<(), XrceError> {
        let entities = self
            .entities
            .lock()
            .map_err(|_| XrceError::BridgeError("entity table poisoned".into()))?;
        match entities.get(&writer_id) {
            Some(Entity::Writer(w)) => w.write_raw(data).map_err(|e| bridge_err("write", e)),
            _ => Err(XrceError::BridgeError("unknown writer".into())),
        }
    }

    fn read_data(&self, reader_id: u32) -> Result<Option<Vec<u8>>, XrceError> {
        let entities = self
            .entities
            .lock()
            .map_err(|_| XrceError::BridgeError("entity table poisoned".into()))?;
        match entities.get(&reader_id) {
            Some(Entity::Reader(r)) => {
                let mut samples = r.try_take_raw().map_err(|e| bridge_err("read", e))?;
                if samples.is_empty() {
                    Ok(None)
                } else {
                    Ok(Some(samples.remove(0).payload))
                }
            }
            _ => Err(XrceError::BridgeError("unknown reader".into())),
        }
    }

    fn delete_entity(&self, entity_id: u32) -> Result<(), XrceError> {
        let removed = self
            .entities
            .lock()
            .map_err(|_| XrceError::BridgeError("entity table poisoned".into()))?
            .remove(&entity_id);
        match removed {
            Some(_) => Ok(()),
            // Saturate rather than truncate: entity_id is this bridge's own
            // u32 handle counter (alloc()), ObjectId on the wire is 16-bit.
            // A truncating cast could silently report the WRONG object as
            // missing (entity_id's low 16 bits colliding with a real,
            // different ObjectId) once past 65535 allocations; this report
            // is diagnostic only, so saturating keeps it honestly "some
            // handle beyond ObjectId's range" instead of a wrong one.
            None => Err(XrceError::ObjectNotFound(
                u16::try_from(entity_id).unwrap_or(u16::MAX),
            )),
        }
    }
}

impl HddsBridge {
    fn topic_parts(&self, topic_id: u32) -> Result<(Arc<Participant>, String, String), XrceError> {
        let entities = self
            .entities
            .lock()
            .map_err(|_| XrceError::BridgeError("entity table poisoned".into()))?;
        match entities.get(&topic_id) {
            Some(Entity::Topic {
                participant,
                name,
                type_name,
            }) => Ok((Arc::clone(participant), name.clone(), type_name.clone())),
            _ => Err(XrceError::BridgeError("unknown topic".into())),
        }
    }
}
