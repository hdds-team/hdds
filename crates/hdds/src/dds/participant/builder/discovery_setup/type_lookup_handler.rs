// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! HDDS-only TypeLookup handler (feature-gated).
//!

use crate::core::discovery::multicast::DiscoveryFsm;
use crate::transport::UdpTransport;
use std::net::SocketAddr;
use std::sync::Arc;

#[cfg(feature = "type-lookup")]
use crate::core::types::TypeObjectHandle;
#[cfg(feature = "type-lookup")]
use crate::protocol::discovery::constants::CDR2_LE;
#[cfg(feature = "type-lookup")]
use crate::xtypes::CompleteTypeObject;
#[cfg(feature = "type-lookup")]
use crate::{Cdr2Decode, Cdr2Encode};
#[cfg(feature = "type-lookup")]
use parking_lot::{Mutex, RwLock};
#[cfg(feature = "type-lookup")]
use std::collections::{HashMap, HashSet};
#[cfg(feature = "type-lookup")]
use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(feature = "type-lookup")]
const TYPE_LOOKUP_MAGIC: [u8; 4] = *b"HTLK";
#[cfg(feature = "type-lookup")]
const TYPE_LOOKUP_VERSION: u8 = 1;
#[cfg(feature = "type-lookup")]
const TYPE_LOOKUP_KIND_REQUEST: u8 = 1;
#[cfg(feature = "type-lookup")]
const TYPE_LOOKUP_KIND_RESPONSE: u8 = 2;

#[cfg(feature = "type-lookup")]
#[derive(Debug)]
#[allow(dead_code)] // Error variants used during type lookup message parsing
enum TypeLookupError {
    Truncated,
    InvalidMagic,
    UnsupportedVersion(u8),
    InvalidKind(u8),
    InvalidUtf8,
}

#[cfg(feature = "type-lookup")]
#[derive(Debug)]
struct TypeLookupMessage {
    kind: u8,
    type_name: String,
    type_object: Option<Vec<u8>>,
}

#[cfg(feature = "type-lookup")]
pub(super) struct TypeLookupService {
    fsm: Arc<DiscoveryFsm>,
    transport: Arc<UdpTransport>,
    our_guid_prefix: [u8; 12],
    requested_types: Mutex<HashSet<String>>,
    registered_types: Arc<RwLock<HashMap<String, Arc<TypeObjectHandle>>>>,
    seq: AtomicU64,
    dialect_detector:
        Arc<std::sync::Mutex<crate::core::discovery::multicast::dialect_detector::DialectDetector>>,
}

#[cfg(not(feature = "type-lookup"))]
pub(super) struct TypeLookupService;

pub(super) type TypeLookupHandle = Option<Arc<TypeLookupService>>;

#[cfg(feature = "type-lookup")]
pub(in crate::dds::participant::builder) struct TypeLookupConfig {
    pub registered_types: Arc<RwLock<HashMap<String, Arc<TypeObjectHandle>>>>,
    pub dialect_detector:
        Arc<std::sync::Mutex<crate::core::discovery::multicast::dialect_detector::DialectDetector>>,
}

#[cfg(not(feature = "type-lookup"))]
pub(in crate::dds::participant::builder) struct TypeLookupConfig;

#[cfg(feature = "type-lookup")]
impl TypeLookupService {
    pub(super) fn new(
        fsm: Arc<DiscoveryFsm>,
        transport: Arc<UdpTransport>,
        our_guid_prefix: [u8; 12],
        config: TypeLookupConfig,
    ) -> Self {
        Self {
            fsm,
            transport,
            our_guid_prefix,
            requested_types: Mutex::new(HashSet::new()),
            registered_types: config.registered_types,
            seq: AtomicU64::new(0),
            dialect_detector: config.dialect_detector,
        }
    }

    fn next_seq(&self) -> u64 {
        self.seq.fetch_add(1, Ordering::Relaxed) + 1
    }

    fn is_interop_mode(&self) -> bool {
        self.dialect_detector
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_interop_mode()
    }

    pub(super) fn handle_packet(&self, payload: &[u8], cdr_offset: usize, src_addr: SocketAddr) {
        if self.is_interop_mode() {
            return;
        }

        let cdr_payload = match payload.get(cdr_offset..) {
            Some(slice) => slice,
            None => {
                log::debug!(
                    "[TypeLookup] Invalid CDR offset {} (len={})",
                    cdr_offset,
                    payload.len()
                );
                return;
            }
        };

        let message = match decode_type_lookup_message(cdr_payload) {
            Ok(msg) => msg,
            Err(err) => {
                log::debug!("[TypeLookup] Decode failed: {:?}", err);
                return;
            }
        };

        match message.kind {
            TYPE_LOOKUP_KIND_REQUEST => {
                self.handle_request(&message, payload, src_addr);
            }
            TYPE_LOOKUP_KIND_RESPONSE => {
                self.handle_response(&message);
            }
            _ => {
                log::debug!(
                    "[TypeLookup] Unsupported message kind={} for type '{}'",
                    message.kind,
                    message.type_name
                );
            }
        }
    }

    pub(super) fn maybe_request_type_object(
        &self,
        type_name: &str,
        src_addr: SocketAddr,
        peer_guid_prefix: Option<[u8; 12]>,
    ) {
        if self.is_interop_mode() {
            return;
        }

        let mut requested = self.requested_types.lock();
        if !requested.insert(type_name.to_string()) {
            return;
        }

        let payload = match encode_type_lookup_message(type_name, None) {
            Ok(buf) => buf,
            Err(err) => {
                log::debug!("[TypeLookup] Failed to encode request: {:?}", err);
                return;
            }
        };

        let seq = self.next_seq();
        let packet = match build_type_lookup_packet(
            &payload,
            &self.our_guid_prefix,
            peer_guid_prefix.as_ref(),
            seq,
        ) {
            Ok(packet) => packet,
            Err(err) => {
                log::debug!("[TypeLookup] Failed to build request packet: {}", err);
                return;
            }
        };

        if let Err(err) = self.transport.send_to_endpoint(&packet, &src_addr) {
            log::debug!("[TypeLookup] Failed to send request: {}", err);
        } else {
            log::debug!(
                "[TypeLookup] Requested TypeObject for '{}' from {}",
                type_name,
                src_addr
            );
        }
    }

    fn handle_request(&self, message: &TypeLookupMessage, packet: &[u8], src_addr: SocketAddr) {
        let handle = {
            let map = self.registered_types.read();
            map.get(&message.type_name).cloned()
        };

        let Some(handle) = handle else {
            log::debug!(
                "[TypeLookup] No local TypeObject for '{}'",
                message.type_name
            );
            return;
        };

        let type_object_bytes = match encode_type_object(&handle.complete) {
            Ok(bytes) => bytes,
            Err(err) => {
                log::debug!("[TypeLookup] Failed to encode TypeObject: {}", err);
                return;
            }
        };

        let payload = match encode_type_lookup_message(&message.type_name, Some(&type_object_bytes))
        {
            Ok(buf) => buf,
            Err(err) => {
                log::debug!("[TypeLookup] Failed to encode response: {:?}", err);
                return;
            }
        };

        let peer_prefix = extract_guid_prefix(packet);
        let seq = self.next_seq();
        let packet = match build_type_lookup_packet(
            &payload,
            &self.our_guid_prefix,
            peer_prefix.as_ref(),
            seq,
        ) {
            Ok(packet) => packet,
            Err(err) => {
                log::debug!("[TypeLookup] Failed to build response packet: {}", err);
                return;
            }
        };

        if let Err(err) = self.transport.send_to_endpoint(&packet, &src_addr) {
            log::debug!("[TypeLookup] Failed to send response: {}", err);
        } else {
            log::debug!(
                "[TypeLookup] Sent TypeObject for '{}' to {}",
                message.type_name,
                src_addr
            );
        }
    }

    fn handle_response(&self, message: &TypeLookupMessage) {
        let Some(bytes) = message.type_object.as_ref() else {
            log::debug!(
                "[TypeLookup] Response missing TypeObject for '{}'",
                message.type_name
            );
            return;
        };

        let type_object = match CompleteTypeObject::decode_cdr2_le(bytes) {
            Ok((obj, _)) => obj,
            Err(err) => {
                log::debug!("[TypeLookup] Failed to decode TypeObject: {}", err);
                return;
            }
        };

        let updated = self
            .fsm
            .update_type_object_for_type(&message.type_name, type_object);

        if updated > 0 {
            log::debug!(
                "[TypeLookup] Updated {} endpoint(s) with TypeObject for '{}'",
                updated,
                message.type_name
            );
        }
    }
}

#[cfg(not(feature = "type-lookup"))]
impl TypeLookupService {
    #[allow(dead_code)] // Used when type-lookup feature is disabled as stub
    pub(super) fn new(
        _fsm: Arc<DiscoveryFsm>,
        _transport: Arc<UdpTransport>,
        _our_guid_prefix: [u8; 12],
        _config: TypeLookupConfig,
    ) -> Self {
        Self
    }
}

#[cfg(feature = "type-lookup")]
pub(super) fn handle_type_lookup_packet(
    handle: &TypeLookupHandle,
    payload: &[u8],
    cdr_offset: usize,
    src_addr: SocketAddr,
) {
    if let Some(service) = handle {
        service.handle_packet(payload, cdr_offset, src_addr);
    }
}

#[cfg(not(feature = "type-lookup"))]
pub(super) fn handle_type_lookup_packet(
    _handle: &TypeLookupHandle,
    _payload: &[u8],
    _cdr_offset: usize,
    _src_addr: SocketAddr,
) {
}

#[cfg(feature = "type-lookup")]
pub(super) fn maybe_request_type_object(
    handle: &TypeLookupHandle,
    type_name: &str,
    src_addr: SocketAddr,
    peer_guid_prefix: Option<[u8; 12]>,
) {
    if let Some(service) = handle {
        service.maybe_request_type_object(type_name, src_addr, peer_guid_prefix);
    }
}

#[cfg(not(feature = "type-lookup"))]
pub(super) fn maybe_request_type_object(
    _handle: &TypeLookupHandle,
    _type_name: &str,
    _src_addr: SocketAddr,
    _peer_guid_prefix: Option<[u8; 12]>,
) {
}

#[cfg(feature = "type-lookup")]
fn extract_guid_prefix(packet: &[u8]) -> Option<[u8; 12]> {
    if packet.len() < 20 || &packet[0..4] != b"RTPS" {
        return None;
    }
    let mut prefix = [0u8; 12];
    prefix.copy_from_slice(&packet[8..20]);
    Some(prefix)
}

#[cfg(feature = "type-lookup")]
fn encode_type_object(type_object: &CompleteTypeObject) -> Result<Vec<u8>, String> {
    let mut buf = vec![0u8; type_object.max_cdr2_size()];
    let len = type_object
        .encode_cdr2_le(&mut buf)
        .map_err(|_| "cdr2 encode failed".to_string())?;
    buf.truncate(len);
    Ok(buf)
}

#[cfg(feature = "type-lookup")]
fn decode_type_lookup_message(payload: &[u8]) -> Result<TypeLookupMessage, TypeLookupError> {
    if payload.len() < 8 {
        return Err(TypeLookupError::Truncated);
    }

    let encapsulation = u16::from_be_bytes([payload[0], payload[1]]);
    if encapsulation != CDR2_LE {
        return Err(TypeLookupError::InvalidMagic);
    }

    let mut offset = 4; // encapsulation + options
    if payload.len() < offset + 8 {
        return Err(TypeLookupError::Truncated);
    }

    if payload[offset..offset + 4] != TYPE_LOOKUP_MAGIC {
        return Err(TypeLookupError::InvalidMagic);
    }
    offset += 4;

    let version = payload[offset];
    offset += 1;
    if version != TYPE_LOOKUP_VERSION {
        return Err(TypeLookupError::UnsupportedVersion(version));
    }

    let kind = payload[offset];
    offset += 1;
    if kind != TYPE_LOOKUP_KIND_REQUEST && kind != TYPE_LOOKUP_KIND_RESPONSE {
        return Err(TypeLookupError::InvalidKind(kind));
    }

    if payload.len() < offset + 2 + 4 {
        return Err(TypeLookupError::Truncated);
    }

    offset += 2; // flags/reserved

    let name_len = u32::from_le_bytes([
        payload[offset],
        payload[offset + 1],
        payload[offset + 2],
        payload[offset + 3],
    ]) as usize;
    offset += 4;

    if payload.len() < offset + name_len + 4 {
        return Err(TypeLookupError::Truncated);
    }

    let name_bytes = &payload[offset..offset + name_len];
    let type_name = std::str::from_utf8(name_bytes)
        .map_err(|_| TypeLookupError::InvalidUtf8)?
        .to_string();
    offset += name_len;

    let obj_len = u32::from_le_bytes([
        payload[offset],
        payload[offset + 1],
        payload[offset + 2],
        payload[offset + 3],
    ]) as usize;
    offset += 4;

    if obj_len == 0 {
        return Ok(TypeLookupMessage {
            kind,
            type_name,
            type_object: None,
        });
    }

    if payload.len() < offset + obj_len {
        return Err(TypeLookupError::Truncated);
    }

    let type_object = payload[offset..offset + obj_len].to_vec();

    Ok(TypeLookupMessage {
        kind,
        type_name,
        type_object: Some(type_object),
    })
}

#[cfg(feature = "type-lookup")]
fn encode_type_lookup_message(
    type_name: &str,
    type_object: Option<&[u8]>,
) -> Result<Vec<u8>, TypeLookupError> {
    let name_bytes = type_name.as_bytes();
    let name_len = name_bytes.len();
    let object_len = type_object.map(|obj| obj.len()).unwrap_or(0);

    if name_len > u32::MAX as usize || object_len > u32::MAX as usize {
        return Err(TypeLookupError::Truncated);
    }

    let mut buf = Vec::with_capacity(4 + 4 + name_len + object_len + 16);
    buf.extend_from_slice(&CDR2_LE.to_be_bytes());
    buf.extend_from_slice(&[0u8; 2]); // options
    buf.extend_from_slice(&TYPE_LOOKUP_MAGIC);
    buf.push(TYPE_LOOKUP_VERSION);
    buf.push(if type_object.is_some() {
        TYPE_LOOKUP_KIND_RESPONSE
    } else {
        TYPE_LOOKUP_KIND_REQUEST
    });
    buf.extend_from_slice(&[0u8; 2]); // flags/reserved
    buf.extend_from_slice(&(name_len as u32).to_le_bytes());
    buf.extend_from_slice(name_bytes);
    buf.extend_from_slice(&(object_len as u32).to_le_bytes());
    if let Some(bytes) = type_object {
        buf.extend_from_slice(bytes);
    }

    Ok(buf)
}

#[cfg(feature = "type-lookup")]
fn build_type_lookup_packet(
    payload: &[u8],
    participant_guid_prefix: &[u8; 12],
    destination_prefix: Option<&[u8; 12]>,
    seq_num: u64,
) -> Result<Vec<u8>, String> {
    use crate::core::discovery::multicast::rtps_packet::build_type_lookup_rtps_packet;

    build_type_lookup_rtps_packet(
        payload,
        participant_guid_prefix,
        destination_prefix,
        seq_num,
    )
    .map_err(|_| "build_type_lookup_rtps_packet failed".to_string())
}
