// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Live DDS capture API for type-agnostic traffic monitoring.
//!
//!
//! This module provides APIs for discovering topics and reading raw CDR payloads
//! without compile-time type knowledge, enabling tools like `hdds_viewer` to
//! capture and analyze live DDS traffic (similar to Wireshark for DDS).

use crate::core::discovery::multicast::fsm::{EndpointInfo, EndpointKind};
use crate::core::discovery::GUID;
use crate::core::ser::{Cdr2Decode, Cdr2Encode, CdrError};
use crate::core::types::TypeDescriptor;
use crate::dds::listener::{DataReaderListener, DataWriterListener};
use crate::dds::{Error, Result, SampleInfo, DDS as DdsTrait};
use crate::xtypes::CompleteTypeObject;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Raw CDR payload wrapper for type-agnostic reading.
///
/// This type bypasses CDR deserialization and stores raw bytes directly.
/// Used by `RawDataReader` to capture DDS traffic without compile-time type knowledge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawBytes(pub Vec<u8>, pub crate::dds::CdrVersion);

impl Cdr2Decode for RawBytes {
    fn decode_cdr2_le(src: &[u8]) -> std::result::Result<(Self, usize), CdrError> {
        let mut offset = 0;
        let value = Self::decode_cdr2_le_at(src, &mut offset)?;
        Ok((value, offset))
    }

    fn decode_cdr2_le_at(src: &[u8], offset: &mut usize) -> std::result::Result<Self, CdrError> {
        // No deserialization - just copy remaining bytes from offset
        let data = src[*offset..].to_vec();
        *offset = src.len();
        Ok(RawBytes(data, crate::dds::CdrVersion::Xcdr2))
    }
}

impl Cdr2Encode for RawBytes {
    fn max_cdr2_size(&self) -> usize {
        self.0.len()
    }

    fn encode_cdr2_le_at(
        &self,
        buf: &mut [u8],
        offset: &mut usize,
    ) -> std::result::Result<(), CdrError> {
        if *offset + self.0.len() > buf.len() {
            return Err(CdrError::BufferTooSmall);
        }
        buf[*offset..*offset + self.0.len()].copy_from_slice(&self.0);
        *offset += self.0.len();
        Ok(())
    }
}

impl DdsTrait for RawBytes {
    fn type_descriptor() -> &'static TypeDescriptor {
        static DESC: TypeDescriptor = TypeDescriptor {
            type_id: 0x0000_0000,
            type_name: "RawBytes",
            size_bytes: 0, // Variable size
            alignment: 1,
            is_variable_size: true,
            fields: &[], // No fields - opaque payload
        };
        &DESC
    }

    fn encode(&self, buf: &mut [u8], _version: crate::dds::CdrVersion) -> Result<usize> {
        use crate::core::ser::Cdr2Encode;
        self.encode_cdr2_le(buf).map_err(|e| match e {
            CdrError::BufferTooSmall => Error::BufferTooSmall,
            _ => Error::SerializationError,
        })
    }

    fn decode(buf: &[u8], version: crate::dds::CdrVersion) -> Result<Self> {
        use crate::core::ser::Cdr2Decode;
        Self::decode_cdr2_le(buf)
            .map(|(mut val, _)| {
                val.1 = version;
                val
            })
            .map_err(|e| match e {
                CdrError::UnexpectedEof => Error::SerializationError,
                _ => Error::SerializationError,
            })
    }

    /// Opaque bytes: a raw reader keeps the version the encapsulation
    /// identifier names (`RawBytes.1`) and a raw writer sends the caller's
    /// bytes under the representation its QoS offers. Nothing here
    /// re-encodes them, so an XCDR1 pair is not refused for the type.
    fn encodes_xcdr1_natively() -> bool {
        true
    }
}

/// Information about a discovered topic on the DDS bus.
///
/// Returned by [`Participant::discover_topics()`](super::Participant::discover_topics).
#[derive(Debug, Clone)]
pub struct DiscoveredTopicInfo {
    /// Topic name (e.g., "/chatter")
    pub name: String,

    /// Type name (e.g., "std_msgs::msg::String")
    pub type_name: String,

    /// XTypes TypeIdentifier (for type compatibility checking)
    pub type_id: Vec<u8>,

    /// Complete TypeObject (if discovered)
    pub type_object: Option<CompleteTypeObject>,

    /// Number of publishers for this topic
    pub publisher_count: usize,

    /// Number of subscribers for this topic
    pub subscriber_count: usize,

    /// QoS profile advertised by the first discovered endpoint
    pub qos: crate::dds::QoS,

    /// QoS hash (for matching)
    pub qos_hash: u32,
}

/// Kind of a discovered DDS endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscoveredEndpointKind {
    /// A remote DataWriter (publication).
    Writer,
    /// A remote DataReader (subscription).
    Reader,
}

/// Lossless public view of one endpoint discovered through SEDP.
///
/// Unlike [`DiscoveredTopicInfo`], this view does not merge endpoints by
/// topic. Its GUID can be joined directly with listener match handles such as
/// `SubscriptionMatchedStatus::last_publication_handle`.
#[derive(Debug, Clone)]
pub struct DiscoveredEndpointInfo {
    /// Globally unique endpoint identifier.
    pub endpoint_guid: GUID,
    /// GUID of the participant that owns the endpoint.
    pub participant_guid: GUID,
    /// Topic advertised by the endpoint.
    pub topic_name: String,
    /// DDS type name advertised by the endpoint.
    pub type_name: String,
    /// Complete advertised QoS policies for this endpoint.
    pub qos: crate::dds::QoS,
    /// Whether the endpoint is a writer or reader.
    pub kind: DiscoveredEndpointKind,
    /// Complete XTypes TypeObject when the remote endpoint supplied one.
    pub type_object: Option<CompleteTypeObject>,
}

impl From<EndpointInfo> for DiscoveredEndpointInfo {
    fn from(endpoint: EndpointInfo) -> Self {
        Self {
            endpoint_guid: endpoint.endpoint_guid,
            participant_guid: endpoint.participant_guid,
            topic_name: endpoint.topic_name,
            type_name: endpoint.type_name,
            qos: endpoint.qos,
            kind: match endpoint.kind {
                EndpointKind::Writer => DiscoveredEndpointKind::Writer,
                EndpointKind::Reader => DiscoveredEndpointKind::Reader,
            },
            type_object: endpoint.type_object,
        }
    }
}

fn discovered_endpoint_snapshot(
    all_topics: std::collections::HashMap<String, (Vec<EndpointInfo>, Vec<EndpointInfo>)>,
) -> Vec<DiscoveredEndpointInfo> {
    let mut endpoints = Vec::new();
    for (topic_name, (writers, readers)) in all_topics {
        if topic_name.starts_with("DCPS") {
            continue;
        }
        endpoints.extend(
            writers
                .into_iter()
                .chain(readers)
                .map(DiscoveredEndpointInfo::from),
        );
    }
    endpoints.sort_by(|left, right| {
        left.endpoint_guid
            .as_bytes()
            .cmp(&right.endpoint_guid.as_bytes())
    });
    endpoints
}

// Reader-only encoding: the key precedes the unchanged payload in retained
// storage. This header is never sent on the wire or exposed as sample bytes.
#[derive(Debug, Clone)]
pub(super) struct CapturedBytes(RawBytes, [u8; 16]);

impl Cdr2Encode for CapturedBytes {
    fn max_cdr2_size(&self) -> usize {
        16 + self.0.max_cdr2_size()
    }
    fn encode_cdr2_le_at(
        &self,
        buf: &mut [u8],
        offset: &mut usize,
    ) -> std::result::Result<(), CdrError> {
        if buf.len().saturating_sub(*offset) < 16 {
            return Err(CdrError::BufferTooSmall);
        }
        buf[*offset..*offset + 16].copy_from_slice(&self.1);
        *offset += 16;
        self.0.encode_cdr2_le_at(buf, offset)
    }
}
impl Cdr2Decode for CapturedBytes {
    fn decode_cdr2_le(src: &[u8]) -> std::result::Result<(Self, usize), CdrError> {
        let mut offset = 0;
        let value = Self::decode_cdr2_le_at(src, &mut offset)?;
        Ok((value, offset))
    }
    fn decode_cdr2_le_at(src: &[u8], offset: &mut usize) -> std::result::Result<Self, CdrError> {
        if src.len().saturating_sub(*offset) < 16 {
            return Err(CdrError::UnexpectedEof);
        }
        let mut key = [0; 16];
        key.copy_from_slice(&src[*offset..*offset + 16]);
        *offset += 16;
        Ok(Self(RawBytes::decode_cdr2_le_at(src, offset)?, key))
    }
}
impl DdsTrait for CapturedBytes {
    fn type_descriptor() -> &'static TypeDescriptor {
        RawBytes::type_descriptor()
    }
    fn encode(&self, buf: &mut [u8], _version: crate::dds::CdrVersion) -> Result<usize> {
        self.encode_cdr2_le(buf).map_err(|e| match e {
            CdrError::BufferTooSmall => Error::BufferTooSmall,
            _ => Error::SerializationError,
        })
    }
    fn decode(buf: &[u8], version: crate::dds::CdrVersion) -> Result<Self> {
        let (mut value, _) = Self::decode_cdr2_le(buf).map_err(|_| Error::SerializationError)?;
        value.0 .1 = version;
        Ok(value)
    }
    fn capture_wire_data(data: &[u8], key_hash: Option<[u8; 16]>) -> std::borrow::Cow<'_, [u8]> {
        let mut captured = Vec::with_capacity(16 + data.len());
        captured.extend_from_slice(&key_hash.unwrap_or([0; 16]));
        captured.extend_from_slice(data);
        std::borrow::Cow::Owned(captured)
    }
    fn captures_wire_identity() -> bool {
        true
    }
    fn compute_key(&self) -> [u8; 16] {
        self.1
    }
    fn has_key() -> bool {
        true
    }
    fn encodes_xcdr1_natively() -> bool {
        true
    }
}

struct CaptureListener(Arc<dyn DataReaderListener<RawBytes>>);
impl DataReaderListener<CapturedBytes> for CaptureListener {
    fn on_data_available(&self, sample: &CapturedBytes) {
        self.0.on_data_available(&sample.0);
    }
    fn on_data_available_notification(&self) {
        self.0.on_data_available_notification();
    }
    fn on_subscription_matched(&self, status: crate::dds::listener::SubscriptionMatchedStatus) {
        self.0.on_subscription_matched(status);
    }
    fn on_liveliness_changed(&self, status: crate::dds::listener::LivelinessChangedStatus) {
        self.0.on_liveliness_changed(status);
    }
    fn on_sample_lost(&self, status: crate::dds::listener::SampleLostStatus) {
        self.0.on_sample_lost(status);
    }
    fn on_sample_rejected(&self, status: crate::dds::listener::SampleRejectedStatus) {
        self.0.on_sample_rejected(status);
    }
    fn on_requested_deadline_missed(
        &self,
        status: crate::dds::listener::RequestedDeadlineMissedStatus,
    ) {
        self.0.on_requested_deadline_missed(status);
    }
    fn on_requested_incompatible_qos(
        &self,
        status: crate::dds::listener::RequestedIncompatibleQosStatus,
    ) {
        self.0.on_requested_incompatible_qos(status);
    }
    fn on_inconsistent_topic(&self, status: crate::dds::listener::InconsistentTopicStatus) {
        self.0.on_inconsistent_topic(status);
    }
}

/// A raw sample with unparsed CDR payload.
///
/// Returned by [`RawDataReader::try_take_raw()`].
#[derive(Debug, Clone)]
pub struct RawSample {
    /// Raw CDR2 payload (unparsed bytes)
    pub payload: Vec<u8>,

    /// Source timestamp from the DataWriter when one was supplied.
    ///
    /// For compatibility with the original non-optional field, this falls
    /// back to [`reception_timestamp`](Self::reception_timestamp) when the
    /// writer omitted INFO_TS. Use [`RawDataReader::try_take_raw_with_info()`]
    /// when the distinction must be preserved.
    pub source_timestamp: SystemTime,

    /// Reception timestamp (local time)
    pub reception_timestamp: SystemTime,

    /// Sample sequence number. The metadata-aware reader path always fills it;
    /// the `Option` is retained for source compatibility.
    pub sequence_number: Option<u64>,

    /// GUID of the source DataWriter, or [`GUID::zero()`] when unresolved.
    ///
    /// [`RawDataReader::try_take_raw_with_info()`] represents absence with
    /// `None` instead of this compatibility sentinel.
    pub writer_guid: GUID,
}

fn system_time_from_unix_ns(timestamp_ns: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_nanos(timestamp_ns)
}

fn legacy_raw_sample(raw_bytes: RawBytes, info: SampleInfo) -> RawSample {
    let reception_timestamp = system_time_from_unix_ns(info.reception_timestamp_ns);
    RawSample {
        payload: raw_bytes.0,
        source_timestamp: info
            .source_timestamp_ns
            .map(system_time_from_unix_ns)
            .unwrap_or(reception_timestamp),
        reception_timestamp,
        sequence_number: Some(info.sequence_number),
        writer_guid: info
            .writer_guid
            .map(GUID::from_bytes)
            .unwrap_or_else(GUID::zero),
    }
}

/// A DataReader that returns raw CDR payloads instead of typed data.
///
/// Created by [`Participant::create_raw_reader()`](super::Participant::create_raw_reader).
pub struct RawDataReader {
    /// Internal reader retaining opaque bytes and instance identity.
    inner: crate::dds::DataReader<CapturedBytes>,
}

/// A DataWriter that sends raw CDR payloads without compile-time type knowledge.
pub struct RawDataWriter {
    inner: crate::dds::DataWriter<RawBytes>,
}

impl RawDataReader {
    /// Wrap the internal reader without exposing its retained key header.
    fn new(inner: crate::dds::DataReader<CapturedBytes>) -> Self {
        Self { inner }
    }

    /// Try to take available samples without blocking.
    ///
    /// Returns all available raw samples since the last call.
    ///
    /// # Returns
    /// Vector of raw samples with metadata
    ///
    /// # Errors
    /// Returns error if reading fails
    pub fn try_take_raw(&self) -> Result<Vec<RawSample>> {
        Ok(self
            .try_take_raw_with_encoding()?
            .into_iter()
            .map(|(sample, _)| sample)
            .collect())
    }

    /// Take raw samples with their actual per-sample XCDR alignment version.
    ///
    /// Payloads have no encapsulation header. Dynamic consumers must retain
    /// this version when decoding 64-bit values and extensible structs.
    pub fn try_take_raw_with_encoding(&self) -> Result<Vec<(RawSample, crate::dds::CdrVersion)>> {
        let mut samples = Vec::new();
        while let Some((raw_bytes, info)) = self.inner.take_with_info()? {
            if let Some(raw_bytes) = raw_bytes {
                let version = raw_bytes.0 .1;
                samples.push((legacy_raw_sample(raw_bytes.0, info), version));
            }
        }
        Ok(samples)
    }

    /// Take payloads, lossless metadata and the encoding of each sample.
    /// The instance handle in `SampleInfo` retains the wire KeyHash for opaque
    /// readers; absent KeyHash is represented by the nil handle.
    ///
    /// # Errors
    /// Returns an error if reading or decoding fails.
    pub fn try_take_raw_with_info_and_encoding(
        &self,
    ) -> Result<Vec<(Vec<u8>, SampleInfo, crate::dds::CdrVersion)>> {
        let mut samples = Vec::new();
        while let Some((raw_bytes, info)) = self.inner.take_with_info()? {
            if let Some(raw_bytes) = raw_bytes {
                samples.push((raw_bytes.0 .0, info, raw_bytes.0 .1));
            }
        }
        Ok(samples)
    }

    /// Try to take raw payloads together with lossless per-sample metadata.
    ///
    /// This is the raw equivalent of [`crate::dds::DataReader::take_with_info`].
    /// Unlike [`try_take_raw`](Self::try_take_raw), missing source timestamps
    /// and unresolved writer GUIDs remain `None` in [`SampleInfo`].
    ///
    /// # Errors
    /// Returns an error if reading or raw payload decoding fails.
    pub fn try_take_raw_with_info(&self) -> Result<Vec<(Vec<u8>, SampleInfo)>> {
        let mut samples = Vec::new();

        while let Some((raw_bytes, info)) = self.inner.take_with_info()? {
            // Same as above: no payload, nothing to hand back, still consumed.
            if let Some(raw_bytes) = raw_bytes {
                samples.push((raw_bytes.0 .0, info));
            }
        }

        Ok(samples)
    }
}

impl RawDataWriter {
    /// Create a new RawDataWriter wrapping a DataWriter<RawBytes>.
    pub(super) fn new(inner: crate::dds::DataWriter<RawBytes>) -> Self {
        Self { inner }
    }

    /// Write a raw CDR payload, labelling it with this writer's OWN
    /// resolved offer (`resolve_writer_data_representation`) -- never a
    /// hardcoded guess. A hardcoded
    /// `RawBytes(payload, Xcdr2)` would disagree with reality for any
    /// writer that resolves something else (an explicit `[XCDR1]` writer,
    /// or a DEFAULT writer of a type that does not refuse XCDR1, `RawBytes`
    /// included). Every consumer of a sample's
    /// representation (`RawBytes::decode`, `try_take_raw_with_encoding`)
    /// already re-derives it from the MATCHED WRITER's resolved offer,
    /// never from this struct's tag at write time -- so a stale
    /// hardcoded tag would be inert, not a wire defect. Labelling with the
    /// resolved offer avoids the inconsistency anyway: a value that looks like
    /// the wire label and is not is exactly the kind of thing the next
    /// change through here trusts by accident.
    ///
    /// This does NOT validate `payload`'s actual byte layout against the
    /// offer -- `write_raw` has no version parameter, so it cannot. A
    /// caller that knows which version its bytes are actually encoded in
    /// (a raw relay forwarding another writer's bytes) must call
    /// [`write_raw_with_encoding`](Self::write_raw_with_encoding) instead,
    /// which refuses a mismatch rather than mislabeling it.
    ///
    /// # Errors
    /// Returns an error if the write fails.
    pub fn write_raw(&self, payload: &[u8]) -> Result<()> {
        let version = crate::dds::cdr_negotiation::writer_offered_version(self.inner.qos())
            .unwrap_or(crate::dds::CdrVersion::Xcdr2);
        let msg = RawBytes(payload.to_vec(), version);
        self.inner.write(&msg)
    }

    /// Write a raw payload that is already encoded in `version`, refusing
    /// the write when `version` is not the one representation this writer
    /// offers.
    ///
    /// DDS-XTypes v1.3 Sec.7.6.3.1.1: "Writers offer a single
    /// representation. A writer will use its offered policy to communicate
    /// with its matched readers". The wire encapsulation identifier this
    /// writer stamps on every sample comes from its own resolved
    /// `data_representation` (set once at creation,
    /// `resolve_writer_data_representation`), never from the bytes handed
    /// to `write()`. A caller that forwards bytes it did not produce --
    /// every raw relay -- must know which version those bytes were encoded
    /// in and call this instead of [`write_raw`](Self::write_raw): this is
    /// the one place that checks the version against the offer before the
    /// label and the bytes can disagree on the wire (item 6, the
    /// default-raw-writer relay mislabeling defect).
    ///
    /// # Errors
    /// Returns [`Error::InvalidState`] when this writer's offered
    /// representation is not `version` (including when the writer's QoS
    /// carries no resolved or recognized representation at all), and
    /// whatever [`write`](crate::dds::DataWriter::write) returns otherwise.
    /// Either way the sample is never sent mislabeled.
    pub fn write_raw_with_encoding(
        &self,
        payload: &[u8],
        version: crate::dds::CdrVersion,
    ) -> Result<()> {
        self.write_raw_with_encoding_and_key(payload, version, None)
    }

    /// Write opaque bytes with their original instance KeyHash in inline QoS
    /// (DDSI-RTPS v2.5 Sec.9.6.4.8), preserving per-instance history.
    ///
    /// # Errors
    /// Returns an error for an encoding mismatch or an underlying write failure.
    pub fn write_raw_with_encoding_and_key(
        &self,
        payload: &[u8],
        version: crate::dds::CdrVersion,
        key_hash: Option<[u8; 16]>,
    ) -> Result<()> {
        self.write_raw_sample(payload, version, key_hash, None)
    }

    fn write_raw_sample(
        &self,
        payload: &[u8],
        version: crate::dds::CdrVersion,
        key_hash: Option<[u8; 16]>,
        source_timestamp_ns: Option<u64>,
    ) -> Result<()> {
        let offered = crate::dds::cdr_negotiation::writer_offered_version(self.inner.qos());
        if offered != Some(version) {
            return Err(Error::InvalidState(format!(
                "raw writer on topic '{}' offers {:?}, refusing to write a payload encoded as {:?}",
                self.inner.topic_name(),
                offered,
                version
            )));
        }
        let msg = RawBytes(payload.to_vec(), version);
        match source_timestamp_ns {
            Some(timestamp) => self
                .inner
                .write_with_key_hash_and_timestamp(&msg, key_hash, timestamp),
            None => self.inner.write_with_key_hash(&msg, key_hash),
        }
    }

    /// Access the configured QoS.
    #[must_use]
    pub fn qos(&self) -> &crate::dds::QoS {
        self.inner.qos()
    }

    /// Return the topic name for this writer.
    #[must_use]
    pub fn topic_name(&self) -> &str {
        self.inner.topic_name()
    }
}

/// A raw writer for a relay, carrying samples of more than one
/// [`crate::dds::CdrVersion`] truthfully: one real [`RawDataWriter`] per
/// representation it has created, each one built to offer exactly that
/// representation ([`crate::dds::QoS::data_representation_xcdr1`] /
/// [`crate::dds::QoS::data_representation_xcdr2`] on top of the relay's
/// other QoS), so the encapsulation label on the wire always matches the
/// bytes [`relay_write`](Self::relay_write) was given.
///
/// This is the fix for item 6: a plain [`RawDataWriter`] created with no
/// `DATA_REPRESENTATION` resolves ONE representation at creation
/// (`RawBytes::encodes_xcdr1_natively() == true`, so an unset QoS offers
/// XCDR1 -- DDS-XTypes v1.3 Sec.7.6.3.1.1) and then labels every sample it
/// is given with that one representation forever, whatever version the
/// source actually used. `RawRelayWriter` instead keeps one writer per
/// version actually seen and routes each payload to the writer that
/// offers it.
///
/// # When a per-version writer is created: eager hint, then lazy
///
/// [`new`](Self::new) takes an optional `eager_hint`: the representation
/// to create a writer for immediately, before any sample has been
/// forwarded. Pass the version already known in advance -- the source
/// writer's own discovered/resolved offer for a live relay
/// (`hdds-router`), the version a recording or a stored route config
/// says it carried, and so on. That writer is then matched with
/// downstream readers by the time the first sample normally arrives,
/// exactly like a writer created once up front today: for the
/// overwhelmingly common case of a topic carrying a single
/// representation this causes no new discovery-latency or
/// first-sample-loss versus the current (if silently mislabeling)
/// behavior.
///
/// A representation this relay sees that is NOT the eager hint -- a
/// second source writer on the same topic offering the other
/// representation, or simply no hint at all -- gets its writer created
/// lazily, on the first sample of that version. That first sample of a
/// newly-seen representation can be lost to normal discovery latency
/// before the new writer matches downstream readers. This relay was
/// previously silently mislabeling 100% of such samples forever (or, for
/// `hdds-recording`/`hdds-persistence`/`hdds-xrce`, had never even
/// observed more than one representation existed); a transient
/// first-sample gap on a newly-seen representation is strictly better
/// than that, and it self-heals on the very next sample instead of never.
pub struct RawRelayWriter {
    participant: Arc<super::Participant>,
    topic_name: String,
    type_name: String,
    base_qos: crate::dds::QoS,
    type_object: Option<CompleteTypeObject>,
    writers: std::sync::Mutex<Vec<(crate::dds::CdrVersion, RawDataWriter)>>,
}

impl RawRelayWriter {
    /// Build a relay writer for `topic_name`/`type_name`. `qos` is the
    /// relay's other QoS (reliability, durability, ...); its
    /// `data_representation` is overwritten per created writer and so is
    /// ignored here. `eager_hint`, when `Some`, is created immediately --
    /// see the type docs for why.
    ///
    /// # Errors
    /// Returns an error when creating the `eager_hint` writer fails
    /// (discovery/transport not initialized, or a QoS the participant
    /// refuses).
    pub fn new(
        participant: Arc<super::Participant>,
        topic_name: &str,
        type_name: &str,
        qos: Option<crate::dds::QoS>,
        type_object: Option<CompleteTypeObject>,
        eager_hint: Option<crate::dds::CdrVersion>,
    ) -> Result<Self> {
        let relay = Self {
            participant,
            topic_name: topic_name.to_string(),
            type_name: type_name.to_string(),
            base_qos: qos.unwrap_or_default(),
            type_object,
            writers: std::sync::Mutex::new(Vec::new()),
        };
        if let Some(version) = eager_hint {
            relay.writer_for(version)?;
        }
        Ok(relay)
    }

    /// The representation-specific QoS for a writer offering `version`:
    /// the relay's base QoS with `data_representation` pinned to exactly
    /// that one version, so `resolve_writer_data_representation` has
    /// nothing to resolve -- the offer is already `version`.
    fn qos_for(&self, version: crate::dds::CdrVersion) -> crate::dds::QoS {
        let qos = self.base_qos.clone();
        match version {
            crate::dds::CdrVersion::Xcdr1 => qos.data_representation_xcdr1(),
            crate::dds::CdrVersion::Xcdr2 => qos.data_representation_xcdr2(),
        }
    }

    /// Ensure a writer offering `version` exists, creating it if this is
    /// the first sample (or the eager hint) of that representation.
    fn writer_for(&self, version: crate::dds::CdrVersion) -> Result<()> {
        let mut writers = self.writers.lock().unwrap_or_else(|e| e.into_inner());
        if writers.iter().any(|(v, _)| *v == version) {
            return Ok(());
        }
        let writer = self.participant.create_raw_writer_with_type(
            &self.topic_name,
            &self.type_name,
            Some(self.qos_for(version)),
            self.type_object.clone(),
            None,
        )?;
        writers.push((version, writer));
        Ok(())
    }

    /// Forward `payload`, already encoded in `version`, through the
    /// writer that offers exactly `version` -- creating it first when
    /// this relay has not carried that representation yet.
    ///
    /// # Errors
    /// Returns an error when creating a not-yet-seen representation's
    /// writer fails, or when the underlying write fails. Either way the
    /// sample is refused, visibly, rather than sent through a writer that
    /// does not offer `version`.
    pub fn relay_write(&self, payload: &[u8], version: crate::dds::CdrVersion) -> Result<()> {
        self.relay_write_with_key(payload, version, None)
    }

    /// Forward an opaque sample with its original instance KeyHash.
    /// The key is emitted as PID_KEY_HASH and retained with writer history.
    ///
    /// # Errors
    /// Returns an error if creating the writer or writing the sample fails.
    pub fn relay_write_with_key(
        &self,
        payload: &[u8],
        version: crate::dds::CdrVersion,
        key_hash: Option<[u8; 16]>,
    ) -> Result<()> {
        self.relay_sample(payload, version, key_hash, None)
    }

    /// Forward opaque bytes with the original instance and source timestamp.
    ///
    /// # Errors
    /// Returns an error if writer creation or sample delivery fails.
    pub fn relay_write_with_key_and_timestamp(
        &self,
        payload: &[u8],
        version: crate::dds::CdrVersion,
        key_hash: Option<[u8; 16]>,
        source_timestamp_ns: u64,
    ) -> Result<()> {
        self.relay_sample(payload, version, key_hash, Some(source_timestamp_ns))
    }

    fn relay_sample(
        &self,
        payload: &[u8],
        version: crate::dds::CdrVersion,
        key_hash: Option<[u8; 16]>,
        source_timestamp_ns: Option<u64>,
    ) -> Result<()> {
        self.writer_for(version)?;
        let writers = self.writers.lock().unwrap_or_else(|e| e.into_inner());
        // `writer_for` above created or found this version's writer.
        let found = writers.iter().find(|(v, _)| *v == version);
        debug_assert!(
            found.is_some(),
            "writer_for leaves a writer for this version"
        );
        let Some((_, writer)) = found else {
            log::error!("relay has no writer for CDR version {version:?} after writer_for");
            return Err(crate::dds::Error::Config(format!(
                "no writer for CDR version {version:?} after writer_for"
            )));
        };
        writer.write_raw_sample(payload, version, key_hash, source_timestamp_ns)
    }

    /// The representations this relay currently carries a writer for
    /// (diagnostics/tests).
    #[must_use]
    pub fn representations(&self) -> Vec<crate::dds::CdrVersion> {
        self.writers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .map(|(v, _)| *v)
            .collect()
    }

    /// Return the topic name this relay writer publishes to.
    #[must_use]
    pub fn topic_name(&self) -> &str {
        &self.topic_name
    }
}

impl super::Participant {
    /// Return every discovered user endpoint without collapsing by topic.
    ///
    /// The snapshot contains the endpoint GUID and its complete advertised
    /// QoS, so callers can distinguish writers with different policies on the
    /// same topic. Built-in `DCPS*` endpoints are omitted, matching
    /// [`Self::discover_topics`].
    pub fn discover_endpoints(&self) -> Result<Vec<DiscoveredEndpointInfo>> {
        let Some(ref discovery_fsm) = self.discovery_fsm else {
            return Err(Error::InvalidState(
                "Discovery not initialized (participant may be in IntraProcess mode)".to_string(),
            ));
        };

        Ok(discovered_endpoint_snapshot(discovery_fsm.get_all_topics()))
    }

    /// Find one discovered endpoint by its publication or subscription handle.
    pub fn find_discovered_endpoint(
        &self,
        endpoint_guid: &GUID,
    ) -> Result<Option<DiscoveredEndpointInfo>> {
        Ok(self
            .discover_endpoints()?
            .into_iter()
            .find(|endpoint| &endpoint.endpoint_guid == endpoint_guid))
    }

    /// Resolve an endpoint's complete dynamic layout, requesting missing types.
    ///
    /// This call does not wait for network replies. `Ok(None)` means discovery
    /// or dependency lookup is still pending; call again after a short delay.
    /// Requests are deduplicated and retried after five seconds. The returned
    /// descriptor contains no unresolved placeholders. Supports structs,
    /// aliases, nonnegative 32-bit enums, numeric primitives and strings.
    /// Cycles, inheritance, optional members, unions, collections and bitmasks
    /// return an error because their dynamic layouts are not fully supported.
    /// Requires `xtypes-structural-assignability` (enabled by default) and UDP
    /// discovery. Only COMPLETE hash references can be requested.
    pub fn resolve_type_descriptor(
        &self,
        endpoint_guid: &GUID,
    ) -> Result<Option<Arc<crate::dynamic::TypeDescriptor>>> {
        #[cfg(feature = "xtypes-structural-assignability")]
        if let Some(service) = &self.type_lookup {
            return service.resolve_type_descriptor(endpoint_guid);
        }
        let _ = endpoint_guid;
        Err(Error::InvalidState(
            "Dynamic type lookup requires UDP discovery and xtypes-structural-assignability".into(),
        ))
    }

    /// Find the complete advertised QoS for a discovered endpoint GUID.
    ///
    /// This is the direct join for match listener handles such as
    /// `SubscriptionMatchedStatus::last_publication_handle`.
    pub fn find_discovered_qos(&self, endpoint_guid: &GUID) -> Result<Option<crate::dds::QoS>> {
        Ok(self
            .find_discovered_endpoint(endpoint_guid)?
            .map(|endpoint| endpoint.qos))
    }

    /// Register nested TypeObjects for structural-assignability resolution.
    ///
    /// Pass the map returned by `hdds::dynamic::collect_nested_type_objects`
    /// (with the `xtypes-structural-assignability` feature enabled) before
    /// creating writers/readers so that the discovery-match path can resolve
    /// hash-keyed inner types (enum members, nested-struct members) to their
    /// `CompleteTypeObject` and compare them structurally per DDS-XTypes v1.3
    /// sec. 7.5.1.  Multiple calls merge; existing entries are preserved.
    /// Hash dependencies must be included in this call or registered earlier.
    /// Objects with unresolved Complete dependencies cannot produce a Minimal
    /// representation and are skipped until registered with those dependencies.
    ///
    /// # No-op without the feature
    ///
    /// When compiled without `xtypes-structural-assignability` this method
    /// does nothing and the parameter is not even evaluated.
    #[cfg(feature = "xtypes-structural-assignability")]
    pub fn register_nested_type_objects(
        &self,
        types: std::collections::HashMap<
            crate::xtypes::EquivalenceHash,
            crate::xtypes::CompleteTypeObject,
        >,
    ) {
        let mut complete_refs_store = self.snapshot_local_type_objects();
        complete_refs_store.extend(types.clone());
        let mut matching_types = types.clone();
        // Build both representations before moving the graph into the matcher.
        // The incoming key may identify either representation; derive the
        // Minimal identity from the converted object rather than trusting it.
        {
            use crate::core::types::{TypeObjectHandle, ROS_HASH_SIZE};
            use crate::xtypes::TypeIdentifier;
            let mut registered = self.registered_types.write();
            // Sorted, so which structurally identical object a shared Minimal
            // key ends up holding never depends on HashMap iteration order.
            let mut ordered: Vec<_> = types.iter().collect();
            ordered.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
            for (source_hash, complete) in ordered {
                let Some(minimal) = crate::dynamic::complete_to_minimal_with_dependencies(
                    complete,
                    &complete_refs_store,
                ) else {
                    log::debug!(
                        "[xtypes] register_nested_type_objects: no Minimal form for {:?}, skipped",
                        complete.type_name()
                    );
                    continue;
                };
                let Ok(complete_hash) = complete.compute_equivalence_hash() else {
                    log::debug!(
                        "[xtypes] register_nested_type_objects: no Complete hash for {:?}, skipped",
                        complete.type_name()
                    );
                    continue;
                };
                // The responders scan handle values by both identifiers.
                let key: String = source_hash
                    .as_bytes()
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect();
                let Ok(minimal_hash) = minimal.compute_equivalence_hash() else {
                    log::debug!(
                        "[xtypes] register_nested_type_objects: no Minimal hash for {:?}, skipped",
                        complete.type_name()
                    );
                    continue;
                };
                let handle = TypeObjectHandle::new(
                    self.distro,
                    Arc::from(key.as_str()),
                    0,
                    Arc::new([0u8; ROS_HASH_SIZE]),
                    complete.clone(),
                    minimal,
                    TypeIdentifier::complete(complete_hash),
                    TypeIdentifier::minimal(minimal_hash),
                );
                // Spec-correct wire Complete TypeObject (DDS-XTypes v1.3
                // 7.3.4.5): member references rewritten from EK_MINIMAL to
                // EK_COMPLETE, resolved through the incoming map itself, so
                // the OMG getTypes responder can serve a Complete object
                // whose dependency references are Complete ids. A receiver
                // that resolves the remote Complete graph may reject Minimal
                // refs inside a Complete object (permanent match retry).
                let complete_wire = crate::dynamic::complete_type_object_with_complete_refs(
                    complete,
                    &complete_refs_store,
                );
                let handle = match complete_wire.compute_equivalence_hash() {
                    Ok(wire_hash) => handle
                        .with_complete_wire(complete_wire, TypeIdentifier::complete(wire_hash)),
                    Err(_) => handle,
                };
                matching_types.insert(complete_hash, complete.clone());
                // A Minimal hash excludes type names: structurally identical
                // types with different names share it. The caller's own entry
                // under that key (or the first in sorted order) keeps it; the
                // others stay reachable under their Complete hash.
                matching_types
                    .entry(minimal_hash)
                    .or_insert_with(|| complete.clone());
                if let (Some(TypeIdentifier::Complete(hash)), Some(wire)) =
                    (&handle.type_id_complete_wire, &handle.complete_wire)
                {
                    matching_types.insert(*hash, wire.clone());
                }
                let handle = Arc::new(handle);
                // Complete identities remain distinct even when Minimal
                // identities coincide across separate registrations.
                let complete_key: String = complete_hash
                    .as_bytes()
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect();
                registered
                    .entry(complete_key)
                    .or_insert_with(|| Arc::clone(&handle));
                registered.entry(key).or_insert(handle);
            }
        }

        if let Some(ref reg) = self.match_registry {
            reg.register_type_objects(matching_types);
        }
    }

    /// ```rust,no_run
    /// use hdds::Participant;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let participant = Participant::builder("viewer").domain_id(0).build()?;
    /// let topics = participant.discover_topics()?;
    /// for topic in topics {
    ///     println!("Found topic: {} (type: {})", topic.name, topic.type_name);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn discover_topics(&self) -> Result<Vec<DiscoveredTopicInfo>> {
        // Check if discovery is available
        let Some(ref discovery_fsm) = self.discovery_fsm else {
            return Err(Error::InvalidState(
                "Discovery not initialized (participant may be in IntraProcess mode)".to_string(),
            ));
        };

        // Query all discovered topics from DiscoveryFsm
        let all_topics = discovery_fsm.get_all_topics();

        let mut result = Vec::new();

        for (topic_name, (writers, readers)) in all_topics {
            // Filter out built-in DDS topics (start with "DCPS")
            if topic_name.starts_with("DCPS") {
                continue;
            }

            // Skip topics with no endpoints
            if writers.is_empty() && readers.is_empty() {
                continue;
            }

            // Extract metadata from first endpoint (all should have same type_name/type_id)
            let first_endpoint = writers.first().or_else(|| readers.first());

            if let Some(endpoint) = first_endpoint {
                // Compute QoS hash from actual QoS object
                // Simple hash combining reliability+durability+history for telemetry
                use crate::dds::qos::{Durability, History, Reliability};
                let rel_val = match endpoint.qos.reliability {
                    Reliability::BestEffort => 1u32,
                    Reliability::Reliable => 2u32,
                };
                let dur_val = match endpoint.qos.durability {
                    Durability::Volatile => 0u32,
                    Durability::TransientLocal => 1u32,
                    Durability::Transient => 2u32,
                    Durability::Persistent => 3u32,
                };
                let hist_val = match endpoint.qos.history {
                    History::KeepLast(depth) => depth & 0xFF,
                    History::KeepAll => 0xFF,
                };
                let qos_hash = (rel_val << 16) | (dur_val << 8) | hist_val;

                // Extract type_id (XTypes TypeIdentifier bytes)
                // For now, use empty Vec (will be populated with real TypeObject in Phase 8b)
                let type_id = Vec::new();

                result.push(DiscoveredTopicInfo {
                    name: topic_name,
                    type_name: endpoint.type_name.clone(),
                    type_id,
                    type_object: endpoint.type_object.clone(),
                    publisher_count: writers.len(),
                    subscriber_count: readers.len(),
                    qos: endpoint.qos.clone(),
                    qos_hash,
                });
            }
        }

        Ok(result)
    }

    /// Create a raw DataReader for a topic (no type checking).
    ///
    /// Subscribes to a topic and returns raw CDR payloads without deserialization.
    /// This allows monitoring DDS traffic without knowing the data type at compile-time.
    ///
    /// The reader has no type of its own, so it announces the type name the
    /// topic's writers already announce ([`Self::adopt_type_name`]); with none
    /// known it announces the placeholder `RawBytes`. Use
    /// [`Self::create_raw_reader_with_type`] to choose the name.
    ///
    /// # Arguments
    /// * `topic_name` - Name of the topic to subscribe to
    /// * `qos` - Optional QoS (uses default if None)
    ///
    /// # Returns
    /// RawDataReader that yields unparsed CDR payloads
    ///
    /// # Errors
    /// Returns error if subscription fails or if transport is not initialized
    ///
    /// # Example
    /// ```no_run
    /// use hdds::Participant;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let participant = Participant::builder("viewer").domain_id(0).build()?;
    /// let raw_reader = participant.create_raw_reader("/chatter", None)?;
    ///
    /// let samples = raw_reader.try_take_raw()?;
    /// println!("Received {} raw samples", samples.len());
    /// # Ok(())
    /// # }
    /// ```
    pub fn create_raw_reader(
        self: &Arc<Self>,
        topic_name: &str,
        qos: Option<crate::dds::QoS>,
    ) -> Result<RawDataReader> {
        self.build_raw_reader(topic_name, None, qos, None, None)
    }

    /// Create a raw DataReader for a topic with an explicit type name.
    ///
    /// # Arguments
    /// * `topic_name` - Name of the topic to subscribe to
    /// * `type_name` - DDS type name to announce for discovery
    /// * `qos` - Optional QoS (uses default if None)
    /// * `type_object` - Optional CompleteTypeObject (XTypes)
    /// * `listener` - Optional listener for `on_subscription_matched` /
    ///   `on_requested_incompatible_qos` callbacks
    pub fn create_raw_reader_with_type(
        self: &Arc<Self>,
        topic_name: &str,
        type_name: &str,
        qos: Option<crate::dds::QoS>,
        type_object: Option<CompleteTypeObject>,
        listener: Option<Arc<dyn DataReaderListener<RawBytes>>>,
    ) -> Result<RawDataReader> {
        self.build_raw_reader(topic_name, Some(type_name), qos, type_object, listener)
    }

    /// The raw reader both constructors build: with `type_name` it announces
    /// that name, without it the reader adopts one
    /// ([`Self::adopt_type_name`]).
    fn build_raw_reader(
        self: &Arc<Self>,
        topic_name: &str,
        type_name: Option<&str>,
        qos: Option<crate::dds::QoS>,
        type_object: Option<CompleteTypeObject>,
        listener: Option<Arc<dyn DataReaderListener<RawBytes>>>,
    ) -> Result<RawDataReader> {
        // Check if transport is available
        if self.transport.is_none() {
            return Err(Error::InvalidState(
                "Transport not initialized (participant may be in IntraProcess mode)".to_string(),
            ));
        }

        // Use default QoS if not provided
        let qos = qos.unwrap_or_default();

        // Capture instance identity alongside the unchanged CDR payload.
        let mut builder = self
            .topic::<CapturedBytes>(topic_name)?
            .reader()
            .qos(qos.clone());
        builder = match type_name {
            Some(type_name) => builder.with_type_name_override(type_name),
            None => builder.adopting_type_name(),
        };

        if let Some(type_object) = type_object {
            builder = builder.with_type_object_override(type_object);
        }

        if let Some(listener) = listener {
            builder = builder.with_listener(Arc::new(CaptureListener(listener)));
        }

        if let Some(ref registry) = self.registry {
            builder = builder.with_registry(registry.clone());
        }

        if let Some(ref transport) = self.transport {
            builder = builder.with_transport(transport.clone());
        }

        builder = builder.with_participant_guard(self.graph_guard());

        let inner_reader = builder.build()?;

        Ok(RawDataReader::new(inner_reader))
    }

    /// Create a raw DataWriter for a topic with an explicit type name.
    ///
    /// # Arguments
    /// * `topic_name` - Name of the topic to publish to
    /// * `type_name` - DDS type name to announce for discovery
    /// * `qos` - Optional QoS (uses default if None)
    /// * `type_object` - Optional CompleteTypeObject (XTypes)
    /// * `listener` - Optional listener for `on_publication_matched` /
    ///   `on_offered_incompatible_qos` callbacks
    pub fn create_raw_writer_with_type(
        self: &Arc<Self>,
        topic_name: &str,
        type_name: &str,
        qos: Option<crate::dds::QoS>,
        type_object: Option<CompleteTypeObject>,
        listener: Option<Arc<dyn DataWriterListener<RawBytes>>>,
    ) -> Result<RawDataWriter> {
        self.create_raw_writer_with_type_and_encapsulation(
            topic_name,
            type_name,
            qos,
            type_object,
            None,
            listener,
        )
    }

    /// Create a raw DataWriter with an explicit canonical (XCDR2)
    /// encapsulation kind override.
    ///
    /// Identical to [`create_raw_writer_with_type`] plus
    /// `encapsulation_kind`: when `Some`, the writer stamps that canonical
    /// representation identifier (`0x0007` PLAIN_CDR2_LE / `0x0009`
    /// D_CDR2_LE / `0x000B` PL_CDR2_LE, DDS-XTypes v1.3 section 7.6.3.1.2)
    /// on its serialized payloads instead of deriving it from the
    /// TypeObject extensibility flags. The wire encap still degrades to
    /// the matching XCDR1 code when XCDR1 is negotiated.
    ///
    /// Use this when the application suppresses the TypeObject from SEDP
    /// (`type_object == None`) but publishes appendable/mutable bodies:
    /// without a TypeObject the engine cannot know the extensibility and
    /// would default to PLAIN_CDR2 (`0x0007`), which strict peers reject
    /// for DHEADER-framed payloads.
    ///
    /// [`create_raw_writer_with_type`]: Self::create_raw_writer_with_type
    pub fn create_raw_writer_with_type_and_encapsulation(
        self: &Arc<Self>,
        topic_name: &str,
        type_name: &str,
        qos: Option<crate::dds::QoS>,
        type_object: Option<CompleteTypeObject>,
        encapsulation_kind: Option<u16>,
        listener: Option<Arc<dyn DataWriterListener<RawBytes>>>,
    ) -> Result<RawDataWriter> {
        self.build_raw_writer(
            topic_name,
            Some(type_name),
            qos,
            type_object,
            encapsulation_kind,
            listener,
        )
    }

    /// The raw writer both constructors build: with `type_name` it announces
    /// that name, without it the writer adopts one
    /// ([`Self::adopt_type_name`]).
    fn build_raw_writer(
        self: &Arc<Self>,
        topic_name: &str,
        type_name: Option<&str>,
        qos: Option<crate::dds::QoS>,
        type_object: Option<CompleteTypeObject>,
        encapsulation_kind: Option<u16>,
        listener: Option<Arc<dyn DataWriterListener<RawBytes>>>,
    ) -> Result<RawDataWriter> {
        if self.transport.is_none() {
            return Err(Error::InvalidState(
                "Transport not initialized (participant may be in IntraProcess mode)".to_string(),
            ));
        }

        let qos = qos.unwrap_or_default();

        let mut builder = self
            .topic::<RawBytes>(topic_name)?
            .writer()
            .qos(qos.clone());
        builder = match type_name {
            Some(type_name) => builder.with_type_name_override(type_name),
            None => builder.adopting_type_name(),
        };

        if let Some(type_object) = type_object {
            builder = builder.with_type_object_override(type_object);
        }

        if let Some(kind) = encapsulation_kind {
            builder = builder.with_encapsulation_kind_override(kind);
        }

        if let Some(listener) = listener {
            builder = builder.with_listener(listener);
        }

        if let Some(ref registry) = self.registry {
            builder = builder.with_registry(registry.clone());
        }

        if let Some(ref transport) = self.transport {
            builder = builder.with_transport(transport.clone());
        }

        if let Some(ref discovery_fsm) = self.discovery_fsm {
            builder = builder.with_endpoint_registry(discovery_fsm.endpoint_registry());
        }

        builder = builder.with_domain_state(self.domain_state.clone());

        let inner_writer = builder.build()?;

        Ok(RawDataWriter::new(inner_writer))
    }

    /// Create a raw DataWriter for a topic (no type checking).
    ///
    /// Like [`Self::create_raw_reader`], it announces the type name the
    /// topic's readers already announce ([`Self::adopt_type_name`]), else the
    /// placeholder `RawBytes`.
    pub fn create_raw_writer(
        self: &Arc<Self>,
        topic_name: &str,
        qos: Option<crate::dds::QoS>,
    ) -> Result<RawDataWriter> {
        self.build_raw_writer(topic_name, None, qos, None, None, None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A UDP participant on a domain in the 200-230 test range.
    fn adopt_participant(
        name: &str,
    ) -> (
        crate::test_support::domains::DomainLease,
        Arc<crate::dds::Participant>,
    ) {
        let domain = loop {
            let lease = crate::test_support::domains::unique_domain();
            if (200..=230).contains(&lease.id()) {
                break lease;
            }
        };
        let participant = crate::dds::Participant::builder(name)
            .domain_id(domain.id())
            .with_transport(crate::dds::TransportMode::UdpMulticast)
            .build()
            .expect("udp participant");
        (domain, participant)
    }

    /// The type name `participant` announced in SEDP for its endpoint of
    /// `kind` on `topic`.
    fn announced_name(
        participant: &crate::dds::Participant,
        topic: &str,
        kind: crate::core::discovery::multicast::SedpEndpointKind,
    ) -> String {
        let history = participant
            .sedp_announcements
            .read()
            .unwrap_or_else(|e| e.into_inner());
        let found = history
            .alive()
            .find(|(data, k)| data.topic_name == topic && *k == kind)
            .map(|(data, _)| data.type_name.clone());
        found.expect("the endpoint was announced")
    }

    fn remote_endpoint(topic: &str, type_name: &str, kind: EndpointKind, id: u8) -> EndpointInfo {
        let guid = GUID::from_bytes([
            0xA,
            0xB,
            0xC,
            0xD,
            0xE,
            0xF,
            1,
            2,
            3,
            4,
            5,
            id,
            0,
            0,
            0,
            match kind {
                EndpointKind::Writer => 0x03,
                EndpointKind::Reader => 0x04,
            },
        ]);
        EndpointInfo {
            endpoint_guid: guid,
            participant_guid: guid,
            topic_name: topic.into(),
            type_name: type_name.into(),
            qos: crate::dds::QoS::best_effort(),
            kind,
            type_object: None,
            type_object_legacy_v1: false,
            type_information: None,
            has_explicit_ownership: false,
            has_ownership_strength: false,
            shm_capability: None,
            incarnation: 0,
            group_entity_id: None,
            endpoint_security_info: None,
        }
    }

    /// XTypes 1.3 7.6.3.4.2 Step 2: a raw reader created without a name
    /// announces the name of the typed writer of its topic, so the pair
    /// matches (under `HDDS_TYPE_NAME_MATCH=enforce` too) and Step 2 records
    /// no mismatch.
    #[test]
    fn raw_reader_without_a_name_adopts_the_typed_writers_name() {
        let (_domain, participant) = adopt_participant("adopt_reader");
        let topic = "adopt_reader_topic";
        let _typed = participant
            .create_raw_writer_with_type(topic, "X::Y", None, None, None)
            .expect("typed writer");
        let reader = participant
            .create_raw_reader(topic, None)
            .expect("nameless raw reader");

        assert_eq!(
            announced_name(
                &participant,
                topic,
                crate::core::discovery::multicast::SedpEndpointKind::Reader
            ),
            "X::Y"
        );
        assert_eq!(
            reader.inner.get_subscription_matched_status().current_count,
            1,
            "the nameless reader must match the typed writer"
        );
        let registry = participant.match_registry.as_ref().expect("match registry");
        assert_eq!(registry.type_name_warning_count(topic), 0);
    }

    /// The writer side: a raw writer created without a name announces the
    /// name of the typed reader of its topic.
    #[test]
    fn raw_writer_without_a_name_adopts_the_typed_readers_name() {
        let (_domain, participant) = adopt_participant("adopt_writer");
        let topic = "adopt_writer_topic";
        let _typed = participant
            .create_raw_reader_with_type(topic, "X::Y", None, None, None)
            .expect("typed reader");
        let writer = participant
            .create_raw_writer(topic, None)
            .expect("nameless raw writer");

        assert_eq!(
            announced_name(
                &participant,
                topic,
                crate::core::discovery::multicast::SedpEndpointKind::Writer
            ),
            "X::Y"
        );
        assert_eq!(
            writer.inner.get_publication_matched_status().current_count,
            1,
            "the nameless writer must match the typed reader"
        );
        let registry = participant.match_registry.as_ref().expect("match registry");
        assert_eq!(registry.type_name_warning_count(topic), 0);
    }

    /// Nothing discovered: the placeholder stays, so two nameless endpoints
    /// still match each other; the endpoint is not re-announced when a
    /// typed peer shows up later.
    #[test]
    fn nameless_endpoints_with_nothing_discovered_keep_the_placeholder() {
        let (_domain, participant) = adopt_participant("adopt_none");
        let topic = "adopt_none_topic";
        let _reader = participant.create_raw_reader(topic, None).expect("reader");
        let _writer = participant.create_raw_writer(topic, None).expect("writer");
        use crate::core::discovery::multicast::SedpEndpointKind as K;
        assert_eq!(announced_name(&participant, topic, K::Reader), "RawBytes");
        assert_eq!(announced_name(&participant, topic, K::Writer), "RawBytes");

        let fsm = participant.discovery_fsm.as_ref().expect("discovery");
        fsm.insert_remote_endpoint_for_test(remote_endpoint(
            topic,
            "Late::T",
            EndpointKind::Writer,
            1,
        ));
        assert_eq!(announced_name(&participant, topic, K::Reader), "RawBytes");
    }

    /// A remote writer's name is adopted; a placeholder-named writer beside it
    /// is a name too (ambiguous: the placeholder is kept), as are two
    /// different real names.
    #[test]
    fn remote_writers_names_are_adopted_unless_ambiguous() {
        let (_domain, participant) = adopt_participant("adopt_remote");
        let fsm = participant.discovery_fsm.as_ref().expect("discovery");
        use DiscoveredEndpointKind::Reader;

        fsm.insert_remote_endpoint_for_test(remote_endpoint(
            "adopt_r1",
            "A::T",
            EndpointKind::Writer,
            1,
        ));
        assert_eq!(
            participant.adopt_type_name("adopt_r1", Reader).as_deref(),
            Some("A::T")
        );
        // A live placeholder-named writer beside it is a name too: the
        // topic is ambiguous and the placeholder is kept.
        fsm.insert_remote_endpoint_for_test(remote_endpoint(
            "adopt_r1",
            "RawBytes",
            EndpointKind::Writer,
            2,
        ));
        assert_eq!(participant.adopt_type_name("adopt_r1", Reader), None);

        fsm.insert_remote_endpoint_for_test(remote_endpoint(
            "adopt_r2",
            "A::T",
            EndpointKind::Writer,
            3,
        ));
        fsm.insert_remote_endpoint_for_test(remote_endpoint(
            "adopt_r2",
            "B::T",
            EndpointKind::Writer,
            4,
        ));
        assert_eq!(participant.adopt_type_name("adopt_r2", Reader), None);

        // Readers on the topic do not name a reader's type.
        fsm.insert_remote_endpoint_for_test(remote_endpoint(
            "adopt_r3",
            "C::T",
            EndpointKind::Reader,
            5,
        ));
        assert_eq!(participant.adopt_type_name("adopt_r3", Reader), None);
    }

    /// The optional wait ends as soon as a name is discovered, and gives up
    /// at its deadline when none is.
    #[test]
    fn adopt_wait_ends_on_discovery_and_at_its_deadline() {
        let (_domain, participant) = adopt_participant("adopt_wait");
        let fsm = participant.discovery_fsm.clone().expect("discovery");
        let started = std::time::Instant::now();
        assert_eq!(
            participant.adopt_type_name_within(
                "adopt_wait_none",
                DiscoveredEndpointKind::Reader,
                Duration::from_millis(150)
            ),
            None
        );
        assert!(started.elapsed() >= Duration::from_millis(150));

        let late = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            fsm.insert_remote_endpoint_for_test(remote_endpoint(
                "adopt_wait_late",
                "L::T",
                EndpointKind::Writer,
                7,
            ));
        });
        assert_eq!(
            participant
                .adopt_type_name_within(
                    "adopt_wait_late",
                    DiscoveredEndpointKind::Reader,
                    Duration::from_secs(5)
                )
                .as_deref(),
            Some("L::T")
        );
        late.join().expect("inserter");
    }

    /// A TypeObject handle for the keyed type `name`, as a registered topic
    /// type would be.
    fn registered_keyed_type(name: &str) -> Arc<crate::core::types::TypeObjectHandle> {
        use crate::core::types::{Distro, TypeObjectHandle, ROS_HASH_SIZE};
        use crate::xtypes::{
            CommonStructMember, CompleteMemberDetail, CompleteStructHeader, CompleteStructMember,
            CompleteStructType, CompleteTypeDetail, CompleteTypeObject, EquivalenceHash,
            MemberFlag, MinimalStructHeader, MinimalStructType, MinimalTypeDetail,
            MinimalTypeObject, StructTypeFlag, TypeIdentifier,
        };
        let complete = CompleteTypeObject::Struct(CompleteStructType {
            struct_flags: StructTypeFlag::IS_FINAL,
            header: CompleteStructHeader {
                base_type: None,
                detail: CompleteTypeDetail::new(name),
            },
            member_seq: vec![CompleteStructMember {
                common: CommonStructMember {
                    member_id: 0,
                    member_flags: MemberFlag(MemberFlag::IS_KEY.0 | MemberFlag::TRY_CONSTRUCT1.0),
                    member_type_id: TypeIdentifier::TK_INT32,
                },
                detail: CompleteMemberDetail::new("id"),
            }],
        });
        let minimal = MinimalTypeObject::Struct(MinimalStructType {
            struct_flags: StructTypeFlag::IS_FINAL,
            header: MinimalStructHeader {
                base_type: None,
                detail: MinimalTypeDetail::new(),
            },
            member_seq: Vec::new(),
        });
        Arc::new(TypeObjectHandle::new(
            Distro::Humble,
            Arc::<str>::from(name),
            1,
            Arc::new([0u8; ROS_HASH_SIZE]),
            complete,
            minimal,
            TypeIdentifier::Complete(EquivalenceHash::from_bytes([3u8; 14])),
            TypeIdentifier::Minimal(EquivalenceHash::from_bytes([4u8; 14])),
        ))
    }

    /// The SEDP record `participant` announced for its endpoint of `kind`
    /// on `topic`.
    fn announced_data(
        participant: &crate::dds::Participant,
        topic: &str,
        kind: crate::core::discovery::multicast::SedpEndpointKind,
    ) -> crate::protocol::discovery::SedpData {
        let history = participant
            .sedp_announcements
            .read()
            .unwrap_or_else(|e| e.into_inner());
        let found = history
            .alive()
            .find(|(data, k)| data.topic_name == topic && *k == kind)
            .map(|(data, _)| data.clone());
        found.expect("the endpoint was announced")
    }

    /// Type A registered on topic T (`registered_topic_t`), then a nameless
    /// writer and a nameless reader in one in-process participant: the
    /// rule the C constructors apply (`adopting_type_name`).
    fn registered_topic_endpoints(
        label: &str,
    ) -> (
        Arc<crate::dds::Participant>,
        crate::dds::DataWriter<RawBytes>,
        crate::dds::DataReader<RawBytes>,
    ) {
        let domain = loop {
            let lease = crate::test_support::domains::unique_domain();
            if (200..=230).contains(&lease.id()) {
                break lease;
            }
        };
        let participant = crate::dds::Participant::builder(label)
            .domain_id(domain.id())
            .with_transport(crate::dds::TransportMode::IntraProcess)
            .build()
            .expect("participant");
        participant.register_topic_type("registered_topic_t", registered_keyed_type("A::T"));
        let writer = participant
            .topic::<RawBytes>("registered_topic_t")
            .unwrap()
            .writer()
            .adopting_type_name()
            .build()
            .expect("nameless writer");
        let reader = participant
            .topic::<RawBytes>("registered_topic_t")
            .unwrap()
            .reader()
            .adopting_type_name()
            .build()
            .expect("nameless reader");
        (participant, writer, reader)
    }

    /// The name each endpoint announces in SEDP and its TypeObject are the
    /// registered type's.
    #[test]
    fn nameless_endpoints_announce_the_registered_topic_type() {
        use crate::core::discovery::multicast::SedpEndpointKind as K;
        let (participant, _writer, _reader) = registered_topic_endpoints("registered_announce");
        for kind in [K::Writer, K::Reader] {
            let data = announced_data(&participant, "registered_topic_t", kind);
            assert_eq!(
                data.type_name, "A::T",
                "{kind:?} announces the registered type"
            );
            assert!(
                data.type_object.is_some(),
                "{kind:?} announces the registered TypeObject"
            );
        }
    }

    /// The intra-process MatchKey of both endpoints is the name they
    /// announce: the reader takes what the writer wrote.
    #[test]
    fn nameless_endpoints_match_in_process_under_the_registered_type() {
        let (_participant, writer, reader) = registered_topic_endpoints("registered_match");
        writer
            .write(&RawBytes(vec![1, 2, 3, 4], crate::dds::CdrVersion::Xcdr2))
            .expect("write");
        assert!(
            reader.take().expect("take").is_some(),
            "the reader must match the writer in-process"
        );
    }

    /// A name adopted from a peer is a name alone: the TypeObject (and the
    /// keyed entityKind it carries) that this participant registered under
    /// the same name belongs to another type than the bytes the endpoint
    /// carries, and is not attached. An explicit name still gets it.
    #[test]
    fn an_adopted_name_attaches_no_type_object_or_key_kind() {
        use crate::core::discovery::multicast::SedpEndpointKind as K;
        let (_domain, participant) = adopt_participant("adopt_name_only");
        participant.cache_registered_type(&registered_keyed_type("K::Keyed"));
        let fsm = participant.discovery_fsm.as_ref().expect("discovery");
        fsm.insert_remote_endpoint_for_test(remote_endpoint(
            "adopt_name_only_adopting",
            "K::Keyed",
            EndpointKind::Reader,
            1,
        ));

        let _adopting = participant
            .topic::<RawBytes>("adopt_name_only_adopting")
            .unwrap()
            .writer()
            .adopting_type_name()
            .build()
            .expect("adopting writer");
        let data = announced_data(&participant, "adopt_name_only_adopting", K::Writer);
        assert_eq!(data.type_name, "K::Keyed");
        assert!(
            data.type_object.is_none(),
            "an adopted name carries no TypeObject"
        );
        assert_eq!(
            data.endpoint_guid.as_bytes()[15],
            crate::core::rtps_constants::ENTITY_KIND_USER_WRITER_NO_KEY
        );

        let _explicit = participant
            .topic::<RawBytes>("adopt_name_only_explicit")
            .unwrap()
            .writer()
            .with_type_name("K::Keyed")
            .build()
            .expect("explicit writer");
        let data = announced_data(&participant, "adopt_name_only_explicit", K::Writer);
        assert!(
            data.type_object.is_some(),
            "an explicit name keeps its lookup"
        );
        assert_eq!(
            data.endpoint_guid.as_bytes()[15],
            crate::core::rtps_constants::ENTITY_KIND_USER_WRITER_WITH_KEY
        );
    }

    /// A raw writer, a typed peer reader, then a new raw reader: the raw
    /// pair stays matched. The raw writer's placeholder counts as a name
    /// beside the typed one, so the topic is ambiguous and the new reader
    /// keeps the placeholder.
    #[test]
    fn a_raw_writer_beside_a_typed_peer_keeps_the_new_raw_reader_raw() {
        use crate::core::discovery::multicast::SedpEndpointKind as K;
        let (_domain, participant) = adopt_participant("adopt_raw_pair");
        let topic = "adopt_raw_pair_topic";
        let _writer = participant.create_raw_writer(topic, None).expect("writer");
        let fsm = participant.discovery_fsm.as_ref().expect("discovery");
        fsm.insert_remote_endpoint_for_test(remote_endpoint(
            topic,
            "X::Y",
            EndpointKind::Writer,
            1,
        ));
        let reader = participant
            .create_raw_reader(topic, None)
            .expect("new raw reader");

        assert_eq!(announced_name(&participant, topic, K::Writer), "RawBytes");
        assert_eq!(announced_name(&participant, topic, K::Reader), "RawBytes");
        assert!(
            reader.inner.get_subscription_matched_status().current_count >= 1,
            "the raw reader stays matched to the raw writer"
        );
    }

    /// An endpoint created for a type announces that type whatever is
    /// registered for its topic: only a type-less endpoint follows the
    /// registered topic type. A typed `RawBytes` writer beside type A
    /// registered on the topic announces `RawBytes`, with no TypeObject, and
    /// the adopting reader (A) does not receive from it.
    #[test]
    fn a_typed_builder_ignores_the_registered_topic_type() {
        use crate::core::discovery::multicast::SedpEndpointKind as K;
        let (participant, _writer, adopting_reader) =
            registered_topic_endpoints("registered_typed");
        let typed_topic = "registered_topic_t";
        let typed = participant
            .topic::<RawBytes>(typed_topic)
            .unwrap()
            .writer()
            .build()
            .expect("typed writer");
        let announced: Vec<_> = {
            let history = participant
                .sedp_announcements
                .read()
                .unwrap_or_else(|e| e.into_inner());
            history
                .alive()
                .filter(|(data, k)| data.topic_name == typed_topic && *k == K::Writer)
                .map(|(data, _)| (data.type_name.clone(), data.type_object.is_some()))
                .collect()
        };
        assert!(
            announced.contains(&("RawBytes".to_string(), false)),
            "the typed writer announces its own type: {announced:?}"
        );
        // Drain what the adopting pair exchanged, then write from the typed
        // writer only: the reader (A::T) must not get it.
        while adopting_reader.take().expect("take").is_some() {}
        typed
            .write(&RawBytes(vec![9, 9, 9, 9], crate::dds::CdrVersion::Xcdr2))
            .expect("write");
        assert!(
            adopting_reader.take().expect("take").is_none(),
            "a typed writer's match key is its own type, not the registered A::T"
        );
    }

    /// Only placeholders announced: the answer cannot change, so the wait
    /// ends at once. Nothing announced still waits for its deadline.
    #[test]
    fn a_placeholder_only_topic_does_not_wait() {
        let (_domain, participant) = adopt_participant("adopt_placeholder_only");
        let fsm = participant.discovery_fsm.as_ref().expect("discovery");
        fsm.insert_remote_endpoint_for_test(remote_endpoint(
            "adopt_placeholder_only",
            "RawBytes",
            EndpointKind::Writer,
            1,
        ));
        let started = std::time::Instant::now();
        assert_eq!(
            participant.adopt_type_name_within(
                "adopt_placeholder_only",
                DiscoveredEndpointKind::Reader,
                Duration::from_secs(5)
            ),
            None
        );
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "waited {:?} for a placeholder-only topic",
            started.elapsed()
        );
    }

    /// An XCDR2 writer: a writer labels every sample with the one
    /// representation it offers (DDS-XTypes v1.3 Sec.7.6.3.1.1), whatever
    /// version a `RawBytes` carries.
    fn bound_raw_reader(topic: &str) -> (crate::dds::DataWriter<RawBytes>, RawDataReader) {
        let _ = crate::core::rt::init_slab_pool();
        let writer = crate::dds::writer::WriterBuilder::<RawBytes>::new(topic.to_string())
            .qos(crate::dds::QoS::best_effort().data_representation_xcdr2())
            .build()
            .expect("raw writer build should succeed");
        let reader = crate::dds::reader::ReaderBuilder::<CapturedBytes>::new(topic.to_string())
            .qos(crate::dds::QoS::best_effort())
            .build()
            .expect("raw reader build should succeed");
        reader.bind_to_writer(writer.merger());
        (writer, RawDataReader::new(reader))
    }

    /// DDS v1.4 Sec.2.2.4.3.2: DATA_AVAILABLE still reaches an opaque
    /// reader's listener; source-ordered readers receive no payload.
    #[test]
    fn raw_listener_preserves_destination_order_notifications() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        #[derive(Default)]
        struct Counting {
            payloads: AtomicUsize,
            notifications: AtomicUsize,
        }
        impl DataReaderListener<RawBytes> for Counting {
            fn on_data_available(&self, _sample: &RawBytes) {
                self.payloads.fetch_add(1, Ordering::SeqCst);
            }
            fn on_data_available_notification(&self) {
                self.notifications.fetch_add(1, Ordering::SeqCst);
            }
        }

        let _ = crate::core::rt::init_slab_pool();
        for by_source in [false, true] {
            let topic = format!("raw/listener/{by_source}");
            let writer = crate::dds::writer::WriterBuilder::<RawBytes>::new(topic.clone())
                .qos(crate::dds::QoS::best_effort().data_representation_xcdr2())
                .build()
                .unwrap();
            let listener = Arc::new(Counting::default());
            let qos = if by_source {
                crate::dds::QoS::best_effort().destination_order_by_source()
            } else {
                crate::dds::QoS::best_effort()
            };
            let inner = crate::dds::reader::ReaderBuilder::<CapturedBytes>::new(topic)
                .qos(qos)
                .with_listener(Arc::new(CaptureListener(listener.clone())))
                .build()
                .unwrap();
            inner.bind_to_writer(writer.merger());
            let reader = RawDataReader::new(inner);
            writer
                .write(&RawBytes(vec![1, 2, 3], crate::dds::CdrVersion::Xcdr2))
                .unwrap();
            assert_eq!(
                listener.payloads.load(Ordering::SeqCst),
                usize::from(!by_source)
            );
            assert_eq!(
                listener.notifications.load(Ordering::SeqCst),
                usize::from(by_source)
            );
            let samples = reader.try_take_raw().unwrap();
            assert_eq!(samples.len(), 1);
            assert_eq!(samples[0].payload, [1, 2, 3]);
        }
    }

    /// DDS v1.4 Sec.2.2.2.4.2.11/2.2.3.17: an explicit source timestamp
    /// does not change opaque payload or instance identity on local delivery.
    #[test]
    fn raw_local_capture_preserves_metadata_with_a_reception_prefix() {
        let (writer, reader) = bound_raw_reader("raw/reception-prefix");
        let key = [0x42; 16];
        writer
            .write_with_key_hash_and_timestamp(
                &RawBytes(vec![1, 2, 3], crate::dds::CdrVersion::Xcdr2),
                Some(key),
                1_234_567_890,
            )
            .unwrap();
        let samples = reader.try_take_raw_with_info_and_encoding().unwrap();
        assert_eq!(samples.len(), 1);
        assert_eq!(samples[0].0, [1, 2, 3]);
        assert_eq!(samples[0].1.source_timestamp_ns, Some(1_234_567_890));
        assert_eq!(samples[0].1.instance_handle.as_bytes(), &key);
        assert!(samples[0].1.writer_guid.is_some());
        assert_eq!(samples[0].2, crate::dds::CdrVersion::Xcdr2);
    }

    #[test]
    fn raw_payload_preserves_the_reader_supplied_encoding() {
        for version in [crate::dds::CdrVersion::Xcdr1, crate::dds::CdrVersion::Xcdr2] {
            let raw = <RawBytes as DdsTrait>::decode(&[1, 2, 3], version).unwrap();
            assert_eq!(raw.0, vec![1, 2, 3]);
            assert_eq!(raw.1, version);
        }
        let (writer, reader) = bound_raw_reader("raw/version");
        writer
            .write(&RawBytes(vec![1, 2, 3], crate::dds::CdrVersion::Xcdr2))
            .unwrap();
        let samples = reader.try_take_raw_with_encoding().unwrap();
        assert_eq!(samples.len(), 1);
        assert_eq!(samples[0].0.payload, vec![1, 2, 3]);
        assert_eq!(samples[0].1, crate::dds::CdrVersion::Xcdr2);
    }

    /// RTPS v2.5 Sec.8.3.8.11: one source timestamp per sample, including
    /// when a local durable writer supplies the capture reader's history.
    #[test]
    fn local_durable_source_timestamp_survives_late_capture() {
        use crate::dds::{CdrVersion, QoS};
        let _ = crate::core::rt::init_slab_pool();
        let name = "local_durable_source_timestamp".to_string();
        let writer = crate::dds::writer::WriterBuilder::<RawBytes>::new(name.clone())
            .qos(QoS::reliable().transient_local().keep_all())
            .build()
            .unwrap();
        let live = crate::dds::reader::ReaderBuilder::<CapturedBytes>::new(name.clone())
            .qos(QoS::reliable().transient_local().keep_all())
            .build()
            .unwrap();
        live.bind_to_writer(writer.merger());
        writer
            .write(&RawBytes(vec![1, 2, 3], CdrVersion::Xcdr1))
            .unwrap();
        let live = RawDataReader::new(live);
        let samples = live.try_take_raw_with_info_and_encoding().unwrap();
        assert_eq!(samples.len(), 1);
        let source = samples[0]
            .1
            .source_timestamp_ns
            .expect("original source time");
        let late = crate::dds::reader::ReaderBuilder::<CapturedBytes>::new(name)
            .qos(QoS::reliable().transient_local().keep_all())
            .build()
            .unwrap();
        late.bind_to_writer(writer.merger());
        let samples = RawDataReader::new(late)
            .try_take_raw_with_info_and_encoding()
            .unwrap();
        assert_eq!(samples.len(), 1);
        assert_eq!(samples[0].1.source_timestamp_ns, Some(source));
    }

    #[test]
    fn unattributed_capture_preserves_the_payload() {
        let _ = crate::core::rt::init_slab_pool();
        let registry = Arc::new(crate::engine::demux::TopicRegistry::new());
        let inner =
            crate::dds::reader::ReaderBuilder::<CapturedBytes>::new("unattributed_raw".to_string())
                .network_ring_for_test()
                .with_registry(Arc::clone(&registry))
                .qos(crate::dds::QoS::best_effort())
                .build()
                .unwrap();
        registry.get_topic("unattributed_raw").unwrap().deliver(
            1,
            &[0xCA, 0xFE],
            crate::dds::CdrVersion::Xcdr1,
        );
        let reader = RawDataReader::new(inner);
        let samples = reader.try_take_raw_with_info_and_encoding().unwrap();
        assert_eq!(samples.len(), 1);
        assert_eq!(samples[0].0, [0xCA, 0xFE]);
        assert_eq!(
            samples[0].1.instance_handle,
            crate::dds::InstanceHandle::nil()
        );
        assert_eq!(samples[0].2, crate::dds::CdrVersion::Xcdr1);
    }

    /// DDS v1.4 Sec.2.2.3.7: deadlines track each received instance,
    /// without requiring a take and without creating a phantom nil instance.
    #[test]
    fn raw_local_deadlines_count_only_real_instances() {
        #[derive(crate::DDS, Debug, Clone)]
        struct RawDeadlineState {
            #[key]
            id: u32,
        }
        let clock = Arc::new(crate::dds::liveliness::ManualClock::new(0));
        let domain = loop {
            let lease = crate::test_support::domains::unique_domain();
            if (200..=230).contains(&lease.id()) {
                break lease;
            }
        };
        let mut builder = crate::dds::Participant::builder("raw_deadline_identity")
            .domain_id(domain.id())
            .with_transport(crate::dds::TransportMode::IntraProcess);
        builder.liveliness_clock = Some(clock.clone());
        let participant = builder.build().unwrap();
        let mut qos = crate::dds::QoS::best_effort().keep_last(4);
        qos.deadline = crate::qos::deadline::Deadline::new(Duration::from_millis(10));
        let inner = participant
            .topic::<CapturedBytes>("raw_deadline_identity")
            .unwrap()
            .reader()
            .qos(qos.clone())
            .with_type_name_override(RawDeadlineState::type_descriptor().type_name)
            .build()
            .unwrap();
        let reader = RawDataReader::new(inner);
        let writer = participant
            .topic::<RawDeadlineState>("raw_deadline_identity")
            .unwrap()
            .writer()
            .qos(qos)
            .build()
            .unwrap();
        writer.write(&RawDeadlineState { id: 1 }).unwrap();
        writer.write(&RawDeadlineState { id: 2 }).unwrap();
        clock.advance(Duration::from_millis(10));
        participant.liveliness.as_ref().unwrap().shared().settle();
        assert_eq!(
            reader
                .inner
                .get_requested_deadline_missed_status()
                .total_count,
            2
        );
        let samples = reader.try_take_raw_with_info_and_encoding().unwrap();
        assert_eq!(samples.len(), 2);
        assert!(samples
            .iter()
            .all(|(_, info, _)| info.instance_handle != crate::dds::InstanceHandle::nil()));
    }

    // RTPS v2.5 Sec.9.6.4.8: PID_KEY_HASH identifies an opaque sample's
    // instance even though its payload cannot be decoded for key fields.
    #[test]
    fn wire_key_hash_reaches_raw_sample_info() {
        use crate::engine::demux::TopicRegistry;
        use crate::engine::router::{route_data_packet, RouteStatus, RouterMetrics};
        use crate::protocol::builder::{
            build_data_packet_with_context_full_keyed, RtpsEndpointContext,
        };
        let _ = crate::core::rt::init_slab_pool();
        let registry = Arc::new(TopicRegistry::new());
        let topic = "raw_wire_keys";
        let ctx = RtpsEndpointContext {
            guid_prefix: [0x71; 12],
            reader_entity_id: [0; 4],
            writer_entity_id: [0, 0, 3, 2],
            encapsulation_kind: 0x0001,
            publisher_entity_id: [0; 4],
        };
        let mut guid = [0; 16];
        guid[..12].copy_from_slice(&ctx.guid_prefix);
        guid[12..].copy_from_slice(&ctx.writer_entity_id);
        registry.register_writer_guid(guid, topic.to_string());
        registry.register_writer_ownership_kind(guid, crate::qos::ownership::OwnershipKind::Shared);
        let inner = crate::dds::reader::ReaderBuilder::<CapturedBytes>::new(topic.to_string())
            .network_ring_for_test()
            .qos(crate::dds::QoS::best_effort().keep_last(1))
            .with_registry(Arc::clone(&registry))
            .build()
            .unwrap();
        let reader = RawDataReader::new(inner);
        let metrics = RouterMetrics::new();
        for (seq, key) in [(1, [0xA1; 16]), (2, [0xB2; 16]), (3, [0xA1; 16])] {
            let packet = build_data_packet_with_context_full_keyed(
                &ctx,
                topic,
                seq,
                &[seq as u8],
                crate::dds::CdrVersion::Xcdr1,
                None,
                None,
                Some(&key),
            );
            assert_eq!(
                route_data_packet(&packet, packet.len(), None, &registry, &metrics),
                RouteStatus::Delivered
            );
        }
        let samples = reader.try_take_raw_with_info_and_encoding().unwrap();
        assert_eq!(
            samples.len(),
            2,
            "KEEP_LAST(1) retains one value of each wire key"
        );
        assert!(samples.iter().any(|(bytes, info, version)| bytes == &[2]
            && info.instance_handle.0 == [0xB2; 16]
            && *version == crate::dds::CdrVersion::Xcdr1));
        assert!(samples
            .iter()
            .any(|(bytes, info, _)| bytes == &[3] && info.instance_handle.0 == [0xA1; 16]));
    }

    #[test]
    fn test_discovered_topic_info_construction() {
        let info = DiscoveredTopicInfo {
            name: "/chatter".to_string(),
            type_name: "std_msgs::msg::String".to_string(),
            type_id: vec![1, 2, 3, 4],
            type_object: None,
            publisher_count: 2,
            subscriber_count: 1,
            qos: crate::dds::QoS::best_effort(),
            qos_hash: 0x12345678,
        };

        assert_eq!(info.name, "/chatter");
        assert_eq!(info.type_name, "std_msgs::msg::String");
        assert_eq!(info.publisher_count, 2);
        assert_eq!(info.subscriber_count, 1);
    }

    #[test]
    fn discovered_endpoint_preserves_guid_kind_and_qos() {
        let endpoint_guid =
            GUID::from_bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 0, 0, 1, 0x02]);
        let participant_guid =
            GUID::from_bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 0, 0, 1, 0xC1]);
        let endpoint = EndpointInfo {
            endpoint_guid,
            participant_guid,
            topic_name: "/telemetry".to_string(),
            type_name: "Telemetry".to_string(),
            qos: crate::dds::QoS::reliable(),
            kind: EndpointKind::Writer,
            type_object: None,
            type_object_legacy_v1: false,
            type_information: None,
            has_explicit_ownership: true,
            has_ownership_strength: false,
            shm_capability: None,
            incarnation: 0,
            group_entity_id: None,
            endpoint_security_info: None,
        };

        let discovered = DiscoveredEndpointInfo::from(endpoint);
        assert_eq!(discovered.endpoint_guid, endpoint_guid);
        assert_eq!(discovered.participant_guid, participant_guid);
        assert_eq!(discovered.kind, DiscoveredEndpointKind::Writer);
        assert_eq!(discovered.topic_name, "/telemetry");
        assert_eq!(
            discovered.qos.reliability,
            crate::dds::qos::Reliability::Reliable
        );
    }

    #[test]
    fn endpoint_snapshot_does_not_collapse_qos_on_shared_topic() {
        let participant_guid =
            GUID::from_bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 0, 0, 1, 0xC1]);
        let endpoint = |entity: u8, qos| EndpointInfo {
            endpoint_guid: GUID::from_bytes([
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 0, 0, entity, 0x02,
            ]),
            participant_guid,
            topic_name: "/shared".to_string(),
            type_name: "SharedType".to_string(),
            qos,
            kind: EndpointKind::Writer,
            type_object: None,
            type_object_legacy_v1: false,
            type_information: None,
            has_explicit_ownership: false,
            has_ownership_strength: false,
            shm_capability: None,
            incarnation: 0,
            group_entity_id: None,
            endpoint_security_info: None,
        };
        let mut topics = std::collections::HashMap::new();
        topics.insert(
            "/shared".to_string(),
            (
                vec![
                    endpoint(1, crate::dds::QoS::best_effort()),
                    endpoint(2, crate::dds::QoS::reliable()),
                ],
                Vec::new(),
            ),
        );

        let endpoints = discovered_endpoint_snapshot(topics);
        assert_eq!(endpoints.len(), 2);
        assert_eq!(
            endpoints[0].qos.reliability,
            crate::dds::qos::Reliability::BestEffort
        );
        assert_eq!(
            endpoints[1].qos.reliability,
            crate::dds::qos::Reliability::Reliable
        );
    }

    #[test]
    fn test_raw_sample_construction() {
        let sample = RawSample {
            payload: vec![0xCA, 0xFE, 0xBA, 0xBE],
            source_timestamp: SystemTime::now(),
            reception_timestamp: SystemTime::now(),
            sequence_number: Some(42),
            writer_guid: GUID::zero(),
        };

        let RawSample {
            payload,
            source_timestamp: _,
            reception_timestamp: _,
            sequence_number,
            writer_guid: _,
        } = sample;
        assert_eq!(payload.len(), 4);
        assert_eq!(sequence_number, Some(42));
    }

    #[test]
    fn try_take_raw_with_info_preserves_local_writer_metadata() {
        let (writer, reader) = bound_raw_reader("raw_with_info_metadata");
        let expected_guid = writer.merger().writer().expect("known local writer").guid;
        writer
            .write(&RawBytes(vec![0xCA, 0xFE], crate::dds::CdrVersion::Xcdr2))
            .expect("raw write should succeed");

        let samples = reader
            .try_take_raw_with_info()
            .expect("raw take with info should succeed");
        assert_eq!(samples.len(), 1);
        assert_eq!(samples[0].0, vec![0xCA, 0xFE]);
        assert!(samples[0].1.source_timestamp_ns.is_some());
        assert_eq!(samples[0].1.writer_guid, Some(expected_guid));
        assert_eq!(samples[0].1.sequence_number, 1);
    }

    #[test]
    fn legacy_raw_sample_projects_real_metadata_with_documented_fallbacks() {
        let writer_guid = [
            0x01, 0x0f, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x00, 0x00,
            0x00, 0x02,
        ];
        let key_hash = [0x7A; 16];
        let info = SampleInfo {
            source_timestamp_ns: Some(1_234_567_890),
            reception_timestamp_ns: 1_234_568_999,
            writer_guid: Some(writer_guid),
            sequence_number: 42,
            instance_handle: crate::dds::InstanceHandle::new(key_hash),
            instance_state: crate::dds::InstanceState::Alive,
            valid_data: true,
            sample_state: crate::dds::SampleState::NotRead,
            view_state: crate::dds::ViewState::New,
            disposed_generation_count: 0,
            no_writers_generation_count: 0,
            sample_rank: 0,
            generation_rank: 0,
            absolute_generation_rank: 0,
        };

        let sample =
            legacy_raw_sample(RawBytes(vec![1, 2, 3], crate::dds::CdrVersion::Xcdr2), info);
        assert_eq!(sample.payload, vec![1, 2, 3]);
        assert_eq!(
            sample.source_timestamp,
            system_time_from_unix_ns(1_234_567_890)
        );
        assert_eq!(
            sample.reception_timestamp,
            system_time_from_unix_ns(1_234_568_999)
        );
        assert_eq!(sample.sequence_number, Some(42));
        assert_eq!(sample.writer_guid, GUID::from_bytes(writer_guid));

        let no_source = SampleInfo {
            source_timestamp_ns: None,
            writer_guid: None,
            ..info
        };
        let sample = legacy_raw_sample(RawBytes(vec![], crate::dds::CdrVersion::Xcdr2), no_source);
        assert_eq!(sample.source_timestamp, sample.reception_timestamp);
        assert!(sample.writer_guid.is_zero());
    }
}
