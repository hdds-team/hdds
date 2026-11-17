// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! # DDS Core API
//!
//! This module contains the primary DDS (Data Distribution Service) API for HDDS.
//!
//! ## Overview
//!
//! The DDS API provides a publish-subscribe middleware for real-time data distribution.
//! Key concepts:
//!
//! - **Participant**: Entry point to a DDS domain, factory for all entities
//! - **Topic**: Named data channel with an associated type
//! - **Publisher/Subscriber**: Intermediate grouping entities
//! - **DataWriter/DataReader**: Endpoints that send/receive typed data
//! - **QoS**: Quality of Service policies controlling behavior
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use hdds::{Participant, QoS, TransportMode, DDS};
//!
//! #[derive(DDS)]
//! struct SensorData { value: f64 }
//!
//! // Publisher
//! let pub_participant = Participant::builder("publisher")
//!     .with_transport(TransportMode::UdpMulticast)
//!     .build()?;
//! let writer = pub_participant.create_writer::<SensorData>("sensors", QoS::reliable())?;
//! writer.write(&SensorData { value: 42.0 })?;
//!
//! // Subscriber
//! let sub_participant = Participant::builder("subscriber")
//!     .with_transport(TransportMode::UdpMulticast)
//!     .build()?;
//! let reader = sub_participant.create_reader::<SensorData>("sensors", QoS::reliable())?;
//! if let Some(sample) = reader.try_take()? {
//!     println!("Got: {}", sample.value);
//! }
//! # Ok::<(), hdds::Error>(())
//! ```
//!
//! ## Entity Hierarchy
//!
//! ```text
//! DomainParticipant
//! +-- Publisher
//! |   +-- DataWriter<T>  ------> Topic<T>
//! +-- Subscriber
//!     +-- DataReader<T>  <------ Topic<T>
//! ```
//!
//! ## See Also
//!
//! - [`Participant`] - Start here
//! - [`QoS`] - Quality of Service configuration
//! - [`DDS`] - Trait for serializable types
//! - [DDS Specification](https://www.omg.org/spec/DDS/1.4/)

pub(crate) mod cdr_negotiation;
pub(crate) mod coherent_publication;
mod condition;
mod content_filtered_topic;
mod domain_registry;
mod encode_scratch;
/// Content filter expression parser and evaluator.
pub mod filter;
/// Listener traits for callback-based notifications.
pub mod listener;
pub(crate) mod liveliness;
pub(crate) mod match_notification;
mod participant;
/// Prelude module for convenient imports.
pub mod prelude;
mod publisher;
/// QoS policy definitions and helpers for HDDS public API.
pub mod qos;
mod read_condition;
mod reader;
pub(crate) use reader::GroupArrivalScope;
mod subscriber;
mod topic;
mod waitset;
pub(crate) mod writer;

pub(crate) use condition::WAKE_WORDS;
pub use condition::{Condition, GuardCondition, HasStatusCondition, StatusCondition, StatusMask};
pub use content_filtered_topic::ContentFilteredTopic;
pub use filter::{ContentFilter, FieldValue, FilterError, FilterEvaluator};
pub use participant::{
    DiscoveredEndpointInfo, DiscoveredEndpointKind, DiscoveredTopicInfo, Participant,
    ParticipantBuilder, RawDataReader, RawDataWriter, RawRelayWriter, RawSample, TransportMode,
    ADOPT_WAIT_ENV, PLACEHOLDER_TYPE_NAME,
};
pub use publisher::Publisher;
pub use qos::{
    Deadline, DestinationOrder, DestinationOrderKind, Durability, DurabilityService, EntityFactory,
    GroupData, History, LatencyBudget, Lifespan, Liveliness, LivelinessKind, Ownership,
    OwnershipKind, OwnershipStrength, Partition, Presentation, PresentationAccessScope, QoS,
    ReaderDataLifecycle, Reliability, TimeBasedFilter, TopicData, TransportPriority,
    TypeConsistencyEnforcement, UserData, WriterDataLifecycle,
};
pub use read_condition::{
    InstanceStateMask, QueryCondition, ReadCondition, SampleStateMask, ViewStateMask,
};
pub(crate) use reader::notices::{notify as notify_local, Delivering as LocalDelivery};
pub use reader::{
    DataReader, FieldExtractor, InstanceDisposeEvent, InstanceHandle, InstanceState, SampleInfo,
    SampleState, ViewState,
};
pub use subscriber::Subscriber;
pub use topic::Topic;
pub use waitset::WaitSet;
pub use writer::DataWriter;

// Listener traits and status types
pub use listener::{
    ClosureListener, DataReaderListener, DataWriterListener, LivelinessChangedStatus,
    LivelinessLostStatus, PublicationMatchedStatus, RequestedDeadlineMissedStatus,
    RequestedIncompatibleQosStatus, SampleLostStatus, SampleRejectedReason, SampleRejectedStatus,
    SubscriptionMatchedStatus,
};

// Intra-process auto-binding
pub use domain_registry::{BindToken, DomainRegistry, DomainState, EndpointKind, MatchKey, TypeId};

/// Errors returned by HDDS DDS operations.
///
/// This enum covers all error conditions that can occur during DDS operations,
/// from configuration issues to runtime failures.
///
/// # Example
///
/// ```rust,no_run
/// use hdds::{Participant, Error};
///
/// let result = Participant::builder("test")
///     .domain_id(999) // Invalid!
///     .build();
///
/// match result {
///     Err(Error::InvalidDomainId(id)) => println!("Bad domain: {}", id),
///     Err(e) => println!("Other error: {}", e),
///     Ok(_) => println!("Success"),
/// }
/// ```
#[derive(Debug)]
pub enum Error {
    // ========================================================================
    // Configuration Errors
    // ========================================================================
    /// Configuration error with context describing what failed.
    Config(String),
    /// QoS policy is invalid (e.g., negative depth, conflicting policies).
    InvalidQos(String),
    /// Configuration file not found at specified path.
    ConfigFileNotFound(String),

    // ========================================================================
    // Entity Errors
    // ========================================================================
    /// Domain ID out of range (0-232).
    InvalidDomainId(u32),
    /// Participant ID out of range (0-119).
    InvalidParticipantId(u8),
    /// No available participant ID (all 120 ports occupied).
    NoAvailableParticipantId,
    /// Requested participant not found in domain.
    ParticipantNotFound,
    /// Topic registration failed.
    RegistrationFailed,
    /// Invalid state for the requested operation.
    InvalidState(String),

    // ========================================================================
    // Transport Errors
    // ========================================================================
    /// Generic I/O error (deprecated, prefer `IoError`).
    Io,
    /// I/O error with underlying cause.
    IoError(std::io::Error),
    /// UDP transport send/receive failed (deprecated, prefer specific variants).
    TransportError,
    /// Failed to bind socket to address.
    BindFailed(String),
    /// Failed to join multicast group.
    MulticastJoinFailed(String),
    /// Send operation failed.
    SendFailed(String),

    // ========================================================================
    // Data Errors
    // ========================================================================
    /// Type mismatch between writer and reader (different type names or incompatible schemas).
    TypeMismatch,
    /// QoS policies are incompatible between endpoints (e.g., reliable writer + best-effort reader).
    QosIncompatible,
    /// CDR endianness mismatch (received big-endian but expected little-endian or vice versa).
    EndianMismatch,
    /// CDR serialization failed (encoding error, invalid data).
    SerializationError,
    /// Buffer too small for encoding.
    BufferTooSmall,

    // ========================================================================
    // Resource Errors
    // ========================================================================
    /// Operation would block but non-blocking mode requested (e.g., history cache full).
    WouldBlock,
    /// Resource limit exceeded (history depth, max_samples, etc.).
    ResourceLimitExceeded(String),
    /// Out of memory during allocation.
    OutOfMemory,
    /// Write operation timed out (reliable delivery).
    WriteTimeout,
    /// Discovery operation timed out.
    DiscoveryTimeout,
    /// `wait_for_acknowledgments` returned before every sample was
    /// acknowledged by every matched RELIABLE reader (DDS v1.4
    /// Sec.2.2.2.4.1.12 / 2.2.2.4.2.15: RETCODE_TIMEOUT).
    AcknowledgmentTimeout,

    // ========================================================================
    // Other Errors
    // ========================================================================
    /// Requested feature or operation is not supported.
    Unsupported,
    /// Permission denied by access control (DDS Security).
    #[cfg(feature = "security")]
    PermissionDenied(String),
    /// Encryption was requested but could not be applied to a sample, so the
    /// write was refused rather than emitted in cleartext (DDS Security).
    ///
    /// A writer whose participant was built with `enable_encryption(true)` never
    /// falls back to plaintext. If no usable key is available the sample is not
    /// sent and `write()` returns this error.
    #[cfg(feature = "security")]
    EncryptionUnavailable(String),
}

impl std::fmt::Display for Error {
    // @audit-ok: Simple pattern matching (cyclo 28, cogni 1) - error message dispatch table
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            // Configuration
            Error::Config(ctx) => {
                if ctx.is_empty() {
                    write!(f, "Configuration error")
                } else {
                    write!(f, "Configuration error: {}", ctx)
                }
            }
            Error::InvalidQos(msg) => write!(f, "Invalid QoS: {}", msg),
            Error::ConfigFileNotFound(path) => write!(f, "Config file not found: {}", path),
            // Entity
            Error::InvalidDomainId(id) => write!(f, "Invalid domain_id: {} (must be 0-232)", id),
            Error::InvalidParticipantId(id) => {
                write!(f, "Invalid participant_id: {} (must be 0-119)", id)
            }
            Error::NoAvailableParticipantId => write!(
                f,
                "No available participant_id: all 120 slots in use for this domain"
            ),
            Error::ParticipantNotFound => write!(f, "Participant not found"),
            Error::RegistrationFailed => write!(f, "Topic registration failed"),
            Error::InvalidState(msg) => write!(f, "Invalid state: {}", msg),
            // Transport
            Error::Io => write!(f, "I/O error"),
            Error::IoError(e) => write!(f, "I/O error: {}", e),
            Error::TransportError => write!(f, "Transport error"),
            Error::BindFailed(msg) => write!(f, "Bind failed: {}", msg),
            Error::MulticastJoinFailed(msg) => write!(f, "Multicast join failed: {}", msg),
            Error::SendFailed(msg) => write!(f, "Send failed: {}", msg),
            // Data
            Error::TypeMismatch => write!(f, "Type mismatch"),
            Error::QosIncompatible => write!(f, "QoS incompatible"),
            Error::EndianMismatch => write!(f, "Endian mismatch"),
            Error::SerializationError => write!(f, "CDR serialization failed"),
            Error::BufferTooSmall => write!(f, "Buffer too small for encoding"),
            // Resource
            Error::WouldBlock => write!(f, "Operation would block"),
            Error::ResourceLimitExceeded(msg) => write!(f, "Resource limit exceeded: {}", msg),
            Error::OutOfMemory => write!(f, "Out of memory"),
            Error::WriteTimeout => write!(f, "Write timeout"),
            Error::DiscoveryTimeout => write!(f, "Discovery timeout"),
            Error::AcknowledgmentTimeout => write!(f, "Acknowledgment wait timeout"),
            // Other
            Error::Unsupported => write!(f, "Unsupported operation"),
            #[cfg(feature = "security")]
            Error::PermissionDenied(msg) => write!(f, "Permission denied: {}", msg),
            #[cfg(feature = "security")]
            Error::EncryptionUnavailable(msg) => {
                write!(f, "Encryption unavailable, write refused: {}", msg)
            }
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::IoError(e) => Some(e),
            _ => None,
        }
    }
}

/// Convenient alias for API results using the public `Error` type.
pub type Result<T> = core::result::Result<T, Error>;

/// CDR encoding version negotiated per OMG DDS-XTypes v1.3 sec. 7.6.3.1.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CdrVersion {
    /// XCDR v1 per OMG DDS-XTypes v1.3 sec. 7.4.1.
    Xcdr1,
    /// XCDR v2 per OMG DDS-XTypes v1.3 sec. 7.4.2.
    Xcdr2,
}

impl CdrVersion {
    /// The DATA_REPRESENTATION wire code this version announces, per
    /// DDS-XTypes v1.3 sec. 7.6.2.1.2: `0x0000` for XCDR1, `0x0002` for XCDR2.
    ///
    /// For a caller outside this crate that reads a discovered endpoint's
    /// [`crate::dds::QoS::data_representation`] (public: a raw relay
    /// reads the source writer's resolved offer this way, to seed a
    /// [`crate::RawRelayWriter`]'s eager hint without reaching into this
    /// crate's private negotiation internals).
    #[must_use]
    pub fn representation_code(self) -> u16 {
        match self {
            Self::Xcdr1 => 0x0000,
            Self::Xcdr2 => 0x0002,
        }
    }

    /// The version a DATA_REPRESENTATION wire code names, when it is a
    /// CDR version HDDS serializes (`0x0000` XCDR1, `0x0002` XCDR2).
    /// `None` for any other code (XML, or an identifier this build does
    /// not serialize) -- the inverse of [`Self::representation_code`].
    #[must_use]
    pub fn from_representation_code(code: u16) -> Option<Self> {
        match code {
            0x0000 => Some(Self::Xcdr1),
            0x0002 => Some(Self::Xcdr2),
            _ => None,
        }
    }
}

/// DDS trait: encode/decode contract
pub trait DDS: Sized + Send + Sync + 'static {
    /// Type descriptor (compile-time or manual registration)
    fn type_descriptor() -> &'static crate::core::types::TypeDescriptor;

    /// Encode to CDR LE buffer at the requested `version`.
    ///
    /// Version selection follows OMG DDS-XTypes v1.3 sec. 7.6.3.1
    /// (DataRepresentationQosPolicy).
    ///
    /// # Errors
    ///
    /// Returns `Err` if the buffer is too small or encoding fails.
    fn encode(&self, buf: &mut [u8], version: CdrVersion) -> Result<usize>;

    /// Decode from CDR LE buffer at the requested `version`.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the buffer is truncated or contains invalid data.
    fn decode(buf: &[u8], version: CdrVersion) -> Result<Self>;

    /// Whether `encode` and `decode` at [`CdrVersion::Xcdr1`] produce the
    /// XCDR1 layout, with an 8-byte member aligned at 8 (DDS-XTypes 1.3
    /// 7.4.3.2.2, `MAXALIGN(VERSION1) = 8`), everywhere in the type.
    ///
    /// A writer of a type that answers `false` and sets no
    /// DATA_REPRESENTATION offers and encodes XCDR2, and a pair that
    /// negotiates XCDR1 is not matched (INCOMPATIBLE_QOS, policy 23),
    /// rather than sending or reading the XCDR2 layout under an XCDR1
    /// header.
    ///
    /// The default answers `false`: a type is taken to encode XCDR1 only
    /// when it says so. A hand-written `encode` that ignores `version`, or
    /// that relies on the `Cdr2Encode` default `encode_xcdr1_le` (which
    /// delegates to the XCDR2 path), puts an 8-byte member at 4 where XCDR1
    /// puts it at 8; no descriptor tells that apart from a native encoder
    /// (a fixed-size `{u32, f64}` is the case a descriptor guess missed).
    /// `#[derive(DDS)]` and the Rust types `hdds_gen` emits answer `true`:
    /// their encoder aligns every 8-byte member by the requested version.
    /// A hand-written type answers `true` when its XCDR1 bytes are XCDR1:
    /// it implements both layouts, or its body is the same under both (no
    /// 8-byte member, no DHEADER), or it carries opaque bytes whose
    /// representation the QoS names.
    fn encodes_xcdr1_natively() -> bool {
        false
    }

    /// Extract field values for content filtering.
    ///
    /// Returns a map of field name to field value for use with ContentFilteredTopic.
    /// Types that want to support content filtering should override this method.
    ///
    /// # Default Implementation
    ///
    /// Returns an empty map by default. Types can opt-in to content filtering by:
    /// 1. **Derive:** `#[derive(DDS)]` generates this automatically for every
    ///    primitive field and for `String`, keyed by the Rust field name;
    ///    `Vec<u8>` fields are not included (not a filterable scalar).
    /// 2. **Manual impl:** Implement this method to provide field values
    ///    (needed for any type with a hand-written `DDS` impl).
    ///
    /// # Key convention (DDS 1.4 Annex B FIELDNAME)
    ///
    /// A filter expression names a member by its IDL path with dots
    /// (`pos.x`, `pos.inner.depth`) and the evaluator looks that whole path
    /// up as one key of this map. A type with nested structures inserts each
    /// filterable leaf under its dotted path. An enumeration member is
    /// inserted as its label (`FieldValue::String`) so that an
    /// ENUMERATEDVALUE literal (`color = 'RED'`) compares against it; an IDL
    /// `char` is inserted as its code so that a CHARVALUE literal compares by
    /// code point.
    ///
    /// # Example (Manual Implementation)
    ///
    /// ```ignore
    /// fn get_fields(&self) -> std::collections::HashMap<String, filter::FieldValue> {
    ///     let mut fields = std::collections::HashMap::new();
    ///     fields.insert("temperature".to_string(), filter::FieldValue::from_f64(self.temperature));
    ///     fields.insert("sensor_id".to_string(), filter::FieldValue::from_u32(self.sensor_id));
    ///     fields
    /// }
    /// ```
    fn get_fields(&self) -> std::collections::HashMap<String, filter::FieldValue> {
        std::collections::HashMap::new()
    }

    /// Get XTypes v1.3 TypeObject for this type (optional)
    ///
    /// Returns the complete type definition for runtime type discovery.
    /// Used by SEDP (Simple Endpoint Discovery Protocol) to announce
    /// endpoint types to remote participants.
    ///
    /// # XTypes v1.3 Integration
    ///
    /// When present, enables:
    /// - Runtime type compatibility checking (structural equivalence)
    /// - Dynamic type evolution (compatible type changes)
    /// - Multi-vendor interoperability (type discovery without IDL)
    ///
    /// # Default Implementation
    ///
    /// Returns `None` by default. Types can opt-in to type discovery by:
    /// 1. **Auto-generation (future):** Proc-macro generates TypeObject from struct
    /// 2. **Manual impl:** Implement this method to provide custom TypeObject
    ///
    /// # Usage (Future Phase 8b)
    ///
    /// ```ignore
    /// #[derive(DDS)]
    /// struct Temperature {
    ///     celsius: f32,
    ///     timestamp: u64,
    /// }
    ///
    /// // Proc-macro generates:
    /// // fn get_type_object() -> Option<CompleteTypeObject> {
    /// //     Some(CompleteTypeObject::Struct(...))
    /// // }
    ///
    /// // DataWriter<Temperature> automatically announces TypeObject in SEDP
    /// ```
    ///
    /// # None Cases
    ///
    /// - Legacy types (pre-XTypes)
    /// - Proc-macro not available (Phase 8b)
    /// - Types that opt out of type discovery
    #[must_use]
    fn get_type_object() -> Option<crate::xtypes::CompleteTypeObject> {
        None // Default: no generated TypeObject available.
    }

    /// The TypeObjects this type references by hash, so a peer can resolve them.
    ///
    /// A `CompleteTypeObject` names a nested member by its `EquivalenceHash`,
    /// not by value. A consumer that receives this type and wants to decode it
    /// therefore asks the TypeLookup service for each member in turn, and gets
    /// nothing unless the participant can serve them. Code generators already
    /// build every nested object in order to compute the hash they embed in the
    /// parent, so returning them here costs nothing but the move.
    ///
    /// Return the transitive closure: a member's own nested members are asked
    /// for in the same way, so a generator that stops at depth one leaves the
    /// consumer stuck one level down. Order is irrelevant and duplicates are
    /// harmless. No hash is returned with each object because the key a peer
    /// asks by is derived from the object itself, inside the library, by the
    /// same construction the peer used; an implementor cannot compute it and
    /// must not try.
    ///
    /// The default is empty: a type with only primitive, String and byte-vector
    /// members has nothing to declare, which is every type the `#[derive(DDS)]`
    /// macro can express today.
    #[must_use]
    fn nested_type_objects() -> Vec<crate::xtypes::CompleteTypeObject> {
        Vec::new()
    }

    /// The instance KeyHash (`PID_KEY_HASH`) of this sample, as DDSI-RTPS 2.5
    /// 9.6.4.8 and DDS-XTypes 1.3 7.6.8 define it.
    ///
    /// The KeyHash identifies the instance locally and on the wire: a peer
    /// that computes it from the same key values must reach the same 16
    /// bytes, so this is a specified value, not a hash of HDDS's choosing.
    ///
    /// # Default Implementation
    ///
    /// For a type whose [`has_key`](Self::has_key) is `false`, all zeros.
    /// Otherwise the KeyHolder that
    /// [`write_key_holder`](Self::write_key_holder) writes, reduced by
    /// [`KeyHolderWriter::finish`](crate::core::key_hash::KeyHolderWriter::finish)
    /// with the maximum size it returns: padded to 16 bytes when the
    /// KeyHolder's maximum serialized size is at most 16, MD5 otherwise.
    /// Implement that hook rather than this method; see
    /// [`crate::core::key_hash`] for the mapping from IDL to writer calls.
    ///
    /// A type that declares a key and writes no KeyHolder (its
    /// `write_key_holder` returns `None`, the default) gets all zeros, the
    /// value every keyed type got before 1.5.0: all its samples are then one
    /// instance, and a warning is logged once per process.
    fn compute_key(&self) -> [u8; 16] {
        if !Self::has_key() {
            return [0u8; 16];
        }
        let mut w = crate::core::key_hash::KeyHolderWriter::new();
        match self.write_key_holder(&mut w) {
            Some(max) => w.finish(max),
            None => {
                crate::core::key_hash::warn_keyed_type_without_key_holder(std::any::type_name::<
                    Self,
                >());
                [0u8; 16]
            }
        }
    }

    /// This sample's instance identity. Opaque serialization adapters may
    /// carry a key per sample even though their Rust wrapper is keyless.
    fn instance_key(&self) -> Option<[u8; 16]> {
        Self::has_key().then(|| self.compute_key())
    }

    /// MD5 of the CDR big-endian key fields (DDS-Security 1.1 7.3.4).
    /// Opaque adapters may supply the digest computed by their typed codec.
    fn protected_key(&self) -> Option<[u8; 16]> {
        let mut holder = crate::core::key_hash::KeyHolderWriter::for_security();
        self.write_key_holder(&mut holder)?;
        Some(holder.finish(crate::core::key_hash::KeyMaxSize::Unbounded))
    }

    /// Retain wire identity in an opaque reader's internal sample encoding.
    /// Typed readers derive identity from their decoded key fields instead.
    #[doc(hidden)]
    fn capture_wire_data(data: &[u8], _key_hash: Option<[u8; 16]>) -> std::borrow::Cow<'_, [u8]> {
        std::borrow::Cow::Borrowed(data)
    }

    /// Whether the opaque capture needs the writer's local instance identity.
    #[doc(hidden)]
    fn captures_wire_identity() -> bool {
        false
    }

    /// Returns true if this type has @key fields
    ///
    /// Used to determine if instance-level operations apply to this type.
    #[must_use]
    fn has_key() -> bool {
        false
    }

    /// Write this sample's KeyHolder object (RTPS 2.5 9.6.4.8 steps 1 to 4)
    /// and return the KeyHolder's maximum serialized size (step 5).
    ///
    /// The KeyHolder keeps the `@key` members (all members when the type has
    /// none), in ascending member-id order, applying the same rule to each
    /// member that is itself a structure or a union. Write each one with the
    /// call [`crate::core::key_hash`] maps its IDL type to; the writer handles
    /// byte order, alignment and padding.
    ///
    /// The returned size is a property of the type, the same for every
    /// sample: [`KeyMaxSize::Bounded`](crate::core::key_hash::KeyMaxSize::Bounded)
    /// with the largest serialization any value can reach, under the same
    /// alignment rule, or
    /// [`KeyMaxSize::Unbounded`](crate::core::key_hash::KeyMaxSize::Unbounded)
    /// when the KeyHolder holds an unbounded string or sequence. It selects
    /// the padded form (at most 16 bytes) or MD5.
    ///
    /// # Default Implementation
    ///
    /// Writes nothing and returns `None`: the type has no KeyHolder. Only
    /// consulted by the default [`compute_key`](Self::compute_key) when
    /// [`has_key`](Self::has_key) is `true`.
    fn write_key_holder(
        &self,
        _w: &mut crate::core::key_hash::KeyHolderWriter,
    ) -> Option<crate::core::key_hash::KeyMaxSize> {
        None
    }

    /// Serialize ONLY the @key fields for K-flag DATA payloads.
    ///
    /// Per RTPS v2.5 sec. 9.4.5.3.2, a DATA submessage with the K (Key) flag set
    /// carries the serialized key fields as its payload, not the full data.
    /// Subscribers reconstruct instance identity from those bytes; a spec-strict
    /// peer may reject lifecycle samples whose K-payload can
    /// not be parsed as the key encoding declared by the topic's TypeObject.
    ///
    /// # Default Implementation
    ///
    /// Returns an empty `Vec` -- no key bytes. Cross-vendor dispose / unregister
    /// then ships an empty K-payload, which spec-strict peers may still drop
    /// but is preferable to shipping garbage hash bytes. Types with `@key`
    /// fields should override.
    fn encode_key(&self, _version: CdrVersion) -> Vec<u8> {
        Vec::new()
    }

    /// The instance a key-only payload names: the
    /// [`compute_key`](Self::compute_key) of a sample whose key members hold
    /// the values `payload` serializes.
    ///
    /// `payload` is the whole serializedPayload of a DATA with the K flag
    /// set, its 4-byte encapsulation header included: "the value of the key
    /// that identifies the registered instance" (RTPS v2.5 8.3.7.2). The
    /// PID_KEY_HASH that may travel beside it is "a hint for the key"
    /// (8.7.10), so a reader that can read the key names the dispose or
    /// unregister by the key, and falls back to the PID_KEY_HASH only when
    /// this returns `None`. That is what lets a foreign or older writer whose
    /// PID_KEY_HASH is not this type's KeyHash still reach the instance it
    /// means, provided it serialized the key.
    ///
    /// Read the payload with
    /// [`KeyPayloadReader`](crate::core::key_hash::KeyPayloadReader), the
    /// inverse of what [`encode_key`](Self::encode_key) writes, then hash the
    /// values as [`write_key_holder`](Self::write_key_holder) does. Return
    /// `None` for anything that is not certain: an encoding the reader does
    /// not read, a truncated or over-long payload, a value beyond its bound.
    /// A wrong answer here moves a dispose to another instance; `None` only
    /// leaves it to the PID_KEY_HASH.
    ///
    /// # Default Implementation
    ///
    /// `None`: the type cannot read its key, and the reader uses the
    /// PID_KEY_HASH. A type that overrides [`compute_key`](Self::compute_key)
    /// with a value other than the KeyHash must keep this default or return
    /// that same value.
    fn key_hash_of_key_payload(_payload: &[u8]) -> Option<[u8; 16]> {
        None
    }

    /// Whether this type writes and reads back its own key-only payload:
    /// both [`encode_key`](Self::encode_key) and
    /// [`key_hash_of_key_payload`](Self::key_hash_of_key_payload) are
    /// implemented, so a dispose or unregister crosses and names its
    /// instance.
    ///
    /// Endpoint creation consults this on a keyed type under key protection
    /// (`data_protection_kind ENCRYPT`): without the pair, a writer sends an
    /// empty K-payload and a reader cannot name the instance it decrypts, so
    /// every dispose and unregister would be dropped in silence. Such an
    /// endpoint is refused instead.
    ///
    /// # Default Implementation
    ///
    /// `false`. Generated types and the derive return `true`, and so must a
    /// hand-written type that overrides both hooks above: the declaration is
    /// what lets endpoint creation tell a complete pair from a silent loss.
    fn keys_round_trip() -> bool {
        false
    }
}

// All generated types (via build.rs or #[derive(DDS)]) provide real type_descriptor().
// No blanket impl -- each type has its own XTypes metadata.
// Historical context (before Task 1.2):
//   - Temperature used #[derive(hdds::DDS)] -> procmacro generated type_descriptor()
//   - Procmacro only supports primitives (f32, u32, etc.)
//   - Complex types (String, Vec) would fall back to this blanket impl stub
//
// After Task 1.2:
//   - Temperature generated by build.rs with full type_descriptor()
//   - Future: hdds-gen will generate complete DDS impls for ALL types (including String/Vec)
//   - No more stubs -> 100% real metadata
//
// If you're getting "trait DDS is not implemented" errors after this change:
//   -> Use #[derive(hdds::DDS)] for simple types (primitives only)
//   -> Use hdds-gen codegen for complex types (generates full impl in build.rs)

#[cfg(test)]
mod cdr_version_tests {
    use super::CdrVersion;

    #[test]
    fn representation_code_roundtrips_through_from_representation_code() {
        for version in [CdrVersion::Xcdr1, CdrVersion::Xcdr2] {
            assert_eq!(
                CdrVersion::from_representation_code(version.representation_code()),
                Some(version)
            );
        }
    }

    #[test]
    fn representation_code_matches_the_spec_wire_values() {
        assert_eq!(CdrVersion::Xcdr1.representation_code(), 0x0000);
        assert_eq!(CdrVersion::Xcdr2.representation_code(), 0x0002);
    }

    #[test]
    fn from_representation_code_rejects_a_non_cdr_code() {
        // 0x0001 is XML (DDS-XTypes v1.3 Sec.7.6.2.1.2), not a CDR version.
        assert_eq!(CdrVersion::from_representation_code(0x0001), None);
    }
}
