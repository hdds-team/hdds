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

mod condition;
mod content_filtered_topic;
mod domain_registry;
/// Content filter expression parser and evaluator.
pub mod filter;
/// Listener traits for callback-based notifications.
pub mod listener;
mod participant;
/// Prelude module for convenient imports.
pub mod prelude;
mod publisher;
/// QoS policy definitions and helpers for HDDS public API.
pub mod qos;
mod read_condition;
mod reader;
mod subscriber;
mod topic;
mod waitset;
mod writer;

pub use condition::{Condition, GuardCondition, HasStatusCondition, StatusCondition, StatusMask};
pub use content_filtered_topic::ContentFilteredTopic;
pub use filter::{ContentFilter, FieldValue, FilterError, FilterEvaluator};
pub use participant::{
    DiscoveredTopicInfo, Participant, ParticipantBuilder, RawDataReader, RawDataWriter, RawSample,
    TransportMode,
};
pub use publisher::Publisher;
pub use qos::{
    Deadline, DestinationOrder, DestinationOrderKind, Durability, DurabilityService, EntityFactory,
    GroupData, History, LatencyBudget, Lifespan, Liveliness, LivelinessKind, Ownership,
    OwnershipKind, OwnershipStrength, Partition, Presentation, PresentationAccessScope, QoS,
    ReaderDataLifecycle, Reliability, TimeBasedFilter, TopicData, TransportPriority, UserData,
    WriterDataLifecycle,
};
pub use read_condition::{
    InstanceStateMask, QueryCondition, ReadCondition, SampleStateMask, ViewStateMask,
};
pub use reader::DataReader;
pub use subscriber::Subscriber;
pub use topic::Topic;
pub use waitset::WaitSet;
pub use writer::DataWriter;

// Listener traits and status types
pub use listener::{
    ClosureListener, DataReaderListener, DataWriterListener, LivelinessChangedStatus,
    PublicationMatchedStatus, RequestedDeadlineMissedStatus, RequestedIncompatibleQosStatus,
    SampleLostStatus, SampleRejectedReason, SampleRejectedStatus, SubscriptionMatchedStatus,
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
    /// Generic configuration error (prefer specific variants below).
    Config,
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

    // ========================================================================
    // Other Errors
    // ========================================================================
    /// Requested feature or operation is not supported.
    Unsupported,
    /// Permission denied by access control (DDS Security).
    #[cfg(feature = "security")]
    PermissionDenied(String),
}

impl std::fmt::Display for Error {
    // @audit-ok: Simple pattern matching (cyclo 28, cogni 1) - error message dispatch table
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            // Configuration
            Error::Config => write!(f, "Configuration error"),
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
            // Other
            Error::Unsupported => write!(f, "Unsupported operation"),
            #[cfg(feature = "security")]
            Error::PermissionDenied(msg) => write!(f, "Permission denied: {}", msg),
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

/// DDS trait: encode/decode contract
pub trait DDS: Sized + Send + Sync + 'static {
    /// Type descriptor (compile-time or manual registration)
    fn type_descriptor() -> &'static crate::core::types::TypeDescriptor;

    /// Encode to CDR2 LE buffer
    ///
    /// # Errors
    ///
    /// Returns `Err` if the buffer is too small or encoding fails.
    fn encode_cdr2(&self, buf: &mut [u8]) -> Result<usize>;

    /// Decode from CDR2 LE buffer
    ///
    /// # Errors
    ///
    /// Returns `Err` if the buffer is truncated or contains invalid data.
    fn decode_cdr2(buf: &[u8]) -> Result<Self>;

    /// Extract field values for content filtering.
    ///
    /// Returns a map of field name to field value for use with ContentFilteredTopic.
    /// Types that want to support content filtering should override this method.
    ///
    /// # Default Implementation
    ///
    /// Returns an empty map by default. Types can opt-in to content filtering by:
    /// 1. **Manual impl:** Implement this method to provide field values
    /// 2. **Proc-macro (future):** `#[derive(DDS)]` will generate this automatically
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

    /// Compute instance key hash from @key fields (FNV-1a, 16 bytes)
    ///
    /// For types with @key fields, computes a 16-byte hash from key field values.
    /// Used for instance identity in keyed topics.
    ///
    /// # Default Implementation
    ///
    /// Returns zeroed hash (no key fields). Types with @key fields should override.
    fn compute_key(&self) -> [u8; 16] {
        [0u8; 16]
    }

    /// Returns true if this type has @key fields
    ///
    /// Used to determine if instance-level operations apply to this type.
    #[must_use]
    fn has_key() -> bool {
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
