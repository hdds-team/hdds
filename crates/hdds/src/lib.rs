// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! # HDDS - High-performance Data Distribution Service
//!
//! A pure Rust implementation of the OMG DDS (Data Distribution Service) and RTPS
//! (Real-Time Publish-Subscribe) specifications, designed for real-time systems,
//! robotics, `IoT`, and high-frequency trading.
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use hdds::{Participant, QoS, Result};
//!
//! fn main() -> Result<()> {
//!     // Create a DDS participant
//!     let participant = Participant::builder("my_app")
//!         .domain_id(0)
//!         .build()?;
//!
//!     // Create a typed writer
//!     let writer = participant.create_writer::<MyData>("sensors/temperature", QoS::default())?;
//!
//!     // Publish data
//!     writer.write(&MyData { value: 42.0 })?;
//!
//!     Ok(())
//! }
//! # #[derive(hdds::DDS)] struct MyData { value: f64 }
//! ```
//!
//! ## Architecture
//!
//! ```text
//! +---------------------------------------------------------------------+
//! |                         Application Layer                          |
//! |   Participant -> Publisher/Subscriber -> DataWriter/DataReader     |
//! +---------------------------------------------------------------------+
//! |                           DDS Layer                                 |
//! |   QoS Policies | Topic Management | Instance Lifecycle | WaitSets  |
//! +---------------------------------------------------------------------+
//! |                          RTPS Layer                                 |
//! |   Discovery (SPDP/SEDP) | Reliability | History Cache | Fragmentation|
//! +---------------------------------------------------------------------+
//! |                        Transport Layer                              |
//! |   UDP Unicast | UDP Multicast | Shared Memory (*) | TCP (optional) |
//! +---------------------------------------------------------------------+
//! |   (*) present and tested, not yet connected to the data path         |
//! +---------------------------------------------------------------------+
//! ```
//!
//! ## Key Types
//!
//! | Type | Description |
//! |------|-------------|
//! | [`Participant`] | Entry point to the DDS domain, factory for all entities |
//! | [`DataWriter`] | Publishes typed data samples to a topic |
//! | [`DataReader`] | Subscribes to typed data samples from a topic |
//! | [`Topic`] | Named data channel with associated type and `QoS` |
//! | [`QoS`] | Quality of Service policies (reliability, durability, etc.) |
//!
//! ## Features
//!
//! - **Shared memory transport** for co-located participants (Linux). A
//!   BEST_EFFORT writer paired with a BEST_EFFORT reader in the same
//!   shared-memory realm moves unfragmented DATA over a ring in
//!   `/dev/shm`; the control plane (HEARTBEAT, ACKNACK, discovery) stays on
//!   UDP by design, which costs nothing because the leg is BEST_EFFORT on
//!   both sides. Co-location is PROVEN from the IPC and mount namespaces,
//!   never assumed from `/etc/machine-id`, so two containers built from one
//!   image do not mistake each other for neighbours. The choice is made
//!   once per peer, at pairing; a sample that cannot cross afterwards is
//!   always counted in `transport::shm::global_metrics()` and logged, never
//!   silently rerouted. [`ShmPolicy::Require`] still refuses at participant
//!   build: fragmented samples (past 8192 bytes) are still UDP-only.
//! - **DDS Security** v1.1 (authentication, encryption, access control)
//! - **`XTypes`** v1.3 for runtime type discovery and compatibility
//! - **Discovery Server** mode for non-multicast networks
//! - **ROS 2 compatible** via `rmw_hdds` middleware layer
//!
//! ## Modules Overview
//!
//! - [`dds`] - Core DDS API (start here)
//! - [`qos`] - Quality of Service policies
//! - [`transport`] - Network transport implementations
//! - [`discovery`] - SPDP/SEDP discovery protocols
//! - [`security`] - DDS Security plugin
//! - [`xtypes`] - Extended type system
//!
//! ## See Also
//!
//! - [DDS Specification](https://www.omg.org/spec/DDS/1.4/)
//! - [RTPS Specification](https://www.omg.org/spec/DDSI-RTPS/2.5/)
//! - [DDS Security](https://www.omg.org/spec/DDS-SECURITY/1.1/)
//! - [DDS XTypes](https://www.omg.org/spec/DDS-XTypes/1.3/)

// Clippy: No blanket suppressions. Fix issues properly or use inline #[allow] with justification.

// Allow the derive macro to work inside this crate's tests
extern crate self as hdds;

/// Administration and monitoring API (metrics, mesh introspection).
pub mod admin;
/// Compatibility contract between `hddsgen`-generated code and this `hdds`
/// release. Generated Rust files reference [`codegen::CODEGEN_ABI`] (and, for
/// the 1.5.0 jump specifically, the self-naming [`codegen::REQUIRES_HDDS_1_5`])
/// so that linking generated code against an incompatible runtime fails with
/// one readable error instead of thousands of missing-symbol errors.
pub mod codegen;
/// Global configuration (RTPS constants, runtime config, QoS store).
pub mod config;
/// Congestion control (rate limiting, priority queues, AIMD adaptation).
pub mod congestion;
/// Core RTPS protocol implementation (discovery, serialization).
pub mod core;
/// Core DDS API (Participant, DataReader, DataWriter, Publisher, Subscriber).
pub mod dds;
/// Discovery mechanisms (multicast SPDP/SEDP, Discovery Server, Cloud Discovery).
pub mod discovery;
/// Dynamic Types for runtime type manipulation without compile-time type knowledge.
pub mod dynamic;
/// Consolidated data routing and event distribution engine.
pub mod engine;
/// Compile-time configurable logging system (zero-cost when disabled).
pub mod logging;
/// RTPS protocol implementation (constants, builders, discovery parsers).
pub mod protocol;
/// Reliability QoS implementation (Reliable protocol, RTPS messages, history cache).
pub mod reliability;
/// Packet demultiplexing and topic-based routing (re-exported from engine for backwards compatibility).
pub mod demux {
    pub use crate::engine::*;
}
/// Discovery Server client support (for non-multicast environments).
pub mod discovery_server;
/// Interop V2 (wire profiles, matching diagnostics).
mod interop;
/// Legacy interop helpers (FastDDS/RTI env-based toggles).
mod interop_legacy;
/// `QoS` (Quality of Service) policies for DDS entities.
pub mod qos;
/// ROS 2 middleware integration layer (`rmw_hdds`).
pub mod rmw;
/// DDS-RPC: Request/Reply pattern for service-oriented communication.
#[cfg(feature = "rpc")]
pub mod rpc;
/// DDS Security v1.1 implementation (authentication, encryption, access control).
pub mod security;
/// Test-only helpers (UDP port reservation with retry) shared between this
/// crate's own tests and dependent crates' test suites. Compiled only under
/// `cfg(test)` or the `test-support` feature (default off) -- neither adds
/// anything to a normal build's public API.
///
/// The panic lints are switched off for this module, and only this module,
/// because they ask a question that does not apply to it: "would this panic
/// reach an application?". Nothing here is ever compiled into a shipped
/// library, so the answer is no, and a test helper that cannot fail loudly is
/// a worse test helper. The release audit's safety gate runs
/// `clippy --all-features`, which switches `test-support` ON and then reported
/// five of its `expect()`/`panic!` calls as "present in production code" -
/// five HIGH findings against a release, for code the shipped artifact does
/// not contain. Scoping the allow here fixes that at the source rather than
/// teaching the gate another exception.
#[cfg(any(test, feature = "test-support"))]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
pub mod test_support;
/// Transport layer for RTPS communication (UDP, multicast, port mapping).
pub mod transport;
/// XTypes v1.3 support (type discovery, type compatibility checking).
pub mod xtypes;

// Generated types from build.rs (IDL -> Rust codegen, output in OUT_DIR)
#[rustfmt::skip]
#[allow(dead_code, clippy::all, unused)]
/// Generated types from IDL files (build.rs codegen).
pub mod generated {
    include!(concat!(env!("OUT_DIR"), "/generated/mod.rs"));
}

pub use admin::{AdminApi, EndpointsSnapshot, MeshSnapshot, MetricsSnapshot, TopicsSnapshot};
pub use dds::{
    ContentFilteredTopic, DataReader, DataWriter, DiscoveredEndpointInfo, DiscoveredEndpointKind,
    DiscoveredTopicInfo, Error, FieldValue, FilterError, GuardCondition, HasStatusCondition,
    Participant, QoS, RawDataReader, RawDataWriter, RawRelayWriter, RawSample, Result, Topic,
    TransportMode, TypeConsistencyEnforcement, WaitSet, ADOPT_WAIT_ENV, PLACEHOLDER_TYPE_NAME,
};

// Re-export transport configs for ParticipantBuilder
pub use transport::lowbw::LowBwConfig;
pub use transport::shm::ShmPolicy;
pub use transport::tcp::{TcpConfig, TcpRole, TransportPreference};
pub use transport::{MulticastMode, TransportOptions};

// Re-export Discovery Server config
pub use discovery_server::DiscoveryServerConfig;

// Re-export QUIC config when feature is enabled
#[cfg(feature = "quic")]
pub use transport::quic::QuicConfig;

// Re-export Security config when feature is enabled
#[cfg(feature = "security")]
pub use security::{SecurityConfig, SecurityConfigBuilder};

/// Content filter expression parser and evaluator.
pub use dds::filter;

// Re-export K8s discovery types (feature-gated)
#[cfg(feature = "k8s")]
pub use discovery::k8s::{K8sDiscovery, K8sDiscoveryConfig};

// Re-export Cloud discovery types (feature-gated)
#[cfg(feature = "cloud-discovery")]
pub use discovery::cloud::{
    AwsCloudMap, AzureDiscovery, CloudDiscovery, ConsulDiscovery, ConsulHealthPolicy, ConsulOptions,
};

// Re-export CDR2 traits for hdds_gen integration
pub use core::ser::{Cdr2Decode, Cdr2Encode, CdrError};

// Re-export DDS trait and derive macro
pub use dds::CdrVersion;
pub use dds::DDS as DdsTrait; // Trait (for type bounds)
/// Derive macro for the [`DdsTrait`] contract; see `hdds_codegen::DDS`.
///
/// `#[dds(final)]` and `#[dds(appendable)]` choose the extensibility; any
/// other `#[dds(...)]` is refused at compile time:
///
/// ```compile_fail
/// #[derive(hdds::DDS)]
/// #[dds(mutable)]
/// struct M { a: i32 }
/// ```
///
/// ```compile_fail
/// #[derive(hdds::DDS)]
/// #[dds(finale)]
/// struct M { a: i32 }
/// ```
///
/// ```compile_fail
/// #[derive(hdds::DDS)]
/// struct M { #[dds(final)] a: i32 }
/// ```
///
/// ```
/// #[derive(hdds::DDS)]
/// #[dds(final)]
/// struct F { a: i32 }
/// ```
pub use hdds_codegen::DDS;

/// Deprecated: Use `dds` module instead. Kept for backward compatibility.
#[deprecated(since = "0.6.0", note = "Use `dds` module instead")]
pub mod api {
    pub use crate::dds::*;
}

/// Telemetry collection, export, and live capture.
pub mod telemetry;

/// HDDS version string.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Source commit this library was built from (short hash), `"unknown"` when
/// the build had no git checkout and no `HDDS_BUILD_GIT_SHA` in its
/// environment. Lets any shipped artifact be tied back to its source.
pub const BUILD_GIT_SHA: &str = env!("HDDS_BUILD_GIT_SHA");

#[cfg(test)]
mod tests {
    use crate::dds::DDS;
    use crate::xtypes::{CompleteStructMember, CompleteStructType, StructTypeFlag, TypeIdentifier};

    // ===== Test Helpers for TypeObject Verification =====

    /// Verify Temperature struct header properties
    ///
    /// # Assertions
    /// - Struct flags: IS_FINAL
    /// - Type name: "Temperature"
    /// - No base type (no inheritance)
    /// - Member count: 2
    fn verify_struct_header(struct_type: &CompleteStructType) {
        // Verify struct flags (IS_FINAL expected)
        assert_eq!(
            struct_type.struct_flags,
            StructTypeFlag::IS_FINAL,
            "Expected IS_FINAL flag"
        );

        // Verify struct name (allow both "Temperature" and "TemperatureData::Temperature")
        // A code generator may include the module namespace depending on IDL structure
        assert!(
            struct_type.header.detail.type_name.ends_with("Temperature"),
            "Expected type name to end with 'Temperature', got: {}",
            struct_type.header.detail.type_name
        );

        // Verify no inheritance
        assert!(
            struct_type.header.base_type.is_none(),
            "Expected no base type (no inheritance)"
        );

        // Verify 2 members (value, timestamp)
        assert_eq!(
            struct_type.member_seq.len(),
            2,
            "Temperature should have 2 members"
        );
    }

    /// Verify Temperature struct members (value: f32, timestamp: i32)
    ///
    /// # Assertions
    /// - Member 0: value, TK_FLOAT32
    /// - Member 1: timestamp, TK_INT32 (IDL 'long' maps to i32)
    fn verify_temperature_members(members: &[CompleteStructMember]) {
        // Verify first member: value (f32)
        let value_member = &members[0];
        assert_eq!(value_member.common.member_id, 0, "Expected member_id 0");
        assert_eq!(
            value_member.detail.name, "value",
            "Expected field name 'value'"
        );
        assert_eq!(
            value_member.common.member_type_id,
            TypeIdentifier::TK_FLOAT32,
            "Expected TK_FLOAT32 for f32"
        );

        // Verify second member: timestamp (i32 - IDL 'long' type)
        let timestamp_member = &members[1];
        assert_eq!(timestamp_member.common.member_id, 1, "Expected member_id 1");
        assert_eq!(
            timestamp_member.detail.name, "timestamp",
            "Expected field name 'timestamp'"
        );
        assert_eq!(
            timestamp_member.common.member_type_id,
            TypeIdentifier::TK_INT32,
            "Expected TK_INT32 for i32 (IDL 'long')"
        );
    }

    /// Test that proc-macro generates get_type_object() for Temperature (Phase 8b)
    #[test]
    fn test_temperature_type_object_generation() {
        use crate::generated::temperature::Temperature;
        use crate::xtypes::CompleteTypeObject;

        // Get type object
        let type_object = Temperature::get_type_object();
        assert!(
            type_object.is_some(),
            "Temperature should provide TypeObject"
        );
        let type_object = type_object.expect("Temperature TypeObject (verified .is_some() above)");

        // Verify it's a Struct variant
        match type_object {
            CompleteTypeObject::Struct(struct_type) => {
                verify_struct_header(&struct_type);
                verify_temperature_members(&struct_type.member_seq);
            }
            other => {
                assert!(
                    matches!(other, CompleteTypeObject::Struct(_)),
                    "Expected CompleteTypeObject::Struct, got {:?}",
                    other
                );
            }
        }
    }
}
