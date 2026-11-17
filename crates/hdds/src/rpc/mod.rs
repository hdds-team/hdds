// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! DDS-RPC: Request/Reply Pattern for DDS
//!
//! This module provides request/reply communication on top of DDS pub/sub.
//!
//! # What follows the specification, and what does not
//!
//! The request and reply headers are the OMG DDS-RPC 1.0 (formal/17-04-01)
//! Basic Service Mapping headers of clause 7.5.1.1.1, byte for byte: see
//! [`RequestHeader`], [`ReplyHeader`], [`SampleIdentity`] and
//! [`RemoteExceptionCode`]. The payload that follows the header is opaque to
//! this module: the application supplies the bytes of the `_Call` and
//! `_Return` unions itself, no typed IDL service binding is generated.
//!
//! Clause 7.5.1.1 says the Basic Service Mapping "maps interfaces to
//! data-types that can be used by DDS version 1.3 compliant implementations,
//! which may lack support for the [DDS-XTypes] specification". [`rpc_qos`]
//! therefore pins `DATA_REPRESENTATION` to XCDR1 (`data_representation_xcdr1`)
//! so the writer's wire encapsulation negotiates down to `PLAIN_CDR_LE`
//! (`0x0001`) instead of the plain-DDS-XTypes default `PLAIN_CDR2_LE`
//! (`0x0007`) a pre-XTypes peer cannot be assumed to parse; see
//! `canonical_encapsulation_kind` and `encap_kind_for_version` in
//! `dds::writer::builder` / `dds::cdr_negotiation`, which this module reuses
//! unchanged rather than special-casing RPC there. Only RPC writers and
//! readers request this: `data_representation` is empty (the crate-wide
//! default) everywhere else, so no other topic's wire bytes move.
//!
//! The topic names below are an HDDS default (the specification lets them be
//! chosen at run time, 7.4.2.3, and requires only that both ends agree);
//! [`ServiceClient::with_topic_names`] and [`ServiceServer::with_topic_names`]
//! let a caller point at a peer using the specification's own default
//! grammar (7.4.1, `<interface>_<service>_Request`/`_Reply`) or any other
//! convention. End-to-end interoperability with a foreign DDS-RPC
//! implementation (topic naming agreement, typed `_Call`/`_Return` unions)
//! has not been validated; see sdk/c/RPC.md for the C contract.
//!
//! # Scope: typed operation unions are not implemented
//!
//! DDS-RPC 1.0 clause 7.5.1.1.4/7.5.1.1.6 synthesizes, per interface, a
//! `_Call` union and a `_Return` union whose cases are the interface's
//! operations, discriminated by `HASH(operation_name)` (clause 7.5.1.1.2:
//! the first 4 bytes of `MD5(operation_name)` as a `long`). That is how a
//! single request/reply topic pair carries every operation of a
//! multi-method interface, and how a foreign Basic-Service-Mapping peer
//! decides which method a request is calling.
//!
//! This module does not generate or interpret that union. What exists:
//! * The header framing up to and including the payload boundary is exact
//!   (see above) -- a consumer can rely on where the header ends.
//! * The payload after the header is delivered and returned as opaque
//!   bytes, verbatim, both directions ([`RequestHandler::handle`],
//!   [`ServiceClient::call_raw`]).
//! * One [`ServiceServer`] dispatches every request on its topic pair to
//!   ONE handler; there is no operation-hash keyed routing to multiple
//!   handlers within a service.
//!
//! What does not exist and a consumer must not assume:
//! * No `HASH`/MD5 discriminator is computed, checked, or reserved space
//!   for by this module. An application implementing a multi-operation
//!   Basic-Service-Mapping interface must encode and decode that
//!   discriminator itself, inside the opaque payload, to match what a
//!   real DDS-RPC peer or an `hdds_gen`-generated service binding would
//!   put there -- this module does not help with or verify that.
//! * No IDL `interface`/operation code generation exists in `hdds_gen`
//!   for DDS-RPC; the `_Call`/`_Return` union types this clause requires
//!   are not something the toolchain can emit today.
//! * Because of the two points above, wire compatibility with a real
//!   foreign DDS-RPC Basic-Service-Mapping peer that expects the standard
//!   union framing has not been demonstrated and should not be assumed,
//!   even now that the header layout and the wire
//!   encapsulation are spec-correct.
//!
//! Implementing typed unions is out of scope here: it is an `hdds_gen`
//! (IDL code generation) feature, not a `crates/hdds` runtime change, and
//! is a materially larger effort than the two items above.
//!
//! # Changes from the 1.4 `rpc` API
//!
//! The 1.4 headers were self-consistent but did not match the specification;
//! making them match changed the public types:
//! - `RequestHeader::instance_id: SampleIdentity` became
//!   `instance_name: String` (the specification's `string<255> instanceName`)
//!   and `RequestHeader::with_instance` became `with_instance_name`.
//! - `RemoteExceptionCode` carries the six `RemoteExceptionCode_t` values
//!   with their wire numbers: `Ok`, `Unsupported`, `InvalidArgument`,
//!   `OutOfResources`, `UnknownOperation`, `UnknownException`. The former
//!   `UnsupportedService`, `UnsupportedMethod`, `ServiceUnavailable`,
//!   `Timeout`, `InternalError` and `Unknown` no longer exist, and `from_i32`
//!   became `from_wire`, which returns `None` for a value outside the
//!   enumeration.
//! - A server-side handler timeout or panic is reported to the client as
//!   `UnknownException`; `RpcError::Timeout` now only means the client's own
//!   deadline.
//! - `SampleIdentity::sequence_number` is still an `i64` in memory but is
//!   encoded as the RTPS `SequenceNumber_t` pair (`high`, then `low`).
//!
//! Wire compatibility with 1.4 HDDS peers is deliberately broken: the 1.4
//! bytes were not DDS-RPC, and a mixed 1.4 / 1.5 deployment must upgrade
//! both ends together.
//!
//! # Overview
//!
//! DDS-RPC allows building service-oriented architectures where:
//! - **Clients** send requests and wait for replies
//! - **Servers** receive requests, process them, and send replies
//! - Communication uses standard DDS topics with correlation
//!
//! # Example
//!
//! ```rust,ignore
//! // Full example requires async runtime and proper request handler implementation
//! use hdds::rpc::{ServiceClient, ServiceServer, RpcResult};
//! use hdds::Participant;
//!
//! // See examples/ directory for complete RPC examples
//! ```
//!
//! # Topic Naming
//!
//! For a service named "Calculator", the default (`ServiceClient::new` /
//! `ServiceServer::new`) is an HDDS convention, not the specification's:
//! - Request topic: `rq/Calculator`
//! - Reply topic: `rr/Calculator`
//!
//! Use `ServiceClient::with_topic_names` / `ServiceServer::with_topic_names`
//! to match a peer that expects the specification's own default (7.4.1,
//! `Calculator_Service_Request` / `Calculator_Service_Reply`) or any other
//! run-time name; DDS-RPC only requires both ends to agree (7.4.2).
//!
//! # Correlation
//!
//! Each request header carries the `SampleIdentity` (request writer GUID +
//! sequence number) of the request; the reply header carries it back as
//! `relatedRequestId`, which is how the client matches replies to requests
//! (explicit correlation, DDS-RPC 7.8.1).

mod client;
mod error;
mod registry;
mod server;
mod types;

pub use client::ServiceClient;
pub use error::{RpcError, RpcResult};
pub use registry::{list_services, ServiceInfo};
pub use server::{RequestHandler, ServiceServer};
pub use types::{RemoteExceptionCode, ReplyHeader, RequestHeader, SampleIdentity};

/// QoS profile optimized for RPC communication
///
/// - Reliable: ensures requests/replies are not lost
/// - KeepAll: maintains all samples in history (for correlation)
/// - Volatile: no persistence needed for transient RPC calls
/// - DATA_REPRESENTATION = XCDR1 only: per DDS-RPC 1.0 (formal/17-04-01)
///   clause 7.5.1.1, the Basic Service Mapping targets DDS 1.3
///   implementations that may lack DDS-XTypes support, so the writer must
///   not offer the XTypes-only XCDR2 representations. This is what makes
///   `canonical_encapsulation_kind`'s XCDR2 default degrade to
///   `PLAIN_CDR_LE` (`0x0001`) on the wire for RPC topics specifically
///   (see `dds::cdr_negotiation::encap_kind_for_version`); every other
///   writer in the crate still negotiates its encapsulation from an empty
///   `data_representation` (the HDDS-wide default), unaffected by this.
pub fn rpc_qos() -> crate::dds::QoS {
    use crate::dds::QoS;

    QoS::reliable()
        .keep_all()
        .volatile()
        .data_representation_xcdr1()
}

#[cfg(test)]
mod tests;
