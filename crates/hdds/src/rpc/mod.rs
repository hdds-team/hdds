// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! DDS-RPC: Request/Reply Pattern for DDS
//!
//! This module implements the OMG DDS-RPC specification (formal/17-04-01),
//! providing synchronous and asynchronous request/reply communication
//! on top of DDS pub/sub.
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
//! For a service named "Calculator":
//! - Request topic: `rq/Calculator`
//! - Reply topic: `rr/Calculator`
//!
//! # Correlation
//!
//! Each request includes a `SampleIdentity` (writer GUID + sequence number).
//! The reply includes `related_sample_identity` to correlate responses.

mod client;
mod error;
mod server;
mod types;

pub use client::ServiceClient;
pub use error::{RpcError, RpcResult};
pub use server::{RequestHandler, ServiceServer};
pub use types::{RemoteExceptionCode, ReplyHeader, RequestHeader, SampleIdentity};

/// QoS profile optimized for RPC communication
///
/// - Reliable: ensures requests/replies are not lost
/// - KeepAll: maintains all samples in history (for correlation)
/// - Volatile: no persistence needed for transient RPC calls
pub fn rpc_qos() -> crate::dds::QoS {
    use crate::dds::QoS;

    QoS::reliable().keep_all().volatile()
}

#[cfg(test)]
mod tests;
