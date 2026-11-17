// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Test-only helpers (DDS domain allocation, UDP port reservation, fake HTTP
//! and DNS servers) shared between this crate's unit tests, its own
//! integration tests under `tests/`, and dependent crates' test suites
//! (currently `hdds-discovery-server`).
//!
//! Compiled only under `cfg(test)` (automatic for unit tests and for this
//! crate's own integration tests once the self dev-dependency below enables
//! the feature) or the `test-support` cargo feature, which defaults to off.
//! Neither path adds anything to a normal build's public API surface.

/// Deterministic reproduction of the intra-process coherent-set staging
/// race (widens the window between a coherent write's stamp and the stage
/// of its sample).
pub mod coherent_race;
/// Unique DDS domain allocation, arbitrated across every test process on
/// this machine. Use it instead of a hand-written domain constant.
pub mod domains;
/// In-process AWS Cloud Map endpoint (SigV4-verifying) over `fake_http`.
#[cfg(feature = "cloud-discovery")]
pub mod fake_aws;
/// In-process Azure token issuer + Table Storage REST endpoint.
pub mod fake_azure;
/// In-process Consul agent (register / health / KV / TTL checks).
#[cfg(feature = "cloud-discovery")]
pub mod fake_consul;
/// In-process DNS server (A / SRV) standing in for a DNS-SD nameserver.
pub mod fake_dns;
/// In-process HTTP/1.1 server standing in for a cloud registry.
pub mod fake_http;
/// Pins discovery-dependent tests onto the loopback interface, independent
/// of host routing (VPN/tunnel default routes, container bridges, multi-NIC
/// hosts). Wired into [`domains::try_unique_domain`]; see its module docs
/// for why a test author cannot forget this.
pub mod network;
/// UDP port reservation for tests that need to bind real sockets.
pub mod ports;
/// Thread lifetime hooks for tests of the participant teardown.
pub mod threads;
/// The DATA a writer puts on the wire, captured and taken apart.
pub mod wire;
