// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 naskel.com

//! # hdds-micro-sel4
//!
//! seL4/Microkit transport adapter for `hdds-micro`.
//!
//! This crate is intentionally split in two layers:
//!
//! 1. [`PacketRing`] - a minimal ring-buffer abstraction over a link that
//!    carries raw UDP-ish datagrams (bytes + IPv4 address + port). It is
//!    deliberately decoupled from seL4 so the Transport impl can be
//!    exercised on the host with a mock.
//! 2. [`Sel4UdpTransport`] - an implementation of the `hdds-micro`
//!    [`Transport`] trait that sits on top of any `PacketRing`.
//!
//! Two `PacketRing` implementations are provided:
//!
//! - [`MockRing`] (always available): in-memory FIFO, used by host tests
//!   and as a loopback for two-transport pair tests.
//! - [`Sel4Ring`]: wraps sDDF net shared-memory queues (Ethernet/IPv4/
//!   UDP framing plus an ARP cache). It builds on the host too; only
//!   the Microkit notify call is gated on feature `microkit` (a no-op
//!   on host).
//!
//! The `MicroParticipant` / Writer / Reader stack from `hdds-micro` plugs
//! straight on top of [`Sel4UdpTransport`] - see `tests/host_pubsub.rs`.

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]
#![warn(missing_docs)]

mod drain;
mod locator;
mod ring;
mod sel4_ring;
mod transport;

#[cfg(feature = "std")]
mod mock_ring;

pub use locator::{locator_to_ipv4, LocatorKind};
pub use ring::{PacketRing, RingError};
pub use sel4_ring::{Sel4Ring, Sel4RingInit, LOCAL_PORT, NET_BUFFER_SIZE, SLOT_MTU};
pub use drain::drain_queue;
pub use transport::Sel4UdpTransport;

#[cfg(feature = "std")]
pub use mock_ring::{
    mock_pair, mock_pair_with_capacity, mock_pair_with_mtu, MockRing, MOCK_DEFAULT_MTU,
};
