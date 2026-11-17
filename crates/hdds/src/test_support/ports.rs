// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Shared UDP port reservation helper for tests.
//!
//! Reserving a free port for a UDP-based test is inherently racy: the only
//! portable way to ask the OS for one is to bind to port 0, read back the
//! OS-assigned port, then drop the socket and rebind that same port number
//! later (transports and `Participant` builders take a concrete port, not a
//! socket). Between the drop and the rebind, another test running in
//! parallel under `cargo test` can grab the same port -- this shows up as a
//! sporadic `AddrInUse` error. [`with_reserved_ports`] retries the whole
//! reserve-then-build cycle when that happens, instead of every call site
//! reimplementing its own retry loop.

use std::io;
use std::net::{Ipv4Addr, UdpSocket};

/// Reserve `N` distinct loopback UDP ports by binding ephemeral sockets and
/// reading back the OS-assigned port, then dropping the sockets. The ports
/// are free at the moment this call returns, but nothing stops another
/// process or thread from grabbing one before a caller rebinds it for real
/// -- prefer [`with_reserved_ports`] over calling this directly when the
/// caller is about to bind those ports.
pub fn reserve_udp_ports<const N: usize>() -> [u16; N] {
    let sockets: Vec<UdpSocket> = (0..N)
        .map(|_| UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind ephemeral UDP socket"))
        .collect();
    let mut ports = [0u16; N];
    for (slot, socket) in ports.iter_mut().zip(sockets.iter()) {
        *slot = socket
            .local_addr()
            .expect("read local addr of reserved socket")
            .port();
    }
    ports
}

/// Bind the UDP socket that stands in for a remote peer in a writer test:
/// the code under test sends to this socket's address and the test reads
/// the datagram back. Always loopback, on every platform, so the suite
/// stays hermetic. On Windows this only works because the transport binds
/// its user-data send socket to the unspecified address there: a socket
/// bound to the interface address cannot send to 127.0.0.1 under the
/// strong host model (WSAEADDRNOTAVAIL on Windows), see `UdpTransport` in `transport/udp.rs`.
pub fn bind_capture_socket() -> UdpSocket {
    UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .unwrap_or_else(|e| panic!("bind capture socket on 127.0.0.1:0: {e}"))
}

/// Errors a [`with_reserved_ports`] build closure can return that this
/// helper knows how to recognize as "just the port-collision race, try
/// again" versus "a real failure, stop and hand it back to the caller".
///
/// Implemented here for the two error types build closures in this crate
/// realistically return: a bare `std::io::Error` from constructing a
/// transport directly, and `crate::dds::Error` from the `Participant`
/// builder (which wraps bind failures in `Error::IoError`).
pub trait RetryableBuildError: std::fmt::Debug {
    /// True if this error is exactly the port-collision race
    /// `with_reserved_ports` exists to paper over.
    fn is_addr_in_use(&self) -> bool;
}

impl RetryableBuildError for io::Error {
    fn is_addr_in_use(&self) -> bool {
        self.kind() == io::ErrorKind::AddrInUse
    }
}

impl RetryableBuildError for crate::dds::Error {
    fn is_addr_in_use(&self) -> bool {
        matches!(self, crate::dds::Error::IoError(e) if e.kind() == io::ErrorKind::AddrInUse)
    }
}

/// Reserve `N` fresh ports and hand them to `build`, retrying the whole
/// reserve-and-build cycle up to `attempts` times when `build` fails with
/// `AddrInUse` (the reserve-drop-rebind window losing a race against a
/// concurrently running test). Any other error is returned immediately on
/// the attempt it occurs, unretried -- callers that want to treat that as a
/// hard failure can `.unwrap()`/`.expect()` the result; callers with a
/// softer policy (e.g. skip a test when no multicast-capable interface is
/// available in this environment) can match on it themselves.
///
/// Panics if `attempts == 0`.
pub fn with_reserved_ports<const N: usize, T, E>(
    attempts: usize,
    mut build: impl FnMut([u16; N]) -> Result<T, E>,
) -> Result<T, E>
where
    E: RetryableBuildError,
{
    assert!(attempts > 0, "with_reserved_ports: attempts must be >= 1");
    let mut last_err = None;
    for _ in 0..attempts {
        let ports = reserve_udp_ports::<N>();
        match build(ports) {
            Ok(value) => return Ok(value),
            Err(e) if e.is_addr_in_use() => last_err = Some(e),
            Err(e) => return Err(e),
        }
    }
    Err(last_err.expect("loop runs at least once since attempts > 0"))
}
