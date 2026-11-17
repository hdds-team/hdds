// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 naskel.com

//! `Locator` <-> (IPv4, port) conversion.
//!
//! `hdds-micro::rtps::Locator` stores addresses in IPv4-mapped IPv6 form
//! (`::ffff:a.b.c.d`) with `kind == KIND_UDPV4`. On the seL4 side we only
//! push IPv4 bytes through sDDF, so we need a cheap round-trip.

use hdds_micro::rtps::Locator;

/// Classification of a `Locator` for routing decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocatorKind {
    /// UDPv4 - payload carried as (ipv4[4], port).
    Udpv4,
    /// UDPv6 - not supported by this transport.
    Udpv6,
    /// Anything else (invalid, `KIND_INVALID`, experimental).
    Other,
}

impl LocatorKind {
    /// Classify a `Locator` by its `kind` field.
    pub const fn from_locator(loc: &Locator) -> Self {
        match loc.kind {
            Locator::KIND_UDPV4 => Self::Udpv4,
            Locator::KIND_UDPV6 => Self::Udpv6,
            _ => Self::Other,
        }
    }
}

/// Extract the IPv4 address + port from a UDPv4 `Locator`.
///
/// Returns `None` if the locator is not `KIND_UDPV4`. The IPv4 bytes are
/// read from the last 4 bytes of the 16-byte IPv4-mapped IPv6 address,
/// matching what `Locator::udpv4` writes.
pub const fn locator_to_ipv4(loc: &Locator) -> Option<([u8; 4], u16)> {
    if loc.kind != Locator::KIND_UDPV4 {
        return None;
    }
    let ip = [
        loc.address[12],
        loc.address[13],
        loc.address[14],
        loc.address[15],
    ];
    Some((ip, loc.port as u16))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_udpv4() {
        let src = Locator::udpv4([192, 168, 1, 20], 7400);
        let (ip, port) = locator_to_ipv4(&src).expect("udpv4");
        assert_eq!(ip, [192, 168, 1, 20]);
        assert_eq!(port, 7400);
        assert_eq!(LocatorKind::from_locator(&src), LocatorKind::Udpv4);

        let rebuilt = Locator::udpv4(ip, port);
        assert_eq!(rebuilt, src);
    }

    #[test]
    fn rejects_non_udpv4() {
        let invalid = Locator::INVALID;
        assert_eq!(locator_to_ipv4(&invalid), None);
        assert_eq!(LocatorKind::from_locator(&invalid), LocatorKind::Other);
    }
}
