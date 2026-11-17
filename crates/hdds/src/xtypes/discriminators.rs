// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Wire-level discriminator octets for the `TypeIdentifier` discriminated
//! union, per OMG DDS-XTypes v1.3 specification.
//!
//! Source citations refer to the IDL `union TypeIdentifier switch (octet)`
//! declared in sec. 7.3.4.4 of the formal-2020-02-04 release. The constants
//! reproduce verbatim the values in the IDL block at the end of that
//! section (`const octet EK_MINIMAL = 0xF1;` etc.).
//!
//! Wire-format only -- not to be confused with [`super::EquivalenceKind`]
//! which is an in-memory enum unrelated to the on-the-wire representation.
//!
//! Primitive kinds (TK_BOOLEAN..TK_CHAR16, 0x00..0x11) reuse the values
//! from [`super::TypeKind`] and are not redeclared here; per the spec,
//! when a `TypeIdentifier` carries a primitive type the discriminator
//! octet IS the `TypeKind` value with no additional payload.
//!
//! `TI_PLAIN_SEQUENCE_*`, `TI_PLAIN_ARRAY_*` and `TI_PLAIN_MAP_*` are
//! also declared below -- the corresponding `TypeIdentifier` variants
//! are supported so HDDS can decode the plain-collection
//! discriminators (0x80, 0x81, 0x90, 0x91, 0xA0, 0xA1) that peers
//! emit for `sequence`, fixed-size array, and `map` types (DDS-XTypes
//! 1.3 7.3.4.2).

#![allow(dead_code)]

/// `EK_MINIMAL` -- TypeIdentifier discriminator for hash-based
/// `MinimalTypeObject` reference (DDS-XTypes v1.3 sec. 7.3.4.4 IDL).
pub(crate) const EK_MINIMAL: u8 = 0xF1;

/// `EK_COMPLETE` -- TypeIdentifier discriminator for hash-based
/// `CompleteTypeObject` reference (DDS-XTypes v1.3 sec. 7.3.4.4 IDL).
pub(crate) const EK_COMPLETE: u8 = 0xF2;

/// `EK_BOTH` -- TypeIdentifier discriminator when the minimal and the
/// complete `TypeObject` produce the same hash (DDS-XTypes v1.3 sec. 7.3.4.4
/// IDL). Forward-compat marker; HDDS does not currently emit this value.
pub(crate) const EK_BOTH: u8 = 0xF3;

/// `TI_STRING8_SMALL` -- bounded `string<bound>` with `bound <= 255`
/// (DDS-XTypes v1.3 sec. 7.3.4.4 IDL).
pub(crate) const TI_STRING8_SMALL: u8 = 0x70;

/// `TI_STRING8_LARGE` -- bounded `string<bound>` with `bound > 255` or
/// unbounded (DDS-XTypes v1.3 sec. 7.3.4.4 IDL).
pub(crate) const TI_STRING8_LARGE: u8 = 0x71;

/// `TI_STRING16_SMALL` -- bounded `wstring<bound>` with `bound <= 255`
/// (DDS-XTypes v1.3 sec. 7.3.4.4 IDL).
pub(crate) const TI_STRING16_SMALL: u8 = 0x72;

/// `TI_STRING16_LARGE` -- bounded `wstring<bound>` with `bound > 255` or
/// unbounded (DDS-XTypes v1.3 sec. 7.3.4.4 IDL).
pub(crate) const TI_STRING16_LARGE: u8 = 0x73;

/// `TI_PLAIN_SEQUENCE_SMALL` -- plain `sequence<T, bound>` with
/// `bound <= 255` (DDS-XTypes v1.3 sec. 7.3.4.4 IDL).
pub(crate) const TI_PLAIN_SEQUENCE_SMALL: u8 = 0x80;

/// `TI_PLAIN_SEQUENCE_LARGE` -- plain `sequence<T, bound>` with
/// `bound > 255` or unbounded (DDS-XTypes v1.3 sec. 7.3.4.4 IDL).
pub(crate) const TI_PLAIN_SEQUENCE_LARGE: u8 = 0x81;

/// `TI_PLAIN_ARRAY_SMALL` -- plain `T[dim1][...][dimN]` with all bounds
/// `<= 255` (DDS-XTypes v1.3 sec. 7.3.4.4 IDL).
pub(crate) const TI_PLAIN_ARRAY_SMALL: u8 = 0x90;

/// `TI_PLAIN_ARRAY_LARGE` -- plain `T[dim1][...][dimN]` with any bound
/// `> 255` (DDS-XTypes v1.3 sec. 7.3.4.4 IDL).
pub(crate) const TI_PLAIN_ARRAY_LARGE: u8 = 0x91;

/// `TI_PLAIN_MAP_SMALL` -- plain `map<K, V, bound>` with `bound <= 255`
/// (DDS-XTypes v1.3 sec. 7.3.4.4 IDL).
pub(crate) const TI_PLAIN_MAP_SMALL: u8 = 0xA0;

/// `TI_PLAIN_MAP_LARGE` -- plain `map<K, V, bound>` with `bound > 255`
/// or unbounded (DDS-XTypes v1.3 sec. 7.3.4.4 IDL).
pub(crate) const TI_PLAIN_MAP_LARGE: u8 = 0xA1;

/// `TI_STRONGLY_CONNECTED_COMPONENT` -- TypeIdentifier discriminator for
/// recursive type cycles (DDS-XTypes v1.3 sec. 7.3.4.4 IDL + sec. 7.3.4.11).
pub(crate) const TI_STRONGLY_CONNECTED_COMPONENT: u8 = 0xB0;

#[cfg(test)]
mod tests {
    use super::*;

    /// Lock the wire-level discriminator constants against the OMG
    /// DDS-XTypes v1.3 sec. 7.3.4.4 IDL block. Any drift in these values
    /// would silently break cross-vendor `TypeIdentifier` matching, so
    /// the numeric assertions are the spec citation reified as a test.
    #[test]
    fn typeid_discriminators_match_xtypes_v1_3_spec() {
        assert_eq!(EK_MINIMAL, 0xF1);
        assert_eq!(EK_COMPLETE, 0xF2);
        assert_eq!(EK_BOTH, 0xF3);
        assert_eq!(TI_STRING8_SMALL, 0x70);
        assert_eq!(TI_STRING8_LARGE, 0x71);
        assert_eq!(TI_STRING16_SMALL, 0x72);
        assert_eq!(TI_STRING16_LARGE, 0x73);
        assert_eq!(TI_PLAIN_SEQUENCE_SMALL, 0x80);
        assert_eq!(TI_PLAIN_SEQUENCE_LARGE, 0x81);
        assert_eq!(TI_PLAIN_ARRAY_SMALL, 0x90);
        assert_eq!(TI_PLAIN_ARRAY_LARGE, 0x91);
        assert_eq!(TI_PLAIN_MAP_SMALL, 0xA0);
        assert_eq!(TI_PLAIN_MAP_LARGE, 0xA1);
        assert_eq!(TI_STRONGLY_CONNECTED_COMPONENT, 0xB0);
    }
}
