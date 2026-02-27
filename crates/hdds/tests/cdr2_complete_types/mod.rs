// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! CDR2 Serialization Tests - Complete TypeObject Variants
//!
//! Tests for CompleteTypeObject encode/decode roundtrips (OMG DDS-XTypes v1.3).
//! All `.unwrap()` replaced with `.expect("...")` per CODING_RULES Sec.5.

use hdds::core::ser::traits::{Cdr2Decode, Cdr2Encode};
use hdds::xtypes::*;

mod alias;
mod annotations;
mod bitsets;
mod collections;
mod details;
mod enums;
mod hashes;
mod structs;
mod unions;
