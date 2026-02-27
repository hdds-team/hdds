// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! CDR2 Serialization Tests - Minimal TypeObject Variants
//!
//! Tests mirror the `cdr2_complete_types` suite but target MinimalTypeObject
//! encoding paths.

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
