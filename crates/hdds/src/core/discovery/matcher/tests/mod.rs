// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

use super::*;

mod assignable_arrays;
#[cfg(feature = "xtypes-structural-assignability")]
mod assignable_bitmasks;
mod assignable_directionality;
mod assignable_final_appendable;
mod assignable_keys;
mod assignable_maps_and_scc;
mod assignable_mutable;
mod assignable_unions;
mod basics;
mod inert_string_identifiers;
mod must_reject_fence;
mod policy_enforcement;
mod structural_assignability_fix;
mod type_compat;
