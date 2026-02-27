// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

pub mod rust_backend;
pub mod type_hash;

pub use rust_backend::{emit_type_descriptor, FieldKind, FieldSpec, PrimitiveType, StructSpec};
pub use type_hash::compute_type_id;
