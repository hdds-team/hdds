// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Runtime type system for dynamic serialization and XTypes support.
//!
//! Provides `TypeDescriptor` for field layout metadata, `TypeCache` for
//! caching discovered types, and `Distro` for type distribution strategy.

pub mod cache;
pub mod descriptor;
pub mod distro;
pub mod handle;

pub use cache::{LookupStats, TypeCache};
pub use descriptor::{FieldLayout, FieldType, PrimitiveKind, TypeDescriptor};
pub use distro::Distro;
pub use handle::{TypeObjectHandle, ROS_HASH_SIZE};

// TypeRegistry removed in v0.3.0 cleanup.
// v0.3.0 uses static dispatch via generics (T::type_descriptor()).
// Dynamic type registration deferred to future if needed.
