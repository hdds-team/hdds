// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! PRESENTATION QoS policy (DDS v1.4 Sec.2.2.3.12).
//!
//! Controls how data is presented to the DataReader, including access scope,
//! coherent changes, and ordered access.

mod access_scope;
mod policy;

pub use access_scope::PresentationAccessScope;
pub use policy::Presentation;

#[cfg(test)]
mod tests;
