// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! MCQ v0.1 -- Modele canonique DDS `QoS` (vendor neutral).

mod model;
mod validation;

pub use model::*;
pub use validation::ValidationError;

#[cfg(test)]
mod tests;
