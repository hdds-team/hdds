// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Entity factory QoS policy.
//!
//! Controls automatic enabling of created DDS entities.

/// Entity factory policy controlling auto-enable behaviour.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EntityFactory {
    /// Whether to automatically enable entities when created.
    pub autoenable_created_entities: bool,
}

impl EntityFactory {
    /// Create ENTITY_FACTORY with auto-enable (default).
    pub fn auto_enable() -> Self {
        Self {
            autoenable_created_entities: true,
        }
    }

    /// Create ENTITY_FACTORY with manual enable.
    pub fn manual_enable() -> Self {
        Self {
            autoenable_created_entities: false,
        }
    }

    /// Check if auto-enable is enabled.
    pub fn is_auto_enable(&self) -> bool {
        self.autoenable_created_entities
    }

    /// Check if manual enable is required.
    pub fn is_manual_enable(&self) -> bool {
        !self.autoenable_created_entities
    }
}

impl Default for EntityFactory {
    fn default() -> Self {
        Self::auto_enable()
    }
}
