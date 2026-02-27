// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! ENTITY_FACTORY QoS policy (DDS v1.4 Sec.2.2.3.5)
//!
//! Controls whether entities (DataReader, DataWriter, Topic, etc.) are
//! automatically enabled when they are created.
//!
//! # QoS Compatibility (Request vs Offered)
//!
//! **Rule:** ENTITY_FACTORY is not part of RxO compatibility checking
//!
//! This policy controls entity lifecycle behavior and does not affect
//! compatibility between readers and writers.
//!
//! # Policy Semantics
//!
//! - **autoenable_created_entities = true** (default): Entities are automatically
//!   enabled when created. They can immediately send/receive data.
//! - **autoenable_created_entities = false**: Entities are created in a disabled
//!   state and must be explicitly enabled via `entity.enable()`.
//!
//! # Use Cases
//!
//! - **Auto-enable (default)**: Simplifies application code - entities are ready
//!   immediately after creation
//! - **Manual enable**: Allows batch configuration of multiple entities before
//!   enabling them atomically, useful for:
//!   - Configuring multiple related entities before starting discovery
//!   - Testing scenarios where controlled activation is needed
//!   - Performance optimization (batch enable reduces discovery overhead)
//!
//! # Examples
//!
//! ```no_run
//! use hdds::qos::entity_factory::EntityFactory;
//!
//! // Default: auto-enable entities
//! let factory = EntityFactory::auto_enable();
//! assert!(factory.autoenable_created_entities);
//!
//! // Manual enable: entities created disabled, require explicit enable()
//! let factory = EntityFactory::manual_enable();
//! assert!(!factory.autoenable_created_entities);
//! ```

/// ENTITY_FACTORY QoS policy (DDS v1.4 Sec.2.2.3.5)
///
/// Controls whether entities are automatically enabled upon creation.
///
/// Default: auto-enable (true).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EntityFactory {
    /// Whether to automatically enable entities when created
    pub autoenable_created_entities: bool,
}

impl Default for EntityFactory {
    /// Default: auto-enable entities
    fn default() -> Self {
        Self::auto_enable()
    }
}

impl EntityFactory {
    /// Create ENTITY_FACTORY with custom auto-enable setting
    ///
    /// # Arguments
    ///
    /// * `autoenable` - Whether to automatically enable entities
    ///
    /// # Examples
    ///
    /// ```
    /// use hdds::qos::entity_factory::EntityFactory;
    ///
    /// let factory = EntityFactory::new(true);
    /// assert!(factory.autoenable_created_entities);
    /// ```
    pub fn new(autoenable: bool) -> Self {
        Self {
            autoenable_created_entities: autoenable,
        }
    }

    /// Create ENTITY_FACTORY with auto-enable (default)
    ///
    /// Entities are automatically enabled when created.
    ///
    /// # Examples
    ///
    /// ```
    /// use hdds::qos::entity_factory::EntityFactory;
    ///
    /// let factory = EntityFactory::auto_enable();
    /// assert!(factory.autoenable_created_entities);
    /// ```
    pub fn auto_enable() -> Self {
        Self {
            autoenable_created_entities: true,
        }
    }

    /// Create ENTITY_FACTORY with manual enable
    ///
    /// Entities are created disabled and must be explicitly enabled.
    ///
    /// # Examples
    ///
    /// ```
    /// use hdds::qos::entity_factory::EntityFactory;
    ///
    /// let factory = EntityFactory::manual_enable();
    /// assert!(!factory.autoenable_created_entities);
    /// ```
    pub fn manual_enable() -> Self {
        Self {
            autoenable_created_entities: false,
        }
    }

    /// Check if auto-enable is enabled
    pub fn is_auto_enable(&self) -> bool {
        self.autoenable_created_entities
    }

    /// Check if manual enable is required
    pub fn is_manual_enable(&self) -> bool {
        !self.autoenable_created_entities
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // Basic functionality tests
    // ========================================================================

    #[test]
    fn test_entity_factory_default() {
        let factory = EntityFactory::default();
        assert!(factory.autoenable_created_entities);
        assert!(factory.is_auto_enable());
        assert!(!factory.is_manual_enable());
    }

    #[test]
    fn test_entity_factory_auto_enable() {
        let factory = EntityFactory::auto_enable();
        assert!(factory.autoenable_created_entities);
        assert!(factory.is_auto_enable());
    }

    #[test]
    fn test_entity_factory_manual_enable() {
        let factory = EntityFactory::manual_enable();
        assert!(!factory.autoenable_created_entities);
        assert!(!factory.is_auto_enable());
        assert!(factory.is_manual_enable());
    }

    #[test]
    fn test_entity_factory_new_true() {
        let factory = EntityFactory::new(true);
        assert!(factory.autoenable_created_entities);
    }

    #[test]
    fn test_entity_factory_new_false() {
        let factory = EntityFactory::new(false);
        assert!(!factory.autoenable_created_entities);
    }

    #[test]
    fn test_entity_factory_clone() {
        let factory1 = EntityFactory::manual_enable();
        let factory2 = factory1; // Copy, not clone (EntityFactory is Copy)
        assert_eq!(factory1, factory2);
    }

    #[test]
    fn test_entity_factory_copy() {
        let factory1 = EntityFactory::auto_enable();
        let factory2 = factory1;
        assert_eq!(factory1, factory2);
    }

    #[test]
    fn test_entity_factory_equality() {
        let factory1 = EntityFactory::auto_enable();
        let factory2 = EntityFactory::auto_enable();
        let factory3 = EntityFactory::manual_enable();

        assert_eq!(factory1, factory2);
        assert_ne!(factory1, factory3);
    }

    #[test]
    fn test_entity_factory_debug() {
        let factory = EntityFactory::auto_enable();
        let debug_str = format!("{:?}", factory);
        assert!(debug_str.contains("EntityFactory"));
        assert!(debug_str.contains("autoenable_created_entities"));
    }

    // ========================================================================
    // Use case tests
    // ========================================================================

    #[test]
    fn test_use_case_default_simple_apps() {
        // Simple applications: auto-enable for ease of use
        let factory = EntityFactory::default();
        assert!(factory.is_auto_enable());
    }

    #[test]
    fn test_use_case_batch_configuration() {
        // Batch configuration: disable auto-enable to configure multiple entities
        let factory = EntityFactory::manual_enable();
        assert!(factory.is_manual_enable());

        // Application would:
        // 1. Create multiple entities (disabled)
        // 2. Configure QoS for each
        // 3. Enable all at once
    }

    #[test]
    fn test_use_case_testing_controlled_activation() {
        // Testing: manual enable for controlled activation
        let factory = EntityFactory::manual_enable();
        assert!(!factory.autoenable_created_entities);

        // Test framework would:
        // 1. Create entities in disabled state
        // 2. Set up test conditions
        // 3. Enable entities to start test
    }

    #[test]
    fn test_use_case_performance_optimization() {
        // Performance: batch enable to reduce discovery overhead
        let factory = EntityFactory::manual_enable();
        assert!(factory.is_manual_enable());

        // Application would:
        // 1. Create N entities (disabled, no discovery)
        // 2. Configure all entities
        // 3. Enable all at once (single discovery burst)
    }

    #[test]
    fn test_use_case_atomic_activation() {
        // Atomic activation: ensure all related entities start together
        let factory = EntityFactory::manual_enable();
        assert!(!factory.autoenable_created_entities);

        // Example: Robot controller
        // 1. Create sensor readers (disabled)
        // 2. Create actuator writers (disabled)
        // 3. Enable all at once (atomic start)
    }

    // ========================================================================
    // Edge cases
    // ========================================================================

    #[test]
    fn test_entity_factory_multiple_toggles() {
        let factory1 = EntityFactory::auto_enable();
        let factory2 = EntityFactory::manual_enable();
        let factory3 = EntityFactory::auto_enable();

        assert!(factory1.is_auto_enable());
        assert!(factory2.is_manual_enable());
        assert!(factory3.is_auto_enable());
    }

    #[test]
    fn test_entity_factory_from_bool() {
        let factory_true = EntityFactory::new(true);
        let factory_false = EntityFactory::new(false);

        assert_eq!(factory_true, EntityFactory::auto_enable());
        assert_eq!(factory_false, EntityFactory::manual_enable());
    }

    #[test]
    fn test_entity_factory_field_access() {
        let factory = EntityFactory::manual_enable();
        let autoenable = factory.autoenable_created_entities;
        assert!(!autoenable);
    }
}
