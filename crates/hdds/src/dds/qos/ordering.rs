// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Sample ordering policies.
//!
//! Defines how samples are ordered for delivery to readers.

/// Destination order policy kinds.
///
/// Uses `#[derive(Default)]` to keep clippy happy while retaining previous
/// behaviour.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum DestinationOrderKind {
    /// Order samples by reception timestamp (default, fastest).
    #[default]
    ByReceptionTimestamp = 0,
    /// Order samples by source timestamp (temporal consistency).
    BySourceTimestamp = 1,
}

/// Destination order policy wrapper.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DestinationOrder {
    /// Ordering criterion.
    pub kind: DestinationOrderKind,
}

impl DestinationOrder {
    /// Create BY_RECEPTION_TIMESTAMP policy (default).
    pub fn by_reception_timestamp() -> Self {
        Self {
            kind: DestinationOrderKind::ByReceptionTimestamp,
        }
    }

    /// Create BY_SOURCE_TIMESTAMP policy.
    pub fn by_source_timestamp() -> Self {
        Self {
            kind: DestinationOrderKind::BySourceTimestamp,
        }
    }

    /// Check if policy uses source timestamps.
    pub fn uses_source_timestamp(&self) -> bool {
        self.kind == DestinationOrderKind::BySourceTimestamp
    }

    /// Check if policy uses reception timestamps.
    pub fn uses_reception_timestamp(&self) -> bool {
        self.kind == DestinationOrderKind::ByReceptionTimestamp
    }
}

impl Default for DestinationOrder {
    fn default() -> Self {
        Self::by_reception_timestamp()
    }
}

/// Presentation access scope policy kinds.
///
/// Uses `#[derive(Default)]` to express default variant.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum PresentationAccessScope {
    /// Instance-level access (default, fastest).
    #[default]
    Instance = 0,
    /// Topic-level access (coherent snapshots).
    Topic = 1,
    /// Group-level access (transactional updates).
    Group = 2,
}

/// Presentation of coherent/ordered changes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Presentation {
    /// Access scope (INSTANCE, TOPIC, or GROUP).
    pub access_scope: PresentationAccessScope,
    /// Whether changes are presented coherently (atomically).
    pub coherent_access: bool,
    /// Whether samples are presented in order.
    pub ordered_access: bool,
}

impl Presentation {
    /// Create INSTANCE-level presentation (default).
    pub fn instance() -> Self {
        Self {
            access_scope: PresentationAccessScope::Instance,
            coherent_access: false,
            ordered_access: false,
        }
    }

    /// Create TOPIC-level presentation with coherent access.
    pub fn topic_coherent() -> Self {
        Self {
            access_scope: PresentationAccessScope::Topic,
            coherent_access: true,
            ordered_access: false,
        }
    }

    /// Create TOPIC-level presentation with ordered access.
    pub fn topic_ordered() -> Self {
        Self {
            access_scope: PresentationAccessScope::Topic,
            coherent_access: false,
            ordered_access: true,
        }
    }

    /// Create GROUP-level presentation with coherent access.
    pub fn group_coherent() -> Self {
        Self {
            access_scope: PresentationAccessScope::Group,
            coherent_access: true,
            ordered_access: false,
        }
    }

    /// Create GROUP-level presentation with coherent and ordered access.
    pub fn group_coherent_ordered() -> Self {
        Self {
            access_scope: PresentationAccessScope::Group,
            coherent_access: true,
            ordered_access: true,
        }
    }

    /// Create custom PRESENTATION policy.
    pub fn new(
        access_scope: PresentationAccessScope,
        coherent_access: bool,
        ordered_access: bool,
    ) -> Self {
        Self {
            access_scope,
            coherent_access,
            ordered_access,
        }
    }

    /// Check if policy uses INSTANCE scope.
    pub fn is_instance_scope(&self) -> bool {
        self.access_scope == PresentationAccessScope::Instance
    }

    /// Check if policy uses TOPIC scope.
    pub fn is_topic_scope(&self) -> bool {
        self.access_scope == PresentationAccessScope::Topic
    }

    /// Check if policy uses GROUP scope.
    pub fn is_group_scope(&self) -> bool {
        self.access_scope == PresentationAccessScope::Group
    }
}

impl Default for Presentation {
    fn default() -> Self {
        Self::instance()
    }
}
