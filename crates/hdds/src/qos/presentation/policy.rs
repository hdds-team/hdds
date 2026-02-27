// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

use super::PresentationAccessScope;

/// PRESENTATION QoS policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Presentation {
    /// Access scope (INSTANCE, TOPIC, or GROUP).
    pub access_scope: PresentationAccessScope,
    /// Whether changes are presented coherently.
    pub coherent_access: bool,
    /// Whether samples are presented in order.
    pub ordered_access: bool,
}

impl Default for Presentation {
    fn default() -> Self {
        Self::instance()
    }
}

impl Presentation {
    #[must_use]
    pub fn instance() -> Self {
        Self {
            access_scope: PresentationAccessScope::Instance,
            coherent_access: false,
            ordered_access: false,
        }
    }

    #[must_use]
    pub fn topic_coherent() -> Self {
        Self {
            access_scope: PresentationAccessScope::Topic,
            coherent_access: true,
            ordered_access: false,
        }
    }

    #[must_use]
    pub fn topic_ordered() -> Self {
        Self {
            access_scope: PresentationAccessScope::Topic,
            coherent_access: false,
            ordered_access: true,
        }
    }

    #[must_use]
    pub fn group_coherent() -> Self {
        Self {
            access_scope: PresentationAccessScope::Group,
            coherent_access: true,
            ordered_access: false,
        }
    }

    #[must_use]
    pub fn group_coherent_ordered() -> Self {
        Self {
            access_scope: PresentationAccessScope::Group,
            coherent_access: true,
            ordered_access: true,
        }
    }

    #[must_use]
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

    #[must_use]
    pub fn is_compatible_with(&self, requested: &Presentation) -> bool {
        if self.access_scope < requested.access_scope {
            return false;
        }

        if requested.coherent_access && !self.coherent_access {
            return false;
        }

        if requested.ordered_access && !self.ordered_access {
            return false;
        }

        true
    }

    #[must_use]
    pub fn is_instance_scope(&self) -> bool {
        self.access_scope == PresentationAccessScope::Instance
    }

    #[must_use]
    pub fn is_topic_scope(&self) -> bool {
        self.access_scope == PresentationAccessScope::Topic
    }

    #[must_use]
    pub fn is_group_scope(&self) -> bool {
        self.access_scope == PresentationAccessScope::Group
    }
}
