// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! XTypes integration for Participant.
//!
//! Provides type registration and caching for ROS 2 type support
//! introspection and XTypes TypeObject handling.

use super::runtime::Participant;
use crate::core::types::{Distro, TypeObjectHandle};
use crate::xtypes::{rosidl_message_type_support_t, RosidlError};
use std::sync::Arc;

impl Participant {
    /// Register a ROS 2 type support with the participant's type cache.
    ///
    /// # Safety
    /// `type_support` must point to a valid `rosidl_message_type_support_t`.
    pub unsafe fn register_type_from_type_support(
        &self,
        distro: Distro,
        type_support: *const rosidl_message_type_support_t,
    ) -> std::result::Result<Arc<TypeObjectHandle>, RosidlError> {
        let handle = self
            .type_cache
            .get_or_build_from_type_support(distro, type_support)?;

        Ok(self.cache_registered_type(&handle))
    }

    /// Register a ROS 2 type support using the participant default ROS distribution.
    ///
    /// # Safety
    /// `type_support` must point to a valid ROS 2 type support structure and remain alive
    /// for the duration of the registration call.
    pub unsafe fn register_type_from_type_support_default(
        &self,
        type_support: *const rosidl_message_type_support_t,
    ) -> std::result::Result<Arc<TypeObjectHandle>, RosidlError> {
        self.register_type_from_type_support(self.distro, type_support)
    }

    pub(super) fn cache_registered_type(
        &self,
        handle: &Arc<TypeObjectHandle>,
    ) -> Arc<TypeObjectHandle> {
        let mut map = self.registered_types.write();
        map.insert(handle.fqn.to_string(), Arc::clone(handle));
        if let Some(name) = handle.type_name() {
            map.insert(name.to_string(), Arc::clone(handle));
        }
        Arc::clone(handle)
    }

    pub(super) fn registered_type(&self, name: &str) -> Option<Arc<TypeObjectHandle>> {
        self.registered_types.read().get(name).cloned()
    }

    pub(crate) fn register_topic_type(&self, topic: &str, handle: Arc<TypeObjectHandle>) {
        let mut map = self.topic_types.write();
        map.insert(topic.to_string(), handle);
    }

    pub(crate) fn topic_type_handle(&self, topic: &str) -> Option<Arc<TypeObjectHandle>> {
        self.topic_types.read().get(topic).cloned()
    }
}
