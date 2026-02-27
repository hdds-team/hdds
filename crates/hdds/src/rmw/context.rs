// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! High-level context wrapper for the future `rmw_hdds` adapter.
//!
//! The ROS 2 middleware API expects an opaque context handle that owns the
//! participant, the primary waitset and the guard condition used to notify
//! clients about topology changes. This module provides a Rust abstraction
//! with those responsibilities so the C-facing layer only has to handle FFI
//! glue.

use super::graph::{EndpointQos, GraphCache, RMW_GID_STORAGE_SIZE};
use super::waitset::{ConditionHandle, ConditionKey, RmwWaitSet};
#[cfg(feature = "xtypes")]
use crate::core::types::TypeObjectHandle;
use crate::core::types::ROS_HASH_SIZE;
use crate::dds::{
    DataReader, GuardCondition, Participant, ParticipantBuilder, Result as ApiResult,
    StatusCondition, TransportMode, DDS,
};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

/// rmw context - owns the participant and a waitset with the graph guard
/// already attached.
pub struct RmwContext {
    participant: Arc<Participant>,
    waitset: RmwWaitSet,
    graph_guard_handle: ConditionHandle,
    graph_cache: Arc<GraphCache>,
}

impl RmwContext {
    /// Create a context using the supplied participant builder.
    pub fn from_builder(builder: ParticipantBuilder) -> ApiResult<Self> {
        let participant = builder.build()?;
        Self::from_participant(participant)
    }

    /// Wrap an existing participant inside an RMW context.
    pub fn from_participant(participant: Arc<Participant>) -> ApiResult<Self> {
        let waitset = RmwWaitSet::new();
        let graph_guard_handle = waitset.attach_participant(&participant)?;
        let graph_cache = Arc::new(GraphCache::new());

        Ok(Self {
            participant,
            waitset,
            graph_guard_handle,
            graph_cache,
        })
    }

    /// Convenience helper that builds a participant with the default settings.
    ///
    /// Transport selection (checked in order):
    /// 1. `HDDS_TRANSPORT=intra` - force intra-process only (no network)
    /// 2. `HDDS_TRANSPORT=udp`   - force UDP multicast (fail if unavailable)
    /// 3. Default: try UDP multicast, fall back to intra-process on failure
    ///
    /// When using UDP, each process gets a unique participant ID (0, 1, 2...)
    /// which maps to different RTPS unicast ports.
    pub fn create(name: &str) -> ApiResult<Self> {
        let transport_mode = std::env::var("HDDS_TRANSPORT").unwrap_or_default();

        match transport_mode.as_str() {
            "intra" => {
                log::info!("[rmw] HDDS_TRANSPORT=intra: using intra-process only");
                Self::from_builder(Participant::builder(name))
            }
            "udp" => {
                log::info!("[rmw] HDDS_TRANSPORT=udp: forcing UDP multicast");
                let builder = Participant::builder(name)
                    .domain_id(0)
                    .with_transport(TransportMode::UdpMulticast);
                Self::from_builder(builder)
            }
            _ => {
                // Default: try UDP, fall back to intra-process
                let builder = Participant::builder(name)
                    .domain_id(0)
                    .with_transport(TransportMode::UdpMulticast);
                match Self::from_builder(builder) {
                    Ok(ctx) => Ok(ctx),
                    Err(err) => {
                        log::warn!(
                            "[rmw] UDP transport failed for '{}', falling back to intra-process: {:?}",
                            name,
                            err
                        );
                        Self::from_builder(Participant::builder(name))
                    }
                }
            }
        }
    }

    /// Access the underlying participant (shared ownership).
    #[must_use]
    pub fn participant(&self) -> Arc<Participant> {
        Arc::clone(&self.participant)
    }

    /// Access the local graph cache.
    #[must_use]
    pub fn graph_cache(&self) -> Arc<GraphCache> {
        Arc::clone(&self.graph_cache)
    }

    #[must_use]
    pub fn user_unicast_locators(&self) -> Vec<SocketAddr> {
        let Some(transport) = self.participant.transport() else {
            return Vec::new();
        };
        let Some(port_mapping) = self.participant.port_mapping() else {
            return Vec::new();
        };

        transport.get_user_unicast_locators(port_mapping.user_unicast)
    }

    #[cfg(feature = "xtypes")]
    pub fn register_topic_type(&self, topic: &str, handle: Arc<TypeObjectHandle>) {
        self.participant
            .register_topic_type(topic, Arc::clone(&handle));
        if self.graph_cache.register_topic_type(topic, handle) {
            self.graph_guard_condition().set_trigger_value(true);
        }
    }

    pub fn register_writer(&self, topic: &str) {
        if self.graph_cache.register_writer(topic) {
            self.graph_guard_condition().set_trigger_value(true);
        }
    }

    pub fn unregister_writer(&self, topic: &str) {
        if self.graph_cache.unregister_writer(topic) {
            self.graph_guard_condition().set_trigger_value(true);
        }
    }

    pub fn register_reader(&self, topic: &str) {
        if self.graph_cache.register_reader(topic) {
            self.graph_guard_condition().set_trigger_value(true);
        }
    }

    pub fn unregister_reader(&self, topic: &str) {
        if self.graph_cache.unregister_reader(topic) {
            self.graph_guard_condition().set_trigger_value(true);
        }
    }

    pub fn register_node(&self, name: &str, namespace_: &str) {
        if self.graph_cache.register_node(name, namespace_) {
            self.graph_guard_condition().set_trigger_value(true);
        }
    }

    pub fn register_node_with_enclave(&self, name: &str, namespace_: &str, enclave: &str) {
        if self
            .graph_cache
            .register_node_with_enclave(name, namespace_, enclave)
        {
            self.graph_guard_condition().set_trigger_value(true);
        }
    }

    pub fn unregister_node(&self, name: &str, namespace_: &str) {
        if self.graph_cache.unregister_node(name, namespace_) {
            self.graph_guard_condition().set_trigger_value(true);
        }
    }

    #[allow(clippy::too_many_arguments)] // ROS2 rmw API requirements
    pub fn register_publisher_endpoint(
        &self,
        name: &str,
        namespace_: &str,
        topic: &str,
        type_name: &str,
        type_hash: &[u8; ROS_HASH_SIZE],
        gid: &[u8; RMW_GID_STORAGE_SIZE],
        qos: EndpointQos,
    ) {
        if self
            .graph_cache
            .register_publisher_endpoint(name, namespace_, topic, type_name, type_hash, gid, qos)
        {
            self.graph_guard_condition().set_trigger_value(true);
        }
    }

    pub fn unregister_publisher_endpoint(
        &self,
        name: &str,
        namespace_: &str,
        topic: &str,
        gid: &[u8; RMW_GID_STORAGE_SIZE],
    ) {
        if self
            .graph_cache
            .unregister_publisher_endpoint(name, namespace_, topic, gid)
        {
            self.graph_guard_condition().set_trigger_value(true);
        }
    }

    #[allow(clippy::too_many_arguments)] // ROS2 rmw API requirements
    pub fn register_subscription_endpoint(
        &self,
        name: &str,
        namespace_: &str,
        topic: &str,
        type_name: &str,
        type_hash: &[u8; ROS_HASH_SIZE],
        gid: &[u8; RMW_GID_STORAGE_SIZE],
        qos: EndpointQos,
    ) {
        if self
            .graph_cache
            .register_subscription_endpoint(name, namespace_, topic, type_name, type_hash, gid, qos)
        {
            self.graph_guard_condition().set_trigger_value(true);
        }
    }

    pub fn unregister_subscription_endpoint(
        &self,
        name: &str,
        namespace_: &str,
        topic: &str,
        gid: &[u8; RMW_GID_STORAGE_SIZE],
    ) {
        if self
            .graph_cache
            .unregister_subscription_endpoint(name, namespace_, topic, gid)
        {
            self.graph_guard_condition().set_trigger_value(true);
        }
    }

    /// Access the waitset (graph guard already attached).
    #[must_use]
    pub fn waitset(&self) -> &RmwWaitSet {
        &self.waitset
    }

    /// Key associated with the participant graph guard.
    #[must_use]
    pub fn graph_guard_key(&self) -> ConditionKey {
        self.graph_guard_handle.key()
    }

    /// Retrieve the participant graph guard condition.
    #[must_use]
    pub fn graph_guard_condition(&self) -> Arc<GuardCondition> {
        self.participant.graph_guard()
    }

    /// Delegate to the internal waitset to attach a reader status condition.
    pub fn attach_reader<T: DDS>(&self, reader: &DataReader<T>) -> ApiResult<ConditionHandle> {
        self.waitset.attach_reader(reader)
    }

    /// Delegate to the internal waitset to attach an additional guard.
    pub fn attach_guard(&self, guard: &Arc<GuardCondition>) -> ApiResult<ConditionHandle> {
        self.waitset.attach_guard(guard)
    }

    /// Delegate to the internal waitset to attach an existing status condition.
    pub fn attach_status_condition(
        &self,
        status: Arc<StatusCondition>,
    ) -> ApiResult<ConditionHandle> {
        self.waitset.attach_status(status)
    }

    /// Wait until at least one registered condition triggers.
    pub fn wait(&self, timeout: Option<Duration>) -> ApiResult<Vec<ConditionKey>> {
        self.waitset.wait(timeout)
    }
}

#[cfg(test)]
mod tests;
