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
use crate::transport::{MulticastMode, TransportOptions};
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

/// Environment variable naming the unicast SPDP peers, and its documented
/// alias.
///
/// `crates/rmw-hdds/src/env_config.rs` has always documented and parsed BOTH
/// spellings, and applied neither: the parsed value was printed once and
/// dropped. Honouring only the first one would have closed the defect for one
/// of the two documented names and left a node started with the other
/// discovering nobody.
const ENV_DISCOVERY_PEERS: &str = "HDDS_DISCOVERY_PEERS";
const ENV_INITIAL_PEERS: &str = "HDDS_INITIAL_PEERS";

/// Environment variable that turns multicast off for a ROS 2 node.
///
/// The name is `crates/rmw-hdds/src/env_config.rs`'s own
/// `ENV_MULTICAST_DISABLE`, which that file has documented and parsed since it
/// was written and never applied to anything.
const ENV_MULTICAST: &str = "HDDS_MULTICAST_DISABLE";

/// The comma-separated peer list an rmw participant should seed itself with,
/// or `None` when neither spelling is set (or both are empty).
///
/// Format: comma-separated `host:port` metatraffic-unicast addresses, e.g.
/// `HDDS_DISCOVERY_PEERS=172.21.0.2:17160,172.21.0.3:17160`. A peer that does
/// not parse is logged and skipped by `add_static_peer`, never fatal.
fn rmw_static_peers_from_env() -> Option<String> {
    resolve_static_peers(
        std::env::var(ENV_DISCOVERY_PEERS).ok().as_deref(),
        std::env::var(ENV_INITIAL_PEERS).ok().as_deref(),
    )
}

/// The pure half of [`rmw_static_peers_from_env`], so the precedence and the
/// alias can be tested without a `set_var` racing every other test in the
/// binary.
fn resolve_static_peers(discovery: Option<&str>, initial: Option<&str>) -> Option<String> {
    let raw = discovery.or(initial)?;
    if raw.split(',').all(|peer| peer.trim().is_empty()) {
        return None;
    }
    Some(raw.to_string())
}

/// The multicast policy a ROS 2 node should run with.
///
/// `HDDS_MULTICAST_DISABLE=1` (aliases `true`, `yes`, `on`) is the
/// unicast-only deployment the peer list exists for: a container network or a
/// WAN segment where SPDP multicast does not reach the peers at all. Anything
/// else, including the variable being unset, keeps the historical default.
/// `env_config.rs` parses it as `"1" || eq_ignore_ascii_case("true")`; this
/// accepts those and a few obvious synonyms, and warns rather than guessing on
/// anything else - silently cutting a node off the network is the worst
/// possible reading of a typo.
///
/// This is also what makes the static-peer path MEASURABLE: with multicast on,
/// every peer would have been found anyway and a peer-list gate case would
/// pass whether or not the list reached the participant.
fn rmw_multicast_mode_from_env() -> MulticastMode {
    resolve_multicast_mode(std::env::var(ENV_MULTICAST).ok().as_deref())
}

/// The pure half of [`rmw_multicast_mode_from_env`].
fn resolve_multicast_mode(raw: Option<&str>) -> MulticastMode {
    let Some(raw) = raw else {
        return MulticastMode::Enabled;
    };
    match raw.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" | "disable" | "disabled" => MulticastMode::Disabled,
        "" | "0" | "false" | "no" | "off" => MulticastMode::Enabled,
        other => {
            log::warn!(
                "[rmw] {ENV_MULTICAST}='{other}' is not a boolean; keeping multicast enabled"
            );
            MulticastMode::Enabled
        }
    }
}

/// Apply the discovery environment to an rmw participant builder.
///
/// It is the only way to run ROS 2 nodes on a network where SPDP multicast
/// does not reach the peers, so an inert variable is the difference between
/// "works" and "silently discovers nobody". Cold path: read once per
/// participant, at creation.
fn with_rmw_discovery_env(builder: ParticipantBuilder) -> ParticipantBuilder {
    let mut builder = builder;

    let multicast = rmw_multicast_mode_from_env();
    if multicast != MulticastMode::Enabled {
        log::info!("[rmw] {ENV_MULTICAST}: unicast-only discovery ({multicast:?})");
        builder =
            builder.with_transport_options(TransportOptions::default().with_multicast(multicast));
    }

    if let Some(raw) = rmw_static_peers_from_env() {
        let count = raw
            .split(',')
            .map(str::trim)
            .filter(|peer| !peer.is_empty())
            .count();
        builder = builder.with_seed_peers(&raw);
        log::info!("[rmw] static SPDP peers from the environment: {count} entry(ies)");
    }

    builder
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
        Self::create_with_domain(name, 0)
    }

    /// Same as [`RmwContext::create`], on an explicit DDS domain.
    ///
    /// `rmw_init` resolves the ROS domain (`init_options.domain_id`, which
    /// `rcl` fills from `ROS_DOMAIN_ID`) before it reaches the middleware, so
    /// the adapter must hand that number down here: [`RmwContext::create`]
    /// hardcodes domain 0, which would ignore `ROS_DOMAIN_ID`.
    ///
    /// Transport selection (checked in order), see [`parse_transport_selection`]:
    /// 1. `HDDS_TRANSPORT=intra` (or `intra_process`) - intra-process only (no network)
    /// 2. `HDDS_TRANSPORT=udp` (or `udp_multicast`) - UDP multicast (fail if unavailable)
    /// 3. Unset or empty: try UDP multicast, fall back to intra-process on failure
    /// 4. Anything else is REFUSED by name. Falling into a
    ///    default arm that takes UDP without a word would let a test written
    ///    with the documented `intra_process` spelling open sockets while
    ///    believing itself hermetic.
    pub fn create_with_domain(name: &str, domain_id: u32) -> ApiResult<Self> {
        let transport_mode = std::env::var("HDDS_TRANSPORT").unwrap_or_default();

        match parse_transport_selection(&transport_mode)? {
            TransportSelection::Intra => {
                log::info!(
                    "[rmw] HDDS_TRANSPORT={}: using intra-process only",
                    transport_mode
                );
                Self::from_builder(Participant::builder(name).domain_id(domain_id))
            }
            TransportSelection::Udp => {
                log::info!(
                    "[rmw] HDDS_TRANSPORT={}: forcing UDP multicast on domain {}",
                    transport_mode,
                    domain_id
                );
                let builder = with_rmw_discovery_env(
                    Participant::builder(name)
                        .domain_id(domain_id)
                        .with_transport(TransportMode::UdpMulticast),
                );
                Self::from_builder(builder)
            }
            TransportSelection::Auto => {
                // Default: try UDP, fall back to intra-process
                let builder = with_rmw_discovery_env(
                    Participant::builder(name)
                        .domain_id(domain_id)
                        .with_transport(TransportMode::UdpMulticast),
                );
                match Self::from_builder(builder) {
                    Ok(ctx) => Ok(ctx),
                    Err(err) => {
                        log::warn!(
                            "[rmw] UDP transport failed for '{}', falling back to intra-process: {:?}",
                            name,
                            err
                        );
                        Self::from_builder(Participant::builder(name).domain_id(domain_id))
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
}

/// What `HDDS_TRANSPORT` asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TransportSelection {
    /// `intra` / `intra_process`: no network at all.
    Intra,
    /// `udp` / `udp_multicast`: UDP multicast, and fail if it is unavailable.
    Udp,
    /// Unset or empty: UDP multicast, falling back to intra-process.
    Auto,
}

/// Parse `HDDS_TRANSPORT`, by name, refusing what it cannot honour.
///
/// Both spellings the documentation has used are accepted (`intra` and
/// `intra_process`, `udp` and `udp_multicast`), case-insensitively. The
/// transports the documentation ALSO named (`tcp`, `quic`, `low_bandwidth`)
/// are refused with the reason: this selector cannot provide them in this
/// version (the RTPS send path is UDP; TCP and QUIC are wired for receive
/// only; `low_bandwidth` has no production constructor), and refusing beats
/// the previous behaviour, which was to take UDP silently. An unknown word is
/// refused too, so a typo cannot select a transport.
pub(crate) fn parse_transport_selection(value: &str) -> ApiResult<TransportSelection> {
    let word = value.trim().to_ascii_lowercase();
    match word.as_str() {
        "" => Ok(TransportSelection::Auto),
        "intra" | "intra_process" => Ok(TransportSelection::Intra),
        "udp" | "udp_multicast" => Ok(TransportSelection::Udp),
        "tcp" | "quic" | "low_bandwidth" => Err(crate::dds::Error::Config(format!(
            "HDDS_TRANSPORT={}: this transport cannot be selected through HDDS_TRANSPORT in this \
             version (the RTPS send path is UDP; TCP and QUIC are wired for receive only; \
             low_bandwidth has no production constructor). Refused rather than silently taking \
             UDP. Accepted: intra | intra_process | udp | udp_multicast, or unset for UDP with \
             intra-process fallback",
            value.trim()
        ))),
        _ => Err(crate::dds::Error::Config(format!(
            "HDDS_TRANSPORT={}: unknown value. Accepted: intra | intra_process | udp | \
             udp_multicast, or unset for UDP with intra-process fallback",
            value.trim()
        ))),
    }
}

#[cfg(test)]
mod transport_selection_tests {
    use super::{parse_transport_selection, TransportSelection};

    /// Both documented spellings reach the same selection; empty is Auto.
    #[test]
    fn both_documented_spellings_are_accepted() {
        assert_eq!(
            parse_transport_selection("intra").ok(),
            Some(TransportSelection::Intra)
        );
        assert_eq!(
            parse_transport_selection("intra_process").ok(),
            Some(TransportSelection::Intra)
        );
        assert_eq!(
            parse_transport_selection("udp").ok(),
            Some(TransportSelection::Udp)
        );
        assert_eq!(
            parse_transport_selection(" UDP_MULTICAST ").ok(),
            Some(TransportSelection::Udp)
        );
        assert_eq!(
            parse_transport_selection("").ok(),
            Some(TransportSelection::Auto)
        );
    }

    /// The transports this selector cannot provide are refused WITH the
    /// reason, never mapped onto UDP.
    #[test]
    fn a_documented_but_unwired_transport_is_refused_by_name() {
        for word in ["tcp", "quic", "low_bandwidth"] {
            let text = format!("{}", parse_transport_selection(word).expect_err(word));
            assert!(text.contains(word), "{}", text);
            assert!(text.contains("cannot be selected"), "{}", text);
        }
    }

    /// A typo is a refusal, not a transport.
    #[test]
    fn an_unknown_word_is_refused() {
        let text = format!(
            "{}",
            parse_transport_selection("intra-process").expect_err("typo")
        );
        assert!(text.contains("unknown value"), "{}", text);
        assert!(text.contains("intra-process"), "{}", text);
    }
}

impl RmwContext {
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
