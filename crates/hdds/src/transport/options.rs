// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Participant-level transport options for constrained-network deployments.
//!
//! This module groups the socket-level transport knobs (TTL, DSCP, interface
//! allowlist, multicast on/off) into a single [`TransportOptions`] struct that
//! can be handed to `ParticipantBuilder::with_transport_options`.
//!
//! # Precedence
//!
//! Explicit builder options ALWAYS win over environment variables. Environment
//! variables remain the fallback for any field left unset:
//!
//! | Field                 | Explicit (builder)      | Env fallback              | Nothing set          |
//! |-----------------------|-------------------------|---------------------------|----------------------|
//! | `ttl`                 | `Some(TtlConfig)`       | `HDDS_TTL`, `HDDS_MULTICAST_TTL`, `HDDS_UNICAST_TTL` | multicast=1, unicast=64 |
//! | `dscp`                | `Some(DscpConfig)`      | `HDDS_DSCP`               | no TOS marking (kernel default 0) |
//! | `interface_allowlist` | `Some(InterfaceFilter)` | `HDDS_INTERFACE_ALLOW`    | all interfaces allowed |
//! | `multicast`           | `MulticastMode`         | (none)                    | `Enabled`            |
//!
//! # Default = today's behavior (hard invariant)
//!
//! `TransportOptions::default()` resolved with no relevant environment
//! variables set replicates the pre-options behavior exactly:
//!
//! - TTL: multicast TTL 1 / unicast TTL 64 on every UDP socket (identical to
//!   the previous `TtlConfig::from_env()` call in `UdpTransport::new` and to
//!   the hardcoded `set_multicast_ttl_v4(1)` on the listener sockets; the
//!   kernel default unicast TTL on Linux is 64).
//! - DSCP: no `IP_TOS` setsockopt is issued at all (packets keep TOS 0).
//!   Note that `DscpConfig::default()` is NOT best-effort, so the resolved
//!   DSCP is `Option<DscpConfig>`: `None` means "do not touch TOS".
//! - Interface allowlist: permissive (`InterfaceFilter::allow_all()`), every
//!   non-loopback interface is joined/advertised as before.
//! - Multicast: `Enabled` -- SPDP announce/dispose go to 239.255.0.1 and
//!   multicast locators are advertised, as before.
//!
//! # Interaction with `HDDS_INTERFACE`
//!
//! `HDDS_INTERFACE` (force a single interface) is an explicit user choice and
//! bypasses the allowlist entirely, mirroring its existing "trust the user"
//! semantics elsewhere in the transport.

use crate::transport::dscp::DscpConfig;
use crate::transport::external_locator::{ExternalLocator, ENV_EXTERNAL_LOCATOR};
use crate::transport::filter::InterfaceFilter;
use crate::transport::ttl::TtlConfig;

/// Multicast usage policy for the UDP transport.
///
/// One switch, three states, expressed by what happens on the wire. Every
/// consumer (transport sends and group join, multicast listeners, SPDP
/// locator advertising, the SPDP announcer's unicast fan-out) reads this
/// single resolved value; there is no second knob. The invariant, whatever
/// the mode: a locator advertised in DATA(p) is a locator this participant
/// is bound to and listens on.
///
/// | mode | multicast TX | group join + listeners | multicast locators advertised | unicast SPDP to discovered peers |
/// |---|---|---|---|---|
/// | `Enabled` | yes | yes | yes | no (multicast reaches them) |
/// | `ReceiveOnly` | no | yes | no | yes |
/// | `Disabled` | no | no | no | yes |
///
/// In `ReceiveOnly` and `Disabled`, static peers, `HDDS_SPDP_UNICAST_PEERS`,
/// Discovery Server locators and every participant learned by any means
/// receive periodic unicast SPDP (for the remote's lease duration). Without
/// that, a peer heard over multicast would never receive our DATA(p):
/// one-way discovery, SEDP sent to a participant that does not know us, and
/// its lease on us expiring in a loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MulticastMode {
    /// Full multicast: emission, group join, listeners, multicast locators
    /// advertised (default, matches historical behavior).
    #[default]
    Enabled,
    /// Listen but never emit multicast. For asymmetric links where sending
    /// multicast is costly or detectable (tactical radios) or filtered on
    /// egress, while the local segment still carries multicast inbound:
    ///
    /// - SPDP announce and dispose are NOT sent to the multicast group; they
    ///   go to the static peers / `HDDS_SPDP_UNICAST_PEERS` / Discovery
    ///   Server locators / discovered participants instead.
    /// - No multicast locators are advertised in SPDP (peers reach us over
    ///   the unicast locators we advertise).
    /// - All multicast sends on `UdpTransport` (SPDP, SEDP, user data,
    ///   HEARTBEAT/GAP repair to the data multicast group) are suppressed.
    /// - The SPDP socket still joins the group and both multicast listeners
    ///   run: multicast SPDP from peers and early user data sprayed to the
    ///   well-known data group are still received.
    ///
    /// Security note: listening on a group we do not advertise is an
    /// unsolicited-ingress surface; under DDS-Security unmatched writers are
    /// rejected by the reader-side gate like any other source.
    ReceiveOnly,
    /// No multicast at all, for links and hosts where multicast does not
    /// exist (containers, WAN segments, Discovery Server deployments):
    /// everything in `ReceiveOnly`, plus no group join and no multicast
    /// listener, so the participant is reachable only through the unicast
    /// locators it advertises. `DiscoveryServerConfig::disable_multicast`
    /// maps onto this mode.
    Disabled,
}

/// Participant-level transport options (phase 1: Rust core surface).
///
/// See the [module documentation](self) for precedence rules and the
/// "defaults = today" invariant. Construct with [`TransportOptions::default`]
/// and override the fields you need:
///
/// ```
/// use hdds::transport::{MulticastMode, TransportOptions, TtlConfig};
///
/// let opts = TransportOptions {
///     ttl: Some(TtlConfig::custom(8, 64)),
///     multicast: MulticastMode::Disabled,
///     ..TransportOptions::default()
/// };
/// assert_eq!(opts.multicast, MulticastMode::Disabled);
/// ```
#[derive(Debug, Clone, Default)]
pub struct TransportOptions {
    /// IP TTL configuration. `None` = fall back to the `HDDS_TTL` /
    /// `HDDS_MULTICAST_TTL` / `HDDS_UNICAST_TTL` environment variables,
    /// then to the defaults (multicast 1, unicast 64).
    pub ttl: Option<TtlConfig>,
    /// Per-traffic-class DSCP marking. `None` = fall back to `HDDS_DSCP`;
    /// when that is unset either, NO TOS marking is applied (kernel default).
    pub dscp: Option<DscpConfig>,
    /// Interface allowlist consulted for multicast joins, locator
    /// advertising and primary-interface selection. `None` = fall back to
    /// `HDDS_INTERFACE_ALLOW`; when unset, all interfaces are allowed.
    pub interface_allowlist: Option<InterfaceFilter>,
    /// Multicast usage policy (default: [`MulticastMode::Enabled`]).
    pub multicast: MulticastMode,
    /// What to do when the multicast group cannot be joined on any
    /// interface while the mode wants reception (`Enabled`, `ReceiveOnly`).
    ///
    /// `false` (default): degrade. The participant is created without
    /// multicast reception (no group, no multicast listeners), a WARN is
    /// logged, [`crate::transport::UdpTransport::multicast_join_error`]
    /// reports the cause and the effective-configuration line shows
    /// `rx=false`. Unicast discovery (static peers, Discovery Server,
    /// discovered peers) keeps working.
    ///
    /// `true`: fail participant creation with the join error. For
    /// deployments where a silently degraded discovery must never start.
    pub require_multicast_join: bool,
    /// Addresses announced to peers although no local socket is bound to
    /// them: the public side of a NAT mapping, or a relay endpoint. They are
    /// ADDED to the locators read off local interfaces, never substituted
    /// for them, so a peer on the LAN keeps reaching us directly.
    ///
    /// `None` = fall back to `HDDS_EXTERNAL_LOCATOR`; `Some(vec![])`
    /// explicitly announces none and ignores that variable.
    pub external_locators: Option<Vec<ExternalLocator>>,
}

impl TransportOptions {
    /// Set an explicit TTL configuration (wins over env vars).
    #[must_use]
    pub fn with_ttl(mut self, ttl: TtlConfig) -> Self {
        self.ttl = Some(ttl);
        self
    }

    /// Set an explicit per-class DSCP configuration (wins over env vars).
    #[must_use]
    pub fn with_dscp(mut self, dscp: DscpConfig) -> Self {
        self.dscp = Some(dscp);
        self
    }

    /// Set an explicit interface allowlist (wins over env vars).
    #[must_use]
    pub fn with_interface_allowlist(mut self, filter: InterfaceFilter) -> Self {
        self.interface_allowlist = Some(filter);
        self
    }

    /// Set the multicast usage policy.
    #[must_use]
    pub fn with_multicast(mut self, mode: MulticastMode) -> Self {
        self.multicast = mode;
        self
    }

    /// Shorthand for `.with_multicast(MulticastMode::Disabled)`.
    #[must_use]
    pub fn unicast_only(self) -> Self {
        self.with_multicast(MulticastMode::Disabled)
    }

    /// Shorthand for `with_multicast(MulticastMode::ReceiveOnly)`: listen to
    /// multicast, never emit it.
    #[must_use]
    pub fn receive_only(self) -> Self {
        self.with_multicast(MulticastMode::ReceiveOnly)
    }

    /// Fail participant creation instead of degrading when the multicast
    /// group cannot be joined (see [`Self::require_multicast_join`]).
    #[must_use]
    pub fn require_multicast_join(mut self) -> Self {
        self.require_multicast_join = true;
        self
    }

    /// Announce one more address that is not bound locally, in ADDITION to
    /// the local ones (see [`Self::external_locators`]).
    ///
    /// Calling this at all stops `HDDS_EXTERNAL_LOCATOR` from being read.
    #[must_use]
    pub fn with_external_locator(mut self, locator: ExternalLocator) -> Self {
        self.external_locators
            .get_or_insert_with(Vec::new)
            .push(locator);
        self
    }

    /// Announce exactly this set of external locators, ignoring
    /// `HDDS_EXTERNAL_LOCATOR`. An empty slice means "none, and do not read
    /// the environment".
    #[must_use]
    pub fn with_external_locators(mut self, locators: impl Into<Vec<ExternalLocator>>) -> Self {
        self.external_locators = Some(locators.into());
        self
    }

    /// Resolve builder options against the environment.
    ///
    /// Precedence per field: explicit value -> environment variable ->
    /// historical default. This is the single resolution point; downstream
    /// code (transport, listener sockets, SPDP announcer) consumes the
    /// resolved struct and never re-reads the environment.
    #[must_use]
    pub fn resolve(&self) -> ResolvedTransportOptions {
        Self::resolve_with(
            self,
            env_ttl(),
            env_dscp(),
            env_interface_allowlist(),
            env_external_locators(),
        )
    }

    /// Pure resolution logic, separated from environment reads for testability.
    fn resolve_with(
        opts: &Self,
        env_ttl: Option<TtlConfig>,
        env_dscp: Option<DscpConfig>,
        env_filter: Option<InterfaceFilter>,
        env_external: Option<Vec<ExternalLocator>>,
    ) -> ResolvedTransportOptions {
        ResolvedTransportOptions {
            ttl: opts.ttl.or(env_ttl).unwrap_or_default(),
            dscp: opts.dscp.or(env_dscp),
            interface_allowlist: opts
                .interface_allowlist
                .clone()
                .or(env_filter)
                .unwrap_or_else(InterfaceFilter::allow_all),
            multicast: opts.multicast,
            require_multicast_join: opts.require_multicast_join,
            external_locators: opts
                .external_locators
                .clone()
                .or(env_external)
                .unwrap_or_default(),
        }
    }
}

/// Read the TTL env vars, returning `None` when none of them is set.
fn env_ttl() -> Option<TtlConfig> {
    let any_set = ["HDDS_TTL", "HDDS_MULTICAST_TTL", "HDDS_UNICAST_TTL"]
        .iter()
        .any(|v| std::env::var(v).is_ok());
    if any_set {
        Some(TtlConfig::from_env())
    } else {
        None
    }
}

/// Read `HDDS_DSCP`, returning `None` when unset (= do not mark TOS at all;
/// applying `DscpConfig::default()` here would CHANGE behavior since that
/// default is not best-effort).
fn env_dscp() -> Option<DscpConfig> {
    if std::env::var("HDDS_DSCP").is_ok() {
        Some(DscpConfig::from_env())
    } else {
        None
    }
}

/// Read `HDDS_EXTERNAL_LOCATOR`, returning `None` when unset.
///
/// A malformed value yields `Some(vec![])` and an ERROR log, never a partial
/// list: announcing half of what the operator asked for would produce a
/// locator set nobody configured, and the failure would then show up as a
/// peer that is sometimes reachable. All or nothing, loudly.
fn env_external_locators() -> Option<Vec<ExternalLocator>> {
    let raw = std::env::var(ENV_EXTERNAL_LOCATOR).ok()?;
    match ExternalLocator::parse_list(&raw) {
        Ok(locators) => Some(locators),
        Err(error) => {
            log::error!(
                "[transport] {ENV_EXTERNAL_LOCATOR}='{raw}' refused, NO external locator will be announced: {error}"
            );
            Some(Vec::new())
        }
    }
}

/// Read `HDDS_INTERFACE_ALLOW`, returning `None` when unset.
fn env_interface_allowlist() -> Option<InterfaceFilter> {
    if std::env::var("HDDS_INTERFACE_ALLOW").is_ok() {
        Some(InterfaceFilter::from_env())
    } else {
        None
    }
}

/// Transport options after env-var resolution.
///
/// Produced by [`TransportOptions::resolve`]; every consumer downstream of
/// the participant builder reads this struct instead of the environment.
#[derive(Debug, Clone)]
pub struct ResolvedTransportOptions {
    /// TTL applied to every UDP socket the participant opens.
    pub ttl: TtlConfig,
    /// DSCP marking per traffic class; `None` = leave the kernel default
    /// TOS untouched (historical behavior).
    ///
    /// Socket class mapping (phase 1):
    /// - metatraffic multicast socket (SPDP/SEDP/user multicast sends) and
    ///   metatraffic unicast socket -> `dscp.metatraffic`. Discovery shares
    ///   these sockets, so `dscp.discovery` is currently blurred into
    ///   `metatraffic`; a dedicated discovery socket would be needed to
    ///   distinguish them on the wire.
    /// - user-data unicast socket and user-data listener sockets ->
    ///   `dscp.user_data`.
    pub dscp: Option<DscpConfig>,
    /// Interface allowlist; permissive when nothing was configured.
    pub interface_allowlist: InterfaceFilter,
    /// Multicast usage policy.
    pub multicast: MulticastMode,
    /// Fail participant creation when the multicast group cannot be joined
    /// (see [`TransportOptions::require_multicast_join`]).
    pub require_multicast_join: bool,
    /// Addresses announced in ADDITION to the local ones; empty when none
    /// was configured, which is the historical behaviour exactly.
    pub external_locators: Vec<ExternalLocator>,
}

impl ResolvedTransportOptions {
    /// True when multicast EMISSION is enabled (`Enabled` only): multicast
    /// sends go out and multicast locators are advertised.
    #[must_use]
    pub fn multicast_send_enabled(&self) -> bool {
        self.multicast == MulticastMode::Enabled
    }

    /// True when multicast RECEPTION is enabled (`Enabled` or
    /// `ReceiveOnly`): the SPDP socket joins the group and the multicast
    /// listeners run.
    #[must_use]
    pub fn multicast_receive_enabled(&self) -> bool {
        matches!(
            self.multicast,
            MulticastMode::Enabled | MulticastMode::ReceiveOnly
        )
    }

    /// True when discovered participants must receive periodic unicast SPDP
    /// because multicast cannot carry our announcements to them
    /// (`ReceiveOnly` and `Disabled`).
    #[must_use]
    pub fn unicast_spdp_to_discovered(&self) -> bool {
        self.multicast != MulticastMode::Enabled
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::dscp::DscpClass;

    #[test]
    fn default_options_are_none_and_enabled() {
        let opts = TransportOptions::default();
        assert!(opts.ttl.is_none());
        assert!(opts.dscp.is_none());
        assert!(opts.interface_allowlist.is_none());
        assert_eq!(opts.multicast, MulticastMode::Enabled);
    }

    #[test]
    fn resolve_defaults_replicate_today() {
        // No explicit options, no env: TTL 1/64, no DSCP, permissive filter,
        // multicast enabled -- exactly the pre-options behavior.
        let resolved =
            TransportOptions::resolve_with(&TransportOptions::default(), None, None, None, None);
        assert_eq!(resolved.ttl, TtlConfig::default());
        assert_eq!(resolved.ttl.multicast, 1);
        assert_eq!(resolved.ttl.unicast, 64);
        assert!(resolved.dscp.is_none());
        assert!(resolved.interface_allowlist.is_permissive());
        assert!(resolved.multicast_send_enabled());
        assert!(resolved.external_locators.is_empty());
    }

    #[test]
    fn explicit_options_win_over_env() {
        let opts = TransportOptions::default()
            .with_ttl(TtlConfig::custom(32, 96))
            .with_dscp(DscpConfig::realtime())
            .with_interface_allowlist(InterfaceFilter::only_names(&["eth0"]))
            .with_external_locator(sample_locator(40001, 40002));
        // Simulated env values that must all LOSE against the explicit ones.
        let resolved = TransportOptions::resolve_with(
            &opts,
            Some(TtlConfig::custom(2, 2)),
            Some(DscpConfig::best_effort()),
            Some(InterfaceFilter::only_names(&["wlan0"])),
            Some(vec![sample_locator(9999, 9998)]),
        );
        assert_eq!(resolved.ttl, TtlConfig::custom(32, 96));
        assert_eq!(
            resolved.dscp.expect("explicit dscp").user_data,
            DscpClass::Ef
        );
        assert!(resolved.interface_allowlist.allows_name("eth0"));
        assert!(!resolved.interface_allowlist.allows_name("wlan0"));
        assert_eq!(
            resolved.external_locators,
            vec![sample_locator(40001, 40002)]
        );
    }

    #[test]
    fn env_is_fallback_when_no_explicit_option() {
        let resolved = TransportOptions::resolve_with(
            &TransportOptions::default(),
            Some(TtlConfig::custom(16, 64)),
            Some(DscpConfig::high_priority()),
            Some(InterfaceFilter::only_names(&["eth1"])),
            Some(vec![sample_locator(40001, 40002)]),
        );
        assert_eq!(resolved.ttl.multicast, 16);
        assert_eq!(resolved.dscp.expect("env dscp").user_data, DscpClass::Af41);
        assert!(resolved.interface_allowlist.allows_name("eth1"));
        assert!(!resolved.interface_allowlist.allows_name("eth0"));
        assert_eq!(
            resolved.external_locators,
            vec![sample_locator(40001, 40002)]
        );
    }

    #[test]
    fn require_multicast_join_is_off_by_default_and_resolves() {
        assert!(!TransportOptions::default().resolve().require_multicast_join);
        assert!(
            TransportOptions::default()
                .require_multicast_join()
                .resolve()
                .require_multicast_join
        );
    }

    #[test]
    fn receive_only_keeps_reception_and_stops_emission() {
        let resolved = TransportOptions::default().receive_only().resolve();
        assert_eq!(resolved.multicast, MulticastMode::ReceiveOnly);
        assert!(!resolved.multicast_send_enabled());
        assert!(resolved.multicast_receive_enabled());
        assert!(resolved.unicast_spdp_to_discovered());
    }

    #[test]
    fn mode_predicates_cover_the_three_states() {
        let enabled = TransportOptions::default().resolve();
        assert!(enabled.multicast_send_enabled());
        assert!(enabled.multicast_receive_enabled());
        assert!(!enabled.unicast_spdp_to_discovered());
        let disabled = TransportOptions::default().unicast_only().resolve();
        assert!(!disabled.multicast_send_enabled());
        assert!(!disabled.multicast_receive_enabled());
        assert!(disabled.unicast_spdp_to_discovered());
    }

    #[test]
    fn unicast_only_disables_multicast() {
        let opts = TransportOptions::default().unicast_only();
        assert_eq!(opts.multicast, MulticastMode::Disabled);
        let resolved = TransportOptions::resolve_with(&opts, None, None, None, None);
        assert!(!resolved.multicast_send_enabled());
    }

    fn sample_locator(metatraffic: u16, user: u16) -> ExternalLocator {
        ExternalLocator::new(std::net::Ipv4Addr::new(93, 184, 216, 34), metatraffic, user)
            .expect("valid external locator")
    }

    #[test]
    fn an_explicitly_empty_set_ignores_the_environment() {
        // `Some(vec![])` is not the same as `None`: it means "announce none,
        // and do not read HDDS_EXTERNAL_LOCATOR".
        let opts = TransportOptions::default().with_external_locators(Vec::new());
        let resolved = TransportOptions::resolve_with(
            &opts,
            None,
            None,
            None,
            Some(vec![sample_locator(40001, 40002)]),
        );
        assert!(resolved.external_locators.is_empty());
    }

    #[test]
    fn several_external_locators_accumulate_in_order() {
        let opts = TransportOptions::default()
            .with_external_locator(sample_locator(40001, 40002))
            .with_external_locator(sample_locator(50001, 50002));
        let resolved = TransportOptions::resolve_with(&opts, None, None, None, None);
        assert_eq!(resolved.external_locators.len(), 2);
        assert_eq!(resolved.external_locators[0].metatraffic_port(), 40001);
        assert_eq!(resolved.external_locators[1].metatraffic_port(), 50001);
    }
}
