# ADR 0001: MulticastMode is one three-state switch, and reception is a security posture

Status: accepted (2026-09-02). Scope: `hdds` core UDP transport and discovery.

## Context

Two features developed on separate lines each introduced a "multicast off"
for a participant: the transport options (`MulticastMode::Disabled`, written
for asymmetric tactical links: "emission off, reception kept") and the
Discovery Server integration (`disable_multicast`: "no multicast at all",
written for containers and WAN segments). When the lines were merged, an
independent four-vendor review found:

- the "reception kept, emission off" contract was incoherent as specified: a
  participant that listens but never emits is heard by nobody, so a peer it
  hears over multicast never receives its DATA(p); the result is one-way
  discovery, SEDP sent to a participant that does not know us, and that
  participant's lease on us expiring in a loop;
- a boolean cannot express the two legitimate deployments (listen-but-never-
  emit versus no-multicast-at-all) without a hidden second knob;
- listening on a multicast group that the participant does not advertise is
  an unsolicited-ingress surface: frames from writers that were never matched
  enter the stack before any authentication, and the "early user-data spray"
  some vendors send to the well-known data group before SEDP completes is
  incompatible with DDS-Security by construction.

## Decision

1. `MulticastMode` has exactly three states, named by what happens on the wire:

   | mode | multicast TX | group join + listeners | multicast locators advertised | unicast SPDP to discovered peers |
   |---|---|---|---|---|
   | `Enabled` (default) | yes | yes | yes | no |
   | `ReceiveOnly` | no | yes | no | yes |
   | `Disabled` | no | no | no | yes |

   There is no second knob. `DiscoveryServerConfig::disable_multicast` only
   lowers the default (`Enabled` -> `Disabled`) and never overrides an
   explicit mode. The C SDK's `hdds_config_set_multicast_enabled(false)` maps
   to `ReceiveOnly`, the contract its documentation always promised.

2. The invariant across modes: every locator advertised in DATA(p) is a
   locator the participant is bound to and listens on. `ReceiveOnly` listens
   on the group but does not advertise it, because a peer that preferred an
   advertised multicast locator for user data would lose everything on a link
   that does not route multicast towards us; the advertised unicast locators
   always work.

3. In `ReceiveOnly` and `Disabled` the SPDP announcer unicasts DATA(p) to
   every participant learned by any means (static peers, `HDDS_SPDP_UNICAST_
   PEERS`, Discovery Server locators, and participants heard on the wire),
   for the duration of the remote's lease. This is what makes `ReceiveOnly`
   coherent. Static peers receive unicast SPDP in every mode, the usual
   meaning of a static initial-peers list in DDS configuration.

4. A multicast send refused by policy is an error (`ErrorKind::Unsupported`),
   never a fake success, and is counted. Callers that need delivery fall back
   to unicast on error; nothing is silently dropped.

5. A multicast group join that fails on every interface degrades the
   participant to unicast-only reception with a WARN and a queryable cause
   (`UdpTransport::multicast_join_error`), unless
   `TransportOptions::require_multicast_join` is set, in which case
   participant creation fails. Deployments that must never start degraded
   opt into the failure explicitly.

6. The effective configuration is logged once at participant creation
   (mode, effective TX/RX, join error, origin counts of the unicast SPDP
   peers, Discovery Server, lease, period), so "no hidden behaviour" can be
   checked from a log.

## Security posture

Multicast reception is not an optimisation, it is an ingress decision:

- `Disabled` is the mode with no unsolicited ingress at all and is the
  recommended mode wherever DDS-Security is enabled on a segment that also
  carries foreign or unauthenticated multicast traffic.
- `ReceiveOnly` deliberately accepts multicast ingress on a group it does not
  advertise. Under DDS-Security every sample from an unmatched or
  unauthenticated writer is rejected by the reader-side gate exactly as any
  other source, so the exposure is bounded to parsing and matching; it is
  nevertheless an exposure and must be a conscious choice for a link.
- `Enabled` keeps the historical behaviour and the historical exposure.

## Consequences

- One resolved value drives the transport (sends and join), the multicast
  listeners, the SPDP locator advertising and the announcer's unicast
  fan-out. Any new consumer must read that value, not reinvent a flag.
- Proofs live in `crates/hdds/tests/multicast_mode_v2.rs` (mutual discovery
  A `ReceiveOnly` / B `Enabled` in both directions, and the `Disabled`
  negative control) and in the announcer and transport unit tests
  (advertised-locator invariant per mode, rate floor, refused sends, join
  degrade).
- Not decided here: emitting `PID_METATRAFFIC_MULTICAST_LOCATOR` (dropped
  since v126) is a cross-vendor wire change that needs its own measurement.
