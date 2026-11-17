// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! The ROS domain must reach the DDS participant.
//!
//! `rmw_init` resolves the ROS domain (`init_options.domain_id`, which `rcl`
//! fills from `ROS_DOMAIN_ID`) before the middleware is reached, then hands it
//! to `rmw_hdds_context_create_with_domain`. Before that parameter existed,
//! `RmwContext::create` hardcoded `.domain_id(0)` and every ROS 2 node landed
//! on DDS domain 0 no matter what `ROS_DOMAIN_ID` said - the stored February
//! bench log records `RMW HDDS initialized (domain 18446744073709551615)`
//! while the participant sat on domain 0.
//!
//! Hermetic by construction: `HDDS_TRANSPORT=intra` keeps every case
//! inside the process (no socket, no multicast, no dependence on the host's
//! NICs), and the discovery-port case is pure RTPS port arithmetic. All
//! tests in this binary want the same `HDDS_TRANSPORT` value, so the one
//! `set_var` below is idempotent under `cargo test`'s thread pool.

use hdds::rmw::context::RmwContext;
use hdds::transport::PortMapping;

/// Domain ids used by the cases. Not 0 (reserved for debug) and
/// not the `hdds` domain 39 either: nothing here touches a socket, but
/// the numbers stay out of the way of a live run all the same.
const DOMAIN_A: u32 = 71;
const DOMAIN_B: u32 = 72;

fn force_intra_transport() {
    // Every test in this binary sets the same value, so the write races with
    // itself at worst.
    std::env::set_var("HDDS_TRANSPORT", "intra");
}

#[test]
fn context_create_with_domain_lands_on_that_domain() {
    force_intra_transport();

    let ctx_a = RmwContext::create_with_domain("rmw_domain_a", DOMAIN_A).expect("context A");
    let ctx_b = RmwContext::create_with_domain("rmw_domain_b", DOMAIN_B).expect("context B");

    assert_eq!(
        ctx_a.participant().domain_id(),
        DOMAIN_A,
        "the domain rmw_init resolved never reached the participant"
    );
    assert_eq!(
        ctx_b.participant().domain_id(),
        DOMAIN_B,
        "the domain rmw_init resolved never reached the participant"
    );
}

#[test]
fn default_create_still_lands_on_domain_zero() {
    force_intra_transport();

    // The domain-less entry point is kept for callers that predate the
    // parameter; it must keep its old answer.
    let ctx = RmwContext::create("rmw_domain_default").expect("default context");
    assert_eq!(ctx.participant().domain_id(), 0);
}

/// WHY the domain has to reach the participant, not that it does.
///
/// This exercises `PortMapping::calculate` only, which does not depend on
/// the domain reaching the participant: it passes either way and proves
/// nothing about the propagation. The proof of the propagation is
/// `context_create_with_domain_lands_on_that_domain` in this same file. Keep
/// this one as the statement of the consequence.
#[test]
fn different_domains_do_not_share_discovery_ports() {
    // Two ROS 2 nodes on different ROS_DOMAIN_IDs must not meet. On UDP that
    // separation IS the RTPS port arithmetic: the SPDP multicast port and the
    // per-participant unicast ports are all derived from the domain id, so a
    // participant that ignored the domain (always 0) would sit on domain 0's
    // ports and hear every other domain-0 node on the box.
    let a = PortMapping::calculate(DOMAIN_A, 0).expect("port mapping A");
    let b = PortMapping::calculate(DOMAIN_B, 0).expect("port mapping B");

    assert_ne!(
        a.metatraffic_multicast, b.metatraffic_multicast,
        "SPDP multicast port"
    );
    assert_ne!(a.sedp_multicast, b.sedp_multicast, "SEDP multicast port");
    assert_ne!(
        a.metatraffic_unicast, b.metatraffic_unicast,
        "metatraffic unicast port"
    );
    assert_ne!(a.user_unicast, b.user_unicast, "user unicast port");

    // Same domain, same participant id: identical mapping (the pair that DOES
    // discover each other).
    let a_again = PortMapping::calculate(DOMAIN_A, 0).expect("port mapping A again");
    assert_eq!(a.metatraffic_multicast, a_again.metatraffic_multicast);
    assert_eq!(a.metatraffic_unicast, a_again.metatraffic_unicast);
    assert_eq!(a.user_unicast, a_again.user_unicast);
}
