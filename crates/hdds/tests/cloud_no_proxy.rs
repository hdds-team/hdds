// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! A cloud registry endpoint is reached DIRECTLY, never through the
//! environment's HTTP proxy.
//!
//! reqwest picks `HTTP_PROXY` / `ALL_PROXY` up from the environment by
//! default and does not exclude loopback destinations, so without an
//! explicit `.no_proxy()` on the registry client a box that exports a
//! proxy would (a) route this participant's registration - GUID,
//! locators, and for the managed backends a bearer token - through
//! whatever that variable names, and (b) make every hermetic loopback
//! test in this tree depend on the box it runs on.
//!
//! This lives in its own test binary because it mutates process-global
//! environment: one test, no parallel reader.

#![cfg(feature = "cloud-discovery")]

use hdds::test_support::domains::unique_domain;
use hdds::test_support::fake_http::{FakeHttpServer, FakeRequest, FakeResponse};
use hdds::test_support::ports::with_reserved_ports;
use hdds::{Participant, TransportMode};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[test]
fn registry_traffic_ignores_the_environment_proxy() {
    // Declared first so it is dropped last, after the participant's
    // sockets are closed.
    let domain = unique_domain();

    let registered = Arc::new(AtomicBool::new(false));
    let handler_flag = Arc::clone(&registered);
    let consul = FakeHttpServer::start(move |request: &FakeRequest| {
        if request.method == "PUT" && request.path() == "/v1/agent/service/register" {
            handler_flag.store(true, Ordering::SeqCst);
        }
        FakeResponse::json(200, "[]")
    })
    .expect("start fake consul");
    let url = consul.base_url();

    // A proxy that cannot answer: anything routed through it fails. Port 1
    // is bound by nothing on a normal host, so a connect is refused at once
    // rather than hanging.
    for name in ["HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"] {
        std::env::set_var(name, "http://127.0.0.1:1");
    }

    let participant = with_reserved_ports(8, |[mcast, sedp, user]: [u16; 3]| {
        Participant::builder("cloud_no_proxy")
            .domain_id(domain.id())
            .with_transport(TransportMode::UdpMulticast)
            .with_discovery_ports(mcast, sedp, user)
            .participant_id(Some(0))
            .with_consul(&url)
            .with_cloud_poll_interval(Duration::from_millis(200))
            .build()
    })
    .expect("participant with a cloud registry builds");

    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline && !registered.load(Ordering::SeqCst) {
        std::thread::sleep(Duration::from_millis(25));
    }

    let reached = registered.load(Ordering::SeqCst);
    let status = participant.cloud_discovery_status();
    drop(participant);
    for name in ["HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"] {
        std::env::remove_var(name);
    }

    assert!(
        reached,
        "the registry was never reached with a proxy in the environment \
         (registry client missing .no_proxy()); status={status:?}"
    );
}
