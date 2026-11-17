// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! The fence's CPU while the Router is stopped.

use super::departures::{fence_item, Departure, DepartureRoute};
use super::subscriber::WriterDeparture;
use crossbeam::queue::ArrayQueue;
use std::sync::Arc;
use std::time::Duration;

fn thread_cpu() -> Duration {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: valid out-pointer.
    unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut ts) };
    Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32)
}

/// A stopped Router (ring full for good): the fence waits FENCE_WAIT. It
/// should not burn a core while it waits.
#[test]
fn f1_a_fence_waiting_on_a_stopped_router_does_not_burn_a_core() {
    let ring = Arc::new(ArrayQueue::new(1));
    ring.push(fence_item()).expect("full");
    let route = DepartureRoute::new(Arc::clone(&ring), None);
    let t0 = std::time::Instant::now();
    let c0 = thread_cpu();
    let placed = route.fence(Departure::Participant {
        prefix: [9; 12],
        cause: WriterDeparture::Deleted,
    });
    let cpu = thread_cpu() - c0;
    let wall = t0.elapsed();
    eprintln!("placed={placed} wall={wall:?} thread cpu={cpu:?}");
    assert!(!placed);
    assert!(
        cpu < wall / 5,
        "the fence burned {cpu:?} of CPU in {wall:?} waiting on a stopped Router"
    );
}
