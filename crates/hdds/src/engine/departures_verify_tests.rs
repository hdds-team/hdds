// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! The departure fence under a full receive ring.

use super::departures::{fence_item, Departure, DepartureRoute};
use super::subscriber::WriterDeparture;
use crate::core::discovery::multicast::{Origin, PacketKind, RxMeta};
use crossbeam::queue::ArrayQueue;
use std::sync::Arc;
use std::time::{Duration, Instant};

fn participant(byte: u8) -> Departure {
    Departure::Participant {
        prefix: [byte; 12],
        cause: WriterDeparture::Deleted,
    }
}

/// A full ring holding an earlier departure's fence: the Router pops that
/// fence and asks the route for its departure (`next`) while the discovery
/// thread waits in `fence` for a place. Expected: the Router gets its
/// departure at once, keeps draining, and the waiting fence finds a place.
#[test]
fn d1_a_waiting_fence_does_not_stall_the_router() {
    let ring = Arc::new(ArrayQueue::new(2));
    let route = Arc::new(DepartureRoute::new(Arc::clone(&ring), None));
    assert!(route.fence(participant(1)), "fixture: first fence placed");
    let data = (
        RxMeta::new(
            Origin::direct(std::net::SocketAddr::from(([127, 0, 0, 1], 1))),
            4,
            PacketKind::Data,
        ),
        3u8,
    );
    ring.push(data).expect("fixture: ring now full");
    // The discovery thread posts a second departure: the ring is full.
    let discovery = {
        let route = Arc::clone(&route);
        std::thread::spawn(move || {
            let t = Instant::now();
            let placed = route.fence(participant(2));
            (placed, t.elapsed())
        })
    };
    std::thread::sleep(Duration::from_millis(50));
    // The Router.
    let mut router_next_wait = Duration::ZERO;
    let mut order = Vec::new();
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(3) {
        match ring.pop() {
            Some((meta, _)) if meta.kind == PacketKind::Departure => {
                let t = Instant::now();
                let d = route.next();
                router_next_wait = router_next_wait.max(t.elapsed());
                order.push(d);
            }
            Some(_) => {}
            None => {
                if discovery.is_finished() && ring.is_empty() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(1));
            }
        }
    }
    let (placed, waited) = discovery.join().expect("discovery");
    let overflow = route.take_overflow();
    eprintln!(
        "router next() waited {router_next_wait:?}; fence(2) placed={placed} after {waited:?}; \
         router order={order:?}; overflow={overflow:?}"
    );
    assert!(
        router_next_wait < Duration::from_millis(200),
        "the Router was blocked {router_next_wait:?} in next() by the waiting fence's lock"
    );
    assert!(
        placed,
        "the second fence gave up (applied ahead of its data and of departure 1) \
         though the Router freed a place right away"
    );
}

/// Fence items in the ring are not datagrams: the ring item shape.
#[test]
fn d2_fence_item_is_departure_kind() {
    assert_eq!(fence_item().0.kind, PacketKind::Departure);
}

/// D1 under load: a receive listener refills every place the Router frees
/// (a saturated socket). The fence that waits holds the route's lock, and
/// the Router, popping an earlier fence, waits on that lock in `next`:
/// nothing drains the ring until the fence gives up.
#[test]
fn d3_a_waiting_fence_under_a_saturated_ring_does_not_stall_the_router() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let ring = Arc::new(ArrayQueue::new(4));
    let route = Arc::new(DepartureRoute::new(Arc::clone(&ring), None));
    assert!(route.fence(participant(1)), "fixture: first fence placed");
    let data = || {
        (
            RxMeta::new(
                Origin::direct(std::net::SocketAddr::from(([127, 0, 0, 1], 1))),
                4,
                PacketKind::Data,
            ),
            3u8,
        )
    };
    while ring.push(data()).is_ok() {}
    let stop = Arc::new(AtomicBool::new(false));
    let listener = {
        let ring = Arc::clone(&ring);
        let stop = Arc::clone(&stop);
        std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                let _ = ring.push(data());
                std::hint::spin_loop();
            }
        })
    };
    let discovery = {
        let route = Arc::clone(&route);
        std::thread::spawn(move || {
            let t = Instant::now();
            let placed = route.fence(participant(2));
            (placed, t.elapsed())
        })
    };
    std::thread::sleep(Duration::from_millis(20));
    let mut router_next_wait = Duration::ZERO;
    let start = Instant::now();
    while start.elapsed() < Duration::from_millis(1500) {
        if let Some((meta, _)) = ring.pop() {
            if meta.kind == PacketKind::Departure {
                let t = Instant::now();
                let _ = route.next();
                router_next_wait = router_next_wait.max(t.elapsed());
            }
        }
    }
    stop.store(true, Ordering::Relaxed);
    listener.join().expect("listener");
    let (placed, waited) = discovery.join().expect("discovery");
    eprintln!(
        "router next() waited {router_next_wait:?}; fence(2) placed={placed} after {waited:?}"
    );
    assert!(
        router_next_wait < Duration::from_millis(200),
        "the Router was blocked {router_next_wait:?} in next() by the waiting fence's lock"
    );
}
