// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! The default destination policy must retain the merge's allocation budget:
//! ring references, parked heads and history places, with no auxiliary keys.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

struct CountingAllocator;

thread_local! {
    static ALLOCATIONS: Cell<Option<usize>> = const { Cell::new(None) };
    static LARGE_ALLOCATIONS: Cell<Option<usize>> = const { Cell::new(None) };
}

fn note_allocation(size: usize) {
    if size >= 140_000 {
        let _ = LARGE_ALLOCATIONS.try_with(|count| {
            if let Some(n) = count.get() {
                count.set(Some(n + 1));
            }
        });
    }
    let _ = ALLOCATIONS.try_with(|count| {
        if let Some(n) = count.get() {
            count.set(Some(n + 1));
        }
    });
}

// SAFETY: every allocation operation is forwarded unchanged to System;
// counting is thread-local, has const initialization and never allocates.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        note_allocation(layout.size());
        // SAFETY: the caller provides the layout required by GlobalAlloc.
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        note_allocation(layout.size());
        // SAFETY: the caller provides the layout required by GlobalAlloc.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: ptr and layout come from the same forwarding allocator.
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        note_allocation(size);
        // SAFETY: ptr, layout and size satisfy the GlobalAlloc contract.
        unsafe { System.realloc(ptr, layout, size) }
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

#[derive(Debug, Clone, PartialEq, hdds::DDS)]
struct Value {
    value: i32,
}

/// DDS 1.4 Sec.2.2.3.14: a bounded ordinary write that finds no room
/// returns TIMEOUT without allocating a box for its blocked registration.
#[test]
fn ordinary_local_backpressure_does_not_allocate() {
    let participant = hdds::Participant::builder("ordinary_backpressure_allocations")
        .with_transport(hdds::TransportMode::IntraProcess)
        .build()
        .unwrap();
    let topic = participant
        .topic::<Value>("ordinary_backpressure_allocations")
        .unwrap();
    let mut qos = hdds::QoS::reliable().keep_all();
    qos.reliability_max_blocking_time = std::time::Duration::ZERO;
    let writer = topic.writer().qos(qos.clone()).build().unwrap();
    qos.resource_limits.max_samples = 1;
    let reader = topic.reader().qos(qos).build().unwrap();
    writer.write(&Value { value: 0 }).unwrap();
    // Warm the timeout path before measuring its repeatable allocation budget.
    assert!(matches!(
        writer.write(&Value { value: 1 }),
        Err(hdds::Error::WriteTimeout)
    ));
    ALLOCATIONS.with(|n| n.set(Some(0)));
    let result = writer.write(&Value { value: 2 });
    let count = ALLOCATIONS.with(|n| n.replace(None).unwrap());
    assert!(matches!(result, Err(hdds::Error::WriteTimeout)));
    assert_eq!(count, 0, "ordinary backpressure allocated");
    assert_eq!(reader.take().unwrap().unwrap().value, 0);
}

#[test]
fn reception_merge_needs_no_auxiliary_key_allocation() {
    let domain = hdds::test_support::domains::unique_domain();
    let participant = hdds::Participant::builder("reception_merge_allocations")
        .domain_id(domain.id())
        .with_transport(hdds::TransportMode::IntraProcess)
        .build()
        .unwrap();
    let topic = participant
        .topic::<Value>("reception_merge_allocations")
        .unwrap();
    let a = topic
        .writer()
        .qos(hdds::QoS::best_effort())
        .build()
        .unwrap();
    let b = topic
        .writer()
        .qos(hdds::QoS::best_effort())
        .build()
        .unwrap();
    let reader = topic
        .reader()
        .qos(hdds::QoS::best_effort().keep_last(1))
        .build()
        .unwrap();
    a.write(&Value { value: 0 }).unwrap();
    b.write(&Value { value: 1 }).unwrap();
    assert_eq!(reader.take().unwrap(), Some(Value { value: 1 }));
    a.write(&Value { value: 2 }).unwrap();
    b.write(&Value { value: 3 }).unwrap();

    ALLOCATIONS.with(|n| n.set(Some(0)));
    let result = reader.take();
    let count = ALLOCATIONS.with(|n| n.replace(None).unwrap());
    assert_eq!(result.unwrap(), Some(Value { value: 3 }));
    assert_eq!(count, 3, "default merge allocation budget");
}

#[derive(Debug, Clone, PartialEq, hdds::DDS)]
struct Blob {
    value: i32,
    bytes: Vec<u8>,
}

/// DDS v1.4 Sec.2.2.3.17: reception order uses write time even for an
/// explicit source timestamp. Reading a parked head's merge key must not
/// allocate or copy its heap-tier payload on each comparison.
#[test]
fn reception_merge_reads_heap_head_keys_without_payload_copies() {
    let domain = hdds::test_support::domains::unique_domain();
    let participant = hdds::Participant::builder("heap_merge_key")
        .domain_id(domain.id())
        .with_transport(hdds::TransportMode::IntraProcess)
        .build()
        .unwrap();
    let topic = participant.topic::<Blob>("heap_merge_key").unwrap();
    let a = topic
        .writer()
        .qos(hdds::QoS::best_effort())
        .build()
        .unwrap();
    let b = topic
        .writer()
        .qos(hdds::QoS::best_effort())
        .build()
        .unwrap();
    let reader = topic
        .reader()
        .qos(hdds::QoS::best_effort().keep_last(8))
        .build()
        .unwrap();
    a.write(&Blob {
        value: -1,
        bytes: Vec::new(),
    })
    .unwrap();
    reader.take().unwrap().unwrap();
    for value in 0..4 {
        a.write(&Blob {
            value,
            bytes: Vec::new(),
        })
        .unwrap();
    }
    b.write_w_timestamp(
        &Blob {
            value: 9,
            bytes: vec![0x5a; 140_000],
        },
        1,
    )
    .unwrap();

    LARGE_ALLOCATIONS.with(|n| n.set(Some(0)));
    let first = reader.take();
    let copies = LARGE_ALLOCATIONS.with(|n| n.replace(None).unwrap());
    assert_eq!(
        first.unwrap().unwrap().value,
        0,
        "write time orders the heads"
    );
    // One heap buffer copy to decode, one allocation for the decoded Vec.
    // Looking at the merge key owes no payload-sized allocation.
    assert_eq!(copies, 2, "only decoding allocates payload-sized storage");
    let mut rest = Vec::new();
    while let Some(sample) = reader.take().unwrap() {
        rest.push(sample.value);
    }
    assert_eq!(rest, vec![1, 2, 3, 9]);
}
