// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! The lease heap against a reference model, over seeded random sequences
//! of watch / unwatch / renew / time steps, with a scheduler that runs on
//! time, late, or not at all between steps.
//!
//! The reference evaluates every lease at the exact instant it expires and
//! keeps each writer's transitions in order. The heap only runs when the
//! sequence says so; what it must still produce, writer by writer, is the
//! same sequence of transitions and the same final state: an expiry the
//! scheduler ran too late to see is recorded all the same, once
//! (`Core::resumed`).

use std::collections::HashMap;
use std::sync::{Arc, Mutex, Weak};

use super::clock::{Nanos, INFINITE};
use super::leases::{Core, LivelinessSink, Outcome, Renewal, WatchKey};

const MS: Nanos = 1_000_000;

/// xorshift64*: the sequence is a function of the seed.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Self(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1)
    }

    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

#[derive(Default)]
struct Recorder(Mutex<HashMap<WatchKey, Vec<bool>>>);

impl LivelinessSink for Recorder {
    fn transition(
        &self,
        key: WatchKey,
        alive: bool,
    ) -> Option<Arc<crate::dds::reader::notices::Ordered>> {
        self.0.lock().unwrap().entry(key).or_default().push(alive);
        None
    }
}

fn deliver(out: Vec<Outcome>) {
    for outcome in out {
        if let Outcome::Transition { sink, key, alive } = outcome {
            if let Some(sink) = sink.upgrade() {
                sink.transition(key, alive);
            }
        }
    }
}

/// The reference: exact expiry instants.
struct RefWatch {
    renewal: usize,
    lease: Nanos,
    since: Nanos,
    alive: bool,
    transitions: Vec<bool>,
}

struct Reference {
    last: Vec<Nanos>,
    watches: HashMap<WatchKey, RefWatch>,
}

impl Reference {
    /// Time moves to `t`: every alive lease that ends at or before it ends.
    fn advance(&mut self, t: Nanos) {
        for w in self.watches.values_mut() {
            if w.alive
                && w.lease != INFINITE
                && self.last[w.renewal].max(w.since).saturating_add(w.lease) <= t
            {
                w.alive = false;
                w.transitions.push(false);
            }
        }
    }

    fn renew(&mut self, r: usize, t: Nanos) {
        self.last[r] = self.last[r].max(t);
        for w in self.watches.values_mut() {
            if w.renewal == r && !w.alive {
                w.alive = true;
                w.since = t;
                w.transitions.push(true);
            }
        }
    }
}

fn run_seed(seed: u64) {
    let mut rng = Rng::new(seed);
    let renewals: Vec<Arc<Renewal>> = (0..3).map(|i| Arc::new(Renewal::new(i + 1, 0))).collect();
    let mut reference = Reference {
        last: vec![0; renewals.len()],
        watches: HashMap::new(),
    };
    let recorder = Arc::new(Recorder::default());
    let sink: Arc<dyn LivelinessSink> = Arc::clone(&recorder) as Arc<dyn LivelinessSink>;
    let sink: Weak<dyn LivelinessSink> = Arc::downgrade(&sink);
    let mut core = Core::default();
    let leases = [50 * MS, 100 * MS, 100 * MS, 250 * MS, INFINITE];
    let mut t: Nanos = 0;
    // 0 and 1 are reserved for this participant's own AUTOMATIC and
    // MANUAL_BY_PARTICIPANT send entries (`SEND_KEY`, `MANUAL_SEND_KEY`),
    // exactly like `Shared::next_key`'s starting value.
    let mut next_key: WatchKey = 2;
    let mut live: Vec<WatchKey> = Vec::new();
    let mut gone: Vec<WatchKey> = Vec::new();
    let mut finished: HashMap<WatchKey, RefWatch> = HashMap::new();
    let mut out = Vec::new();
    for _ in 0..300 {
        match rng.below(10) {
            0 | 1 => {
                let r = rng.below(renewals.len() as u64) as usize;
                let lease = leases[rng.below(leases.len() as u64) as usize];
                let key = next_key;
                next_key += 1;
                // The reference sees time reach `t` before the watch.
                reference.advance(t);
                core.watch(key, Arc::clone(&renewals[r]), lease, sink.clone(), t);
                reference.watches.insert(
                    key,
                    RefWatch {
                        renewal: r,
                        lease,
                        since: t,
                        alive: true,
                        transitions: Vec::new(),
                    },
                );
                live.push(key);
            }
            2 if !live.is_empty() => {
                let key = live.swap_remove(rng.below(live.len() as u64) as usize);
                reference.advance(t);
                // Whatever the heap knew and did not tell yet is told now,
                // as the thread would before taking the unwatch.
                core.advance(t, &mut out);
                deliver(std::mem::take(&mut out));
                core.unwatch(key);
                if let Some(w) = reference.watches.remove(&key) {
                    finished.insert(key, w);
                }
                gone.push(key);
            }
            3..=5 => {
                let r = rng.below(renewals.len() as u64) as usize;
                reference.advance(t);
                reference.renew(r, t);
                if let Some(old) = renewals[r].renew(t) {
                    core.resumed(renewals[r].id(), old, t, &mut out);
                }
            }
            _ => {
                t += rng.below(300) * MS;
            }
        }
        // The scheduler runs on time, late, or not at all.
        if rng.below(3) == 0 {
            core.advance(t, &mut out);
        }
        deliver(std::mem::take(&mut out));
    }
    reference.advance(t);
    core.advance(t, &mut out);
    deliver(out);

    let told = recorder.0.lock().unwrap();
    for (key, w) in reference.watches.iter().chain(finished.iter()) {
        let got = told.get(key).cloned().unwrap_or_default();
        assert_eq!(
            got,
            w.transitions,
            "seed {seed}: watch {key} (lease {} ms, renewal {})",
            w.lease / MS,
            w.renewal
        );
        if live.contains(key) {
            assert_eq!(
                core.is_alive(*key),
                Some(w.alive),
                "seed {seed}: watch {key} final state"
            );
        }
    }
    for key in gone {
        assert_eq!(
            core.is_alive(key),
            None,
            "seed {seed}: watch {key} unwatched"
        );
    }
}

#[test]
fn the_lease_heap_matches_the_reference_model() {
    for seed in 0..3000 {
        run_seed(seed);
    }
}
