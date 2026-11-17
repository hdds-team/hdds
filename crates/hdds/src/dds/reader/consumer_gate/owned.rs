// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Mutual exclusion among the consumers of a reader's rings (see the
//! `consumer_gate` field of `DataReader`).
//!
//! The rings are single-consumer. Their consumers are the ordinary accessors
//! (`take`, `read`, the instance accessors, the legacy `try_take`) and the
//! condition accessors (trigger evaluation, `take_w_condition`,
//! `read_w_condition`), and these may run on several threads at once: a
//! WaitSet evaluating a ReadCondition on one thread while the application
//! drains with `take()` on another is the ordinary DDS pattern. The gate
//! makes them one consumer.
//!
//! # Two regimes
//!
//! **Owned.** The first thread that consumes owns the gate. While it is the
//! only thread that ever consumed, it enters and leaves with plain stores
//! and loads: a `fast` flag raised on entry and lowered on exit, and a
//! check of `mode` between the two. No read-modify-write, no hardware
//! fence. This is every acquisition of a reader drained by one thread, the
//! one-thread write-then-take path included.
//!
//! **Engaged.** The first time any other thread consumes, it engages the
//! gate for good: it moves `mode` away from `OPEN`, runs a process-wide
//! heavy barrier (`membarrier(MEMBARRIER_CMD_PRIVATE_EXPEDITED)`), waits
//! until the owner is out of any section it had entered, and records
//! `ENGAGED`. From then on every consumer, the owner included, takes the
//! `held` flag with a compare-and-swap and releases it with a store.
//!
//! # Why the owner's plain accesses are enough
//!
//! The owner does `fast = true`, a compiler fence, then reads `mode`; an
//! engager does `mode = ENGAGING`, the heavy barrier, then reads `fast`.
//! This is Dekker's handshake with the owner's half of the full fence
//! moved to the engager: the kernel runs a full memory barrier on every
//! running thread of the process before `membarrier` returns, and a thread
//! not running has passed one at its context switch. The compiler fence
//! keeps the owner's store before its load in program order, and the
//! barrier makes that order hold in memory as if the owner had fenced
//! itself (the asymmetric fence pair of liburcu and of Folly's
//! `asymmetricLightBarrier` / `asymmetricHeavyBarrier`). So either the
//! owner's read of `mode` sees `ENGAGING` (it backs out and lowers `fast`
//! without touching a ring), or the engager's read of `fast` sees the
//! owner inside and waits for the release store that ends the section,
//! which also orders the owner's ring accesses before the engager's. Two
//! states, not one: a consumer that finds `ENGAGING` has no proof the
//! engager finished waiting, so it runs the engagement itself; only
//! `ENGAGED` lets a consumer go straight to the compare-and-swap.
//!
//! Where `membarrier` is not available (another operating system, an old
//! kernel, a seccomp filter refusing it) the gate starts `ENGAGED`: every
//! acquisition is the compare-and-swap, as before the owned regime existed.
//!
//! The owner is named by a token unique to each thread for the life of the
//! process, never reused: a thread that started after the owner exited is a
//! different thread, which engages. A guard cannot leave the thread that
//! took it (`ConsumerGuard` is not `Send`), and the owner taking the gate
//! again while it holds it panics: the `fast` flag says the owner is inside,
//! not how many times, so a nested section would end the outer one early.
//! (A nested acquisition of the held flag spins forever, as it always did.)
//!
//! # What the argument rests on
//!
//! The handshake is outside the Rust abstract memory model, which knows no
//! `membarrier`: it rests on the kernel's documented guarantee for that
//! system call and on `compiler_fence` compiling to a compiler barrier, the
//! same footing as liburcu, Folly and the `membarrier` crate. Miri cannot
//! run the system call, so under Miri the gate starts engaged. The
//! availability probe runs the very command the engagement uses; a seccomp
//! filter installed afterwards, or on one thread only, that refuses it makes
//! the engagement panic rather than let two consumers into one ring.

use std::cell::Cell;
use std::marker::PhantomData;
use std::sync::atomic::{compiler_fence, AtomicBool, AtomicU64, AtomicU8, Ordering};

/// Only the owner consumes; it may use the plain-access sections.
const OPEN: u8 = 0;
/// A second consumer is engaging the gate; nobody may start a plain-access
/// section, and the owner may still be inside one.
const ENGAGING: u8 = 1;
/// Every consumer takes `held`; no plain-access section is in progress or
/// will start again.
const ENGAGED: u8 = 2;

/// The ring consumer gate of one reader.
pub(crate) struct ConsumerGate {
    /// Taken by compare-and-swap in the engaged regime.
    held: AtomicBool,
    /// `OPEN`, `ENGAGING` or `ENGAGED`; never moves back.
    mode: AtomicU8,
    /// The owner's thread token (`thread_token`), 0 until the first
    /// consumer claims the gate.
    owner: AtomicU64,
    /// Raised by the owner for the length of a plain-access section.
    fast: AtomicBool,
    /// Test seam: runs once in the owner's path, after its first read of
    /// the mode and before it raises `fast`, so a test can engage the gate
    /// inside that window.
    #[cfg(test)]
    pre_section_hook: std::sync::Mutex<Option<Box<dyn FnOnce() + Send>>>,
}

/// Holds the [`ConsumerGate`] until dropped.
pub(crate) struct ConsumerGuard<'a> {
    gate: &'a ConsumerGate,
    /// Whether this is an owner's plain-access section (released by
    /// lowering `fast`) rather than the `held` flag.
    fast: bool,
    /// Not `Send`: an owner's section must end on the owner's thread, or the
    /// owner could enter again while another thread still holds it.
    _not_send: PhantomData<*const ()>,
}

impl ConsumerGate {
    pub(crate) fn new() -> Self {
        Self {
            held: AtomicBool::new(false),
            mode: AtomicU8::new(if heavy_barrier_available() {
                OPEN
            } else {
                ENGAGED
            }),
            owner: AtomicU64::new(0),
            fast: AtomicBool::new(false),
            #[cfg(test)]
            pre_section_hook: std::sync::Mutex::new(None),
        }
    }

    #[cfg(test)]
    fn set_pre_section_hook(&self, hook: impl FnOnce() + Send + 'static) {
        *self.pre_section_hook.lock().expect("hook") = Some(Box::new(hook));
    }

    /// Acquire the gate: a plain-access section for the owner while it is
    /// the only consumer, the `held` flag otherwise (spinning, then
    /// yielding, while another consumer holds it).
    #[inline]
    pub(crate) fn lock(&self) -> ConsumerGuard<'_> {
        // The mode is read first too, so that an owner whose gate is engaged
        // goes straight to the held flag without writing `fast`.
        if self.owner.load(Ordering::Relaxed) == thread_token()
            && self.mode.load(Ordering::Relaxed) == OPEN
        {
            // Only the owner raises `fast`: finding it raised here means the
            // owner is already inside (module docs).
            assert!(
                !self.fast.load(Ordering::Relaxed),
                "a reader's consumer gate taken again by the thread holding it"
            );
            #[cfg(test)]
            {
                let hook = self.pre_section_hook.lock().expect("hook").take();
                if let Some(hook) = hook {
                    hook();
                }
            }
            self.fast.store(true, Ordering::Relaxed);
            // The owner's half of the asymmetric fence (module docs): the
            // store above stays before the load below in program order; the
            // engager's heavy barrier makes it so in memory.
            compiler_fence(Ordering::SeqCst);
            if self.mode.load(Ordering::Relaxed) == OPEN {
                return ConsumerGuard {
                    gate: self,
                    fast: true,
                    _not_send: PhantomData,
                };
            }
            // Engaged or being engaged: back out without having touched a
            // ring, and let a waiting engager through.
            self.fast.store(false, Ordering::Release);
        }
        self.lock_slow()
    }

    #[cold]
    #[inline(never)]
    fn lock_slow(&self) -> ConsumerGuard<'_> {
        let me = thread_token();
        if self.mode.load(Ordering::Acquire) == OPEN
            && self
                .owner
                .compare_exchange(0, me, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
        {
            // The first consumer of this reader: it owns the gate from now
            // on (its next acquisitions are the plain-access path). This
            // one goes through the same path, which re-checks the mode.
            return self.lock();
        }
        if self.mode.load(Ordering::Acquire) != ENGAGED {
            self.engage();
        }
        self.lock_held()
    }

    /// Move the gate to the engaged regime: no owner section in progress
    /// and none started afterwards (module docs). Run by every consumer
    /// that finds the mode short of `ENGAGED`, so that each one has the
    /// proof itself rather than trusting an engagement still in flight.
    fn engage(&self) {
        let _ = self
            .mode
            .compare_exchange(OPEN, ENGAGING, Ordering::AcqRel, Ordering::Acquire);
        heavy_barrier();
        let mut spins: u32 = 0;
        while self.fast.load(Ordering::Acquire) {
            backoff(&mut spins);
        }
        self.mode.store(ENGAGED, Ordering::Release);
    }

    fn lock_held(&self) -> ConsumerGuard<'_> {
        let mut spins: u32 = 0;
        loop {
            if !self.held.load(Ordering::Relaxed)
                && self
                    .held
                    .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
                    .is_ok()
            {
                return ConsumerGuard {
                    gate: self,
                    fast: false,
                    _not_send: PhantomData,
                };
            }
            backoff(&mut spins);
        }
    }
}

impl ConsumerGuard<'_> {
    /// Whether this guard is an owner's plain-access section.
    #[cfg(test)]
    pub(super) fn is_fast(&self) -> bool {
        self.fast
    }
}

impl Drop for ConsumerGuard<'_> {
    #[inline]
    fn drop(&mut self) {
        if self.fast {
            self.gate.fast.store(false, Ordering::Release);
        } else {
            self.gate.held.store(false, Ordering::Release);
        }
    }
}

/// Spin briefly, then yield: the holder's section is bounded by one pump
/// plus one cache pass.
fn backoff(spins: &mut u32) {
    if *spins < 64 {
        *spins += 1;
        std::hint::spin_loop();
    } else {
        std::thread::yield_now();
    }
}

/// A token naming the calling thread, unique for the life of the process
/// (never 0, never reused after the thread exits).
#[inline]
fn thread_token() -> u64 {
    thread_local! {
        static TOKEN: Cell<u64> = const { Cell::new(0) };
    }
    static NEXT: AtomicU64 = AtomicU64::new(1);
    TOKEN.with(|token| {
        let current = token.get();
        if current != 0 {
            return current;
        }
        // Exhausting u64 thread tokens takes 2^64 threads: saturate there
        // rather than panic.
        let fresh = NEXT
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |next| {
                next.checked_add(1)
            })
            .unwrap_or_else(|last| {
                debug_assert!(last != u64::MAX, "thread tokens are exhausted only at 2^64");
                log::error!("thread tokens exhausted: a thread shares token {last}");
                last
            });
        token.set(fresh);
        fresh
    })
}

#[cfg(target_os = "linux")]
mod membarrier {
    //! `membarrier(2)`, private expedited command. Registered once per
    //! process; the gate uses the owned regime only if the query, the
    //! registration and one run of the command itself succeed.
    //!
    //! The registration waits for an RCU grace period once the process has
    //! several threads (tens of milliseconds with six threads).
    //! It runs at the construction of the process's first gate, that is at
    //! the first DataReader's creation: setup time, never the take path.
    //! Registering lazily at the first engagement would move that wait into
    //! the steady state of an application, onto both its consumer threads.

    use std::sync::OnceLock;

    const MEMBARRIER_CMD_QUERY: libc::c_long = 0;
    const MEMBARRIER_CMD_GLOBAL: libc::c_long = 1;
    const MEMBARRIER_CMD_PRIVATE_EXPEDITED: libc::c_long = 1 << 3;
    const MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED: libc::c_long = 1 << 4;

    fn call(command: libc::c_long) -> libc::c_long {
        let flags: libc::c_long = 0;
        let cpu_id: libc::c_long = 0;
        // SAFETY: membarrier(2) takes two integers (command, flags) and a
        // cpu id, reads and writes no user memory, and reports failure
        // through its return value; any command value is safe to pass.
        unsafe { libc::syscall(libc::SYS_membarrier, command, flags, cpu_id) }
    }

    pub(super) fn available() -> bool {
        static AVAILABLE: OnceLock<bool> = OnceLock::new();
        *AVAILABLE.get_or_init(|| {
            let supported = call(MEMBARRIER_CMD_QUERY);
            let needed =
                MEMBARRIER_CMD_PRIVATE_EXPEDITED | MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED;
            supported >= 0
                && (supported & needed) == needed
                && call(MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED) == 0
                && call(MEMBARRIER_CMD_PRIVATE_EXPEDITED) == 0
        })
    }

    pub(super) fn barrier() {
        // Registered by `available`, which every gate in the owned regime
        // consulted at construction. Should the command fail anyway (a
        // seccomp filter installed since, or on this thread only), register
        // again and retry, then fall back to the global command, which needs
        // no registration (slower, the same guarantee). This is not fork
        // support: a gate held by a thread at fork time stays held in the
        // child, as any lock does. Should all fail, no owner section can be proven finished, and going on
        // would let two consumers into one ring.
        if call(MEMBARRIER_CMD_PRIVATE_EXPEDITED) == 0 {
            return;
        }
        if call(MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED) == 0
            && call(MEMBARRIER_CMD_PRIVATE_EXPEDITED) == 0
        {
            return;
        }
        let result = call(MEMBARRIER_CMD_GLOBAL);
        assert!(
            result == 0,
            "membarrier: no command available after registration: {}",
            std::io::Error::last_os_error()
        );
    }
}

#[cfg(all(target_os = "linux", not(miri)))]
fn heavy_barrier_available() -> bool {
    membarrier::available()
}

#[cfg(any(not(target_os = "linux"), miri))]
fn heavy_barrier_available() -> bool {
    false
}

#[cfg(target_os = "linux")]
fn heavy_barrier() {
    membarrier::barrier();
}

/// Never reached: without a heavy barrier every gate starts `ENGAGED`, and
/// only a gate short of `ENGAGED` engages. A full fence, should that change.
#[cfg(not(target_os = "linux"))]
fn heavy_barrier() {
    std::sync::atomic::fence(Ordering::SeqCst);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use std::sync::Arc;
    use std::time::Duration;

    /// The owned regime is what these tests are about; on a host without
    /// it every gate is engaged from the start and only the engaged-path
    /// assertions apply.
    fn owned_regime() -> bool {
        heavy_barrier_available()
    }

    #[test]
    fn the_first_consumer_owns_the_gate_and_enters_with_plain_accesses() {
        let gate = ConsumerGate::new();
        let first = gate.lock();
        assert_eq!(first.is_fast(), owned_regime());
        drop(first);
        assert_eq!(gate.lock().is_fast(), owned_regime());
        assert!(!gate.fast.load(Ordering::Relaxed), "the section is closed");
    }

    /// A second thread consumes while the owner is inside a section: it
    /// must wait for that section to end, and the gate is engaged for good
    /// afterwards, the owner included.
    #[test]
    fn a_second_consumer_waits_for_the_owners_section_and_engages_the_gate() {
        let gate = Arc::new(ConsumerGate::new());
        let owner_section = gate.lock();
        let (entered_tx, entered_rx) = mpsc::channel();
        let second = {
            let gate = Arc::clone(&gate);
            std::thread::spawn(move || {
                let guard = gate.lock();
                entered_tx.send(guard.is_fast()).expect("send");
                drop(guard);
            })
        };
        assert!(
            entered_rx.recv_timeout(Duration::from_millis(200)).is_err(),
            "the second consumer entered while the owner was inside"
        );
        drop(owner_section);
        let second_fast = entered_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("the second consumer enters once the owner leaves");
        assert!(!second_fast, "a second consumer takes the held flag");
        second.join().expect("second");
        assert_eq!(gate.mode.load(Ordering::Relaxed), ENGAGED);
        assert!(
            !gate.lock().is_fast(),
            "an engaged gate gives the owner the held flag too"
        );
    }

    /// A consumer that finds the gate being engaged has no proof the
    /// engager finished waiting for the owner: it must not go straight to
    /// the held flag while the owner is still inside its section.
    #[test]
    fn a_consumer_arriving_during_an_engagement_still_waits_for_the_owner() {
        if !owned_regime() {
            return;
        }
        let gate = Arc::new(ConsumerGate::new());
        let owner_section = gate.lock();
        assert!(owner_section.is_fast());
        let (entered_tx, entered_rx) = mpsc::channel();
        let spawn_consumer = |name: &'static str| {
            let gate = Arc::clone(&gate);
            let entered = entered_tx.clone();
            std::thread::spawn(move || {
                let guard = gate.lock();
                entered.send(name).expect("send");
                drop(guard);
            })
        };
        let first = spawn_consumer("first engager");
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while gate.mode.load(Ordering::Acquire) != ENGAGING {
            assert!(std::time::Instant::now() < deadline, "never engaging");
            std::thread::yield_now();
        }
        let second = spawn_consumer("second consumer");
        assert!(
            entered_rx.recv_timeout(Duration::from_millis(200)).is_err(),
            "a consumer entered while the owner was inside"
        );
        drop(owner_section);
        for _ in 0..2 {
            entered_rx
                .recv_timeout(Duration::from_secs(10))
                .expect("both enter once the owner leaves");
        }
        first.join().expect("first");
        second.join().expect("second");
    }

    /// The owner taking the gate again while inside a section would get a
    /// second guard whose drop ends the first section early: refused.
    #[test]
    fn the_owner_taking_the_gate_again_inside_a_section_panics() {
        if !owned_regime() {
            return;
        }
        let gate = ConsumerGate::new();
        let outer = gate.lock();
        assert!(outer.is_fast());
        let nested = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            drop(gate.lock());
        }));
        assert!(nested.is_err(), "a nested section was granted");
        assert!(
            gate.fast.load(Ordering::Relaxed),
            "the outer section is still open"
        );
        drop(outer);
        assert!(!gate.fast.load(Ordering::Relaxed));
    }

    /// An engagement that completes between the owner's first read of the
    /// mode and its `fast` store: the engager saw `fast` low and took the
    /// held flag, so the owner's second read of the mode is all that keeps
    /// it out. It must back out and wait for the held flag.
    #[test]
    fn an_engagement_inside_the_owners_window_is_seen_by_its_second_read() {
        if !owned_regime() {
            return;
        }
        let gate = Arc::new(ConsumerGate::new());
        drop(gate.lock());
        let released = Arc::new(AtomicBool::new(false));
        let engager = Arc::new(std::sync::Mutex::new(None));
        {
            let gate_for_hook = Arc::clone(&gate);
            let released = Arc::clone(&released);
            let engager = Arc::clone(&engager);
            gate.set_pre_section_hook(move || {
                let (entered_tx, entered_rx) = mpsc::channel();
                let handle = std::thread::spawn(move || {
                    let guard = gate_for_hook.lock();
                    assert!(!guard.is_fast());
                    entered_tx.send(()).expect("send");
                    std::thread::sleep(Duration::from_millis(200));
                    released.store(true, Ordering::SeqCst);
                    drop(guard);
                });
                entered_rx
                    .recv_timeout(Duration::from_secs(10))
                    .expect("the engager enters while the owner has not raised fast");
                *engager.lock().expect("engager") = Some(handle);
            });
        }
        let guard = gate.lock();
        assert!(!guard.is_fast(), "the owner entered the engaged gate fast");
        assert!(
            released.load(Ordering::SeqCst),
            "the owner entered while the engager held the gate"
        );
        drop(guard);
        let handle = engager.lock().expect("engager").take().expect("spawned");
        handle.join().expect("engager");
    }

    /// The owner's token dies with its thread: a thread started after the
    /// owner exited is another consumer and engages.
    #[test]
    fn a_thread_started_after_the_owner_exited_is_not_the_owner() {
        let gate = Arc::new(ConsumerGate::new());
        {
            let gate = Arc::clone(&gate);
            std::thread::spawn(move || assert_eq!(gate.lock().is_fast(), owned_regime()))
                .join()
                .expect("owner");
        }
        let later = Arc::clone(&gate);
        let fast = std::thread::spawn(move || later.lock().is_fast())
            .join()
            .expect("later");
        assert!(!fast);
        assert_eq!(gate.mode.load(Ordering::Relaxed), ENGAGED);
    }
}
