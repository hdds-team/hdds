// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Joining the threads an entity owns when it is dropped.
//!
//! A participant's drop is synchronous: when it returns, every thread it
//! started has ended and released what it held (sockets, shared memory, the
//! transport). Two things can stand in the way, and both are handled here:
//!
//! - **a thread that does not end**: [`join_bounded`] waits for it, warns
//!   once past [`JOIN_WARN_AFTER`] and gives up past [`JOIN_GIVE_UP_AFTER`],
//!   so a stuck thread costs a log line and a leak, never a hung drop;
//! - **joining the thread that is dropping**: a thread cannot wait for its
//!   own end. [`join_bounded`] never joins the calling thread, and a
//!   participant dropped on one of its own threads (from a listener callback)
//!   recognises it through [`current_owner`] and hands its teardown to a
//!   thread of its own instead (`Participant::drop`).
//!
//! Ownership is a thread-local mark, inherited at spawn: a participant's
//! build runs under [`OwnerScope`], and every thread body wrapped in
//! [`owned`] carries the mark of the thread that spawned it, so the threads
//! its threads start later are marked too.

use std::cell::Cell;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

/// Past this, a join still waiting logs a warning (once).
pub(crate) const JOIN_WARN_AFTER: Duration = Duration::from_secs(2);

/// Past this, a join gives up: the thread is left to end on its own, and
/// what it holds is released only when it does.
pub(crate) const JOIN_GIVE_UP_AFTER: Duration = Duration::from_secs(10);

thread_local! {
    /// The participant (its process-local token) whose thread this is.
    static OWNER: Cell<Option<u64>> = const { Cell::new(None) };
}

/// The owner of the calling thread, if it is a thread of a participant.
pub(crate) fn current_owner() -> Option<u64> {
    OWNER.try_with(Cell::get).ok().flatten()
}

/// Marks the calling thread as `owner`'s while alive, so the threads it
/// spawns with an [`owned`] body are `owner`'s. Restores the previous mark
/// on drop (a participant built from a listener of another one).
pub(crate) struct OwnerScope {
    previous: Option<u64>,
}

impl OwnerScope {
    pub(crate) fn enter(owner: u64) -> Self {
        let previous = OWNER
            .try_with(|cell| cell.replace(Some(owner)))
            .ok()
            .flatten();
        Self { previous }
    }
}

impl Drop for OwnerScope {
    fn drop(&mut self) {
        let _ = OWNER.try_with(|cell| cell.set(self.previous));
    }
}

/// The thread body `f`, run under the owner of the thread calling `owned`:
/// `thread::spawn(owned(move || ...))` starts a thread of the same
/// participant as the caller's.
pub(crate) fn owned<F, T>(f: F) -> impl FnOnce() -> T + Send + 'static
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    let owner = current_owner();
    move || {
        if let Some(owner) = owner {
            let _ = OWNER.try_with(|cell| cell.set(Some(owner)));
        }
        let result = f();
        #[cfg(any(test, feature = "test-support"))]
        linger_for_test();
        result
    }
}

/// Tests only: how long an [`owned`] thread lingers once its body has
/// returned, unless it is being joined (`set_exit_linger_for_test`).
#[cfg(any(test, feature = "test-support"))]
static EXIT_LINGER_MS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Tests only: the threads a [`join_bounded`] is waiting for.
// @audit-ok: compiled only for tests and the test-support feature; the set
// of threads being joined is process-wide by nature.
#[cfg(any(test, feature = "test-support"))]
static BEING_JOINED: std::sync::Mutex<Vec<thread::ThreadId>> = std::sync::Mutex::new(Vec::new());

/// Tests only: make every [`owned`] thread linger up to `linger` after its
/// body returns, unless a [`join_bounded`] is waiting for it, in which case
/// it ends at once. A thread its owner forgets to join is then still there
/// when the owner's drop returns, where without the linger it would most
/// often have ended already, and a test counting threads would pass.
#[cfg(any(test, feature = "test-support"))]
pub fn set_exit_linger_for_test(linger: Duration) {
    let ms = u64::try_from(linger.as_millis()).unwrap_or(u64::MAX);
    EXIT_LINGER_MS.store(ms, std::sync::atomic::Ordering::Relaxed);
}

/// Tests only: the linger set by [`set_exit_linger_for_test`] (zero: none).
#[cfg(any(test, feature = "test-support"))]
pub(crate) fn exit_linger_for_test() -> Duration {
    Duration::from_millis(EXIT_LINGER_MS.load(std::sync::atomic::Ordering::Relaxed))
}

#[cfg(any(test, feature = "test-support"))]
fn linger_for_test() {
    let ms = EXIT_LINGER_MS.load(std::sync::atomic::Ordering::Relaxed);
    if ms == 0 {
        return;
    }
    let me = thread::current().id();
    let until = Instant::now() + Duration::from_millis(ms);
    while Instant::now() < until {
        let joined = BEING_JOINED
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains(&me);
        if joined {
            return;
        }
        thread::sleep(Duration::from_millis(1));
    }
}

/// Tests only: while alive, `id` reads as being joined (`linger_for_test`).
#[cfg(any(test, feature = "test-support"))]
struct Joining(thread::ThreadId);

#[cfg(any(test, feature = "test-support"))]
impl Joining {
    fn new(id: thread::ThreadId) -> Self {
        BEING_JOINED
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(id);
        Self(id)
    }
}

#[cfg(any(test, feature = "test-support"))]
impl Drop for Joining {
    fn drop(&mut self) {
        BEING_JOINED
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|id| *id != self.0);
    }
}

/// Join `handle`, `what` naming the thread in the logs.
///
/// Never joins the calling thread (that would wait forever, or panic): it is
/// left to end once it returns from what it is doing. Waits at most
/// [`JOIN_GIVE_UP_AFTER`]. Returns whether the thread was joined.
pub(crate) fn join_bounded<T>(handle: JoinHandle<T>, what: &str) -> bool {
    join_within(handle, what, JOIN_WARN_AFTER, JOIN_GIVE_UP_AFTER)
}

fn join_within<T>(
    handle: JoinHandle<T>,
    what: &str,
    warn_after: Duration,
    give_up: Duration,
) -> bool {
    if handle.thread().id() == thread::current().id() {
        log::debug!("[shutdown] {what}: dropped on its own thread, left to end on return");
        return false;
    }
    #[cfg(any(test, feature = "test-support"))]
    let _joining = Joining::new(handle.thread().id());
    let start = Instant::now();
    let mut pause = Duration::from_micros(20);
    let mut warned = false;
    while !handle.is_finished() {
        let waited = start.elapsed();
        if waited >= give_up {
            log::error!(
                "[shutdown] {what}: thread still running after {waited:?}; left behind, \
                 what it holds is released only when it ends"
            );
            return false;
        }
        if !warned && waited >= warn_after {
            warned = true;
            log::warn!("[shutdown] {what}: thread still running after {waited:?}, waiting");
        }
        thread::sleep(pause);
        pause = (pause * 2).min(Duration::from_millis(2));
    }
    let _ = handle.join();
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{mpsc, Arc};

    #[test]
    fn a_thread_that_ends_is_joined() {
        let ended = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&ended);
        let handle = thread::spawn(move || {
            thread::sleep(Duration::from_millis(30));
            flag.store(true, Ordering::SeqCst);
        });
        assert!(join_bounded(handle, "test"));
        assert!(ended.load(Ordering::SeqCst));
    }

    #[test]
    fn a_thread_that_does_not_end_is_left_past_the_bound() {
        let (release, wait) = mpsc::channel::<()>();
        let handle = thread::spawn(move || {
            let _ = wait.recv();
        });
        let start = Instant::now();
        assert!(!join_within(
            handle,
            "stuck",
            Duration::from_millis(20),
            Duration::from_millis(100)
        ));
        let waited = start.elapsed();
        assert!(waited >= Duration::from_millis(100), "{waited:?}");
        assert!(waited < Duration::from_secs(5), "{waited:?}");
        let _ = release.send(());
    }

    #[test]
    fn the_calling_thread_is_never_joined() {
        let (send, receive) = mpsc::channel::<JoinHandle<()>>();
        let (verdict_tx, verdict_rx) = mpsc::channel();
        let handle = thread::spawn(move || {
            let me = receive.recv().expect("own handle");
            let _ = verdict_tx.send(join_bounded(me, "self"));
        });
        send.send(handle).expect("hand the thread its own handle");
        assert_eq!(
            verdict_rx.recv_timeout(Duration::from_secs(5)),
            Ok(false),
            "a thread joining itself must return at once without joining"
        );
    }

    #[test]
    fn a_spawned_thread_inherits_the_owner_and_the_scope_restores_it() {
        assert_eq!(current_owner(), None);
        {
            let _outer = OwnerScope::enter(7);
            {
                let _inner = OwnerScope::enter(9);
                let seen = thread::spawn(owned(|| {
                    let child = current_owner();
                    let grandchild = thread::spawn(owned(current_owner)).join().expect("join");
                    (child, grandchild)
                }))
                .join()
                .expect("join");
                assert_eq!(seen, (Some(9), Some(9)));
            }
            assert_eq!(current_owner(), Some(7));
        }
        assert_eq!(current_owner(), None);
        let unowned = thread::spawn(owned(current_owner)).join().expect("join");
        assert_eq!(unowned, None);
        let plain = {
            let _scope = OwnerScope::enter(3);
            thread::spawn(current_owner).join().expect("join")
        };
        assert_eq!(plain, None, "a body not wrapped in `owned` is nobody's");
    }
}
