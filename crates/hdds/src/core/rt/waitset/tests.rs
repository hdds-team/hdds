// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

#![allow(clippy::unwrap_used)] // test scaffolding

use super::bitmap::AtomicBitset;
use super::driver::{internal, Deadline};
use super::{WaitsetDriver, WaitsetSignal, WaitsetWaitError, WAITSET_DEFAULT_MAX_SLOTS};
use std::sync::{mpsc, Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

/// Upper bound on how late a short timed wait may return. The lower bound
/// is the assertion that matters; this one only tells a wait that returned
/// from one that hung, so it is deliberately loose: a loaded CI box can
/// pause a process for hundreds of milliseconds, which a tight bound would
/// report as a failure.
const GENEROUS_OVERSHOOT: Duration = Duration::from_secs(2);

#[test]
fn register_slot_increments_table() {
    let driver = WaitsetDriver::new(8).expect("driver");
    assert_eq!(internal::slots_len(&driver), 0);

    let reg = driver.register_slot().expect("register");
    let (_slot, _id, signal) = reg.into_trait();
    signal.signal();

    let signaled = driver.wait(Some(Duration::from_millis(10))).expect("wait");
    assert_eq!(signaled.len(), 1);
}

#[test]
fn manual_notify_wakes_wait() {
    let driver = WaitsetDriver::new(WAITSET_DEFAULT_MAX_SLOTS).expect("driver");
    let reg = driver.register_slot().expect("register");
    let (slot_index, slot_id, _signal) = reg.into_trait();

    driver.manual_notify();
    let _ = driver.wait(Some(Duration::from_millis(10)));

    assert!(driver.unregister_slot(slot_index, slot_id));
}

#[test]
fn signal_multiple_slots_once() {
    let driver = Arc::new(WaitsetDriver::new(16).expect("driver"));

    let (slot_a, _, signal_a) = driver.register_slot().expect("slot a").into_trait();
    let (slot_b, _, signal_b) = driver.register_slot().expect("slot b").into_trait();

    signal_a.signal();
    signal_b.signal();

    let mut signaled = driver.wait(Some(Duration::from_millis(10))).expect("wait");
    signaled.sort_unstable();

    assert_eq!(signaled, vec![slot_a, slot_b]);
}

// ---------------------------------------------------------------------------
// Timeout precision
// ---------------------------------------------------------------------------

/// The wait must not end before the requested duration: 1.5 ms must not be
/// truncated to poll(..., 1), which would time out 0.5 ms early.
#[test]
fn wait_timeout_is_not_truncated_to_whole_milliseconds() {
    let driver = WaitsetDriver::new(8).expect("driver");
    let (_slot, _id, _signal) = driver.register_slot().expect("register").into_trait();

    let timeout = Duration::from_micros(1500);
    let start = Instant::now();
    let result = driver.wait(Some(timeout));
    let elapsed = start.elapsed();

    assert!(matches!(result, Err(WaitsetWaitError::Timeout)));
    assert!(
        elapsed >= timeout,
        "driver.wait timed out after {elapsed:?}, before the {timeout:?} deadline"
    );
    assert!(
        elapsed < GENEROUS_OVERSHOOT,
        "driver.wait overshot the {timeout:?} deadline by too much: {elapsed:?}"
    );
}

/// A timeout under one millisecond must block for its duration, not become
/// poll(..., 0), an immediate return that reports Timeout without blocking.
#[test]
fn wait_sub_millisecond_timeout_blocks_for_its_duration() {
    let driver = WaitsetDriver::new(8).expect("driver");
    let (_slot, _id, _signal) = driver.register_slot().expect("register").into_trait();

    let timeout = Duration::from_micros(300);
    let start = Instant::now();
    let result = driver.wait(Some(timeout));
    let elapsed = start.elapsed();

    assert!(matches!(result, Err(WaitsetWaitError::Timeout)));
    assert!(
        elapsed >= timeout,
        "driver.wait timed out after {elapsed:?}, before the {timeout:?} deadline"
    );
    assert!(
        elapsed < GENEROUS_OVERSHOOT,
        "driver.wait overshot the {timeout:?} deadline by too much: {elapsed:?}"
    );
}

/// A finite timeout stays finite even when its end does not fit an
/// `Instant`: the deadline is (start, total), not an end instant whose
/// `checked_add` failure would have to mean "no deadline".
#[test]
fn deadline_keeps_an_unrepresentable_total_finite() {
    assert!(Deadline::from_timeout(None).is_none());

    let huge = Deadline::from_timeout(Some(Duration::MAX)).expect("finite");
    assert!(!huge.expired());
    // Beyond any process lifetime and still counting down, not "forever".
    assert!(huge.remaining() > Duration::from_secs(1 << 40));

    let zero = Deadline::from_timeout(Some(Duration::ZERO)).expect("finite");
    assert!(zero.expired());
    assert_eq!(zero.remaining(), Duration::ZERO);

    let short = Deadline::from_timeout(Some(Duration::from_millis(20))).expect("finite");
    assert!(!short.expired());
    std::thread::sleep(Duration::from_millis(25));
    assert!(short.expired());
    assert_eq!(short.remaining(), Duration::ZERO);
}

/// A signal delivered to the waiting thread makes ppoll return EINTR. The
/// wait must go again for the remainder and still time out on its own
/// clock, neither returning early, nor as an error, nor being pushed past
/// the deadline by a stream of interrupts. The handler is a no-op; without
/// one the default action for SIGUSR1 would end the process.
#[cfg(target_os = "linux")]
#[test]
fn wait_under_a_signal_storm_still_times_out_on_its_clock() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::mpsc;

    extern "C" fn on_signal(_signal: libc::c_int) {}

    // SAFETY: a zeroed sigaction is a valid starting point; the handler is
    // an async-signal-safe no-op; the previous disposition is saved and
    // restored below, after the storm thread has been joined.
    let mut previous: libc::sigaction = unsafe { std::mem::zeroed() };
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    action.sa_sigaction = on_signal as extern "C" fn(libc::c_int) as libc::sighandler_t;
    unsafe {
        libc::sigemptyset(&mut action.sa_mask);
        assert_eq!(libc::sigaction(libc::SIGUSR1, &action, &mut previous), 0);
    }

    let driver = Arc::new(WaitsetDriver::new(8).expect("driver"));
    let (_slot, _id, _signal) = driver.register_slot().expect("register").into_trait();
    let timeout = Duration::from_millis(50);

    let done = Arc::new(AtomicBool::new(false));
    let (thread_tx, thread_rx) = mpsc::channel::<libc::pthread_t>();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let waiter = {
        let driver = Arc::clone(&driver);
        let done = Arc::clone(&done);
        std::thread::spawn(move || {
            // SAFETY: pthread_self has no preconditions.
            thread_tx
                .send(unsafe { libc::pthread_self() })
                .expect("test thread is waiting on this");
            let start = Instant::now();
            let result = driver.wait(Some(timeout));
            let elapsed = start.elapsed();
            done.store(true, Ordering::Release);
            // Stay alive until the storm has stopped: a pthread_t must not
            // be signalled after its thread has exited.
            release_rx.recv().expect("test thread releases the waiter");
            (result, elapsed)
        })
    };

    let target = thread_rx.recv().expect("waiter thread started");
    let mut sent = 0u32;
    while !done.load(Ordering::Acquire) {
        // SAFETY: the target thread is alive until we send on release_tx.
        let ret = unsafe { libc::pthread_kill(target, libc::SIGUSR1) };
        assert_eq!(ret, 0, "pthread_kill failed with {ret}");
        sent += 1;
        std::thread::sleep(Duration::from_micros(500));
    }
    release_tx.send(()).expect("waiter is blocked on this");
    let (result, elapsed) = waiter.join().expect("waiter thread panicked");

    // SAFETY: restores the disposition saved above; no signal is in flight.
    unsafe {
        assert_eq!(
            libc::sigaction(libc::SIGUSR1, &previous, std::ptr::null_mut()),
            0
        );
    }

    assert!(sent > 0, "the storm never reached the waiter");
    assert!(
        matches!(result, Err(WaitsetWaitError::Timeout)),
        "expected Timeout under interrupts, got {result:?}"
    );
    assert!(
        elapsed >= timeout,
        "driver.wait returned after {elapsed:?}, before the {timeout:?} deadline"
    );
    assert!(
        elapsed < GENEROUS_OVERSHOOT,
        "driver.wait overshot the {timeout:?} deadline by too much: {elapsed:?}"
    );
}

// ---------------------------------------------------------------------------
// Bounded take_all
// ---------------------------------------------------------------------------

/// Bits in words beyond the bound must survive a bounded take: that is the
/// observable proof those words were not swapped.
#[test]
fn bitmap_take_all_visits_only_words_below_bound() {
    let bits_per_word = usize::BITS as usize;
    let bitmap = AtomicBitset::new(WAITSET_DEFAULT_MAX_SLOTS);
    let in_word_zero = 3;
    let in_word_one = bits_per_word + 36;

    assert!(!bitmap.test_and_set(in_word_zero));
    assert!(!bitmap.test_and_set(in_word_one));

    // Bound covers word 0 only: word 1 is left untouched.
    assert_eq!(bitmap.take_all(bits_per_word), vec![in_word_zero]);
    assert_eq!(bitmap.take_all(bits_per_word), Vec::<usize>::new());

    // A full-capacity bound still finds the bit parked in word 1.
    assert_eq!(
        bitmap.take_all(WAITSET_DEFAULT_MAX_SLOTS),
        vec![in_word_one]
    );
}

/// The bound is word-granular: bound 1 (only slot 0 registered) still takes
/// every bit of word 0, which callers tolerate.
#[test]
fn bitmap_take_all_bound_is_word_granular() {
    let bits_per_word = usize::BITS as usize;
    let bitmap = AtomicBitset::new(WAITSET_DEFAULT_MAX_SLOTS);
    let last_in_word_zero = bits_per_word - 1;

    assert!(!bitmap.test_and_set(last_in_word_zero));
    assert_eq!(bitmap.take_all(1), vec![last_in_word_zero]);
}

#[test]
fn bitmap_take_all_bound_zero_visits_nothing() {
    let bitmap = AtomicBitset::new(WAITSET_DEFAULT_MAX_SLOTS);

    assert!(!bitmap.test_and_set(0));
    assert_eq!(bitmap.take_all(0), Vec::<usize>::new());
    assert_eq!(bitmap.take_all(1), vec![0]);
}

/// A bound past the capacity is clamped to the word count rather than
/// indexing out of range.
#[test]
fn bitmap_take_all_bound_past_capacity_is_clamped() {
    let bitmap = AtomicBitset::new(8);

    assert!(!bitmap.test_and_set(7));
    assert_eq!(bitmap.take_all(usize::MAX), vec![7]);
}

#[test]
fn bitmap_clear_resets_a_set_bit() {
    let bitmap = AtomicBitset::new(WAITSET_DEFAULT_MAX_SLOTS);

    assert!(!bitmap.test_and_set(5));
    assert!(bitmap.test_and_set(5));
    bitmap.clear(5);
    assert!(!bitmap.test_and_set(5));
    assert_eq!(bitmap.take_all(WAITSET_DEFAULT_MAX_SLOTS), vec![5]);
}

// ---------------------------------------------------------------------------
// Slot bound maintenance
// ---------------------------------------------------------------------------

#[test]
fn slot_bound_tracks_highest_registered_slot() {
    let driver = WaitsetDriver::new(WAITSET_DEFAULT_MAX_SLOTS).expect("driver");
    assert_eq!(internal::slot_bound(&driver), 0);

    let mut regs: Vec<(usize, u64, Arc<dyn WaitsetSignal>)> = Vec::new();
    for expected_index in 0..65 {
        let reg = driver.register_slot().expect("register").into_trait();
        assert_eq!(reg.0, expected_index);
        regs.push(reg);
        assert_eq!(internal::slot_bound(&driver), expected_index + 1);
    }

    // Releasing the highest slot lowers the bound to the next live one.
    let (index, id, _) = regs.pop().unwrap();
    assert_eq!(index, 64);
    assert!(driver.unregister_slot(index, id));
    assert_eq!(internal::slot_bound(&driver), 64);

    // Releasing a slot in the middle punches a hole but keeps the bound.
    let (index, id, _) = regs.remove(10);
    assert_eq!(index, 10);
    assert!(driver.unregister_slot(index, id));
    assert_eq!(internal::slot_bound(&driver), 64);

    // Releasing from the top down walks the bound past the hole.
    while let Some((index, id, _)) = regs.pop() {
        assert!(driver.unregister_slot(index, id));
        let expected = if index == 11 { 10 } else { index };
        assert_eq!(
            internal::slot_bound(&driver),
            expected,
            "after slot {index}"
        );
    }
    assert_eq!(internal::slot_bound(&driver), 0);

    // A stale (index, id) pair is refused and leaves the bound alone.
    assert!(!driver.unregister_slot(64, 1));
    assert_eq!(internal::slot_bound(&driver), 0);
}

/// One registration means one word: a bit parked in word 1 must survive a
/// wakeup, which proves `wait` handed take_all a one-word bound.
#[test]
fn wait_with_one_registration_takes_only_word_zero() {
    let driver = WaitsetDriver::new(WAITSET_DEFAULT_MAX_SLOTS).expect("driver");
    let (slot, _id, signal) = driver.register_slot().expect("register").into_trait();
    assert_eq!(slot, 0);

    let parked = usize::BITS as usize + 36;
    assert!(!internal::plant_bit(&driver, parked));

    signal.signal();
    let signaled = driver.wait(Some(Duration::from_millis(100))).expect("wait");
    assert_eq!(signaled, vec![slot]);

    // Still set: word 1 was not swapped by the bounded take.
    assert!(internal::plant_bit(&driver, parked));
}

/// A signal handle is a separately owned Arc the driver never revokes, so a
/// holder can call signal() after the slot was unregistered (this test does
/// exactly that). Once the bound has dropped below that word the bit is
/// never taken, and if the index is then reused the new owner's first signal
/// would see "already set" and skip the event write. Registration clears the
/// bit so the new owner's wakeup is never lost.
#[test]
fn stale_signal_after_unregister_cannot_suppress_the_next_owner() {
    let driver = WaitsetDriver::new(WAITSET_DEFAULT_MAX_SLOTS).expect("driver");
    let bits_per_word = usize::BITS as usize;

    let mut regs: Vec<(usize, u64, Arc<dyn WaitsetSignal>)> = Vec::new();
    for _ in 0..=bits_per_word {
        regs.push(driver.register_slot().expect("register").into_trait());
    }
    let (index, id, stale_signal) = regs.pop().unwrap();
    assert_eq!(index, bits_per_word);

    assert!(driver.unregister_slot(index, id));
    assert_eq!(internal::slot_bound(&driver), bits_per_word);

    // The stale signal lands in word 1, beyond the bound: the wake is
    // spurious and the bit stays behind.
    stale_signal.signal();
    let signaled = driver.wait(Some(Duration::from_millis(100))).expect("wake");
    assert!(signaled.is_empty());

    // The index is reused (LIFO free list) and its first signal must wake.
    let (reused, _id, new_signal) = driver.register_slot().expect("register").into_trait();
    assert_eq!(reused, index);
    new_signal.signal();
    let signaled = driver.wait(Some(Duration::from_millis(100))).expect("wake");
    assert_eq!(signaled, vec![index]);
}

/// The straggler can also land after the index has a new owner. Registration
/// raises the bound and clears the bit in one critical section, so from
/// then on a bit the straggler sets sits in a word the next take_all
/// visits: the event the straggler wrote is the wake, and the new owner's
/// own signal, which finds the bit already set and stays silent, rides on
/// it instead of being lost.
///
/// The interleaving inside registration itself (a straggler right after
/// the clear, with the slot mutex still held) is covered by
/// `stale_signal_inside_the_register_window_cannot_suppress_the_next_owner`.
/// This test pins the state the API can reach: bound raised, bit clear,
/// straggler and new owner both signalling the reused index.
#[test]
fn stale_signal_after_reregister_is_taken_by_the_next_wait() {
    let driver = WaitsetDriver::new(WAITSET_DEFAULT_MAX_SLOTS).expect("driver");
    let bits_per_word = usize::BITS as usize;

    let mut regs: Vec<(usize, u64, Arc<dyn WaitsetSignal>)> = Vec::new();
    for _ in 0..=bits_per_word {
        regs.push(driver.register_slot().expect("register").into_trait());
    }
    let (index, id, stale_signal) = regs.pop().unwrap();
    assert_eq!(index, bits_per_word);
    assert!(driver.unregister_slot(index, id));
    assert_eq!(internal::slot_bound(&driver), bits_per_word);

    // Reuse the index: the bit is clear (the plant finds it unset) and the
    // bound covers word 1 again (a wake takes the planted bit).
    let (reused, _id, new_signal) = driver.register_slot().expect("register").into_trait();
    assert_eq!(reused, index);
    assert_eq!(internal::slot_bound(&driver), bits_per_word + 1);
    assert!(!internal::plant_bit(&driver, index));
    driver.manual_notify();
    let signaled = driver.wait(Some(Duration::from_millis(100))).expect("wake");
    assert_eq!(signaled, vec![index]);

    // Straggler first (sets the bit, writes the event), new owner second
    // (finds the bit set, writes nothing): one wake, the index reported.
    stale_signal.signal();
    new_signal.signal();
    let signaled = driver.wait(Some(Duration::from_millis(100))).expect("wake");
    assert_eq!(signaled, vec![index]);

    // The word is clean again: the new owner wakes on its own, and nothing
    // is left pending after that.
    new_signal.signal();
    let signaled = driver.wait(Some(Duration::from_millis(100))).expect("wake");
    assert_eq!(signaled, vec![index]);
    assert!(matches!(
        driver.wait(Some(Duration::from_millis(1))),
        Err(WaitsetWaitError::Timeout)
    ));
}

/// The spot inside registration right after the reused bit is cleared: a
/// straggler signals the reused index there, and a waiter tries to take
/// it. The clear sits in the critical section that raised the bound, and
/// `wait` reads the bound inside that same mutex, so the waiter blocks
/// until registration is over and then reads a bound that covers the
/// word: it takes the stale bit, and the new owner's first signal writes
/// its own event. If the clear ran before the bound was raised, outside
/// the mutex, or if `wait` read the bound outside it, the waiter could
/// finish inside this window with the old bound: it would drain the
/// straggler's event and skip the word, the stale bit would survive, and
/// the new owner's first signal would find it set and write nothing, so
/// the last wait below would time out. The hook fires right after the
/// clear on the registering thread, so the waiter is a second thread; the
/// hook gives it a moment, which it can only use if the mutex is free.
/// "The waiter finished inside the window" is therefore the failure
/// signal, checked before anything else.
#[test]
fn stale_signal_inside_the_register_window_cannot_suppress_the_next_owner() {
    /// How long the hook waits for the waiter before concluding it is
    /// blocked on the slot mutex. Long against a thread spawn plus one
    /// unblocked wakeup, which is how long a waiter that is not blocked takes.
    const WINDOW: Duration = Duration::from_millis(200);

    let driver = Arc::new(WaitsetDriver::new(WAITSET_DEFAULT_MAX_SLOTS).expect("driver"));
    let bits_per_word = usize::BITS as usize;

    let mut regs: Vec<(usize, u64, Arc<dyn WaitsetSignal>)> = Vec::new();
    for _ in 0..=bits_per_word {
        regs.push(driver.register_slot().expect("register").into_trait());
    }
    let (index, id, stale_signal) = regs.pop().unwrap();
    assert_eq!(index, bits_per_word);
    assert!(driver.unregister_slot(index, id));
    assert_eq!(internal::slot_bound(&driver), bits_per_word);

    type WaiterHandle = JoinHandle<Result<Vec<usize>, WaitsetWaitError>>;
    let waiter: Arc<Mutex<Option<WaiterHandle>>> = Arc::new(Mutex::new(None));
    // Whether the waiter reported back while the hook still held the slot
    // mutex, read after registration; None if the hook never ran.
    let finished_in_window: Arc<Mutex<Option<bool>>> = Arc::new(Mutex::new(None));
    internal::set_register_hook(&driver, {
        let driver = Arc::clone(&driver);
        let waiter = Arc::clone(&waiter);
        let finished_in_window = Arc::clone(&finished_in_window);
        Box::new(move || {
            stale_signal.signal();
            let (done_tx, done_rx) = mpsc::channel();
            *waiter.lock().unwrap() = Some(thread::spawn(move || {
                let seen = driver.wait(Some(Duration::from_secs(2)));
                // The hook has usually given up on the receiver by now;
                // that is the expected outcome, not an error.
                let _ = done_tx.send(());
                seen
            }));
            *finished_in_window.lock().unwrap() = Some(done_rx.recv_timeout(WINDOW).is_ok());
        })
    });

    let (reused, _id, new_signal) = driver.register_slot().expect("register").into_trait();
    assert_eq!(reused, index);
    assert_eq!(internal::slot_bound(&driver), bits_per_word + 1);

    let finished_in_window = finished_in_window
        .lock()
        .unwrap()
        .take()
        .expect("the register hook must have run");
    assert!(
        !finished_in_window,
        "a waiter completed inside the register window: it read a bound not covering the reused word"
    );

    // Released with the mutex, the waiter read the raised bound and took
    // the stale bit.
    let seen = waiter
        .lock()
        .unwrap()
        .take()
        .expect("the hook spawned the waiter")
        .join()
        .expect("waiter thread panicked")
        .expect("the straggler's event wakes the waiter");
    assert_eq!(seen, vec![index]);

    // The new owner's first signal must wake on its own event.
    new_signal.signal();
    let signaled = driver
        .wait(Some(Duration::from_millis(100)))
        .expect("the new owner's first signal must wake the waiter");
    assert_eq!(signaled, vec![index]);
}

/// `wait` reads the bound after it wakes, not before it blocks: a slot
/// registered while the waiter sleeps must be visited by the wakeup its
/// first signal causes. Read before blocking, the bound would be 0 here,
/// the wakeup would visit no word, and the signal would be reported as an
/// empty wake with its bit left set. The head start only makes the waiter
/// likely to be asleep before the registration; a late waiter reads the
/// raised bound either way, so this passes deterministically and detects
/// a bound read before blocking whenever the head start is enough.
#[test]
fn wait_reads_the_bound_after_the_wakeup_not_before() {
    let driver = Arc::new(WaitsetDriver::new(WAITSET_DEFAULT_MAX_SLOTS).expect("driver"));
    assert_eq!(internal::slot_bound(&driver), 0);

    let waiter = {
        let driver = Arc::clone(&driver);
        thread::spawn(move || driver.wait(Some(Duration::from_secs(2))))
    };
    thread::sleep(Duration::from_millis(50));

    let (slot, _id, signal) = driver.register_slot().expect("register").into_trait();
    assert_eq!(slot, 0);
    signal.signal();

    let seen = waiter
        .join()
        .expect("waiter thread panicked")
        .expect("the first signal wakes the waiter");
    assert_eq!(seen, vec![slot]);
}
