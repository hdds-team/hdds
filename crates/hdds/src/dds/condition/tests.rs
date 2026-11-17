// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

use super::*;

#[test]
fn test_status_mask_bits() {
    assert_eq!(StatusMask::NONE.bits(), 0);
    assert_eq!(StatusMask::DATA_AVAILABLE.bits(), 1);
    assert_eq!(StatusMask::SAMPLE_LOST.bits(), 2);
}

#[test]
fn test_status_mask_contains() {
    let mask = StatusMask::DATA_AVAILABLE | StatusMask::SAMPLE_LOST;
    assert!(mask.contains(StatusMask::DATA_AVAILABLE));
    assert!(mask.contains(StatusMask::SAMPLE_LOST));
    assert!(!mask.contains(StatusMask::LIVELINESS_CHANGED));
}

#[test]
fn test_status_mask_or() {
    let mask1 = StatusMask::DATA_AVAILABLE;
    let mask2 = StatusMask::SAMPLE_LOST;
    let combined = mask1 | mask2;
    assert!(combined.contains(StatusMask::DATA_AVAILABLE));
    assert!(combined.contains(StatusMask::SAMPLE_LOST));
}

#[test]
fn test_status_mask_and() {
    let mask1 = StatusMask::DATA_AVAILABLE | StatusMask::SAMPLE_LOST;
    let mask2 = StatusMask::DATA_AVAILABLE | StatusMask::LIVELINESS_CHANGED;
    let intersection = mask1 & mask2;
    assert!(intersection.contains(StatusMask::DATA_AVAILABLE));
    assert!(!intersection.contains(StatusMask::SAMPLE_LOST));
    assert!(!intersection.contains(StatusMask::LIVELINESS_CHANGED));
}

#[test]
fn test_status_condition_default() {
    let cond = StatusCondition::new();
    assert!(!cond.get_trigger_value());
    assert_eq!(cond.get_enabled_statuses().bits(), 0);
    assert_eq!(cond.get_active_statuses().bits(), 0);
}

#[test]
fn test_status_condition_set_enabled() {
    let cond = StatusCondition::new();
    cond.set_enabled_statuses(StatusMask::DATA_AVAILABLE);
    assert_eq!(
        cond.get_enabled_statuses().bits(),
        StatusMask::DATA_AVAILABLE.bits()
    );
}

#[test]
fn test_status_condition_trigger() {
    let cond = StatusCondition::new();
    cond.set_enabled_statuses(StatusMask::DATA_AVAILABLE);
    assert!(!cond.get_trigger_value());

    cond.set_active_statuses(StatusMask::DATA_AVAILABLE);
    assert!(cond.get_trigger_value());

    cond.clear_active_statuses();
    assert!(!cond.get_trigger_value());
}

#[test]
fn test_status_condition_multiple_statuses() {
    let cond = StatusCondition::new();
    cond.set_enabled_statuses(StatusMask::DATA_AVAILABLE | StatusMask::LIVELINESS_CHANGED);

    cond.set_active_statuses(StatusMask::DATA_AVAILABLE);
    assert!(cond.get_trigger_value());

    cond.set_active_statuses(StatusMask::LIVELINESS_CHANGED);
    assert!(cond.get_trigger_value());

    // A status outside the enabled set does not trigger on its own.
    cond.clear_active_statuses();
    cond.set_active_statuses(StatusMask::SAMPLE_LOST);
    assert!(!cond.get_trigger_value());
}

/// Raises into the mask never overwrite each other. Two raises of
/// different statuses accumulate, a repeated raise changes nothing, and
/// the clear reports the union it removed. DATA_AVAILABLE passed here
/// lands in the mask like any other bit (the production producers use
/// the wake words instead, tested below).
#[test]
fn set_active_statuses_accumulates_across_producers() {
    let cond = StatusCondition::new();
    cond.set_enabled_statuses(StatusMask::DATA_AVAILABLE);

    cond.set_active_statuses(StatusMask::LIVELINESS_CHANGED);
    assert_eq!(cond.get_active_statuses(), StatusMask::LIVELINESS_CHANGED);
    assert!(!cond.get_trigger_value());

    cond.set_active_statuses(StatusMask::DATA_AVAILABLE);
    assert_eq!(
        cond.get_active_statuses(),
        StatusMask::DATA_AVAILABLE | StatusMask::LIVELINESS_CHANGED
    );
    assert!(cond.get_trigger_value());

    cond.set_active_statuses(StatusMask::DATA_AVAILABLE);
    assert_eq!(
        cond.get_active_statuses(),
        StatusMask::DATA_AVAILABLE | StatusMask::LIVELINESS_CHANGED
    );

    assert_eq!(
        cond.clear_active_statuses(),
        StatusMask::DATA_AVAILABLE | StatusMask::LIVELINESS_CHANGED
    );
    assert_eq!(cond.get_active_statuses(), StatusMask::NONE);
}

#[test]
fn test_guard_condition_default() {
    let guard = GuardCondition::new();
    assert!(!guard.get_trigger_value());
}

#[test]
fn test_guard_condition_set_trigger() {
    let guard = GuardCondition::new();

    guard.set_trigger_value(true);
    assert!(guard.get_trigger_value());

    guard.set_trigger_value(false);
    assert!(!guard.get_trigger_value());
}

#[test]
fn test_condition_ids_unique() {
    let cond1 = StatusCondition::new();
    let cond2 = StatusCondition::new();
    let guard1 = GuardCondition::new();
    let guard2 = GuardCondition::new();

    assert_ne!(cond1.condition_id(), cond2.condition_id());
    assert_ne!(guard1.condition_id(), guard2.condition_id());
}

/// Multi-thread storm over the atomic mask fast path (post17 perf wave:
/// `enabled_statuses`/`active_statuses` AtomicU32 + `waitset_hook_count`
/// AtomicUsize). Lives here rather than in `tests/concurrency_stress.rs`
/// because `set_active_statuses` is `pub(crate)`.
#[test]
fn test_status_condition_set_active_vs_read_storm() {
    use crate::core::rt::waitset::WaitsetSignal;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Barrier};
    use std::thread;

    const WRITERS: u32 = 4;
    const READERS: u32 = 4;
    const ITERS: u32 = 5_000;

    struct CountingSignal {
        id: u64,
        hits: AtomicUsize,
    }
    impl WaitsetSignal for CountingSignal {
        fn signal(&self) {
            self.hits.fetch_add(1, Ordering::Relaxed);
        }
        fn id(&self) -> u64 {
            self.id
        }
    }

    let cond = Arc::new(StatusCondition::new());
    cond.set_enabled_statuses(StatusMask::ALL);
    let signal = Arc::new(CountingSignal {
        id: 0xC0FFEE,
        hits: AtomicUsize::new(0),
    });
    cond.add_waitset_signal(Arc::clone(&signal) as Arc<dyn WaitsetSignal>);

    let barrier = Arc::new(Barrier::new((WRITERS + READERS) as usize));
    let mut handles = Vec::new();

    for t in 0..WRITERS {
        let cond = Arc::clone(&cond);
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            barrier.wait();
            for i in 0..ITERS {
                if (i + t) % 2 == 0 {
                    cond.set_active_statuses(StatusMask::DATA_AVAILABLE);
                } else {
                    cond.clear_active_statuses();
                }
            }
        }));
    }

    for _ in 0..READERS {
        let cond = Arc::clone(&cond);
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            barrier.wait();
            for _ in 0..ITERS {
                let active = cond.get_active_statuses().bits();
                assert!(
                    active == 0 || active == StatusMask::DATA_AVAILABLE.bits(),
                    "active mask must never tear: got {active:#x}"
                );
                // Trigger derives from enabled & active; both are atomic,
                // so the read must never panic and always be a plain bool.
                let _ = cond.get_trigger_value();
            }
        }));
    }

    for handle in handles {
        handle.join().expect("condition storm thread panicked");
    }

    // Deterministic post-storm state.
    cond.set_active_statuses(StatusMask::DATA_AVAILABLE);
    assert!(cond.get_trigger_value());
    assert!(
        signal.hits.load(Ordering::Relaxed) > 0,
        "waitset hook must have been signalled at least once"
    );
    cond.clear_active_statuses();
    assert!(!cond.get_trigger_value());
}

/// The clear reports what it removed: the reader derives "a producer
/// stored before my clear, re-check the rings" from a non-zero return
/// and "nothing to do" from zero. Clearing an already-clear mask must
/// report zero (it is skipped without an RMW), and a mask set again
/// afterwards must be reported by the next clear.
#[test]
fn clear_active_statuses_returns_the_previous_mask() {
    let cond = StatusCondition::new();
    cond.set_enabled_statuses(StatusMask::DATA_AVAILABLE);

    assert_eq!(cond.clear_active_statuses(), StatusMask::NONE);

    cond.set_active_statuses(StatusMask::DATA_AVAILABLE | StatusMask::LIVELINESS_CHANGED);
    assert_eq!(
        cond.clear_active_statuses(),
        StatusMask::DATA_AVAILABLE | StatusMask::LIVELINESS_CHANGED
    );
    assert_eq!(cond.get_active_statuses(), StatusMask::NONE);
    assert!(!cond.get_trigger_value());

    assert_eq!(cond.clear_active_statuses(), StatusMask::NONE);

    cond.set_active_statuses(StatusMask::DATA_AVAILABLE);
    assert_eq!(cond.clear_active_statuses(), StatusMask::DATA_AVAILABLE);
    assert_eq!(cond.clear_active_statuses(), StatusMask::NONE);
}

// ---------------------------------------------------------------------------
// Wake words. Ordering is not testable on one thread; it is argued at
// `WakeWords` and at `DataReader::clear_data_available_if_idle` and
// exercised by the reader's stress tests. What these pin is the value
// protocol of one word: what a raise, a clear, a re-raise and a settle
// leave behind, what a clear returns, and that words are independent.
// ---------------------------------------------------------------------------

/// One word through its life: zero, RAISED after the producer's store,
/// returned by the clear, zero after it, RERAISED after the entity's
/// re-raise, a producer store landing on a re-raised word keeps both
/// bits, and a settle drops everything.
#[test]
fn wake_word_raise_clear_re_raise_protocol() {
    let cond = StatusCondition::new();
    let words = cond.wake_words();
    assert_eq!(words.clear(0), 0, "a fresh word clears to nothing");
    assert!(!words.any_raised());

    words.raise(0);
    assert_eq!(words.load(0), WAKE_RAISED);
    assert!(words.any_raised());

    // A repeated producer store changes nothing.
    words.raise(0);
    assert_eq!(words.load(0), WAKE_RAISED);

    assert_eq!(words.clear(0), WAKE_RAISED, "the clear reports the raise");
    assert_eq!(words.load(0), 0);
    assert!(!words.any_raised());
    assert_eq!(words.clear(0), 0, "a second clear reports nothing");

    // The entity found the producer's work still pending after its
    // clear: the re-raise is a distinct bit and it triggers.
    words.re_raise(0);
    assert_eq!(words.load(0), WAKE_RERAISED);
    assert!(words.any_raised());
    assert_eq!(
        words.clear(0),
        WAKE_RERAISED,
        "the next clear can tell the entity's own re-raise from a producer's raise"
    );

    // A producer store that lands after the re-raise overwrites it
    // (RAISED is what the next clear must see); a re-raise on a word
    // the producer raised in between keeps the producer's bit.
    words.re_raise(0);
    words.raise(0);
    assert_eq!(words.load(0), WAKE_RAISED);
    words.re_raise(0);
    assert_eq!(words.load(0), WAKE_RAISED | WAKE_RERAISED);
    assert_eq!(words.clear(0), WAKE_RAISED | WAKE_RERAISED);

    // A settle (the dispose drain) drops a raised word to zero.
    words.raise(0);
    words.settle(0);
    assert_eq!(words.load(0), 0);
    assert_eq!(words.clear(0), 0);
}

/// Words are independent: clearing one neither reads nor writes
/// another, and the trigger stays up while any word is raised.
#[test]
fn wake_words_are_independent() {
    let cond = StatusCondition::new();
    cond.set_enabled_statuses(StatusMask::DATA_AVAILABLE);
    let words = cond.wake_words();

    for word in 0..WAKE_WORDS {
        words.raise(word);
        assert!(cond.get_trigger_value(), "word {word} raised");
        for other in 0..WAKE_WORDS {
            if other != word {
                assert_eq!(words.clear(other), 0, "word {other} was not raised");
            }
        }
        assert!(
            cond.get_trigger_value(),
            "clearing the other words leaves word {word} raised"
        );
        assert_eq!(words.clear(word), WAKE_RAISED);
        assert!(!cond.get_trigger_value(), "word {word} cleared");
    }

    // Two words raised, cleared one at a time: the trigger follows the
    // last one down.
    words.raise(0);
    words.raise_shared(WAKE_WORDS - 1);
    assert_eq!(words.clear(0), WAKE_RAISED);
    assert!(cond.get_trigger_value());
    assert_eq!(words.clear(WAKE_WORDS - 1), WAKE_RAISED);
    assert!(!cond.get_trigger_value());
}

/// The shared word accumulates through the RMW raise: several raises
/// leave RAISED once, and a clear reports it once.
#[test]
fn shared_wake_word_accumulates() {
    let cond = StatusCondition::new();
    let words = cond.wake_words();
    words.raise_shared(2);
    words.raise_shared(2);
    words.re_raise(2);
    words.raise_shared(2);
    assert_eq!(words.load(2), WAKE_RAISED | WAKE_RERAISED);
    assert_eq!(words.clear(2), WAKE_RAISED | WAKE_RERAISED);
    assert_eq!(words.load(2), 0);
}

/// DATA_AVAILABLE is derived from the words: the trigger and the active
/// mask both report it while a word is raised and only when
/// DATA_AVAILABLE is enabled; the mask statuses keep their own path and
/// the mask clear does not touch the words.
#[test]
fn data_available_is_derived_from_the_wake_words() {
    let cond = StatusCondition::new();
    let words = cond.wake_words();

    // Not enabled: a raised word is reported active but does not trigger.
    words.raise(1);
    assert!(!cond.get_trigger_value());
    assert_eq!(cond.get_active_statuses(), StatusMask::DATA_AVAILABLE);

    cond.set_enabled_statuses(StatusMask::DATA_AVAILABLE | StatusMask::LIVELINESS_CHANGED);
    assert!(cond.get_trigger_value());

    // The mask clear leaves the words alone.
    assert_eq!(cond.clear_active_statuses(), StatusMask::NONE);
    assert!(cond.get_trigger_value());
    assert_eq!(cond.get_active_statuses(), StatusMask::DATA_AVAILABLE);

    // A mask status beside a raised word: the union is reported, and
    // clearing the word leaves the mask status triggering on its own.
    cond.set_active_statuses(StatusMask::LIVELINESS_CHANGED);
    assert_eq!(
        cond.get_active_statuses(),
        StatusMask::DATA_AVAILABLE | StatusMask::LIVELINESS_CHANGED
    );
    assert_eq!(words.clear(1), WAKE_RAISED);
    assert_eq!(cond.get_active_statuses(), StatusMask::LIVELINESS_CHANGED);
    assert!(cond.get_trigger_value());
    assert_eq!(cond.clear_active_statuses(), StatusMask::LIVELINESS_CHANGED);
    assert!(!cond.get_trigger_value());
}

/// The raise, shared raise and re-raise signal the attached WaitSets
/// when DATA_AVAILABLE is enabled and stay silent otherwise; the
/// re-raise signals even though the word was already up (the wake-up it
/// re-delivers may have been consumed); `signal_data_available` is the
/// signal alone, for a producer that stored its word under a lock.
#[test]
fn wake_word_raises_signal_the_waitsets() {
    use crate::core::rt::waitset::WaitsetSignal;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    struct CountingSignal {
        hits: AtomicUsize,
    }
    impl WaitsetSignal for CountingSignal {
        fn signal(&self) {
            self.hits.fetch_add(1, Ordering::Relaxed);
        }
        fn id(&self) -> u64 {
            0xBEEF
        }
    }

    let cond = StatusCondition::new();
    let signal = Arc::new(CountingSignal {
        hits: AtomicUsize::new(0),
    });
    cond.add_waitset_signal(Arc::clone(&signal) as Arc<dyn WaitsetSignal>);
    let hits = || signal.hits.load(Ordering::Relaxed);
    assert_eq!(hits(), 0, "attaching to an untriggered condition is silent");

    // DATA_AVAILABLE not enabled: the word goes up, nobody is woken.
    cond.raise_data_available(0);
    assert_eq!(cond.wake_words().load(0), WAKE_RAISED);
    assert!(!cond.get_trigger_value());
    assert_eq!(hits(), 0);
    assert_eq!(cond.wake_words().clear(0), WAKE_RAISED);

    // Enabling a condition whose word is up signals once.
    cond.raise_data_available(0);
    cond.set_enabled_statuses(StatusMask::DATA_AVAILABLE);
    assert_eq!(hits(), 1);
    assert_eq!(cond.wake_words().clear(0), WAKE_RAISED);

    cond.raise_data_available(0);
    assert!(cond.get_trigger_value());
    assert_eq!(hits(), 2);

    // Already up: the re-raise still signals, and adds its own bit.
    cond.re_raise_data_available(0);
    assert_eq!(cond.wake_words().load(0), WAKE_RAISED | WAKE_RERAISED);
    assert_eq!(hits(), 3);

    cond.raise_data_available_shared(2);
    assert_eq!(hits(), 4);

    cond.signal_data_available();
    assert_eq!(hits(), 5);

    assert_eq!(cond.wake_words().clear(0), WAKE_RAISED | WAKE_RERAISED);
    assert_eq!(cond.wake_words().clear(2), WAKE_RAISED);
    assert!(!cond.get_trigger_value());
    assert_eq!(hits(), 5, "clears never signal");
}
