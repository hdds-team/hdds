// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Thread lifetime hooks for tests of the participant teardown.

use std::time::{Duration, Instant};

/// Make every thread a participant starts linger up to `linger` after it
/// has finished its work, unless the participant's teardown is joining it,
/// in which case it ends at once. A drop that forgets one join returns with
/// that thread still alive, which a test counting the process's threads
/// (`/proc/self/task`) then sees. Without the linger, a stopped thread most
/// often ends before the count is read, and the missing join goes
/// unnoticed. Process-wide; set it in a process that runs that test alone.
pub fn linger_on_exit(linger: Duration) {
    crate::core::rt::shutdown::set_exit_linger_for_test(linger);
}

/// The longest [`settled`] waits for a thread count to come back.
const SETTLE_AT_MOST: Duration = Duration::from_millis(500);

/// Read the process's threads with `read` until the reading equals
/// `expected`, for a short bound, and return the last reading.
///
/// A joined thread is not gone from `/proc/self/task` when its join
/// returns. Linux wakes the joiner from the thread's exit path, when it
/// releases the thread's address space (`CLONE_CHILD_CLEARTID`), and only
/// later in that same path reaps the task and removes its `/proc` entry. On
/// a loaded machine the exiting task can be preempted in between: a count
/// read right after the teardown returns then still lists a thread that was
/// joined, in state `R` with no address space left (measured: gone 1 to
/// 9 ms later, under 88 CPU-bound workers). That task is not a leak, and
/// reading the count once makes such a test fail a few percent of the time
/// under load.
///
/// The wait is bounded well below the [`linger_on_exit`] linger (a quarter
/// of it, at most [`SETTLE_AT_MOST`]): a thread the teardown forgot to join
/// is still lingering, alive, when the wait ends, so the reading returned
/// still shows it and the caller's assertion still fails.
pub fn settled<T: PartialEq>(expected: &T, mut read: impl FnMut() -> T) -> T {
    let linger = crate::core::rt::shutdown::exit_linger_for_test();
    let bound = if linger.is_zero() {
        SETTLE_AT_MOST
    } else {
        (linger / 4).min(SETTLE_AT_MOST)
    };
    let deadline = Instant::now() + bound;
    loop {
        let reading = read();
        if reading == *expected || Instant::now() >= deadline {
            return reading;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}
