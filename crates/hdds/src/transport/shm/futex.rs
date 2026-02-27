// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Linux futex wrapper for inter-process synchronization.
//!
//! # CRITICAL: SHARED vs PRIVATE
//!
//! This module uses `FUTEX_WAIT` and `FUTEX_WAKE` (NOT the `_PRIVATE` variants).
//! The `_PRIVATE` variants only work within a single process and will silently
//! fail to wake threads in other processes.
//!
//! For inter-process shared memory communication, we MUST use:
//! - `FUTEX_WAIT` (value 0) - NOT `FUTEX_WAIT_PRIVATE` (value 128)
//! - `FUTEX_WAKE` (value 1) - NOT `FUTEX_WAKE_PRIVATE` (value 129)

use std::ptr;
use std::sync::atomic::AtomicU32;
use std::time::Duration;

/// Futex operation codes (SHARED, not PRIVATE!)
const FUTEX_WAIT: i32 = 0; // NOT 128 (FUTEX_WAIT_PRIVATE)
const FUTEX_WAKE: i32 = 1; // NOT 129 (FUTEX_WAKE_PRIVATE)

/// Wait on a futex until the value changes or timeout expires.
///
/// # Arguments
///
/// * `addr` - Atomic u32 to wait on (must be in shared memory for inter-process)
/// * `expected` - Only wait if current value equals expected
/// * `timeout` - Optional timeout duration
///
/// # Returns
///
/// * `0` on wake or spurious wakeup
/// * `-1` with `EAGAIN` if value != expected
/// * `-1` with `ETIMEDOUT` on timeout
/// * `-1` with other errno on error
///
/// # Safety
///
/// The address must remain valid for the duration of the wait.
/// For inter-process use, addr must point to shared memory (mmap).
#[cfg(target_os = "linux")]
pub fn futex_wait(addr: &AtomicU32, expected: u32, timeout: Option<Duration>) -> i32 {
    let ts = timeout.map(|d| libc::timespec {
        tv_sec: d.as_secs() as libc::time_t,
        tv_nsec: d.subsec_nanos() as libc::c_long,
    });

    let ts_ptr = ts
        .as_ref()
        .map_or(ptr::null(), |t| t as *const libc::timespec);

    // SAFETY: We're calling the futex syscall with valid parameters.
    // The address is guaranteed valid because we have a reference to it.
    // CRITICAL: Using FUTEX_WAIT (0), NOT FUTEX_WAIT_PRIVATE (128)
    unsafe {
        libc::syscall(
            libc::SYS_futex,
            addr as *const AtomicU32 as *const u32,
            FUTEX_WAIT,
            expected,
            ts_ptr,
            ptr::null::<u32>(), // uaddr2 (unused)
            0i32,               // val3 (unused)
        ) as i32
    }
}

/// Wake threads waiting on a futex.
///
/// # Arguments
///
/// * `addr` - Atomic u32 that waiters are blocked on
/// * `count` - Maximum number of waiters to wake (use `i32::MAX` for all)
///
/// # Returns
///
/// Number of waiters woken, or -1 on error.
///
/// # Safety
///
/// The address must be the same address that waiters are using.
/// For inter-process use, addr must point to shared memory (mmap).
#[cfg(target_os = "linux")]
pub fn futex_wake(addr: &AtomicU32, count: i32) -> i32 {
    // SAFETY: We're calling the futex syscall with valid parameters.
    // CRITICAL: Using FUTEX_WAKE (1), NOT FUTEX_WAKE_PRIVATE (129)
    unsafe {
        libc::syscall(
            libc::SYS_futex,
            addr as *const AtomicU32 as *const u32,
            FUTEX_WAKE,
            count,
            ptr::null::<libc::timespec>(), // timeout (unused for wake)
            ptr::null::<u32>(),            // uaddr2 (unused)
            0i32,                          // val3 (unused)
        ) as i32
    }
}

/// Wake a single waiter
#[cfg(target_os = "linux")]
#[inline]
#[allow(dead_code)] // Part of futex API, used for single-waiter wake scenarios
pub fn futex_wake_one(addr: &AtomicU32) -> i32 {
    futex_wake(addr, 1)
}

/// Wake all waiters
#[cfg(target_os = "linux")]
#[inline]
pub fn futex_wake_all(addr: &AtomicU32) -> i32 {
    futex_wake(addr, i32::MAX)
}

// Non-Linux fallback (busy-wait, for testing only)
#[cfg(not(target_os = "linux"))]
pub fn futex_wait(_addr: &AtomicU32, _expected: u32, timeout: Option<Duration>) -> i32 {
    // Fallback: just sleep for the timeout or a short duration
    let sleep_time = timeout.unwrap_or(Duration::from_millis(1));
    std::thread::sleep(sleep_time.min(Duration::from_millis(10)));
    0
}

#[cfg(not(target_os = "linux"))]
pub fn futex_wake(_addr: &AtomicU32, _count: i32) -> i32 {
    0 // No-op on non-Linux
}

#[cfg(not(target_os = "linux"))]
#[inline]
pub fn futex_wake_one(_addr: &AtomicU32) -> i32 {
    0
}

#[cfg(not(target_os = "linux"))]
#[inline]
pub fn futex_wake_all(_addr: &AtomicU32) -> i32 {
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;
    use std::sync::Arc;
    use std::thread;

    #[test]
    fn test_futex_wake_without_waiters() {
        let val = AtomicU32::new(0);
        let woken = futex_wake(&val, 1);
        // Should return 0 (no waiters to wake)
        assert!(woken >= 0);
    }

    #[test]
    fn test_futex_wait_value_mismatch() {
        let val = AtomicU32::new(42);
        // Wait with wrong expected value should return immediately
        let result = futex_wait(&val, 0, Some(Duration::from_millis(100)));
        // On Linux, returns -1 with EAGAIN; on other platforms, returns 0
        #[cfg(target_os = "linux")]
        assert_eq!(result, -1);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_futex_wait_timeout() {
        let val = AtomicU32::new(42);
        let start = std::time::Instant::now();
        let _ = futex_wait(&val, 42, Some(Duration::from_millis(50)));
        let elapsed = start.elapsed();
        // Should have waited approximately 50ms
        assert!(elapsed >= Duration::from_millis(40));
        assert!(elapsed < Duration::from_millis(200));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_futex_wake_waiter() {
        let val = Arc::new(AtomicU32::new(0));
        let val_clone = Arc::clone(&val);

        let handle = thread::spawn(move || {
            // Wait for value to become non-zero
            while val_clone.load(Ordering::Acquire) == 0 {
                futex_wait(&val_clone, 0, Some(Duration::from_secs(1)));
            }
            val_clone.load(Ordering::Acquire)
        });

        // Give thread time to start waiting
        thread::sleep(Duration::from_millis(10));

        // Change value and wake
        val.store(42, Ordering::Release);
        futex_wake(&val, 1);

        let result = handle.join().expect("Thread panicked");
        assert_eq!(result, 42);
    }
}
