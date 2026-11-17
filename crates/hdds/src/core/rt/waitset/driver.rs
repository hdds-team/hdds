// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Waitset driver for efficient multi-slot notification.
//!
//!
//! Provides `WaitsetDriver` for registering conditions and blocking until
//! any registered condition becomes true.
//!
//! - On Linux: uses eventfd + ppoll for O(1) wakeup with an exact timeout.
//! - On macOS/BSD: uses a self-pipe + poll for portable wakeup.
//! - On Windows: uses kernel Event + WaitForSingleObject.
//!
//! Timeout contract shared by every platform: `wait` never reports
//! `Timeout` before the requested duration has elapsed, and a finite
//! request never becomes an unbounded wait. Each platform fixes a
//! [`Deadline`] once, loops on its primitive, and reports `Timeout` only
//! when its own clock agrees, so a primitive that ends early (a restart
//! after EINTR, or a Windows wait quantized to the scheduler tick) waits
//! again for the remainder, and a restart that lands after the deadline
//! reports `Timeout` instead of going again. Platforms whose primitive only
//! takes whole milliseconds round the remainder UP, so the caller may be
//! woken a little late, never early; the DDS `WaitSet` on top keeps its own
//! clock and is the authority on the deadline.

use super::bitmap::AtomicBitset;
use crate::core::string_utils::format_string;
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

/// Default maximum number of waitset slots per driver instance.
pub const WAITSET_DEFAULT_MAX_SLOTS: usize = 2048;

/// Errors returned by [`WaitsetDriver::wait`].
#[derive(Debug)]
pub enum WaitsetWaitError {
    Timeout,
    Io(io::Error),
}

/// A finite wait, kept as the instant it started and its total length.
///
/// Not as an end instant: `Instant::checked_add` fails when the end does
/// not fit the platform's time representation (`Duration::MAX` does not on
/// Linux), and the only thing an absent end instant could stand for was
/// "no deadline", which would turn a finite request into an unbounded
/// wait. Time elapsed since a start can always be measured, so with this
/// shape every finite request stays finite: a remainder beyond what the
/// platform primitive accepts is clamped for that one call and the loop
/// around the primitive keeps going until this clock says the total has
/// elapsed.
#[derive(Clone, Copy)]
pub(super) struct Deadline {
    start: Instant,
    total: Duration,
}

impl Deadline {
    /// `None` is an unbounded wait; a finite timeout starts its clock now.
    pub(super) fn from_timeout(timeout: Option<Duration>) -> Option<Self> {
        timeout.map(|total| Self {
            start: Instant::now(),
            total,
        })
    }

    /// Time left before the deadline, zero once it has passed.
    pub(super) fn remaining(&self) -> Duration {
        self.total.saturating_sub(self.start.elapsed())
    }

    /// Whether the full duration has elapsed on this clock.
    pub(super) fn expired(&self) -> bool {
        self.start.elapsed() >= self.total
    }
}

/// Trait implemented by waitset signals handed to conditions.
///
/// Conditions retain a weak reference to these handles and call `signal()` when
/// their trigger value becomes true. Each signal is associated with a stable
/// identifier that allows conditions to detach cleanly.
///
/// `signal()` runs on the thread that raised the condition, with no lock
/// of the condition held, but possibly under a lock of the entity that
/// delivered the data: a reader's binding table while a durable writer
/// replays its history into a newly bound reader, the per-writer delivery
/// mutex on the network path, the merger's overflow registration lock on
/// a large fan-out. The in-house implementation only records readiness
/// (an eventfd write) and is safe there. A custom implementation must do
/// the same: one that evaluates a condition or calls into the reader from
/// `signal()` re-enters those locks. This is a known limitation of this
/// public trait.
pub trait WaitsetSignal: Send + Sync {
    /// Notify the waitset that the associated slot became active.
    fn signal(&self);

    /// Stable identifier for this signal (per registration).
    fn id(&self) -> u64;
}

/// Driver responsible for managing event-backed notifications.
#[derive(Clone)]
pub struct WaitsetDriver {
    inner: Arc<WaitsetDriverInner>,
}

impl WaitsetDriver {
    /// Create a new waitset driver capable of tracking up to `max_slots`
    /// concurrent registrations.
    pub fn new(max_slots: usize) -> io::Result<Self> {
        if max_slots == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "max_slots must be > 0",
            ));
        }

        let event_handle = platform::create_event()?;

        Ok(Self {
            inner: Arc::new(WaitsetDriverInner {
                event_handle,
                bitmap: AtomicBitset::new(max_slots),
                slots: Mutex::new(SlotTable::new(max_slots)),
                max_slots,
                #[cfg(test)]
                register_hook: Mutex::new(None),
            }),
        })
    }

    /// Register a new slot and obtain the associated [`WaitsetSignal`].
    pub fn register_slot(&self) -> io::Result<WaitsetRegistration> {
        self.inner.register_slot()
    }

    /// Unregister a previously allocated slot. Returns `true` if the slot was
    /// successfully removed.
    pub fn unregister_slot(&self, slot_index: usize, slot_id: u64) -> bool {
        self.inner.unregister_slot(slot_index, slot_id)
    }

    /// Block until one or more slots have been signalled.
    pub fn wait(&self, timeout: Option<Duration>) -> Result<Vec<usize>, WaitsetWaitError> {
        self.inner.wait(timeout)
    }

    /// Manually wake the underlying event without flipping any bits.
    pub fn manual_notify(&self) {
        self.inner.write_event();
    }
}

struct WaitsetDriverInner {
    event_handle: platform::EventHandle,
    bitmap: AtomicBitset,
    /// The slot table, and with it the bound `wait` hands to `take_all`.
    /// The bound is deliberately not mirrored in an atomic: `wait` reads
    /// it under this mutex, which is what orders the read against every
    /// registration (see `wait`).
    slots: Mutex<SlotTable>,
    max_slots: usize,
    /// Test-only: runs once, inside the next `register_slot`, right after
    /// the reused-bit clear, with the slot mutex held. A straggler's signal
    /// landing there is the case the clear's placement exists for, and the
    /// spot is unreachable from the API; the hook lets a test stand in it.
    #[cfg(test)]
    register_hook: Mutex<Option<Box<dyn FnOnce() + Send>>>,
}

impl WaitsetDriverInner {
    fn register_slot(self: &Arc<Self>) -> io::Result<WaitsetRegistration> {
        let (slot_index, slot_id) = {
            #[allow(clippy::expect_used)] // mutex poisoning is unrecoverable
            let mut table = self
                .slots
                .lock()
                .expect("waitset slot table poisoned (register)");
            let allocated = table.allocate_slot(self.max_slots)?;

            // A reused index may still carry a bit from its previous owner.
            // The driver never revokes a handle: unregister_slot takes the
            // (index, id) pair while the handle is a separately owned Arc, so
            // any holder that outlives its registration (a clone, or a caller
            // that unregisters before dropping the handle, as the tests do)
            // can still set the bit. The DDS WaitSet in this crate does not
            // do that: it removes the condition's hook under the condition's
            // lock, the same lock signal() runs under, before it unregisters,
            // so through that path no signal reaches a released slot. The
            // guard keeps the driver correct on its own terms rather than by
            // every caller's ordering. Once the bound has dropped below the
            // word, take_all no longer clears such a bit, and the new owner's
            // first test_and_set would report "already set" and skip the
            // event write: a lost wakeup.
            //
            // The clear runs inside the critical section that raised the
            // bound (allocate_slot did, just above), and `wait` reads the
            // bound inside this same mutex. So once the bit is clear, no
            // waiter can read a bound that excludes its word: a waiter
            // either read the old bound before this section began, and then
            // whatever it drained was signalled before the clear and any bit
            // it skipped is erased here, or it reads the raised bound after
            // this section ends and visits the word. A straggler that sets
            // the bit after the clear is therefore in a word the next
            // take_all visits, and the event it wrote is that wake. The
            // order of the bound update and the clear within the section
            // is immaterial; that both precede the unlock, and the unlock
            // precedes the handle, is what matters.
            self.clear_reused_bit(allocated.0);
            allocated
        };

        let signal = Arc::new(SignalHandle {
            inner: Arc::downgrade(self),
            slot_index,
            slot_id,
        });

        Ok(WaitsetRegistration {
            slot_index,
            slot_id,
            signal,
        })
    }

    fn unregister_slot(&self, slot_index: usize, slot_id: u64) -> bool {
        let mut table = match self.slots.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                log::debug!("[rt] waitset slot table poisoned (unregister), recovering");
                poisoned.into_inner()
            }
        };
        table.release_slot(slot_index, slot_id)
    }

    /// Erase the bit a previous owner of `index` may have left behind.
    /// Runs with the slot mutex held, after `allocate_slot` has raised the
    /// bound over the word; `register_slot` says why that placement is the
    /// whole point. The test hook fires right here so that a test stands
    /// exactly where a straggler's signal would land after the clear:
    /// moving the clear moves the hook with it.
    fn clear_reused_bit(&self, index: usize) {
        self.bitmap.clear(index);
        #[cfg(test)]
        self.fire_register_hook();
    }

    /// One past the highest registered slot index, read under the slot
    /// mutex. `wait` explains why the mutex, and not an atomic mirror, is
    /// the right place to read it. A poisoned table is still a table: the
    /// bound it holds was written under the lock and is used as is.
    fn slot_bound(&self) -> usize {
        match self.slots.lock() {
            Ok(table) => table.slot_bound,
            Err(poisoned) => poisoned.into_inner().slot_bound,
        }
    }

    #[cfg(test)]
    fn fire_register_hook(&self) {
        // Taken out before it runs, so it fires once and whatever it
        // captured (the tests hand it a clone of the driver) is released.
        let hook = self
            .register_hook
            .lock()
            .ok()
            .and_then(|mut slot| slot.take());
        if let Some(hook) = hook {
            hook();
        }
    }

    fn wait(&self, timeout: Option<Duration>) -> Result<Vec<usize>, WaitsetWaitError> {
        platform::wait_event(&self.event_handle, Deadline::from_timeout(timeout))?;
        platform::drain_event(&self.event_handle);
        // The words take_all visits are chosen by the bound, so the bound
        // must cover the slot of every registration whose handle could have
        // signalled before this drain. It is read under the slot mutex, the
        // mutex every registration holds while it raises the bound and
        // clears the reused bit, so this critical section is ordered
        // against each registration's, and both orders are safe:
        //
        // - The registration finished before our lock: its unlock
        //   synchronises-with our lock, so its bound update and its clear,
        //   both sequenced before that unlock, are visible here, and the
        //   word is visited.
        // - The registration starts after our unlock: our unlock
        //   synchronises-with its lock, so its handle, published after its
        //   unlock, and every signal through that handle happen after this
        //   drain. The event is one kernel object, and a write that happens
        //   after a read is not what that read consumed, so that signal's
        //   event is still pending: the next wait wakes on it, by then the
        //   registration is over, and the next read here sees its bound.
        //   An old bound is never a loss; it defers one word by one wakeup.
        //
        // Only the mutex is used in that argument, not the event's memory
        // ordering. Reading the bound with an atomic RMW would not give the
        // same guarantee: an RMW is ordered after the store it reads, but
        // nothing makes it read the registration's store rather than an
        // older one, and an old bound without a happens-before edge leaves
        // the second case unproven: the registration's signal could then be
        // the very event this drain consumed, its word skipped, and its bit
        // left set to silence every later signal. That would be a lost
        // wakeup on any platform where the event write and read do not
        // order memory.
        //
        // What the event must still provide is the bits, not the bound: a
        // bit set before an event write must be visible to the swap that
        // follows the drain of that event. Every event this driver uses
        // does that (eventfd, pipes and Win32 events serialise writer and
        // reader on a kernel lock), and a futex-based mutex rests on the
        // same property; no bitmap-and-event scheme works without it, and
        // no way of reading the bound could stand in for it.
        //
        // Cost: one uncontended lock and unlock per wakeup, a CAS pair, on
        // a path that has just returned from a blocking syscall and costs
        // microseconds. The only other holders are registration and
        // release, the cold attach and detach paths.
        let bound = self.slot_bound();
        Ok(self.bitmap.take_all(bound))
    }

    fn signal_slot(&self, slot_index: usize) {
        if slot_index >= self.max_slots {
            return;
        }

        let already_set = self.bitmap.test_and_set(slot_index);
        if !already_set {
            self.write_event();
        }
    }

    fn write_event(&self) {
        platform::signal_event(&self.event_handle);
    }
}

impl Drop for WaitsetDriverInner {
    fn drop(&mut self) {
        platform::close_event(&self.event_handle);
    }
}

// =============================================================================
// Linux implementation (eventfd + ppoll)
// =============================================================================
#[cfg(target_os = "linux")]
mod platform {
    use std::io;
    use std::os::fd::RawFd;

    use super::{Deadline, WaitsetWaitError};

    const EVENTFD_FLAGS: libc::c_int = libc::EFD_NONBLOCK | libc::EFD_CLOEXEC;

    pub type EventHandle = RawFd;

    pub fn create_event() -> io::Result<EventHandle> {
        // SAFETY: eventfd is invoked with valid flags and no shared state.
        let fd = unsafe { libc::eventfd(0, EVENTFD_FLAGS) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(fd)
    }

    /// Block until the eventfd is readable or `timeout` has elapsed.
    ///
    /// ppoll(2) takes a timespec, so the timeout is passed to the kernel
    /// with nanosecond resolution. poll(2) only takes whole milliseconds; a
    /// remainder under 1 ms would become poll(..., 0), which returns at once
    /// and reports Timeout up to 1 ms BEFORE the requested deadline (a
    /// 300 us wait would not block at all). The deadline is fixed once by the
    /// caller so that an EINTR restart waits for the remainder, not for the
    /// full timeout again.
    pub fn wait_event(
        handle: &EventHandle,
        deadline: Option<Deadline>,
    ) -> Result<(), WaitsetWaitError> {
        let mut pollfd = libc::pollfd {
            fd: *handle,
            events: libc::POLLIN,
            revents: 0,
        };

        loop {
            let mut ts = libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            };
            let ts_ptr: *const libc::timespec = match deadline {
                None => std::ptr::null(),
                Some(deadline) => {
                    let remaining = deadline.remaining();
                    // The field types are left to the struct so that the
                    // deprecated `libc::time_t` alias is never named (it is
                    // still 32-bit on some musl targets). The seconds are
                    // capped at i32::MAX before the cast so it cannot wrap on
                    // any width of tv_sec; 2^31 s is 68 years, beyond any
                    // process lifetime, and the kernel clamps an oversized
                    // timespec to its own maximum rather than rejecting it,
                    // so the wait stays effectively unbounded either way.
                    ts.tv_sec = remaining.as_secs().min(i32::MAX as u64) as _;
                    // subsec_nanos() < 1e9 fits every tv_nsec, 32-bit included.
                    ts.tv_nsec = remaining.subsec_nanos() as _;
                    std::ptr::addr_of!(ts)
                }
            };

            // SAFETY: poll_target points to our stack-allocated pollfd
            // structure; ts_ptr is null or points to the stack timespec above,
            // which outlives the call; a null sigmask leaves the signal mask
            // untouched, so this is poll with a finer timeout.
            let poll_target = std::ptr::addr_of_mut!(pollfd);
            let res = unsafe { libc::ppoll(poll_target, 1, ts_ptr, std::ptr::null()) };
            if res == 0 {
                // Only our own clock decides that the deadline has passed;
                // a primitive that ended early waits again for the remainder.
                match deadline {
                    Some(deadline) if !deadline.expired() => continue,
                    _ => return Err(WaitsetWaitError::Timeout),
                }
            }
            if res < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::Interrupted {
                    // A signal cut the poll short. Go again for the
                    // remainder, unless the deadline has passed meanwhile:
                    // a steady stream of signals must not push a finite
                    // wait past its end one restart at a time.
                    match deadline {
                        Some(deadline) if deadline.expired() => {
                            return Err(WaitsetWaitError::Timeout)
                        }
                        _ => continue,
                    }
                }
                return Err(WaitsetWaitError::Io(err));
            }
            break;
        }
        Ok(())
    }

    pub fn signal_event(handle: &EventHandle) {
        let value: u64 = 1;
        let payload = value.to_ne_bytes();
        loop {
            // SAFETY: payload references a stack buffer with the 8-byte eventfd payload.
            let ret = unsafe { libc::write(*handle, payload.as_ptr().cast(), payload.len()) };
            if ret >= 0 {
                break;
            }

            let err = io::Error::last_os_error();
            let kind = err.kind();
            if kind == io::ErrorKind::Interrupted {
                continue;
            }
            if kind == io::ErrorKind::WouldBlock {
                break;
            }
            log::debug!("[rt] waitset eventfd write failed: {}", err);
            break;
        }
    }

    pub fn drain_event(handle: &EventHandle) {
        let mut payload = [0u8; 8];
        loop {
            // SAFETY: payload is a stack buffer sized to the eventfd read requirements (8 bytes).
            let ret = unsafe { libc::read(*handle, payload.as_mut_ptr().cast(), payload.len()) };
            if ret >= 0 {
                break;
            }

            let err = io::Error::last_os_error();
            let kind = err.kind();
            if kind == io::ErrorKind::Interrupted {
                continue;
            }
            if kind == io::ErrorKind::WouldBlock {
                break;
            }
            log::debug!("[rt] waitset eventfd read failed: {}", err);
            break;
        }
    }

    pub fn close_event(handle: &EventHandle) {
        // SAFETY: eventfd was obtained via libc::eventfd and is closed once here.
        unsafe {
            libc::close(*handle);
        }
    }
}

// =============================================================================
// macOS / BSD implementation (pipe + poll)
// =============================================================================
#[cfg(all(unix, not(target_os = "linux")))]
mod platform {
    use std::io;
    use std::os::fd::RawFd;
    use std::time::Duration;

    use super::{Deadline, WaitsetWaitError};

    /// A self-pipe pair: read_fd for polling, write_fd for signalling.
    pub struct EventHandle {
        read_fd: RawFd,
        write_fd: RawFd,
    }

    pub fn create_event() -> io::Result<EventHandle> {
        let mut fds = [0 as RawFd; 2];
        // SAFETY: fds is a valid 2-element array for pipe().
        let ret = unsafe { libc::pipe(fds.as_mut_ptr()) };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        // Set both ends non-blocking and close-on-exec
        for &fd in &fds {
            unsafe {
                let flags = libc::fcntl(fd, libc::F_GETFL);
                libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
                let fd_flags = libc::fcntl(fd, libc::F_GETFD);
                libc::fcntl(fd, libc::F_SETFD, fd_flags | libc::FD_CLOEXEC);
            }
        }
        Ok(EventHandle {
            read_fd: fds[0],
            write_fd: fds[1],
        })
    }

    /// poll(2) timeout for `remaining`, rounded UP to the next millisecond.
    ///
    /// poll only takes whole milliseconds. Rounding down would turn a remainder
    /// under 1 ms into poll(..., 0), an immediate return that reports Timeout
    /// before the deadline; rounding up wakes at most 1 ms late, which the
    /// caller's own clock absorbs. A remainder past i32::MAX ms is clamped,
    /// not mapped to -1 (infinite), so a huge finite timeout stays finite and
    /// the caller loops on its deadline.
    fn poll_timeout_ms(remaining: Duration) -> libc::c_int {
        let whole_ms = remaining.as_millis();
        let ms = if remaining.subsec_nanos().is_multiple_of(1_000_000) {
            whole_ms
        } else {
            whole_ms + 1
        };
        libc::c_int::try_from(ms).unwrap_or(libc::c_int::MAX)
    }

    /// The deadline is fixed once by the caller so that an EINTR restart
    /// waits for the remainder, not for the full timeout again.
    pub fn wait_event(
        handle: &EventHandle,
        deadline: Option<Deadline>,
    ) -> Result<(), WaitsetWaitError> {
        let mut pollfd = libc::pollfd {
            fd: handle.read_fd,
            events: libc::POLLIN,
            revents: 0,
        };

        loop {
            let timeout_ms = match deadline {
                None => -1,
                Some(deadline) => poll_timeout_ms(deadline.remaining()),
            };

            let poll_target = std::ptr::addr_of_mut!(pollfd);
            // SAFETY: poll_target points to our stack-allocated pollfd structure.
            let res = unsafe { libc::poll(poll_target, 1, timeout_ms) };
            if res == 0 {
                // Only our own clock decides that the deadline has passed;
                // a primitive that ended early waits again for the remainder.
                match deadline {
                    Some(deadline) if !deadline.expired() => continue,
                    _ => return Err(WaitsetWaitError::Timeout),
                }
            }
            if res < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::Interrupted {
                    // A signal cut the poll short. Go again for the
                    // remainder, unless the deadline has passed meanwhile:
                    // a steady stream of signals must not push a finite
                    // wait past its end one restart at a time.
                    match deadline {
                        Some(deadline) if deadline.expired() => {
                            return Err(WaitsetWaitError::Timeout)
                        }
                        _ => continue,
                    }
                }
                return Err(WaitsetWaitError::Io(err));
            }
            break;
        }
        Ok(())
    }

    pub fn signal_event(handle: &EventHandle) {
        let payload: [u8; 1] = [1];
        loop {
            // SAFETY: payload is a 1-byte stack buffer written to the pipe.
            let ret =
                unsafe { libc::write(handle.write_fd, payload.as_ptr().cast(), payload.len()) };
            if ret >= 0 {
                break;
            }
            let err = io::Error::last_os_error();
            let kind = err.kind();
            if kind == io::ErrorKind::Interrupted {
                continue;
            }
            if kind == io::ErrorKind::WouldBlock {
                break; // pipe buffer full, already signalled
            }
            log::debug!("[rt] waitset pipe write failed: {}", err);
            break;
        }
    }

    pub fn drain_event(handle: &EventHandle) {
        // The eventfd path drains in one bounded read. A pipe does not: each
        // signal is its own byte, so a `while ret > 0` loop keeps reading for
        // as long as other threads keep writing, and a signal storm can hold
        // the waiter in here past its deadline. So the drain is capped at one
        // pipe's worth of traffic. Stopping early is safe by the driver's own
        // rule (see `wait`): bytes left behind make the NEXT wait return at
        // once and find nothing, which is a spurious wake-up. Only a lost
        // wake-up would break the contract, and leaving bytes cannot cause one.
        const MAX_DRAIN_READS: usize = 256; // 256 * 512 B = 128 KiB
        let mut buf = [0u8; 512];
        for _ in 0..MAX_DRAIN_READS {
            // SAFETY: buf is a stack buffer; we drain all pending bytes from the read end.
            let ret = unsafe { libc::read(handle.read_fd, buf.as_mut_ptr().cast(), buf.len()) };
            if ret > 0 {
                continue; // drain more
            }
            if ret == 0 {
                break;
            }
            let err = io::Error::last_os_error();
            let kind = err.kind();
            if kind == io::ErrorKind::Interrupted {
                continue;
            }
            // WouldBlock means pipe is empty -- done draining
            break;
        }
    }

    pub fn close_event(handle: &EventHandle) {
        // SAFETY: both fds were obtained from pipe() and are closed once here.
        unsafe {
            libc::close(handle.read_fd);
            libc::close(handle.write_fd);
        }
    }
}

// =============================================================================
// Windows implementation (kernel Event object)
// =============================================================================
#[cfg(windows)]
mod platform {
    use std::io;
    use std::time::Duration;

    use super::{Deadline, WaitsetWaitError};

    // Win32 constants
    const INFINITE: u32 = 0xFFFFFFFF;
    const WAIT_OBJECT_0: u32 = 0;
    const WAIT_TIMEOUT: u32 = 258;
    /// Largest finite WaitForSingleObject timeout (INFINITE is the sentinel
    /// one above it).
    const MAX_FINITE_MS: u32 = INFINITE - 1;

    // Opaque handle wrapper (HANDLE is *mut c_void on Windows)
    pub struct EventHandle(std::os::windows::io::RawHandle);

    // SAFETY: Windows Event objects are inherently thread-safe kernel objects.
    unsafe impl Send for EventHandle {}
    unsafe impl Sync for EventHandle {}

    extern "system" {
        fn CreateEventW(
            lpEventAttributes: *const std::ffi::c_void,
            bManualReset: i32,
            bInitialState: i32,
            lpName: *const u16,
        ) -> *mut std::ffi::c_void;

        fn SetEvent(hEvent: *mut std::ffi::c_void) -> i32;
        fn ResetEvent(hEvent: *mut std::ffi::c_void) -> i32;
        fn WaitForSingleObject(hHandle: *mut std::ffi::c_void, dwMilliseconds: u32) -> u32;
        fn CloseHandle(hObject: *mut std::ffi::c_void) -> i32;
    }

    pub fn create_event() -> io::Result<EventHandle> {
        // Create an auto-reset event (bManualReset = 0), initially non-signaled
        // SAFETY: CreateEventW FFI with null security attributes and name (valid for unnamed event)
        let handle = unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) };
        if handle.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(EventHandle(handle as std::os::windows::io::RawHandle))
    }

    /// WaitForSingleObject timeout for `remaining`, rounded UP to the next
    /// millisecond (a remainder under 1 ms would become 0, an immediate
    /// return). A value past the finite range is clamped rather than mapped
    /// to INFINITE, so a huge finite timeout stays finite and the caller
    /// loops on its deadline.
    fn wait_timeout_ms(remaining: Duration) -> u32 {
        let whole_ms = remaining.as_millis();
        let ms = if remaining.subsec_nanos().is_multiple_of(1_000_000) {
            whole_ms
        } else {
            whole_ms + 1
        };
        u32::try_from(ms)
            .unwrap_or(MAX_FINITE_MS)
            .min(MAX_FINITE_MS)
    }

    /// Block until the event is signalled or `timeout` has elapsed.
    ///
    /// Rounding the millisecond count up is not enough on Windows: a
    /// relative wait is quantized to the scheduler tick (15.625 ms by
    /// default) and the tick already in progress when the wait starts
    /// counts in full, so WaitForSingleObject can return WAIT_TIMEOUT before
    /// the requested duration has elapsed. The deadline is therefore fixed
    /// once on our own clock by the caller and the wait loops until that
    /// clock agrees, the same shape as the unix paths.
    pub fn wait_event(
        handle: &EventHandle,
        deadline: Option<Deadline>,
    ) -> Result<(), WaitsetWaitError> {
        loop {
            let timeout_ms = match deadline {
                None => INFINITE,
                Some(deadline) => wait_timeout_ms(deadline.remaining()),
            };

            // SAFETY: WaitForSingleObject FFI with valid event handle from CreateEventW
            let result = unsafe { WaitForSingleObject(handle.0 as *mut _, timeout_ms) };
            match result {
                WAIT_OBJECT_0 => return Ok(()),
                WAIT_TIMEOUT => {
                    // Only our own clock decides that the deadline has
                    // passed; a wait that ended early goes again for the
                    // remainder.
                    match deadline {
                        Some(deadline) if !deadline.expired() => continue,
                        _ => return Err(WaitsetWaitError::Timeout),
                    }
                }
                _ => return Err(WaitsetWaitError::Io(io::Error::last_os_error())),
            }
        }
    }

    pub fn signal_event(handle: &EventHandle) {
        // SAFETY: SetEvent FFI with valid event handle from CreateEventW
        unsafe {
            SetEvent(handle.0 as *mut _);
        }
    }

    pub fn drain_event(handle: &EventHandle) {
        // Manual-reset event: reset it after wakeup so next wait blocks
        // SAFETY: ResetEvent FFI with valid event handle from CreateEventW
        unsafe {
            ResetEvent(handle.0 as *mut _);
        }
    }

    pub fn close_event(handle: &EventHandle) {
        // SAFETY: CloseHandle FFI with valid event handle from CreateEventW, called once in Drop
        unsafe {
            CloseHandle(handle.0 as *mut _);
        }
    }
}

/// Registration details returned by [`WaitsetDriver::register_slot`].
pub struct WaitsetRegistration {
    slot_index: usize,
    slot_id: u64,
    signal: Arc<SignalHandle>,
}

impl WaitsetRegistration {
    /// Erase the concrete type so callers can store `Arc<dyn WaitsetSignal>`.
    pub fn into_trait(self) -> (usize, u64, Arc<dyn WaitsetSignal>) {
        (
            self.slot_index,
            self.slot_id,
            self.signal as Arc<dyn WaitsetSignal>,
        )
    }
}

struct SignalHandle {
    inner: Weak<WaitsetDriverInner>,
    slot_index: usize,
    slot_id: u64,
}

impl WaitsetSignal for SignalHandle {
    fn signal(&self) {
        if let Some(inner) = self.inner.upgrade() {
            inner.signal_slot(self.slot_index);
        }
    }

    fn id(&self) -> u64 {
        self.slot_id
    }
}

struct SlotTable {
    entries: Vec<Option<SlotEntry>>,
    free: Vec<usize>,
    /// One past the highest index currently holding an entry, 0 when the
    /// table is empty. `entries.len()` cannot serve: it never shrinks, so a
    /// table that held 100 slots and now holds one would keep the wakeup
    /// scanning two words forever.
    slot_bound: usize,
}

/// Slot ids are drawn from ONE counter for the whole process, not one per
/// table.
///
/// The id is also what a `Condition` stores to identify an attached WaitSet
/// (`WaitsetSignal::id`), and removal matches on it alone. Every `WaitSet`
/// builds its own driver, so a per-table counter starting at 1 would hand the
/// SAME id to two WaitSets attached to the SAME condition: detaching or
/// dropping either one would then match BOTH hooks and silently disarm the
/// survivor, which would go on believing it was attached and sleep to its
/// timeout with the condition true. Two WaitSets observing one condition is
/// ordinary - DDS v1.4 puts no limit on it.
///
/// A process-wide counter keeps the id's other job intact: it is still
/// monotonic per table, so a released and reused slot index never collides
/// with the id of the entry it replaced.
static NEXT_SLOT_ID: AtomicU64 = AtomicU64::new(1);

impl SlotTable {
    fn new(max_slots: usize) -> Self {
        Self {
            entries: Vec::with_capacity(max_slots),
            free: Vec::new(),
            slot_bound: 0,
        }
    }

    fn allocate_slot(&mut self, max_slots: usize) -> io::Result<(usize, u64)> {
        let slot_index = if let Some(index) = self.free.pop() {
            index
        } else {
            let index = self.entries.len();
            if index >= max_slots {
                return Err(io::Error::other(format_string(format_args!(
                    "waitset capacity exceeded (max {})",
                    max_slots
                ))));
            }
            self.entries.push(None);
            index
        };

        // `Relaxed` is enough: this only has to be unique, and the value is
        // published to other threads through the mutex that guards the table
        // and through the Arc that carries the SignalHandle.
        let mut slot_id = NEXT_SLOT_ID.fetch_add(1, Ordering::Relaxed);
        if slot_id == 0 {
            // Only after 2^64 registrations, and 0 is reserved as "no id".
            slot_id = NEXT_SLOT_ID.fetch_add(1, Ordering::Relaxed);
        }

        if slot_index >= self.entries.len() {
            self.entries.resize(slot_index + 1, None);
        }
        self.entries[slot_index] = Some(SlotEntry { id: slot_id });
        self.slot_bound = self.slot_bound.max(slot_index + 1);

        Ok((slot_index, slot_id))
    }

    fn release_slot(&mut self, slot_index: usize, slot_id: u64) -> bool {
        if slot_index >= self.entries.len() {
            return false;
        }

        match &self.entries[slot_index] {
            Some(entry) if entry.id == slot_id => {
                self.entries[slot_index] = None;
                self.free.push(slot_index);
                if slot_index + 1 == self.slot_bound {
                    // The highest slot went away: the new bound is one past
                    // the next highest live entry. Linear, but unregister is
                    // a cold path and the scan stops at the first live entry.
                    self.slot_bound = self.entries[..slot_index]
                        .iter()
                        .rposition(Option::is_some)
                        .map_or(0, |index| index + 1);
                }
                true
            }
            _ => false,
        }
    }
}

#[derive(Clone)]
struct SlotEntry {
    id: u64,
}

#[cfg(test)]
pub(super) mod internal {
    use super::*;

    pub(crate) fn slots_len(driver: &WaitsetDriver) -> usize {
        driver
            .inner
            .slots
            .lock()
            .expect("slot table poisoned")
            .entries
            .len()
    }

    /// The bound `wait` hands to `AtomicBitset::take_all`: one past the
    /// highest registered slot index, read the way `wait` reads it.
    pub(crate) fn slot_bound(driver: &WaitsetDriver) -> usize {
        driver.inner.slot_bound()
    }

    /// Set a bit directly, without an event write, and report whether it
    /// was already set. Doubles as an "is this bit still set" probe.
    pub(crate) fn plant_bit(driver: &WaitsetDriver, index: usize) -> bool {
        driver.inner.bitmap.test_and_set(index)
    }

    /// Run `hook` once, inside the next `register_slot` on this driver,
    /// right after the reused-bit clear, with the slot mutex held. The hook
    /// may signal (that takes no lock) but must not wait, register or
    /// unregister on its own thread: all three take the slot mutex.
    pub(crate) fn set_register_hook(driver: &WaitsetDriver, hook: Box<dyn FnOnce() + Send>) {
        *driver
            .inner
            .register_hook
            .lock()
            .expect("register hook poisoned") = Some(hook);
    }
}
