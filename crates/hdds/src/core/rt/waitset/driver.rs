// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Waitset driver for efficient multi-slot notification.
//!
//!
//! Provides `WaitsetDriver` for registering conditions and blocking until
//! any registered condition becomes true.
//!
//! - On Linux/Unix: uses eventfd + poll for O(1) wakeup.
//! - On Windows: uses kernel Event + WaitForSingleObject.

use super::bitmap::AtomicBitset;
use crate::core::string_utils::format_string;
use std::io;
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

/// Default maximum number of waitset slots per driver instance.
pub const WAITSET_DEFAULT_MAX_SLOTS: usize = 2048;

/// Errors returned by [`WaitsetDriver::wait`].
#[derive(Debug)]
pub enum WaitsetWaitError {
    Timeout,
    Io(io::Error),
}

/// Trait implemented by waitset signals handed to conditions.
///
/// Conditions retain a weak reference to these handles and call `signal()` when
/// their trigger value becomes true. Each signal is associated with a stable
/// identifier that allows conditions to detach cleanly.
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
    slots: Mutex<SlotTable>,
    max_slots: usize,
}

impl WaitsetDriverInner {
    fn register_slot(self: &Arc<Self>) -> io::Result<WaitsetRegistration> {
        let (slot_index, slot_id) = {
            #[allow(clippy::expect_used)] // mutex poisoning is unrecoverable
            let mut table = self
                .slots
                .lock()
                .expect("waitset slot table poisoned (register)");
            table.allocate_slot(self.max_slots)?
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

    fn wait(&self, timeout: Option<Duration>) -> Result<Vec<usize>, WaitsetWaitError> {
        platform::wait_event(&self.event_handle, timeout)?;
        platform::drain_event(&self.event_handle);
        Ok(self.bitmap.take_all())
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
// Unix implementation (eventfd + poll)
// =============================================================================
#[cfg(unix)]
mod platform {
    use std::io;
    use std::os::fd::RawFd;
    use std::time::Duration;

    use super::WaitsetWaitError;

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

    pub fn wait_event(
        handle: &EventHandle,
        timeout: Option<Duration>,
    ) -> Result<(), WaitsetWaitError> {
        let timeout_ms = timeout
            .and_then(|d| {
                d.as_millis()
                    .try_into()
                    .ok()
                    .map(|ms: i32| if ms < 0 { i32::MAX } else { ms })
            })
            .unwrap_or(-1);

        let mut pollfd = libc::pollfd {
            fd: *handle,
            events: libc::POLLIN,
            revents: 0,
        };

        loop {
            // SAFETY: poll_target points to our stack-allocated pollfd structure.
            let poll_target = std::ptr::addr_of_mut!(pollfd);
            let res = unsafe { libc::poll(poll_target, 1, timeout_ms) };
            if res == 0 {
                return Err(WaitsetWaitError::Timeout);
            }
            if res < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::Interrupted {
                    continue;
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
// Windows implementation (kernel Event object)
// =============================================================================
#[cfg(windows)]
mod platform {
    use std::io;
    use std::time::Duration;

    use super::WaitsetWaitError;

    // Win32 constants
    const INFINITE: u32 = 0xFFFFFFFF;
    const WAIT_OBJECT_0: u32 = 0;
    const WAIT_TIMEOUT: u32 = 258;

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

    pub fn wait_event(
        handle: &EventHandle,
        timeout: Option<Duration>,
    ) -> Result<(), WaitsetWaitError> {
        let timeout_ms = timeout
            .map(|d| {
                let ms = d.as_millis();
                // Clamp to u32::MAX, use INFINITE for values that don't fit
                u32::try_from(ms).unwrap_or(INFINITE)
            })
            .unwrap_or(INFINITE);

        // SAFETY: WaitForSingleObject FFI with valid event handle from CreateEventW
        let result = unsafe { WaitForSingleObject(handle.0 as *mut _, timeout_ms) };
        match result {
            WAIT_OBJECT_0 => Ok(()),
            WAIT_TIMEOUT => Err(WaitsetWaitError::Timeout),
            _ => Err(WaitsetWaitError::Io(io::Error::last_os_error())),
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
    next_id: u64,
}

impl SlotTable {
    fn new(max_slots: usize) -> Self {
        Self {
            entries: Vec::with_capacity(max_slots),
            free: Vec::new(),
            next_id: 1,
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

        let slot_id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1).max(1);

        if slot_index >= self.entries.len() {
            self.entries.resize(slot_index + 1, None);
        }
        self.entries[slot_index] = Some(SlotEntry { id: slot_id });

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
}
