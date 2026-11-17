// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Topic notification system using futex-based buckets.
//!
//! Multiple writers can notify readers about new data availability.
//! Uses a bucketed approach to reduce contention when many writers
//! are active simultaneously.
//!
//! # Layout (version 2)
//!
//! ```text
//! /hdds_notify_v2_d<domain>_<topic>   (84 KiB, mode 0600)
//! +----------------------------------------+ 0
//! | NotifyHeader                           |
//! |   magic, version, lock ABI, closed     |
//! |   robust process-shared mutex          |
//! |   UserSlot[1024] (64-byte liveness rows)|
//! +----------------------------------------+ HEADER_SIZE (68 KiB, whole pages)
//! | NotifyBucket[0]   (64 bytes, aligned)  |
//! | ...                                    |
//! | NotifyBucket[255] (64 bytes, aligned)  |
//! +----------------------------------------+ HEADER_SIZE + 16384
//! ```
//!
//! Writers increment their assigned bucket and wake waiters.
//! Readers snapshot the bucket value before waiting to avoid lost wakes.
//! The hot path (`notify`, `snapshot`, `wait`) touches only the buckets; the
//! header is touched only when a process attaches or detaches.
//!
//! # Lifecycle
//!
//! The segment is shared by every SHM writer and reader of the topic on the
//! host and has no single owner. It is released by its last live user:
//!
//! * Every process that maps the segment registers ONE row in the header's
//!   user table (`UserSlot`: pid, boot id, pid start time, pid namespace),
//!   whatever the number of `TopicNotify` handles it holds (a process-local
//!   registry shares one `Attachment` per name). Only processes that notify
//!   or wait map it: SHM writers and blocking readers, not the
//!   participant's receive poller (see `NOTIFY_MAX_USERS`).
//! * Opening an existing object requires it to be owned by this effective
//!   user with mode 0600 (as every object is created), so another local
//!   account cannot plant the name; anything else is refused, left alone,
//!   and logged once per process.
//! * Every change to the table, and the `closed` flag, happens under the
//!   header's robust process-shared mutex. A holder that dies with the lock
//!   held hands the next locker `EOWNERDEAD`; every critical section below
//!   leaves the header consistent after each single store, so the next
//!   locker simply marks the mutex consistent and carries on.
//! * Attach (under the lock): if `closed`, the object is dying -- retry the
//!   name. Otherwise claim a free row; when none is free, first reclaim rows
//!   whose process is provably dead (same rules as ring-segment owners,
//!   `owner::owner_is_dead`: never on doubt). A full table of live rows is
//!   a clean refusal.
//! * Detach (under the lock): free our row, then reclaim dead rows until the
//!   first live one; if no live row remains, set `closed` and unlink the
//!   name -- only if the name still refers to THIS object (inode check).
//! * Create: the object is built unnamed (`O_TMPFILE` on `/dev/shm`), its
//!   header and mutex initialised and the creator's row already claimed, and
//!   only then published with `linkat` (atomic, fails with `EEXIST` if the
//!   name exists). A racing creator that loses discards its unnamed object
//!   (nothing to clean: an unnamed tmpfs inode dies with its last
//!   reference) and opens the winner's.
//!
//! # Why no user is ever left on an unlinked object
//!
//! 1. A linked object is fully initialised (it is published by `linkat` only
//!    after initialisation), and the creator is registered before publish.
//! 2. `closed` is set only under the lock, only when no live row remains,
//!    and is never cleared.
//! 3. A row is claimed only under the lock and only while `closed` is false.
//! 4. The name is unlinked only under the object's lock, only once `closed`
//!    is set, and only after checking that the name still refers to this
//!    object. While it does, no other object can exist under that name
//!    (`linkat` fails with `EEXIST`), and every protocol actor that might
//!    unlink it must hold this same lock, so check-then-unlink cannot be
//!    overtaken by another protocol actor.
//!
//! From 2 and 3, every registered user registered before `closed` was set,
//! and `closed` was set when none of them was live any more; from 4, unlink
//! follows `closed`. So an object with a live registered user is still
//! linked, and since a name names one object at a time, all live users of a
//! name share one object and see each other's notifications. A closer that
//! dies between setting `closed` and unlinking is finished by the next
//! locker of that object (it sees `closed` with the name still on it).
//!
//! Never-on-doubt has a cost: a row recorded in another PID namespace, or
//! by a process this one cannot probe, is never reclaimed from here, so a
//! segment whose last user crashed in another namespace stays until a
//! process in that namespace attaches and detaches. Same rule, same caveat
//! as `owner.rs`.
//!
//! # Older peers on the same host
//!
//! Version 1 (HDDS 1.4.x and 1.5 builds before this layout) used the name
//! `/hdds_notify_d<domain>_<topic>`, a bare 16 KiB bucket array with no
//! header, and created it by unlinking whatever was there first. Version 2
//! uses a different name, so the two never map each other's object: an old
//! peer can neither corrupt the user table nor unlink a version-2 object
//! (its `cleanup_domain_segments` prefix `hdds_notify_d<domain>_` does not
//! match `hdds_notify_v2_`, and its `cleanup_stale_segments` heuristic reads
//! the first 8 bytes as a ring head, which here is `magic | version << 32`,
//! far below its 2^48 threshold). The cost is that an old and a new process
//! on the same topic do not share wake-ups: a new reader blocked in
//! `ShmRingReader::take_blocking` is not woken by an old writer, and vice
//! versa. The participant's own receive poller does not wait on these
//! buckets (it sweeps its rings on a timer), so DDS delivery between
//! versions is unaffected. Version-1 objects left in `/dev/shm` by older
//! binaries are not touched: nothing here can tell whether an old process
//! still uses one.
//!
//! A version-2 name holding anything else (wrong size, magic, version, or a
//! mutex ABI from another C library) is refused, never mapped as ours and
//! never unlinked.

use super::futex::{futex_wait, futex_wake_all};
use super::owner;
use super::{Result, ShmError, NOTIFY_BUCKET_COUNT};
use std::collections::HashMap;
use std::ffi::CString;
use std::io;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::Duration;

/// Notification bucket (cache-line aligned to prevent false sharing).
///
/// Each writer is assigned a bucket based on hash of its GUID.
/// This distributes contention across multiple cache lines.
#[repr(C, align(64))]
pub struct NotifyBucket {
    /// Notification counter (incremented on each publish)
    pub val: AtomicU32,
    /// Padding to fill cache line
    _pad: [u8; 60],
}

impl NotifyBucket {
    /// Create a new zeroed bucket
    #[must_use]
    pub const fn new() -> Self {
        Self {
            val: AtomicU32::new(0),
            _pad: [0u8; 60],
        }
    }

    /// Increment the notification counter and wake waiters
    #[inline]
    pub fn notify(&self) {
        self.val.fetch_add(1, Ordering::Release);
        futex_wake_all(&self.val);
    }

    /// Get current counter value (for snapshot before wait)
    #[inline]
    pub fn snapshot(&self) -> u32 {
        self.val.load(Ordering::Acquire)
    }

    /// Wait until counter changes from snapshot value
    ///
    /// Uses double-check pattern to avoid lost wakes:
    /// 1. Poll data
    /// 2. Snapshot notify counter
    /// 3. Re-poll data (catches race)
    /// 4. If still no data, wait on futex
    #[inline]
    pub fn wait(&self, snapshot: u32, timeout: Option<Duration>) -> i32 {
        futex_wait(&self.val, snapshot, timeout)
    }
}

impl Default for NotifyBucket {
    fn default() -> Self {
        Self::new()
    }
}

/// "NTFY" read as a little-endian u32.
const NOTIFY_MAGIC: u32 = 0x5946_544E;

/// Layout version of the segment. Version 1 had no header (see module doc).
const NOTIFY_LAYOUT_VERSION: u32 = 2;

/// Bytes before the bucket array: the header, rounded up to whole pages.
const HEADER_SIZE: usize = std::mem::size_of::<NotifyHeader>().next_multiple_of(4096);

/// Rows in the user table: the processes that can share one topic's
/// segment on one host. Only processes that notify or wait on the buckets
/// take a row: writers (`ShmWriterTransport`) and blocking readers
/// (`ShmReaderTransport`). The participant's receive poller, which reads
/// every SHM ring a DDS reader matched, never waits on them and takes none,
/// so a topic like `/rosout` costs one row per WRITING process. One more
/// process than this is refused (one warning per process) and its writer
/// leg falls back to UDP.
pub const NOTIFY_MAX_USERS: usize = NOTIFY_MAX_USERS_U32 as usize;

/// `NOTIFY_MAX_USERS` in the width the header stores it.
const NOTIFY_MAX_USERS_U32: u32 = 1024;

/// Bound on waiting for the header lock. A holder only does a few syscalls
/// under it; a live holder stuck past this (stopped by a debugger, frozen
/// cgroup) makes an attach fail (the topic loses its wake-ups, not its data)
/// and a detach leave the segment in place (a leak, never an unlink).
const LOCK_TIMEOUT: Duration = Duration::from_secs(2);

/// Bound on open/create retries, in time. Each retry follows an observed
/// state change made by another user (an object closed under us, or a lost
/// `linkat` race), so retrying is progress for the topic; the bound only
/// turns pathological starvation into an error. Retries back off from a
/// yield to a short sleep so a crowd of attachers does not spin.
const ATTACH_BUDGET: Duration = Duration::from_secs(5);

const SLOT_FREE: u32 = 0;
const SLOT_LIVE: u32 = 1;

/// One registered process. Read and written only under the header lock.
#[repr(C)]
struct UserSlot {
    state: u32,
    pid: u32,
    /// Field 22 of `/proc/<pid>/stat`; 0 when unreadable (unknown).
    start_time: u64,
    /// Inode of `/proc/<pid>/ns/pid`; 0 when unreadable (unknown).
    pid_ns: u64,
    /// `/proc/sys/kernel/random/boot_id` text; all zero when unreadable.
    boot_id: [u8; 36],
    _pad: [u8; 4],
}

/// Room for any C library's `pthread_mutex_t` on a supported target.
#[repr(C, align(64))]
struct LockStorage([u8; 64]);

#[repr(C)]
struct NotifyHeader {
    magic: u32,
    version: u32,
    /// `lock_abi()` of the creator: the mutex bytes are only shared between
    /// processes that agree on the C library's mutex layout.
    lock_abi: u32,
    max_users: u32,
    /// 0 while users may register; 1 once the last user left (never reset).
    closed: u32,
    _pad: [u8; 44],
    lock: LockStorage,
    slots: [UserSlot; NOTIFY_MAX_USERS],
}

const _: () = assert!(std::mem::size_of::<UserSlot>() == 64);
const _: () = assert!(std::mem::size_of::<NotifyHeader>() <= HEADER_SIZE);
const _: () = assert!(HEADER_SIZE.is_multiple_of(4096));
const _: () = assert!(std::mem::size_of::<libc::pthread_mutex_t>() <= 64);
const _: () = assert!(std::mem::align_of::<libc::pthread_mutex_t>() <= 64);

/// Tag for the mutex ABI: its size, and which C library laid it out.
fn lock_abi() -> u32 {
    let env: u32 = if cfg!(target_env = "gnu") {
        1
    } else if cfg!(target_env = "musl") {
        2
    } else {
        3
    };
    // The size is asserted above to be at most 64, so it fits in 16 bits.
    let size = u32::try_from(std::mem::size_of::<libc::pthread_mutex_t>());
    debug_assert!(
        size.is_ok(),
        "the pthread_mutex_t ABI fits the 64-octet bound"
    );
    let size = size.unwrap_or_else(|_| {
        log::error!("mutex ABI size tag saturated: pthread_mutex_t exceeds 16 bits");
        u32::MAX
    });
    (env << 16) | (size & 0xFFFF)
}

static TABLE_FULL_WARNED: AtomicBool = AtomicBool::new(false);
static FOREIGN_WARNED: AtomicBool = AtomicBool::new(false);

/// Log `msg` the first time `flag` is raised in this process.
fn warn_once(flag: &AtomicBool, msg: &str) {
    if !flag.swap(true, Ordering::Relaxed) {
        log::warn!("{msg}");
    }
}

fn other_err(msg: &str) -> io::Error {
    io::Error::other(msg.to_string())
}

/// This process's identity, as recorded in a `UserSlot`. Computed fresh at
/// every attach (a cold path) rather than cached: a forked child has its own
/// pid and start time, and must not register under its parent's.
struct Identity {
    pid: u32,
    start_time: u64,
    pid_ns: u64,
    boot_id: [u8; 36],
}

impl Identity {
    fn current() -> Self {
        use std::os::unix::fs::MetadataExt;
        let pid = std::process::id();
        let start_time = owner::read_start_time(pid)
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let pid_ns = std::fs::metadata("/proc/self/ns/pid")
            .map(|m| m.ino())
            .unwrap_or(0);
        let mut boot_id = [0u8; 36];
        let boot = owner::current_boot_id().as_bytes();
        if boot.len() == boot_id.len() {
            boot_id.copy_from_slice(boot);
        }
        Self {
            pid,
            start_time,
            pid_ns,
            boot_id,
        }
    }
}

/// A live mapping of one notify object (named or not).
struct Mapping {
    ptr: *mut u8,
    /// `(st_dev, st_ino)` of the mapped object: what "the name still refers
    /// to this object" is checked against.
    id: (u64, u64),
}

// SAFETY: the mapping is plain shared memory; every access to it goes
// through atomics (buckets) or happens under the process-shared mutex
// (header), so moving or sharing the handle between threads is sound.
unsafe impl Send for Mapping {}
// SAFETY: see `Send` above.
unsafe impl Sync for Mapping {}

impl Mapping {
    /// Map `fd` (left open for the caller to close), refusing an object that
    /// is not exactly `TopicNotify::SEGMENT_SIZE` bytes, or, when
    /// `require_own`, one that is not owned by this effective user with mode
    /// 0600 (another account could otherwise create the name first and read
    /// or rewrite the header every user trusts).
    fn map_fd(fd: libc::c_int, require_own: bool) -> Result<Self> {
        // SAFETY: `stat` is plain old data the kernel fills in; `fd` is a
        // valid descriptor owned by the caller for the duration of the call.
        let st = unsafe {
            let mut st: libc::stat = std::mem::zeroed();
            if libc::fstat(fd, &mut st) < 0 {
                return Err(ShmError::SegmentOpen(io::Error::last_os_error()));
            }
            st
        };
        // SAFETY: geteuid has no preconditions and cannot fail.
        let euid = unsafe { libc::geteuid() };
        if require_own && (st.st_uid != euid || st.st_mode & 0o777 != 0o600) {
            return Err(ShmError::SegmentOpen(other_err(
                "notify segment is not this user's own mode-0600 object (refused, left untouched)",
            )));
        }
        let actual = u64::try_from(st.st_size).unwrap_or(0);
        if actual != TopicNotify::SEGMENT_SIZE as u64 {
            return Err(ShmError::SegmentOpen(other_err(
                "notify segment has an unexpected size (another layout version or a foreign object)",
            )));
        }
        // SAFETY: null hint, a length equal to the object's size checked
        // above, read/write shared mapping of a valid fd at offset 0; the
        // result is checked against MAP_FAILED.
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                TopicNotify::SEGMENT_SIZE,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd,
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            return Err(ShmError::Mmap(io::Error::last_os_error()));
        }
        #[allow(clippy::useless_conversion)] // st_dev/st_ino widths vary by target
        let id = (u64::from(st.st_dev), u64::from(st.st_ino));
        Ok(Self {
            ptr: ptr.cast::<u8>(),
            id,
        })
    }

    fn header(&self) -> *mut NotifyHeader {
        self.ptr.cast::<NotifyHeader>()
    }

    fn buckets(&self) -> *const NotifyBucket {
        // SAFETY: the mapping is SEGMENT_SIZE bytes, HEADER_SIZE of which
        // precede the bucket array; the result stays in bounds.
        unsafe { self.ptr.add(HEADER_SIZE).cast::<NotifyBucket>() }
    }

    fn mutex(&self) -> *mut libc::pthread_mutex_t {
        // SAFETY: in-bounds field projection of the mapped header.
        unsafe { std::ptr::addr_of_mut!((*self.header()).lock).cast() }
    }

    fn slot(&self, i: usize) -> *mut UserSlot {
        debug_assert!(i < NOTIFY_MAX_USERS);
        // SAFETY: in-bounds field projection; `i < NOTIFY_MAX_USERS`.
        unsafe { std::ptr::addr_of_mut!((*self.header()).slots[i]) }
    }

    /// Whether the header is one this build shares: right magic, version,
    /// mutex ABI and table size. Immutable after publication, so it is read
    /// without the lock.
    fn header_is_compatible(&self) -> bool {
        let h = self.header();
        // SAFETY: in-bounds reads of the mapped header; volatile because
        // another process wrote it.
        unsafe {
            std::ptr::addr_of!((*h).magic).read_volatile() == NOTIFY_MAGIC
                && std::ptr::addr_of!((*h).version).read_volatile() == NOTIFY_LAYOUT_VERSION
                && std::ptr::addr_of!((*h).lock_abi).read_volatile() == lock_abi()
                && std::ptr::addr_of!((*h).max_users).read_volatile() == NOTIFY_MAX_USERS_U32
        }
    }

    /// Take the header lock, bounded by `LOCK_TIMEOUT`.
    fn lock(&self) -> io::Result<HeaderLock<'_>> {
        let mut now = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: valid clock id and out-pointer.
        unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut now) };
        let deadline = libc::timespec {
            tv_sec: now.tv_sec + LOCK_TIMEOUT.as_secs() as libc::time_t,
            tv_nsec: now.tv_nsec,
        };
        // SAFETY: the mutex was initialised process-shared and robust by the
        // object's creator before the object was published (see
        // `create_unnamed`); `deadline` is a valid absolute time.
        let rc = unsafe { libc::pthread_mutex_timedlock(self.mutex(), &deadline) };
        match rc {
            0 => Ok(HeaderLock { map: self }),
            libc::EOWNERDEAD => {
                // A holder died inside a critical section. Every critical
                // section leaves the header consistent after each single
                // store (module doc), so the state is usable as it is.
                // SAFETY: we own the mutex in the EOWNERDEAD state, which is
                // exactly when `pthread_mutex_consistent` is to be called.
                unsafe { libc::pthread_mutex_consistent(self.mutex()) };
                Ok(HeaderLock { map: self })
            }
            err => Err(io::Error::from_raw_os_error(err)),
        }
    }

    fn closed(&self) -> bool {
        // SAFETY: in-bounds read of the mapped header, under the lock.
        unsafe { std::ptr::addr_of!((*self.header()).closed).read_volatile() != 0 }
    }

    fn set_closed(&self) {
        // SAFETY: in-bounds write of the mapped header, under the lock.
        unsafe { std::ptr::addr_of_mut!((*self.header()).closed).write_volatile(1) }
    }

    fn slot_state(&self, i: usize) -> u32 {
        // SAFETY: in-bounds read of a row, under the lock.
        unsafe { std::ptr::addr_of!((*self.slot(i)).state).read_volatile() }
    }

    fn slot_pid(&self, i: usize) -> u32 {
        // SAFETY: in-bounds read of a row, under the lock.
        unsafe { std::ptr::addr_of!((*self.slot(i)).pid).read_volatile() }
    }

    fn free_slot(&self, i: usize) {
        // SAFETY: in-bounds write of a row, under the lock (or on an object
        // nobody else can see yet).
        unsafe { std::ptr::addr_of_mut!((*self.slot(i)).state).write_volatile(SLOT_FREE) }
    }

    /// Write `me` into row `i`, then mark it live. The state store comes
    /// last so a crash part-way leaves a free row, never a live row holding
    /// a half-written identity.
    fn fill_slot(&self, i: usize, me: &Identity) {
        let s = self.slot(i);
        // SAFETY: in-bounds writes of a row, under the lock (or on an object
        // nobody else can see yet).
        unsafe {
            std::ptr::addr_of_mut!((*s).pid).write_volatile(me.pid);
            std::ptr::addr_of_mut!((*s).start_time).write_volatile(me.start_time);
            std::ptr::addr_of_mut!((*s).pid_ns).write_volatile(me.pid_ns);
            std::ptr::addr_of_mut!((*s).boot_id).write_volatile(me.boot_id);
            std::ptr::addr_of_mut!((*s).state).write_volatile(SLOT_LIVE);
        }
    }

    /// Whether the process recorded in live row `i` is provably dead.
    fn slot_is_dead(&self, i: usize) -> bool {
        let s = self.slot(i);
        // SAFETY: in-bounds reads of a row, under the lock.
        let (pid, start_time, pid_ns, boot) = unsafe {
            (
                std::ptr::addr_of!((*s).pid).read_volatile(),
                std::ptr::addr_of!((*s).start_time).read_volatile(),
                std::ptr::addr_of!((*s).pid_ns).read_volatile(),
                std::ptr::addr_of!((*s).boot_id).read_volatile(),
            )
        };
        if pid == 0 {
            return false; // not a real pid: unknown, so not dead
        }
        // An unreadable boot id was recorded as zeros: compare it as equal to
        // ours so the boot check cannot call it dead on its own.
        let boot_id = match std::str::from_utf8(&boot) {
            Ok(b) if boot != [0u8; 36] => b.to_string(),
            _ => owner::current_boot_id().to_string(),
        };
        let recorded = owner::Owner {
            pid,
            boot_id,
            pid_ns: if pid_ns == 0 {
                String::new()
            } else {
                pid_ns.to_string()
            },
            start_time: if start_time == 0 {
                String::new()
            } else {
                start_time.to_string()
            },
        };
        owner::owner_is_dead(&recorded)
    }

    /// Free live rows whose process is provably dead, in table order. With
    /// `stop_at_live`, stop at the first row whose process is (or may be)
    /// alive: a detacher only needs to know whether any user is left, and
    /// probing every row (a `kill` and a `/proc` read each) of a crowded
    /// table on every detach would cost milliseconds. Returns whether a live
    /// row was found.
    fn reclaim_dead_rows(&self, stop_at_live: bool) -> bool {
        let mut live = false;
        for i in 0..NOTIFY_MAX_USERS {
            if self.slot_state(i) != SLOT_LIVE {
                continue;
            }
            if self.slot_is_dead(i) {
                log::debug!(
                    "[SHM] notify: reclaimed the row of dead process {}",
                    self.slot_pid(i)
                );
                self.free_slot(i);
            } else {
                live = true;
                if stop_at_live {
                    break;
                }
            }
        }
        live
    }

    fn free_row(&self) -> Option<usize> {
        (0..NOTIFY_MAX_USERS).find(|&i| self.slot_state(i) == SLOT_FREE)
    }

    /// Whether `name` currently refers to this very object.
    fn is_named(&self, name: &str) -> bool {
        let Ok(c_name) = CString::new(name) else {
            return false;
        };
        // SAFETY: valid C string; the fd is checked and closed below.
        let fd = unsafe { libc::shm_open(c_name.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC, 0) };
        if fd < 0 {
            return false;
        }
        // SAFETY: `stat` is plain old data; `fd` is valid until closed here.
        unsafe {
            let mut st: libc::stat = std::mem::zeroed();
            let ok = libc::fstat(fd, &mut st) == 0;
            libc::close(fd);
            #[allow(clippy::useless_conversion)] // st_dev/st_ino widths vary by target
            let id = (u64::from(st.st_dev), u64::from(st.st_ino));
            ok && id == self.id
        }
    }

    /// Unlink `name` if, and only if, it still refers to this object.
    /// Called only under this object's lock with `closed` set (rule 4).
    fn unlink_if_named(&self, name: &str) -> bool {
        if !self.is_named(name) {
            return false;
        }
        let Ok(c_name) = CString::new(name) else {
            return false;
        };
        // SAFETY: valid C string; only affects the name, not any mapping.
        unsafe { libc::shm_unlink(c_name.as_ptr()) == 0 }
    }
}

impl Drop for Mapping {
    fn drop(&mut self) {
        // SAFETY: `ptr` came from a successful mmap of SEGMENT_SIZE bytes and
        // is unmapped exactly once, here.
        unsafe {
            libc::munmap(self.ptr.cast(), TopicNotify::SEGMENT_SIZE);
        }
    }
}

/// The header lock; released on drop.
struct HeaderLock<'a> {
    map: &'a Mapping,
}

impl Drop for HeaderLock<'_> {
    fn drop(&mut self) {
        // SAFETY: this guard exists only while this thread holds the mutex.
        unsafe { libc::pthread_mutex_unlock(self.map.mutex()) };
    }
}

/// Outcome of one open-or-create attempt.
enum Attempt {
    Attached(Attachment),
    /// The object found under the name is closing, or another creator won
    /// the race: look the name up again.
    Retry,
}

/// One process's registration on one notify object.
struct Attachment {
    map: Mapping,
    name: String,
    slot: usize,
    /// The pid that registered `slot`. A forked child inherits the handle but
    /// is not the registered user, so it must not release the row.
    pid: u32,
    released: bool,
}

impl Attachment {
    /// Open-or-create (when `create`) and register, retrying across objects
    /// that close under us and lost creation races.
    fn attach(name: &str, create: bool) -> Result<Self> {
        validate_name(name)?;
        let deadline = std::time::Instant::now() + ATTACH_BUDGET;
        let mut retries: u32 = 0;
        while std::time::Instant::now() < deadline {
            let attempt = match Self::open_existing(name) {
                Ok(attempt) => attempt,
                Err(ShmError::NotFound(_)) if create => Self::create_published(name)?,
                Err(err) => return Err(err),
            };
            match attempt {
                Attempt::Attached(attachment) => return Ok(attachment),
                Attempt::Retry => {
                    retries = retries.saturating_add(1);
                    if retries < 8 {
                        std::thread::yield_now();
                    } else {
                        let micros = 50u64 << (retries - 8).min(5);
                        std::thread::sleep(Duration::from_micros(micros));
                    }
                }
            }
        }
        Err(ShmError::SegmentOpen(other_err(
            "notify segment kept closing under every attach attempt",
        )))
    }

    /// Map the object currently under `name` and register on it.
    fn open_existing(name: &str) -> Result<Attempt> {
        let c_name = CString::new(name).map_err(|_| ShmError::InvalidName(name.to_string()))?;
        // SAFETY: valid C string; the fd is checked and closed below.
        let fd = unsafe {
            libc::shm_open(
                c_name.as_ptr(),
                libc::O_RDWR | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0,
            )
        };
        if fd < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::NotFound {
                return Err(ShmError::NotFound(name.to_string()));
            }
            return Err(ShmError::SegmentOpen(err));
        }
        let map = Mapping::map_fd(fd, true);
        // SAFETY: `fd` is valid and closed exactly once; the mapping (if
        // any) holds its own reference to the object.
        unsafe { libc::close(fd) };
        let map = map.inspect_err(|_| {
            warn_once(
                &FOREIGN_WARNED,
                &format!(
                    "[SHM] notify {name}: the object under this name is not this user's own \
                     mode-0600 notify segment; refused and left untouched (further refusals \
                     not logged)"
                ),
            );
        })?;
        if !map.header_is_compatible() {
            warn_once(
                &FOREIGN_WARNED,
                &format!(
                    "[SHM] notify {name}: the object under this name is not a version-2 notify \
                     segment of this build; refused and left untouched (further refusals not logged)"
                ),
            );
            return Err(ShmError::SegmentOpen(other_err(
                "notify segment header is not this layout version (refused, left untouched)",
            )));
        }

        let me = Identity::current();
        let slot = {
            let _lock = map.lock().map_err(ShmError::SegmentOpen)?;
            if map.closed() {
                // The last user left (rule 2). If its unlink never happened
                // (it died in between), finish it: we hold the lock and the
                // object is closed, so rule 4 applies to us.
                map.unlink_if_named(name);
                return Ok(Attempt::Retry);
            }
            // Dead rows are reclaimed by every detach; an attach only needs
            // to when the table looks full.
            let free = match map.free_row() {
                Some(free) => Some(free),
                None => {
                    map.reclaim_dead_rows(false);
                    map.free_row()
                }
            };
            let Some(free) = free else {
                warn_once(
                    &TABLE_FULL_WARNED,
                    &format!(
                        "[SHM] notify {name}: user table full ({NOTIFY_MAX_USERS} live processes); \
                         this process gets no wake-ups for the topic (further refusals not logged)"
                    ),
                );
                return Err(ShmError::SegmentOpen(other_err(
                    "notify segment user table is full",
                )));
            };
            map.fill_slot(free, &me);
            free
        };
        Ok(Attempt::Attached(Self {
            map,
            name: name.to_string(),
            slot,
            pid: me.pid,
            released: false,
        }))
    }

    /// Build an initialised, registered object off-name, then publish it
    /// under `name` unless someone else already did.
    fn create_published(name: &str) -> Result<Attempt> {
        let (fd, map) = create_unnamed()?;
        let me = Identity::current();
        // The creator is registered BEFORE the object becomes reachable
        // (rule 1): nobody can observe it with zero users.
        map.fill_slot(0, &me);

        let src = CString::new(format!("/proc/self/fd/{fd}"))
            .map_err(|_| ShmError::InvalidName(name.to_string()))?;
        let dst = CString::new(format!("/dev/shm/{}", name.trim_start_matches('/')))
            .map_err(|_| ShmError::InvalidName(name.to_string()))?;
        // SAFETY: valid C strings; `fd` is valid until closed below.
        let rc = unsafe {
            libc::linkat(
                libc::AT_FDCWD,
                src.as_ptr(),
                libc::AT_FDCWD,
                dst.as_ptr(),
                libc::AT_SYMLINK_FOLLOW,
            )
        };
        let link_err = (rc != 0).then(io::Error::last_os_error);
        #[cfg(test)]
        if link_err.is_none() {
            tests::run_after_publish_hook(name);
        }
        // SAFETY: `fd` is valid and closed exactly once.
        unsafe { libc::close(fd) };
        match link_err {
            None => Ok(Attempt::Attached(Self {
                map,
                name: name.to_string(),
                slot: 0,
                pid: me.pid,
                released: false,
            })),
            // Another creator published first: our object was never visible
            // and dies with `map`. Open theirs.
            Some(err) if err.raw_os_error() == Some(libc::EEXIST) => Ok(Attempt::Retry),
            Some(err) => Err(ShmError::SegmentCreate(err)),
        }
    }

    /// Release this registration. Returns true when this call unlinked the
    /// name (this was the last live user).
    fn release(&mut self) -> bool {
        if self.released {
            return false;
        }
        self.released = true;
        if std::process::id() != self.pid {
            return false; // forked copy: the row is the parent's
        }
        let lock = match self.map.lock() {
            Ok(lock) => lock,
            Err(err) => {
                log::warn!(
                    "[SHM] notify {}: could not take the header lock to detach ({}); \
                     leaving the segment in place",
                    self.name,
                    err
                );
                return false;
            }
        };
        if self.map.slot_state(self.slot) == SLOT_LIVE && self.map.slot_pid(self.slot) == self.pid {
            self.map.free_slot(self.slot);
        }
        let unlinked = if !self.map.reclaim_dead_rows(true) {
            self.map.set_closed();
            self.map.unlink_if_named(&self.name)
        } else {
            false
        };
        drop(lock);
        unlinked
    }
}

impl Drop for Attachment {
    fn drop(&mut self) {
        self.release();
    }
}

/// Create an unnamed, initialised object on `/dev/shm`. Returns its fd
/// (still open, for `linkat`) and its mapping.
fn create_unnamed() -> Result<(libc::c_int, Mapping)> {
    let dir = CString::new("/dev/shm").map_err(|_| ShmError::InvalidName("/dev/shm".into()))?;
    // SAFETY: valid C string; the fd is checked below.
    let fd = unsafe {
        libc::open(
            dir.as_ptr(),
            libc::O_TMPFILE | libc::O_RDWR | libc::O_CLOEXEC,
            0o600 as libc::c_uint,
        )
    };
    if fd < 0 {
        return Err(ShmError::SegmentCreate(io::Error::last_os_error()));
    }
    let fail = |err: ShmError| {
        // SAFETY: `fd` is valid and closed exactly once on this error path.
        unsafe { libc::close(fd) };
        Err(err)
    };
    // SAFETY: `fd` is valid; SEGMENT_SIZE fits off_t.
    if unsafe { libc::ftruncate(fd, TopicNotify::SEGMENT_SIZE as libc::off_t) } < 0 {
        return fail(ShmError::SegmentCreate(io::Error::last_os_error()));
    }
    // The mode asked for above is filtered by the umask; set it exactly.
    // SAFETY: `fd` is valid.
    if unsafe { libc::fchmod(fd, 0o600) } < 0 {
        return fail(ShmError::SegmentCreate(io::Error::last_os_error()));
    }
    let map = match Mapping::map_fd(fd, false) {
        Ok(map) => map,
        Err(err) => return fail(err),
    };
    // Fresh tmpfs pages are zero: every row is SLOT_FREE and `closed` is 0.
    // SAFETY: the object is unnamed, so this thread is its only user; the
    // attr is initialised before use and destroyed after.
    let rc = unsafe {
        let h = map.header();
        std::ptr::addr_of_mut!((*h).magic).write(NOTIFY_MAGIC);
        std::ptr::addr_of_mut!((*h).version).write(NOTIFY_LAYOUT_VERSION);
        std::ptr::addr_of_mut!((*h).lock_abi).write(lock_abi());
        std::ptr::addr_of_mut!((*h).max_users).write(NOTIFY_MAX_USERS_U32);
        let mut attr: libc::pthread_mutexattr_t = std::mem::zeroed();
        let mut rc = libc::pthread_mutexattr_init(&mut attr);
        if rc == 0 {
            rc = libc::pthread_mutexattr_setpshared(&mut attr, libc::PTHREAD_PROCESS_SHARED);
            if rc == 0 {
                rc = libc::pthread_mutexattr_setrobust(&mut attr, libc::PTHREAD_MUTEX_ROBUST);
            }
            if rc == 0 {
                rc = libc::pthread_mutex_init(map.mutex(), &attr);
            }
            libc::pthread_mutexattr_destroy(&mut attr);
        }
        rc
    };
    if rc != 0 {
        return fail(ShmError::SegmentCreate(io::Error::from_raw_os_error(rc)));
    }
    Ok((fd, map))
}

fn validate_name(name: &str) -> Result<()> {
    let ok =
        name.starts_with('/') && name.len() > 1 && !name[1..].contains('/') && name.len() <= 255;
    if ok {
        Ok(())
    } else {
        Err(ShmError::InvalidName(name.to_string()))
    }
}

/// This process's attachments, one per name, shared by every `TopicNotify`
/// handle for that name. Only a deduplication: correctness comes from the
/// shared protocol, which also holds between two attachments of one process.
fn registry() -> &'static Mutex<HashMap<String, Weak<Attachment>>> {
    static REGISTRY: OnceLock<Mutex<HashMap<String, Weak<Attachment>>>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Topic-level notification coordinator.
///
/// A handle on the topic's shared notification segment. Every writer and
/// reader for the topic on this host shares the same segment; the segment
/// is unlinked when the last process using it lets go (module doc).
#[derive(Clone)]
pub struct TopicNotify {
    /// First bucket of the mapping that `attachment` keeps alive.
    buckets: *const NotifyBucket,
    attachment: Arc<Attachment>,
}

// SAFETY: `buckets` points into the mapping owned by `attachment`, which
// this handle keeps alive; buckets are only accessed through atomics.
unsafe impl Send for TopicNotify {}
// SAFETY: see `Send` above.
unsafe impl Sync for TopicNotify {}

impl TopicNotify {
    /// Size of the notification segment: one header page plus
    /// 256 buckets x 64 bytes.
    pub const SEGMENT_SIZE: usize =
        HEADER_SIZE + NOTIFY_BUCKET_COUNT * std::mem::size_of::<NotifyBucket>();

    /// Attach to a topic notification segment.
    ///
    /// # Arguments
    ///
    /// * `name` - Segment name (from [`TopicNotify::segment_name`])
    /// * `create` - If true, open the existing segment or create it when
    ///   there is none (never replaces an existing one); if false, only open
    ///   an existing one.
    ///
    /// # Errors
    ///
    /// `NotFound` when `create` is false and no segment exists; an error when
    /// the name holds an object of another layout (left untouched), when the
    /// user table is full, or on a system error.
    pub fn new(name: &str, create: bool) -> Result<Self> {
        let pid = std::process::id();
        let lookup = || {
            registry()
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get(name)
                .and_then(Weak::upgrade)
                .filter(|existing| existing.pid == pid)
        };
        if let Some(existing) = lookup() {
            return Ok(Self::from_attachment(existing));
        }
        // The attach may wait up to LOCK_TIMEOUT on the segment's own lock:
        // never with the process-wide registry held, or one stopped holder
        // of one topic's segment would stall every topic of this process.
        let attachment = Arc::new(Attachment::attach(name, create)?);
        let mut registry = registry().lock().unwrap_or_else(|e| e.into_inner());
        if let Some(existing) = registry
            .get(name)
            .and_then(Weak::upgrade)
            .filter(|existing| existing.pid == pid)
        {
            // Another thread attached meanwhile: share its registration and
            // release ours (a normal detach; theirs keeps the segment).
            drop(registry);
            drop(attachment);
            return Ok(Self::from_attachment(existing));
        }
        registry.retain(|_, weak| weak.strong_count() > 0);
        registry.insert(name.to_string(), Arc::downgrade(&attachment));
        Ok(Self::from_attachment(attachment))
    }

    fn from_attachment(attachment: Arc<Attachment>) -> Self {
        Self {
            buckets: attachment.map.buckets(),
            attachment,
        }
    }

    /// Whether the segment's name still refers to the object this handle
    /// maps, i.e. whether a process attaching now would share it. Always
    /// true for a handle whose registration is live; exposed for tests and
    /// diagnostics (a few syscalls, not for the hot path).
    #[must_use]
    pub fn is_linked(&self) -> bool {
        self.attachment.map.is_named(&self.attachment.name)
    }

    /// Get a reference to a specific bucket
    ///
    /// Bucket index must be < NOTIFY_BUCKET_COUNT
    #[inline]
    pub fn bucket(&self, index: usize) -> &NotifyBucket {
        debug_assert!(index < NOTIFY_BUCKET_COUNT);
        // SAFETY: the mapping is alive as long as `self.attachment`, and the
        // bucket array holds NOTIFY_BUCKET_COUNT entries.
        unsafe { &*self.buckets.add(index) }
    }

    /// Compute bucket index for a writer GUID
    ///
    /// Uses FNV-1a hash of the GUID to distribute writers across buckets.
    #[must_use]
    pub fn bucket_for_guid(guid: &[u8; 16]) -> usize {
        let mut hash: u32 = 2_166_136_261;
        for byte in guid {
            hash ^= u32::from(*byte);
            hash = hash.wrapping_mul(16_777_619);
        }
        (hash as usize) % NOTIFY_BUCKET_COUNT
    }

    /// Notify on a specific bucket
    #[inline]
    pub fn notify(&self, bucket_index: usize) {
        self.bucket(bucket_index).notify();
    }

    /// Wait on a specific bucket
    #[inline]
    pub fn wait(&self, bucket_index: usize, snapshot: u32, timeout: Option<Duration>) -> i32 {
        self.bucket(bucket_index).wait(snapshot, timeout)
    }

    /// Get segment name for a topic
    #[must_use]
    pub fn segment_name(domain_id: u32, topic_name: &str) -> String {
        // Sanitize topic name for POSIX shm naming
        let safe_topic: String = topic_name
            .chars()
            .map(|c| if c.is_alphanumeric() { c } else { '_' })
            .collect();
        format!("/{NOTIFY_PREFIX}d{domain_id}_{safe_topic}")
    }
}

/// Name prefix (without the leading `/`) of version-2 notify segments.
pub(crate) const NOTIFY_PREFIX: &str = "hdds_notify_v2_";

/// Release the notify segments of `domain_id` whose every registered user is
/// provably dead (a process that crashed while it was the last user).
///
/// For each such segment this attaches (which reclaims dead rows) and
/// detaches (which unlinks when no live user is left): exactly the protocol
/// any user follows, so it is safe against live users and concurrent
/// attachers. A segment this process already uses is skipped. Meant for
/// participant startup.
///
/// # Returns
///
/// Number of segments unlinked.
pub fn reclaim_dead_notify_segments(domain_id: u32) -> usize {
    let prefix = format!("{NOTIFY_PREFIX}d{domain_id}_");
    let Ok(entries) = std::fs::read_dir("/dev/shm") else {
        return 0;
    };
    let names: Vec<String> = entries
        .flatten()
        .filter_map(|e| e.file_name().to_str().map(str::to_string))
        .filter(|n| n.starts_with(&prefix))
        .collect();
    let mut unlinked = 0;
    for base in names {
        let name = format!("/{base}");
        {
            let registry = registry().lock().unwrap_or_else(|e| e.into_inner());
            if registry
                .get(&name)
                .is_some_and(|weak| weak.strong_count() > 0)
            {
                continue;
            }
        }
        if let Ok(mut attachment) = Attachment::attach(&name, false) {
            if attachment.release() {
                unlinked += 1;
            }
        }
    }
    unlinked
}

#[cfg(test)]
mod tests {
    use super::*;

    thread_local! {
        static AFTER_PUBLISH: std::cell::Cell<Option<fn(&str)>> =
            const { std::cell::Cell::new(None) };
    }

    /// Runs (once) a hook set by the current test thread right after a
    /// successful publish, before the creator does anything else.
    pub(super) fn run_after_publish_hook(name: &str) {
        if let Some(hook) = AFTER_PUBLISH.with(std::cell::Cell::take) {
            hook(name);
        }
    }

    fn unique_name(tag: &str) -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        TopicNotify::segment_name(0, &format!("unit_{tag}_{}_{ts}", std::process::id()))
    }

    fn exists(name: &str) -> bool {
        super::super::segment::ShmSegment::exists(name)
    }

    #[test]
    fn test_notify_bucket_alignment() {
        assert_eq!(std::mem::align_of::<NotifyBucket>(), 64);
        assert_eq!(std::mem::size_of::<NotifyBucket>(), 64);
    }

    #[test]
    fn test_notify_bucket_increment() {
        let bucket = NotifyBucket::new();
        assert_eq!(bucket.snapshot(), 0);

        // Note: notify() calls futex_wake which is fine in tests
        bucket.val.fetch_add(1, Ordering::Release);
        assert_eq!(bucket.snapshot(), 1);
    }

    #[test]
    fn test_bucket_for_guid_distribution() {
        // Test that different GUIDs get distributed across buckets
        let mut buckets_used = std::collections::HashSet::new();

        for i in 0u8..100 {
            let mut guid = [0u8; 16];
            guid[0] = i;
            let bucket = TopicNotify::bucket_for_guid(&guid);
            assert!(bucket < NOTIFY_BUCKET_COUNT);
            buckets_used.insert(bucket);
        }

        // Should use at least 50 different buckets for 100 GUIDs
        assert!(buckets_used.len() > 50, "Poor bucket distribution");
    }

    #[test]
    fn test_segment_name_sanitization() {
        let name = TopicNotify::segment_name(0, "my/topic/name");
        assert_eq!(name, "/hdds_notify_v2_d0_my_topic_name");

        let name2 = TopicNotify::segment_name(42, "Hello World!");
        assert_eq!(name2, "/hdds_notify_v2_d42_Hello_World_");
    }

    #[test]
    fn test_segment_size() {
        // 128 bytes of header fields and lock, 1024 rows of 64 bytes, rounded
        // up to whole pages, then 256 buckets of 64 bytes.
        assert_eq!(HEADER_SIZE, (128 + 1024 * 64usize).next_multiple_of(4096));
        assert_eq!(TopicNotify::SEGMENT_SIZE, HEADER_SIZE + 256 * 64);
    }

    /// The first 8 bytes are what a version-1 binary's
    /// `cleanup_stale_segments` reads as a ring head and calls stale above
    /// 2^48: a version-2 header must stay below that.
    #[test]
    fn header_prefix_is_not_stale_to_a_version_one_scan() {
        let first_word = u64::from(NOTIFY_MAGIC) | (u64::from(NOTIFY_LAYOUT_VERSION) << 32);
        assert!(first_word <= 1u64 << 48);
    }

    #[test]
    fn last_handle_unlinks_and_shared_handles_do_not() {
        let name = unique_name("last");
        let a = TopicNotify::new(&name, true).expect("create");
        let b = TopicNotify::new(&name, false).expect("open");
        assert!(a.is_linked() && b.is_linked());
        let before = b.bucket(3).snapshot();
        a.bucket(3).val.fetch_add(1, Ordering::Release);
        assert_eq!(b.bucket(3).snapshot(), before.wrapping_add(1));
        drop(a);
        assert!(exists(&name), "a handle is still alive");
        drop(b);
        assert!(!exists(&name), "the last handle must unlink");
    }

    #[test]
    fn open_only_does_not_create() {
        let name = unique_name("openonly");
        assert!(matches!(
            TopicNotify::new(&name, false),
            Err(ShmError::NotFound(_))
        ));
        assert!(!exists(&name));
    }

    /// Two attachments in one process (bypassing the registry) behave like
    /// two processes: the first to leave does not unlink.
    #[test]
    fn two_registrations_last_one_unlinks() {
        let name = unique_name("tworeg");
        let mut a = Attachment::attach(&name, true).expect("a");
        let mut b = Attachment::attach(&name, true).expect("b");
        assert_ne!(a.map.id, (0, 0));
        assert_eq!(a.map.id, b.map.id, "both must map the same object");
        assert!(!a.release(), "b is still registered");
        assert!(exists(&name));
        assert!(b.map.is_named(&name));
        assert!(b.release(), "b is the last user");
        assert!(!exists(&name));
    }

    /// A row whose process is provably dead is reclaimed by the next
    /// detacher, which then unlinks as the last live user.
    #[test]
    fn a_dead_row_is_reclaimed_by_the_next_detach() {
        let name = unique_name("deadrow");
        let mut a = Attachment::attach(&name, true).expect("a");
        // Forge a second row from a previous boot: provably dead.
        let mut ghost = Identity::current();
        ghost.boot_id = *b"00000000-0000-0000-0000-000000000001";
        {
            let _l = a.map.lock().unwrap();
            a.map.fill_slot(5, &ghost);
        }
        assert!(a.release(), "the ghost row must not keep the segment alive");
        assert!(!exists(&name));
    }

    /// A row whose process is alive (here: this very process, in another
    /// row) is never reclaimed.
    #[test]
    fn a_live_row_is_never_reclaimed() {
        let name = unique_name("liverow");
        let mut a = Attachment::attach(&name, true).expect("a");
        {
            let _l = a.map.lock().unwrap();
            a.map.fill_slot(7, &Identity::current());
        }
        assert!(!a.release(), "a live row must keep the segment");
        assert!(exists(&name));
        // Clean up the forged row through the protocol.
        let mut b = Attachment::attach(&name, false).expect("b");
        {
            let _l = b.map.lock().unwrap();
            b.map.free_slot(7);
        }
        assert!(b.release());
        assert!(!exists(&name));
    }

    /// A closed object's late locker must never unlink a NEWER object that
    /// now carries the name (rule 4's inode check).
    #[test]
    fn a_closed_object_never_unlinks_its_successor() {
        let name = unique_name("successor");
        let mut old = Attachment::attach(&name, true).expect("old");
        // Leave as a last user would, keeping the (now unnamed) mapping.
        {
            let _l = old.map.lock().unwrap();
            old.map.free_slot(old.slot);
            old.map.set_closed();
            assert!(old.map.unlink_if_named(&name));
        }
        old.released = true;
        let newer = TopicNotify::new(&name, true).expect("newer");
        assert!(newer.is_linked());
        // A late locker of the closed object sees `closed` and must not
        // unlink the name, which now belongs to `newer`.
        {
            let _l = old.map.lock().unwrap();
            assert!(old.map.closed());
            assert!(!old.map.unlink_if_named(&name));
        }
        assert!(exists(&name), "the successor must survive");
        drop(old);
        drop(newer);
        assert!(!exists(&name));
    }

    /// An attacher that meets a closed object whose closer died before
    /// unlinking finishes the unlink and attaches to a fresh object.
    #[test]
    fn a_closed_but_still_named_object_is_finished_by_the_next_attacher() {
        let name = unique_name("finish");
        let mut a = Attachment::attach(&name, true).expect("a");
        let stale_id = a.map.id;
        {
            let _l = a.map.lock().unwrap();
            a.map.free_slot(a.slot);
            a.map.set_closed(); // "dies" before unlinking
        }
        a.released = true;
        assert!(exists(&name));
        let fresh = Attachment::attach(&name, true).expect("fresh");
        assert_ne!(
            fresh.map.id, stale_id,
            "must not register on a closed object"
        );
        assert!(fresh.map.is_named(&name));
        drop(a);
        drop(fresh);
        assert!(!exists(&name));
    }

    /// A table whose every row belongs to a dead process does not refuse a
    /// new user: the attach reclaims dead rows before looking for a free one.
    #[test]
    fn a_table_full_of_dead_rows_still_admits_a_user() {
        let name = unique_name("fulldead");
        let mut a = Attachment::attach(&name, true).expect("a");
        let mut ghost = Identity::current();
        ghost.boot_id = *b"00000000-0000-0000-0000-000000000003";
        {
            let _l = a.map.lock().unwrap();
            for i in 0..NOTIFY_MAX_USERS {
                a.map.fill_slot(i, &ghost);
            }
        }
        a.released = true; // its own row was overwritten by a ghost
        let mut b = Attachment::attach(&name, false).expect("dead rows must be reclaimed");
        assert!(b.release());
        assert!(!exists(&name));
        drop(a);
    }

    /// A thread that dies holding the header lock does not wedge the
    /// segment: the next locker gets the robust mutex back (EOWNERDEAD).
    #[test]
    fn a_lock_holder_that_dies_does_not_wedge_the_segment() {
        let name = unique_name("deadlock");
        let a = Arc::new(Attachment::attach(&name, true).expect("a"));
        let held = Arc::clone(&a);
        std::thread::spawn(move || {
            std::mem::forget(held.map.lock().expect("lock"));
        })
        .join()
        .expect("holder thread");
        let mut b = Attachment::attach(&name, false).expect("lock must be recovered");
        assert!(!b.release(), "a is still registered");
        drop(a);
        assert!(!exists(&name));
    }

    /// Rule 1: the creator is registered before its object is reachable. A
    /// user that attaches and leaves in the instant right after publication
    /// must find the creator already there, so it does not close the object
    /// under it.
    #[test]
    fn a_user_leaving_right_after_publication_does_not_strand_the_creator() {
        fn attach_and_leave(name: &str) {
            let mut other = Attachment::attach(name, false).expect("published");
            assert!(!other.release(), "the creator is a live user already");
        }
        let name = unique_name("publish");
        AFTER_PUBLISH.with(|h| h.set(Some(attach_and_leave)));
        let mut creator = Attachment::attach(&name, true).expect("create");
        assert!(
            creator.map.is_named(&name),
            "the creator must still be on the linked object"
        );
        assert!(creator.release());
        assert!(!exists(&name));
    }

    /// An existing object that is not this user's own mode-0600 object is
    /// refused and left alone: another local account cannot squat the name.
    #[test]
    fn an_object_with_a_foreign_mode_is_refused_and_kept() {
        use std::os::unix::fs::PermissionsExt;
        let name = unique_name("mode");
        let mut a = Attachment::attach(&name, true).expect("a");
        let path = format!("/dev/shm/{}", name.trim_start_matches('/'));
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "created objects are mode 0600");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(
            Attachment::attach(&name, true).is_err(),
            "a group/world-readable object is refused"
        );
        assert!(exists(&name), "a refused object is never unlinked");
        assert!(a.release());
        assert!(!exists(&name));
    }

    /// A segment whose header lock is held (a stopped holder) delays only
    /// attaches to THAT segment: attaches to other names in the same process
    /// proceed (the process-wide registry is not held across the wait).
    #[test]
    fn a_blocked_attach_does_not_block_other_names() {
        let blocked = unique_name("blocked");
        let other = unique_name("unblocked");
        let held = Arc::new(Attachment::attach(&blocked, true).expect("held"));
        let (locked_tx, locked_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let holder_view = Arc::clone(&held);
        let holder = std::thread::spawn(move || {
            let _lock = holder_view.map.lock().expect("lock");
            locked_tx.send(()).unwrap();
            let _ = release_rx.recv_timeout(Duration::from_secs(10));
        });
        locked_rx.recv().unwrap();
        let blocked_name = blocked.clone();
        let waiter = std::thread::spawn(move || TopicNotify::new(&blocked_name, true).map(|_| ()));
        std::thread::sleep(Duration::from_millis(100)); // let it wait on the lock
        let t = std::time::Instant::now();
        let other_handle = TopicNotify::new(&other, true).expect("other name");
        let took = t.elapsed();
        release_tx.send(()).unwrap();
        holder.join().unwrap();
        let _ = waiter.join().unwrap();
        drop(other_handle);
        drop(held);
        assert!(
            took < Duration::from_millis(500),
            "an unrelated attach waited {took:?} behind a blocked segment"
        );
        assert!(!exists(&blocked) && !exists(&other));
    }

    /// The limit is a clean refusal, not a panic or a wait: with every row
    /// live, one more registration is refused and the segment is untouched.
    #[test]
    fn a_full_table_of_live_rows_refuses_cleanly() {
        let name = unique_name("fulllive");
        let mut a = Attachment::attach(&name, true).expect("a");
        let me = Identity::current();
        {
            let _l = a.map.lock().unwrap();
            for i in 0..NOTIFY_MAX_USERS {
                if i != a.slot {
                    a.map.fill_slot(i, &me);
                }
            }
        }
        assert!(Attachment::attach(&name, true).is_err(), "table is full");
        assert!(exists(&name));
        {
            let _l = a.map.lock().unwrap();
            for i in 0..NOTIFY_MAX_USERS {
                if i != a.slot {
                    a.map.free_slot(i);
                }
            }
        }
        assert!(a.release());
        assert!(!exists(&name));
    }

    /// A version-2 name holding something else is refused and left alone.
    #[test]
    fn a_foreign_object_under_the_name_is_refused_and_kept() {
        let name = unique_name("foreign");
        let seg = super::super::segment::ShmSegment::create(&name, TopicNotify::SEGMENT_SIZE)
            .expect("raw");
        let err = TopicNotify::new(&name, true);
        assert!(err.is_err(), "zeroed header must be refused");
        assert!(exists(&name), "a refused object is never unlinked");
        drop(seg);
        let _ = super::super::segment::ShmSegment::unlink(&name);
    }

    /// Threads racing open-or-create against last-detach (registry bypassed,
    /// so every thread is its own user): a registered user is always on the
    /// linked object, and the name is gone at the end.
    #[test]
    fn create_vs_last_detach_race_threads() {
        let name = unique_name("race");
        let threads: Vec<_> = (0..8)
            .map(|t| {
                let name = name.clone();
                std::thread::spawn(move || {
                    for i in 0..300 {
                        let a = Attachment::attach(&name, true).expect("attach");
                        assert!(
                            a.map.is_named(&name),
                            "thread {t} iteration {i}: registered on an unlinked object"
                        );
                        // SAFETY: bucket index in range; the mapping is alive.
                        unsafe { &*a.map.buckets().add(t) }
                            .val
                            .fetch_add(1, Ordering::Release);
                        drop(a);
                    }
                })
            })
            .collect();
        for t in threads {
            t.join().expect("racer");
        }
        assert!(!exists(&name), "every user left: the name must be gone");
    }

    #[test]
    fn reclaim_sweep_unlinks_a_segment_whose_users_are_all_dead() {
        // Its own domain so no other test's live segment is in the scan.
        let name = TopicNotify::segment_name(4_000_001, &format!("sweep_{}", std::process::id()));
        let mut a = Attachment::attach(&name, true).expect("a");
        // Make our own row look like it belongs to a previous boot, then
        // drop the handle without the protocol: a crashed sole user.
        {
            let _l = a.map.lock().unwrap();
            let mut ghost = Identity::current();
            ghost.boot_id = *b"00000000-0000-0000-0000-000000000002";
            a.map.fill_slot(a.slot, &ghost);
        }
        a.released = true;
        drop(a);
        assert!(exists(&name));
        assert_eq!(reclaim_dead_notify_segments(4_000_001), 1);
        assert!(!exists(&name));
    }
}
