// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! POSIX shared memory segment management.
//!
//! Provides safe wrappers around `shm_open`, `ftruncate`, and `mmap`
//! for creating and mapping shared memory segments.
//!
//! # Segment Lifecycle
//!
//! 1. Writer creates segment with `ShmSegment::create()`
//! 2. Readers open segment with `ShmSegment::open()`
//! 3. Segment is automatically unmapped on drop
//! 4. Writer should call `ShmSegment::unlink()` on cleanup
//!
//! # Naming Convention
//!
//! Segment names must start with `/` and contain no other `/`.
//! Example: `/hdds_d0_w0102030405060708090a0b0c0d0e0f10`

use super::{Result, ShmError};
use std::ffi::CString;
use std::io;
use std::ptr;

/// POSIX shared memory segment wrapper.
///
/// Automatically unmaps the memory region on drop.
/// Does NOT automatically unlink the segment (caller's responsibility).
pub struct ShmSegment {
    /// Pointer to mapped memory region
    ptr: *mut u8,
    /// Size of the mapping
    size: usize,
    /// Segment name (for unlink)
    name: String,
}

// SAFETY: ShmSegment pointer points to shared memory that can be
// accessed from multiple threads/processes. The underlying data
// structures use atomic operations for synchronization.
unsafe impl Send for ShmSegment {}
unsafe impl Sync for ShmSegment {}

impl ShmSegment {
    /// Create a new shared memory segment.
    ///
    /// If a segment with this name already exists, it will be replaced.
    ///
    /// # Arguments
    ///
    /// * `name` - Segment name (must start with `/`, no other `/`)
    /// * `size` - Size in bytes
    ///
    /// # Errors
    ///
    /// Returns error if segment creation or mapping fails.
    pub fn create(name: &str, size: usize) -> Result<Self> {
        Self::validate_name(name)?;

        let c_name = CString::new(name).map_err(|_| ShmError::InvalidName(name.to_string()))?;

        // SAFETY:
        // - c_name is a valid null-terminated CString created above
        // - shm_unlink is safe to call with any valid path; errors are ignored
        // - shm_open with O_CREAT|O_RDWR|O_EXCL creates a new segment or fails if exists
        // - The mode 0o600 is a valid file permission mask
        // - shm_open returns a valid fd on success or -1 on error (checked below)
        let fd = unsafe {
            // Remove existing segment first (ignore errors)
            libc::shm_unlink(c_name.as_ptr());

            libc::shm_open(
                c_name.as_ptr(),
                libc::O_CREAT | libc::O_RDWR | libc::O_EXCL,
                0o600, // Owner read/write only
            )
        };

        if fd < 0 {
            return Err(ShmError::SegmentCreate(io::Error::last_os_error()));
        }

        // Set segment size
        // SAFETY:
        // - fd is a valid file descriptor from the successful shm_open call above
        // - size cast to off_t is safe as segment sizes are bounded by validate_name (max 255 char name)
        //   and practical memory limits; ftruncate will fail gracefully if size is too large
        let ret = unsafe { libc::ftruncate(fd, size as libc::off_t) };
        if ret < 0 {
            let err = io::Error::last_os_error();
            // SAFETY:
            // - fd is still valid from the successful shm_open call
            // - close is safe to call once on any valid fd; we're in an error path so fd won't be reused
            unsafe { libc::close(fd) };
            return Err(ShmError::SegmentCreate(err));
        }

        // Map the segment
        // SAFETY:
        // - First argument is null, letting the kernel choose the address (always valid)
        // - size is the user-provided segment size; mmap will fail if invalid
        // - PROT_READ | PROT_WRITE are valid protection flags for a read-write mapping
        // - MAP_SHARED creates a shared mapping visible to other processes
        // - fd is valid from successful shm_open and ftruncate above
        // - Offset 0 maps from the beginning of the segment
        // - mmap returns MAP_FAILED on error (checked below), otherwise a valid pointer
        let ptr = unsafe {
            libc::mmap(
                ptr::null_mut(),
                size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd,
                0,
            )
        };

        // Close fd (mapping keeps reference)
        // SAFETY:
        // - fd is valid from successful shm_open
        // - The mmap call above (success or failure) does not invalidate fd
        // - After mmap succeeds, the mapping holds a reference; closing fd is safe
        // - close is idempotent for error handling purposes
        unsafe { libc::close(fd) };

        if ptr == libc::MAP_FAILED {
            return Err(ShmError::Mmap(io::Error::last_os_error()));
        }

        // Zero-initialize the segment
        // SAFETY:
        // - ptr is valid and points to a memory region of exactly `size` bytes from successful mmap
        // - The mapping has PROT_WRITE permission, so writing is allowed
        // - ptr is properly aligned for u8 (alignment of 1)
        // - size bytes are within the mapped region bounds
        // - No other references exist to this memory yet (segment just created)
        unsafe {
            ptr::write_bytes(ptr as *mut u8, 0, size);
        }

        Ok(Self {
            ptr: ptr as *mut u8,
            size,
            name: name.to_string(),
        })
    }

    /// Open an existing shared memory segment.
    ///
    /// # Arguments
    ///
    /// * `name` - Segment name
    /// * `size` - Expected size (must match or be smaller than actual)
    ///
    /// # Errors
    ///
    /// Returns error if segment doesn't exist or mapping fails.
    pub fn open(name: &str, size: usize) -> Result<Self> {
        Self::validate_name(name)?;

        let c_name = CString::new(name).map_err(|_| ShmError::InvalidName(name.to_string()))?;

        // SAFETY:
        // - c_name is a valid null-terminated CString created above
        // - O_RDWR is a valid flag for opening an existing segment for read/write
        // - Mode 0 is ignored when O_CREAT is not specified
        // - shm_open returns a valid fd on success or -1 on error (checked below)
        let fd = unsafe { libc::shm_open(c_name.as_ptr(), libc::O_RDWR, 0) };

        if fd < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::NotFound {
                return Err(ShmError::NotFound(name.to_string()));
            }
            return Err(ShmError::SegmentOpen(err));
        }

        // KNOWN LIMIT, stated here because the check below reads like more of a
        // guarantee than it is: this is a POINT-IN-TIME read of a size that any
        // holder of a writable fd can change afterwards. `ftruncate` on the
        // object AFTER this mapping exists discards the tmpfs pages behind it,
        // and the next touch of a slot raises SIGBUS, which kills the whole
        // participant rather than the poller thread - Rust installs no handler,
        // and a library has no business installing a process-global one.
        //
        // What bounds it: the segment is created `O_EXCL` mode 0600, so the
        // name cannot be squatted (a writer whose create fails disables its own
        // shared-memory leg, loudly), and truncating the writer's object needs
        // a writable fd, hence the same uid - which already permits `kill(2)`
        // on the victim. So this is not a privilege boundary being crossed. It
        // is still reachable WITHOUT malice, by a buggy peer or an unrelated
        // local tool, and that is the part worth closing.
        //
        // The real fix is not a better size check, it is a segment that cannot
        // shrink and cannot be found by guessing: `memfd_create` with
        // `F_SEAL_SHRINK | F_SEAL_GROW`, handed to the peer as a file
        // descriptor over a unix socket. That also dissolves three other open
        // items at once - the segment stops being addressable by a name derived
        // from public discovery data (the owner-nonce attach below becomes
        // unnecessary), and receiving the fd over a unix socket IS the
        // co-location proof that `host_id` currently only approximates.
        //
        // Refuse a segment smaller than the geometry we are about to map onto
        // it, BEFORE mapping. `mmap` happily maps past the end of the object
        // and the failure surfaces later as a SIGBUS on first touch of a page
        // beyond it, which kills the thread rather than returning an error.
        // Reachable without any hostile intent: a peer built with a different
        // `SLOT_PAYLOAD_SIZE` (the constant has changed before, and the
        // segment name carries neither version nor size), or a segment some
        // other process created under the same name and sized to one page.
        //
        // SAFETY: `stat` is a POD struct the kernel fills in; `fd` is valid
        // from the successful `shm_open` above.
        let actual = unsafe {
            let mut st: libc::stat = std::mem::zeroed();
            if libc::fstat(fd, &mut st) < 0 {
                let err = io::Error::last_os_error();
                libc::close(fd);
                return Err(ShmError::SegmentOpen(err));
            }
            // `st_size` is signed; a negative value is not a size we can
            // honour, so clamp to 0 and let the comparison below refuse it.
            u64::try_from(st.st_size).unwrap_or(0)
        };
        if actual < size as u64 {
            // SAFETY: `fd` is valid and not yet closed on this path.
            unsafe { libc::close(fd) };
            return Err(ShmError::SegmentTooSmall {
                actual,
                expected: size,
            });
        }

        // Map the segment
        // SAFETY:
        // - First argument is null, letting the kernel choose the address (always valid)
        // - size is the expected segment size, checked against the object's real size above
        // - PROT_READ | PROT_WRITE are valid protection flags
        // - MAP_SHARED creates a shared mapping visible to other processes
        // - fd is valid from successful shm_open above
        // - Offset 0 maps from the beginning of the segment
        // - mmap returns MAP_FAILED on error (checked below), otherwise a valid pointer
        let ptr = unsafe {
            libc::mmap(
                ptr::null_mut(),
                size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd,
                0,
            )
        };

        // Close fd (mapping keeps reference)
        // SAFETY:
        // - fd is valid from successful shm_open
        // - The mmap call above (success or failure) does not invalidate fd
        // - After mmap succeeds, the mapping holds a reference; closing fd is safe
        unsafe { libc::close(fd) };

        if ptr == libc::MAP_FAILED {
            return Err(ShmError::Mmap(io::Error::last_os_error()));
        }

        Ok(Self {
            ptr: ptr as *mut u8,
            size,
            name: name.to_string(),
        })
    }

    /// Validate segment name follows POSIX rules
    fn validate_name(name: &str) -> Result<()> {
        if !name.starts_with('/') {
            return Err(ShmError::InvalidName(format!(
                "Segment name must start with '/': {name}"
            )));
        }
        if name.len() > 1 && name[1..].contains('/') {
            return Err(ShmError::InvalidName(format!(
                "Segment name cannot contain '/' after prefix: {name}"
            )));
        }
        if name.len() > 255 {
            return Err(ShmError::InvalidName(format!(
                "Segment name too long (max 255): {name}"
            )));
        }
        Ok(())
    }

    /// Unlink (delete) a shared memory segment by name.
    ///
    /// The segment will be removed once all processes unmap it.
    /// This should be called by the creator when cleaning up.
    ///
    /// # Errors
    ///
    /// Returns error if unlink fails (segment not found is not an error).
    pub fn unlink(name: &str) -> Result<()> {
        let c_name = CString::new(name).map_err(|_| ShmError::InvalidName(name.to_string()))?;

        // SAFETY:
        // - c_name is a valid null-terminated CString created above
        // - shm_unlink removes the named shared memory object
        // - Safe to call even if segment doesn't exist (returns error, handled below)
        // - No memory safety issues; only affects the filesystem namespace
        let ret = unsafe { libc::shm_unlink(c_name.as_ptr()) };

        // Best-effort: remove the crash-reclamation sidecar record (see
        // `super::owner`), if any, HERE rather than only in
        // `ShmRingWriter::unlink`. This is the one choke point every caller
        // that removes a segment by name goes through (the ring's own
        // `unlink`, every test's `UnlinkOnDrop`, `cleanup_stale_segments`,
        // `cleanup_domain_segments`, a product caller that force-unlinks a
        // stale segment before re-creating it), so a segment cannot
        // lose its name while leaving its sidecar file behind for
        // `reclaim_dead_ring_segments` to keep stumbling over on an
        // already-gone segment. A segment that never had one (every name
        // outside the ring naming scheme) just gets a harmless no-op remove.
        super::owner::remove_owner_record(name);

        if ret < 0 {
            let err = io::Error::last_os_error();
            // Not found is OK (idempotent cleanup)
            if err.kind() != io::ErrorKind::NotFound {
                return Err(ShmError::SegmentOpen(err));
            }
        }

        Ok(())
    }

    /// Get raw pointer to the mapped memory
    #[inline]
    #[must_use]
    pub fn as_ptr(&self) -> *mut u8 {
        self.ptr
    }

    /// Get the size of the mapping
    #[inline]
    #[must_use]
    pub fn size(&self) -> usize {
        self.size
    }

    /// Get the segment name
    #[inline]
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Check if a segment with the given name exists
    #[must_use]
    pub fn exists(name: &str) -> bool {
        let Ok(c_name) = CString::new(name) else {
            return false;
        };

        // SAFETY:
        // - c_name is a valid null-terminated CString created above
        // - O_RDONLY is a valid flag for read-only access check
        // - Mode 0 is ignored when O_CREAT is not specified
        // - shm_open returns a valid fd on success or -1 if segment doesn't exist
        let fd = unsafe { libc::shm_open(c_name.as_ptr(), libc::O_RDONLY, 0) };

        if fd >= 0 {
            // SAFETY:
            // - fd is valid (>= 0) from successful shm_open
            // - close is safe to call once on any valid fd
            // - fd is not used after this point
            unsafe { libc::close(fd) };
            true
        } else {
            false
        }
    }
}

impl Drop for ShmSegment {
    fn drop(&mut self) {
        // SAFETY:
        // - self.ptr was obtained from a successful mmap call in create() or open()
        // - self.size is the exact size that was passed to mmap
        // - The pointer has not been munmap'd before (Drop is called only once)
        // - munmap is safe to call on any valid mmap'd region
        // - After munmap, self.ptr becomes invalid, but the struct is being dropped
        unsafe {
            libc::munmap(self.ptr as *mut libc::c_void, self.size);
        }
        // Note: We do NOT unlink here. The creator is responsible for cleanup.
    }
}

/// Cleanup stale HDDS shared memory segments.
///
/// Scans `/dev/shm` for segments matching the HDDS naming pattern
/// (`/hdds_d*_w*` for writers, plus version-1 `/hdds_notify_d*_*` notify
/// segments) and removes any that look stale. Version-2 notify segments
/// (`/hdds_notify_v2_*`) are skipped: see `reclaim_dead_notify_segments`.
///
/// This should be called at participant startup to clean up segments
/// left behind by crashed processes.
///
/// # Returns
///
/// Number of segments cleaned up.
///
/// # Example
///
/// ```ignore
/// use hdds::transport::shm::cleanup_stale_segments;
///
/// let cleaned = cleanup_stale_segments();
/// if cleaned > 0 {
///     log::info!("Cleaned up {} stale SHM segments", cleaned);
/// }
/// ```
pub fn cleanup_stale_segments() -> usize {
    let mut cleaned = 0;

    // On Linux, SHM segments appear in /dev/shm
    let shm_dir = std::path::Path::new("/dev/shm");
    if !shm_dir.exists() {
        return 0;
    }

    let Ok(entries) = std::fs::read_dir(shm_dir) else {
        return 0;
    };

    for entry in entries.flatten() {
        let file_name = entry.file_name();
        let Some(name) = file_name.to_str() else {
            continue;
        };

        // Check if this is an HDDS segment
        if !name.starts_with("hdds_") {
            continue;
        }

        // Owner-reclamation sidecars (`super::owner`) live right beside
        // their segment under the SAME "hdds_" prefix, as a plain text
        // file (`<segment-name>.owner`), never a shared-memory object. A
        // scan keyed only on the prefix also matches these: `shm_open`
        // happily opens an ordinary tmpfs file that was never created via
        // `shm_open`, `is_segment_stale` then reads its text bytes as a
        // binary `head` counter (almost always "huge", since the content
        // is ASCII), and the segment below unlinks it -- deleting a live
        // owner's crash-reclamation record while the real segment it
        // describes is never touched. Reclaim's own scan
        // (`reclaim_dead_ring_segments`) already excludes `.owner` names
        // for exactly this reason; this scan must too.
        if name.ends_with(".owner") {
            continue;
        }

        // Topic notify segments are released by their last live user, with
        // crashed users reclaimed by `reclaim_dead_notify_segments`; this
        // heuristic (a ring head counter at offset 0) knows nothing about
        // their header and must never unlink one.
        if name.starts_with(super::notify::NOTIFY_PREFIX) {
            continue;
        }

        // Try to detect if the segment is stale by checking if the
        // creating process is still alive. We do this by trying to
        // open the segment and checking the control block.
        let segment_name = format!("/{name}");

        // For now, use a simple heuristic: if we can open the segment
        // but the magic number is invalid or zero, it's likely stale.
        // A more robust approach would store the PID and check /proc.
        if is_segment_stale(&segment_name) && ShmSegment::unlink(&segment_name).is_ok() {
            log::debug!("[SHM] Cleaned up stale segment: {}", segment_name);
            cleaned += 1;
        }
    }

    cleaned
}

/// Check if a segment appears to be stale (orphaned).
///
/// Currently uses a simple heuristic: tries to open and check if
/// the control block has valid data.
fn is_segment_stale(name: &str) -> bool {
    use std::sync::atomic::{AtomicU64, Ordering};

    // Try to open the segment with minimal size to read control block
    let Ok(seg) = ShmSegment::open(name, 64) else {
        // Can't open = doesn't exist or permission denied, not stale
        return false;
    };

    // Check if the segment looks uninitialized or corrupted
    // The first 8 bytes should be the head sequence number
    // A value of u64::MAX is suspicious (uninitialized memory)
    let head_ptr = seg.as_ptr() as *const AtomicU64;
    // SAFETY:
    // - seg.as_ptr() returns a valid pointer from successful ShmSegment::open with size 64
    // - AtomicU64 requires 8-byte alignment; mmap returns page-aligned memory (4096+ bytes)
    //   which satisfies the alignment requirement
    // - The segment is at least 64 bytes, so reading 8 bytes is within bounds
    // - Atomic load with Relaxed ordering is safe for reading potentially uninitialized
    //   shared memory; we're just checking for corruption heuristics
    let head = unsafe { (*head_ptr).load(Ordering::Relaxed) };

    // Heuristic: if head is extremely large, likely corrupted/stale
    // Normal operation would have head < 2^48 even after years of operation
    head > (1u64 << 48)
}

/// Cleanup segments for a specific domain.
///
/// More targeted cleanup that only removes segments for the given domain ID.
///
/// Unconditional: it unlinks every ring segment and every version-1 notify
/// segment (`/hdds_notify_d<domain>_*`) of the domain, live or not, so it is
/// for tools and tests that own the whole domain. Version-2 notify segments
/// are not matched by either prefix and are only ever released by their
/// last user (`reclaim_dead_notify_segments` for crashed ones).
pub fn cleanup_domain_segments(domain_id: u32) -> usize {
    let mut cleaned = 0;

    let shm_dir = std::path::Path::new("/dev/shm");
    if !shm_dir.exists() {
        return 0;
    }

    let Ok(entries) = std::fs::read_dir(shm_dir) else {
        return 0;
    };

    let prefix = format!("hdds_d{domain_id}_");
    let notify_prefix = format!("hdds_notify_d{domain_id}_");

    for entry in entries.flatten() {
        let file_name = entry.file_name();
        let Some(name) = file_name.to_str() else {
            continue;
        };

        // Same exclusion as `cleanup_stale_segments`: an owner sidecar
        // (`<segment-name>.owner`) matches this prefix too but is a plain
        // text file, never a segment -- never unlink it here.
        if name.ends_with(".owner") {
            continue;
        }

        if name.starts_with(&prefix) || name.starts_with(&notify_prefix) {
            let segment_name = format!("/{name}");
            if ShmSegment::unlink(&segment_name).is_ok() {
                log::debug!(
                    "[SHM] Cleaned up domain {} segment: {}",
                    domain_id,
                    segment_name
                );
                cleaned += 1;
            }
        }
    }

    cleaned
}

#[cfg(test)]
mod tests {
    use super::super::test_support::UnlinkOnDrop;
    use super::*;

    fn unique_name() -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        format!("/hdds_unit_{ts}")
    }

    #[test]
    fn test_validate_name_valid() {
        assert!(ShmSegment::validate_name("/foo").is_ok());
        assert!(ShmSegment::validate_name("/hdds_d0_w1234").is_ok());
    }

    #[test]
    fn test_validate_name_no_leading_slash() {
        assert!(ShmSegment::validate_name("foo").is_err());
    }

    #[test]
    fn test_validate_name_embedded_slash() {
        assert!(ShmSegment::validate_name("/foo/bar").is_err());
    }

    #[test]
    fn test_create_and_open() {
        let name = unique_name();
        let size = 4096;
        let _guard = UnlinkOnDrop::one(name.clone());

        // Create segment
        let seg1 = ShmSegment::create(&name, size).expect("Failed to create");
        assert_eq!(seg1.size(), size);

        // SAFETY: seg1 was just created with size 4096, so offsets 0 and 1 are valid.
        // as_ptr() returns a valid pointer to the mapped memory region.
        unsafe {
            *seg1.as_ptr() = 0x42;
            *seg1.as_ptr().add(1) = 0x43;
        }

        // Open same segment from "another process"
        let seg2 = ShmSegment::open(&name, size).expect("Failed to open");

        // SAFETY: seg2 opened the same shared memory segment with size 4096.
        // Offsets 0 and 1 are valid and were written by seg1 above.
        unsafe {
            assert_eq!(*seg2.as_ptr(), 0x42);
            assert_eq!(*seg2.as_ptr().add(1), 0x43);
        }

        // Cleanup is the guard's job; dropping the mappings here is
        // still useful so the guard's unlink (which runs after, LIFO) is
        // not racing a still-mapped segment in spirit, though POSIX would
        // allow either order.
        drop(seg1);
        drop(seg2);
    }

    #[test]
    fn test_open_nonexistent() {
        let result = ShmSegment::open("/hdds_nonexistent_12345", 4096);
        assert!(matches!(result, Err(ShmError::NotFound(_))));
    }

    #[test]
    fn test_exists() {
        let name = unique_name();
        let _guard = UnlinkOnDrop::one(name.clone());

        assert!(!ShmSegment::exists(&name));

        let _seg = ShmSegment::create(&name, 4096).expect("Failed to create");
        assert!(ShmSegment::exists(&name));
    }

    #[test]
    fn test_unlink_idempotent() {
        let name = unique_name();
        let _guard = UnlinkOnDrop::one(name.clone());

        // Create and immediately unlink
        let _seg = ShmSegment::create(&name, 4096).expect("Failed to create");
        assert!(ShmSegment::unlink(&name).is_ok());

        // Second unlink should also succeed (idempotent); the guard's own
        // unlink on drop is a third, for the same reason.
        assert!(ShmSegment::unlink(&name).is_ok());
    }

    #[test]
    fn test_cleanup_stale_segments() {
        // This test just verifies the function runs without crashing
        // Actual cleanup behavior is hard to test without creating stale segments
        let cleaned = cleanup_stale_segments();
        // Should be 0 or more (we don't know if there are stale segments)
        assert!(cleaned < 1000); // Sanity check
    }

    #[test]
    fn test_cleanup_domain_segments() {
        // Create a test segment for domain 999 (unlikely to conflict)
        let name = "/hdds_d999_wtest123";
        let _guard = UnlinkOnDrop::one(name);
        let _seg = ShmSegment::create(name, 4096).expect("Failed to create");

        // Cleanup should find and remove it
        let cleaned = cleanup_domain_segments(999);
        assert!(cleaned >= 1);

        // Segment should no longer exist
        assert!(!ShmSegment::exists(name));
    }

    /// Regression: a crash-reclamation sidecar
    /// (`super::owner`, `<segment-name>.owner`) sits right beside its
    /// segment under the SAME "hdds_" prefix this scan matches on. Before
    /// the `.owner` exclusion, `shm_open` happily opened this plain text
    /// file (it was never created via `shm_open`, but Linux's
    /// implementation is just `open()` under `/dev/shm`), `is_segment_stale`
    /// read its ASCII bytes as a binary `head` counter -- "huge" by
    /// construction, since the content is text -- and `cleanup_stale_segments`
    /// unlinked it: deleting a live owner's crash-reclamation record while
    /// the real segment it describes was never touched. A concurrent
    /// `reclaim_dead_ring_segments` scan could thus make a live owner's
    /// sidecar vanish while its segment survived.
    #[test]
    fn cleanup_stale_segments_never_touches_an_owner_sidecar() {
        use std::time::{SystemTime, UNIX_EPOCH};
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        // A REAL backing segment, not just a sidecar file, and a domain
        // (997) nothing else in this binary uses: domain 0 is live traffic
        // for the whole `transport::shm::owner` test module (every one of
        // its tests calls `reclaim_dead_ring_segments(0)`, concurrently,
        // on its own thread), and this probe's sidecar below deliberately
        // carries a FAKE boot_id -- which is exactly what makes a sidecar
        // look provably dead to that function's first pass. On domain 0
        // that call would legitimately reclaim this probe out from under
        // the test (observed: `cleaned`/`reclaimed` counts off by one in
        // sibling tests while this ran on domain 0); domain 997 keeps it
        // out of every domain-scoped function's reach while still being
        // squarely in scope for `cleanup_stale_segments`, which scans
        // every domain -- the one function actually under test here.
        let segment_name = format!("/hdds_d997_wsidecarprobe{ts}");
        let _guard = UnlinkOnDrop::one(segment_name.clone());
        let _seg = ShmSegment::create(&segment_name, 4096).expect("create probe segment");

        let sidecar_path =
            std::path::Path::new("/dev/shm").join(format!("hdds_d997_wsidecarprobe{ts}.owner"));
        // Real owner-record shape and length (> the 64-byte minimum
        // `is_segment_stale` requires to even attempt the read), ASCII
        // throughout -- exactly the content that could misread as a "stale"
        // head counter.
        std::fs::write(
            &sidecar_path,
            format!(
                "v3:{}:00000000-0000-0000-0000-000000000000:1:123456",
                std::process::id()
            ),
        )
        .expect("create probe sidecar");

        let _ = cleanup_stale_segments();

        assert!(
            ShmSegment::exists(&segment_name),
            "cleanup_stale_segments must never touch a live segment"
        );
        assert!(
            sidecar_path.exists(),
            "cleanup_stale_segments must never remove a `.owner` sidecar, \
             live or not -- it is not a shared-memory segment"
        );

        std::fs::remove_file(&sidecar_path).expect("remove probe sidecar");
    }

    /// Sibling case for `cleanup_domain_segments`, which scans by the
    /// SAME "hdds_d<domain>_" prefix and has the same exposure: WITHOUT the
    /// `.owner` exclusion, a dangling sidecar with no backing segment (a
    /// crash can leave exactly this behind, same as the orphan case
    /// `reclaim_dead_ring_segments` guards against) is mistaken for a
    /// segment named "<name>.owner" and unlinked by that literal (wrong)
    /// name. This is deliberately NOT "create a segment, then check its
    /// sidecar survives": `cleanup_domain_segments` unconditionally removes
    /// every REAL segment in the domain by design
    /// (`test_cleanup_domain_segments` above pins exactly that), and
    /// `ShmSegment::unlink` already tears down a real segment's own
    /// sidecar as a correct, intentional side effect -- not a bug. Domain
    /// 998, not 999: `test_cleanup_domain_segments` already owns 999.
    #[test]
    fn cleanup_domain_segments_never_touches_a_dangling_owner_sidecar() {
        use std::time::{SystemTime, UNIX_EPOCH};
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let sidecar_path =
            std::path::Path::new("/dev/shm").join(format!("hdds_d998_wsidecarprobe{ts}.owner"));
        std::fs::write(&sidecar_path, "not a real owner record, just text")
            .expect("create probe sidecar");

        let _ = cleanup_domain_segments(998);

        assert!(
            sidecar_path.exists(),
            "cleanup_domain_segments must never remove a `.owner` sidecar \
             (dangling or not -- it is never a shared-memory segment)"
        );

        std::fs::remove_file(&sidecar_path).expect("remove probe sidecar");
    }

    #[test]
    fn test_is_segment_stale_valid_segment() {
        let name = unique_name();
        let _guard = UnlinkOnDrop::one(name.clone());

        // Create a valid segment with initialized control block
        let seg = ShmSegment::create(&name, 4096).expect("Failed to create");

        // SAFETY: seg was just created with size 4096, which is >= size_of::<u64>().
        // as_ptr() returns a valid aligned pointer to the mapped memory region.
        // Writing 0 to the head pointer simulates an initialized control block.
        unsafe {
            let head_ptr = seg.as_ptr() as *mut u64;
            *head_ptr = 0;
        }

        // Should NOT be considered stale
        assert!(!is_segment_stale(&name));

        drop(seg);
    }
}
