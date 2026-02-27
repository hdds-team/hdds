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

        // Map the segment
        // SAFETY:
        // - First argument is null, letting the kernel choose the address (always valid)
        // - size is the expected segment size; caller must ensure it matches or is smaller than actual
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
/// (`/hdds_d*_w*` for writers, `/hdds_notify_d*_*` for notifications)
/// and removes any that are no longer in use.
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
    use super::*;

    fn unique_name() -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        format!("/hdds_test_{ts}")
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

        // Cleanup
        drop(seg1);
        drop(seg2);
        ShmSegment::unlink(&name).ok();
    }

    #[test]
    fn test_open_nonexistent() {
        let result = ShmSegment::open("/hdds_nonexistent_12345", 4096);
        assert!(matches!(result, Err(ShmError::NotFound(_))));
    }

    #[test]
    fn test_exists() {
        let name = unique_name();

        assert!(!ShmSegment::exists(&name));

        let _seg = ShmSegment::create(&name, 4096).expect("Failed to create");
        assert!(ShmSegment::exists(&name));

        ShmSegment::unlink(&name).ok();
    }

    #[test]
    fn test_unlink_idempotent() {
        let name = unique_name();

        // Create and immediately unlink
        let _seg = ShmSegment::create(&name, 4096).expect("Failed to create");
        assert!(ShmSegment::unlink(&name).is_ok());

        // Second unlink should also succeed (idempotent)
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
        let _seg = ShmSegment::create(name, 4096).expect("Failed to create");

        // Cleanup should find and remove it
        let cleaned = cleanup_domain_segments(999);
        assert!(cleaned >= 1);

        // Segment should no longer exist
        assert!(!ShmSegment::exists(name));
    }

    #[test]
    fn test_is_segment_stale_valid_segment() {
        let name = unique_name();

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

        // Cleanup
        drop(seg);
        ShmSegment::unlink(&name).ok();
    }
}
