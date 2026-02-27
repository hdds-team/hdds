// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Shared memory ring buffer implementation for inter-process communication.
//!
//! # Memory Layout
//!
//! ```text
//! +-------------------------------------------------------------+
//! | ShmControl (64 bytes, cache-aligned)                        |
//! +-------------------------------------------------------------+
//! | ShmSlot[0] (64 bytes header + SLOT_PAYLOAD_SIZE payload)    |
//! | ShmSlot[1]                                                  |
//! | ...                                                         |
//! | ShmSlot[capacity-1]                                         |
//! +-------------------------------------------------------------+
//! ```
//!
//! # Synchronization Protocol
//!
//! Writer push:
//! 1. Mark slot as writing: `slot.seq = (msg_seq << 1) | 1`
//! 2. Write payload length and data
//! 3. Commit: `slot.seq = msg_seq << 1` (Release)
//! 4. Publish head: `control.head = msg_seq + 1` (Release)
//! 5. Wake readers via futex
//!
//! Reader try_pop:
//! 1. Load head (Acquire), check for overrun
//! 2. Load slot.seq (Acquire), verify `seq == expected << 1`
//! 3. Copy payload
//! 4. Re-check slot.seq (detect torn read)
//! 5. Advance local sequence

use super::notify::TopicNotify;
use super::segment::ShmSegment;
use super::slot::{ShmControl, ShmSlot, SLOT_PAYLOAD_SIZE};
use super::{Result, ShmError};
use std::ptr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// Calculate total segment size for a ring buffer
#[must_use]
pub const fn ring_segment_size(capacity: usize) -> usize {
    std::mem::size_of::<ShmControl>() + capacity * std::mem::size_of::<ShmSlot>()
}

/// Shared memory ring buffer writer.
///
/// Owns the shared memory segment and writes messages to it.
/// Readers can attach to the same segment via `ShmRingReader::attach()`.
pub struct ShmRingWriter {
    /// Shared memory segment (owned)
    segment: ShmSegment,
    /// Ring capacity (power of 2)
    capacity: usize,
    /// Capacity mask for index calculation
    mask: usize,
    /// Next sequence number to write
    next_seq: u64,
    /// Topic notification for waking readers
    topic_notify: Option<TopicNotify>,
    /// Notification bucket index (hash of writer GUID)
    notify_bucket: usize,
}

impl ShmRingWriter {
    /// Create a new shared memory ring buffer.
    ///
    /// # Arguments
    ///
    /// * `name` - Segment name (e.g., `/hdds_d0_w{guid}`)
    /// * `capacity` - Number of slots (must be power of 2)
    /// * `writer_guid` - Writer GUID for bucket assignment
    ///
    /// # Errors
    ///
    /// Returns error if capacity is not power of 2 or segment creation fails.
    pub fn create(name: &str, capacity: usize, writer_guid: &[u8; 16]) -> Result<Self> {
        if !capacity.is_power_of_two() {
            return Err(ShmError::InvalidCapacity(capacity));
        }

        let size = ring_segment_size(capacity);
        let segment = ShmSegment::create(name, size)?;

        // Initialize control block
        // SAFETY:
        // - segment.as_ptr() returns a valid pointer from successful ShmSegment::create
        // - The segment was created with size = ring_segment_size(capacity), which includes
        //   sizeof(ShmControl) at the beginning
        // - ShmControl requires 8-byte alignment; mmap returns page-aligned memory (4096+ bytes)
        // - The segment was just created, so we have exclusive access (no data races)
        // - The memory was zero-initialized by ShmSegment::create
        let control = unsafe { &mut *(segment.as_ptr() as *mut ShmControl) };
        *control = ShmControl::new(capacity as u32, SLOT_PAYLOAD_SIZE as u32);

        let notify_bucket = TopicNotify::bucket_for_guid(writer_guid);

        Ok(Self {
            segment,
            capacity,
            mask: capacity - 1,
            next_seq: 0,
            topic_notify: None,
            notify_bucket,
        })
    }

    /// Attach a topic notification for waking readers
    pub fn with_notify(mut self, notify: TopicNotify) -> Self {
        self.topic_notify = Some(notify);
        self
    }

    /// Set topic notification after construction
    pub fn set_notify(&mut self, notify: TopicNotify) {
        self.topic_notify = Some(notify);
    }

    /// Get pointer to control block
    #[inline]
    fn control(&self) -> &ShmControl {
        // SAFETY:
        // - segment.as_ptr() returns a valid pointer from ShmSegment::create
        // - The segment size includes ShmControl at offset 0
        // - ShmControl requires 8-byte alignment; mmap provides page alignment
        // - ShmControl uses atomic fields for thread-safe access across processes
        // - The reference is valid for the lifetime of &self
        unsafe { &*(self.segment.as_ptr() as *const ShmControl) }
    }

    /// Get pointer to slots array
    #[inline]
    fn slots(&self) -> *mut ShmSlot {
        // SAFETY:
        // - segment.as_ptr() returns a valid pointer from ShmSegment::create
        // - Adding sizeof(ShmControl) bytes is within bounds because the segment was
        //   created with size = sizeof(ShmControl) + capacity * sizeof(ShmSlot)
        // - ShmSlot is cache-aligned (64 bytes); ShmControl is also 64 bytes, so
        //   the slots array starts at a 64-byte aligned offset
        // - The pointer arithmetic does not overflow (segment sizes are bounded)
        unsafe { self.segment.as_ptr().add(std::mem::size_of::<ShmControl>()) as *mut ShmSlot }
    }

    /// Get a specific slot
    #[inline]
    fn slot(&self, index: usize) -> &ShmSlot {
        debug_assert!(index < self.capacity);
        // SAFETY:
        // - self.slots() returns a valid pointer to the start of the slots array
        // - index < self.capacity is asserted in debug mode and guaranteed by callers
        //   (index is computed as seq & mask where mask = capacity - 1)
        // - The slots array has exactly `capacity` elements, so index is in bounds
        // - ShmSlot uses atomic fields for thread-safe concurrent access
        // - The reference is valid for the lifetime of &self
        unsafe { &*self.slots().add(index) }
    }

    /// Push a message to the ring buffer.
    ///
    /// # Arguments
    ///
    /// * `data` - Message payload (must fit in SLOT_PAYLOAD_SIZE)
    ///
    /// # Errors
    ///
    /// Returns error if payload is too large.
    ///
    /// # Performance
    ///
    /// Target: < 200 ns per push
    pub fn push(&mut self, data: &[u8]) -> Result<()> {
        if data.len() > SLOT_PAYLOAD_SIZE {
            return Err(ShmError::PayloadTooLarge {
                size: data.len(),
                capacity: SLOT_PAYLOAD_SIZE,
            });
        }

        let msg_seq = self.next_seq;
        let idx = (msg_seq as usize) & self.mask;
        let slot = self.slot(idx);

        // 1. Mark in-progress (odd)
        slot.seq.store((msg_seq << 1) | 1, Ordering::Relaxed);

        // 2. Write payload length
        slot.len.store(data.len() as u32, Ordering::Relaxed);

        // 3. Write payload data
        // SAFETY:
        // - slot.payload is a valid UnsafeCell containing a byte array of SLOT_PAYLOAD_SIZE
        // - data.len() <= SLOT_PAYLOAD_SIZE was checked at function entry
        // - We have exclusive write access because:
        //   a) The slot's sequence number was set to an odd value (in-progress marker)
        //   b) Only one writer exists per ring buffer (single-producer design)
        //   c) Readers check the sequence number and skip in-progress slots
        // - ptr::copy_nonoverlapping is safe because src and dst don't overlap
        //   (data is caller's buffer, dst is in shared memory)
        // - The destination buffer is properly aligned for u8 (alignment of 1)
        unsafe {
            let dst = (*slot.payload.get()).as_mut_ptr();
            ptr::copy_nonoverlapping(data.as_ptr(), dst, data.len());
        }

        // 4. Commit (even) with Release ordering
        slot.seq.store(msg_seq << 1, Ordering::Release);

        // 5. Publish head
        self.control().publish_head(msg_seq + 1);

        // 6. Wake readers (if notify attached)
        if let Some(ref notify) = self.topic_notify {
            notify.notify(self.notify_bucket);
        }

        self.next_seq = msg_seq + 1;
        Ok(())
    }

    /// Get current sequence number (next to be written)
    #[must_use]
    pub fn sequence(&self) -> u64 {
        self.next_seq
    }

    /// Get the segment name
    #[must_use]
    pub fn segment_name(&self) -> &str {
        self.segment.name()
    }

    /// Get ring capacity
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Unlink the segment (cleanup)
    pub fn unlink(&self) -> Result<()> {
        ShmSegment::unlink(self.segment.name())
    }
}

/// Metrics for reader operations
#[derive(Debug, Default)]
pub struct ReaderMetrics {
    /// Number of messages read successfully
    pub messages_read: AtomicU64,
    /// Number of overruns (reader too slow)
    pub overruns: AtomicU64,
    /// Number of corrupted reads (torn read detected)
    pub corrupted: AtomicU64,
    /// Number of empty polls (no data available)
    pub empty_polls: AtomicU64,
}

impl ReaderMetrics {
    /// Create new metrics
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

/// Shared memory ring buffer reader.
///
/// Attaches to an existing shared memory segment created by `ShmRingWriter`.
/// Multiple readers can attach to the same segment.
pub struct ShmRingReader {
    /// Shared memory segment (opened, not owned)
    segment: ShmSegment,
    /// Ring capacity
    capacity: usize,
    /// Capacity mask
    mask: usize,
    /// Next expected sequence number
    next_seq: u64,
    /// Topic notification for blocking wait
    topic_notify: Option<TopicNotify>,
    /// Notification bucket index to wait on
    notify_bucket: usize,
    /// Performance metrics
    pub metrics: ReaderMetrics,
}

impl ShmRingReader {
    /// Attach to an existing shared memory ring buffer.
    ///
    /// # Arguments
    ///
    /// * `name` - Segment name
    /// * `capacity` - Expected ring capacity
    /// * `notify_bucket` - Bucket index to wait on (usually from writer GUID)
    ///
    /// # Errors
    ///
    /// Returns error if segment doesn't exist or validation fails.
    pub fn attach(name: &str, capacity: usize, notify_bucket: usize) -> Result<Self> {
        let size = ring_segment_size(capacity);
        let segment = ShmSegment::open(name, size)?;

        // Validate control block
        // SAFETY:
        // - segment.as_ptr() returns a valid pointer from successful ShmSegment::open
        // - The segment was opened with size = ring_segment_size(capacity), which includes
        //   sizeof(ShmControl) at the beginning
        // - ShmControl requires 8-byte alignment; mmap returns page-aligned memory
        // - ShmControl uses atomic fields, so reading from another process is safe
        // - The reference is valid for the duration of this validation check
        let control = unsafe { &*(segment.as_ptr() as *const ShmControl) };
        if !control.validate() {
            return Err(ShmError::Corruption);
        }

        if control.capacity != capacity as u32 {
            return Err(ShmError::InvalidCapacity(control.capacity as usize));
        }

        // Start reading from current head (skip old data)
        let start_seq = control.get_head();

        Ok(Self {
            segment,
            capacity,
            mask: capacity - 1,
            next_seq: start_seq,
            topic_notify: None,
            notify_bucket,
            metrics: ReaderMetrics::new(),
        })
    }

    /// Attach with specific starting sequence (for replay)
    pub fn attach_from(
        name: &str,
        capacity: usize,
        notify_bucket: usize,
        start_seq: u64,
    ) -> Result<Self> {
        let mut reader = Self::attach(name, capacity, notify_bucket)?;
        reader.next_seq = start_seq;
        Ok(reader)
    }

    /// Attach a topic notification for blocking waits
    pub fn with_notify(mut self, notify: TopicNotify) -> Self {
        self.topic_notify = Some(notify);
        self
    }

    /// Set topic notification after construction
    pub fn set_notify(&mut self, notify: TopicNotify) {
        self.topic_notify = Some(notify);
    }

    /// Get pointer to control block
    #[inline]
    fn control(&self) -> &ShmControl {
        // SAFETY:
        // - segment.as_ptr() returns a valid pointer from ShmSegment::open
        // - The segment size includes ShmControl at offset 0 (validated in attach())
        // - ShmControl requires 8-byte alignment; mmap provides page alignment
        // - ShmControl uses atomic fields for thread-safe access across processes
        // - The reference is valid for the lifetime of &self
        unsafe { &*(self.segment.as_ptr() as *const ShmControl) }
    }

    /// Get pointer to slots array
    #[inline]
    fn slots(&self) -> *const ShmSlot {
        // SAFETY:
        // - segment.as_ptr() returns a valid pointer from ShmSegment::open
        // - Adding sizeof(ShmControl) bytes is within bounds because the segment was
        //   opened with size = sizeof(ShmControl) + capacity * sizeof(ShmSlot)
        // - ShmSlot is cache-aligned (64 bytes); ShmControl is also 64 bytes, so
        //   the slots array starts at a 64-byte aligned offset
        // - The pointer arithmetic does not overflow (segment sizes are bounded)
        unsafe { self.segment.as_ptr().add(std::mem::size_of::<ShmControl>()) as *const ShmSlot }
    }

    /// Get a specific slot
    #[inline]
    fn slot(&self, index: usize) -> &ShmSlot {
        debug_assert!(index < self.capacity);
        // SAFETY:
        // - self.slots() returns a valid pointer to the start of the slots array
        // - index < self.capacity is asserted in debug mode and guaranteed by callers
        //   (index is computed as seq & mask where mask = capacity - 1)
        // - The slots array has exactly `capacity` elements, so index is in bounds
        // - ShmSlot uses atomic fields for thread-safe concurrent access
        // - The reference is valid for the lifetime of &self
        unsafe { &*self.slots().add(index) }
    }

    /// Try to read the next message without blocking.
    ///
    /// # Arguments
    ///
    /// * `buf` - Buffer to copy payload into
    ///
    /// # Returns
    ///
    /// * `Some(len)` - Payload was copied, len bytes written
    /// * `None` - No data available or corruption detected
    ///
    /// # Performance
    ///
    /// Target: < 100 ns per successful pop
    pub fn try_pop(&mut self, buf: &mut [u8]) -> Option<usize> {
        let head = self.control().get_head();

        // Overrun check: if head has advanced more than capacity, we lost data
        if head.saturating_sub(self.next_seq) > self.capacity as u64 {
            // Too slow - jump to latest readable position
            self.next_seq = head.saturating_sub(1);
            self.metrics.overruns.fetch_add(1, Ordering::Relaxed);
            return None;
        }

        // Nothing to read
        if self.next_seq >= head {
            self.metrics.empty_polls.fetch_add(1, Ordering::Relaxed);
            return None;
        }

        let expected = self.next_seq;
        let idx = (expected as usize) & self.mask;
        let slot = self.slot(idx);
        let want = expected << 1; // Expected committed marker

        // 1. Check seq (must be committed, not in-progress)
        let seq1 = slot.seq.load(Ordering::Acquire);
        if seq1 != want {
            // Slot not ready (still being written or different seq)
            return None;
        }

        // 2. Copy payload length
        let len = slot.len.load(Ordering::Relaxed) as usize;
        if len > buf.len() {
            // Buffer too small - treat as corruption
            self.metrics.corrupted.fetch_add(1, Ordering::Relaxed);
            return None;
        }

        // 3. Copy payload data
        // SAFETY:
        // - slot.payload is a valid UnsafeCell containing a byte array of SLOT_PAYLOAD_SIZE
        // - len <= buf.len() was checked above, preventing buffer overflow
        // - len <= SLOT_PAYLOAD_SIZE is guaranteed by the writer (checked on push)
        // - The slot's sequence number indicates the data is committed (not in-progress)
        // - ptr::copy_nonoverlapping is safe because src and dst don't overlap
        //   (src is in shared memory, dst is caller's buffer)
        // - Both buffers are properly aligned for u8 (alignment of 1)
        // - Note: A torn read is possible if writer overwrites during copy, but we
        //   detect this by re-checking the sequence number after the copy
        unsafe {
            let src = (*slot.payload.get()).as_ptr();
            ptr::copy_nonoverlapping(src, buf.as_mut_ptr(), len);
        }

        // 4. Re-check seq (detect torn read - slot was overwritten during copy)
        let seq2 = slot.seq.load(Ordering::Acquire);
        if seq2 != seq1 {
            self.metrics.corrupted.fetch_add(1, Ordering::Relaxed);
            return None;
        }

        // Success!
        self.next_seq = expected + 1;
        self.metrics.messages_read.fetch_add(1, Ordering::Relaxed);
        Some(len)
    }

    /// Read next message, blocking until available.
    ///
    /// Uses double-check pattern to avoid lost wakes:
    /// 1. Poll for data
    /// 2. Snapshot notify counter
    /// 3. Re-poll (catches race)
    /// 4. If still no data, wait on futex
    ///
    /// # Arguments
    ///
    /// * `buf` - Buffer to copy payload into
    /// * `timeout` - Optional timeout duration
    ///
    /// # Returns
    ///
    /// * `Some(len)` - Payload was copied
    /// * `None` - Timeout expired
    pub fn take_blocking(&mut self, buf: &mut [u8], timeout: Option<Duration>) -> Option<usize> {
        // Check if we have notify - if not, fallback to spinning
        if self.topic_notify.is_none() {
            return self.take_spinning(buf, timeout);
        }

        let deadline = timeout.map(|t| std::time::Instant::now() + t);
        let bucket_idx = self.notify_bucket;

        loop {
            // 1. Poll for data
            if let Some(len) = self.try_pop(buf) {
                return Some(len);
            }

            // 2. Snapshot notify counter
            // SAFETY: We checked topic_notify.is_some() at the start of the function
            let snapshot = self
                .topic_notify
                .as_ref()
                .map(|tn| tn.bucket(bucket_idx).snapshot());

            let snapshot = snapshot?;

            // 3. Re-poll (anti lost-wake)
            if let Some(len) = self.try_pop(buf) {
                return Some(len);
            }

            // 4. Calculate remaining timeout
            let remaining = match deadline {
                Some(d) => {
                    let now = std::time::Instant::now();
                    if now >= d {
                        return None; // Timeout expired
                    }
                    Some(d - now)
                }
                None => None,
            };

            // 5. Wait on futex
            if let Some(ref topic_notify) = self.topic_notify {
                topic_notify.wait(bucket_idx, snapshot, remaining);
            }
        }
    }

    /// Fallback blocking read using spinning with sleep
    fn take_spinning(&mut self, buf: &mut [u8], timeout: Option<Duration>) -> Option<usize> {
        let deadline = timeout.map(|t| std::time::Instant::now() + t);
        let spin_count = 1000;

        loop {
            // Spin first
            for _ in 0..spin_count {
                if let Some(len) = self.try_pop(buf) {
                    return Some(len);
                }
                std::hint::spin_loop();
            }

            // Check timeout
            if let Some(d) = deadline {
                if std::time::Instant::now() >= d {
                    return None;
                }
            }

            // Sleep briefly
            std::thread::sleep(Duration::from_micros(10));
        }
    }

    /// Get current read position
    #[must_use]
    pub fn sequence(&self) -> u64 {
        self.next_seq
    }

    /// Get number of messages available to read
    #[must_use]
    pub fn available(&self) -> u64 {
        let head = self.control().get_head();
        head.saturating_sub(self.next_seq)
    }

    /// Check if any data is available
    #[must_use]
    pub fn has_data(&self) -> bool {
        self.available() > 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Instant;

    fn unique_name() -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        format!("/hdds_ring_{ts}")
    }

    fn test_guid() -> [u8; 16] {
        [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]
    }

    #[test]
    fn test_ring_segment_size() {
        let size = ring_segment_size(256);
        // Control (64) + 256 slots
        let expected = 64 + 256 * std::mem::size_of::<ShmSlot>();
        assert_eq!(size, expected);
    }

    #[test]
    fn test_writer_create() {
        let name = unique_name();
        let writer = ShmRingWriter::create(&name, 256, &test_guid()).expect("Failed to create");

        assert_eq!(writer.capacity(), 256);
        assert_eq!(writer.sequence(), 0);

        writer.unlink().ok();
    }

    #[test]
    fn test_writer_push() {
        let name = unique_name();
        let mut writer = ShmRingWriter::create(&name, 256, &test_guid()).expect("Failed to create");

        let data = b"Hello, SHM!";
        writer.push(data).expect("Push failed");

        assert_eq!(writer.sequence(), 1);

        writer.unlink().ok();
    }

    #[test]
    fn test_writer_push_too_large() {
        let name = unique_name();
        let mut writer = ShmRingWriter::create(&name, 256, &test_guid()).expect("Failed to create");

        let data = vec![0u8; SLOT_PAYLOAD_SIZE + 1];
        let result = writer.push(&data);

        assert!(matches!(result, Err(ShmError::PayloadTooLarge { .. })));

        writer.unlink().ok();
    }

    #[test]
    fn test_reader_attach() {
        let name = unique_name();
        let writer = ShmRingWriter::create(&name, 256, &test_guid()).expect("Failed to create");

        let bucket = TopicNotify::bucket_for_guid(&test_guid());
        let reader = ShmRingReader::attach(&name, 256, bucket).expect("Failed to attach");

        assert_eq!(reader.capacity, 256);
        assert_eq!(reader.sequence(), 0); // Starts at head

        drop(reader);
        writer.unlink().ok();
    }

    #[test]
    fn test_write_read_cycle() {
        let name = unique_name();
        let mut writer = ShmRingWriter::create(&name, 256, &test_guid()).expect("Failed to create");

        // Push a message
        let msg = b"Test message 123";
        writer.push(msg).expect("Push failed");

        // Attach reader starting from 0 (not head)
        let bucket = TopicNotify::bucket_for_guid(&test_guid());
        let mut reader =
            ShmRingReader::attach_from(&name, 256, bucket, 0).expect("Failed to attach");

        assert!(reader.has_data());
        assert_eq!(reader.available(), 1);

        // Read the message
        let mut buf = [0u8; 256];
        let len = reader.try_pop(&mut buf).expect("Should have data");

        assert_eq!(len, msg.len());
        assert_eq!(&buf[..len], msg);

        writer.unlink().ok();
    }

    #[test]
    fn test_multiple_messages() {
        let name = unique_name();
        let mut writer = ShmRingWriter::create(&name, 256, &test_guid()).expect("Failed to create");

        // Push multiple messages
        for i in 0..10 {
            let msg = format!("Message {i}");
            writer.push(msg.as_bytes()).expect("Push failed");
        }

        // Read all messages
        let bucket = TopicNotify::bucket_for_guid(&test_guid());
        let mut reader =
            ShmRingReader::attach_from(&name, 256, bucket, 0).expect("Failed to attach");

        let mut buf = [0u8; 256];
        for i in 0..10 {
            let len = reader.try_pop(&mut buf).expect("Should have data");
            let expected = format!("Message {i}");
            assert_eq!(&buf[..len], expected.as_bytes());
        }

        // No more data
        assert!(reader.try_pop(&mut buf).is_none());

        writer.unlink().ok();
    }

    #[test]
    fn test_overrun_detection() {
        let name = unique_name();
        // Small ring to easily trigger overrun
        let mut writer = ShmRingWriter::create(&name, 4, &test_guid()).expect("Failed to create");

        // Reader starts at 0
        let bucket = TopicNotify::bucket_for_guid(&test_guid());
        let mut reader = ShmRingReader::attach_from(&name, 4, bucket, 0).expect("Failed to attach");

        // Write more than capacity (overflow)
        for i in 0..10 {
            writer.push(&[i as u8]).expect("Push failed");
        }

        // Reader should detect overrun
        let mut buf = [0u8; 256];
        let result = reader.try_pop(&mut buf);
        assert!(result.is_none());
        assert!(reader.metrics.overruns.load(Ordering::Relaxed) > 0);

        writer.unlink().ok();
    }

    #[test]
    fn test_concurrent_write_read() {
        let name = unique_name();
        let guid = test_guid();
        let mut writer = ShmRingWriter::create(&name, 256, &guid).expect("Failed to create");

        let name_clone = name.clone();
        let bucket = TopicNotify::bucket_for_guid(&guid);

        let reader_handle = thread::spawn(move || {
            let mut reader =
                ShmRingReader::attach_from(&name_clone, 256, bucket, 0).expect("Failed to attach");

            let mut buf = [0u8; 256];
            let mut count = 0;

            // Read 100 messages
            while count < 100 {
                if let Some(_len) = reader.try_pop(&mut buf) {
                    count += 1;
                } else {
                    thread::yield_now();
                }
            }

            count
        });

        // Write 100 messages
        for i in 0..100u32 {
            writer.push(&i.to_le_bytes()).expect("Push failed");
            // Small delay to let reader catch up sometimes
            if i % 10 == 0 {
                thread::yield_now();
            }
        }

        let read_count = reader_handle.join().expect("Reader panicked");
        assert_eq!(read_count, 100);

        writer.unlink().ok();
    }

    #[test]
    fn test_push_latency() {
        let name = unique_name();
        let mut writer = ShmRingWriter::create(&name, 256, &test_guid()).expect("Failed to create");

        let data = [0u8; 64]; // Small payload
        let iterations = 10_000;

        // Warmup
        for _ in 0..1000 {
            writer.push(&data).ok();
        }

        let start = Instant::now();
        for _ in 0..iterations {
            writer.push(&data).expect("Push failed");
        }
        let elapsed = start.elapsed();

        let avg_ns = elapsed.as_nanos() as f64 / iterations as f64;
        println!("Average push latency: {avg_ns:.1} ns");

        // Should be under 1000 ns (target is 200 ns)
        assert!(avg_ns < 1000.0, "Push too slow: {avg_ns} ns");

        writer.unlink().ok();
    }

    #[test]
    fn test_try_pop_latency() {
        let name = unique_name();
        let mut writer = ShmRingWriter::create(&name, 256, &test_guid()).expect("Failed to create");

        // Fill ring
        for i in 0..200 {
            writer.push(&[i as u8; 64]).expect("Push failed");
        }

        let bucket = TopicNotify::bucket_for_guid(&test_guid());
        let mut reader =
            ShmRingReader::attach_from(&name, 256, bucket, 0).expect("Failed to attach");

        let mut buf = [0u8; 256];
        let iterations = 200;

        let start = Instant::now();
        for _ in 0..iterations {
            reader.try_pop(&mut buf).expect("Should have data");
        }
        let elapsed = start.elapsed();

        let avg_ns = elapsed.as_nanos() as f64 / iterations as f64;
        println!("Average try_pop latency: {avg_ns:.1} ns");

        // Should be under 1000 ns in debug mode (target is 100 ns in release)
        assert!(avg_ns < 1000.0, "Pop too slow: {avg_ns} ns");

        writer.unlink().ok();
    }
}
