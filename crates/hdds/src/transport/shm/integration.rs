// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! SHM Transport Integration Layer
//!
//! Provides high-level APIs for integrating shared memory transport
//! with DDS writers and readers. This module bridges the gap between
//! the low-level SHM ring buffers and the DDS endpoint layer.
//!
//! # Usage Flow
//!
//! 1. Writer creates `ShmWriterTransport` with its GUID
//! 2. Reader discovers writer via SEDP (user_data contains SHM info)
//! 3. Reader attaches to writer's SHM segment via `ShmReaderTransport`
//! 4. Data flows through SHM instead of UDP
//!
//! # Discovery Integration
//!
//! Writers announce SHM capability via SEDP user_data:
//! ```text
//! shm=1;host_id=XXXXXXXX;v=1
//! ```
//!
//! Readers check if:
//! 1. Remote writer has `shm=1` in user_data
//! 2. Remote `host_id` matches local `host_id` (same machine)
//! 3. If both true, attach to SHM segment instead of using UDP

use super::notify::TopicNotify;
use super::ring::{ShmRingReader, ShmRingWriter};
use super::{segment_name, Result, DEFAULT_RING_CAPACITY};
use crate::core::discovery::GUID;
use std::collections::HashMap;
use std::sync::RwLock;

/// SHM transport for a DDS writer.
///
/// Creates and manages a shared memory ring buffer that readers
/// can attach to for zero-copy data transfer.
pub struct ShmWriterTransport {
    /// The underlying ring buffer writer
    ring: ShmRingWriter,
    /// Domain ID for segment naming
    domain_id: u32,
    /// Writer GUID (used for segment naming and bucket assignment)
    writer_guid: [u8; 16],
}

impl ShmWriterTransport {
    /// Create a new SHM writer transport.
    ///
    /// # Arguments
    ///
    /// * `domain_id` - DDS domain ID
    /// * `writer_guid` - Full 16-byte GUID of the writer endpoint
    /// * `topic_name` - Topic name (for notification segment)
    ///
    /// # Errors
    ///
    /// Returns error if segment creation fails.
    pub fn new(domain_id: u32, writer_guid: GUID, topic_name: &str) -> Result<Self> {
        let guid_bytes = writer_guid.as_bytes();
        let name = segment_name(domain_id, &guid_bytes);

        let mut ring = ShmRingWriter::create(&name, DEFAULT_RING_CAPACITY, &guid_bytes)?;

        // Attach topic notification
        let notify_name = TopicNotify::segment_name(domain_id, topic_name);
        let notify = TopicNotify::new(&notify_name, true)?;
        ring.set_notify(notify);

        Ok(Self {
            ring,
            domain_id,
            writer_guid: guid_bytes,
        })
    }

    /// Write data to the SHM ring buffer.
    ///
    /// This is the hot path - should be < 200 ns.
    #[inline]
    pub fn write(&mut self, data: &[u8]) -> Result<()> {
        self.ring.push(data)
    }

    /// Get the segment name for this writer
    #[must_use]
    pub fn segment_name(&self) -> String {
        segment_name(self.domain_id, &self.writer_guid)
    }

    /// Get current write sequence number
    #[must_use]
    pub fn sequence(&self) -> u64 {
        self.ring.sequence()
    }

    /// Cleanup: unlink the segment
    pub fn cleanup(&self) -> Result<()> {
        self.ring.unlink()
    }
}

impl Drop for ShmWriterTransport {
    fn drop(&mut self) {
        // Best-effort cleanup
        let _ = self.ring.unlink();
    }
}

/// SHM transport for a DDS reader.
///
/// Attaches to one or more writer SHM segments for zero-copy data transfer.
pub struct ShmReaderTransport {
    /// Domain ID
    domain_id: u32,
    /// Topic name (for notification segment)
    topic_name: String,
    /// Attached writer rings
    writers: Vec<ShmRingReader>,
    /// Topic notification (shared across all writers for this topic)
    topic_notify: Option<TopicNotify>,
}

impl ShmReaderTransport {
    /// Create a new SHM reader transport.
    ///
    /// # Arguments
    ///
    /// * `domain_id` - DDS domain ID
    /// * `topic_name` - Topic name
    pub fn new(domain_id: u32, topic_name: &str) -> Result<Self> {
        // Try to open existing notification segment, or create new one
        let notify_name = TopicNotify::segment_name(domain_id, topic_name);
        let topic_notify = TopicNotify::new(&notify_name, false)
            .or_else(|_| TopicNotify::new(&notify_name, true))
            .ok();

        Ok(Self {
            domain_id,
            topic_name: topic_name.to_string(),
            writers: Vec::new(),
            topic_notify,
        })
    }

    /// Attach to a discovered writer's SHM segment.
    ///
    /// Called when SEDP discovers a remote writer with matching
    /// `host_id` (same machine) and `shm=1` capability.
    ///
    /// # Arguments
    ///
    /// * `writer_guid` - The writer's GUID (from SEDP)
    pub fn attach_writer(&mut self, writer_guid: GUID) -> Result<()> {
        self.attach_writer_from(writer_guid, None)
    }

    /// Attach to a writer's SHM segment with optional starting sequence.
    ///
    /// # Arguments
    ///
    /// * `writer_guid` - The writer's GUID
    /// * `start_seq` - Starting sequence (None = start from head, Some(0) = from beginning)
    pub fn attach_writer_from(&mut self, writer_guid: GUID, start_seq: Option<u64>) -> Result<()> {
        let guid_bytes = writer_guid.as_bytes();
        let name = segment_name(self.domain_id, &guid_bytes);
        let bucket = TopicNotify::bucket_for_guid(&guid_bytes);

        let mut reader = match start_seq {
            Some(seq) => {
                super::ring::ShmRingReader::attach_from(&name, DEFAULT_RING_CAPACITY, bucket, seq)?
            }
            None => ShmRingReader::attach(&name, DEFAULT_RING_CAPACITY, bucket)?,
        };

        // Attach notification if available
        if self.topic_notify.is_some() {
            let notify_name = TopicNotify::segment_name(self.domain_id, &self.topic_name);
            if let Ok(notify_copy) = TopicNotify::new(&notify_name, false) {
                reader.set_notify(notify_copy);
            }
        }

        self.writers.push(reader);
        Ok(())
    }

    /// Try to read data from any attached writer.
    ///
    /// Non-blocking poll across all attached writers.
    ///
    /// # Returns
    ///
    /// * `Some(len)` if data was read
    /// * `None` if no data available
    pub fn try_read(&mut self, buf: &mut [u8]) -> Option<usize> {
        for reader in &mut self.writers {
            if let Some(len) = reader.try_pop(buf) {
                return Some(len);
            }
        }
        None
    }

    /// Read with blocking wait.
    ///
    /// Waits for data from any attached writer using futex notification.
    pub fn read_blocking(
        &mut self,
        buf: &mut [u8],
        timeout: Option<std::time::Duration>,
    ) -> Option<usize> {
        // Simple round-robin with blocking on first writer
        // More sophisticated implementations could use epoll-like multiplexing
        if let Some(first) = self.writers.first_mut() {
            first.take_blocking(buf, timeout)
        } else {
            None
        }
    }

    /// Get number of attached writers
    #[must_use]
    pub fn writer_count(&self) -> usize {
        self.writers.len()
    }

    /// Check if any data is available
    #[must_use]
    pub fn has_data(&self) -> bool {
        self.writers.iter().any(|r| r.has_data())
    }
}

/// Registry for active SHM transports in a domain.
///
/// Used to track which writers have SHM segments available
/// and enable automatic attachment during matching.
pub struct ShmTransportRegistry {
    /// Map of writer GUID -> segment info
    writers: RwLock<HashMap<[u8; 16], ShmWriterInfo>>,
    /// Local host ID for filtering
    local_host_id: u32,
}

/// Information about an SHM-enabled writer
#[derive(Clone)]
pub struct ShmWriterInfo {
    /// Segment name
    pub segment_name: String,
    /// Notification bucket
    pub notify_bucket: usize,
    /// Host ID of the writer
    pub host_id: u32,
}

impl ShmTransportRegistry {
    /// Create a new registry
    #[must_use]
    pub fn new() -> Self {
        Self {
            writers: RwLock::new(HashMap::new()),
            local_host_id: super::host_id(),
        }
    }

    /// Register a local writer's SHM transport
    pub fn register_writer(&self, guid: [u8; 16], segment_name: String, notify_bucket: usize) {
        let info = ShmWriterInfo {
            segment_name,
            notify_bucket,
            host_id: self.local_host_id,
        };
        let mut guard = self.writers.write().unwrap_or_else(|e| e.into_inner());
        guard.insert(guid, info);
    }

    /// Check if a remote writer is SHM-capable and on the same host
    #[must_use]
    pub fn can_use_shm(&self, remote_host_id: u32) -> bool {
        remote_host_id == self.local_host_id
    }

    /// Get writer info if available
    #[must_use]
    pub fn get_writer(&self, guid: &[u8; 16]) -> Option<ShmWriterInfo> {
        let guard = self.writers.read().unwrap_or_else(|e| e.into_inner());
        guard.get(guid).cloned()
    }

    /// Unregister a writer
    pub fn unregister_writer(&self, guid: &[u8; 16]) {
        let mut guard = self.writers.write().unwrap_or_else(|e| e.into_inner());
        guard.remove(guid);
    }

    /// Get local host ID
    #[must_use]
    pub fn local_host_id(&self) -> u32 {
        self.local_host_id
    }
}

impl Default for ShmTransportRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    fn test_guid(id: u8) -> GUID {
        let mut bytes = [0u8; 16];
        bytes[0] = id;
        bytes[15] = 0x02; // Writer entity kind
        GUID::from_bytes(bytes)
    }

    #[test]
    fn test_writer_transport_create() {
        let guid = test_guid(1);
        let transport = ShmWriterTransport::new(0, guid, "test_topic");
        assert!(transport.is_ok());

        let transport = transport.unwrap();
        assert_eq!(transport.sequence(), 0);
    }

    #[test]
    fn test_writer_reader_integration() {
        let guid = test_guid(2);

        // Create writer
        let mut writer = ShmWriterTransport::new(0, guid, "test_topic2").expect("Writer create");

        // Write some data
        let msg = b"Hello, SHM!";
        writer.write(msg).expect("Write failed");

        // Create reader and attach from seq 0 to see the message we just wrote
        let mut reader = ShmReaderTransport::new(0, "test_topic2").expect("Reader create");
        reader
            .attach_writer_from(guid, Some(0))
            .expect("Attach failed");

        assert_eq!(reader.writer_count(), 1);
        assert!(reader.has_data());

        // Read the data
        let mut buf = [0u8; 256];
        let len = reader.try_read(&mut buf).expect("Should have data");

        assert_eq!(len, msg.len());
        assert_eq!(&buf[..len], msg);
    }

    #[test]
    fn test_multiple_messages() {
        let guid = test_guid(3);

        let mut writer = ShmWriterTransport::new(0, guid, "test_topic3").expect("Writer create");
        let mut reader = ShmReaderTransport::new(0, "test_topic3").expect("Reader create");
        reader.attach_writer(guid).expect("Attach failed");

        // Write multiple messages
        for i in 0..100 {
            let msg = format!("Message {i}");
            writer.write(msg.as_bytes()).expect("Write failed");
        }

        // Read all messages
        let mut buf = [0u8; 256];
        for i in 0..100 {
            let len = reader.try_read(&mut buf).expect("Should have data");
            let expected = format!("Message {i}");
            assert_eq!(&buf[..len], expected.as_bytes());
        }
    }

    #[test]
    fn test_registry() {
        let registry = ShmTransportRegistry::new();

        let guid = [1u8; 16];
        registry.register_writer(guid, "/hdds_test".to_string(), 42);

        let info = registry.get_writer(&guid);
        assert!(info.is_some());
        let info = info.unwrap();
        assert_eq!(info.segment_name, "/hdds_test");
        assert_eq!(info.notify_bucket, 42);

        // Same host should be SHM-capable
        assert!(registry.can_use_shm(registry.local_host_id()));

        // Different host should not
        assert!(!registry.can_use_shm(0xDEADBEEF));

        registry.unregister_writer(&guid);
        assert!(registry.get_writer(&guid).is_none());
    }

    #[test]
    fn test_end_to_end_latency() {
        let guid = test_guid(4);

        let mut writer = ShmWriterTransport::new(0, guid, "test_latency").expect("Writer create");
        let mut reader = ShmReaderTransport::new(0, "test_latency").expect("Reader create");
        reader.attach_writer(guid).expect("Attach failed");

        let msg = [0u8; 64];
        let mut buf = [0u8; 256];
        let iterations = 10_000;

        // Warmup
        for _ in 0..1000 {
            writer.write(&msg).ok();
            reader.try_read(&mut buf);
        }

        // Measure round-trip latency
        let start = Instant::now();
        for _ in 0..iterations {
            writer.write(&msg).expect("Write");
            reader.try_read(&mut buf).expect("Read");
        }
        let elapsed = start.elapsed();

        let avg_ns = elapsed.as_nanos() as f64 / iterations as f64;
        println!("End-to-end SHM latency: {avg_ns:.1} ns");

        // Should be under 5000 ns in debug mode (target < 1000 ns in release)
        // Debug builds have significant overhead from bounds checks etc.
        assert!(avg_ns < 5000.0, "End-to-end latency too high: {avg_ns} ns");
    }
}
