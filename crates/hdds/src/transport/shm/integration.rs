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
//! shm=1;host_id=XXXXXXXX;nonce=YYYYYYYYYYYYYYYY;v=1
//! ```
//!
//! `can_use_shm_transport` (see `transport/shm/mod.rs`) proposes SHM when:
//! 1. Remote writer has `shm=1` in user_data
//! 2. Both sides announced a trustworthy nonce (a `host_id` match
//!    alone is an inference, not proof, so a peer that could never be
//!    authenticated is not even proposed)
//! 3. Remote `host_id` matches local `host_id` (same machine -- a filter,
//!    not proof either)
//!
//! That verdict is still provisional. The reader then attaches to the SHM
//! segment, and only a nonce-authenticated attach
//! (`ShmSlot::owner_matches`) actually PROVES co-location; a peer that fails
//! it stays on UDP.

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
    /// The ring sequence `participant` starts reading from, or `None` when it
    /// has not proven it is attached at all.
    ///
    /// The writer's gate for dropping a peer's UDP leg. `None` covers the peer
    /// that selected shared memory at pairing but has not (or cannot) attach,
    /// which would otherwise lose every sample for it silently; the value
    /// itself covers the peer that attached AFTER the packet in hand entered
    /// the ring, which would lose exactly that packet.
    pub fn participant_cursor(&self, participant: [u8; 16]) -> Option<u64> {
        self.ring.presence().cursor_of(participant)
    }

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

        // Attach the topic's shared notification segment. A failure fails
        // the transport, as before: the caller retires the shared-memory leg
        // loudly and counts it (`writer_segment_failures`), which is how a
        // foreign object squatting the name, or a full user table, becomes
        // visible instead of silently costing blocked readers their wake-ups.
        //
        // Attached BEFORE the ring is created: `ShmRingWriter` does not
        // unlink its segment on drop (only this type's `Drop` does), so a
        // refusal after the ring existed would leave the ring and its owner
        // record in /dev/shm.
        let notify_name = TopicNotify::segment_name(domain_id, topic_name);
        let notify = TopicNotify::new(&notify_name, true)?;

        let mut ring = ShmRingWriter::create(&name, DEFAULT_RING_CAPACITY, &guid_bytes)?;
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
    /// Push one packet and return the ring sequence it landed on.
    ///
    /// The caller needs that number, not just success: a peer may only have
    /// its UDP leg dropped for a packet whose sequence is at or after the
    /// cursor that peer published when it claimed its presence entry.
    pub fn write(&mut self, data: &[u8]) -> Result<u64> {
        let msg_seq = self.ring.sequence();
        self.ring.push(data)?;
        Ok(msg_seq)
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

        // Same-process attach: the segment's owner nonce is this process's
        // own, because the writer that created it lives here. A cross-process
        // reader takes the `receiver.rs` path instead, where the expected
        // nonce comes from what the remote participant announced in
        // discovery and is therefore not something the reader can choose.
        let expected_owner = Some((guid_bytes, super::local_nonce()));

        let mut reader = match start_seq {
            Some(seq) => super::ring::ShmRingReader::attach_from(
                &name,
                DEFAULT_RING_CAPACITY,
                bucket,
                seq,
                expected_owner,
            )?,
            None => ShmRingReader::attach(&name, DEFAULT_RING_CAPACITY, bucket, expected_owner)?,
        };

        // Attach notification if available
        if let Some(notify) = &self.topic_notify {
            reader.set_notify(notify.clone());
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
    use super::super::test_support::NotifyGoneOnDrop;
    use super::*;

    /// The topic's notify segment must be gone once the test's writers and
    /// readers are dropped: it is released by its last user.
    fn notify_guard(domain_id: u32, topic: &str) -> NotifyGoneOnDrop {
        NotifyGoneOnDrop::topic(domain_id, topic)
    }

    fn test_guid(id: u8) -> GUID {
        let mut bytes = [0u8; 16];
        bytes[0] = id;
        bytes[15] = 0x02; // Writer entity kind
        GUID::from_bytes(bytes)
    }

    #[test]
    fn test_writer_transport_create() {
        let _guard = notify_guard(0, "test_topic");
        let guid = test_guid(1);
        let transport = ShmWriterTransport::new(0, guid, "test_topic");
        assert!(transport.is_ok());

        let transport = transport.unwrap();
        assert_eq!(transport.sequence(), 0);
    }

    #[test]
    fn test_writer_reader_integration() {
        let _guard = notify_guard(0, "test_topic2");
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
        let _guard = notify_guard(0, "test_topic3");
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
        registry.register_writer(guid, "/hdds_registry_probe".to_string(), 42);

        let info = registry.get_writer(&guid);
        assert!(info.is_some());
        let info = info.unwrap();
        assert_eq!(info.segment_name, "/hdds_registry_probe");
        assert_eq!(info.notify_bucket, 42);

        // Same host should be SHM-capable
        assert!(registry.can_use_shm(registry.local_host_id()));

        // Different host should not
        // @audit-ok: test sentinel for "foreign host" check
        assert!(!registry.can_use_shm(0xDEADBEEF));

        registry.unregister_writer(&guid);
        assert!(registry.get_writer(&guid).is_none());
    }

    /// This test asserts no latency bound over its 10_000 round trips: a
    /// speed claim is not a behavioral one, and it would miss under a slower
    /// clock (for example under strace) while the transport is perfectly
    /// healthy. The speed claim lives in `benches/shm_latency.rs`
    /// (`cargo bench -p hdds --bench shm_latency`).
    ///
    /// What this test proves, without a clock: the
    /// SHM ring sustains 10_000 write()+try_read() round trips back to back
    /// with `Result::expect`, i.e. zero dropped or corrupted deliveries and
    /// no ring-state lockup, under sustained same-process traffic. That is
    /// a real behavioral property (correctness under load), independent of
    /// how fast any single machine executes it, so it stays a `#[test]`.
    #[test]
    fn test_end_to_end_round_trip_succeeds_repeatedly() {
        let _guard = notify_guard(0, "test_latency");
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

        // Every one of these 10_000 round trips must succeed: `.expect`
        // panics the test on the first dropped write or failed read, which
        // is the actual property under test.
        for _ in 0..iterations {
            writer.write(&msg).expect("Write");
            reader.try_read(&mut buf).expect("Read");
        }
    }
    /// The handover invariant, in isolation: a peer is served from the ring for
    /// a packet only when the cursor it published is at or before that packet's
    /// sequence.
    ///
    /// This is the defect that made the writer's no-loss guarantee false. The
    /// push is memoised at the FIRST peer served, so a peer evaluated later in
    /// the same send loop may have attached in between, with a cursor already
    /// past the packet in the ring. Crediting it dropped its UDP leg for a
    /// sample it could never read - lost on both legs, uncounted, with no
    /// acknowledgement on BEST_EFFORT to reveal it.
    #[test]
    fn a_peer_that_attached_after_the_push_is_not_served_from_the_ring() {
        let _guard = notify_guard(4242, "HandoverProbe");
        let guid = test_guid(0x5A);
        let mut writer = ShmWriterTransport::new(4242, guid, "HandoverProbe").expect("writer");
        let peer = [0x11u8; 16];

        // Packet A lands at sequence 0.
        let seq_a = writer.write(&[0xAA; 32]).expect("push A");

        // The peer attaches only now, so it starts reading AFTER packet A.
        let start_cursor = seq_a + 1;
        assert!(
            writer.ring.presence().claim(peer, start_cursor),
            "the peer must be able to claim"
        );

        let cursor = writer
            .participant_cursor(peer)
            .expect("the peer has claimed, so it has a cursor");
        assert!(
            cursor > seq_a,
            "a peer that attached after the push must NOT be credited with it: \
             cursor {cursor} vs packet {seq_a}"
        );

        // Packet B lands at the next sequence, which the peer CAN read, so the
        // same comparison must credit it - otherwise shared memory would
        // never be used.
        let seq_b = writer.write(&[0xBB; 32]).expect("push B");
        assert!(
            cursor <= seq_b,
            "the next packet must be served from the ring: cursor {cursor} vs packet {seq_b}"
        );
    }
}
