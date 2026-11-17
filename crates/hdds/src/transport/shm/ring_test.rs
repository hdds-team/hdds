// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

use super::super::test_support::UnlinkOnDrop;
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

/// The owner identity a same-process reader must present: the writer's GUID
/// and this process's nonce, which is exactly what `ShmRingWriter::create`
/// stamped into the control block.
fn owner_of(guid: [u8; 16]) -> Option<([u8; 16], u64)> {
    Some((guid, crate::transport::shm::local_nonce()))
}

fn test_guid() -> [u8; 16] {
    [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]
}

#[test]
fn test_ring_segment_size() {
    let size = ring_segment_size(256);
    // Control block, then the presence table, then the slots. Written as the
    // layout rather than as a constant on purpose: the presence table was
    // added between the control block and the slots, and a
    // hard-coded total would have had to be re-derived by hand instead of
    // failing where the layout actually changed.
    let expected = super::slots_offset() + 256 * std::mem::size_of::<ShmSlot>();
    assert_eq!(size, expected);
    assert_eq!(super::presence_offset(), std::mem::size_of::<ShmControl>());
    assert!(
        super::slots_offset() > super::presence_offset(),
        "the presence table must sit between the control block and the slots"
    );
}

#[test]
fn test_writer_create() {
    let name = unique_name();
    let _guard = UnlinkOnDrop::one(name.clone());
    let writer = ShmRingWriter::create(&name, 256, &test_guid()).expect("Failed to create");

    assert_eq!(writer.capacity(), 256);
    assert_eq!(writer.sequence(), 0);
}

#[test]
fn test_writer_push() {
    let name = unique_name();
    let _guard = UnlinkOnDrop::one(name.clone());
    let mut writer = ShmRingWriter::create(&name, 256, &test_guid()).expect("Failed to create");

    let data = b"Hello, SHM!";
    writer.push(data).expect("Push failed");

    assert_eq!(writer.sequence(), 1);
}

#[test]
fn test_writer_push_too_large() {
    let name = unique_name();
    let _guard = UnlinkOnDrop::one(name.clone());
    let mut writer = ShmRingWriter::create(&name, 256, &test_guid()).expect("Failed to create");

    let data = vec![0u8; SLOT_PAYLOAD_SIZE + 1];
    let result = writer.push(&data);

    assert!(matches!(result, Err(ShmError::PayloadTooLarge { .. })));
}

#[test]
fn test_reader_attach() {
    let name = unique_name();
    let _guard = UnlinkOnDrop::one(name.clone());
    let _writer = ShmRingWriter::create(&name, 256, &test_guid()).expect("Failed to create");

    let bucket = TopicNotify::bucket_for_guid(&test_guid());
    let reader =
        ShmRingReader::attach(&name, 256, bucket, owner_of(test_guid())).expect("Failed to attach");

    assert_eq!(reader.capacity, 256);
    assert_eq!(reader.sequence(), 0); // Starts at head

    drop(reader);
}

#[test]
fn test_write_read_cycle() {
    let name = unique_name();
    let _guard = UnlinkOnDrop::one(name.clone());
    let mut writer = ShmRingWriter::create(&name, 256, &test_guid()).expect("Failed to create");

    // Push a message
    let msg = b"Test message 123";
    writer.push(msg).expect("Push failed");

    // Attach reader starting from 0 (not head)
    let bucket = TopicNotify::bucket_for_guid(&test_guid());
    let mut reader = ShmRingReader::attach_from(&name, 256, bucket, 0, owner_of(test_guid()))
        .expect("Failed to attach");

    assert!(reader.has_data());
    assert_eq!(reader.available(), 1);

    // Read the message
    let mut buf = [0u8; 256];
    let len = reader.try_pop(&mut buf).expect("Should have data");

    assert_eq!(len, msg.len());
    assert_eq!(&buf[..len], msg);
}

#[test]
fn test_multiple_messages() {
    let name = unique_name();
    let _guard = UnlinkOnDrop::one(name.clone());
    let mut writer = ShmRingWriter::create(&name, 256, &test_guid()).expect("Failed to create");

    // Push multiple messages
    for i in 0..10 {
        let msg = format!("Message {i}");
        writer.push(msg.as_bytes()).expect("Push failed");
    }

    // Read all messages
    let bucket = TopicNotify::bucket_for_guid(&test_guid());
    let mut reader = ShmRingReader::attach_from(&name, 256, bucket, 0, owner_of(test_guid()))
        .expect("Failed to attach");

    let mut buf = [0u8; 256];
    for i in 0..10 {
        let len = reader.try_pop(&mut buf).expect("Should have data");
        let expected = format!("Message {i}");
        assert_eq!(&buf[..len], expected.as_bytes());
    }

    // No more data
    assert!(reader.try_pop(&mut buf).is_none());
}

/// A message that does not fit the buffer is refused with its length and
/// stays first in the ring: a retry with a buffer of that length pops it,
/// then the next message follows in order. A refusal is not corruption.
#[test]
fn a_too_small_pop_keeps_the_message_for_a_bigger_buffer() {
    let name = unique_name();
    let _guard = UnlinkOnDrop::one(name.clone());
    let mut writer = ShmRingWriter::create(&name, 256, &test_guid()).expect("Failed to create");
    let first = [7u8; 40];
    let second = b"second";
    writer.push(&first).expect("Push failed");
    writer.push(second).expect("Push failed");

    let bucket = TopicNotify::bucket_for_guid(&test_guid());
    let mut reader = ShmRingReader::attach_from(&name, 256, bucket, 0, owner_of(test_guid()))
        .expect("Failed to attach");

    let mut small = [0u8; 16];
    assert_eq!(
        reader.try_pop_sized(&mut small),
        Err(40),
        "refused with its length"
    );
    assert_eq!(
        reader.try_pop_sized(&mut small),
        Err(40),
        "still first: a second refusal with the same buffer"
    );
    assert_eq!(reader.metrics.corrupted.load(Ordering::Relaxed), 0);

    let mut big = [0u8; 64];
    assert_eq!(reader.try_pop_sized(&mut big), Ok(Some(40)));
    assert_eq!(&big[..40], &first[..]);
    assert_eq!(reader.try_pop_sized(&mut big), Ok(Some(second.len())));
    assert_eq!(&big[..second.len()], second);
    assert_eq!(reader.try_pop_sized(&mut big), Ok(None));
}

/// A slot whose length is beyond the slot payload is corruption: it is not
/// reported as a size (no allocation, no copy) and it counts as corrupt.
#[test]
fn a_length_beyond_the_slot_payload_is_corruption_not_a_size() {
    let name = unique_name();
    let _guard = UnlinkOnDrop::one(name.clone());
    let mut writer = ShmRingWriter::create(&name, 256, &test_guid()).expect("Failed to create");
    writer.push(b"hello").expect("Push failed");

    let bucket = TopicNotify::bucket_for_guid(&test_guid());
    let mut reader = ShmRingReader::attach_from(&name, 256, bucket, 0, owner_of(test_guid()))
        .expect("Failed to attach");
    reader
        .slot(0)
        .len
        .store(SLOT_PAYLOAD_SIZE_U32 + 1, Ordering::Relaxed);

    let mut big = vec![0u8; 1 << 16];
    assert_eq!(reader.try_pop_sized(&mut big), Ok(None));
    assert_eq!(reader.metrics.corrupted.load(Ordering::Relaxed), 1);
    assert_eq!(reader.next_seq, 0, "nothing consumed");
    assert_eq!(reader.try_pop_sized(&mut big), Ok(None));
}

/// `discard_if_longer` consumes the head only when it is longer than the
/// caller's buffer, without copying it; a head that fits is left in place.
#[test]
fn discard_if_longer_consumes_only_an_oversize_head() {
    let name = unique_name();
    let _guard = UnlinkOnDrop::one(name.clone());
    let mut writer = ShmRingWriter::create(&name, 256, &test_guid()).expect("Failed to create");
    writer.push(&[7u8; 40]).expect("Push failed");
    writer.push(b"six").expect("Push failed");

    let bucket = TopicNotify::bucket_for_guid(&test_guid());
    let mut reader = ShmRingReader::attach_from(&name, 256, bucket, 0, owner_of(test_guid()))
        .expect("Failed to attach");

    assert_eq!(reader.discard_if_longer(16), Some(40));
    assert_eq!(reader.discard_if_longer(16), None, "the head fits 16 bytes");
    assert_eq!(reader.metrics.oversize_skipped.load(Ordering::Relaxed), 1);
    let mut big = [0u8; 64];
    assert_eq!(reader.try_pop_sized(&mut big), Ok(Some(3)));
    assert_eq!(&big[..3], b"six");
}

#[test]
fn test_overrun_detection() {
    let name = unique_name();
    let _guard = UnlinkOnDrop::one(name.clone());
    // Small ring to easily trigger overrun
    let mut writer = ShmRingWriter::create(&name, 4, &test_guid()).expect("Failed to create");

    // Reader starts at 0
    let bucket = TopicNotify::bucket_for_guid(&test_guid());
    let mut reader = ShmRingReader::attach_from(&name, 4, bucket, 0, owner_of(test_guid()))
        .expect("Failed to attach");

    // Write more than capacity (overflow)
    for i in 0..10 {
        writer.push(&[i as u8]).expect("Push failed");
    }

    // Reader should detect overrun
    let mut buf = [0u8; 256];
    let result = reader.try_pop(&mut buf);
    assert!(result.is_none());
    assert!(reader.metrics.overruns.load(Ordering::Relaxed) > 0);
}

#[test]
fn test_concurrent_write_read() {
    let name = unique_name();
    let _guard = UnlinkOnDrop::one(name.clone());
    let guid = test_guid();
    let mut writer = ShmRingWriter::create(&name, 256, &guid).expect("Failed to create");

    let name_clone = name.clone();
    let bucket = TopicNotify::bucket_for_guid(&guid);

    let reader_handle = thread::spawn(move || {
        let mut reader =
            ShmRingReader::attach_from(&name_clone, 256, bucket, 0, owner_of(test_guid()))
                .expect("Failed to attach");

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
}

#[test]
fn test_push_latency() {
    let name = unique_name();
    let _guard = UnlinkOnDrop::one(name.clone());
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

    // SMOKE bound, not a latency measurement -- the same distinction, and the
    // same 50 us ceiling, as `test_try_pop_latency` below.
    //
    // A tight bound is wrong in a unit test: under ThreadSanitizer a push
    // takes an order of magnitude longer than uninstrumented (tens of ns),
    // so a tight bound would fail for a reason the sanitizer does not
    // measure. A unit test carries no regime guard at all: it runs at
    // `opt-level = 0` (see `[profile.test]`), under any sanitizer, in a VM,
    // on a loaded box. This is not the place where push latency is known.
    //
    // Real numbers come from the perf harness, warmed, repeated, pinned, with
    // the dispersion reported (`scripts/bench-machine.sh`, which REFUSES to
    // measure on a non-performance governor). What belongs here is only "did
    // this become catastrophically slow".
    assert!(
        avg_ns < 50_000.0,
        "push is {avg_ns:.0} ns, two orders of magnitude past where it has ever \
         measured: that is a structural regression, not machine noise"
    );
}

#[test]
fn test_try_pop_latency() {
    let name = unique_name();
    let _guard = UnlinkOnDrop::one(name.clone());
    let mut writer = ShmRingWriter::create(&name, 256, &test_guid()).expect("Failed to create");

    // Fill ring
    for i in 0..200 {
        writer.push(&[i as u8; 64]).expect("Push failed");
    }

    let bucket = TopicNotify::bucket_for_guid(&test_guid());
    let mut reader = ShmRingReader::attach_from(&name, 256, bucket, 0, owner_of(test_guid()))
        .expect("Failed to attach");

    let mut buf = [0u8; 256];
    let iterations = 200;

    let start = Instant::now();
    for _ in 0..iterations {
        reader.try_pop(&mut buf).expect("Should have data");
    }
    let elapsed = start.elapsed();

    let avg_ns = elapsed.as_nanos() as f64 / iterations as f64;
    println!("Average try_pop latency: {avg_ns:.1} ns");

    // This is a SMOKE bound, not a latency measurement, and the distinction is
    // deliberate.
    //
    // A tight bound (around 1000 ns) sits so close to the unit-test noise
    // floor (the dispersion is half the distance to the threshold) that it
    // fires when something else is compiling on the same machine and never
    // for a real slowdown. A bound that close to the noise is a coin flip.
    //
    // This is not the place where pop latency is known.
    //
    // Real numbers come from the perf harness, warmed, repeated, pinned, with
    // the dispersion reported (`scripts/bench-machine.sh`). What belongs HERE
    // is only "did this become catastrophically slow", which is what the loose
    // bound below catches while staying silent about scheduling noise.
    assert!(
        avg_ns < 50_000.0,
        "try_pop is {avg_ns:.0} ns, two orders of magnitude past where it has ever \
         measured: that is a structural regression, not machine noise"
    );
}

/// A segment shorter than the geometry we are about to map onto it must
/// be REFUSED, not mapped. `mmap` succeeds past the end of the object and the
/// failure surfaces later as a SIGBUS on first touch, which kills the poller
/// thread instead of returning an error. Reachable without hostile intent: a
/// peer built with a different SLOT_PAYLOAD_SIZE, or a truncated segment.
#[test]
fn a_segment_shorter_than_its_geometry_is_refused_not_mapped() {
    use std::ffi::CString;

    let name = unique_name();
    let _guard = UnlinkOnDrop::one(name.clone());
    let c_name = CString::new(name.clone()).expect("name");

    // Create the segment by hand, one page long, under a name the reader will
    // compute for a full-size ring.
    let fd = unsafe {
        libc::shm_open(
            c_name.as_ptr(),
            libc::O_CREAT | libc::O_RDWR | libc::O_EXCL,
            0o600,
        )
    };
    assert!(fd >= 0, "could not create the short segment");
    assert_eq!(unsafe { libc::ftruncate(fd, 4096) }, 0, "ftruncate failed");
    unsafe { libc::close(fd) };

    let attached = ShmRingReader::attach(&name, 256, 0, owner_of(test_guid()));
    unsafe { libc::shm_unlink(c_name.as_ptr()) };

    match attached {
        Err(ShmError::SegmentTooSmall { actual, expected }) => {
            assert_eq!(actual, 4096);
            assert!(
                expected > 4096,
                "the refusal must name the geometry it refused to map"
            );
        }
        Err(other) => panic!("expected SegmentTooSmall, got {other:?}"),
        Ok(_) => panic!(
            "attached to a 4096 byte segment with a {} byte geometry: the next slot read \
             would be a SIGBUS past the end of the object",
            ring_segment_size(256)
        ),
    }
}

/// A segment planted by anything other than the writer that announced it
/// must be refused, not drained. `/dev/shm` is typically mode 1777 and the
/// segment name derives from the domain id plus the writer GUID, both of which
/// are broadcast in discovery, so the name is not a secret and cannot be used
/// as evidence of who created the segment. Without this check the planted
/// samples reach the Router stamped with the legitimate peer's real unicast
/// locator, which is the identity every per-peer check upstream relies on.
#[test]
fn a_segment_planted_by_someone_else_is_refused() {
    let name = unique_name();
    let _guard = UnlinkOnDrop::one(name.clone());
    let guid = test_guid();

    // A segment that is valid in every structural way: right magic, right
    // version, right capacity, right slot size, right writer GUID. Only the
    // nonce differs, because the planter cannot know it.
    let _writer = ShmRingWriter::create(&name, 256, &guid).expect("create");

    let announced_nonce = crate::transport::shm::local_nonce();
    let attackers_guess = announced_nonce.wrapping_add(1);

    match ShmRingReader::attach(&name, 256, 0, Some((guid, attackers_guess))) {
        Err(ShmError::Corruption) => {}
        Err(other) => panic!("expected the owner check to refuse, got {other:?}"),
        Ok(_) => panic!(
            "attached to a segment whose nonce does not match the one announced: any local \
             process could feed this reader forged samples under the peer's identity"
        ),
    }

    // The legitimate expectation still attaches, so the check refuses the
    // impostor rather than refusing everyone.
    ShmRingReader::attach(&name, 256, 0, Some((guid, announced_nonce)))
        .expect("the real owner must still be accepted");
}

/// A peer that announced no nonce cannot be authenticated, so the reader keeps
/// UDP rather than attaching to something it cannot verify.
#[test]
fn a_segment_with_no_announced_nonce_is_refused() {
    let name = unique_name();
    let _guard = UnlinkOnDrop::one(name.clone());
    let guid = test_guid();
    let _writer = ShmRingWriter::create(&name, 256, &guid).expect("create");

    match ShmRingReader::attach(&name, 256, 0, None) {
        Err(ShmError::Corruption) => {}
        Err(other) => panic!("expected a refusal, got {other:?}"),
        Ok(_) => panic!("attached to a segment that could not be authenticated at all"),
    }
}

/// Overrun recovery must resume at the OLDEST message still in the ring, not at
/// the newest one.
///
/// Jumping to `head - 1` discarded up to `capacity - 2` samples that were
/// committed and readable, to recover from as little as one that had actually
/// been overwritten, and reported the whole hole as a single overrun. On a
/// BEST_EFFORT path with nothing to repair it, that turned a brief scheduling
/// hiccup into a ring-sized loss.
#[test]
fn an_overrun_resumes_at_the_oldest_intact_message() {
    const CAP: usize = 16;
    let name = unique_name();
    let _guard = UnlinkOnDrop::one(name.clone());
    let guid = test_guid();
    let mut writer = ShmRingWriter::create(&name, CAP, &guid).expect("create");
    let mut reader = ShmRingReader::attach(&name, CAP, 0, owner_of(guid)).expect("attach");

    // Lap the reader: write more than one ring without reading.
    let total = CAP + 4;
    for i in 0..total {
        writer.push(&[i as u8; 8]).expect("push");
    }

    let mut buf = [0u8; 64];
    // The first pop detects the overrun, resumes, and returns None.
    assert!(
        reader.try_pop(&mut buf).is_none(),
        "the overrun pop reports nothing and repositions"
    );

    // Now count what is actually still readable. The oldest intact message is
    // head - capacity + 1, so capacity - 1 messages must come back.
    let mut got = 0usize;
    while reader.try_pop(&mut buf).is_some() {
        got += 1;
    }
    assert_eq!(
        got,
        CAP - 1,
        "recovery must keep every message still resident in the ring, not just the last one"
    );

    // And the loss must be reported in SAMPLES, not as one event.
    let skipped = reader
        .metrics
        .samples_skipped
        .load(std::sync::atomic::Ordering::Relaxed);
    assert_eq!(
        skipped,
        (total - (CAP - 1)) as u64,
        "the skipped count must be the number of samples actually stepped over"
    );
    assert_eq!(
        reader
            .metrics
            .overruns
            .load(std::sync::atomic::Ordering::Relaxed),
        1,
        "one overrun event, however many samples it covered"
    );
}

/// A writer killed between marking a slot in-progress and publishing the head
/// must not wedge a reader for ever.
///
/// `head = M` means messages up to M-1 are committed and says nothing about
/// whether M has been started. A writer that started M and died leaves the odd
/// marker for M in exactly the slot a reader `capacity` behind is waiting for,
/// with `head` frozen at M: the lag check (deliberately `>`, because at rest
/// that reader IS waiting for an intact message) never fires, and the reader
/// must not return None on every call from then on - no metric, no log, no
/// progress, while the rest of the ring sits there readable.
#[test]
fn a_reader_is_not_wedged_by_a_writer_that_died_mid_write() {
    const CAP: usize = 16;
    let name = unique_name();
    let _guard = UnlinkOnDrop::one(name.clone());
    let guid = test_guid();
    let mut writer = ShmRingWriter::create(&name, CAP, &guid).expect("create");

    // Fill exactly one ring: head = CAP, messages 0..CAP-1 committed.
    for i in 0..CAP {
        writer.push(&[i as u8; 8]).expect("push");
    }

    // The writer begins message CAP - same slot as message 0 - and dies there:
    // the in-progress marker lands, `head` is never published again.
    writer.slot(0).mark_writing(CAP as u64);

    let mut reader = ShmRingReader::attach_from(&name, CAP, 0, 0, owner_of(guid)).expect("attach");
    let mut buf = [0u8; 64];

    // Message 0 is gone. The reader must say so and move on, not spin on it.
    assert!(
        reader.try_pop(&mut buf).is_none(),
        "message 0 is unreadable"
    );

    let mut got = 0usize;
    while reader.try_pop(&mut buf).is_some() {
        got += 1;
    }
    assert!(
        got > 0,
        "the reader must drain what is still in the ring instead of wedging on the \
         slot the dead writer left mid-write"
    );
    assert_eq!(
        got,
        CAP - 1,
        "every message after the lost one is intact and must come back"
    );
    assert!(
        reader
            .metrics
            .overruns
            .load(std::sync::atomic::Ordering::Relaxed)
            > 0,
        "losing a message must be counted, not silent"
    );
}
