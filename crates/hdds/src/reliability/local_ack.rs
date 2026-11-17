// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Acknowledgment at admission into a local reader's history, including its ring.

use super::HistoryCache;
use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, Mutex};

/// Per-reader cumulative acknowledgment watermarks shared by wire and local paths.
pub type AckTrack = Arc<Mutex<HashMap<[u8; 16], u64>>>;

pub(crate) struct LocalAckWriter {
    pub(crate) track: AckTrack,
    pub(crate) cache: Arc<HistoryCache>,
    pub(crate) volatile: bool,
}

/// One reliable local pairing. Replayed and deferred coherent deliveries can
/// complete out of sequence; a later arrival never acknowledges a missing one.
pub(crate) struct LocalReaderAck {
    guid: [u8; 16],
    track: AckTrack,
    cache: Arc<HistoryCache>,
    state: Mutex<LocalAckState>,
}

struct LocalAckState {
    historical: BTreeSet<u64>,
    next: u64,
    completed: BTreeSet<u64>,
}

impl LocalAckWriter {
    pub(crate) fn reader(&self, guid: [u8; 16], reader_volatile: bool) -> Arc<LocalReaderAck> {
        let mut track = self.track.lock().unwrap_or_else(|e| e.into_inner());
        let (highest, mut historical) = self.cache.local_ack_history();
        if self.volatile || reader_volatile {
            historical.clear();
        }
        let floor = historical.first().map_or(highest, |seq| seq - 1);
        track.insert(guid, floor);
        self.cache.set_acked_floor(floor_of(&track));
        Arc::new(LocalReaderAck {
            guid,
            track: self.track.clone(),
            cache: self.cache.clone(),
            state: Mutex::new(LocalAckState {
                historical,
                next: highest.saturating_add(1),
                completed: BTreeSet::new(),
            }),
        })
    }
}

fn floor_of(track: &HashMap<[u8; 16], u64>) -> u64 {
    track.values().copied().min().unwrap_or(u64::MAX)
}

impl LocalReaderAck {
    /// The entry was admitted, or deliberately excluded by a filter/gate.
    /// An end-of-set control has no local payload and is settled the same way.
    pub(crate) fn acknowledge(&self, seq: u64) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.historical.remove(&seq);
        if seq == state.next {
            state.next = state.next.saturating_add(1);
        } else if seq > state.next {
            state.completed.insert(seq);
        }
        loop {
            let next = state.next;
            if !state.completed.remove(&next) {
                break;
            }
            state.next = next.saturating_add(1);
        }
        let floor = state
            .historical
            .first()
            .map_or(state.next - 1, |seq| seq - 1);
        let mut track = self.track.lock().unwrap_or_else(|e| e.into_inner());
        // A delivery racing teardown cannot recreate a departed pairing.
        if let Some(acked) = track.get_mut(&self.guid) {
            if floor > *acked {
                *acked = floor;
                self.cache.set_acked_floor(floor_of(&track));
            }
        }
    }

    pub(crate) fn depart(&self) {
        let mut track = self.track.lock().unwrap_or_else(|e| e.into_inner());
        track.remove(&self.guid);
        self.cache.set_acked_floor(floor_of(&track));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::rt::{Claim, IndexEntry, IndexRing, MergerReader, SlabPool, TopicMerger};
    use crate::dds::qos::History;
    use std::sync::atomic::{AtomicBool, Ordering};

    fn writer(volatile: bool) -> LocalAckWriter {
        LocalAckWriter {
            track: Arc::default(),
            cache: Arc::new(HistoryCache::new_with_limits(
                Arc::new(SlabPool::new()),
                100,
                100_000,
                History::KeepAll,
            )),
            volatile,
        }
    }

    #[test]
    fn local_acknowledgment_preserves_holes_until_each_change_is_admitted() {
        let writer = writer(true);
        let reader = writer.reader([1; 16], true);
        reader.acknowledge(3);
        reader.acknowledge(2);
        assert_eq!(writer.track.lock().unwrap()[&[1; 16]], 0);
        reader.acknowledge(1);
        assert_eq!(writer.track.lock().unwrap()[&[1; 16]], 3);
        reader.depart();
        reader.acknowledge(4);
        assert!(writer.track.lock().unwrap().is_empty());
        assert_eq!(writer.cache.acked_floor(), u64::MAX);
    }

    #[test]
    fn local_acknowledgment_starts_after_earlier_volatile_writes() {
        let writer = writer(true);
        writer.cache.record_local_commit(7);
        let reader = writer.reader([1; 16], true);
        assert_eq!(writer.track.lock().unwrap()[&[1; 16]], 7);
        reader.acknowledge(8);
        assert_eq!(writer.track.lock().unwrap()[&[1; 16]], 8);
    }

    #[test]
    fn local_acknowledgment_of_filtered_data_waits_for_the_write_to_commit() {
        let writer = writer(true);
        let ack = writer.reader([1; 16], true);
        let merger = TopicMerger::new();
        let accepting = Arc::new(AtomicBool::new(false));
        let filter = accepting.clone();
        merger.add_reader(
            MergerReader::with_filter(
                Arc::new(IndexRing::with_capacity(16)),
                Arc::new(|| {}),
                Some(Arc::new(move |_, _| filter.load(Ordering::Acquire))),
            )
            .acknowledging(Some(ack)),
        );
        let pool = SlabPool::new();
        let (handle, _) = pool.reserve_and_write(b"data", Claim::Writer).unwrap();
        let entry = IndexEntry::new(1, handle, 4);
        let key = || None;
        let admission = merger.admit(&entry, &pool, &key, None).unwrap();
        drop(admission); // Another reader or the writer's history refused the write.
        assert_eq!(writer.track.lock().unwrap()[&[1; 16]], 0);
        // Reuse the unpublished number for a value that passes the filter.
        accepting.store(true, Ordering::Release);
        let admission = merger.admit(&entry, &pool, &key, None).unwrap();
        assert_eq!(writer.track.lock().unwrap()[&[1; 16]], 0);
        assert!(merger.deliver(
            admission,
            entry,
            &pool,
            &key,
            None,
            crate::core::rt::merger::PendingOrders::default()
        ));
        assert_eq!(writer.track.lock().unwrap()[&[1; 16]], 1);
    }
}
