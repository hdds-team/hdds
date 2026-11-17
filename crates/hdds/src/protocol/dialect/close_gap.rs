// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Vendor zone: when the retirement GAP of an InterCOM set boundary goes out.
//!
//! The end of a coherent set takes a sequence number of its own, the
//! boundary, which InterCOM never acknowledges: it leaves the SN unreceived
//! and its reliable reader will not hand anything behind it to the
//! application until the SN is resolved. That is how InterCOM withholds the
//! next set: the samples arrive, wait behind the boundary, and appear when
//! the boundary is retired. The writer therefore decides WHEN a set becomes
//! visible: it retires the previous boundary with a GAP right before the
//! close marker of the set that follows, after every sample of that set is
//! on the wire, so the whole set is released at once.
//!
//! InterCOM NACKs the boundary on every HEARTBEAT it answers, and the
//! ordinary repair of a close slot (`WriterNackHandler::repair_ecs_close`)
//! retires the SN with a GAP at once. That arrives at an arbitrary phase of
//! the next set's transmission: before it, the set is no longer withheld
//! and each sample is handed over as it arrives; in the middle of it, the
//! reader releases a part of the set. A read cycle landing in either window
//! returns a part of a coherent set.
//!
//! A boundary whose retirement is deferred is therefore NOT retired by the
//! repair of a NACK, for [`INTERCOM_CLOSE_GAP_HOLD`] at most: past it the
//! repair answers as it always did, so a reader never waits on a set that
//! does not follow.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// How long the NACK repair leaves a deferred boundary alone. It has to
/// outlast one write period of a coherent writer plus the transmission of
/// its set; a writer whose sets are further apart than this falls back to
/// the immediate retirement.
pub(crate) const INTERCOM_CLOSE_GAP_HOLD: Duration = Duration::from_millis(1000);

/// The boundaries awaiting their deferred retirement, per reader (the key is
/// the reader's endpoint GUID): one writer, one boundary per reader.
#[derive(Default)]
pub(crate) struct DeferredCloseGaps {
    pending: Mutex<HashMap<[u8; 16], (u64, Instant)>>,
}

impl DeferredCloseGaps {
    /// `boundary` becomes the reader's pending boundary at `now`; returns
    /// the boundary it replaces, the one to retire now, when it is another
    /// SN.
    pub(crate) fn defer(&self, reader: [u8; 16], boundary: u64, now: Instant) -> Option<u64> {
        let mut pending = self.pending.lock().unwrap_or_else(|e| e.into_inner());
        pending
            .insert(reader, (boundary, now))
            .map(|(previous, _)| previous)
            .filter(|previous| *previous != boundary)
    }

    /// The reader's pending boundary, taken: it is retired now.
    pub(crate) fn take(&self, reader: [u8; 16]) -> Option<u64> {
        self.pending
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&reader)
            .map(|(boundary, _)| boundary)
    }

    /// Whether the repair of a NACK on `sn` from `reader`, at `now`, leaves
    /// the boundary to its deferred retirement.
    pub(crate) fn holds(&self, reader: &[u8; 16], sn: u64, now: Instant) -> bool {
        let pending = self.pending.lock().unwrap_or_else(|e| e.into_inner());
        matches!(
            pending.get(reader),
            Some((boundary, since))
                if *boundary == sn
                    && now.saturating_duration_since(*since) < INTERCOM_CLOSE_GAP_HOLD
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const READER: [u8; 16] = [7; 16];

    /// The first boundary of a reader has nothing to retire; the next one
    /// retires the one before it, and only that one.
    #[test]
    fn a_new_boundary_retires_the_previous_one() {
        let gaps = DeferredCloseGaps::default();
        let t0 = Instant::now();
        assert_eq!(gaps.defer(READER, 13, t0), None);
        assert_eq!(gaps.defer(READER, 26, t0), Some(13));
        assert_eq!(
            gaps.defer(READER, 26, t0),
            None,
            "the same SN is not retired"
        );
        assert_eq!(gaps.defer([8; 16], 13, t0), None, "per reader");
    }

    /// The repair of a NACK leaves the pending boundary alone for the hold
    /// and no longer after it, and only for that reader and that SN.
    #[test]
    fn the_repair_waits_for_the_deferred_retirement_within_the_hold() {
        let gaps = DeferredCloseGaps::default();
        let t0 = Instant::now();
        gaps.defer(READER, 13, t0);
        assert!(gaps.holds(&READER, 13, t0));
        assert!(gaps.holds(
            &READER,
            13,
            t0 + INTERCOM_CLOSE_GAP_HOLD - Duration::from_millis(1)
        ));
        assert!(
            !gaps.holds(&READER, 13, t0 + INTERCOM_CLOSE_GAP_HOLD),
            "past the hold the repair answers as it always did"
        );
        assert!(
            !gaps.holds(&READER, 12, t0),
            "another SN is not the boundary"
        );
        assert!(!gaps.holds(&[8; 16], 13, t0), "another reader is not held");
    }

    /// Once the boundary is retired by its successor, the repair of a NACK
    /// on the retired SN is no longer held.
    #[test]
    fn a_retired_boundary_is_no_longer_held() {
        let gaps = DeferredCloseGaps::default();
        let t0 = Instant::now();
        gaps.defer(READER, 13, t0);
        gaps.defer(READER, 26, t0);
        assert!(!gaps.holds(&READER, 13, t0));
        assert!(gaps.holds(&READER, 26, t0));
        assert_eq!(gaps.take(READER), Some(26));
        assert!(!gaps.holds(&READER, 26, t0), "a taken boundary is released");
        assert_eq!(gaps.take(READER), None);
    }
}
