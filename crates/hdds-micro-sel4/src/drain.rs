// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 naskel.com

//! Drain the receive queue of one hdds-micro reader.
//!
//! The ring re-arms its RX notification only when it finds the queue empty
//! (`Sel4Ring::try_dequeue_rx`). A drain that stops early, on a frame it
//! could not use, leaves frames queued with no notification pending, and
//! the PD stops receiving. [`drain_queue`] therefore stops only when the
//! transport reports an empty queue.

use hdds_micro::{Error as MicroError, MicroReader, Next, Transport};

/// Consume every frame queued for `reader` and call `on_sample(seq, payload)`
/// for each sample. Frames that carry no sample for this reader (malformed,
/// foreign, oversized) are counted in `skipped` and do not end the drain.
/// Returns the number of samples delivered.
pub fn drain_queue<T, F>(
    reader: &mut MicroReader,
    transport: &mut T,
    skipped: &mut u64,
    mut on_sample: F,
) -> Result<u64, MicroError>
where
    T: Transport,
    F: FnMut(i64, &[u8]),
{
    let mut delivered = 0u64;
    loop {
        match reader.read_next(transport)? {
            Next::Sample(sample) => {
                on_sample(sample.sequence_number.value(), sample.payload);
                delivered += 1;
            }
            Next::Skipped => *skipped += 1,
            Next::Empty => return Ok(delivered),
        }
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use crate::mock_ring::mock_pair;
    use crate::transport::Sel4UdpTransport;
    use hdds_micro::rtps::{EntityId, GuidPrefix, Locator};

    const READER: EntityId = EntityId::new([0, 0, 0x01, 0xc7]);

    /// A real 64-octet RTPS DATA datagram captured from `hdds_pub` on the
    /// LAN (writer SN 1, readerId UNKNOWN). Source: `scripts/base_datagram.hex`
    /// in the evidence directory.
    const BASE_HEX: &str = "525450530205011a0000ffffc0a8015b0000834c150528000000100000000000000001c20000000001000000000100002a0000006666a0410100000000000000";

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
            .collect()
    }

    /// A valid sample with writer sequence number `seq`.
    fn valid(seq: u32) -> Vec<u8> {
        let mut d = unhex(BASE_HEX);
        d[40..44].copy_from_slice(&seq.to_le_bytes());
        d
    }

    /// A DATA addressed to a reader other than ours.
    fn foreign() -> Vec<u8> {
        let mut d = unhex(BASE_HEX);
        d[28..32].copy_from_slice(&[0, 0, 0, 1]);
        d
    }

    /// Cut off inside the RTPS header.
    fn truncated() -> Vec<u8> {
        unhex(BASE_HEX)[..8].to_vec()
    }

    /// Larger than the reader's 1024-octet receive buffer.
    fn oversized() -> Vec<u8> {
        vec![0xAB; 1100]
    }

    fn pair() -> (Sel4UdpTransport<crate::mock_ring::MockRing>, Sel4UdpTransport<crate::mock_ring::MockRing>) {
        let (a, b) = mock_pair(([10, 0, 0, 1], 7400), ([10, 0, 0, 2], 7401));
        (
            Sel4UdpTransport::new(a, Locator::udpv4([10, 0, 0, 1], 7400)),
            Sel4UdpTransport::new(b, Locator::udpv4([10, 0, 0, 2], 7401)),
        )
    }

    #[test]
    fn malformed_and_foreign_frames_do_not_stop_the_drain() {
        let (mut tx, mut rx) = pair();
        let dest = Locator::udpv4([10, 0, 0, 2], 7401);
        let mut reader = MicroReader::new(GuidPrefix::UNKNOWN, READER, "Temperature")
            .expect("reader");
        for frame in [truncated(), foreign(), oversized(), valid(1), truncated(), valid(2)] {
            tx.send(&frame, &dest).expect("send");
        }

        let mut skipped = 0u64;
        let mut seqs: Vec<i64> = Vec::new();
        let delivered = drain_queue(&mut reader, &mut rx, &mut skipped, |seq: i64, _p: &[u8]| {
            seqs.push(seq)
        })
        .expect("drain");

        assert_eq!(seqs, vec![1, 2], "valid samples behind the bad frames must arrive");
        assert_eq!(delivered, 2);
        assert_eq!(skipped, 4, "trunc, foreign, oversized and trunc are counted");
        assert_eq!(
            rx.try_recv(&mut [0u8; 64]),
            Err(MicroError::ResourceExhausted),
            "the drain must end on an empty queue"
        );
    }

    #[test]
    fn a_queue_of_only_bad_frames_drains_to_empty() {
        let (mut tx, mut rx) = pair();
        let dest = Locator::udpv4([10, 0, 0, 2], 7401);
        let mut reader = MicroReader::new(GuidPrefix::UNKNOWN, READER, "Temperature")
            .expect("reader");
        for frame in [truncated(), oversized(), foreign()] {
            tx.send(&frame, &dest).expect("send");
        }
        let mut skipped = 0u64;
        let delivered = drain_queue(&mut reader, &mut rx, &mut skipped, |_: i64, _: &[u8]| {})
            .expect("drain");
        assert_eq!(delivered, 0);
        assert_eq!(skipped, 3);
        assert_eq!(rx.try_recv(&mut [0u8; 64]), Err(MicroError::ResourceExhausted));
    }
}
