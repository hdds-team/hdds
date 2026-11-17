// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 naskel.com
//
// Host-side integration test for the seL4 port.
//
// Goal: prove that two `MicroParticipant`s running back-to-back over a
// pure in-memory `MockRing` can exchange CDR-encoded samples end-to-end,
// with every packet being parsed by `hdds-micro` as a valid RTPS
// datagram. If this test passes, the Transport trait impl is correct
// and `MockRing` can be swapped for a real sDDF binding without
// touching the DDS stack.

use hdds_micro::cdr::{CdrDecoder, CdrEncoder};
use hdds_micro::rtps::{EntityId, Locator};
use hdds_micro::{MicroParticipant, MicroReader, MicroWriter};

use hdds_micro_sel4::{mock_pair, Sel4UdpTransport};

const N_SAMPLES: u32 = 500;

#[test]
fn writer_to_reader_no_loss() {
    let a_addr = ([10, 0, 0, 1], 7400u16);
    let b_addr = ([10, 0, 0, 2], 7401u16);

    let (ring_a, ring_b) = mock_pair(a_addr, b_addr);
    let transport_a = Sel4UdpTransport::new(ring_a, Locator::udpv4(a_addr.0, a_addr.1));
    let transport_b = Sel4UdpTransport::new(ring_b, Locator::udpv4(b_addr.0, b_addr.1));

    let mut participant_a =
        MicroParticipant::with_instance(0, transport_a, 1).expect("participant A");
    let mut participant_b =
        MicroParticipant::with_instance(0, transport_b, 2).expect("participant B");

    let writer_entity = participant_a.allocate_entity_id(true);
    let reader_entity = participant_b.allocate_entity_id(false);

    let mut writer = MicroWriter::new(
        participant_a.guid_prefix(),
        writer_entity,
        "TestCounter",
        Locator::udpv4(b_addr.0, b_addr.1),
    )
    .expect("writer");

    let mut reader = MicroReader::new(
        participant_b.guid_prefix(),
        reader_entity,
        "TestCounter",
    )
    .expect("reader");

    let mut rx_values = Vec::with_capacity(N_SAMPLES as usize);
    let mut last_seq: i64 = 0;

    for i in 0..N_SAMPLES {
        // Encode a single u32 as the sample payload.
        let mut payload_buf = [0u8; 16];
        let mut encoder = CdrEncoder::new(&mut payload_buf);
        encoder.encode_u32(i).expect("encode u32");
        let payload = encoder.finish();

        writer
            .write(payload, participant_a.transport_mut())
            .expect("write sample");

        // Reader uses try_recv under the hood - since MockRing is
        // synchronous, the packet is already queued when we poll.
        let sample = reader
            .read(participant_b.transport_mut())
            .expect("read ok")
            .expect("sample present");

        // Sequence numbers from hdds-micro are 1-based and monotonic.
        let seq = sample.sequence_number.value();
        assert!(
            seq > last_seq,
            "seq not strictly increasing: got {} after {}",
            seq,
            last_seq
        );
        last_seq = seq;

        let mut decoder = CdrDecoder::new(sample.payload);
        let got = decoder.decode_u32().expect("decode u32");
        rx_values.push(got);

        // Writer entity id must match what participant_a allocated.
        assert_eq!(sample.writer_guid.entity_id, writer_entity);
        // Reader filters EntityId::UNKNOWN -> everyone, so the sample
        // arrives even though the writer sends to UNKNOWN reader_id.
        let _ = EntityId::UNKNOWN;
    }

    assert_eq!(rx_values.len() as u32, N_SAMPLES);
    for (i, v) in rx_values.iter().enumerate() {
        assert_eq!(*v as usize, i, "sample {} content mismatch (got {})", i, v);
    }

    // Sanity: the shared ring counters should reflect exactly N_SAMPLES
    // passes in each direction (well, only A->B here).
    let tx_seen = participant_a.transport().ring().tx_count();
    let rx_seen = participant_b.transport().ring().rx_count();
    assert_eq!(tx_seen, N_SAMPLES);
    assert_eq!(rx_seen, N_SAMPLES);
}

#[test]
fn reader_returns_none_when_idle() {
    let (_ring_a, ring_b) = mock_pair(([10, 0, 0, 1], 7400), ([10, 0, 0, 2], 7401));
    let transport_b =
        Sel4UdpTransport::new(ring_b, Locator::udpv4([10, 0, 0, 2], 7401));
    let mut participant_b = MicroParticipant::with_instance(0, transport_b, 2).unwrap();
    let reader_entity = participant_b.allocate_entity_id(false);

    let mut reader = MicroReader::new(
        participant_b.guid_prefix(),
        reader_entity,
        "Idle",
    )
    .unwrap();

    // No writer, no traffic -> read() must be Ok(None), not an error.
    let result = reader
        .read(participant_b.transport_mut())
        .expect("idle read should be Ok(None), not Err");
    assert!(result.is_none());
}

#[test]
fn bidirectional_two_topics() {
    // A publishes "Up", B publishes "Down". Each side subscribes to
    // whatever the other publishes. We only verify that both directions
    // carry at least a handful of samples without error.

    const N: u32 = 50;

    let (ring_a, ring_b) = mock_pair(([10, 0, 0, 1], 7400), ([10, 0, 0, 2], 7401));
    let mut part_a = MicroParticipant::with_instance(
        0,
        Sel4UdpTransport::new(ring_a, Locator::udpv4([10, 0, 0, 1], 7400)),
        1,
    )
    .unwrap();
    let mut part_b = MicroParticipant::with_instance(
        0,
        Sel4UdpTransport::new(ring_b, Locator::udpv4([10, 0, 0, 2], 7401)),
        2,
    )
    .unwrap();

    let mut w_up = MicroWriter::new(
        part_a.guid_prefix(),
        part_a.allocate_entity_id(true),
        "Up",
        Locator::udpv4([10, 0, 0, 2], 7401),
    )
    .unwrap();
    let mut w_down = MicroWriter::new(
        part_b.guid_prefix(),
        part_b.allocate_entity_id(true),
        "Down",
        Locator::udpv4([10, 0, 0, 1], 7400),
    )
    .unwrap();
    let mut r_up = MicroReader::new(
        part_b.guid_prefix(),
        part_b.allocate_entity_id(false),
        "Up",
    )
    .unwrap();
    let mut r_down = MicroReader::new(
        part_a.guid_prefix(),
        part_a.allocate_entity_id(false),
        "Down",
    )
    .unwrap();

    for i in 0..N {
        let mut buf = [0u8; 8];
        let mut enc = CdrEncoder::new(&mut buf);
        enc.encode_u32(i).unwrap();
        let p = enc.finish();
        w_up.write(p, part_a.transport_mut()).unwrap();

        let mut buf2 = [0u8; 8];
        let mut enc2 = CdrEncoder::new(&mut buf2);
        enc2.encode_u32(i + 1000).unwrap();
        let p2 = enc2.finish();
        w_down.write(p2, part_b.transport_mut()).unwrap();
    }

    let mut up_seen = 0;
    let mut down_seen = 0;
    for _ in 0..N {
        let s_up = r_up.read(part_b.transport_mut()).unwrap();
        if let Some(s) = s_up {
            let mut d = CdrDecoder::new(s.payload);
            let v = d.decode_u32().unwrap();
            assert_eq!(v, up_seen as u32);
            up_seen += 1;
        }
        let s_down = r_down.read(part_a.transport_mut()).unwrap();
        if let Some(s) = s_down {
            let mut d = CdrDecoder::new(s.payload);
            let v = d.decode_u32().unwrap();
            assert_eq!(v, down_seen as u32 + 1000);
            down_seen += 1;
        }
    }

    assert_eq!(up_seen as u32, N);
    assert_eq!(down_seen as u32, N);
}
