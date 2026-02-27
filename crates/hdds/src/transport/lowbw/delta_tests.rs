// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

    use super::*;

    #[test]
    fn test_delta_config_default() {
        let config = DeltaConfig::default();
        assert_eq!(config.keyframe_period, Duration::from_millis(5000));
        assert_eq!(config.keyframe_redundancy, 2);
        assert_eq!(config.redundancy_spacing, Duration::from_millis(200));
        assert_eq!(config.max_fields, 64);
    }

    #[test]
    fn test_encoder_first_poll_is_full() {
        let mut encoder = DeltaEncoder::new(DeltaConfig::default());
        encoder.update_field(0, b"temp=25.5");
        encoder.update_field(1, b"humidity=60");

        let now = Instant::now();
        let record = encoder.poll_record(now);

        match record {
            DeltaRecord::Full { full_seq, payload } => {
                assert_eq!(full_seq, 1);
                assert!(!payload.is_empty());
            }
            other => unreachable!("Expected FULL record, got {:?}", other),
        }
    }

    #[test]
    fn test_encoder_delta_after_full() {
        let mut encoder = DeltaEncoder::new(DeltaConfig::default());
        encoder.update_field(0, b"temp=25.5");

        let now = Instant::now();

        // First poll: FULL
        let _ = encoder.poll_record(now);

        // Update field
        encoder.update_field(0, b"temp=26.0");

        // Second poll: DELTA
        let record = encoder.poll_record(now);

        match record {
            DeltaRecord::Delta {
                base_full_seq,
                patch_seq,
                payload,
            } => {
                assert_eq!(base_full_seq, 1);
                assert_eq!(patch_seq, 1);
                assert!(!payload.is_empty());
            }
            other => unreachable!("Expected DELTA record, got {:?}", other),
        }
    }

    #[test]
    fn test_encoder_no_change_no_record() {
        let mut encoder = DeltaEncoder::new(DeltaConfig::default());
        encoder.update_field(0, b"temp=25.5");

        let now = Instant::now();

        // First poll: FULL
        let _ = encoder.poll_record(now);

        // No changes - should return None
        let record = encoder.poll_record(now);
        assert_eq!(record, DeltaRecord::None);
    }

    #[test]
    fn test_encoder_redundant_fulls() {
        let config = DeltaConfig {
            keyframe_redundancy: 2,
            redundancy_spacing: Duration::from_millis(100),
            ..Default::default()
        };
        let mut encoder = DeltaEncoder::new(config);
        encoder.update_field(0, b"temp=25.5");

        let start = Instant::now();

        // First poll: FULL
        let record1 = encoder.poll_record(start);
        assert!(matches!(record1, DeltaRecord::Full { .. }));

        // Immediately after: no record (spacing not elapsed)
        let record2 = encoder.poll_record(start);
        assert_eq!(record2, DeltaRecord::None);

        // After spacing: redundant FULL
        let later = start + Duration::from_millis(150);
        let record3 = encoder.poll_record(later);
        assert!(matches!(record3, DeltaRecord::Full { .. }));

        // After another spacing: second redundant FULL
        let even_later = later + Duration::from_millis(150);
        let record4 = encoder.poll_record(even_later);
        assert!(matches!(record4, DeltaRecord::Full { .. }));

        // No more redundant FULLs
        let much_later = even_later + Duration::from_millis(150);
        let record5 = encoder.poll_record(much_later);
        assert_eq!(record5, DeltaRecord::None);

        assert_eq!(encoder.stats.fulls_sent, 1);
        assert_eq!(encoder.stats.redundant_fulls_sent, 2);
    }

    #[test]
    fn test_encoder_periodic_full() {
        let config = DeltaConfig {
            keyframe_period: Duration::from_millis(100),
            keyframe_redundancy: 0,
            ..Default::default()
        };
        let mut encoder = DeltaEncoder::new(config);
        encoder.update_field(0, b"temp=25.5");

        let start = Instant::now();

        // First poll: FULL
        let record1 = encoder.poll_record(start);
        assert!(matches!(record1, DeltaRecord::Full { full_seq: 1, .. }));

        // Before period: no FULL
        encoder.update_field(0, b"temp=26.0");
        let record2 = encoder.poll_record(start + Duration::from_millis(50));
        assert!(matches!(record2, DeltaRecord::Delta { .. }));

        // After period: new FULL
        encoder.update_field(0, b"temp=27.0");
        let record3 = encoder.poll_record(start + Duration::from_millis(150));
        assert!(matches!(record3, DeltaRecord::Full { full_seq: 2, .. }));
    }

    #[test]
    fn test_decoder_full_decode() {
        let mut decoder = DeltaDecoder::new();

        // Create a FULL payload manually
        let mut encoder = DeltaEncoder::new(DeltaConfig::default());
        encoder.update_field(0, b"temp=25.5");
        encoder.update_field(1, b"humidity=60");

        let now = Instant::now();
        let record = encoder.poll_record(now);

        if let DeltaRecord::Full { payload, .. } = record {
            let full_seq = decoder.on_full(&payload).unwrap();
            assert_eq!(full_seq, 1);
            assert_eq!(decoder.get_field(0), Some(b"temp=25.5".as_slice()));
            assert_eq!(decoder.get_field(1), Some(b"humidity=60".as_slice()));
        }
    }

    #[test]
    fn test_decoder_delta_decode() {
        let mut encoder = DeltaEncoder::new(DeltaConfig::default());
        let mut decoder = DeltaDecoder::new();

        encoder.update_field(0, b"temp=25.5");
        encoder.update_field(1, b"humidity=60");

        let now = Instant::now();

        // FULL
        if let DeltaRecord::Full { payload, .. } = encoder.poll_record(now) {
            decoder.on_full(&payload).unwrap();
        }

        // Update and DELTA
        encoder.update_field(0, b"temp=26.0");
        if let DeltaRecord::Delta { payload, .. } = encoder.poll_record(now) {
            let patch_seq = decoder.on_delta(&payload).unwrap();
            assert_eq!(patch_seq, 1);
            assert_eq!(decoder.get_field(0), Some(b"temp=26.0".as_slice()));
            assert_eq!(decoder.get_field(1), Some(b"humidity=60".as_slice())); // unchanged
        }
    }

    #[test]
    fn test_decoder_delta_without_base() {
        let mut decoder = DeltaDecoder::new();

        // Try to decode a DELTA without having received FULL
        let mut encoder = DeltaEncoder::new(DeltaConfig::default());
        encoder.update_field(0, b"temp=25.5");

        let now = Instant::now();
        let _ = encoder.poll_record(now); // FULL (discard)

        encoder.update_field(0, b"temp=26.0");
        if let DeltaRecord::Delta { payload, .. } = encoder.poll_record(now) {
            let result = decoder.on_delta(&payload);
            assert!(matches!(result, Err(DeltaError::BaseMissing(_))));
            assert_eq!(decoder.stats.deltas_dropped, 1);
        }
    }

    #[test]
    fn test_decoder_resync_detection() {
        let mut decoder = DeltaDecoder::new();

        // First FULL (seq=1)
        let mut encoder = DeltaEncoder::new(DeltaConfig {
            keyframe_period: Duration::from_millis(1),
            keyframe_redundancy: 0,
            ..Default::default()
        });
        encoder.update_field(0, b"temp=25.5");

        let now = Instant::now();
        if let DeltaRecord::Full { payload, .. } = encoder.poll_record(now) {
            decoder.on_full(&payload).unwrap();
        }

        // Simulate gap: send seq=5 (skipped 2,3,4)
        for _ in 0..4 {
            encoder.update_field(0, b"x");
            let later = now + Duration::from_millis(10);
            let _ = encoder.poll_record(later); // force new FULLs
        }

        // This should trigger resync
        encoder.update_field(0, b"temp=30.0");
        let much_later = now + Duration::from_millis(100);
        if let DeltaRecord::Full { payload, .. } = encoder.poll_record(much_later) {
            decoder.on_full(&payload).unwrap();
        }

        assert!(decoder.stats.resyncs > 0);
    }

    #[test]
    fn test_state_ack_encode_decode() {
        let ack = StateAck { last_full_seq: 42 };

        let mut buf = [0u8; 16];
        let len = ack.encode(&mut buf).unwrap();

        let (decoded, consumed) = StateAck::decode(&buf[..len]).unwrap();
        assert_eq!(decoded.last_full_seq, 42);
        assert_eq!(consumed, len);
    }

    #[test]
    fn test_decoder_generate_state_ack() {
        let mut decoder = DeltaDecoder::new();

        // No FULL yet
        assert!(decoder.generate_state_ack().is_none());

        // After FULL
        let mut encoder = DeltaEncoder::new(DeltaConfig::default());
        encoder.update_field(0, b"data");
        if let DeltaRecord::Full { payload, .. } = encoder.poll_record(Instant::now()) {
            decoder.on_full(&payload).unwrap();
        }

        let ack = decoder.generate_state_ack();
        assert!(ack.is_some());
        assert_eq!(ack.unwrap().last_full_seq, 1);
        assert_eq!(decoder.stats.state_acks_sent, 1);
    }

    #[test]
    fn test_estimate_full_size() {
        let fields: Vec<(u32, &[u8])> = vec![(0, b"temp"), (1, b"humidity")];
        let size = estimate_full_size(&fields);
        // full_seq(~2) + field_count(1) + field0(1+1+4) + field1(1+1+8) = ~19
        assert!(size > 15 && size < 30);
    }

    #[test]
    fn test_estimate_delta_size() {
        let fields: Vec<(u32, &[u8])> = vec![(0, b"temp")];
        let size = estimate_delta_size(1, 1, &fields);
        // base_seq(1) + patch_seq(1) + count(1) + field(1+1+4) = ~9
        assert!(size > 5 && size < 15);
    }

    #[test]
    fn test_encoder_stats() {
        let config = DeltaConfig {
            keyframe_redundancy: 1,
            redundancy_spacing: Duration::from_millis(1),
            ..Default::default()
        };
        let mut encoder = DeltaEncoder::new(config);
        encoder.update_field(0, b"temp=25.5");

        let now = Instant::now();

        // FULL
        let _ = encoder.poll_record(now);
        assert_eq!(encoder.stats.fulls_sent, 1);

        // Redundant FULL
        let later = now + Duration::from_millis(10);
        let _ = encoder.poll_record(later);
        assert_eq!(encoder.stats.redundant_fulls_sent, 1);

        // DELTA
        encoder.update_field(0, b"temp=26.0");
        let _ = encoder.poll_record(later);
        assert_eq!(encoder.stats.deltas_sent, 1);
    }

    #[test]
    fn test_decoder_stats() {
        let mut encoder = DeltaEncoder::new(DeltaConfig::default());
        let mut decoder = DeltaDecoder::new();

        encoder.update_field(0, b"data");
        let now = Instant::now();

        // FULL
        if let DeltaRecord::Full { payload, .. } = encoder.poll_record(now) {
            decoder.on_full(&payload).unwrap();
        }
        assert_eq!(decoder.stats.fulls_received, 1);

        // DELTA
        encoder.update_field(0, b"new_data");
        if let DeltaRecord::Delta { payload, .. } = encoder.poll_record(now) {
            decoder.on_delta(&payload).unwrap();
        }
        assert_eq!(decoder.stats.deltas_received, 1);
    }

    #[test]
    fn test_force_full() {
        let mut encoder = DeltaEncoder::new(DeltaConfig::default());
        encoder.update_field(0, b"data");

        let now = Instant::now();

        // Force FULL (even though no poll needed)
        let record = encoder.force_full(now);
        assert!(matches!(record, DeltaRecord::Full { .. }));
    }

    #[test]
    fn test_full_roundtrip_many_fields() {
        let mut encoder = DeltaEncoder::new(DeltaConfig::default());
        let mut decoder = DeltaDecoder::new();

        // Add many fields
        for i in 0..20 {
            encoder.update_field(i, format!("field_{}", i).as_bytes());
        }

        let now = Instant::now();
        if let DeltaRecord::Full { payload, .. } = encoder.poll_record(now) {
            decoder.on_full(&payload).unwrap();
        }

        // Verify all fields
        for i in 0..20 {
            let expected = format!("field_{}", i);
            assert_eq!(decoder.get_field(i), Some(expected.as_bytes()));
        }
    }

    #[test]
    fn test_delta_only_dirty_fields() {
        let mut encoder = DeltaEncoder::new(DeltaConfig::default());
        let mut decoder = DeltaDecoder::new();

        encoder.update_field(0, b"field0");
        encoder.update_field(1, b"field1");
        encoder.update_field(2, b"field2");

        let now = Instant::now();

        // FULL with 3 fields
        if let DeltaRecord::Full { payload, .. } = encoder.poll_record(now) {
            decoder.on_full(&payload).unwrap();
        }

        // Update only field 1
        encoder.update_field(1, b"field1_updated");

        if let DeltaRecord::Delta { payload, .. } = encoder.poll_record(now) {
            // DELTA should be smaller than FULL
            let full_size =
                estimate_full_size(&[(0, b"field0"), (1, b"field1_updated"), (2, b"field2")]);
            assert!(payload.len() < full_size);

            decoder.on_delta(&payload).unwrap();
        }

        // Verify state
        assert_eq!(decoder.get_field(0), Some(b"field0".as_slice()));
        assert_eq!(decoder.get_field(1), Some(b"field1_updated".as_slice()));
        assert_eq!(decoder.get_field(2), Some(b"field2".as_slice()));
    }

    #[test]
    fn test_decode_invalid_full() {
        let mut decoder = DeltaDecoder::new();

        // Empty payload
        assert!(decoder.on_full(&[]).is_err());

        // Truncated payload
        assert!(decoder.on_full(&[0x01]).is_err());

        // Invalid field count
        assert!(decoder.on_full(&[0x01, 0xFF, 0xFF, 0xFF, 0xFF]).is_err());
    }

    #[test]
    fn test_decode_invalid_delta() {
        let mut decoder = DeltaDecoder::new();

        // Need a base FULL first
        let mut encoder = DeltaEncoder::new(DeltaConfig::default());
        encoder.update_field(0, b"data");
        if let DeltaRecord::Full { payload, .. } = encoder.poll_record(Instant::now()) {
            decoder.on_full(&payload).unwrap();
        }

        // Empty delta payload
        assert!(decoder.on_delta(&[]).is_err());

        // Truncated delta payload
        assert!(decoder.on_delta(&[0x01]).is_err());
    }

    #[test]
    fn test_has_valid_state() {
        let mut decoder = DeltaDecoder::new();
        assert!(!decoder.has_valid_state());

        let mut encoder = DeltaEncoder::new(DeltaConfig::default());
        encoder.update_field(0, b"data");
        if let DeltaRecord::Full { payload, .. } = encoder.poll_record(Instant::now()) {
            decoder.on_full(&payload).unwrap();
        }

        assert!(decoder.has_valid_state());
    }

    #[test]
    fn test_get_all_fields() {
        let mut decoder = DeltaDecoder::new();
        let mut encoder = DeltaEncoder::new(DeltaConfig::default());

        encoder.update_field(0, b"a");
        encoder.update_field(1, b"b");

        if let DeltaRecord::Full { payload, .. } = encoder.poll_record(Instant::now()) {
            decoder.on_full(&payload).unwrap();
        }

        let fields = decoder.get_all_fields();
        assert_eq!(fields.len(), 2);
        assert_eq!(fields.get(&0), Some(&b"a".to_vec()));
        assert_eq!(fields.get(&1), Some(&b"b".to_vec()));
    }
