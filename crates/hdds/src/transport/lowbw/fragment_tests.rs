// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

    use super::*;

    // ========================================================================
    // FragHeader Tests
    // ========================================================================

    #[test]
    fn test_frag_header_encode_decode() {
        let header = FragHeader::new(12345, 2, 5, 1000, 200);

        let mut buf = [0u8; 32];
        let encoded_len = header.encode(&mut buf).unwrap();

        let (decoded, consumed) = FragHeader::decode(&buf).unwrap();

        assert_eq!(encoded_len, consumed);
        assert_eq!(decoded, header);
    }

    #[test]
    fn test_frag_header_invalid_idx() {
        // frag_idx >= frag_cnt is invalid
        let mut buf = [0u8; 32];
        let mut offset = 0;
        offset += encode_varint(100, &mut buf[offset..]); // group_id
        offset += encode_varint(5, &mut buf[offset..]); // frag_idx = 5
        offset += encode_varint(5, &mut buf[offset..]); // frag_cnt = 5
        offset += encode_varint(1000, &mut buf[offset..]); // orig_len
        let _ = encode_varint(100, &mut buf[offset..]); // frag_len

        let result = FragHeader::decode(&buf);
        assert!(matches!(result, Err(FragError::InvalidHeader)));
    }

    // ========================================================================
    // Fragmenter Tests
    // ========================================================================

    #[test]
    fn test_fragmenter_no_fragmentation_needed() {
        let fragmenter = Fragmenter::new(256, 20);

        let payload = vec![1u8; 100];
        assert!(!fragmenter.needs_fragmentation(payload.len()));

        let fragments = fragmenter.fragment(&payload, 1).unwrap();
        assert_eq!(fragments.len(), 1);
        assert_eq!(fragments[0].data, payload);
    }

    #[test]
    fn test_fragmenter_basic() {
        let fragmenter = Fragmenter::new(100, 20); // ~68 byte max payload

        let payload = vec![0xABu8; 200];
        assert!(fragmenter.needs_fragmentation(payload.len()));

        let fragments = fragmenter.fragment(&payload, 42).unwrap();

        assert!(fragments.len() >= 3);

        // All fragments should have same group_id and frag_cnt
        for frag in &fragments {
            assert_eq!(frag.header.group_id, 42);
            // Test uses small controlled buffers, but clamp defensively
            assert_eq!(frag.header.frag_cnt, fragments.len().min(u16::MAX as usize) as u16);
            assert_eq!(frag.header.orig_len, 200);
        }

        // Total data should equal original
        let total_data: usize = fragments.iter().map(|f| f.data.len()).sum();
        assert_eq!(total_data, 200);
    }

    #[test]
    fn test_fragmenter_empty_payload() {
        let fragmenter = Fragmenter::new(256, 20);

        let fragments = fragmenter.fragment(&[], 1).unwrap();
        assert_eq!(fragments.len(), 1);
        assert_eq!(fragments[0].header.orig_len, 0);
        assert!(fragments[0].data.is_empty());
    }

    #[test]
    fn test_fragmenter_exact_fit() {
        let fragmenter = Fragmenter::new(100, 20);
        let max_payload = fragmenter.max_payload();

        let payload = vec![0xCDu8; max_payload];
        let fragments = fragmenter.fragment(&payload, 1).unwrap();

        assert_eq!(fragments.len(), 1);
    }

    // ========================================================================
    // Reassembler Tests
    // ========================================================================

    #[test]
    fn test_reassembler_single_fragment() {
        let mut reassembler = Reassembler::new(ReassemblerConfig::default());

        let data = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let header = FragHeader::new(1, 0, 1, 10, data.len().min(u16::MAX as usize) as u16);

        let result = reassembler.on_fragment(1, &header, data.clone()).unwrap();

        assert!(result.is_some());
        assert_eq!(result.unwrap(), data);
    }

    #[test]
    fn test_reassembler_multiple_fragments() {
        let mut reassembler = Reassembler::new(ReassemblerConfig::default());

        let orig = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];

        // Fragment 0
        let d0 = vec![1, 2, 3, 4, 5];
        let h0 = FragHeader::new(1, 0, 2, 10, d0.len().min(u16::MAX as usize) as u16);
        let r0 = reassembler.on_fragment(1, &h0, d0).unwrap();
        assert!(r0.is_none()); // Not complete yet

        // Fragment 1
        let d1 = vec![6, 7, 8, 9, 10];
        let h1 = FragHeader::new(1, 1, 2, 10, d1.len().min(u16::MAX as usize) as u16);
        let r1 = reassembler.on_fragment(1, &h1, d1).unwrap();

        assert!(r1.is_some());
        assert_eq!(r1.unwrap(), orig);
    }

    #[test]
    fn test_reassembler_out_of_order() {
        let mut reassembler = Reassembler::new(ReassemblerConfig::default());

        let orig = vec![1, 2, 3, 4, 5, 6, 7, 8, 9];

        // Send fragment 2 first
        let d2 = vec![7, 8, 9];
        let h2 = FragHeader::new(1, 2, 3, 9, d2.len().min(u16::MAX as usize) as u16);
        assert!(reassembler.on_fragment(1, &h2, d2).unwrap().is_none());

        // Then fragment 0
        let d0 = vec![1, 2, 3];
        let h0 = FragHeader::new(1, 0, 3, 9, d0.len().min(u16::MAX as usize) as u16);
        assert!(reassembler.on_fragment(1, &h0, d0).unwrap().is_none());

        // Finally fragment 1
        let d1 = vec![4, 5, 6];
        let h1 = FragHeader::new(1, 1, 3, 9, d1.len().min(u16::MAX as usize) as u16);
        let result = reassembler.on_fragment(1, &h1, d1).unwrap();

        assert!(result.is_some());
        assert_eq!(result.unwrap(), orig);
    }

    #[test]
    fn test_reassembler_duplicate() {
        let mut reassembler = Reassembler::new(ReassemblerConfig::default());

        let d0 = vec![1, 2, 3, 4, 5];
        let h0 = FragHeader::new(1, 0, 2, 10, d0.len().min(u16::MAX as usize) as u16);

        // First fragment
        reassembler.on_fragment(1, &h0, d0.clone()).unwrap();

        // Duplicate
        let result = reassembler.on_fragment(1, &h0, d0).unwrap();
        assert!(result.is_none());
        assert_eq!(reassembler.stats().duplicates_dropped, 1);
    }

    #[test]
    fn test_reassembler_timeout() {
        let config = ReassemblerConfig {
            timeout: Duration::from_millis(10),
            ..Default::default()
        };
        let mut reassembler = Reassembler::new(config);

        let d0 = vec![1, 2, 3, 4, 5];
        let h0 = FragHeader::new(1, 0, 2, 10, d0.len().min(u16::MAX as usize) as u16);
        reassembler.on_fragment(1, &h0, d0).unwrap();

        assert_eq!(reassembler.pending_count(), 1);

        // Wait for timeout
        std::thread::sleep(Duration::from_millis(15));
        reassembler.tick();

        assert_eq!(reassembler.pending_count(), 0);
        assert_eq!(reassembler.stats().groups_timed_out, 1);
    }

    #[test]
    fn test_reassembler_max_groups() {
        let config = ReassemblerConfig {
            max_groups: 2,
            ..Default::default()
        };
        let mut reassembler = Reassembler::new(config);

        // Add 3 incomplete groups
        for group_id in 0..3 {
            let d = vec![1, 2, 3, 4, 5];
            let h = FragHeader::new(group_id, 0, 2, 10, d.len().min(u16::MAX as usize) as u16);
            reassembler.on_fragment(1, &h, d).unwrap();
        }

        // Should have evicted oldest, keeping only 2
        assert_eq!(reassembler.pending_count(), 2);
        assert_eq!(reassembler.stats().groups_dropped, 1);
    }

    #[test]
    fn test_reassembler_separate_streams() {
        let mut reassembler = Reassembler::new(ReassemblerConfig::default());

        // Stream 1, group 1
        let d1 = vec![1, 2, 3, 4, 5];
        let h1 = FragHeader::new(1, 0, 1, 5, d1.len().min(u16::MAX as usize) as u16);

        // Stream 2, group 1 (same group_id, different stream)
        let d2 = vec![6, 7, 8];
        let h2 = FragHeader::new(1, 0, 1, 3, d2.len().min(u16::MAX as usize) as u16);

        let r1 = reassembler.on_fragment(1, &h1, d1.clone()).unwrap();
        let r2 = reassembler.on_fragment(2, &h2, d2.clone()).unwrap();

        assert_eq!(r1.unwrap(), d1);
        assert_eq!(r2.unwrap(), d2);
    }

    // ========================================================================
    // Integration Tests
    // ========================================================================

    #[test]
    fn test_fragment_reassemble_roundtrip() {
        let fragmenter = Fragmenter::new(50, 20);
        let mut reassembler = Reassembler::new(ReassemblerConfig::default());

        let original = (0u8..=255).collect::<Vec<u8>>();

        // Fragment
        let fragments = fragmenter.fragment(&original, 42).unwrap();
        assert!(fragments.len() > 1);

        // Reassemble
        let mut result = None;
        for frag in fragments {
            result = reassembler.on_fragment(1, &frag.header, frag.data).unwrap();
        }

        assert!(result.is_some());
        assert_eq!(result.unwrap(), original);
    }

    #[test]
    fn test_fragment_encode_decode_roundtrip() {
        let frag = Fragment {
            header: FragHeader::new(100, 2, 5, 500, 4), // frag_len = 4 bytes
            data: vec![0xDE, 0xAD, 0xBE, 0xEF],
        };

        let mut buf = [0u8; 64];
        let encoded_len = frag.encode(&mut buf).unwrap();

        let (decoded, consumed) = Fragment::decode(&buf[..encoded_len]).unwrap();

        assert_eq!(consumed, encoded_len);
        assert_eq!(decoded.header, frag.header);
        assert_eq!(decoded.data, frag.data);
    }

    #[test]
    fn test_calculate_fragment_size() {
        // 10 bytes split into 3 fragments: 4, 3, 3
        assert_eq!(calculate_fragment_size(10, 3, 0), 4);
        assert_eq!(calculate_fragment_size(10, 3, 1), 3);
        assert_eq!(calculate_fragment_size(10, 3, 2), 3);

        // 9 bytes split into 3 fragments: 3, 3, 3
        assert_eq!(calculate_fragment_size(9, 3, 0), 3);
        assert_eq!(calculate_fragment_size(9, 3, 1), 3);
        assert_eq!(calculate_fragment_size(9, 3, 2), 3);
    }

    #[test]
    fn test_calculate_fragment_offset() {
        // 10 bytes split into 3 fragments: 4, 3, 3
        assert_eq!(calculate_fragment_offset(10, 3, 0), 0);
        assert_eq!(calculate_fragment_offset(10, 3, 1), 4);
        assert_eq!(calculate_fragment_offset(10, 3, 2), 7);
    }
