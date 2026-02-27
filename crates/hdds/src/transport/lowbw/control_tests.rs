// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

    use super::*;

    #[test]
    fn test_hello_roundtrip() {
        let hello = Hello {
            proto_ver: 1,
            features: features::DELTA | features::COMPRESSION,
            mtu: 512,
            node_id: 42,
            session_id: 1000,
            map_epoch: 5,
        };

        let mut buf = [0u8; 64];
        let encoded_len = hello.encode(&mut buf).expect("encode");

        // Verify ctrl_type
        assert_eq!(buf[0], ctrl_type::HELLO);

        // Decode
        let (decoded, decoded_len) = Hello::decode(&buf[1..encoded_len]).expect("decode");
        assert_eq!(decoded_len + 1, encoded_len);
        assert_eq!(decoded, hello);
    }

    #[test]
    fn test_map_add_roundtrip() {
        let map_add = MapAdd {
            epoch: 1,
            stream_id: 5,
            topic_hash: 0x123456789ABCDEF0,
            type_hash: 0xFEDCBA9876543210,
            stream_flags: stream_flags::RELIABLE | stream_flags::DELTA_ENABLED,
        };

        let mut buf = [0u8; 64];
        let encoded_len = map_add.encode(&mut buf).expect("encode");

        assert_eq!(buf[0], ctrl_type::MAP_ADD);

        let (decoded, decoded_len) = MapAdd::decode(&buf[1..encoded_len]).expect("decode");
        assert_eq!(decoded_len + 1, encoded_len);
        assert_eq!(decoded, map_add);
    }

    #[test]
    fn test_map_ack_roundtrip() {
        let map_ack = MapAck {
            epoch: 100,
            stream_id: 10,
        };

        let mut buf = [0u8; 64];
        let encoded_len = map_ack.encode(&mut buf).expect("encode");

        let (decoded, decoded_len) = MapAck::decode(&buf[1..encoded_len]).expect("decode");
        assert_eq!(decoded_len + 1, encoded_len);
        assert_eq!(decoded, map_ack);
    }

    #[test]
    fn test_ack_roundtrip() {
        let ack = Ack {
            stream_id: 5,
            last_seq: 12345,
            bitmask: 0,
        };

        let mut buf = [0u8; 64];
        let encoded_len = ack.encode(&mut buf).expect("encode");

        let (decoded, decoded_len) = Ack::decode(&buf[1..encoded_len]).expect("decode");
        assert_eq!(decoded_len + 1, encoded_len);
        assert_eq!(decoded, ack);
    }

    #[test]
    fn test_state_ack_roundtrip() {
        let state_ack = StateAck {
            stream_id: 3,
            last_full_seq: 999,
        };

        let mut buf = [0u8; 64];
        let encoded_len = state_ack.encode(&mut buf).expect("encode");

        let (decoded, decoded_len) = StateAck::decode(&buf[1..encoded_len]).expect("decode");
        assert_eq!(decoded_len + 1, encoded_len);
        assert_eq!(decoded, state_ack);
    }

    #[test]
    fn test_keyframe_req_roundtrip() {
        let req = KeyframeReq { stream_id: 7 };

        let mut buf = [0u8; 64];
        let encoded_len = req.encode(&mut buf).expect("encode");

        let (decoded, decoded_len) = KeyframeReq::decode(&buf[1..encoded_len]).expect("decode");
        assert_eq!(decoded_len + 1, encoded_len);
        assert_eq!(decoded, req);
    }

    #[test]
    fn test_control_message_unified() {
        let messages: Vec<ControlMessage> = vec![
            ControlMessage::Hello(Hello::default()),
            ControlMessage::MapAdd(MapAdd {
                epoch: 1,
                stream_id: 1,
                topic_hash: 123,
                type_hash: 456,
                stream_flags: 0,
            }),
            ControlMessage::MapAck(MapAck {
                epoch: 1,
                stream_id: 1,
            }),
            ControlMessage::MapReq(MapReq {
                epoch: 1,
                stream_id: 1,
            }),
            ControlMessage::Ack(Ack::new(1, 100)),
            ControlMessage::StateAck(StateAck {
                stream_id: 1,
                last_full_seq: 50,
            }),
            ControlMessage::KeyframeReq(KeyframeReq { stream_id: 1 }),
        ];

        for msg in messages {
            let mut buf = [0u8; 64];
            let encoded_len = msg.encode(&mut buf).expect("encode");

            let (decoded, decoded_len) =
                ControlMessage::decode(&buf[..encoded_len]).expect("decode");
            assert_eq!(decoded_len, encoded_len);
            assert_eq!(decoded, msg);
        }
    }

    #[test]
    fn test_unknown_ctrl_type() {
        let buf = [0xFF, 0x00, 0x00];
        assert_eq!(
            ControlMessage::decode(&buf),
            Err(ControlError::UnknownType(0xFF))
        );
    }

    #[test]
    fn test_stream_flags_priority() {
        use super::super::record::Priority;

        let flags = stream_flags::set_priority(0, Priority::P0);
        assert_eq!(stream_flags::get_priority(flags), Priority::P0);

        let flags = stream_flags::set_priority(stream_flags::RELIABLE, Priority::P2);
        assert_eq!(stream_flags::get_priority(flags), Priority::P2);
        assert_eq!(flags & stream_flags::RELIABLE, stream_flags::RELIABLE);
    }

    #[test]
    fn test_buffer_too_small() {
        let hello = Hello::default();
        let mut buf = [0u8; 2]; // Too small
        assert_eq!(hello.encode(&mut buf), Err(ControlError::BufferTooSmall));
    }

    #[test]
    fn test_truncated_decode() {
        // Empty buffer
        assert_eq!(ControlMessage::decode(&[]), Err(ControlError::Truncated));

        // Just ctrl_type, no payload
        assert_eq!(
            ControlMessage::decode(&[ctrl_type::HELLO]),
            Err(ControlError::Truncated)
        );
    }
