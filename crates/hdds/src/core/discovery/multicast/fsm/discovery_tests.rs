// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

    use super::*;
    use crate::core::discovery::GUID;
    use crate::protocol::discovery::{SedpData, SpdpData};
    use std::convert::TryFrom;

    fn sample_remote_guid(byte: u8) -> GUID {
        let mut data = [0u8; 16];
        for (idx, slot) in data.iter_mut().enumerate() {
            let offset = u8::try_from(idx).unwrap_or(0);
            *slot = byte.wrapping_add(offset);
        }
        GUID::from_bytes(data)
    }

    #[test]
    fn test_fsm_new() {
        let local_guid = sample_remote_guid(1);
        let fsm = DiscoveryFsm::new(local_guid, 100_000);

        assert_eq!(fsm.local_guid, local_guid);
        assert_eq!(fsm.lease_duration_ms, 100_000);
        assert!(fsm.get_participants().is_empty());
    }

    #[test]
    fn test_handle_spdp_new_participant() {
        let local_guid = GUID::zero();
        let fsm = DiscoveryFsm::new(local_guid, 100_000);

        let remote_guid = sample_remote_guid(2);
        let spdp_data = SpdpData {
            participant_guid: remote_guid,
            lease_duration_ms: 100_000,
            domain_id: 0,
            metatraffic_unicast_locators: vec!["127.0.0.1:7400"
                .parse()
                .expect("Socket address parsing should succeed")],
            default_unicast_locators: vec![],
            default_multicast_locators: vec![],
            metatraffic_multicast_locators: vec![],
            identity_token: None,
        };

        fsm.handle_spdp(spdp_data);

        let participants = fsm.get_participants();
        assert_eq!(participants.len(), 1);
        assert_eq!(participants[0].guid, remote_guid);
        assert_eq!(participants[0].endpoints.len(), 1);
    }

    #[test]
    fn test_handle_spdp_duplicate_refresh() {
        let local_guid = GUID::zero();
        let fsm = DiscoveryFsm::new(local_guid, 100_000);

        let remote_guid = sample_remote_guid(3);
        let spdp_data = SpdpData {
            participant_guid: remote_guid,
            lease_duration_ms: 100_000,
            domain_id: 0,
            metatraffic_unicast_locators: vec![],
            default_unicast_locators: vec![],
            default_multicast_locators: vec![],
            metatraffic_multicast_locators: vec![],
            identity_token: None,
        };

        fsm.handle_spdp(spdp_data.clone());
        let first_seen = {
            let db = fsm.db.read().expect("RwLock read should succeed");
            db.get(&remote_guid)
                .expect("Participant should exist")
                .last_seen
        };

        std::thread::sleep(std::time::Duration::from_millis(5));

        fsm.handle_spdp(spdp_data);
        let second_seen = {
            let db = fsm.db.read().expect("RwLock read should succeed");
            db.get(&remote_guid)
                .expect("Participant should exist")
                .last_seen
        };

        assert!(second_seen > first_seen);
        assert_eq!(fsm.get_participants().len(), 1);
    }

    #[test]
    fn test_handle_spdp_ignore_self() {
        let local_guid = sample_remote_guid(4);
        let fsm = DiscoveryFsm::new(local_guid, 100_000);

        let spdp_data = SpdpData {
            participant_guid: local_guid,
            lease_duration_ms: 100_000,
            domain_id: 0,
            metatraffic_unicast_locators: vec![],
            default_unicast_locators: vec![],
            default_multicast_locators: vec![],
            metatraffic_multicast_locators: vec![],
            identity_token: None,
        };

        fsm.handle_spdp(spdp_data);
        assert!(fsm.get_participants().is_empty());
    }

    #[test]
    fn test_remove_participant() {
        let local_guid = GUID::zero();
        let fsm = DiscoveryFsm::new(local_guid, 100_000);

        let remote_guid = sample_remote_guid(5);
        let spdp_data = SpdpData {
            participant_guid: remote_guid,
            lease_duration_ms: 100_000,
            domain_id: 0,
            metatraffic_unicast_locators: vec![],
            default_unicast_locators: vec![],
            default_multicast_locators: vec![],
            metatraffic_multicast_locators: vec![],
            identity_token: None,
        };

        fsm.handle_spdp(spdp_data);
        assert_eq!(fsm.get_participants().len(), 1);

        fsm.remove_participant(remote_guid);
        assert!(fsm.get_participants().is_empty());
    }

    #[test]
    fn test_handle_sedp_ignores_unknown_participant() {
        let local_guid = GUID::zero();
        let fsm = DiscoveryFsm::new(local_guid, 100_000);

        let sedp_data = SedpData {
            topic_name: "sensor/temp".to_string(),
            type_name: "Temperature".to_string(),
            participant_guid: GUID::zero(), // Test data
            endpoint_guid: sample_remote_guid(6),
            qos_hash: 12345,
            qos: None, // Tests use default QoS values
            type_object: None,
            unicast_locators: vec![],
            user_data: None,
        };

        fsm.handle_sedp(sedp_data);
        assert!(fsm.find_writers_for_topic("sensor/temp").is_empty());
    }

    #[test]
    fn test_handle_sedp_inserts_endpoint() {
        let local_guid = GUID::zero();
        let fsm = DiscoveryFsm::new(local_guid, 100_000);

        let remote_guid = sample_remote_guid(7);
        let spdp_data = SpdpData {
            participant_guid: remote_guid,
            lease_duration_ms: 100_000,
            domain_id: 0,
            metatraffic_unicast_locators: vec![],
            default_unicast_locators: vec![],
            default_multicast_locators: vec![],
            metatraffic_multicast_locators: vec![],
            identity_token: None,
        };
        fsm.handle_spdp(spdp_data);

        let mut endpoint_guid_bytes = remote_guid.as_bytes();
        endpoint_guid_bytes[15] = 0x02; // writer
        let sedp_data = SedpData {
            topic_name: "sensor/temp".to_string(),
            type_name: "Temperature".to_string(),
            participant_guid: GUID::zero(), // Test data
            endpoint_guid: GUID::from_bytes(endpoint_guid_bytes),
            qos_hash: 123,
            qos: None, // Tests use default QoS values
            type_object: None,
            unicast_locators: vec![],
            user_data: None,
        };

        fsm.handle_sedp(sedp_data);

        let writers = fsm.find_writers_for_topic("sensor/temp");
        assert_eq!(writers.len(), 1);
        assert_eq!(writers[0].type_name, "Temperature");
    }

    #[test]
    fn test_metrics_snapshot() {
        let local_guid = GUID::zero();
        let fsm = DiscoveryFsm::new(local_guid, 100_000);

        let remote_guid = sample_remote_guid(8);
        let spdp_data = SpdpData {
            participant_guid: remote_guid,
            lease_duration_ms: 100_000,
            domain_id: 0,
            metatraffic_unicast_locators: vec![],
            default_unicast_locators: vec![],
            default_multicast_locators: vec![],
            metatraffic_multicast_locators: vec![],
            identity_token: None,
        };
        fsm.handle_spdp(spdp_data.clone());
        fsm.handle_spdp(spdp_data);

        let (spdp_rx, sedp_rx, discovered, expired, errors) = fsm.metrics.snapshot();
        assert_eq!(spdp_rx, 2);
        assert_eq!(sedp_rx, 0);
        assert_eq!(discovered, 1);
        assert_eq!(expired, 0);
        assert_eq!(errors, 0);
    }
