// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Hybrid SEDP encoder - conservative fallback
//!
//! Uses all standard PIDs in spec-compliant order.
//! No vendor-specific PIDs, no TypeObject.
//! Should work with any RTPS 2.3+ implementation.
//!

mod locators;
mod metadata;
mod qos;

use crate::protocol::dialect::error::{EncodeError, EncodeResult};
use crate::protocol::dialect::SedpEndpointData;

/// Build Hybrid SEDP parameter list
///
/// Standard PID ordering (no vendor-specific):
/// 1. PID_ENDPOINT_GUID
/// 2. PID_PARTICIPANT_GUID
/// 3. PID_TOPIC_NAME
/// 4. PID_TYPE_NAME
/// 5. PID_UNICAST_LOCATOR (for each)
/// 6. QoS policies (reliability, durability, etc.)
/// 7. PID_SENTINEL
#[allow(dead_code)] // Part of dialect API, used when hybrid dialect is selected
                    // @audit-ok: Sequential builder (cyclo 14, cogni 2) - linear write_xxx calls without complex branching
pub fn build_sedp(data: &SedpEndpointData) -> EncodeResult<Vec<u8>> {
    let mut buf = vec![0u8; 1024];
    #[allow(unused_assignments)] // Initial value needed for clarity, immediately overwritten
    let mut offset = 0;

    // CDR encapsulation header (PL_CDR_LE)
    if buf.len() < 4 {
        return Err(EncodeError::BufferTooSmall);
    }
    buf[0..4].copy_from_slice(&[0x00, 0x03, 0x00, 0x00]);
    offset = 4;

    // 1. Metadata PIDs (standard order)
    metadata::write_endpoint_guid(&data.endpoint_guid, &mut buf, &mut offset)?;
    metadata::write_participant_guid(&data.participant_guid, &mut buf, &mut offset)?;
    metadata::write_topic_name(data.topic_name, &mut buf, &mut offset)?;
    metadata::write_type_name(data.type_name, &mut buf, &mut offset)?;

    // 2. Locators
    for locator in data.unicast_locators {
        locators::write_unicast_locator(locator, &mut buf, &mut offset)?;
    }

    // 3. QoS policies (full set for compatibility)
    qos::write_reliability(data.qos, &mut buf, &mut offset)?;
    qos::write_durability(data.qos, &mut buf, &mut offset)?;
    qos::write_history(data.qos, &mut buf, &mut offset)?;
    qos::write_deadline(&mut buf, &mut offset)?;
    qos::write_ownership(&mut buf, &mut offset)?;
    qos::write_liveliness(&mut buf, &mut offset)?;

    // 4. PID_SENTINEL (0x0001)
    buf[offset..offset + 4].copy_from_slice(&[0x01, 0x00, 0x00, 0x00]);
    offset += 4;

    buf.truncate(offset);
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::dialect::Guid;
    use std::net::SocketAddr;

    #[test]
    fn test_build_sedp_hybrid() {
        let locators = vec!["192.168.1.1:7411"
            .parse::<SocketAddr>()
            .expect("valid addr")];

        let data = SedpEndpointData {
            endpoint_guid: Guid {
                prefix: [0x01; 12],
                entity_id: [0x00, 0x00, 0x01, 0x02],
            },
            participant_guid: Guid {
                prefix: [0x01; 12],
                entity_id: [0x00, 0x00, 0x01, 0xc1],
            },
            topic_name: "TestTopic",
            type_name: "TestType",
            unicast_locators: &locators,
            multicast_locators: &[],
            qos: None,
            type_object: None,
        };

        let result = build_sedp(&data);
        assert!(result.is_ok());

        let buf = result.expect("build_sedp should succeed");

        // Verify PL_CDR_LE header
        assert_eq!(&buf[0..4], &[0x00, 0x03, 0x00, 0x00]);

        // Verify ends with sentinel
        let len = buf.len();
        assert_eq!(&buf[len - 4..], &[0x01, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_hybrid_has_all_standard_qos() {
        let data = SedpEndpointData {
            endpoint_guid: Guid {
                prefix: [0x02; 12],
                entity_id: [0x00, 0x00, 0x02, 0x02],
            },
            participant_guid: Guid {
                prefix: [0x02; 12],
                entity_id: [0x00, 0x00, 0x01, 0xc1],
            },
            topic_name: "QosTopic",
            type_name: "QosType",
            unicast_locators: &[],
            multicast_locators: &[],
            qos: None,
            type_object: None,
        };

        let buf = build_sedp(&data).expect("build_sedp should succeed");

        // Check for standard QoS PIDs
        let has_reliability = buf.windows(2).any(|w| w == [0x1a, 0x00]);
        let has_durability = buf.windows(2).any(|w| w == [0x1d, 0x00]);
        let has_history = buf.windows(2).any(|w| w == [0x40, 0x00]);
        let has_deadline = buf.windows(2).any(|w| w == [0x23, 0x00]);
        let has_ownership = buf.windows(2).any(|w| w == [0x1f, 0x00]);
        let has_liveliness = buf.windows(2).any(|w| w == [0x1b, 0x00]);

        assert!(has_reliability, "Missing PID_RELIABILITY");
        assert!(has_durability, "Missing PID_DURABILITY");
        assert!(has_history, "Missing PID_HISTORY");
        assert!(has_deadline, "Missing PID_DEADLINE");
        assert!(has_ownership, "Missing PID_OWNERSHIP");
        assert!(has_liveliness, "Missing PID_LIVELINESS");
    }
}
