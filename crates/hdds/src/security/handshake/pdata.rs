// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! `c.pdata`, the participant data a handshake request and reply carry
//! (DDS Security v1.1 Sec.9.3.2.5.1, Table 49, and Sec.9.3.2.5.2, Table 50):
//! "The CDR Big Endian Serialization of the ParticipantBuiltinTopicData" of
//! the sender.
//!
//! ParticipantBuiltinTopicData has mutable extensibility and is serialized
//! as a parameter list (Sec.7.4.1.3; DDSI-RTPS Sec.9.6.2.2.2): each member
//! a parameter id, a length and the member, closed by PID_SENTINEL, with no
//! encapsulation header (Cyclone DDS `ddsi_auth_get_serialized_participant_data`
//! and `DDS_Security_Deserialize_ParticipantBuiltinTopicData`, Fast DDS
//! `ParameterList::read_guid_from_cdr_msg`). HDDS serializes the member
//! the handshake reads, its key (PID_PARTICIPANT_GUID), plus the vendor id
//! and capabilities. These properties are covered by the handshake
//! signature. Other members remain omitted.
//!
//! What a peer's `c.pdata` is checked for is its key: Sec.9.3.3, Table 52,
//! `begin_handshake_reply` (`HandshakeMachine::refuses_foreign_pdata`).

use crate::core::discovery::GUID;
use crate::core::rtps_constants::RTPS_ENTITYID_PARTICIPANT;
use crate::protocol::discovery::constants::{PID_HDDS_CAPABILITIES, PID_VENDOR_ID};
use crate::protocol::discovery::constants::{PID_PARTICIPANT_GUID, PID_SENTINEL};
use crate::security::SecurityError;

/// The `c.pdata` of the participant `participant` (its entity id is taken
/// as ENTITYID_PARTICIPANT, whatever it carries): its GUID, vendor id and
/// capabilities, then PID_SENTINEL, big endian.
#[cfg(test)]
pub(crate) fn serialize(participant: &GUID) -> Vec<u8> {
    serialize_with_capabilities(participant, crate::protocol::group::LOCAL_CAPABILITIES)
}

pub(crate) fn serialize_with_capabilities(participant: &GUID, caps: u32) -> Vec<u8> {
    let guid = GUID::new(participant.prefix, RTPS_ENTITYID_PARTICIPANT);
    let mut out = Vec::with_capacity(40);
    out.extend_from_slice(&PID_PARTICIPANT_GUID.to_be_bytes());
    out.extend_from_slice(&16u16.to_be_bytes());
    out.extend_from_slice(&guid.as_bytes());
    out.extend_from_slice(&PID_VENDOR_ID.to_be_bytes());
    out.extend_from_slice(&4u16.to_be_bytes());
    out.extend_from_slice(&crate::core::rtps_constants::HDDS_VENDOR_ID);
    out.extend_from_slice(&[0, 0]);
    out.extend_from_slice(&PID_HDDS_CAPABILITIES.to_be_bytes());
    out.extend_from_slice(&4u16.to_be_bytes());
    out.extend_from_slice(&caps.to_be_bytes());
    out.extend_from_slice(&PID_SENTINEL.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out
}

/// The participant GUID a peer's `c.pdata` carries: its first
/// PID_PARTICIPANT_GUID, read from a parameter list that must end with
/// PID_SENTINEL within the value (as Cyclone DDS requires it to).
pub(crate) fn participant_guid(pdata: &[u8]) -> Result<GUID, SecurityError> {
    let malformed = |why: &str| {
        SecurityError::AuthenticationFailed(format!("c.pdata is no participant data: {}", why))
    };
    let mut guid = None;
    let mut at = 0usize;
    loop {
        let header = pdata
            .get(at..at + 4)
            .ok_or_else(|| malformed("it ends before its PID_SENTINEL"))?;
        let pid = u16::from_be_bytes([header[0], header[1]]);
        let len = usize::from(u16::from_be_bytes([header[2], header[3]]));
        at += 4;
        if pid == PID_SENTINEL {
            break;
        }
        let value = pdata
            .get(at..at + len)
            .ok_or_else(|| malformed("a parameter runs past its end"))?;
        if pid == PID_PARTICIPANT_GUID && guid.is_none() {
            let (Some(prefix), Some(entity_id)) = (value.get(..12), value.get(12..16)) else {
                return Err(malformed("its PID_PARTICIPANT_GUID is shorter than a GUID"));
            };
            let mut p = [0u8; 12];
            p.copy_from_slice(prefix);
            let mut e = [0u8; 4];
            e.copy_from_slice(entity_id);
            guid = Some(GUID::new(p, e));
        }
        // Parameters are 4-octet aligned (DDSI-RTPS Sec.9.4.2.11).
        at += len.next_multiple_of(4);
    }
    guid.ok_or_else(|| malformed("it carries no PID_PARTICIPANT_GUID"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn guid() -> GUID {
        GUID::new(
            [0x81, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
            RTPS_ENTITYID_PARTICIPANT,
        )
    }

    #[test]
    fn the_key_round_trips() {
        assert_eq!(participant_guid(&serialize(&guid())).expect("read"), guid());
    }

    /// A participant data as Cyclone DDS sends it: the whole SPDP parameter
    /// list, the key among other parameters, an odd-length one padded.
    #[test]
    fn the_key_is_found_among_other_parameters() {
        let mut pdata = vec![0x00, 0x15, 0x00, 0x04, 2, 1, 0, 0]; // PID_PROTOCOL_VERSION
        pdata.extend_from_slice(&[0x00, 0x2c, 0x00, 0x03, 0xaa, 0xbb, 0xcc, 0x00]); // user data, len 3
        pdata.extend_from_slice(&serialize(&guid()));
        assert_eq!(participant_guid(&pdata).expect("read"), guid());
    }

    #[test]
    fn a_malformed_participant_data_is_refused() {
        let full = serialize(&guid());
        for (pdata, what) in [
            (Vec::new(), "empty"),
            (full[..full.len() - 4].to_vec(), "no sentinel"),
            (full[..10].to_vec(), "truncated GUID"),
            (vec![0x00, 0x01, 0x00, 0x00], "no GUID"),
            (
                vec![
                    0x00, 0x50, 0x00, 0x08, 1, 2, 3, 4, 5, 6, 7, 8, 0x00, 0x01, 0x00, 0x00,
                ],
                "short GUID",
            ),
        ] {
            assert!(participant_guid(&pdata).is_err(), "{}", what);
        }
    }
}
