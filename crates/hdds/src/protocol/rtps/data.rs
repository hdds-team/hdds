// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! DATA and DATA_FRAG submessage encoders (RTPS 2.3 Section 8.3.7.2-3)
//!
//! DATA contains serialized application data.
//! DATA_FRAG contains a fragment of a large data sample.

use super::RtpsEncodeResult;

/// Encode a DATA submessage per RTPS 2.3 specification.
///
/// # Arguments
///
/// * `reader_id` - EntityId of the target Reader (can be ENTITYID_UNKNOWN)
/// * `writer_id` - EntityId of the Writer sending the data
/// * `sequence_number` - Sequence number of this sample
/// * `payload` - Serialized data payload
///
/// # Returns
///
/// Encoded DATA submessage bytes.
pub fn encode_data(
    reader_id: &[u8; 4],
    writer_id: &[u8; 4],
    sequence_number: u64,
    payload: &[u8],
) -> RtpsEncodeResult<Vec<u8>> {
    // Fixed header fields: extraFlags(2) + octetsToInlineQos(2) + entityIds(8) + seqNum(8) = 20
    let submsg_len = 20 + payload.len();
    let mut buf = vec![0u8; 4 + submsg_len];

    // Submessage header
    buf[0] = 0x15; // DATA
    buf[1] = 0x05; // Flags: LE + Data present (no inline QoS)
    buf[2..4].copy_from_slice(&(submsg_len as u16).to_le_bytes());

    let mut offset = 4;

    // Extra flags + octetsToInlineQos (no inline QoS = 16 bytes to skip)
    buf[offset..offset + 2].copy_from_slice(&0u16.to_le_bytes()); // extraFlags
    buf[offset + 2..offset + 4].copy_from_slice(&16u16.to_le_bytes()); // octetsToInlineQos
    offset += 4;

    // Reader EntityId
    buf[offset..offset + 4].copy_from_slice(reader_id);
    offset += 4;

    // Writer EntityId
    buf[offset..offset + 4].copy_from_slice(writer_id);
    offset += 4;

    // Sequence number (SequenceNumber_t = high:i32 + low:u32)
    let sn_high = (sequence_number >> 32) as i32;
    let sn_low = sequence_number as u32;
    buf[offset..offset + 4].copy_from_slice(&sn_high.to_le_bytes());
    offset += 4;
    buf[offset..offset + 4].copy_from_slice(&sn_low.to_le_bytes());
    offset += 4;

    // Payload (serialized data)
    buf[offset..offset + payload.len()].copy_from_slice(payload);

    Ok(buf)
}

/// Encode a DATA_FRAG submessage per RTPS 2.3 specification.
///
/// # Arguments
///
/// * `reader_id` - EntityId of the target Reader
/// * `writer_id` - EntityId of the Writer sending the fragment
/// * `sequence_number` - Sequence number of the complete sample
/// * `fragment_starting_num` - Starting fragment number (1-based)
/// * `fragments_in_submessage` - Number of fragments in this submessage
/// * `data_size` - Total size of the complete sample
/// * `fragment_size` - Size of each fragment
/// * `payload` - Fragment payload
///
/// # Returns
///
/// Encoded DATA_FRAG submessage bytes.
#[allow(clippy::too_many_arguments)] // RTPS DATA_FRAG fields per spec
pub fn encode_data_frag(
    reader_id: &[u8; 4],
    writer_id: &[u8; 4],
    sequence_number: u64,
    fragment_starting_num: u32,
    fragments_in_submessage: u16,
    data_size: u32,
    fragment_size: u16,
    payload: &[u8],
) -> RtpsEncodeResult<Vec<u8>> {
    // Header fields: extraFlags(2) + octetsToInlineQos(2) + entityIds(8) + seqNum(8)
    //              + fragStartNum(4) + fragsInSubmsg(2) + fragSize(2) + sampleSize(4) = 32
    let submsg_len = 32 + payload.len();
    let mut buf = vec![0u8; 4 + submsg_len];

    // Submessage header
    buf[0] = 0x16; // DATA_FRAG
    buf[1] = 0x05; // Flags: LE + Data present
    buf[2..4].copy_from_slice(&(submsg_len as u16).to_le_bytes());

    let mut offset = 4;

    // Extra flags + octetsToInlineQos
    buf[offset..offset + 2].copy_from_slice(&0u16.to_le_bytes());
    buf[offset + 2..offset + 4].copy_from_slice(&16u16.to_le_bytes());
    offset += 4;

    // Reader/Writer EntityIds
    buf[offset..offset + 4].copy_from_slice(reader_id);
    offset += 4;
    buf[offset..offset + 4].copy_from_slice(writer_id);
    offset += 4;

    // Sequence number
    let sn_high = (sequence_number >> 32) as i32;
    let sn_low = sequence_number as u32;
    buf[offset..offset + 4].copy_from_slice(&sn_high.to_le_bytes());
    offset += 4;
    buf[offset..offset + 4].copy_from_slice(&sn_low.to_le_bytes());
    offset += 4;

    // Fragment starting number
    buf[offset..offset + 4].copy_from_slice(&fragment_starting_num.to_le_bytes());
    offset += 4;

    // Fragments in submessage
    buf[offset..offset + 2].copy_from_slice(&fragments_in_submessage.to_le_bytes());
    offset += 2;

    // Fragment size
    buf[offset..offset + 2].copy_from_slice(&fragment_size.to_le_bytes());
    offset += 2;

    // Sample size (total data size)
    buf[offset..offset + 4].copy_from_slice(&data_size.to_le_bytes());
    offset += 4;

    // Fragment payload
    buf[offset..offset + payload.len()].copy_from_slice(payload);

    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_data_encoding() {
        let reader_id = [0x00, 0x00, 0x00, 0x00];
        let writer_id = [0x00, 0x01, 0x02, 0x02];
        let payload = b"Hello, DDS!";

        let result = encode_data(&reader_id, &writer_id, 1, payload);
        assert!(result.is_ok());

        let buf = result.unwrap();
        assert_eq!(buf[0], 0x15); // DATA
        assert_eq!(buf[1], 0x05); // Flags
    }

    #[test]
    fn test_data_frag_encoding() {
        let reader_id = [0x00, 0x00, 0x00, 0x00];
        let writer_id = [0x00, 0x01, 0x02, 0x02];
        let payload = vec![0u8; 1300];

        let result = encode_data_frag(
            &reader_id, &writer_id, 1,    // sequence_number
            1,    // fragment_starting_num
            1,    // fragments_in_submessage
            5000, // data_size
            1300, // fragment_size
            &payload,
        );
        assert!(result.is_ok());

        let buf = result.unwrap();
        assert_eq!(buf[0], 0x16); // DATA_FRAG
    }
}
