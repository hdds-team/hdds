// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

use super::constants::{
    CDR_BE, CDR_BE_VENDOR, CDR_LE, CDR_LE_VENDOR, PID_SENTINEL, PID_TOPIC_NAME,
};

/// Extract the topic name from a serialized SEDP DATA parameter list.
///
/// # Arguments
/// - `buf`: RTPS payload positioned at the DATA submessage.
///
/// # Returns
/// The topic name when present and valid UTF-8.
/// Returns `None` when the PID is missing, the encapsulation is invalid, or the payload is truncated.
///
/// # Encapsulation support
/// Accepts the four XCDR1 PL_CDR variants used on the wire for SEDP:
///   - `CDR_LE`        (0x0003) -- standard little-endian
///   - `CDR_BE`        (0x0002) -- PL_CDR_BE big-endian (DDSI-RTPS 2.5 Sec.10.3)
///   - `CDR_LE_VENDOR` (0x8001) -- Fast DDS vendor-flagged little-endian
///   - `CDR_BE_VENDOR` (0x8002) -- Fast DDS vendor-flagged big-endian
///
/// XCDR2 PL_CDR2 (0x000A/0x000B) is intentionally NOT handled here: it uses
/// a DHEADER + EMHEADER framing that this lightweight fallback parser does
/// not implement. Callers receiving an XCDR2 payload should rely on the
/// full `protocol::discovery::parse_sedp` path instead, which decodes the
/// `PL_CDR2` member layout.
pub fn parse_topic_name(buf: &[u8]) -> Option<String> {
    if buf.len() < 12 {
        return None;
    }

    // The encapsulation identifier itself is always written as two big-endian
    // bytes per RTPS sec. 10.2; the LE/BE flag governs only the body that follows.
    let encapsulation = u16::from_be_bytes([buf[0], buf[1]]);
    let is_little_endian = match encapsulation {
        CDR_LE | CDR_LE_VENDOR => true,
        CDR_BE | CDR_BE_VENDOR => false,
        _ => return None,
    };

    let read_u16 = |o: usize| -> u16 {
        if is_little_endian {
            u16::from_le_bytes([buf[o], buf[o + 1]])
        } else {
            u16::from_be_bytes([buf[o], buf[o + 1]])
        }
    };
    let read_u32 = |o: usize| -> u32 {
        if is_little_endian {
            u32::from_le_bytes([buf[o], buf[o + 1], buf[o + 2], buf[o + 3]])
        } else {
            u32::from_be_bytes([buf[o], buf[o + 1], buf[o + 2], buf[o + 3]])
        }
    };

    let mut offset = 4;

    loop {
        if offset + 4 > buf.len() {
            return None;
        }

        let pid = read_u16(offset);
        let length = read_u16(offset + 2) as usize;
        offset += 4;

        if pid == PID_SENTINEL {
            break;
        }

        if offset + length > buf.len() {
            return None;
        }

        if pid == PID_TOPIC_NAME && length >= 4 {
            let str_len = read_u32(offset) as usize;

            if offset + 4 + str_len <= buf.len() && str_len > 0 {
                let bytes = &buf[offset + 4..offset + 4 + str_len - 1];
                if let Ok(s) = std::str::from_utf8(bytes) {
                    return Some(s.to_string());
                }
            }
        }

        offset += (length + 3) & !3;
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::discovery::constants::{PL_CDR2_BE, PL_CDR2_LE};

    /// Build a minimal SEDP parameter-list payload carrying PID_TOPIC_NAME.
    /// `endian_is_le` controls both the PID/length and the string-length
    /// byte order; the encapsulation header itself is always big-endian.
    fn build_payload(encap: u16, endian_is_le: bool, topic: &str) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&encap.to_be_bytes());
        buf.extend_from_slice(&[0, 0]); // 2-byte options field

        let put_u16 = |out: &mut Vec<u8>, v: u16| {
            if endian_is_le {
                out.extend_from_slice(&v.to_le_bytes());
            } else {
                out.extend_from_slice(&v.to_be_bytes());
            }
        };

        // CDR strings: length (u32) including NUL, then bytes + NUL terminator,
        // padded to 4-byte alignment.
        let topic_bytes = topic.as_bytes();
        let cdr_str_len = (topic_bytes.len() + 1) as u32; // includes NUL
        let mut value = Vec::new();
        if endian_is_le {
            value.extend_from_slice(&cdr_str_len.to_le_bytes());
        } else {
            value.extend_from_slice(&cdr_str_len.to_be_bytes());
        }
        value.extend_from_slice(topic_bytes);
        value.push(0);
        while value.len() % 4 != 0 {
            value.push(0);
        }

        put_u16(&mut buf, PID_TOPIC_NAME);
        put_u16(&mut buf, value.len() as u16);
        buf.extend_from_slice(&value);

        // PID_SENTINEL with zero length closes the parameter list.
        // PL_CDR sentinel: PID (u16) + length (u16) = 4 bytes total, length must be 0.
        put_u16(&mut buf, PID_SENTINEL);
        put_u16(&mut buf, 0u16);
        buf
    }

    #[test]
    fn parse_topic_name_accepts_cdr_le() {
        let buf = build_payload(CDR_LE, true, "MyTopic");
        assert_eq!(parse_topic_name(&buf).as_deref(), Some("MyTopic"));
    }

    #[test]
    fn parse_topic_name_accepts_cdr_be() {
        let buf = build_payload(CDR_BE, false, "RtiTopic");
        assert_eq!(parse_topic_name(&buf).as_deref(), Some("RtiTopic"));
    }

    #[test]
    fn parse_topic_name_accepts_cdr_le_vendor() {
        let buf = build_payload(CDR_LE_VENDOR, true, "FastDdsTopic");
        assert_eq!(parse_topic_name(&buf).as_deref(), Some("FastDdsTopic"));
    }

    #[test]
    fn parse_topic_name_accepts_cdr_be_vendor() {
        let buf = build_payload(CDR_BE_VENDOR, false, "FastDdsBe");
        assert_eq!(parse_topic_name(&buf).as_deref(), Some("FastDdsBe"));
    }

    #[test]
    fn parse_topic_name_rejects_xcdr2_pl_cdr2_le() {
        // XCDR2 PL_CDR2 is intentionally out of scope here; the fallback
        // parser returns None so callers fall through to parse_sedp().
        let buf = build_payload(PL_CDR2_LE, true, "Anything");
        assert_eq!(parse_topic_name(&buf), None);
    }

    #[test]
    fn parse_topic_name_rejects_xcdr2_pl_cdr2_be() {
        let buf = build_payload(PL_CDR2_BE, false, "Anything");
        assert_eq!(parse_topic_name(&buf), None);
    }

    #[test]
    fn parse_topic_name_rejects_unknown_encapsulation() {
        let buf = build_payload(0x00CC, true, "Garbage");
        assert_eq!(parse_topic_name(&buf), None);
    }

    #[test]
    fn parse_topic_name_handles_truncated_buffer() {
        let short = [0u8, 0x03, 0, 0, 0x05]; // 5 bytes < 12 required
        assert_eq!(parse_topic_name(&short), None);
    }
}
