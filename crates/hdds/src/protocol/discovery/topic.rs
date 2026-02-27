// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

use super::constants::{CDR_LE, PID_SENTINEL, PID_TOPIC_NAME};

/// Extract the topic name from a serialized SEDP DATA parameter list.
///
/// # Arguments
/// - `buf`: RTPS payload positioned at the DATA submessage.
///
/// # Returns
/// The topic name when present and valid UTF-8.
/// Returns `None` when the PID is missing, the encapsulation is invalid, or the payload is truncated.
pub fn parse_topic_name(buf: &[u8]) -> Option<String> {
    if buf.len() < 12 {
        return None;
    }

    // CDR encapsulation header is ALWAYS big-endian per CDR spec
    let encapsulation = u16::from_be_bytes([buf[0], buf[1]]);
    if encapsulation != CDR_LE {
        return None;
    }

    let mut offset = 4;

    loop {
        if offset + 4 > buf.len() {
            return None;
        }

        let pid = u16::from_le_bytes([buf[offset], buf[offset + 1]]);
        let length = u16::from_le_bytes([buf[offset + 2], buf[offset + 3]]) as usize;
        offset += 4;

        if pid == PID_SENTINEL {
            break;
        }

        if offset + length > buf.len() {
            return None;
        }

        if pid == PID_TOPIC_NAME && length >= 4 {
            let str_len = u32::from_le_bytes([
                buf[offset],
                buf[offset + 1],
                buf[offset + 2],
                buf[offset + 3],
            ]) as usize;

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
