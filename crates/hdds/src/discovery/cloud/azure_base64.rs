// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

const ENCODE_TABLE: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Base64 encode bytes to string
pub fn encode(data: &[u8]) -> String {
    let mut result = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = if chunk.len() > 1 { u32::from(chunk[1]) } else { 0 };
        let b2 = if chunk.len() > 2 { u32::from(chunk[2]) } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;

        result.push(ENCODE_TABLE[((triple >> 18) & 0x3F) as usize] as char);
        result.push(ENCODE_TABLE[((triple >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            result.push(ENCODE_TABLE[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
        if chunk.len() > 2 {
            result.push(ENCODE_TABLE[(triple & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
    }
    result
}

/// Decode a base64 character to its 6-bit value
fn decode_char(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        b'=' => Some(0), // padding
        _ => None,
    }
}

/// Base64 decode string to bytes
pub fn decode(input: &str) -> Option<Vec<u8>> {
    let input = input.as_bytes();
    if !input.len().is_multiple_of(4) {
        return None;
    }
    let mut result = Vec::with_capacity(input.len() / 4 * 3);
    for chunk in input.chunks(4) {
        let a = decode_char(chunk[0])?;
        let b = decode_char(chunk[1])?;
        let c = decode_char(chunk[2])?;
        let d = decode_char(chunk[3])?;

        let triple = (u32::from(a) << 18) | (u32::from(b) << 12) | (u32::from(c) << 6) | u32::from(d);
        // Base64 decodes 4 chars (each 6-bit) into 3 bytes (24-bit total)
        // triple max value: (63<<18) | (63<<12) | (63<<6) | 63 = 0x00FFFFFF
        // Extract bytes using masks instead of casts for clarity
        result.push(((triple >> 16) & 0xFF) as u8); // High byte (bits 23-16)
        if chunk[2] != b'=' {
            result.push(((triple >> 8) & 0xFF) as u8); // Middle byte (bits 15-8)
        }
        if chunk[3] != b'=' {
            result.push((triple & 0xFF) as u8); // Low byte (bits 7-0)
        }
    }
    Some(result)
}
