// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! The DATA a writer puts on the wire, read back as bytes.
//!
//! [`capture_data`] points a writer's DATA at a loopback socket instead of
//! the readers discovery matched it with; [`data_payloads`] takes a captured
//! datagram apart into the encapsulation identifier and the body of every
//! DATA it carries (RTPS v2.5 Sec.9.4.5.3, Sec.10.2). The writer can come
//! from any creation path (a participant, the C ABI), so a test checks what
//! that path really sends.

use crate::dds::{DataWriter, DDS};
use std::net::UdpSocket;
use std::time::Duration;

/// A loopback socket that receives every DATA `writer` sends from now on,
/// in place of its matched readers (which no longer receive them).
///
/// # Panics
/// When the socket cannot be bound.
pub fn capture_data<T: DDS>(writer: &mut DataWriter<T>) -> UdpSocket {
    let socket = super::ports::bind_capture_socket();
    socket
        .set_read_timeout(Some(Duration::from_millis(300)))
        .expect("capture socket read timeout");
    writer.send_data_to_for_test(socket.local_addr().expect("capture socket address"));
    socket
}

/// Send every DATA `writer` sends from now on to `addr`, in place of its
/// matched readers: [`capture_data`] for a socket the test does not own
/// (another process's, which decodes the datagrams with
/// [`data_payloads`]).
pub fn send_data_to<T: DDS>(writer: &mut DataWriter<T>, addr: std::net::SocketAddr) {
    writer.send_data_to_for_test(addr);
}

/// Every datagram `socket` receives until it stays silent for its read
/// timeout.
pub fn drain(socket: &UdpSocket) -> Vec<Vec<u8>> {
    let mut datagrams = Vec::new();
    let mut buf = vec![0u8; 65536];
    while let Ok((n, _)) = socket.recv_from(&mut buf) {
        datagrams.push(buf[..n].to_vec());
    }
    datagrams
}

/// The `(encapsulation identifier, body)` of every DATA submessage of
/// `datagram` that carries a serialized payload, in order. The identifier
/// is the big-endian first half of the encapsulation header; the body is
/// what follows the 4-byte header, without the padding its options count
/// (RTPS v2.5 Sec.10.2). A malformed datagram yields what parsed before
/// the defect.
pub fn data_payloads(datagram: &[u8]) -> Vec<(u16, Vec<u8>)> {
    const DATA: u8 = 0x15;
    const FLAG_LE: u8 = 0x01;
    const FLAG_INLINE_QOS: u8 = 0x02;
    const FLAG_DATA: u8 = 0x04;
    let mut out = Vec::new();
    if datagram.len() < 20 || &datagram[..4] != b"RTPS" {
        return out;
    }
    let mut at = 20usize;
    while at + 4 <= datagram.len() {
        let id = datagram[at];
        let flags = datagram[at + 1];
        let raw = [datagram[at + 2], datagram[at + 3]];
        let octets = usize::from(if flags & FLAG_LE != 0 {
            u16::from_le_bytes(raw)
        } else {
            u16::from_be_bytes(raw)
        });
        let body = at + 4;
        let end = if octets == 0 {
            datagram.len()
        } else {
            body + octets
        };
        if end > datagram.len() {
            return out;
        }
        if id == DATA && flags & FLAG_DATA != 0 && body + 20 <= end {
            let raw_oti = [datagram[body + 2], datagram[body + 3]];
            let oti = usize::from(if flags & FLAG_LE != 0 {
                u16::from_le_bytes(raw_oti)
            } else {
                u16::from_be_bytes(raw_oti)
            });
            let mut p = body + 4 + oti;
            if flags & FLAG_INLINE_QOS != 0 {
                loop {
                    if p + 4 > end {
                        return out;
                    }
                    let pid = [datagram[p], datagram[p + 1]];
                    let plen = [datagram[p + 2], datagram[p + 3]];
                    let (pid, plen) = if flags & FLAG_LE != 0 {
                        (u16::from_le_bytes(pid), u16::from_le_bytes(plen))
                    } else {
                        (u16::from_be_bytes(pid), u16::from_be_bytes(plen))
                    };
                    p += 4 + usize::from(plen);
                    if pid == 0x0001 {
                        break;
                    }
                }
            }
            if p + 4 <= end {
                let kind = u16::from_be_bytes([datagram[p], datagram[p + 1]]);
                let padding = usize::from(datagram[p + 3] & 0x03);
                let body_end = end.saturating_sub(padding).max(p + 4);
                out.push((kind, datagram[p + 4..body_end].to_vec()));
            }
        }
        if octets == 0 {
            break;
        }
        at = end;
    }
    out
}
