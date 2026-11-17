// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 naskel.com

//! Ethernet / IPv4 / UDP / ARP frame parsing and building for `Sel4Ring`.
//!
//! Pure-data, `no_std`-friendly, no `unsafe`. Every multi-byte field is
//! read or written via `u8` slice indexing combined with `from_be_bytes`
//! / `to_be_bytes`, so the module is safe under aarch64 strict-alignment
//! (no packed-struct dereference, no transmute).
//!
//! Consumers are `arp.rs` and `Sel4Ring::{enqueue_tx, try_dequeue_rx}`.
//!
//! Rules enforced here:
//! - RFC 791 (IPv4): IHL = 5 only, DF = 1, no fragmentation, no options.
//!   Anything else is rejected at parse time (drop + recycle).
//! - RFC 768 (UDP): a checksum of `0x0000` means "no checksum"; we MUST
//!   accept those datagrams without validation.
//!   On the build side, a freshly computed checksum that happens to be
//!   zero is transmitted as `0xFFFF` (RFC 768).
//! - RFC 826 (ARP): IPv4-over-Ethernet only (htype=1, ptype=0x0800,
//!   hlen=6, plen=4). Other ARP profiles are rejected.

#![allow(dead_code)]

/// Ethernet MAC address, 6 bytes big-endian on the wire.
pub type MacAddr = [u8; 6];

/// IPv4 address, 4 bytes big-endian on the wire.
pub type Ipv4Addr = [u8; 4];

/// Length of an Ethernet II header (no VLAN, no FCS).
pub const ETH_HDR_LEN: usize = 14;

/// Length of an IPv4 header without options.
pub const IPV4_HDR_LEN: usize = 20;

/// Length of a UDP header.
pub const UDP_HDR_LEN: usize = 8;

/// Length of an ARP-for-IPv4 payload (after the Ethernet header).
pub const ARP_PAYLOAD_LEN: usize = 28;

/// Minimum Ethernet frame length to carry any UDP datagram (header only).
pub const MIN_UDP_FRAME_LEN: usize = ETH_HDR_LEN + IPV4_HDR_LEN + UDP_HDR_LEN;

/// Minimum Ethernet frame length to carry an IPv4 ARP exchange.
pub const MIN_ARP_FRAME_LEN: usize = ETH_HDR_LEN + ARP_PAYLOAD_LEN;

/// Ethertype for IPv4.
pub const ETHERTYPE_IPV4: u16 = 0x0800;

/// Ethertype for ARP.
pub const ETHERTYPE_ARP: u16 = 0x0806;

/// IPv4 protocol number for UDP.
pub const IP_PROTO_UDP: u8 = 17;

/// ARP hardware type: Ethernet.
pub const ARP_HTYPE_ETHERNET: u16 = 1;

/// ARP protocol type: IPv4.
pub const ARP_PTYPE_IPV4: u16 = 0x0800;

/// ARP hardware address length: Ethernet MAC.
pub const ARP_HLEN: u8 = 6;

/// ARP protocol address length: IPv4.
pub const ARP_PLEN: u8 = 4;

/// ARP opcode: request.
pub const ARP_OP_REQUEST: u16 = 1;

/// ARP opcode: reply.
pub const ARP_OP_REPLY: u16 = 2;

/// Ethernet broadcast destination address.
pub const MAC_BROADCAST: MacAddr = [0xff; 6];

/// All-zero MAC, used as `tha` in ARP requests (RFC 826).
pub const MAC_ZERO: MacAddr = [0x00; 6];

/// IPv4 TTL stamped on every outgoing UDP datagram.
const DEFAULT_TTL: u8 = 64;

/// Parsed Ethernet frame, narrowed to the kinds we handle.
///
/// `parse_frame` returns `None` for anything that does not match one of
/// these variants (wrong ethertype, malformed header, bad checksum,
/// fragmented IPv4, non-UDP IPv4, etc.). The caller treats `None` as
/// "drop and recycle".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParsedFrame<'a> {
    /// IPv4 UDP datagram. All fields validated (csum, len, no fragment).
    Ipv4Udp(ParsedIpv4Udp<'a>),
    /// ARP request or reply, IPv4-over-Ethernet only.
    Arp(ParsedArp),
}

/// Validated IPv4/UDP datagram. `payload` borrows from the input frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParsedIpv4Udp<'a> {
    /// Ethernet source MAC.
    pub src_mac: MacAddr,
    /// Ethernet destination MAC.
    pub dst_mac: MacAddr,
    /// IPv4 source address.
    pub src_ip: Ipv4Addr,
    /// IPv4 destination address.
    pub dst_ip: Ipv4Addr,
    /// UDP source port.
    pub src_port: u16,
    /// UDP destination port.
    pub dst_port: u16,
    /// UDP payload, slice into the input frame.
    pub payload: &'a [u8],
}

/// Parsed ARP frame.
///
/// Field names follow RFC 826: `sha` / `spa` are the sender's hardware /
/// protocol addresses; `tha` / `tpa` are the target's. The ARP cache
/// only ever learns from `(sha, spa)`; `tha` and `tpa` are
/// preserved so the caller can decide whether to reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParsedArp {
    /// 1 = request, 2 = reply.
    pub op: u16,
    /// Sender hardware address.
    pub sha: MacAddr,
    /// Sender protocol address.
    pub spa: Ipv4Addr,
    /// Target hardware address (zero in well-formed requests).
    pub tha: MacAddr,
    /// Target protocol address (= "who has this IP?" in requests).
    pub tpa: Ipv4Addr,
}

#[inline]
fn read_u16_be(b: &[u8]) -> u16 {
    u16::from_be_bytes([b[0], b[1]])
}

#[inline]
fn write_u16_be(b: &mut [u8], v: u16) {
    let bytes = v.to_be_bytes();
    b[0] = bytes[0];
    b[1] = bytes[1];
}

/// RFC 1071 one's-complement internet checksum.
///
/// Operates on a flat byte slice in network byte order. An odd trailing
/// byte is padded with zero on the right (per RFC 1071 sec. 2).
pub fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Compute the UDP checksum over the IPv4 pseudo-header + UDP header +
/// payload (RFC 768). `udp_segment` is the UDP header followed by the
/// payload, with the checksum field set to zero.
///
/// Returns the on-wire checksum: never zero (a freshly computed value of
/// `0x0000` is transmitted as `0xFFFF` to distinguish from
/// "no checksum").
pub fn udp_checksum_v4(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, udp_segment: &[u8]) -> u16 {
    let mut sum: u32 = 0;

    // Pseudo-header: src_ip, dst_ip, 0, proto, udp_len.
    sum += read_u16_be(&src_ip[0..2]) as u32;
    sum += read_u16_be(&src_ip[2..4]) as u32;
    sum += read_u16_be(&dst_ip[0..2]) as u32;
    sum += read_u16_be(&dst_ip[2..4]) as u32;
    sum += IP_PROTO_UDP as u32;
    sum += udp_segment.len() as u32;

    // UDP header + payload, csum field assumed zero by caller.
    let mut i = 0;
    while i + 1 < udp_segment.len() {
        sum += u16::from_be_bytes([udp_segment[i], udp_segment[i + 1]]) as u32;
        i += 2;
    }
    if i < udp_segment.len() {
        sum += (udp_segment[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    let csum = !(sum as u16);
    if csum == 0 {
        0xFFFF
    } else {
        csum
    }
}

/// Parse an Ethernet frame.
///
/// Returns `None` for any frame that should be dropped:
/// - shorter than an Ethernet header,
/// - ethertype other than IPv4 or ARP,
/// - IPv4 with options, fragmentation, non-UDP protocol, or bad header csum,
/// - UDP with non-zero checksum that fails validation,
/// - ARP frame not in IPv4-over-Ethernet shape,
/// - any truncation inconsistent with the IPv4 `total_len` field.
pub fn parse_frame(data: &[u8]) -> Option<ParsedFrame<'_>> {
    if data.len() < ETH_HDR_LEN {
        return None;
    }
    let mut dst_mac = [0u8; 6];
    dst_mac.copy_from_slice(&data[0..6]);
    let mut src_mac = [0u8; 6];
    src_mac.copy_from_slice(&data[6..12]);
    let ethertype = read_u16_be(&data[12..14]);
    match ethertype {
        ETHERTYPE_IPV4 => parse_ipv4_udp(data, src_mac, dst_mac),
        ETHERTYPE_ARP => parse_arp(data),
        _ => None,
    }
}

fn parse_ipv4_udp(
    data: &[u8],
    src_mac: MacAddr,
    dst_mac: MacAddr,
) -> Option<ParsedFrame<'_>> {
    if data.len() < ETH_HDR_LEN + IPV4_HDR_LEN {
        return None;
    }
    let ip = &data[ETH_HDR_LEN..];

    // IPv4 with IHL = 5 only (no options).
    if ip[0] != 0x45 {
        return None;
    }

    let total_len = read_u16_be(&ip[2..4]) as usize;
    if total_len < IPV4_HDR_LEN {
        return None;
    }
    if ETH_HDR_LEN + total_len > data.len() {
        return None;
    }

    // Reject any fragment (MF=1 or frag_offset != 0). DF=1 is allowed.
    let flags_frag = read_u16_be(&ip[6..8]);
    if (flags_frag & 0x3FFF) != 0 {
        return None;
    }

    if ip[9] != IP_PROTO_UDP {
        return None;
    }

    // Validate IPv4 header checksum. Sum (including the csum field
    // itself) must yield `0xFFFF` in 1's complement, which after the
    // final `NOT` step in `internet_checksum` is `0x0000`.
    if internet_checksum(&ip[0..IPV4_HDR_LEN]) != 0 {
        return None;
    }

    let mut src_ip = [0u8; 4];
    src_ip.copy_from_slice(&ip[12..16]);
    let mut dst_ip = [0u8; 4];
    dst_ip.copy_from_slice(&ip[16..20]);

    let udp_off = ETH_HDR_LEN + IPV4_HDR_LEN;
    let ip_end = ETH_HDR_LEN + total_len;
    if ip_end < udp_off + UDP_HDR_LEN {
        return None;
    }
    let udp = &data[udp_off..ip_end];

    let src_port = read_u16_be(&udp[0..2]);
    let dst_port = read_u16_be(&udp[2..4]);
    let udp_len = read_u16_be(&udp[4..6]) as usize;
    let csum = read_u16_be(&udp[6..8]);

    if udp_len < UDP_HDR_LEN || udp_len > udp.len() {
        return None;
    }

    // RFC 768: checksum 0 means "no checksum", accept unchecked.
    if csum != 0 && !udp_checksum_v4_validate(src_ip, dst_ip, &udp[..udp_len]) {
        return None;
    }

    let payload = &udp[UDP_HDR_LEN..udp_len];
    Some(ParsedFrame::Ipv4Udp(ParsedIpv4Udp {
        src_mac,
        dst_mac,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        payload,
    }))
}

/// True if the UDP segment carries a valid RFC 768 checksum.
///
/// The segment must include the original checksum bytes; we sum the
/// pseudo-header plus the segment as-is and check the result is the
/// all-ones word.
fn udp_checksum_v4_validate(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    udp_segment: &[u8],
) -> bool {
    let mut sum: u32 = 0;
    sum += read_u16_be(&src_ip[0..2]) as u32;
    sum += read_u16_be(&src_ip[2..4]) as u32;
    sum += read_u16_be(&dst_ip[0..2]) as u32;
    sum += read_u16_be(&dst_ip[2..4]) as u32;
    sum += IP_PROTO_UDP as u32;
    sum += udp_segment.len() as u32;

    let mut i = 0;
    while i + 1 < udp_segment.len() {
        sum += u16::from_be_bytes([udp_segment[i], udp_segment[i + 1]]) as u32;
        i += 2;
    }
    if i < udp_segment.len() {
        sum += (udp_segment[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    (sum as u16) == 0xFFFF
}

fn parse_arp(data: &[u8]) -> Option<ParsedFrame<'static>> {
    if data.len() < ETH_HDR_LEN + ARP_PAYLOAD_LEN {
        return None;
    }
    let arp = &data[ETH_HDR_LEN..ETH_HDR_LEN + ARP_PAYLOAD_LEN];

    if read_u16_be(&arp[0..2]) != ARP_HTYPE_ETHERNET {
        return None;
    }
    if read_u16_be(&arp[2..4]) != ARP_PTYPE_IPV4 {
        return None;
    }
    if arp[4] != ARP_HLEN || arp[5] != ARP_PLEN {
        return None;
    }
    let op = read_u16_be(&arp[6..8]);
    if op != ARP_OP_REQUEST && op != ARP_OP_REPLY {
        return None;
    }
    let mut sha = [0u8; 6];
    sha.copy_from_slice(&arp[8..14]);
    let mut spa = [0u8; 4];
    spa.copy_from_slice(&arp[14..18]);
    let mut tha = [0u8; 6];
    tha.copy_from_slice(&arp[18..24]);
    let mut tpa = [0u8; 4];
    tpa.copy_from_slice(&arp[24..28]);
    Some(ParsedFrame::Arp(ParsedArp {
        op,
        sha,
        spa,
        tha,
        tpa,
    }))
}

/// Build an Ethernet + IPv4 + UDP frame into `buf`.
///
/// Layout: Ethernet header (14) + IPv4 header (20) + UDP header (8) +
/// payload bytes. The IPv4 header checksum and UDP checksum are both
/// computed and written.
///
/// Returns the number of bytes written, or `None` if `buf` is too small
/// or `payload` would push the IPv4 total length past `u16::MAX`.
#[allow(clippy::too_many_arguments)]
pub fn build_udp_frame(
    buf: &mut [u8],
    src_mac: MacAddr,
    dst_mac: MacAddr,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Option<usize> {
    let total = MIN_UDP_FRAME_LEN.checked_add(payload.len())?;
    if buf.len() < total {
        return None;
    }
    let ip_total_len = (IPV4_HDR_LEN + UDP_HDR_LEN).checked_add(payload.len())?;
    if ip_total_len > u16::MAX as usize {
        return None;
    }

    // Ethernet header.
    buf[0..6].copy_from_slice(&dst_mac);
    buf[6..12].copy_from_slice(&src_mac);
    write_u16_be(&mut buf[12..14], ETHERTYPE_IPV4);

    // IPv4 header (csum field left at zero for now).
    {
        let ip = &mut buf[ETH_HDR_LEN..ETH_HDR_LEN + IPV4_HDR_LEN];
        ip[0] = 0x45; // version=4, IHL=5
        ip[1] = 0x00; // TOS
        write_u16_be(&mut ip[2..4], ip_total_len as u16);
        write_u16_be(&mut ip[4..6], 0); // id = 0
        write_u16_be(&mut ip[6..8], 0x4000); // DF=1, MF=0, frag_off=0
        ip[8] = DEFAULT_TTL;
        ip[9] = IP_PROTO_UDP;
        write_u16_be(&mut ip[10..12], 0); // csum placeholder
        ip[12..16].copy_from_slice(&src_ip);
        ip[16..20].copy_from_slice(&dst_ip);
    }
    let ip_csum = internet_checksum(&buf[ETH_HDR_LEN..ETH_HDR_LEN + IPV4_HDR_LEN]);
    write_u16_be(
        &mut buf[ETH_HDR_LEN + 10..ETH_HDR_LEN + 12],
        ip_csum,
    );

    // UDP header + payload (csum field left at zero before compute).
    let udp_off = ETH_HDR_LEN + IPV4_HDR_LEN;
    let udp_len = UDP_HDR_LEN + payload.len();
    write_u16_be(&mut buf[udp_off..udp_off + 2], src_port);
    write_u16_be(&mut buf[udp_off + 2..udp_off + 4], dst_port);
    write_u16_be(&mut buf[udp_off + 4..udp_off + 6], udp_len as u16);
    write_u16_be(&mut buf[udp_off + 6..udp_off + 8], 0); // csum placeholder
    buf[udp_off + UDP_HDR_LEN..udp_off + udp_len].copy_from_slice(payload);

    let udp_csum = udp_checksum_v4(src_ip, dst_ip, &buf[udp_off..udp_off + udp_len]);
    write_u16_be(&mut buf[udp_off + 6..udp_off + 8], udp_csum);

    Some(total)
}

/// Build a broadcast ARP request asking who has `target_ip`.
///
/// Ethernet destination is the all-ones broadcast; ARP `tha` is zero
/// per RFC 826. Returns the byte count written or `None` if `buf` is
/// too small.
pub fn build_arp_request(
    buf: &mut [u8],
    our_mac: MacAddr,
    our_ip: Ipv4Addr,
    target_ip: Ipv4Addr,
) -> Option<usize> {
    build_arp(
        buf,
        MAC_BROADCAST,
        our_mac,
        ARP_OP_REQUEST,
        our_mac,
        our_ip,
        MAC_ZERO,
        target_ip,
    )
}

/// Build a unicast ARP reply.
///
/// Used to answer an inbound ARP request whose `tpa` matched our local
/// IP. `target_mac` / `target_ip` are the requester's `sha` / `spa`
/// from the inbound frame.
pub fn build_arp_reply(
    buf: &mut [u8],
    our_mac: MacAddr,
    our_ip: Ipv4Addr,
    target_mac: MacAddr,
    target_ip: Ipv4Addr,
) -> Option<usize> {
    build_arp(
        buf,
        target_mac,
        our_mac,
        ARP_OP_REPLY,
        our_mac,
        our_ip,
        target_mac,
        target_ip,
    )
}

#[allow(clippy::too_many_arguments)]
fn build_arp(
    buf: &mut [u8],
    eth_dst: MacAddr,
    eth_src: MacAddr,
    op: u16,
    sha: MacAddr,
    spa: Ipv4Addr,
    tha: MacAddr,
    tpa: Ipv4Addr,
) -> Option<usize> {
    if buf.len() < MIN_ARP_FRAME_LEN {
        return None;
    }

    buf[0..6].copy_from_slice(&eth_dst);
    buf[6..12].copy_from_slice(&eth_src);
    write_u16_be(&mut buf[12..14], ETHERTYPE_ARP);

    let a = &mut buf[ETH_HDR_LEN..ETH_HDR_LEN + ARP_PAYLOAD_LEN];
    write_u16_be(&mut a[0..2], ARP_HTYPE_ETHERNET);
    write_u16_be(&mut a[2..4], ARP_PTYPE_IPV4);
    a[4] = ARP_HLEN;
    a[5] = ARP_PLEN;
    write_u16_be(&mut a[6..8], op);
    a[8..14].copy_from_slice(&sha);
    a[14..18].copy_from_slice(&spa);
    a[18..24].copy_from_slice(&tha);
    a[24..28].copy_from_slice(&tpa);

    Some(MIN_ARP_FRAME_LEN)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Fixed test vector used across several tests.
    const SRC_MAC: MacAddr = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
    const DST_MAC: MacAddr = [0x02, 0x00, 0x00, 0x00, 0x00, 0x02];
    const SRC_IP: Ipv4Addr = [10, 0, 2, 17];
    const DST_IP: Ipv4Addr = [10, 0, 2, 2];
    const SRC_PORT: u16 = 1235;
    const DST_PORT: u16 = 9999;
    const PAYLOAD: &[u8] = b"payload-0";

    #[test]
    fn internet_checksum_zeroes_yields_all_ones() {
        // All-zero input -> sum = 0 -> NOT 0 = 0xFFFF.
        assert_eq!(internet_checksum(&[0u8; 20]), 0xFFFF);
    }

    #[test]
    fn internet_checksum_odd_trailing_byte_padded_right() {
        // Single byte 0xAB pads to word 0xAB00; NOT 0xAB00 = 0x54FF.
        assert_eq!(internet_checksum(&[0xAB]), 0x54FF);
    }

    #[test]
    fn build_udp_frame_locks_wire_bytes() {
        // Expected checksums: IPv4 0x22b6, UDP 0xce7a (RFC 791, RFC 768).
        // Method, independent of this crate: a standalone Python script
        // builds the IPv4 header and the UDP pseudo-header + UDP header +
        // payload from the field values above, with each checksum field
        // zero. It takes the ones'-complement sum of 16-bit big-endian
        // words (odd trailing byte padded on the right), folds the carries
        // (RFC 1071), inverts the result, and maps a computed 0x0000 to
        // 0xFFFF for UDP. The receiver-side check (sum over the header
        // with the checksum in place) must give 0xFFFF. The same method
        // gives 0x219c for the payload an earlier version of this vector
        // used, which is the value this vector replaced, so the method is
        // not tuned to the new result.
        let expected: [u8; 51] = [
            // Ethernet header
            0x02, 0x00, 0x00, 0x00, 0x00, 0x02, // dst MAC
            0x02, 0x00, 0x00, 0x00, 0x00, 0x01, // src MAC
            0x08, 0x00, // ethertype = IPv4
            // IPv4 header
            0x45, 0x00, // ver=4, IHL=5, TOS=0
            0x00, 0x25, // total_len = 37
            0x00, 0x00, // id = 0
            0x40, 0x00, // DF=1, no frag
            0x40, 0x11, // TTL=64, proto=UDP
            0x22, 0xb6, // csum
            10, 0, 2, 17, // src IP
            10, 0, 2, 2, // dst IP
            // UDP header
            0x04, 0xd3, // src port 1235
            0x27, 0x0f, // dst port 9999
            0x00, 0x11, // length = 17
            0xce, 0x7a, // csum
            // Payload
            b'p', b'a', b'y', b'l', b'o', b'a', b'd', b'-', b'0',
        ];

        let mut buf = [0u8; 64];
        let n = build_udp_frame(
            &mut buf, SRC_MAC, DST_MAC, SRC_IP, DST_IP, SRC_PORT, DST_PORT, PAYLOAD,
        )
        .unwrap();
        assert_eq!(n, expected.len());
        assert_eq!(&buf[..n], &expected[..]);
    }

    #[test]
    fn build_then_parse_udp_round_trip() {
        let mut buf = [0u8; 128];
        let n = build_udp_frame(
            &mut buf, SRC_MAC, DST_MAC, SRC_IP, DST_IP, SRC_PORT, DST_PORT, PAYLOAD,
        )
        .unwrap();

        let parsed = parse_frame(&buf[..n]).expect("frame must parse");
        match parsed {
            ParsedFrame::Ipv4Udp(p) => {
                assert_eq!(p.src_mac, SRC_MAC);
                assert_eq!(p.dst_mac, DST_MAC);
                assert_eq!(p.src_ip, SRC_IP);
                assert_eq!(p.dst_ip, DST_IP);
                assert_eq!(p.src_port, SRC_PORT);
                assert_eq!(p.dst_port, DST_PORT);
                assert_eq!(p.payload, PAYLOAD);
            }
            other => panic!("expected Ipv4Udp, got {:?}", other),
        }
    }

    #[test]
    fn parse_accepts_udp_with_zero_checksum() {
        // RFC 768: csum = 0 means "no checksum"; MUST be accepted.
        let mut buf = [0u8; 128];
        let n = build_udp_frame(
            &mut buf, SRC_MAC, DST_MAC, SRC_IP, DST_IP, SRC_PORT, DST_PORT, PAYLOAD,
        )
        .unwrap();
        // Zero out the UDP csum field (offset = Eth + IPv4 + 6).
        buf[ETH_HDR_LEN + IPV4_HDR_LEN + 6] = 0;
        buf[ETH_HDR_LEN + IPV4_HDR_LEN + 7] = 0;
        let parsed = parse_frame(&buf[..n]).expect("zero-csum UDP must parse");
        let ParsedFrame::Ipv4Udp(p) = parsed else {
            panic!("expected Ipv4Udp");
        };
        assert_eq!(p.payload, PAYLOAD);
    }

    #[test]
    fn parse_rejects_bad_ipv4_checksum() {
        let mut buf = [0u8; 128];
        let n = build_udp_frame(
            &mut buf, SRC_MAC, DST_MAC, SRC_IP, DST_IP, SRC_PORT, DST_PORT, PAYLOAD,
        )
        .unwrap();
        // Flip a byte in the IPv4 source address. UDP csum stays valid
        // only because the pseudo-header inside the UDP csum disagrees,
        // but we reject at the IPv4 level first.
        buf[ETH_HDR_LEN + 12] ^= 0x01;
        assert!(parse_frame(&buf[..n]).is_none());
    }

    #[test]
    fn parse_rejects_bad_udp_checksum() {
        let mut buf = [0u8; 128];
        let n = build_udp_frame(
            &mut buf, SRC_MAC, DST_MAC, SRC_IP, DST_IP, SRC_PORT, DST_PORT, PAYLOAD,
        )
        .unwrap();
        // Flip the last payload byte. IPv4 csum is over the header
        // only and stays valid; UDP csum must catch the corruption.
        buf[n - 1] ^= 0x80;
        assert!(parse_frame(&buf[..n]).is_none());
    }

    #[test]
    fn parse_rejects_truncated_ethernet() {
        assert!(parse_frame(&[]).is_none());
        assert!(parse_frame(&[0u8; 13]).is_none());
    }

    #[test]
    fn parse_rejects_unknown_ethertype() {
        let mut buf = [0u8; 60];
        let n = build_udp_frame(
            &mut buf, SRC_MAC, DST_MAC, SRC_IP, DST_IP, SRC_PORT, DST_PORT, PAYLOAD,
        )
        .unwrap();
        // Rewrite ethertype to something we don't handle (IPv6).
        buf[12] = 0x86;
        buf[13] = 0xdd;
        assert!(parse_frame(&buf[..n]).is_none());
    }

    #[test]
    fn parse_rejects_non_udp_ipv4() {
        let mut buf = [0u8; 60];
        let n = build_udp_frame(
            &mut buf, SRC_MAC, DST_MAC, SRC_IP, DST_IP, SRC_PORT, DST_PORT, PAYLOAD,
        )
        .unwrap();
        // Replace proto with ICMP (1). We don't rewrite the IPv4 csum
        // so the frame is rejected at csum check (which is fine - the
        // proto check happens first regardless, both must drop the frame).
        buf[ETH_HDR_LEN + 9] = 1;
        assert!(parse_frame(&buf[..n]).is_none());
    }

    #[test]
    fn parse_rejects_ipv4_with_options() {
        let mut buf = [0u8; 60];
        let n = build_udp_frame(
            &mut buf, SRC_MAC, DST_MAC, SRC_IP, DST_IP, SRC_PORT, DST_PORT, PAYLOAD,
        )
        .unwrap();
        // Set IHL to 6 (= 24-byte header). We don't handle options.
        buf[ETH_HDR_LEN] = 0x46;
        assert!(parse_frame(&buf[..n]).is_none());
    }

    #[test]
    fn parse_rejects_ipv4_fragment() {
        let mut buf = [0u8; 60];
        let n = build_udp_frame(
            &mut buf, SRC_MAC, DST_MAC, SRC_IP, DST_IP, SRC_PORT, DST_PORT, PAYLOAD,
        )
        .unwrap();
        // Set MF bit (0x2000) in flags/frag.
        buf[ETH_HDR_LEN + 6] |= 0x20;
        assert!(parse_frame(&buf[..n]).is_none());
    }

    #[test]
    fn build_udp_rejects_undersized_buffer() {
        let mut buf = [0u8; 40]; // < MIN_UDP_FRAME_LEN(42) + payload(9)
        assert!(build_udp_frame(
            &mut buf, SRC_MAC, DST_MAC, SRC_IP, DST_IP, SRC_PORT, DST_PORT, PAYLOAD,
        )
        .is_none());
    }

    #[test]
    fn build_arp_request_locks_wire_bytes() {
        let our_mac: MacAddr = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
        let our_ip: Ipv4Addr = [10, 0, 2, 17];
        let target_ip: Ipv4Addr = [10, 0, 2, 2];

        let expected: [u8; 42] = [
            // Ethernet
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // broadcast
            0x02, 0x00, 0x00, 0x00, 0x00, 0x01, // src = our MAC
            0x08, 0x06, // ethertype = ARP
            // ARP
            0x00, 0x01, // htype = Ethernet
            0x08, 0x00, // ptype = IPv4
            0x06, 0x04, // hlen, plen
            0x00, 0x01, // op = request
            0x02, 0x00, 0x00, 0x00, 0x00, 0x01, // sha = our MAC
            10, 0, 2, 17, // spa = our IP
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // tha = zero
            10, 0, 2, 2, // tpa = target
        ];

        let mut buf = [0u8; 60];
        let n = build_arp_request(&mut buf, our_mac, our_ip, target_ip).unwrap();
        assert_eq!(n, expected.len());
        assert_eq!(&buf[..n], &expected[..]);

        // And it must round-trip through parse_frame.
        let parsed = parse_frame(&buf[..n]).expect("ARP request must parse");
        let ParsedFrame::Arp(a) = parsed else {
            panic!("expected ARP");
        };
        assert_eq!(a.op, ARP_OP_REQUEST);
        assert_eq!(a.sha, our_mac);
        assert_eq!(a.spa, our_ip);
        assert_eq!(a.tha, MAC_ZERO);
        assert_eq!(a.tpa, target_ip);
    }

    #[test]
    fn build_arp_reply_targets_requester() {
        let our_mac: MacAddr = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
        let our_ip: Ipv4Addr = [10, 0, 2, 17];
        let peer_mac: MacAddr = [0x52, 0x55, 0x0a, 0x00, 0x02, 0x02];
        let peer_ip: Ipv4Addr = [10, 0, 2, 2];

        let mut buf = [0u8; 60];
        let n = build_arp_reply(&mut buf, our_mac, our_ip, peer_mac, peer_ip).unwrap();
        assert_eq!(n, MIN_ARP_FRAME_LEN);

        // Ethernet dst = peer's MAC (unicast back to requester).
        assert_eq!(&buf[0..6], &peer_mac[..]);
        assert_eq!(&buf[6..12], &our_mac[..]);

        let parsed = parse_frame(&buf[..n]).expect("ARP reply must parse");
        let ParsedFrame::Arp(a) = parsed else {
            panic!("expected ARP");
        };
        assert_eq!(a.op, ARP_OP_REPLY);
        assert_eq!(a.sha, our_mac);
        assert_eq!(a.spa, our_ip);
        assert_eq!(a.tha, peer_mac);
        assert_eq!(a.tpa, peer_ip);
    }

    #[test]
    fn parse_rejects_truncated_arp() {
        let mut buf = [0u8; 40]; // ARP needs 42 bytes
        buf[12] = 0x08;
        buf[13] = 0x06;
        assert!(parse_frame(&buf[..]).is_none());
    }

    #[test]
    fn parse_rejects_arp_wrong_profile() {
        let our_mac: MacAddr = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
        let our_ip: Ipv4Addr = [10, 0, 2, 17];
        let target_ip: Ipv4Addr = [10, 0, 2, 2];
        let mut buf = [0u8; 60];
        let n = build_arp_request(&mut buf, our_mac, our_ip, target_ip).unwrap();
        // Flip ARP htype to something non-Ethernet.
        buf[ETH_HDR_LEN] = 0x00;
        buf[ETH_HDR_LEN + 1] = 0x06; // IEEE 802 LANs
        assert!(parse_frame(&buf[..n]).is_none());
    }

    #[test]
    fn udp_payload_can_be_empty() {
        let mut buf = [0u8; 64];
        let n = build_udp_frame(
            &mut buf, SRC_MAC, DST_MAC, SRC_IP, DST_IP, SRC_PORT, DST_PORT, &[],
        )
        .unwrap();
        assert_eq!(n, MIN_UDP_FRAME_LEN);
        let parsed = parse_frame(&buf[..n]).expect("empty-payload UDP must parse");
        let ParsedFrame::Ipv4Udp(p) = parsed else {
            panic!("expected Ipv4Udp");
        };
        assert!(p.payload.is_empty());
    }

    #[test]
    fn parse_handles_ethernet_padding() {
        // Real Ethernet links pad frames to 60 bytes before FCS. The
        // parser must respect IPv4.total_len and ignore trailing pad.
        let mut buf = [0u8; 64];
        let n_built = build_udp_frame(
            &mut buf, SRC_MAC, DST_MAC, SRC_IP, DST_IP, SRC_PORT, DST_PORT, PAYLOAD,
        )
        .unwrap();
        // Simulate 9 bytes of trailing pad.
        let padded_len = n_built + 9;
        let parsed = parse_frame(&buf[..padded_len]).expect("padded UDP must parse");
        let ParsedFrame::Ipv4Udp(p) = parsed else {
            panic!("expected Ipv4Udp");
        };
        assert_eq!(p.payload, PAYLOAD);
    }

    #[test]
    fn udp_checksum_substitutes_natural_zero_with_ffff() {
        // Lock the `0x0000 -> 0xFFFF` substitution path
        // with a hand-tuned vector instead of an "never returns 0"
        // existence claim.
        //
        // Pseudo-header (src=0, dst=0, proto=17, len=8) sums to 0x0019.
        // We need (pseudo + segment) == 0xFFFF so the 1's-complement
        // negation produces 0x0000, which RFC 768 forbids on the wire.
        // Pick segment = src_port(0x7FFF) + dst_port(0x7FDF) + len(0x0008)
        // + csum(0x0000); segment sum = 0x7FFF + 0x7FDF + 0x0008 = 0xFFE6.
        // Total: 0x0019 + 0xFFE6 = 0xFFFF. The helper MUST emit 0xFFFF
        // (not 0x0000).
        let segment = [0x7F, 0xFF, 0x7F, 0xDF, 0x00, 0x08, 0x00, 0x00];
        let csum = udp_checksum_v4([0; 4], [0; 4], &segment);
        assert_eq!(
            csum, 0xFFFF,
            "natural-zero csum must be substituted with 0xFFFF on the wire"
        );
    }
}
