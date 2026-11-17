// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Per-writer large-payload routing profile.
//!
//! Some peers only sustain fragmented large payloads on a specific
//! topology. For vendor 0x0103 (OpenDDS dialect) HDDS publishes a large
//! payload as a few large DATA_FRAG datagrams to the vendor's default
//! user-data MULTICAST group (239.255.0.2, a vendor convention not
//! announced in SPDP), carried by kernel IP fragmentation, instead of a
//! back-to-back line-rate DATA_FRAG burst to the reader's unicast
//! locator, which a receiver with a default-size socket buffer cannot
//! absorb (per-skb truesize accounting).
//!
//! Doctrine: the vendor is resolved on the COLD path (registry reads at
//! pairing/write-entry time, see `resolve_frag_route`), stored here, and
//! the hot send/retransmit paths read it O(1). The profile only ever
//! activates when EVERY matched remote reader belongs to an OpenDDS
//! participant, so self and all other vendor pairings never see it.
//!
//! The profile is shared (one `Arc` per writer) between the live write
//! path and the NACK / NACK_FRAG retransmit handlers: every emitter MUST
//! fragment with the same size or fragment numbering diverges and the
//! reader's reassembly is corrupted.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU16, AtomicU64, Ordering};

/// Fragment payload size for the OpenDDS large-payload profile.
///
/// Large-datagram play: a ~100 KB sample becomes 2 datagrams instead of
/// ~98, so the receiver's socket sees a trickle instead of a line-rate
/// burst. Must stay below the UDP payload ceiling (65507) once RTPS
/// framing is added, and be a multiple of 4 (RTPS alignment).
pub(crate) const OPENDDS_LARGE_FRAGMENT_SIZE: u16 = 65_284;

/// OpenDDS default user-data multicast group (OpenDDS convention, not
/// announced in SPDP). The port is the standard RTPS user multicast
/// port for the domain (PB + DG*domainId + d2), taken from the
/// transport's computed `data_multicast_addr`.
pub(crate) const OPENDDS_DEFAULT_USER_MULTICAST_GROUP: Ipv4Addr = Ipv4Addr::new(239, 255, 0, 2);

/// Lock-free per-writer large-payload route (see module docs).
pub(crate) struct FragRouteProfile {
    /// RTPS fragmentSize used by every DATA_FRAG emitter of this writer.
    /// Held in the width of the DATA_FRAG.fragmentSize field (a u16,
    /// RTPS v2.5 Sec.8.3.8.3) so no emitter has to narrow it.
    fragment_size: AtomicU16,
    /// Multicast destination override, encoded as
    /// `(ipv4 as u64) << 16 | port`; 0 = no override (unicast routing).
    mcast_dest: AtomicU64,
    /// Default fragment size to restore when the profile deactivates.
    default_size: u16,
}

impl FragRouteProfile {
    pub(crate) fn new(default_size: u16) -> Self {
        Self {
            fragment_size: AtomicU16::new(default_size),
            mcast_dest: AtomicU64::new(0),
            default_size,
        }
    }

    /// Fragment size every DATA_FRAG build of this writer must use, as the
    /// wire field carries it; slicing code widens it with `usize::from`.
    pub(crate) fn fragment_size(&self) -> u16 {
        self.fragment_size.load(Ordering::Acquire)
    }

    /// Select one fragmentSize for the whole sample (RTPS 2.5 Sec.8.3.8.3/9.4.5.5),
    /// leaving room for the first fragment's inline QoS and routing headers.
    /// Zero means that even a four-octet fragment would exceed IPv4 UDP.
    pub(crate) fn sample_fragment_size(&self, inline_qos_len: usize, routing_len: usize) -> u16 {
        // RTPS header (20), INFO_TS (12), DATA_FRAG header and fields (36).
        // Round down to allow the encoder's four-octet submessage padding.
        let available = udp_payload_ceiling()
            .saturating_sub(68 + routing_len)
            .saturating_sub(inline_qos_len)
            & !3;
        self.fragment_size()
            .min(u16::try_from(available).unwrap_or(0))
    }

    /// Multicast destination override for DATA_FRAG sends, if active.
    pub(crate) fn multicast_dest(&self) -> Option<SocketAddr> {
        let enc = self.mcast_dest.load(Ordering::Acquire);
        if enc == 0 {
            return None;
        }
        // mcast_dest packs ip << 16 | port (see set_opendds), so the
        // shifted value fits 32 bits by construction; saturate (visible
        // garbage, never silent truncation) if that invariant ever breaks.
        let ip = Ipv4Addr::from(u32::try_from(enc >> 16).unwrap_or(u32::MAX));
        let port = (enc & 0xFFFF) as u16;
        Some(SocketAddr::new(IpAddr::V4(ip), port))
    }

    /// Activate the OpenDDS large-payload profile (cold path).
    pub(crate) fn set_opendds(&self, user_multicast_port: u16) {
        let enc = (u64::from(u32::from(OPENDDS_DEFAULT_USER_MULTICAST_GROUP)) << 16)
            | u64::from(user_multicast_port);
        // Size first: a racing build that still sees the old dest must
        // never pair the new size with a stale route decision the other
        // way around (worst case here is one burst sent unicast at the
        // large size, which the reader simply NACKs).
        self.fragment_size
            .store(OPENDDS_LARGE_FRAGMENT_SIZE, Ordering::Release);
        self.mcast_dest.store(enc, Ordering::Release);
    }

    /// Restore the default (unicast, default fragment size) route.
    pub(crate) fn reset_default(&self) {
        self.mcast_dest.store(0, Ordering::Release);
        self.fragment_size
            .store(self.default_size, Ordering::Release);
    }
}

/// Largest UDP payload one send may carry: the IPv4 limit, 65507 octets.
#[cfg(not(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly"
)))]
#[inline(always)]
fn udp_payload_ceiling() -> usize {
    65_507
}

/// Largest UDP payload one send may carry on a BSD-family kernel. These
/// kernels refuse a larger datagram with EMSGSIZE, and their limit is the
/// `net.inet.udp.maxdgram` sysctl (9216 octets by default on macOS), far
/// below the IPv4 limit. Read once, capped at 65507; 9216 when it cannot
/// be read.
#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly"
))]
fn udp_payload_ceiling() -> usize {
    static CEILING: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *CEILING.get_or_init(|| bsd_udp::max_datagram().map_or(9216, |max| max.min(65_507)))
}

#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly"
))]
mod bsd_udp {
    /// `net.inet.udp.maxdgram`, if the kernel has it.
    #[cfg(not(target_os = "openbsd"))]
    pub(super) fn max_datagram() -> Option<usize> {
        let mut value: libc::c_int = 0;
        let mut len = std::mem::size_of::<libc::c_int>();
        // SAFETY: NUL-terminated name, `value` and `len` describe one
        // writable c_int, no new value is set.
        let rc = unsafe {
            libc::sysctlbyname(
                c"net.inet.udp.maxdgram".as_ptr(),
                (&mut value as *mut libc::c_int).cast(),
                &mut len,
                std::ptr::null_mut(),
                0,
            )
        };
        if rc != 0 || len != std::mem::size_of::<libc::c_int>() {
            return None;
        }
        usize::try_from(value).ok().filter(|&max| max > 0)
    }

    /// OpenBSD has no such sysctl.
    #[cfg(target_os = "openbsd")]
    pub(super) fn max_datagram() -> Option<usize> {
        None
    }

    #[cfg(test)]
    mod tests {
        use crate::dds::writer::frag_route::FragRouteProfile;

        /// The large-payload profile never builds a datagram the kernel
        /// refuses: the per-sample fragment fits the platform ceiling.
        #[test]
        fn a_large_fragment_fits_the_kernel_datagram_limit() {
            let ceiling = super::super::udp_payload_ceiling();
            assert!(ceiling <= 65_507);
            let size = FragRouteProfile::new(65_284).sample_fragment_size(64, 16);
            assert!(usize::from(size) + 68 + 16 + 64 <= ceiling);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::discovery::fragment_buffer::FragmentBuffer;
    use crate::core::discovery::multicast::{DiscoveryFsm, FragmentGeometry};
    use crate::core::discovery::GUID;
    use crate::dds::{CdrVersion, QoS, DDS};
    use crate::protocol::builder::{self, RtpsEndpointContext};
    use crate::protocol::discovery::{SedpData, SpdpData};
    use crate::transport::{PortMapping, UdpTransport};
    use std::net::UdpSocket;
    use std::sync::Arc;
    use std::time::Duration;

    #[derive(Debug, Clone, PartialEq, crate::DDS)]
    struct Blob {
        #[key]
        key: u32,
        bytes: Vec<u8>,
    }

    // RTPS 2.5 Sec.8.3.8.3/9.4.5.5: fragmentSize is per sample, including the
    // first fragment with inline QoS. Every datagram must fit IPv4 UDP.
    #[test]
    fn keyed_opendds_fragments_fit_udp_and_reassemble_with_repairs() {
        let domain = loop {
            let lease = crate::test_support::domains::unique_domain();
            if (200..=230).contains(&lease.id()) {
                break lease;
            }
        };
        let mapping = PortMapping::calculate(domain.id(), 0).expect("mapping");
        let transport = Arc::new(UdpTransport::new(domain.id(), 0, mapping).expect("transport"));
        let capture = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, transport.data_multicast_port()))
            .expect("multicast capture");
        capture
            .join_multicast_v4(
                &OPENDDS_DEFAULT_USER_MULTICAST_GROUP,
                &Ipv4Addr::UNSPECIFIED,
            )
            .expect("join default interface");
        // HDDS_INTERFACE=lo uses loopback instead of the default interface.
        let _ =
            capture.join_multicast_v4(&OPENDDS_DEFAULT_USER_MULTICAST_GROUP, &Ipv4Addr::LOCALHOST);
        capture
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let ctx = RtpsEndpointContext {
            guid_prefix: [0x73; 12],
            reader_entity_id: [0; 4],
            writer_entity_id: [0, 0, 1, 3],
            encapsulation_kind: 0x0007,
            publisher_entity_id: [0, 0, 1, 8],
        };
        let participant = GUID::new([0x74; 12], [0, 0, 1, 0xc1]);
        let reader = GUID::new([0x74; 12], [0, 0, 1, 7]);
        let blob = Blob {
            key: 7,
            bytes: vec![0x5a; 100_000],
        };
        // PID_TOPIC_NAME is string<256> (RTPS 2.5 Table 9.18).
        for topic_len in [200, 255, 256] {
            let topic = "t".repeat(topic_len);
            let fsm = Arc::new(DiscoveryFsm::new(GUID::zero(), 100_000));
            let locator = SocketAddr::from((Ipv4Addr::LOCALHOST, 12345));
            fsm.handle_spdp(SpdpData {
                participant_guid: participant,
                lease_duration_ms: 100_000,
                domain_id: domain.id(),
                metatraffic_unicast_locators: vec![],
                default_unicast_locators: vec![locator],
                default_multicast_locators: vec![],
                metatraffic_multicast_locators: vec![],
                identity_token: None,
                permissions_token: None,
                participant_security_info: None,
                vendor_id: Some(crate::core::rtps_constants::OPENDDS_VENDOR_ID_U16),
                hdds_capabilities: None,
                builtin_endpoint_set: None,
            });
            fsm.handle_sedp(SedpData {
                endpoint_security_info: Default::default(),
                topic_name: topic.clone(),
                type_name: Blob::type_descriptor().type_name.to_string(),
                participant_guid: participant,
                endpoint_guid: reader,
                qos_hash: 0,
                qos: None,
                type_object: None,
                dependents: Vec::new(),
                type_object_legacy_v1: false,
                type_information: None,
                unicast_locators: vec![locator],
                user_data: None,
                shm_capability: None,
                has_explicit_reliability: false,
                has_explicit_ownership: false,
                has_ownership_strength: false,
                type_consistency: None,
                group_entity_id: None,
            });
            let mut writer = super::super::WriterBuilder::<Blob>::new(topic.clone())
                .qos(QoS::reliable().transient_local().keep_all())
                .with_transport(transport.clone())
                .with_discovery_fsm(fsm.clone())
                .build()
                .expect("writer");
            writer.rtps_endpoint = Some(ctx);
            writer.endpoint_registry = Some(fsm.endpoint_registry());
            writer.write(&blob).expect("large keyed write");
            assert_eq!(
                writer.frag_route.fragment_size(),
                OPENDDS_LARGE_FRAGMENT_SIZE
            );
            let change = writer
                .history_cache
                .as_ref()
                .unwrap()
                .get_change(1)
                .unwrap();
            let count = (change.payload.len() + 4).div_ceil(usize::from(change.metadata.frag_size));
            let mut live = Vec::new();
            for _ in 0..count {
                let mut buf = vec![0; 65_536];
                let (len, _) = capture
                    .recv_from(&mut buf)
                    .expect("each live fragment arrives");
                buf.truncate(len);
                live.push(buf);
            }
            for spec in [false, true] {
                let repair = super::super::nack::change_frag_packets(
                    &ctx,
                    &topic,
                    1,
                    &change.payload,
                    &change.metadata,
                    change.group.as_ref(),
                    usize::from(change.metadata.frag_size),
                    change.metadata.source_ts,
                    spec,
                );
                assert_eq!(
                    repair, live,
                    "repair reproduces live fragment geometry and QoS"
                );
                assert_reassembles(&repair, &blob, change.metadata.frag_size);
            }
        }
    }

    fn assert_reassembles(packets: &[Vec<u8>], blob: &Blob, fragment_size: u16) {
        let mut buffer = FragmentBuffer::new(8, 5000);
        let mut complete = None;
        for (index, packet) in packets.iter().enumerate() {
            assert!(packet.len() <= 65_507, "IPv4 UDP payload: {}", packet.len());
            assert_eq!(packet[32], 0x16);
            let num = u32::from_le_bytes(packet[56..60].try_into().unwrap());
            let size = u16::from_le_bytes(packet[62..64].try_into().unwrap());
            assert_eq!(
                size, fragment_size,
                "fragmentSize is constant for the sample"
            );
            assert_eq!(num as usize, index + 1);
            let sample_size = u32::from_le_bytes(packet[64..68].try_into().unwrap());
            let mut offset = 68;
            if packet[33] & 2 != 0 {
                loop {
                    let pid = u16::from_le_bytes(packet[offset..offset + 2].try_into().unwrap());
                    let len =
                        u16::from_le_bytes(packet[offset + 2..offset + 4].try_into().unwrap());
                    offset += 4 + usize::from(len);
                    if pid == 1 {
                        break;
                    }
                }
            }
            let result = buffer.insert_fragment(
                GUID::new([0x73; 12], [0, 0, 1, 3]),
                1,
                num,
                FragmentGeometry {
                    fragment_size: size,
                    sample_size,
                },
                packet[offset..].to_vec(),
            );
            if result.is_some() {
                complete = result;
            }
        }
        let bytes = complete.expect("sample reassembles");
        assert_eq!(Blob::decode(&bytes[4..], CdrVersion::Xcdr1).unwrap(), *blob);
    }

    #[test]
    fn sample_fragment_budget_covers_configured_sizes_and_both_group_forms() {
        let ctx = RtpsEndpointContext {
            guid_prefix: [1; 12],
            reader_entity_id: [0; 4],
            writer_entity_id: [0, 0, 1, 3],
            encapsulation_kind: 0x0007,
            publisher_entity_id: [0, 0, 1, 8],
        };
        let tag = crate::protocol::group::GroupTag {
            gsn: 5,
            writer_set: [1; 4],
            set_first_gsn: Some(1),
            part_first_sn: None,
        };
        let topic = "t".repeat(256);
        let qos: Vec<_> = [None, Some(&tag)]
            .into_iter()
            .map(|group| {
                builder::data_frag_inline_qos(&ctx, &topic, Some(1), Some(5), group, Some(&[7; 16]))
            })
            .collect();
        for configured in [1023, 1024, 65_284, u16::MAX] {
            let profile = FragRouteProfile::new(configured);
            let size = profile.sample_fragment_size(qos.iter().map(Vec::len).max().unwrap(), 16);
            assert!(size > 0 && size <= configured);
            for inline in &qos {
                let mut packets = builder::build_data_frag_packets_ts(
                    &ctx,
                    1,
                    &vec![0x5a; 100_000],
                    usize::from(size),
                    CdrVersion::Xcdr1,
                    (1, 2),
                    false,
                );
                assert!(builder::put_inline_qos_in_first_fragment(
                    &mut packets,
                    inline
                ));
                assert!(packets.iter().all(|packet| packet.len() + 16 <= 65_507));
            }
        }
        assert_eq!(
            FragRouteProfile::new(1024).sample_fragment_size(65_440, 0),
            0
        );
    }
}
