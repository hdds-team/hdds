// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Fuzz the submessage walk that every received datagram goes through.
//!
//! `classify_rtps` runs on the multicast listener's receive path, ahead of
//! the `catch_unwind` that guards the discovery callback: a panic here
//! kills the listener thread outright, and the packet that triggers it
//! comes from whoever can reach the multicast group. The walk does index
//! arithmetic on attacker-controlled lengths and carries a forward-scanning
//! recovery loop for a vendor that writes an impossible
//! `octetsToNextHeader`, so "it cannot panic" is a claim that has to be
//! fuzzed rather than read.
//!
//! This covers `for_each_data_submessage` too, which is `pub(crate)` and
//! cannot be named from here: both are visitors over the same
//! `classifier::walk`, and the DATA arm of `classify_rtps` calls the same
//! `classify_data` and `calculate_payload_offset` on the same submessages,
//! plus the DATA_FRAG arm the other one skips. It is a superset, not an
//! approximation.
//!
//! `scan_all_data_frags` rides along because it is the SECOND copy of that
//! traversal, still unmerged: the two are known to differ on recovery,
//! 4-byte realignment and fragment counting, so until they are one thing
//! they are two things to fuzz.

#![no_main]

use hdds::core::discovery::multicast::{classify_rtps, scan_all_data_frags};
use libfuzzer_sys::fuzz_target;

/// Protocol version the header validator accepts; anything else is
/// refused on the major (DDS-RTPS v2.5 Sec.8.6).
const RTPS_VERSION: [u8; 2] = [0x02, 0x05];

fuzz_target!(|data: &[u8]| {
    // Straight off the socket: arbitrary bytes, including everything the
    // header check refuses.
    let _ = classify_rtps(data);
    let _ = scan_all_data_frags(data);

    // Then the same bytes as the submessage chain of a well-formed
    // datagram. Without this the fuzzer spends its whole budget guessing
    // the four magic bytes and a version, and never reaches a submessage
    // at all.
    //
    // The magic and the vendor id come from the input because both steer
    // real branches: "RTPX" is accepted by `classify_rtps` and refused by
    // `scan_all_data_frags`, and the vendor id decides the DATA/DATA_FRAG
    // tie-break plus the proprietary-submessage arms (RTI 0x0101,
    // FastDDS 0x010f, HDDS 0x011a).
    if let Some((steering, submessages)) = data.split_at_checked(3) {
        let mut packet = Vec::with_capacity(20 + submessages.len());
        packet.extend_from_slice(if steering[0] & 0x01 != 0 {
            b"RTPX"
        } else {
            b"RTPS"
        });
        packet.extend_from_slice(&RTPS_VERSION);
        packet.extend_from_slice(&[steering[1], steering[2]]);
        packet.extend_from_slice(&[0u8; 12]);
        packet.extend_from_slice(submessages);

        let _ = classify_rtps(&packet);
        let _ = scan_all_data_frags(&packet);
    }
});
