#!/usr/bin/env python3
"""
vendor_report.py - vendor identity + data-flow proof for scripts/interop-smoke.

A capture can contain an expected vendorId without that proving anything
about THIS cell: multicast SPDP from an unrelated participant (another
domain, a leftover process, a stale capture) carries a vendorId too. The
check implemented here binds the proof to the cell: it looks for an
endpoint of the expected vendor on the cell's own (unique, per-cell) topic
name, an HDDS endpoint on the same topic, and a writer/reader match between
them with a positive data count -- i.e. samples actually flowed on that
exact topic between those two identified participants, not just "that
vendorId showed up somewhere in the pcap".

Two implementations:
  1. the `pcap-diff` tool (a separate project, used whenever it is on PATH;
     richer: parses SEDP endpoint announcements per topic and writer/reader
     matching with a live data count) -- this is the only path that can do
     the topic/identity binding described above;
  2. a small built-in pcap reader (standard-library only) that can only
     confirm a vendorId appeared somewhere in the capture, with no binding
     to the topic or to actual data flow. Used only when pcap-diff is not
     installed, and reported as such (`method` field) so a result built on
     it is never described as a bound proof.
"""
from __future__ import annotations

import json
import shutil
import struct
import subprocess
import time
from dataclasses import dataclass, field


@dataclass
class BindingProof:
    topic: str
    expected_peer_vendor_id: int
    expected_hdds_vendor_id: int
    method: str = "none"  # "pcap-diff-bound" | "builtin-presence-only" | "none"
    capture_started_ok: bool = False
    capture_fresh: bool = False
    peer_identity_on_topic: bool = False
    hdds_identity_on_topic: bool = False
    data_flowed: bool = False
    data_count: int = 0
    seen_vendor_ids: dict = field(default_factory=dict)  # presence-only fallback
    error: str | None = None

    @property
    def fully_bound(self) -> bool:
        return (
            self.method == "pcap-diff-bound"
            and self.capture_started_ok
            and self.capture_fresh
            and self.peer_identity_on_topic
            and self.hdds_identity_on_topic
            and self.data_flowed
        )


def check_binding(
    pcap_path: str,
    topic: str,
    expected_peer_vendor_id: int,
    expected_hdds_vendor_id: int,
    capture_not_before: float,
) -> BindingProof:
    """capture_not_before: a time.time() value from just before tcpdump was
    started for this cell -- the capture file's mtime must be at or after
    this, or it is stale (e.g. a leftover file a failed cleanup left behind
    at a reused path)."""
    proof = BindingProof(
        topic=topic,
        expected_peer_vendor_id=expected_peer_vendor_id,
        expected_hdds_vendor_id=expected_hdds_vendor_id,
    )

    # Deliberately NOT os.path.exists()/getmtime()/getsize() on pcap_path
    # directly: this function runs inside run-matrix.py's own long-lived
    # interpreter, and when pcap_path is a cross-host NFS mount (the
    # --remote-host case), that process's own cached view of the path can
    # keep returning ENOENT for tens of seconds after another host created
    # the file -- confirmed by hand (a brand-new shell's stat on the exact
    # same path succeeded immediately while the long-lived interpreter kept
    # seeing ENOENT). A freshly spawned subprocess for the stat call does
    # not hit that stale cache, the same fix run-matrix.py's own capture
    # readiness poll already applies for exactly this reason.
    stat_out = subprocess.run(
        ["bash", "-c", f"stat -c '%Y %s' {pcap_path} 2>&1"],
        capture_output=True, text=True, timeout=10,
    ).stdout.strip()
    try:
        mtime_str, size_str = stat_out.split()
        mtime, size = float(mtime_str), int(size_str)
    except ValueError:
        proof.error = f"capture file does not exist or could not be stat'd ({stat_out!r})"
        return proof

    # A bare pcap global header (24 bytes) with zero packets is a capture
    # that started but recorded nothing -- still "started", but useless.
    proof.capture_started_ok = size > 24
    proof.capture_fresh = mtime >= capture_not_before - 1.0  # 1s clock slack
    if not proof.capture_started_ok:
        proof.error = f"capture is empty ({size} bytes, header only)"
        return proof
    if not proof.capture_fresh:
        proof.error = (
            f"capture mtime ({time.ctime(mtime)}) predates this cell's start "
            f"({time.ctime(capture_not_before)}) -- stale file"
        )
        return proof

    if shutil.which("pcap-diff"):
        _fill_from_pcap_diff(proof, pcap_path)
        if proof.error is None:
            return proof
        # Fall through to the weaker fallback rather than failing the cell
        # over a tooling hiccup, but keep pcap-diff's error for context and
        # never claim "bound" from the fallback.
        pcap_diff_error = proof.error
        _fill_from_builtin_reader(proof, pcap_path)
        if proof.method == "builtin-presence-only":
            proof.error = f"pcap-diff failed ({pcap_diff_error}); used presence-only fallback"
        return proof

    _fill_from_builtin_reader(proof, pcap_path)
    return proof


def _fill_from_pcap_diff(proof: BindingProof, pcap_path: str) -> None:
    try:
        out = subprocess.run(
            ["pcap-diff", "--format=json", pcap_path],
            capture_output=True, text=True, timeout=60, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        proof.error = f"pcap-diff invocation failed: {exc}"
        return
    if not out.stdout.strip():
        proof.error = f"pcap-diff produced no output (stderr: {out.stderr.strip()[:300]})"
        return
    try:
        report = json.loads(out.stdout)
    except json.JSONDecodeError as exc:
        proof.error = f"pcap-diff JSON parse failed: {exc}"
        return

    proof.method = "pcap-diff-bound"

    endpoints = [e for e in report.get("endpoints", []) if e.get("topic") == proof.topic]
    for e in endpoints:
        guid = e.get("guid", "")
        vendor_id = _vendor_id_from_guid(guid)
        if vendor_id == proof.expected_peer_vendor_id:
            proof.peer_identity_on_topic = True
        if vendor_id == proof.expected_hdds_vendor_id:
            proof.hdds_identity_on_topic = True

    for m in report.get("matching", []):
        if m.get("topic") != proof.topic:
            continue
        w_vid = _vendor_id_from_guid(m.get("writer", {}).get("guid", ""))
        r_vid = _vendor_id_from_guid(m.get("reader", {}).get("guid", ""))
        pair_vids = {w_vid, r_vid}
        if pair_vids == {proof.expected_peer_vendor_id, proof.expected_hdds_vendor_id}:
            count = m.get("data_count", 0) or 0
            proof.data_count = max(proof.data_count, count)
            if count > 0:
                proof.data_flowed = True

    if not endpoints:
        proof.error = f"pcap-diff found no endpoint on topic {proof.topic!r}"


def _vendor_id_from_guid(guid: str) -> int | None:
    # GUID textual form from pcap-diff is dotted hex octets, e.g.
    # "01.10.08.b6.aa.68.94.ab.05.7a.a8.a4.00.00.02.07" -- the vendorId is
    # the first two octets (DDSI-RTPS 2.5 9.3.1, vendor-specific GUID prefix
    # convention every implementation here follows: prefix[0:2] = vendorId).
    parts = guid.split(".")
    if len(parts) < 2:
        return None
    try:
        return int(parts[0], 16) << 8 | int(parts[1], 16)
    except ValueError:
        return None


def _fill_from_builtin_reader(proof: BindingProof, pcap_path: str) -> None:
    """Presence-only: confirms a vendorId appeared somewhere in the capture.
    Cannot bind to a topic or to data flow -- callers must not treat this as
    proof the tested exchange involved that vendor, only that its traffic
    was present in the same capture window."""
    proof.method = "builtin-presence-only"
    try:
        with open(pcap_path, "rb") as f:
            data = f.read()
    except OSError as exc:
        proof.error = f"could not read pcap: {exc}"
        return

    magic = data[0:4]
    if magic == b"\xd4\xc3\xb2\xa1":
        endian = "<"
    elif magic == b"\xa1\xb2\xc3\xd4":
        endian = ">"
    else:
        proof.error = f"unrecognized pcap magic {magic.hex()} (pcapng or nanosecond capture?)"
        return

    linktype = struct.unpack_from(endian + "I", data, 20)[0]
    extract = {
        1: _vendor_id_from_ethernet,      # LINKTYPE_ETHERNET
        113: _vendor_id_from_sll,         # LINKTYPE_LINUX_SLL
        276: _vendor_id_from_sll2,        # LINKTYPE_LINUX_SLL2
    }.get(linktype)
    if extract is None:
        proof.error = f"unsupported link type {linktype}"
        return

    seen = {}
    offset = 24
    rec_hdr = struct.Struct(endian + "IIII")
    while offset + rec_hdr.size <= len(data):
        _, _, incl_len, _ = rec_hdr.unpack_from(data, offset)
        offset += rec_hdr.size
        frame = data[offset:offset + incl_len]
        offset += incl_len
        vid = extract(frame)
        if vid is not None:
            seen.setdefault(vid, "")

    proof.seen_vendor_ids = seen
    proof.peer_identity_on_topic = proof.expected_peer_vendor_id in seen  # presence, not binding
    proof.hdds_identity_on_topic = proof.expected_hdds_vendor_id in seen
    proof.data_flowed = False  # the fallback never claims data-flow binding


def _vendor_id_from_udp_rtps_payload(frame: bytes, ip_off: int) -> int | None:
    if len(frame) < ip_off + 20:
        return None
    ihl = (frame[ip_off] & 0x0F) * 4
    protocol = frame[ip_off + 9]
    if protocol != 17:  # UDP
        return None
    udp_off = ip_off + ihl
    if len(frame) < udp_off + 8:
        return None
    payload = frame[udp_off + 8:]
    if len(payload) < 8 or payload[0:4] != b"RTPS":
        return None
    return struct.unpack_from(">H", payload, 6)[0]


def _vendor_id_from_ethernet(frame: bytes) -> int | None:
    if len(frame) < 14:
        return None
    ethertype = struct.unpack_from(">H", frame, 12)[0]
    ip_off = 14
    if ethertype == 0x8100:  # 802.1Q VLAN tag
        ethertype = struct.unpack_from(">H", frame, 16)[0]
        ip_off = 18
    if ethertype != 0x0800:
        return None
    return _vendor_id_from_udp_rtps_payload(frame, ip_off)


def _vendor_id_from_sll(frame: bytes) -> int | None:
    # LINKTYPE_LINUX_SLL: 16-byte header, protocol type at offset 14.
    if len(frame) < 16:
        return None
    ethertype = struct.unpack_from(">H", frame, 14)[0]
    if ethertype != 0x0800:
        return None
    return _vendor_id_from_udp_rtps_payload(frame, 16)


def _vendor_id_from_sll2(frame: bytes) -> int | None:
    # LINKTYPE_LINUX_SLL2: 20-byte header, protocol type at offset 0.
    if len(frame) < 20:
        return None
    ethertype = struct.unpack_from(">H", frame, 0)[0]
    if ethertype != 0x0800:
        return None
    return _vendor_id_from_udp_rtps_payload(frame, 20)


# Vendor IDs as registered in crates/hdds/src/core/rtps_constants.rs (grep-verified,
# not transcribed from memory: 0x011A HDDS, 0x0103 OpenDDS, 0x010F eProsima Fast DDS,
# 0x0110 Eclipse CycloneDDS).
VENDOR_IDS = {
    "hdds": 0x011A,
    "opendds": 0x0103,
    "fastdds": 0x010F,
    "cyclonedds": 0x0110,
}
