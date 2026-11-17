#!/usr/bin/env python3
"""
run-matrix.py - HDDS cross-vendor interop smoke test.

Reports how HDDS interoperates with a set of independent open-source DDS
implementations (CycloneDDS, Fast DDS, OpenDDS), each built from its own
pinned upstream release in a Docker image (see vendors/<name>/Dockerfile).
This is a report of OUR interoperability with each project, not a ranking
or a performance comparison between them: a cell that does not pass yet is
reported as something for HDDS to keep investigating, never as a defect in
the peer project.

For each (vendor, direction, reliability) cell, on a topic name unique to
that cell and that run:
  - one side runs natively on the test host (HDDS's own `interop_smoke`
    example binary), the other runs the peer's Docker image (`--network
    host`, so plain RTPS/UDP multicast discovery works as it would between
    two local processes);
  - the publisher embeds a random per-cell "challenge" byte into its
    payload pattern; the orchestrator (which generated the challenge)
    recomputes the expected pattern itself rather than trusting either
    side's claim of what was sent;
  - a tcpdump capture of the exchange is handed to the repo's own
    `pcap-diff` tool, which reports, bound to this cell's own topic name:
    an endpoint of the expected peer vendor, an endpoint of HDDS, and a
    writer/reader match between them with a positive data count -- i.e.
    samples actually flowed on THIS topic between THESE identified
    participants, not just "that vendorId appeared somewhere in the pcap";
  - the verdict is computed from exact sets: the publisher's reported
    successful-send set must equal the configured range, the subscriber's
    valid-sample set (right key, right challenge-derived payload, no
    conflicting duplicate) must equal that same set exactly (no missing,
    no extra), neither side's exit code/watchdog may show a timeout, and
    the capture must be fresh, non-empty, and bind both identities to the
    topic with a positive data count. Nothing here greps for "PASSED".

Usage (run from any host that can both reach the Docker-capable test host
over ssh and resolve `pcap-diff`; the test host itself needs Docker, the
built `interop_smoke` binary, and `tcpdump` with permission to capture --
see README.md for both):
  python3 run-matrix.py --hdds-bin <path to interop_smoke release binary> \
      --outdir <results dir> [--count 100] [--timeout 30] \
      [--vendors cyclonedds,fastdds,opendds] [--iface any]

Exit status: 0 only if every requested cell reached "interoperates"; 1 if
any cell did not (results are still written either way, including partial
results if the run is interrupted partway through).

See README.md in this directory for the full column reference, the
readiness-settle disclosure, and how to read the output.
"""
from __future__ import annotations

import argparse
import json
import os
import random
import re
import secrets
import subprocess
import sys
import time
import traceback
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from vendor_report import VENDOR_IDS, check_binding  # noqa: E402

DEFAULT_DOMAIN_BASE = 210
TOPIC_PREFIX = "InteropSmoke"
TYPE_NAME = "InteropPing"
RELIABILITIES = ["best_effort", "reliable"]
DIRECTIONS = ["hdds_to_peer", "peer_to_hdds"]

# Image tag per vendor -- filled in from each vendor's own build report.
# Override with --image-<vendor> if a different tag was built.
DEFAULT_IMAGES = {
    "cyclonedds": "hdds-interop-smoke-cyclonedds:11.0.1",
    "fastdds": "hdds-interop-smoke-fastdds:3.6.2",
    "opendds": "hdds-interop-smoke-opendds:3.34.0",
}

# License + link for the README credit line (not used for scoring, just
# attribution). Keep in sync with each vendor's own repository.
VENDOR_META = {
    "cyclonedds": {
        "display": "Eclipse Cyclone DDS",
        "version": "11.0.1",
        "license": "EPL-2.0 OR BSD-3-Clause",
        "url": "https://github.com/eclipse-cyclonedds/cyclonedds",
    },
    "fastdds": {
        "display": "eProsima Fast DDS",
        "version": "3.6.2",
        "license": "Apache-2.0",
        "url": "https://github.com/eProsima/Fast-DDS",
    },
    "opendds": {
        "display": "OpenDDS",
        "version": "3.34.0",
        "license": "OpenDDS License (permissive, see the project LICENSE file)",
        "url": "https://github.com/OpenDDS/OpenDDS",
    },
}

FIXED_KEY = 42


def expected_payload_hex(seq: int, challenge: int, length: int = 32) -> str:
    return "".join(f"{(seq + i + challenge) % 256:02x}" for i in range(length))


@dataclass
class CellResult:
    vendor: str
    direction: str
    reliability: str
    domain: int
    topic: str
    challenge: int
    hdds_role: str
    peer_role: str

    hdds_matched: bool = False
    peer_matched: bool = False
    hdds_exit_code: int | None = None
    peer_exit_code: int | None = None
    hdds_timeout_forced: bool = False
    peer_timeout_forced: bool = False
    outer_timeout_fired: bool = False

    sent_set_size: int = 0
    sent_set_equals_expected: bool = False
    distinct_valid_received: int = 0
    total_observations: int = 0
    conflicting_duplicates: list = field(default_factory=list)
    invalid_samples: list = field(default_factory=list)
    missing_seq: list = field(default_factory=list)
    extra_seq: list = field(default_factory=list)

    vendor_fully_bound: bool = False
    vendor_binding_method: str = "none"
    vendor_binding_error: str | None = None

    hdds_log: str = ""
    peer_log: str = ""
    pcap: str = ""
    duration_s: float = 0.0
    result: str = "not passing yet"
    category: str = ""
    reason: str = ""


def remote_argv(args, cmd: str) -> list:
    """Wrap a shell command to run on the test host: locally by default (the
    common case -- Docker and the built binary are on this machine), or over
    ssh when --remote-host names a different Docker-capable host (used for
    our own runs, where house rules keep Docker/load work off this machine)."""
    if args.remote_host:
        return ["ssh", args.remote_host, cmd]
    return ["bash", "-c", cmd]


def run_background(args, cmd: str, log_path: Path, overall_timeout: int, env: dict | None = None):
    """`env`, if given, is rendered as `VAR=val ` tokens placed BEFORE
    `timeout`, never after: `timeout DURATION COMMAND [ARGS...]` treats its
    first argument as the command to execute, so `timeout N VAR=val cmd`
    makes `timeout` try (and fail) to execute the literal string
    "VAR=val" -- confirmed by hand against this exact construction. The
    shell's env-assignment-prefix syntax only takes effect when the
    assignment precedes the command name in the simple command, so it must
    precede `timeout` itself here, not `cmd`."""
    log_f = open(log_path, "w")
    env_prefix = "".join(f"{k}={v} " for k, v in (env or {}).items())
    full = f"{env_prefix}timeout {overall_timeout} {cmd}"
    return subprocess.Popen(
        remote_argv(args, full), stdout=log_f, stderr=subprocess.STDOUT
    ), log_f


def parse_lines(log_path: Path) -> list[str]:
    try:
        return log_path.read_text(errors="replace").splitlines()
    except FileNotFoundError:
        return []


def parse_pub(lines: list[str]) -> dict:
    out = {"matched": False, "no_match": False, "sent_set": set(), "done_sent": None, "timeout_forced": False}
    sent_re = re.compile(r"SENT seq=(\d+)")
    for ln in lines:
        s = ln.strip()
        if s == "EVENT matched":
            out["matched"] = True
        elif s == "EVENT no_match":
            out["no_match"] = True
        elif s == "DONE timeout_forced":
            out["timeout_forced"] = True
        else:
            m = sent_re.match(s)
            if m:
                out["sent_set"].add(int(m.group(1)))
                continue
            m = re.match(r"DONE sent=(\d+)", s)
            if m:
                out["done_sent"] = int(m.group(1))
    return out


def parse_sub(lines: list[str]) -> dict:
    """Returns every observation per seq (not deduped) so the caller can
    tell a harmless retransmit duplicate (identical payload) from a
    conflicting one (different payload/key for the same seq -- a real
    failure, not something to quietly overwrite)."""
    out = {"matched": False, "no_match": False, "observations": {}, "total": 0, "timeout_forced": False}
    sample_re = re.compile(r"SAMPLE seq=(\d+) key=(-?\d+) payload=([0-9a-f]+)")
    for ln in lines:
        s = ln.strip()
        if s == "EVENT matched":
            out["matched"] = True
        elif s == "EVENT no_match":
            out["no_match"] = True
        elif s == "DONE timeout_forced":
            out["timeout_forced"] = True
        else:
            m = sample_re.match(s)
            if m:
                seq = int(m.group(1))
                key = int(m.group(2))
                payload = m.group(3)
                out["observations"].setdefault(seq, []).append((key, payload))
                out["total"] += 1
    return out


def run_cell(args, vendor: str, direction: str, reliability: str, domain: int, run_id: str) -> CellResult:
    hdds_role = "pub" if direction == "hdds_to_peer" else "sub"
    peer_role = "sub" if direction == "hdds_to_peer" else "pub"
    tag = f"{vendor}_{direction}_{reliability}"
    topic = f"{TOPIC_PREFIX}-{tag}-{run_id}"
    challenge = random.SystemRandom().randint(1, 255)

    cell = CellResult(
        vendor=vendor, direction=direction, reliability=reliability, domain=domain,
        topic=topic, challenge=challenge, hdds_role=hdds_role, peer_role=peer_role,
    )

    hdds_log = args.outdir / "logs" / f"{tag}_hdds.log"
    peer_log = args.outdir / "logs" / f"{tag}_peer.log"
    final_pcap_path = args.outdir / "pcaps" / f"{tag}.pcap"
    hdds_log.parent.mkdir(parents=True, exist_ok=True)
    final_pcap_path.parent.mkdir(parents=True, exist_ok=True)
    if args.remote_host:
        # tcpdump runs on the remote test host: write to a path on THAT
        # host's own local disk (never the NFS share both hosts mount) and
        # pull it back with `scp` once the capture is done. An NFS path
        # here looked tempting (one path string works for both the remote
        # writer and this process's later read), but it is not safe to read
        # promptly cross-host: confirmed by hand, repeatably, that a file
        # `ls`/`stat` from a brand-new shell found immediately kept reading
        # back as nonexistent from THIS process for 15-20+ seconds after
        # tcpdump had already exited and closed it -- cross-client NFS
        # attribute-cache staleness, not a real "not written yet" race, and
        # not bounded by any practical poll budget here. `scp` sidesteps it
        # entirely: it is the remote sshd reading its own local filesystem,
        # not an NFS client's cached view of someone else's write.
        # Namespaced by run_id so two runs sharing this default path at once
        # cannot unlink/overwrite each other's capture mid-flight.
        remote_pcap_path = f"/tmp/interop-smoke-captures/{run_id}/{tag}.pcap"
        subprocess.run(
            remote_argv(args, f"mkdir -p {Path(remote_pcap_path).parent}"), timeout=10,
        )
        shared_pcap_path = remote_pcap_path  # a REMOTE path string, not a local Path
    else:
        # Running locally: tcpdump and this script see the same filesystem,
        # so write the capture straight to its final home -- no copy, so no
        # shutil.SameFileError when shared == final.
        shared_pcap_path = final_pcap_path
        # Never read a leftover file from a previous run at this same path.
        if shared_pcap_path.exists():
            try:
                shared_pcap_path.unlink()
            except OSError:
                pass
    cell.hdds_log, cell.peer_log, cell.pcap = str(hdds_log), str(peer_log), str(final_pcap_path)

    # The match-wait and send/receive phases are each budgeted --timeout on
    # the app side (sequentially), and each app's own hard watchdog covers
    # 2*timeout plus 10-15s margin (see interop_smoke.rs / the three vendor
    # apps). The outer `timeout` wrapper must stay comfortably above that,
    # or it becomes the thing that fires first and gets misread as a cell
    # failure instead of a budget mismatch.
    overall_timeout = 2 * args.timeout + 30
    image = args.images[vendor]

    start = time.time()
    capture_not_before = start

    # 1. tcpdump, started slightly before the two peers.
    tcpdump_cmd = (
        f"{args.sudo} timeout {overall_timeout + 10} tcpdump -i {args.iface} "
        f"-w {shared_pcap_path} udp"
    )
    tcpdump_proc = subprocess.Popen(remote_argv(args, tcpdump_cmd))
    time.sleep(1.5)

    # 2. HDDS side (native binary) and peer side (docker, --network host).
    # --challenge only matters to whichever side is --mode pub; passed to
    # both for a uniform invocation.
    hdds_cmd = (
        f"{args.hdds_bin} --mode {hdds_role} --domain {domain} --topic {topic} "
        f"--reliability {reliability} --count {args.count} --key {FIXED_KEY} "
        f"--timeout {args.timeout} --challenge {challenge}"
    )
    # Docker gets the env var via its own `-e` flag (not a shell prefix), so
    # it is unaffected by the `timeout`-argument-order issue run_background's
    # docstring explains -- no special handling needed here.
    peer_cmd = (
        f"{args.sudo} docker run --rm --network host -e INTEROP_SMOKE_SETTLE_MS={args.settle_ms} {image} "
        f"--mode {peer_role} --domain {domain} --topic {topic} "
        f"--reliability {reliability} --count {args.count} --key {FIXED_KEY} "
        f"--timeout {args.timeout} --challenge {challenge}"
    )

    hdds_proc, hdds_f = run_background(
        args, hdds_cmd, hdds_log, overall_timeout,
        env={"INTEROP_SMOKE_SETTLE_MS": args.settle_ms},
    )
    peer_proc, peer_f = run_background(args, peer_cmd, peer_log, overall_timeout)

    try:
        hdds_proc.wait(timeout=overall_timeout + 20)
    except subprocess.TimeoutExpired:
        hdds_proc.kill()
    try:
        peer_proc.wait(timeout=overall_timeout + 20)
    except subprocess.TimeoutExpired:
        peer_proc.kill()
    hdds_f.close()
    peer_f.close()
    cell.hdds_exit_code = hdds_proc.returncode
    cell.peer_exit_code = peer_proc.returncode
    # `timeout <N> <cmd>` exits 124 if it had to send the TERM signal itself
    # (and 128+signal, e.g. 137, if that escalated to KILL): both mean the
    # outer backstop fired, which should never happen in a healthy run and
    # must not be silently treated as a clean exit.
    cell.outer_timeout_fired = cell.hdds_exit_code == 124 or cell.peer_exit_code == 124

    # Stop tcpdump gracefully (SIGINT, same as Ctrl-C) rather than letting its
    # own backstop `timeout` fire or killing the local ssh client/process:
    # either of those can truncate the pcap mid-write and make pcap-diff see
    # a short last packet. A short settle after both peers finish lets the
    # last in-flight packet land before we ask tcpdump to close the file.
    time.sleep(1.0)
    subprocess.run(
        remote_argv(args, f"{args.sudo} pkill -INT -f {str(shared_pcap_path)}"),
        timeout=10,
    )
    try:
        tcpdump_proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        tcpdump_proc.kill()
    if args.remote_host:
        # Pull the capture from the remote host's own local disk with scp
        # (reading its own just-closed file directly, not through either
        # host's NFS client cache -- see the note where remote_pcap_path was
        # chosen above). A couple of quick retries cover ordinary process
        # exit/flush latency; this is NOT working around the cross-host NFS
        # staleness that made polling for the file's appearance unbounded.
        for attempt in range(5):
            scp = subprocess.run(
                ["scp", "-q", f"{args.remote_host}:{shared_pcap_path}", str(final_pcap_path)],
                capture_output=True, text=True, timeout=30,
            )
            if scp.returncode == 0 and final_pcap_path.exists() and final_pcap_path.stat().st_size > 24:
                break
            time.sleep(1.0)
        subprocess.run(
            remote_argv(args, f"rm -rf {Path(shared_pcap_path).parent}"), timeout=10,
        )
    else:
        # Purely local run: tcpdump already wrote straight to final_pcap_path
        # (same filesystem, no copy needed); a brief settle covers ordinary
        # close/flush latency only.
        for _ in range(10):
            if final_pcap_path.exists() and final_pcap_path.stat().st_size > 24:
                break
            time.sleep(0.5)

    cell.duration_s = round(time.time() - start, 1)

    hdds_lines = parse_lines(hdds_log)
    peer_lines = parse_lines(peer_log)

    if hdds_role == "pub":
        pub_info, sub_info = parse_pub(hdds_lines), parse_sub(peer_lines)
        cell.hdds_matched, cell.peer_matched = pub_info["matched"], sub_info["matched"]
        cell.hdds_timeout_forced, cell.peer_timeout_forced = pub_info["timeout_forced"], sub_info["timeout_forced"]
    else:
        sub_info, pub_info = parse_sub(hdds_lines), parse_pub(peer_lines)
        cell.hdds_matched, cell.peer_matched = sub_info["matched"], pub_info["matched"]
        cell.hdds_timeout_forced, cell.peer_timeout_forced = sub_info["timeout_forced"], pub_info["timeout_forced"]

    expected_set = set(range(args.count))
    sent_set = pub_info["sent_set"]
    cell.sent_set_size = len(sent_set)
    cell.sent_set_equals_expected = sent_set == expected_set

    valid_received = set()
    for seq, obs_list in sub_info["observations"].items():
        distinct_obs = set(obs_list)
        if len(distinct_obs) > 1:
            # Same seq, disagreeing content across observations: a real
            # failure, never silently resolved by keeping the last one.
            cell.conflicting_duplicates.append(seq)
            continue
        key, payload = obs_list[0]
        if key == FIXED_KEY and payload == expected_payload_hex(seq, challenge):
            valid_received.add(seq)
        else:
            cell.invalid_samples.append(seq)

    cell.distinct_valid_received = len(valid_received)
    cell.total_observations = sub_info["total"]
    cell.missing_seq = sorted(expected_set - valid_received)
    cell.extra_seq = sorted(valid_received - expected_set)  # sequences outside the configured range

    # Vendor + HDDS identity proof bound to this cell's own topic. By this
    # point final_pcap_path is the capture itself: written there directly
    # in local mode, or scp-pulled there above in --remote-host mode -- no
    # further copy needed either way.
    binding = check_binding(
        str(final_pcap_path), topic, VENDOR_IDS[vendor], VENDOR_IDS["hdds"], capture_not_before,
    )
    cell.vendor_fully_bound = binding.fully_bound
    cell.vendor_binding_method = binding.method
    cell.vendor_binding_error = binding.error

    _compute_verdict(cell, args.count)
    return cell


def _compute_verdict(cell: CellResult, count: int) -> None:
    """Verdict from exact sets and hard failure signals, worded as HDDS's
    own interoperability status with this peer -- never a judgement of the
    peer. `category` distinguishes setup/timeout/discovery/publisher/
    subscriber/vendor-proof failures so a reader does not have to infer it
    from the prose."""
    subscriber_label = "HDDS" if cell.hdds_role == "sub" else cell.vendor
    publisher_label = "HDDS" if cell.hdds_role == "pub" else cell.vendor

    if count <= 0:
        cell.result, cell.category = "not passing yet", "config"
        cell.reason = "configured --count must be a positive number"
    elif cell.hdds_exit_code in (2, 3) or cell.peer_exit_code in (2, 3):
        cell.result, cell.category = "not passing yet", "setup"
        cell.reason = (
            f"a side exited with a setup/no-match code (hdds={cell.hdds_exit_code}, "
            f"peer={cell.peer_exit_code})"
        )
    elif cell.outer_timeout_fired:
        cell.result, cell.category = "not passing yet", "timeout"
        cell.reason = "the outer timeout backstop had to kill a process (budget mismatch or a real hang)"
    elif cell.hdds_timeout_forced or cell.peer_timeout_forced:
        cell.result, cell.category = "not passing yet", "timeout"
        cell.reason = "an app's own watchdog fired (DONE timeout_forced) before finishing normally"
    elif not cell.hdds_matched or not cell.peer_matched:
        cell.result, cell.category = "not passing yet", "discovery"
        cell.reason = "the two sides did not discover each other within the timeout window"
    elif not cell.sent_set_equals_expected:
        cell.result, cell.category = "not passing yet", "publisher"
        cell.reason = (
            f"{publisher_label}'s successful-send set ({cell.sent_set_size} entries) did not equal "
            f"the configured set of {count}"
        )
    elif cell.conflicting_duplicates:
        cell.result, cell.category = "not passing yet", "subscriber"
        cell.reason = (
            f"{subscriber_label} reported disagreeing content across repeated observations of "
            f"{len(cell.conflicting_duplicates)} sequence number(s)"
        )
    elif cell.missing_seq or cell.extra_seq:
        cell.result, cell.category = "not passing yet", "subscriber"
        cell.reason = (
            f"{subscriber_label}'s valid-sample set ({cell.distinct_valid_received} entries) did not "
            f"equal the publisher's sent set exactly (missing={len(cell.missing_seq)}, "
            f"extra={len(cell.extra_seq)})"
        )
    elif cell.invalid_samples:
        cell.result, cell.category = "not passing yet", "subscriber"
        cell.reason = (
            f"{subscriber_label} reported {len(cell.invalid_samples)} sample(s) with the wrong key "
            "or payload bytes"
        )
    elif not cell.vendor_fully_bound:
        cell.result, cell.category = "not passing yet", "vendor-proof"
        cell.reason = (
            f"could not bind both identities and a positive data count to this cell's topic in the "
            f"capture (method={cell.vendor_binding_method}: {cell.vendor_binding_error})"
        )
    else:
        cell.result, cell.category = "interoperates", "none"
        cell.reason = (
            f"{subscriber_label}'s valid-sample set matched {publisher_label}'s sent set exactly, "
            "and the capture bound both identities to this cell's topic with a positive data count"
        )


def gather_provenance(args, vendors: list[str]) -> dict:
    prov: dict = {"invocation": " ".join(sys.argv)}

    harness_dir = Path(__file__).resolve().parent
    harness_rev = subprocess.run(
        ["git", "-C", str(harness_dir), "rev-parse", "--short=12", "HEAD"],
        capture_output=True, text=True,
    ).stdout.strip() or "unknown"
    harness_dirty = subprocess.run(
        ["git", "-C", str(harness_dir), "status", "--porcelain"],
        capture_output=True, text=True,
    ).stdout.strip() != ""
    prov["harness"] = {"revision": harness_rev, "dirty": harness_dirty}

    build_info_cmd = remote_argv(args, f"{args.hdds_bin} --build-info")
    try:
        out = subprocess.run(build_info_cmd, capture_output=True, text=True, timeout=20)
        prov["hdds_binary"] = json.loads(out.stdout.strip()) if out.stdout.strip() else {
            "error": f"no output (stderr: {out.stderr.strip()[:300]})"
        }
    except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError) as exc:
        prov["hdds_binary"] = {"error": str(exc)}

    prov["peers"] = {}
    for v in vendors:
        image = args.images[v]
        entry: dict = {"image": image}
        id_cmd = remote_argv(args, f"{args.sudo} docker image inspect --format {{{{.Id}}}} {image}")
        try:
            out = subprocess.run(id_cmd, capture_output=True, text=True, timeout=20)
            entry["image_id"] = out.stdout.strip() or f"error: {out.stderr.strip()[:200]}"
        except (subprocess.TimeoutExpired, OSError) as exc:
            entry["image_id"] = f"error: {exc}"
        build_info_cmd = remote_argv(
            args, f"{args.sudo} docker run --rm --entrypoint cat {image} /opt/interop/BUILD_INFO"
        )
        try:
            out = subprocess.run(build_info_cmd, capture_output=True, text=True, timeout=20)
            text = out.stdout.strip()
            entry["build_info"] = json.loads(text) if text else {
                "error": f"no output (stderr: {out.stderr.strip()[:300]})"
            }
        except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError) as exc:
            entry["build_info"] = {"error": str(exc)}
        prov["peers"][v] = entry

    return prov


def write_reports(args, report: dict) -> None:
    json_path = args.outdir / "results.json"
    json_path.write_text(json.dumps(report, indent=2, default=vars))
    md_path = args.outdir / "results.md"
    md_path.write_text(render_markdown(report))
    print(f"\nwrote {json_path}", file=sys.stderr)
    print(f"wrote {md_path}", file=sys.stderr)


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--hdds-bin", required=True)
    ap.add_argument("--outdir", required=True, type=Path)
    ap.add_argument("--count", type=int, default=100)
    ap.add_argument("--timeout", type=int, default=30)
    ap.add_argument("--domain-base", type=int, default=DEFAULT_DOMAIN_BASE)
    ap.add_argument(
        "--iface", default="any",
        help='capture interface; "any" (default) is required for same-host '
        "traffic between a native process and a --network host container, "
        "which often never touches a single physical/bridge interface",
    )
    ap.add_argument(
        "--settle-ms", type=int, default=500,
        help="readiness settle all four apps apply after match, before the "
        "first write (INTEROP_SMOKE_SETTLE_MS); 0 disables it -- see README.md",
    )
    ap.add_argument(
        "--remote-host",
        default=None,
        help=(
            "run docker/tcpdump/the HDDS binary over `ssh <this>` instead of "
            "locally (only needed if your Docker host is not the machine "
            "running this script)"
        ),
    )
    ap.add_argument(
        "--sudo",
        default="",
        help='prefix for docker/tcpdump, e.g. "sudo -n" if your user needs it for either',
    )
    ap.add_argument("--vendors", default="cyclonedds,fastdds,opendds")
    for v in DEFAULT_IMAGES:
        ap.add_argument(f"--image-{v}", default=DEFAULT_IMAGES[v])
    args = ap.parse_args()

    if args.count <= 0:
        print("--count must be a positive number", file=sys.stderr)
        return 1

    args.images = {v: getattr(args, f"image_{v}") for v in DEFAULT_IMAGES}
    args.outdir.mkdir(parents=True, exist_ok=True)

    vendors = [v.strip() for v in args.vendors.split(",") if v.strip()]
    run_id = secrets.token_hex(4)

    report = {
        "date": time.strftime("%Y-%m-%d"),
        "run_id": run_id,
        "count_per_cell": args.count,
        "settle_ms": args.settle_ms,
        "topic_prefix": TOPIC_PREFIX,
        "type": TYPE_NAME,
        "vendors": {v: VENDOR_META[v] for v in vendors},
        "cells": [],
    }

    any_failed = False
    domain = args.domain_base
    try:
        for vendor in vendors:
            for direction in DIRECTIONS:
                for reliability in RELIABILITIES:
                    print(
                        f"[{vendor}] {direction} / {reliability} (domain {domain}, "
                        f"topic {TOPIC_PREFIX}-{vendor}_{direction}_{reliability}-{run_id})",
                        file=sys.stderr,
                    )
                    try:
                        cell = run_cell(args, vendor, direction, reliability, domain, run_id)
                    except Exception:  # noqa: BLE001 -- one cell's crash must not lose the rest
                        cell = CellResult(
                            vendor=vendor, direction=direction, reliability=reliability,
                            domain=domain, topic="", challenge=0,
                            hdds_role="pub" if direction == "hdds_to_peer" else "sub",
                            peer_role="sub" if direction == "hdds_to_peer" else "pub",
                            result="not passing yet", category="harness-error",
                            reason=f"the harness itself raised: {traceback.format_exc(limit=3)}",
                        )
                    report["cells"].append(cell)
                    if cell.result != "interoperates":
                        any_failed = True
                    print(f"  -> {cell.result} ({cell.category}): {cell.reason}", file=sys.stderr)
                    domain += 1
    finally:
        # Provenance is gathered once, after the cells (so a crash mid-matrix
        # still gets a provenance block appended if there is time) -- but the
        # partial cell list is written NO MATTER WHAT, including on Ctrl-C or
        # an unhandled exception elsewhere in this block.
        try:
            report["provenance"] = gather_provenance(args, vendors)
        except Exception:  # noqa: BLE001
            report["provenance"] = {"error": traceback.format_exc(limit=3)}
        write_reports(args, report)

    return 1 if any_failed else 0


def render_markdown(report: dict) -> str:
    lines = []
    lines.append("# HDDS cross-vendor interop smoke test")
    lines.append("")
    prov = report.get("provenance", {})
    hdds_bin_info = prov.get("hdds_binary", {})
    harness = prov.get("harness", {})
    lines.append(
        f"Date: {report['date']}  |  Run id: `{report.get('run_id', '?')}`  |  "
        f"Type: `{report['type']}`  |  {report['count_per_cell']} samples per cell  |  "
        f"Readiness settle: {report.get('settle_ms', '?')} ms (disclosed, same on all four apps -- see README)"
    )
    lines.append(
        f"HDDS binary: git `{hdds_bin_info.get('git_sha', '?')}` "
        f"(dirty={hdds_bin_info.get('git_dirty', '?')}), sha256 `{hdds_bin_info.get('sha256', '?')}`  |  "
        f"Harness revision: git `{harness.get('revision', '?')}` (dirty={harness.get('dirty', '?')})"
    )
    lines.append("")
    lines.append(f"Invocation: `{prov.get('invocation', '?')}`")
    lines.append("")
    lines.append(
        "This reports how HDDS interoperates with each project below, not a "
        "ranking or a performance comparison. A cell marked \"not passing "
        "yet\" is something we are still investigating on the HDDS side; it "
        "is not a claim about the peer project."
    )
    lines.append("")
    lines.append("## Peers (resolved build provenance)")
    lines.append("")
    for v, meta in report["vendors"].items():
        peer_prov = prov.get("peers", {}).get(v, {})
        lines.append(f"- **{meta['display']}** {meta['version']} -- {meta['license']} -- {meta['url']}")
        lines.append(f"  - image: `{peer_prov.get('image', '?')}`, image id: `{peer_prov.get('image_id', '?')}`")
        lines.append(f"  - resolved build info: `{json.dumps(peer_prov.get('build_info', {}))}`")
    lines.append("")
    lines.append("## Results")
    lines.append("")
    lines.append(
        "| Peer | Direction | Reliability | Result | Category | Samples confirmed | "
        "Peer+HDDS bound on wire | Notes |"
    )
    lines.append("|---|---|---|---|---|---|---|---|")
    for c in report["cells"]:
        c = vars(c) if not isinstance(c, dict) else c
        meta = report["vendors"].get(c["vendor"], {"display": c["vendor"]})
        direction_label = (
            "HDDS -> peer" if c["direction"] == "hdds_to_peer" else "peer -> HDDS"
        )
        samples = f"{c.get('distinct_valid_received', 0)}/{c.get('sent_set_size', '?')}"
        bound = "yes" if c.get("vendor_fully_bound") else "no"
        lines.append(
            f"| {meta['display']} | {direction_label} | {c['reliability']} | "
            f"{c['result']} | {c.get('category', '')} | {samples} | {bound} | {c['reason']} |"
        )
    lines.append("")
    lines.append(
        "Samples confirmed = sequence numbers for which the subscriber's reported key and "
        "challenge-derived payload bytes were fully validated against the publisher's exact "
        "sent set (no missing, no extra, no conflicting duplicate), out of the publisher's "
        "reported successful-send count. Peer+HDDS bound on wire = `pcap-diff` found, on THIS "
        "cell's own (unique, per-run) topic name, an endpoint of the expected peer vendor, an "
        "endpoint of HDDS, and a writer/reader match between them with a positive data count -- "
        "independent of either side's own stdout, and bound to this specific exchange rather than "
        "to \"that vendorId appeared somewhere in the capture\"."
    )
    lines.append("")
    lines.append(
        "Reproduce: `python3 scripts/interop-smoke/run-matrix.py --hdds-bin "
        "<release interop_smoke binary> --outdir <dir>` from a Docker-capable "
        "Linux host with `tcpdump` (see README.md for working directories and permissions)."
    )
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    sys.exit(main())
