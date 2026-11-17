# interop-smoke

A reproducible, scripted check of how HDDS interoperates over plain RTPS/UDP
with a small set of independent open-source DDS implementations. It replaces
an older, unverifiable results table: every number here comes from a run
anyone can repeat, with the commands and raw logs to back it up.

This is **not** a ranking, a score, or a performance comparison between
projects. It reports HDDS's own interoperability with each peer listed
below. Where a cell has not passed yet, that is logged as something for the
HDDS side to keep investigating -- never as a claim about the peer project.
Any vendor-specific quirk this testing turns up is handled in HDDS's own
vendor-compatibility code, not published here as someone else's defect.

## Peers

| Project | License | Source |
|---|---|---|
| [Eclipse Cyclone DDS](https://github.com/eclipse-cyclonedds/cyclonedds) | EPL-2.0 OR BSD-3-Clause | built from the pinned release tag in `vendors/cyclonedds/Dockerfile` |
| [eProsima Fast DDS](https://github.com/eProsima/Fast-DDS) | Apache-2.0 | built from the pinned release tag in `vendors/fastdds/Dockerfile` |
| [OpenDDS](https://github.com/OpenDDS/OpenDDS) | OpenDDS License (permissive; see the project's LICENSE file) | built from the pinned release tag in `vendors/opendds/Dockerfile` |

Each Dockerfile builds its project from the project's own upstream source at
a pinned tag (never a moving branch) -- for OpenDDS this also pins its
ACE_TAO and MPC dependencies to fixed commits, resolved and recorded the day
this was written (see each Dockerfile's comments; OpenDDS's own CI tracks
the same ACE_TAO branch unpinned, so re-resolving periodically is expected
maintenance, not a one-time fix). Rebuilding gives the same pinned *source*;
C/C++ toolchains are not bit-reproducible builds, so this does not promise
byte-identical binaries -- that is what each image's embedded `BUILD_INFO`
(resolved commits + the shipped binary's sha256, see below) is for: it lets
anyone compare what they built against what a given results.json recorded,
rather than relying on an unverified "trust me" claim.

## What it tests

A single shared type, `InteropPing` (`idl/InteropPing.idl`):

```idl
@final
struct InteropPing {
    @key long key;
    unsigned long seq;
    octet payload[32];
};
```

For each peer, for both directions (HDDS publishing / the peer subscribing,
and the reverse) and both reliability kinds (`RELIABLE`, `BEST_EFFORT`), one
side runs HDDS's own `interop_smoke` example
(`crates/hdds/examples/interop_smoke.rs`) natively and the other runs the
peer's container (`--network host`, so ordinary RTPS/UDP multicast discovery
works exactly as it would between two local processes). Each cell gets its
own unique topic name (so a stale participant from an earlier cell can never
be mistaken for this one) and a random payload challenge (so a hardcoded or
replayed response cannot pass as a real exchange -- see below). The
publisher sends the configured number of samples with a deterministic,
challenge-keyed payload (`payload[i] = (seq + i + challenge) % 256`); the
subscriber prints every sample it receives, including duplicates.

### The readiness settle (disclosed, symmetric, same on all four apps)

Each app's publisher sleeps `INTEROP_SMOKE_SETTLE_MS` (an env var, default
500 ms, `--settle-ms` on the matrix script) right after `EVENT matched` and
before its first write. The value and the placement are identical across
HDDS, CycloneDDS, Fast DDS and OpenDDS -- it is not tuned per peer, and
`INTEROP_SMOKE_SETTLE_MS=0` reproduces the no-settle behavior on the exact
same build for anyone who wants to see it. Each `results.md` header records
the settle value a given run used.

**What running without it actually showed (count=100,
`--settle-ms 0`, full 12-cell matrix, every other check -- exact sets,
topic-bound vendor proof -- unchanged):** 11 of 12 cells still reached
`interoperates` with no settle at all. The one exception was Fast DDS
publishing to HDDS, BEST_EFFORT: HDDS's subscriber reported exactly 67 of
100 samples, missing precisely sequence numbers 0-32 -- the first third of
the run, nothing after. The same role (HDDS as the BEST_EFFORT subscriber of
a foreign publisher) passed cleanly against both CycloneDDS and OpenDDS in
the same no-settle run, so this is not "HDDS subscribers are generally too
slow"; it is specific to this pairing's timing, consistent with HDDS's
reader not always being ready for the very first datagrams immediately
after it reports `EVENT matched`, with Fast DDS's publish-after-match
latency apparently narrow enough to land inside that window where
CycloneDDS's and OpenDDS's did not in this run. A second independent
no-settle run (same day, same build) reproduced the identical pattern --
`missing=32`, sequences 0-31 -- in the SAME cell (Fast DDS publishing to
HDDS, BEST_EFFORT), and additionally in the RELIABLE cell of the same
pairing, with the exact same count. The packet timeline established that
the writer's DATA 1-32 could arrive before its SEDP publication. HDDS discarded those datagrams because its
writer-GUID-to-topic mapping did not exist yet, although each DATA already
named the local reader in its `readerId`. In a failing RELIABLE capture,
the only user HEARTBEAT preceded SEDP and advertised an empty writer
(firstSN=1, lastSN=0); no later user HEARTBEAT, ACKNACK or GAP occurred
before the publisher exited. VOLATILE does not excuse losing writes made
after the writer knew this reader (DDS 1.4 2.2.3.4).

HDDS now resolves an explicitly addressed local reader on that discovery
miss and lets its bounded unresolved-writer holding area defer the sample.
Discovery still checks type and QoS before delivery, and deferred samples
are not acknowledged early. Reliable evictions keep their original delivery
floor and remain available for HEARTBEAT/ACKNACK repair. An unknown readerId
still provides no topic to route by. The settle remains a disclosed,
symmetric option; `--settle-ms 0` exercises the immediate-write path.

## How the verdict is computed

`run-matrix.py` never greps for the word "PASSED". A cell is **interoperates**
only if ALL of the following hold, checked against exact evidence, not
approximations:

- neither side's watchdog fired (`DONE timeout_forced`) and both processes
  exited 0 -- a timeout or a nonzero exit is always a hard failure, no
  matter how complete the sample history otherwise looks;
- both sides reported `EVENT matched` within the timeout;
- the publisher's own count of *successful* writes (`SENT seq=N` lines, not
  the configured `--count` blindly) equals the configured count exactly;
- the subscriber's validated set equals that sent set exactly -- no missing
  sequence, no extra one, every observed key correct, every observed
  payload matching the challenge-keyed pattern; a sequence number that
  arrives twice with two *different* payloads is a logged defect
  (`conflicting_duplicate_seq`), never resolved by keeping the later one;
- the peer's identity is bound to this specific cell: `vendor_report.py`
  hands the capture to the `pcap-diff` tool (a separate project, expected on PATH) and requires an
  endpoint of the claimed peer vendor AND an HDDS endpoint, BOTH announced
  on this cell's own unique topic, paired in a writer/reader matching
  record with a positive data count. This is strictly stronger than "the
  peer's RTPS vendorId appeared somewhere in the capture" -- two unrelated
  participants on two different domains, or a stale leftover capture, can
  satisfy that weaker check without proving anything about this cell. The
  capture itself must also have started successfully and be no older than
  the cell it claims to cover (`vendor_report.check_binding`'s
  `capture_not_before`); a capture that never started, or one found to be
  stale, fails this check rather than being silently skipped.

Otherwise the cell is **not passing yet**, with the first disqualifying
reason (and the raw logs + pcap to look at) recorded alongside it.

### tcpdump setup

`run-matrix.py` captures with `tcpdump -i any` by default (`--iface` to
override). `any` matters here, not a physical NIC name: on this same-host
setup (a natively-run HDDS process and a `--network host` container sharing
one network namespace), RTPS traffic between them is delivered by the
kernel without necessarily crossing a physical interface's capture point --
capturing on a specific NIC like `enp3s0` missed SEDP and user DATA
submessages entirely in early runs of this tool, finding only SPDP traffic
that happened to also reach the physical link. `-i any` (or `lo`, if your
setup's traffic is confirmed to only ever use loopback) sees the kernel's
internal delivery path too.

This needs `tcpdump` installed (`apt-get install tcpdump` / `dnf install
tcpdump` / etc.) and either root or the capability to capture raw sockets
(`sudo` -- pass the exact prefix your setup needs via `--sudo "sudo -n"` or
similar; empty by default, which only works if your user can already
capture packets without it, e.g. via `setcap cap_net_raw,cap_net_admin+eip
$(which tcpdump)`).

## Running it

Requires a Linux host with Docker, `tcpdump` (see above), `pcap-diff` on
PATH (strongly recommended -- without it, the vendor binding check falls
back to a weaker presence-only proof that `run-matrix.py` never accepts as
sufficient for "interoperates"; see `vendor_report.py`), and a release
build of the HDDS side. Commands below show the working directory each
needs -- `cargo build` runs from the **repository root**, the `docker
build` context for each vendor is **that vendor's own subdirectory under
`scripts/interop-smoke/vendors/`**, and `run-matrix.py` can run from
anywhere (paths you pass it, like `--hdds-bin`, should be absolute or
relative to wherever you invoke it from):

```bash
# from the repository root:
cargo build --release --example interop_smoke -p hdds

# from scripts/interop-smoke/ (each vendor's Dockerfile COPYs files relative
# to its own subdirectory, so the build context IS that subdirectory, not
# the repo root and not scripts/interop-smoke/ itself):
cd scripts/interop-smoke
docker build -t hdds-interop-smoke-cyclonedds:11.0.1 -f vendors/cyclonedds/Dockerfile vendors/cyclonedds
docker build -t hdds-interop-smoke-fastdds:3.6.2     -f vendors/fastdds/Dockerfile     vendors/fastdds
docker build -t hdds-interop-smoke-opendds:3.34.0    -f vendors/opendds/Dockerfile    vendors/opendds

# from the repository root (or adjust --hdds-bin accordingly):
python3 scripts/interop-smoke/run-matrix.py \
    --hdds-bin target/release/examples/interop_smoke \
    --outdir /path/to/results
```

`run-matrix.py` drives the whole matrix on its own: it starts a `tcpdump`
capture per cell, runs both peers, stops the capture, and writes
`results.json` (machine-readable, one entry per cell with every field above,
plus a `provenance` section: the HDDS binary's git sha/dirty flag/sha256
from its own `--build-info`, this harness's own git revision, and each
peer image's Docker image ID and embedded `BUILD_INFO`) and `results.md`
(the table) into `--outdir`. Results are written after every cell, not only
at the end, so a crash mid-run still leaves a readable partial report; the
script exits nonzero if any requested cell did not reach "interoperates" or
the run did not complete. Each cell gets its own domain ID (`--domain-base`,
default 210, one domain per cell) and its own topic name so cells never
cross-discover each other, and its own log files and pcap under
`--outdir/logs/` and `--outdir/pcaps/` for anyone who wants to look closer
at a specific result.

Useful flags: `--count` (samples per cell, default 100, must be positive),
`--timeout` (seconds; the discovery wait AND the receive/send phase are
each separately budgeted this much -- each app's own watchdog backstop is
`2*timeout + 10..15`, so very short timeouts still leave room for both
phases), `--key` (default 42), `--vendors` (comma list to run a subset),
`--iface` (capture interface/pseudo-interface, default `any` -- see
"tcpdump setup" above), `--settle-ms` (default 500, see "The readiness
settle" above), `--remote-host`/`--sudo` (drive a *different*
Docker-capable host over ssh, e.g. our own house rule that keeps Docker/load
work off the dev box -- empty/local by default, which is what an external
user wants; `--remote-host` also needs `scp` to that host working from
wherever `run-matrix.py` runs, used to pull each cell's capture directly
rather than through a shared filesystem).

### Running a single peer by hand

The `interop_smoke` binary and each peer's container speak the same CLI, so
a single direction/reliability pair can be run directly without the matrix
script, e.g.:

```bash
# terminal 1 (peer, subscribing):
docker run --rm --network host hdds-interop-smoke-cyclonedds:11.0.1 \
    --mode sub --domain 210 --topic InteropSmokeManual --reliability reliable \
    --count 100 --key 42 --timeout 30

# terminal 2 (HDDS, publishing):
target/release/examples/interop_smoke \
    --mode pub --domain 210 --topic InteropSmokeManual --reliability reliable \
    --count 100 --key 42 --challenge 17 --timeout 30
```

`--challenge` (0-255, default 0) only changes what a publisher embeds into
the payload (`(seq + i + challenge) % 256`); a subscriber reports raw hex
either way, so it only needs `--challenge` for CLI uniformity, never to
decode anything. `INTEROP_SMOKE_SETTLE_MS` (env var, default 500) controls
the readiness settle on whichever side is publishing. Every binary also
answers `--build-info` on its own (`interop_smoke --build-info`; for a
vendor image, `docker run --rm --entrypoint cat <image> /opt/interop/BUILD_INFO`)
with its provenance -- git sha/dirty/sha256 for HDDS, resolved upstream
commits + binary sha256 for a vendor image.

## Files

- `idl/InteropPing.idl` -- the shared type, compiled as-is by every peer's
  own IDL compiler.
- `vendors/<name>/Dockerfile` -- builds that peer from its pinned upstream
  source, plus a small pub/sub app implementing the shared CLI contract,
  and bakes a `BUILD_INFO` provenance file into the image.
- `run-matrix.py` -- orchestrates the full matrix, computes the verdict from
  exact evidence, gathers provenance, and writes the report.
- `vendor_report.py` -- the topic/GUID-bound peer-identity + data-flow proof
  (`check_binding`), via `pcap-diff` when available, with a clearly-labelled
  weaker presence-only fallback otherwise.
- `results/` is **not** stored in this repo (see the project's own working
  notes); the output of a run is `results.json` + `results.md` + per-cell
  logs/pcaps wherever `--outdir` points.
