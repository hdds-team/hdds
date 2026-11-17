# docker-interop - parallel OMG dds-rtps interop testing

Runs the OMG `dds-rtps` interoperability matrix in **network-isolated Docker
containers, in parallel**.

## Why

The matrix is serial today because RTPS discovery uses UDP multicast: two pairs
on the same host/LAN cross-discover and corrupt each other's results. We give
**each pair its own Docker bridge** (separate L2 segment) so multicast can't
leak between pairs, then run many pairs at once with per-pair CPU pinning.

## Isolation model (the important bit)

- One **container per pair** - the harness itself spawns both publisher and
  subscriber, so pub+sub are co-located in one container/netns.
- One **dedicated NORMAL bridge per pair**. NOT `--internal` (no default route,
  so the multicast join fails `ENODEV` and discovery dies silently). NOT
  `--network none` (some vendors hard-bind a non-loopback NIC).
- Proven: 2 pairs on a shared bridge corrupt each other (the harness reports
  short sample counts on both); on separate bridges they pass cleanly.

## Usage

```bash
# 1. Build the fat image (bundles all vendor shape_main + the harness).
#    BIN_SRC must point at your vendor shape_main mirror (the OMG-CI-
#    predictive release-mirror set); there is no universal default, see
#    "Vendor binaries" below.
BIN_SRC=/path/to/your/release-mirror bash build-image.sh

# 2. Run the full HDDS matrix (self + 8 vendors x2 dirs = 17 pairs), full suite.
python3 orchestrate.py --matrix hdds --outdir /tmp/hdds-interop-out/full

# Restrict to specific tests:
python3 orchestrate.py --matrix hdds --tests Test_Reliability_0 Test_Ownership_0

# One pair by hand:
bash run-pair.sh hdds-1.3.0_shape_main_linux \
    toc_coredx_dds-6.15.0_shape_main_linux hdds-coredx -t Test_Reliability_0
```

Per-pair JUnit XML + captured log land in `--outdir` as `<tag>.xml` / `<tag>.log`.
`orchestrate.py` prints a pass/total summary at the end. Live progress of a
running pair: `docker logs hddsio-<tag>`.

The `-P`/`-S`/`-x`/`-t`/`-o` flags in the example above belong to the OMG
harness itself (`interoperability_report.py`, pulled in from `HARNESS_SRC` at
image-build time, not part of this repo) - confirmed by reading its
`argparse` definitions. Any other harness flag (`-v`, `-a`, `-s`, `-d`, ...) is
its own and not documented here; run `python3 interoperability_report.py --help`
against your `HARNESS_SRC` checkout for the current, authoritative list -
that has not been re-verified in this pass beyond the five flags used above.

## Vendor binaries

`build-image.sh` bundles every `*_shape_main_linux` binary found under
`BIN_SRC` into the image, under `bin/<basename>`. `BIN_SRC` has **no baked-in
default that works out of the box**: every site keeps its OMG-CI-predictive
release mirror somewhere different, and shipping one particular internal path
as the default would silently point an outsider's build at nothing. Set it
explicitly:

```bash
BIN_SRC=/path/to/your/release-mirror bash build-image.sh
```

If `BIN_SRC` is not set, the script falls back to a `vendor-bin/` directory
next to `build-image.sh` - stage your own binaries there if you would rather
not export the variable every time. Either way, use the **release-mirror**
set (the versions the official OMG CI actually runs), not an ad hoc `/opt`
grab-bag build tree: the whole point of this harness is to reproduce what the
official run measures.

## Substituting a binary (the bind-mount override)

This is the single most-used capability of this rig: testing a freshly built
candidate WITHOUT rebuilding the image. `run-pair.sh` supports it directly via
`PUB_BIN` / `SUB_BIN`:

```bash
PUB_BIN=/path/to/candidate/hdds-1.3.0_shape_main_linux \
    bash run-pair.sh hdds-1.3.0_shape_main_linux \
    toc_coredx_dds-6.15.0_shape_main_linux hdds-coredx -t Test_Reliability_0
```

**The convention: mount the candidate binary OVER an existing vendor
filename, never under a new one.** `PUB_BIN`'s file is bind-mounted onto
`bin/hdds-1.3.0_shape_main_linux` inside the container (the same path the
image already bakes that vendor entry in at); the `-P`/`-S` argument passed
to the harness is byte-identical to a normal run, only the executable bytes
behind it differ.

This matters because the harness identifies a side purely from the basename
of the path it was given: `interoperability_report.py` derives its JUnit
report label by stripping the `_shape_main*` suffix off `-P`/`-S`
(`options['publisher'].split('_shape')[0].split('-shape')[0].split('/')[-1]`,
read directly from the harness source for this doc). `orchestrate.py`'s
matrix and its preflight binary check (`preflight_binaries`) work the same
way, off the fixed basenames in its own vendor table. Mount your candidate
under a NEW filename and either the harness mislabels the report (a
candidate reported as if it were some other, unrelated vendor) or the
preflight check simply cannot find it. Keeping the filename identical is
what keeps the report, and the matrix bookkeeping, honest about what actually
ran.

`run-pair.sh` refuses to start if `PUB_BIN`/`SUB_BIN` does not exist or is
not executable, and resolves it to an absolute path before mounting (a
relative `-v` source is a Docker named-volume request, not a bind mount, and
would silently mount an empty volume instead of your binary).

## Capturing a pcap for a pair

There is no dedicated capture build target in `build-image.sh`/`Dockerfile`
yet. In past debugging sessions an ad hoc `hdds-interop-cap:latest` image
(the interop image plus `tcpdump` and `tc`) has been built by hand for this;
it is not defined anywhere in this repo, so treat the following as guidance,
not a guarantee:

- Its baked-in `bin/` binaries are frozen at whatever the mirror held the day
  it was built, and go stale exactly like the plain image's do. Do not trust
  what is baked in for a capture against a CURRENT candidate - use the same
  bind-mount override as any other run: `IMAGE=hdds-interop-cap:latest
  PUB_BIN=... SUB_BIN=... bash run-pair.sh ...`.
- Capturing inside the container (via `tcpdump`/`tc`) needs Linux
  capabilities (`NET_ADMIN` at least) that plain `docker run` does not grant
  and that `run-pair.sh` does not currently request. Until that is added as
  a proper knob, build the `docker run` line by hand from `run-pair.sh`'s own
  invocation (same network, same mounts, same `-P`/`-S`/`-x`/`-o` arguments)
  with `--cap-add=NET_ADMIN` (and `--cap-add=NET_RAW` if the image's Docker
  default does not already include it) added.
- **Unverified in this pass**: this doc did not build or run `hdds-interop-cap`
  (the rig is a shared machine and this was a read-only documentation task),
  so its entrypoint, its exact capture invocation, and where inside the
  container it writes the capture file are not confirmed here. Check with
  `docker inspect --format '{{.Config.Entrypoint}} {{.Config.Cmd}}'
  hdds-interop-cap:latest` before trusting a capture from it, or rebuild it
  from scratch with a `Dockerfile` derived from this one plus `tcpdump`.

## Knobs

| env / flag              | default                     | meaning                              |
|--------------------------|-----------------------------|--------------------------------------|
| `--matrix`               | `hdds`                      | `hdds` (17 pairs) or `full` (NxN)    |
| `--tests T1 T2 ...`      | full suite                  | restrict test cases                  |
| `--cores-per-pair K`     | 4                           | cores pinned per pair (cpuset)       |
| `--max-pairs N`          | min(24, (ncores-2)//K)      | concurrency cap                      |
| `--outdir DIR`           | `/tmp/hdds-interop-out`     | per-pair XML/log output              |
| `BIN_SRC` (build-image)  | `./vendor-bin` next to the script | vendor `*_shape_main_linux` source dir |
| `HARNESS_SRC` (build-image) | `/opt/dds-rtps`          | OMG harness `.py` source dir         |
| `IMAGE` (run-pair)       | `hdds-interop:latest`       | image tag                            |
| `DATAREP` (run-pair)     | `2`                         | `-x` data representation (1/2)       |
| `PUB_BIN` (run-pair)     | unset                       | host binary to substitute for the pub-side vendor file |
| `SUB_BIN` (run-pair)     | unset                       | host binary to substitute for the sub-side vendor file |

## Files

- `Dockerfile` - fat ubuntu:22.04 image (vendor binaries + harness).
- `build-image.sh` - assembles build context + `docker build`.
- `run-pair.sh` - one isolated pair (bridge create, run, cleanup); supports
  substituting a binary without a rebuild (see above).
- `orchestrate.py` - asyncio matrix runner + cpuset pool + JUnit summary.
