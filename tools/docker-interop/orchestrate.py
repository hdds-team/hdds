#!/usr/bin/env python3
"""Parallel OMG dds-rtps interop matrix runner.

Runs many pub/sub pairs concurrently, each in its own network-isolated
container (see run-pair.sh), with per-pair CPU pinning so deadline/latency
tests stay fair. Aggregates the per-pair JUnit XMLs into a summary.

Isolation is guaranteed by one dedicated Docker bridge per pair (proven: two
pairs on a shared bridge cross-talk and corrupt sample counts; on separate
bridges they pass cleanly). Concurrency is gated by a fixed pool of disjoint
cpusets -- acquiring a cpuset IS the semaphore, which also enforces pinning.

Usage:
    orchestrate.py [--matrix hdds|full] [--tests T1 T2 ...]
                   [--cores-per-pair K] [--max-pairs N] [--outdir DIR]

Default matrix "hdds" = HDDS-self + every vendor as both pub and sub (17 pairs).
"""
import argparse
import asyncio
import os
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
RUN_PAIR = HERE / "run-pair.sh"

# Release-mirror vendor binaries (OMG-CI-predictive set). Basenames as they
# appear in the fat image under /opt/dds-rtps/bin/.
HDDS = "hdds-1.3.0_shape_main_linux"
VENDORS = {
    "connext": "connext_dds-7.7.0_shape_main_linux",
    "cyclone": "eclipse_cyclone-11.0.1_shape_main_linux",
    "fastdds": "eprosima_fastdds-3.6.1_shape_main_linux",
    "coredx":  "toc_coredx_dds-6.15.0_shape_main_linux",
    "dust":    "dust_dds-0.15.0_shape_main_linux",
    "opendds": "opendds-3.35.0-dev_shape_main_linux",
    "intercom": "intercom_dds-4.3.1_shape_main_linux",
    "zzdds":   "zzdds-0.1.1_shape_main_linux",
}


def build_matrix(kind: str, hdds=HDDS):
    """Return a list of (pub_binary, sub_binary, tag) pairs."""
    pairs = [(hdds, hdds, "hdds-hdds")]
    if kind == "hdds":
        for name, binary in VENDORS.items():
            pairs.append((hdds, binary, f"hdds-{name}"))
            pairs.append((binary, hdds, f"{name}-hdds"))
    elif kind == "full":
        allv = {"hdds": HDDS, **VENDORS}
        names = list(allv)
        for i, p in enumerate(names):
            for j, s in enumerate(names):
                if i == j and p == "hdds":
                    continue  # self hdds already added
                pairs.append((allv[p], allv[s], f"{p}-{s}"))
    else:
        raise SystemExit(f"unknown matrix kind: {kind}")
    return pairs


def make_cpuset_pool(cores_per_pair: int, max_pairs: int | None):
    """Disjoint cpuset strings; cores 0-1 reserved for OS/orchestrator."""
    ncores = os.cpu_count() or 4
    usable = max(1, ncores - 2)
    n_slots = usable // cores_per_pair
    if max_pairs:
        n_slots = min(n_slots, max_pairs)
    # Hard ceiling: on a big host the cores // K limit dominates; on a small
    # one this caps RTPS/container churn. 24 covers the full HDDS 17-pair wave.
    n_slots = max(1, min(n_slots, 24))
    pool = []
    for i in range(n_slots):
        lo = 2 + i * cores_per_pair
        hi = lo + cores_per_pair - 1
        pool.append(f"{lo}-{hi}")
    return pool


async def run_one(pub, sub, tag, cpuset, outdir, tests, timeout):
    env = dict(os.environ, CPUSET=cpuset, OUTDIR=outdir)
    cmd = ["bash", str(RUN_PAIR), pub, sub, tag, *tests]
    t0 = time.monotonic()
    proc = await asyncio.create_subprocess_exec(
        *cmd, env=env,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
    )
    timed_out = False
    try:
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        # A pair must never wedge the whole matrix past its budget. Typical
        # cause: a vendor subscriber busy-spinning on a publisher that never
        # started (e.g. a missing/mis-named binary). Kill the launcher and
        # force-remove the pair's container + network, then move on.
        timed_out = True
        proc.kill()
        import subprocess
        subprocess.run(["docker", "rm", "-f", f"hddsio-{tag}"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["docker", "network", "rm", f"hddsio-{tag}"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            out, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
        except (asyncio.TimeoutError, Exception):
            out = b""
    dt = time.monotonic() - t0
    log = Path(outdir) / f"{tag}.log"
    log.write_bytes(out or b"")
    rc = "TIMEOUT" if timed_out else proc.returncode
    return tag, rc, dt


async def preflight_binaries(pairs, image):
    """Fail fast if any referenced binary is missing/non-exec in the image.

    Without this, a typo'd name (e.g. `hdds-devel` instead of the full
    `hdds-devel_shape_main_linux`) spawns pairs whose publisher never starts
    while the peer subscriber spins forever -> the matrix hangs past budget.
    One quick container check up front turns that into an instant clear error.
    """
    bins = sorted({b for pr in pairs for b in pr[:2]})
    check = "; ".join(f"test -x ./bin/{b} || echo MISSING:{b}" for b in bins)
    proc = await asyncio.create_subprocess_exec(
        "docker", "run", "--rm", "--entrypoint", "bash", image, "-c", check,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
    )
    out, _ = await proc.communicate()
    missing = [ln.split(":", 1)[1]
               for ln in out.decode(errors="replace").split()
               if ln.startswith("MISSING:")]
    if missing:
        raise SystemExit(
            f"ERROR: binaries missing from image '{image}': {', '.join(missing)}\n"
            f"  -> stage them in the mirror + run ./build-image.sh, "
            f"or fix --hdds-bin (must be the FULL basename incl _shape_main_linux)."
        )


async def main_async(args):
    outdir = args.outdir
    Path(outdir).mkdir(parents=True, exist_ok=True)
    pairs = build_matrix(args.matrix, args.hdds_bin)
    image = os.environ.get("IMAGE", "hdds-interop:latest")
    await preflight_binaries(pairs, image)
    cpuset_pool = make_cpuset_pool(args.cores_per_pair, args.max_pairs)
    print(f"matrix={args.matrix}  pairs={len(pairs)}  "
          f"concurrency={len(cpuset_pool)} (cpusets {cpuset_pool})  "
          f"pair-timeout={args.pair_timeout}s")
    tests = (["-t", *args.tests] if args.tests else [])

    # A queue of cpusets is the concurrency gate + the pinning assignment.
    slots: asyncio.Queue = asyncio.Queue()
    for c in cpuset_pool:
        slots.put_nowait(c)

    results = []
    done = 0
    total = len(pairs)
    lock = asyncio.Lock()

    async def worker(pub, sub, tag):
        nonlocal done
        cpuset = await slots.get()
        try:
            r = await run_one(pub, sub, tag, cpuset, outdir, tests,
                              args.pair_timeout)
        finally:
            slots.put_nowait(cpuset)
        async with lock:
            done += 1
            tag_, rc, dt = r
            status = "ok" if rc == 0 else f"rc={rc}"
            print(f"[{done}/{total}] {tag_:20s} {status:8s} {dt:6.1f}s")
        results.append(r)

    t0 = time.monotonic()
    await asyncio.gather(*(worker(p, s, t) for (p, s, t) in pairs))
    wall = time.monotonic() - t0
    print(f"\nTotal wall: {wall:.1f}s for {total} pairs")
    summarize(outdir, pairs)
    return 0


def summarize(outdir, pairs):
    """Per-pair pass/fail counts from the JUnit XMLs."""
    try:
        from junitparser import JUnitXml
    except ImportError:
        print("(junitparser not available on host; per-pair XMLs in", outdir, ")")
        return
    print("\n=== summary (pass/total) ===")
    grand_ok = grand_tot = 0
    for _, _, tag in pairs:
        xml_path = Path(outdir) / f"{tag}.xml"
        if not xml_path.exists():
            print(f"{tag:20s} NO-XML")
            continue
        try:
            xml = JUnitXml.fromfile(str(xml_path))
        except Exception as e:
            print(f"{tag:20s} XML-ERR {e}")
            continue
        ok = tot = 0
        for suite in xml:
            for case in suite:
                tot += 1
                if not (case.result and any(
                        r.__class__.__name__ in ("Failure", "Error")
                        for r in case.result)):
                    ok += 1
        grand_ok += ok
        grand_tot += tot
        print(f"{tag:20s} {ok:3d}/{tot:<3d}")
    print(f"{'TOTAL':20s} {grand_ok:3d}/{grand_tot:<3d}")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--matrix", default="hdds", choices=["hdds", "full"])
    ap.add_argument("--hdds-bin", default=HDDS,
                    help="HDDS shape_main basename in the image (default hdds-1.3.0). "
                         "Must also be bundled in the image (add to mirror + rebuild).")
    ap.add_argument("--tests", nargs="+", default=None,
                    help="restrict to these Test_* cases (default: full suite)")
    ap.add_argument("--cores-per-pair", type=int, default=4)
    ap.add_argument("--pair-timeout", type=int, default=1500,
                    help="per-pair wall timeout in seconds; a pair exceeding it "
                         "is killed and its container removed (default 1500=25min, "
                         "healthy full matrix wall is ~21min)")
    ap.add_argument("--max-pairs", type=int, default=None,
                    help="cap concurrent pairs (default: min(12, (ncores-2)//K))")
    ap.add_argument("--outdir", default="/tmp/hdds-interop-out")
    args = ap.parse_args()
    sys.exit(asyncio.run(main_async(args)))


if __name__ == "__main__":
    main()
