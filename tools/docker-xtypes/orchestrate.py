#!/usr/bin/env python3
"""Parallel OMG dds-xtypes interop matrix runner.

Sibling of tools/docker-interop/orchestrate.py (dds-rtps), adapted for the
dds-xtypes suite. Runs many pub/sub pairs concurrently, each in its own
network-isolated container (see run-pair.sh), with per-pair CPU pinning.

Each pair sweeps the 4 OMG dimensions = (data-representation -x {1,2}) x
(--type-object-version {1,2}) -> 4 JUnit XMLs per pair (<tag>_<dim>.xml). The
summary aggregates per-pair per-dim pass/total + a grand total.

Isolation is guaranteed by one dedicated NORMAL Docker bridge per pair (proven
in the rtps harness: a shared bridge cross-talks and corrupts sample counts).
Concurrency is gated by a fixed pool of disjoint cpusets -- acquiring a cpuset
IS the semaphore, which also enforces pinning.

Usage:
    orchestrate.py [--matrix hdds] [--tests T1 T2 ...] [--dims D ...]
                   [--cores-per-pair K] [--max-pairs N] [--outdir DIR]

Default matrix "hdds" = HDDS-self + HDDS vs {connext,cyclone,coredx} both
directions (7 pairs).
"""
import argparse
import asyncio
import os
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
RUN_PAIR = HERE / "run-pair.sh"

# Binary basenames as they appear in the fat image under /opt/dds-xtypes/bin/.
HDDS = "hdds_xtypes_shape_main_linux"
VENDORS = {
    "connext": "connext_dds-7.7.0_test_main_linux",
    "cyclone": "eclipse_cyclone-11.0.1_test_main_linux",
    "coredx":  "toc_coredx_dds-6.14.1_test_main_linux",
}

ALL_DIMS = ["xcdr1_to1", "xcdr1_to2", "xcdr2_to1", "xcdr2_to2"]


def build_matrix(kind: str, hdds=HDDS):
    """Return a list of (pub_binary, sub_binary, tag) pairs."""
    pairs = [(hdds, hdds, "hdds-hdds")]
    if kind == "hdds":
        for name, binary in VENDORS.items():
            pairs.append((hdds, binary, f"hdds-{name}"))
            pairs.append((binary, hdds, f"{name}-hdds"))
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
    # Hard ceiling: 8 covers the 7-pair hdds wave with headroom.
    n_slots = max(1, min(n_slots, 8))
    pool = []
    for i in range(n_slots):
        lo = 2 + i * cores_per_pair
        hi = lo + cores_per_pair - 1
        pool.append(f"{lo}-{hi}")
    return pool


async def run_one(pub, sub, tag, cpuset, outdir, tests, dims, timeout):
    env = dict(os.environ, CPUSET=cpuset, OUTDIR=outdir, DIMS=" ".join(dims))
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
        # A pair must never wedge the whole matrix past its budget. Kill the
        # launcher and force-remove THIS pair's containers + network only
        # (never a global pkill -- a host self-sweep may be running).
        timed_out = True
        proc.kill()
        import subprocess
        for dim in dims:
            subprocess.run(["docker", "rm", "-f", f"hddsxt-{tag}-{dim}"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["docker", "network", "rm", f"hddsxt-{tag}"],
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
    """Fail fast if any referenced binary is missing/non-exec in the image."""
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
            f"  -> add them in build-image.sh + rerun ./build-image.sh."
        )


async def main_async(args):
    outdir = args.outdir
    Path(outdir).mkdir(parents=True, exist_ok=True)
    pairs = build_matrix(args.matrix, args.hdds_bin)
    dims = args.dims or ALL_DIMS
    image = os.environ.get("IMAGE", "hdds-xtypes-interop:latest")
    await preflight_binaries(pairs, image)
    cpuset_pool = make_cpuset_pool(args.cores_per_pair, args.max_pairs)
    print(f"matrix={args.matrix}  pairs={len(pairs)}  dims={dims}  "
          f"concurrency={len(cpuset_pool)} (cpusets {cpuset_pool})  "
          f"pair-timeout={args.pair_timeout}s")
    tests = (["-t", *args.tests] if args.tests else [])

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
            r = await run_one(pub, sub, tag, cpuset, outdir, tests, dims,
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
    summarize(outdir, pairs, dims)
    return 0


def _count_xml(xml_path):
    from junitparser import JUnitXml
    xml = JUnitXml.fromfile(str(xml_path))
    ok = tot = 0
    for suite in xml:
        for case in suite:
            tot += 1
            if not (case.result and any(
                    r.__class__.__name__ in ("Failure", "Error")
                    for r in case.result)):
                ok += 1
    return ok, tot


def summarize(outdir, pairs, dims):
    """Per-pair per-dim pass/total from the JUnit XMLs."""
    try:
        import junitparser  # noqa: F401
    except ImportError:
        print("(junitparser not available on host; per-pair XMLs in", outdir, ")")
        return
    print("\n=== summary (pass/total per dim) ===")
    header = f"{'pair':20s} " + " ".join(f"{d:>11s}" for d in dims) + f"  {'TOTAL':>9s}"
    print(header)
    grand_ok = grand_tot = 0
    for _, _, tag in pairs:
        cells = []
        row_ok = row_tot = 0
        for dim in dims:
            xml_path = Path(outdir) / f"{tag}_{dim}.xml"
            if not xml_path.exists():
                cells.append(f"{'NO-XML':>11s}")
                continue
            try:
                ok, tot = _count_xml(xml_path)
            except Exception:
                cells.append(f"{'XML-ERR':>11s}")
                continue
            row_ok += ok
            row_tot += tot
            cells.append(f"{ok:4d}/{tot:<4d}".rjust(11))
        grand_ok += row_ok
        grand_tot += row_tot
        total_cell = f"{row_ok:4d}/{row_tot:<4d}"
        print(f"{tag:20s} " + " ".join(cells) + f"  {total_cell:>9s}")
    print(f"\n{'GRAND TOTAL':20s} {grand_ok}/{grand_tot}")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--matrix", default="hdds", choices=["hdds"])
    ap.add_argument("--hdds-bin", default=HDDS,
                    help="HDDS xtypes driver basename in the image "
                         "(default hdds_xtypes_shape_main_linux).")
    ap.add_argument("--tests", nargs="+", default=None,
                    help="restrict to these test cases (default: full suite)")
    ap.add_argument("--dims", nargs="+", default=None, choices=ALL_DIMS,
                    help="restrict to these dimensions (default: all 4)")
    ap.add_argument("--cores-per-pair", type=int, default=4)
    ap.add_argument("--pair-timeout", type=int, default=4500,
                    help="per-pair wall timeout in seconds. A pair runs all 4 "
                         "dims serially (~12-15min each full) -> default 4500=75min.")
    ap.add_argument("--max-pairs", type=int, default=None)
    ap.add_argument("--outdir", default="/tmp/hdds-xtypes-out")
    args = ap.parse_args()
    sys.exit(asyncio.run(main_async(args)))


if __name__ == "__main__":
    main()
