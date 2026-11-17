#!/usr/bin/env python3
"""Parallel OMG dds-xtypes DATA interop matrix runner (one HDDS variant per run).

Mirrors the dds-rtps docker_matrix_neo design: many pub/sub pairs run
concurrently, each in its own network-isolated container (run-pair.sh) with
per-pair CPU pinning; per-pair JUnit XMLs are aggregated. Isolation = one
dedicated Docker bridge per pair (proven for rtps). Concurrency gate = a fixed
pool of disjoint cpusets (acquiring one IS the semaphore + the pinning).

Engines: HDDS (feature OFF or ON, selected by --hdds-variant) + the 4 official
OMG dds-xtypes vendor binaries. Full pub x sub cross-product (5x5 = 25 pairs).

Usage:
    orchestrate.py --hdds-variant {on,off} [--outdir DIR] [--suite S]
                   [--cores-per-pair K] [--pair-timeout S]
"""
import argparse
import asyncio
import os
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
RUN_PAIR = HERE / "run-pair.sh"

VENDORS = {
    "connext": "connext_dds-7.7.0_test_main_linux",
    "cyclone": "eclipse_cyclone-11.0.1_test_main_linux",
    "coredx":  "toc_coredx_dds-6.14.1_test_main_linux",
    "opendds": "opendds-3.35.0-dev_test_main_linux",
}
HDDS_BIN = {"on": "hdds_on_shape_main_linux", "off": "hdds_off_shape_main_linux"}


def build_matrix(hdds_bin):
    """Full 5x5 cross-product (pub, sub, tag)."""
    engines = {"hdds": hdds_bin, **VENDORS}
    names = list(engines)
    pairs = []
    for p in names:
        for s in names:
            pairs.append((engines[p], engines[s], f"{p}-{s}"))
    return pairs


def make_cpuset_pool(cores_per_pair, max_pairs):
    ncores = os.cpu_count() or 4
    usable = max(1, ncores - 2)
    n_slots = usable // cores_per_pair
    if max_pairs:
        n_slots = min(n_slots, max_pairs)
    n_slots = max(1, min(n_slots, 25))  # full xtypes matrix = 25 pairs
    return [f"{2 + i * cores_per_pair}-{2 + i * cores_per_pair + cores_per_pair - 1}"
            for i in range(n_slots)]


async def run_one(pub, sub, tag, cpuset, outdir, suite, tests, timeout, prefix=""):
    env = dict(os.environ, CPUSET=cpuset, OUTDIR=outdir, SUITE=suite,
               NAME_PREFIX=prefix)
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
        timed_out = True
        proc.kill()
        import subprocess
        subprocess.run(["docker", "rm", "-f", f"hddsxt-{prefix}{tag}"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["docker", "network", "rm", f"hddsxt-{prefix}{tag}"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            out, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
        except (asyncio.TimeoutError, Exception):
            out = b""
    dt = time.monotonic() - t0
    (Path(outdir) / f"{tag}.log").write_bytes(out or b"")
    return tag, ("TIMEOUT" if timed_out else proc.returncode), dt


async def preflight_binaries(pairs, image):
    bins = sorted({b for pr in pairs for b in pr[:2]})
    check = "; ".join(f"test -x ./bin/{b} || echo MISSING:{b}" for b in bins)
    proc = await asyncio.create_subprocess_exec(
        "docker", "run", "--rm", "--entrypoint", "bash", image, "-c", check,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
    )
    out, _ = await proc.communicate()
    missing = [ln.split(":", 1)[1] for ln in out.decode(errors="replace").split()
               if ln.startswith("MISSING:")]
    if missing:
        raise SystemExit(f"ERROR: binaries missing from image '{image}': "
                         f"{', '.join(missing)} -> rebuild with build-image.sh")


async def main_async(args):
    outdir = args.outdir
    Path(outdir).mkdir(parents=True, exist_ok=True)
    hdds_bin = HDDS_BIN[args.hdds_variant]
    pairs = build_matrix(hdds_bin)
    if args.only:
        want = set(args.only.split(","))
        pairs = [p for p in pairs if p[2] in want]
    if args.exclude:
        drop = set(args.exclude.split(","))
        pairs = [p for p in pairs
                 if not any(p[2].split("-")[k] in drop for k in (0, 1))]
    image = os.environ.get("IMAGE", "hdds-xtypes-interop:latest")
    await preflight_binaries(pairs, image)
    pool = make_cpuset_pool(args.cores_per_pair, args.max_pairs)
    print(f"xtypes DATA matrix  hdds={args.hdds_variant} ({hdds_bin})  "
          f"pairs={len(pairs)}  concurrency={len(pool)}  suite={args.suite}  "
          f"pair-timeout={args.pair_timeout}s")
    tests = (["-t", *args.tests] if args.tests else [])

    slots: asyncio.Queue = asyncio.Queue()
    for c in pool:
        slots.put_nowait(c)
    results, done, total, lock = [], 0, len(pairs), asyncio.Lock()

    async def worker(pub, sub, tag):
        nonlocal done
        cpuset = await slots.get()
        try:
            r = await run_one(pub, sub, tag, cpuset, outdir, args.suite, tests,
                              args.pair_timeout, prefix=f"{args.hdds_variant}-")
        finally:
            slots.put_nowait(cpuset)
        async with lock:
            done += 1
            tag_, rc, dt = r
            print(f"[{done}/{total}] {tag_:16s} {('ok' if rc == 0 else f'rc={rc}'):8s} {dt:6.1f}s")
        results.append(r)

    t0 = time.monotonic()
    await asyncio.gather(*(worker(p, s, t) for (p, s, t) in pairs))
    print(f"\nTotal wall: {time.monotonic() - t0:.1f}s for {total} pairs")
    summarize(outdir, pairs)
    return 0


def summarize(outdir, pairs):
    try:
        from junitparser import JUnitXml
    except ImportError:
        print("(junitparser not on host; per-pair XMLs in", outdir, ")")
        return
    print("\n=== summary (pass/total) ===")
    grand_ok = grand_tot = 0
    for _, _, tag in pairs:
        xml_path = Path(outdir) / f"{tag}.xml"
        if not xml_path.exists():
            print(f"{tag:16s} NO-XML"); continue
        try:
            xml = JUnitXml.fromfile(str(xml_path))
        except Exception as e:
            print(f"{tag:16s} XML-ERR {e}"); continue
        ok = tot = 0
        for suite in xml:
            for case in suite:
                tot += 1
                if not (case.result and any(
                        r.__class__.__name__ in ("Failure", "Error") for r in case.result)):
                    ok += 1
        grand_ok += ok; grand_tot += tot
        print(f"{tag:16s} {ok:3d}/{tot:<3d}")
    print(f"{'TOTAL':16s} {grand_ok:3d}/{grand_tot:<3d}")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--hdds-variant", choices=["on", "off"], default="on")
    ap.add_argument("--suite", default="test_suite_iso70")
    ap.add_argument("--tests", nargs="+", default=None)
    ap.add_argument("--cores-per-pair", type=int, default=4)
    ap.add_argument("--pair-timeout", type=int, default=3600)
    ap.add_argument("--max-pairs", type=int, default=None)
    ap.add_argument("--only", default=None,
                    help="comma-separated pair tags to run (e.g. hdds-cyclone,coredx-hdds)")
    ap.add_argument("--exclude", default=None,
                    help="comma-separated engine names to drop (e.g. opendds)")
    ap.add_argument("--outdir", default="/tmp/hdds-xtypes-out")
    args = ap.parse_args()
    sys.exit(asyncio.run(main_async(args)))


if __name__ == "__main__":
    main()
