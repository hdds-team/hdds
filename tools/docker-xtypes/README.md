# docker-xtypes - Docker-isolated OMG dds-xtypes interop harness

Parallel, network-isolated runner for the OMG **dds-xtypes** interoperability
suite. Sibling of `tools/docker-interop` (which does **dds-rtps**). Same proven
isolation model; adapted to the xtypes harness + its 4 test dimensions.

## What it does

- Bundles the OMG dds-xtypes harness (`interoperability_report.py` + its 3
  sibling modules + the `types/ data/ resource/` asset dirs) and all test
  binaries into one fat image `hdds-xtypes-interop:latest`.
- Runs each pub/sub pair in its **own container on its own normal Docker
  bridge** -> guaranteed zero cross-talk (multicast is not routed between
  bridges). One container per pair (the harness spawns pub+sub itself).
- Each pair sweeps the **4 dimensions** = (`-x` data-representation {1,2}) x
  (`--type-object-version` {1,2}):
  `xcdr1_to1`, `xcdr1_to2`, `xcdr2_to1`, `xcdr2_to2` -> 4 XMLs per pair.
- Per-pair `--cpuset-cpus` pinning; the cpuset pool is the concurrency gate.

## Binaries bundled

| label in image (`/opt/dds-xtypes/bin/`) | source |
|---|---|
| `hdds_xtypes_shape_main_linux` | `$HDDS_BIN` (env, required) |
| `connext_dds-7.7.0_test_main_linux` | `/tmp/xtypes_vendors/.../connext_dds-7.7.0_test_main_linux` |
| `eclipse_cyclone-11.0.1_test_main_linux` | `/tmp/xtypes_vendors/.../eclipse_cyclone-11.0.1_test_main_linux` |
| `toc_coredx_dds-6.14.1_test_main_linux` | `/tmp/xtypes_vendors/.../toc_coredx_dds-6.14.1_test_main_linux` |

## Build

```bash
./build-image.sh        # -> hdds-xtypes-interop:latest  (~235 MB)
```

Override sources via env: `HARNESS_SRC` (default `/opt/dds-xtypes`),
`HDDS_BIN`, `VENDOR_SRC` (default `/tmp/xtypes_vendors`), `IMAGE`.

## Run

Single pair (all 4 dims), isolated:

```bash
OUTDIR=/tmp/hdds-xtypes-out CPUSET=2-5 \
  ./run-pair.sh hdds_xtypes_shape_main_linux hdds_xtypes_shape_main_linux hdds-hdds
# subset of dims:  DIMS="xcdr2_to2"
# subset of cases: append  -t ext_final_struct_1 ext_appendable_struct_1
```

Full matrix (HDDS-self + HDDS vs {connext,cyclone,coredx} both dirs = 7 pairs):

```bash
./orchestrate.py --matrix hdds --outdir /tmp/hdds-xtypes-out
```

Useful flags: `--dims xcdr2_to2` (subset), `--tests <case...>` (subset),
`--cores-per-pair K`, `--max-pairs N`, `--pair-timeout S` (default 4500s = 75min;
a pair runs all 4 dims serially, full suite ~12-15min each).

The orchestrator prints a per-pair per-dim `pass/total` table + a grand total
parsed from the JUnit XMLs in `--outdir`.

## glibc / vendor-lib caveats

- **Base image is `ubuntu:24.04` (glibc 2.39), NOT 22.04.** The HDDS xtypes
  driver in `xtypes-rel/release/` was built against **GLIBC_2.39** (verified via
  `ldd` inside the image - 22.04's glibc 2.35 fails it with
  `version 'GLIBC_2.39' not found`). 24.04 covers it. The vendor `test_main`
  binaries need only up to GLIBC_2.34 and run fine on 2.39 (glibc is
  backward-compatible) - all four binaries' `ldd` is clean inside the image.
- No vendor needed extra bundled shared libs in this set (connext/cyclone/coredx
  test_main are self-contained). If a future vendor binary reports missing libs,
  add them to the image and note here.

## Isolation guarantees (inherited from docker-interop, proven there)

- **Normal bridge, never `--internal`.** An `--internal` net has no default
  route, so the container's `IP_ADD_MEMBERSHIP(INADDR_ANY)` multicast join fails
  with ENODEV and DDS discovery silently dies. A normal per-pair bridge gives
  the default route while staying isolated (multicast isn't routed between
  bridges). A *shared* bridge was proven to corrupt sample counts.
- The orchestrator only ever `docker rm -f`s **its own** named containers
  (`hddsxt-<tag>-<dim>`) / networks (`hddsxt-<tag>`) - never a global pkill -
  so a bare-host self-sweep running in parallel is never disturbed.
