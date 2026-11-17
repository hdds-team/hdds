# xtypes_matrix - docker-isolated OMG dds-xtypes interop matrix

Sibling of `../docker-interop` (dds-rtps `docker_matrix_neo`), for the OMG
**dds-xtypes** suite. Produces the two official xtypes scoreboards for the
5-engine set (HDDS + the 4 vendor binaries published by omg-dds/dds-xtypes:
connext, cyclone, coredx, opendds), in both HDDS feature builds:

- **OFF** = shipped (`xtypes-structural-assignability` off).
- **ON**  = the structural-assignability + OMG TypeLookup branch.

## Two axes
- **DATA interop** - live pub/sub, docker-isolated (one bridge per pair, NORMAL
  bridge not `--internal`), full 5x5. `orchestrate.py` + `run-pair.sh`.
- **TypeId** - offline: each engine emits its own TypeIdentifiers
  (`--print-typeid`), scored pairwise (OK iff pub==sub and != 'not found').
  `typeid_matrix_all.py`. MUST run on a QUIET host (vendor apps init a real
  participant even for --print-typeid; a concurrent DATA matrix exhausts host
  multicast sockets -> false zeros).

## Run
    ./build-image.sh          # ubuntu:24.04 (glibc 2.39 covers HDDS 2.39 + vendors 2.34)
    ./xtypes_matrix           # both axes, OFF + ON, combined summary
    ./xtypes_matrix --data-only
    ./xtypes_matrix --typeid-only

## Inputs
The scripts read these environment variables (the defaults are scratch locations):

| Variable | Meaning | Default |
|----------|---------|---------|
| `XT_SRC` | checkout of the omg-dds/dds-xtypes harness | `/opt/dds-xtypes` |
| `VENDOR_DIR` | the vendor `test_main` binaries from the omg-dds/dds-xtypes release | `/tmp/xtypes_vendors` |
| `HDDS_OFF`, `HDDS_ON` | the HDDS test binary built with the feature off / on | `/tmp/hdds_xt_OFF8`, `/tmp/hdds_xt_ON8` |
| `OUT` | where `xtypes_matrix` writes its results | `/tmp/xtmatrix` |

## Notes
- The harness is driven with `--pub-exe/--sub-exe -s <suite> -o`. The upstream CI
  runs the suite with `--publisher/--subscriber --enable-typeid-tests`; this matrix does
  not use those options, so its scores are not the upstream CI report.
- DATA suite = `test_suite_iso70` (85 case keys -> ~335 junit checks; the
  iso70..86 files are domain-isolated copies of the same suite - irrelevant
  under per-pair network isolation, one is enough).
- The vendor binaries are not part of this repository: download them from the
  upstream release.
