#!/usr/bin/env bash
# Build the fat xtypes-interop image: assembles a temp build context from the
# OMG dds-xtypes harness working tree + all engine binaries, then docker build.
#
# Engine set (5 engines, 6 binaries): the 4 official vendor test_main binaries
# from the omg-dds/dds-xtypes release (connext/cyclone/coredx/opendds) + HDDS in
# BOTH feature-OFF and feature-ON builds of the same commit (to measure the
# structural-assignability / TypeLookup delta).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
XT_SRC="${XT_SRC:-/opt/dds-xtypes}"
VENDOR_DIR="${VENDOR_DIR:-/tmp/xtypes_vendors}"
HDDS_OFF="${HDDS_OFF:-/tmp/hdds_xt_OFF8}"
HDDS_ON="${HDDS_ON:-/tmp/hdds_xt_ON8}"
IMAGE="${IMAGE:-hdds-xtypes-interop:latest}"

# Harness python files (self-contained; no external pip beyond pexpect).
# NOTE: current official tip (70c5bef) renamed rtps_test_utilities.py ->
# interoperability_test_utilities.py.
HARNESS_PY=(
    interoperability_report.py
    test_suite_functions.py
    interoperability_test_utilities.py
    print_ids.py
    typeid_matrix.py
)
# DATA suite(s) to bundle. iso70..iso86 are IDENTICAL case sets differing only
# in DDS domain id (70..86) -> lets concurrent isolated pairs each pick a distinct
# domain (belt-and-suspenders on top of per-pair network isolation).
DATA_SUITES=(
    test_suite_iso70.py test_suite_iso71.py test_suite_iso72.py test_suite_iso73.py
    test_suite_iso74.py test_suite_iso75.py test_suite_iso76.py test_suite_iso77.py
    test_suite_iso78.py test_suite_iso79.py test_suite_iso80.py test_suite_iso81.py
    test_suite_iso82.py test_suite_iso83.py test_suite_iso84.py test_suite_iso85.py
    test_suite_iso86.py
)
# Relative resource trees the shape_main apps read (--type-folder / --data-folder).
# unsupported_test_manifest/ carries the per-vendor skip lists the official CI
# applies (connext/cyclone/coredx-6.14.0/dust); copied so behaviour is faithful.
RES_DIRS=( types data resource unsupported_test_manifest )

CTX="$(mktemp -d /tmp/hdds-xtypes-ctx.XXXXXX)"
trap 'rm -rf "$CTX"' EXIT
mkdir -p "$CTX/harness" "$CTX/binaries"

for f in "${HARNESS_PY[@]}" "${DATA_SUITES[@]}"; do
    cp "$XT_SRC/$f" "$CTX/harness/"
done
for d in "${RES_DIRS[@]}"; do
    [ -d "$XT_SRC/$d" ] && cp -r "$XT_SRC/$d" "$CTX/harness/"
done

# Vendor binaries (find the test_main under each release dir OR the bare file).
copy_vendor() { # <glob> <destname>
    local hit
    hit="$(find "$VENDOR_DIR" -maxdepth 2 -type f -name "$1" | head -1)"
    [ -n "$hit" ] || { echo "ERROR: vendor binary not found: $1 in $VENDOR_DIR" >&2; exit 1; }
    cp "$hit" "$CTX/binaries/$2"
}
copy_vendor "connext_dds-*_test_main_linux"        connext_dds-7.7.0_test_main_linux
copy_vendor "eclipse_cyclone-*_test_main_linux"    eclipse_cyclone-11.0.1_test_main_linux
copy_vendor "toc_coredx_dds-*_test_main_linux"     toc_coredx_dds-6.14.1_test_main_linux
copy_vendor "opendds-*_test_main_linux"            opendds-3.35.0-dev_test_main_linux

[ -x "$HDDS_OFF" ] || { echo "ERROR: HDDS_OFF not executable: $HDDS_OFF" >&2; exit 1; }
[ -x "$HDDS_ON"  ] || { echo "ERROR: HDDS_ON not executable: $HDDS_ON" >&2; exit 1; }
cp "$HDDS_OFF" "$CTX/binaries/hdds_off_shape_main_linux"
cp "$HDDS_ON"  "$CTX/binaries/hdds_on_shape_main_linux"

echo "Bundled binaries:"; ls -1 "$CTX/binaries/" | sed 's/^/  - /'

cp "$HERE/Dockerfile" "$CTX/"
docker build -t "$IMAGE" "$CTX"
echo; echo "Built $IMAGE"
docker run --rm --entrypoint python3 "$IMAGE" interoperability_report.py --help >/dev/null \
    && echo "Smoke: harness --help OK"
