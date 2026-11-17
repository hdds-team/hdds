#!/usr/bin/env bash
# Build the fat hdds-xtypes-interop image: assembles a temp build context from
# the OMG dds-xtypes harness (sources + types/data/resource asset dirs) + the
# HDDS xtypes driver + the vendor test_main binaries, then docker build.
#
# Vendor binaries are nested one dir deep (file inside a same-named dir) in
# VENDOR_SRC; they are flattened into the context bin dir.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# OMG dds-xtypes harness checkout (branch feature/xml-driver-enhanced).
HARNESS_SRC="${HARNESS_SRC:-/opt/dds-xtypes}"
# HDDS xtypes driver (gnu dynamic, glibc).
HDDS_BIN="${HDDS_BIN:?set HDDS_BIN to the HDDS xtypes test_main binary (release build)}"
# Vendor binaries root (each binary nested in a same-named dir).
VENDOR_SRC="${VENDOR_SRC:-/tmp/xtypes_vendors}"
IMAGE="${IMAGE:-hdds-xtypes-interop:latest}"

# Harness python modules (4 files) + asset dirs.
HARNESS_FILES=(
    interoperability_report.py
    test_suite.py
    test_suite_functions.py
    rtps_test_utilities.py
)
HARNESS_DIRS=(
    types
    data
    resource
)

# Vendor binaries to flatten: each entry is "<flat-name>:<nested-relative-path>".
VENDOR_BINS=(
    "connext_dds-7.7.0_test_main_linux:connext_dds-7.7.0_test_main_linux/connext_dds-7.7.0_test_main_linux"
    "eclipse_cyclone-11.0.1_test_main_linux:eclipse_cyclone-11.0.1_test_main_linux/eclipse_cyclone-11.0.1_test_main_linux"
    "toc_coredx_dds-6.14.1_test_main_linux:toc_coredx_dds-6.14.1_test_main_linux/toc_coredx_dds-6.14.1_test_main_linux"
)

CTX="$(mktemp -d /tmp/hdds-xtypes-ctx.XXXXXX)"
trap 'rm -rf "$CTX"' EXIT

mkdir -p "$CTX/harness" "$CTX/binaries"

# Harness sources.
for f in "${HARNESS_FILES[@]}"; do
    cp "$HARNESS_SRC/$f" "$CTX/harness/"
done
# Asset dirs (types/data/resource).
for d in "${HARNESS_DIRS[@]}"; do
    cp -r "$HARNESS_SRC/$d" "$CTX/harness/"
done
# Sanitizing wrapper (entrypoint).
cp "$HERE/run_xtypes.py" "$CTX/harness/"

# HDDS driver.
if [ ! -x "$HDDS_BIN" ]; then
    echo "ERROR: HDDS driver not executable: $HDDS_BIN" >&2
    exit 1
fi
cp "$HDDS_BIN" "$CTX/binaries/hdds_xtypes_shape_main_linux"

# Vendor binaries (flatten).
for entry in "${VENDOR_BINS[@]}"; do
    flat="${entry%%:*}"
    rel="${entry#*:}"
    src="$VENDOR_SRC/$rel"
    if [ ! -f "$src" ]; then
        echo "WARN: vendor binary missing, skipping: $src" >&2
        continue
    fi
    cp "$src" "$CTX/binaries/$flat"
done

echo "Bundled binaries:"
for b in "$CTX"/binaries/*; do echo "  - $(basename "$b")"; done

cp "$HERE/Dockerfile" "$CTX/"

docker build -t "$IMAGE" "$CTX"

echo
echo "Built $IMAGE"
docker run --rm --entrypoint python3 "$IMAGE" \
    /opt/dds-xtypes/run_xtypes.py --help >/dev/null \
    && echo "Smoke: harness --help OK"
