#!/usr/bin/env bash
# Build the fat hdds-interop image: assembles a temp build context from the
# harness sources + a mirror of vendor shape_main binaries, then docker build.
#
# BIN_SRC must point at a directory of '*_shape_main_linux' binaries: the
# RELEASE-MIRROR set (OMG-CI-predictive), not an /opt grab-bag build tree.
# There is no sane universal default for this path -- every site keeps its
# own mirror somewhere different -- so set it explicitly:
#   BIN_SRC=/path/to/your/release-mirror bash build-image.sh
# The fallback below is a local staging directory next to this script: drop
# your own vendor shape_main binaries there if you have not set BIN_SRC.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HARNESS_SRC="${HARNESS_SRC:-/opt/dds-rtps}"
BIN_SRC="${BIN_SRC:-$HERE/vendor-bin}"
IMAGE="${IMAGE:-hdds-interop:latest}"

HARNESS_FILES=(
    interoperability_report.py
    test_suite.py
    test_suite_functions.py
    rtps_test_utilities.py
)

CTX="$(mktemp -d /tmp/hdds-interop-ctx.XXXXXX)"
trap 'rm -rf "$CTX"' EXIT

mkdir -p "$CTX/harness" "$CTX/binaries"

for f in "${HARNESS_FILES[@]}"; do
    cp "$HARNESS_SRC/$f" "$CTX/harness/"
done

shopt -s nullglob
bins=("$BIN_SRC"/*_shape_main_linux)
shopt -u nullglob
if [ "${#bins[@]}" -eq 0 ]; then
    echo "ERROR: no *_shape_main_linux found in $BIN_SRC" >&2
    echo "  -> set BIN_SRC to your vendor shape_main mirror, e.g.:" >&2
    echo "     BIN_SRC=/path/to/your/release-mirror bash build-image.sh" >&2
    exit 1
fi
cp "${bins[@]}" "$CTX/binaries/"
echo "Bundled ${#bins[@]} vendor binaries:"
for b in "${bins[@]}"; do echo "  - $(basename "$b")"; done

cp "$HERE/Dockerfile" "$CTX/"

docker build -t "$IMAGE" "$CTX"

echo
echo "Built $IMAGE"
docker run --rm "$IMAGE" --help >/dev/null && echo "Smoke: harness --help OK"
