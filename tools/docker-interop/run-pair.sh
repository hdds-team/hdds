#!/usr/bin/env bash
# Run ONE pub/sub interop pair inside a dedicated, network-isolated container.
#
# Isolation model: one container per pair (the harness spawns pub+sub itself),
# attached to its OWN dedicated Docker bridge. Each bridge is a separate L2
# segment / subnet; multicast is NOT routed between bridges, so a pair's RTPS
# multicast (SPDP/SEDP) can never reach another pair -> guaranteed zero
# cross-talk, even on a shared host.
#
# NOTE: a normal bridge is used, NOT `--internal`. An --internal network has no
# gateway / default route, so IP_ADD_MEMBERSHIP with INADDR_ANY fails inside the
# container (ENODEV "No such device") and DDS discovery silently breaks. A
# normal bridge provides the default route the multicast join needs; isolation
# still holds because each pair gets its own bridge/subnet.
#
# Usage:
#   run-pair.sh <pub_basename> <sub_basename> <pair_tag> [extra harness args...]
# Example:
#   run-pair.sh hdds-1.3.0_shape_main_linux toc_coredx_dds-6.15.0_shape_main_linux \
#       hdds-coredx -t Test_Reliability_0
#
# Env knobs:
#   OUTDIR  (default /tmp/hdds-interop-out)  host dir for per-pair JUnit XML
#   CPUSET  (default unset)                  e.g. "0-2" : pin this pair's cores
#   IMAGE   (default hdds-interop:latest)
#   DATAREP (default 2)                      -x : 1=XCDR1, 2=XCDR2
#   PUB_BIN (default unset)  host path to a binary to run AS <pub_basename>
#   SUB_BIN (default unset)  host path to a binary to run AS <sub_basename>
#
# PUB_BIN / SUB_BIN: substituting a candidate binary without rebuilding the
# image. Each is bind-mounted OVER the matching vendor file already baked
# into the image (bin/<pub_basename> or bin/<sub_basename>), so the harness
# path -P/-S argument, and the JUnit report label the harness derives from
# it, stay byte-identical to the vendor entry you named on the command line;
# only the executable bytes that actually run differ. Keep <pub_basename> /
# <sub_basename> an EXISTING vendor filename from the image for this reason
# -- see the README for why a new filename breaks the report labeling.
# Example: run a freshly built HDDS candidate as the "hdds-1.3.0" side:
#   PUB_BIN=/path/to/candidate/hdds-1.3.0_shape_main_linux \
#       run-pair.sh hdds-1.3.0_shape_main_linux \
#       toc_coredx_dds-6.15.0_shape_main_linux hdds-coredx -t Test_Reliability_0
set -euo pipefail

if [ "$#" -lt 3 ]; then
    echo "usage: $0 <pub_basename> <sub_basename> <pair_tag> [harness args...]" >&2
    exit 2
fi

PUB="$1"; SUB="$2"; PAIR="$3"; shift 3
TESTARGS=("$@")

OUTDIR="${OUTDIR:-/tmp/hdds-interop-out}"
CPUSET="${CPUSET:-}"
IMAGE="${IMAGE:-hdds-interop:latest}"
DATAREP="${DATAREP:-2}"
PUB_BIN="${PUB_BIN:-}"
SUB_BIN="${SUB_BIN:-}"

# Path inside the image the vendor binaries live under (Dockerfile: COPY
# binaries/ /opt/dds-rtps/bin/, WORKDIR /opt/dds-rtps).
BINDIR_IN_IMAGE="/opt/dds-rtps/bin"

# Resolve to an absolute path: `docker run -v` treats a bare relative path
# as a named-volume name, not a bind mount, so a relative PUB_BIN/SUB_BIN
# would silently create an empty volume instead of erroring.
resolve_bin_override() {
    local path="$1" label="$2"
    if [ ! -f "$path" ]; then
        echo "ERROR: $label=$path does not exist" >&2
        exit 2
    fi
    if [ ! -x "$path" ]; then
        echo "ERROR: $label=$path is not executable (chmod +x it first)" >&2
        exit 2
    fi
    echo "$(cd "$(dirname "$path")" && pwd)/$(basename "$path")"
}

MOUNTARGS=(-v "$OUTDIR:/out")
if [ -n "$PUB_BIN" ]; then
    PUB_BIN="$(resolve_bin_override "$PUB_BIN" PUB_BIN)"
    MOUNTARGS+=(-v "${PUB_BIN}:${BINDIR_IN_IMAGE}/${PUB}:ro")
fi
if [ -n "$SUB_BIN" ]; then
    SUB_BIN="$(resolve_bin_override "$SUB_BIN" SUB_BIN)"
    MOUNTARGS+=(-v "${SUB_BIN}:${BINDIR_IN_IMAGE}/${SUB}:ro")
fi

mkdir -p "$OUTDIR"
rm -f "$OUTDIR/${PAIR}.xml"   # harness APPENDS if the file pre-exists.

NET="hddsio-${PAIR}"
CTR="hddsio-${PAIR}"

cleanup() {
    docker rm -f "$CTR"     >/dev/null 2>&1 || true
    docker network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker network create --driver bridge "$NET" >/dev/null

CPUARGS=()
[ -n "$CPUSET" ] && CPUARGS+=(--cpuset-cpus "$CPUSET")

docker run --rm --name "$CTR" --network "$NET" \
    "${CPUARGS[@]}" --memory=2g \
    "${MOUNTARGS[@]}" \
    "$IMAGE" \
    -P "./bin/${PUB}" -S "./bin/${SUB}" -x "$DATAREP" \
    -o "/out/${PAIR}.xml" "${TESTARGS[@]}"

echo "Pair ${PAIR} done -> $OUTDIR/${PAIR}.xml"
