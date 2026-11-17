#!/usr/bin/env bash
# Run ONE xtypes DATA pub/sub pair inside a dedicated, network-isolated container.
#
# Isolation model (identical to the proven dds-rtps docker_matrix_neo): one
# container per pair on its OWN dedicated Docker bridge. Separate bridges = separate
# L2 segments; multicast is not routed between them, so a pair's RTPS SPDP/SEDP
# never reaches another pair -> zero cross-talk. A NORMAL bridge is used, NOT
# `--internal` (an internal net has no default route, so the multicast
# IP_ADD_MEMBERSHIP join fails ENODEV and DDS discovery silently dies).
#
# Usage: run-pair.sh <pub_basename> <sub_basename> <pair_tag> [extra harness args...]
# Env: OUTDIR (host dir for JUnit XML), CPUSET (pin), IMAGE, DATAREP (-x 1|2),
#      SUITE (xtypes DATA test suite module, default test_suite_iso70).
set -euo pipefail

if [ "$#" -lt 3 ]; then
    echo "usage: $0 <pub_basename> <sub_basename> <pair_tag> [harness args...]" >&2
    exit 2
fi

PUB="$1"; SUB="$2"; PAIR="$3"; shift 3
TESTARGS=("$@")

OUTDIR="${OUTDIR:-/tmp/hdds-xtypes-out}"
CPUSET="${CPUSET:-}"
IMAGE="${IMAGE:-hdds-xtypes-interop:latest}"
DATAREP="${DATAREP:-2}"
SUITE="${SUITE:-test_suite_iso70}"

mkdir -p "$OUTDIR"
rm -f "$OUTDIR/${PAIR}.xml"   # harness APPENDS if the file pre-exists.

# NAME_PREFIX (e.g. "on-"/"off-") keeps the docker network/container names unique
# across concurrent variant runs that share pair tags (same tag -> same name ->
# "network already exists" collision otherwise).
NAME_PREFIX="${NAME_PREFIX:-}"
NET="hddsxt-${NAME_PREFIX}${PAIR}"
CTR="hddsxt-${NAME_PREFIX}${PAIR}"

cleanup() {
    docker rm -f "$CTR"      >/dev/null 2>&1 || true
    docker network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker network create --driver bridge "$NET" >/dev/null

CPUARGS=()
[ -n "$CPUSET" ] && CPUARGS+=(--cpuset-cpus "$CPUSET")

docker run --rm --name "$CTR" --network "$NET" \
    "${CPUARGS[@]}" --memory=2g \
    -v "$OUTDIR:/out" \
    "$IMAGE" \
    --pub-exe "./bin/${PUB}" --sub-exe "./bin/${SUB}" \
    -s "$SUITE" -x "$DATAREP" \
    -o "/out/${PAIR}.xml" "${TESTARGS[@]}"

echo "Pair ${PAIR} done -> $OUTDIR/${PAIR}.xml"
