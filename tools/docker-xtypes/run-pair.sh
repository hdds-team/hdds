#!/usr/bin/env bash
# Run ONE pub/sub xtypes interop pair inside a dedicated, network-isolated
# container, sweeping the 4 OMG dds-xtypes dimensions.
#
# Isolation model (identical to tools/docker-interop, proven there): one
# container per pair (the harness spawns pub+sub itself), attached to its OWN
# dedicated NORMAL Docker bridge. Each bridge is a separate L2 segment / subnet;
# multicast is NOT routed between bridges, so a pair's RTPS multicast can never
# reach another pair -> guaranteed zero cross-talk on a shared host.
#
# NOTE: a normal bridge is used, NOT `--internal`. An --internal network has no
# gateway / default route, so IP_ADD_MEMBERSHIP with INADDR_ANY fails inside the
# container (ENODEV "No such device") and DDS discovery silently breaks. A normal
# bridge provides the default route the multicast join needs; isolation still
# holds because each pair gets its own bridge/subnet.
#
# The 4 dimensions = (data-representation -x) x (--type-object-version):
#     xcdr1_to1 : -x 1 --type-object-version 1
#     xcdr1_to2 : -x 1 --type-object-version 2
#     xcdr2_to1 : -x 2 --type-object-version 1
#     xcdr2_to2 : -x 2 --type-object-version 2
# One container run per dimension -> 4 XMLs named <tag>_<dim>.xml.
#
# Usage:
#   run-pair.sh <pub_basename> <sub_basename> <pair_tag> [extra harness args...]
# Example:
#   run-pair.sh hdds_xtypes_shape_main_linux hdds_xtypes_shape_main_linux \
#       hdds-hdds -t ext_final_struct_1 ext_appendable_struct_1
#
# Env knobs:
#   OUTDIR  (default /tmp/hdds-xtypes-out)  host dir for per-pair JUnit XMLs
#   CPUSET  (default unset)                 e.g. "0-3" : pin this pair's cores
#   IMAGE   (default hdds-xtypes-interop:latest)
#   DIMS    (default "xcdr1_to1 xcdr1_to2 xcdr2_to1 xcdr2_to2") subset of dims
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
DIMS="${DIMS:-xcdr1_to1 xcdr1_to2 xcdr2_to1 xcdr2_to2}"

mkdir -p "$OUTDIR"

NET="hddsxt-${PAIR}"
CTR_BASE="hddsxt-${PAIR}"

cleanup() {
    for dim in $DIMS; do
        docker rm -f "${CTR_BASE}-${dim}" >/dev/null 2>&1 || true
    done
    docker network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker network create --driver bridge "$NET" >/dev/null

CPUARGS=()
[ -n "$CPUSET" ] && CPUARGS+=(--cpuset-cpus "$CPUSET")

# Map dim name -> (-x, --type-object-version).
dim_x() {
    case "$1" in
        xcdr1_to1|xcdr1_to2) echo 1 ;;
        xcdr2_to1|xcdr2_to2) echo 2 ;;
        *) echo "bad dim: $1" >&2; return 1 ;;
    esac
}
dim_tov() {
    case "$1" in
        xcdr1_to1|xcdr2_to1) echo 1 ;;
        xcdr1_to2|xcdr2_to2) echo 2 ;;
        *) echo "bad dim: $1" >&2; return 1 ;;
    esac
}

for dim in $DIMS; do
    X="$(dim_x "$dim")"
    TOV="$(dim_tov "$dim")"
    OUT="${OUTDIR}/${PAIR}_${dim}.xml"
    rm -f "$OUT"   # the harness APPENDS if the file pre-exists.
    docker run --rm --name "${CTR_BASE}-${dim}" --network "$NET" \
        "${CPUARGS[@]}" --memory=2g \
        -v "$OUTDIR:/out" \
        "$IMAGE" \
        --pub-exe "./bin/${PUB}" --sub-exe "./bin/${SUB}" \
        -x "$X" --type-object-version "$TOV" \
        -o "/out/${PAIR}_${dim}.xml" "${TESTARGS[@]}"
    echo "Pair ${PAIR} dim ${dim} done -> $OUT"
done

echo "Pair ${PAIR} all dims done -> $OUTDIR/${PAIR}_*.xml"
