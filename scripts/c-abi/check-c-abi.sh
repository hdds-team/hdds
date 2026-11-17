#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
BASELINE="$ROOT/scripts/c-abi/hdds-c-1.4.0-x86_64-linux.manifest"
HEADER="$ROOT/sdk/c/include/hdds.h"
LIBRARY=
BUILD=1

usage() {
    cat <<'EOF'
Usage: scripts/c-abi/check-c-abi.sh [options]

Options:
  --baseline PATH  ABI baseline manifest
  --header PATH    C header to inspect
  --library PATH   libhdds_c shared library to inspect
  --no-build       do not build hdds-c before checking
EOF
}

die() {
    printf 'c-abi-check: %s\n' "$*" >&2
    exit 1
}

while (($#)); do
    case "$1" in
        --baseline)
            (($# >= 2)) || die "--baseline requires a path"
            BASELINE=$2
            shift 2
            ;;
        --header)
            (($# >= 2)) || die "--header requires a path"
            HEADER=$2
            shift 2
            ;;
        --library)
            (($# >= 2)) || die "--library requires a path"
            LIBRARY=$2
            shift 2
            ;;
        --no-build)
            BUILD=0
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            die "unknown option: $1"
            ;;
    esac
done

for tool in cargo comm jq mktemp; do
    command -v "$tool" >/dev/null 2>&1 || die "required tool not found: $tool"
done

[[ -f "$BASELINE" ]] || die "baseline not found: $BASELINE"
[[ -f "$HEADER" ]] || die "header not found: $HEADER"

if ((BUILD)); then
    cargo build --manifest-path "$ROOT/Cargo.toml" -p hdds-c --release --all-features
fi

if [[ -z "$LIBRARY" ]]; then
    target_dir=$(cargo metadata --manifest-path "$ROOT/Cargo.toml" --format-version 1 --no-deps |
        jq -r .target_directory)
    LIBRARY="$target_dir/release/libhdds_c.so"
fi
[[ -f "$LIBRARY" ]] || die "shared library not found: $LIBRARY"

current=$(mktemp)
missing=$(mktemp)
header_functions=$(mktemp)
exported_symbols=$(mktemp)

cleanup() {
    rm -f "$current" "$missing" "$header_functions" "$exported_symbols"
}
trap cleanup EXIT

"$ROOT/scripts/c-abi/generate-c-abi-manifest.sh" "$HEADER" "$LIBRARY" >"$current"

awk -F '\t' '$1 == "function" { print $3 }' "$current" | LC_ALL=C sort -u >"$header_functions"
awk -F '\t' '$1 == "symbol" { print $3 }' "$current" | LC_ALL=C sort -u >"$exported_symbols"

if ! LC_ALL=C comm -23 "$header_functions" "$exported_symbols" >"$missing"; then
    die "failed to compare header declarations and exported symbols"
fi
if [[ -s "$missing" ]]; then
    printf 'C ABI FAIL: header functions missing from libhdds_c:\n' >&2
    sed 's/^/  /' "$missing" >&2
    exit 1
fi
if ! LC_ALL=C comm -13 "$header_functions" "$exported_symbols" >"$missing"; then
    die "failed to compare exported symbols and header declarations"
fi
if [[ -s "$missing" ]]; then
    printf 'C ABI FAIL: exported hdds_* symbols missing from the public header:\n' >&2
    sed 's/^/  /' "$missing" >&2
    exit 1
fi

if ! LC_ALL=C comm -23 "$BASELINE" "$current" >"$missing"; then
    die "failed to compare ABI manifests"
fi
if [[ -s "$missing" ]]; then
    printf 'C ABI FAIL: baseline entries removed or changed:\n' >&2
    sed 's/^/  /' "$missing" >&2
    exit 1
fi

baseline_count=$(wc -l <"$BASELINE")
current_count=$(wc -l <"$current")
symbol_count=$(wc -l <"$exported_symbols")
printf 'C ABI PASS: %s baseline entries preserved; %s current entries; %s exported hdds_* symbols.\n' \
    "$baseline_count" "$current_count" "$symbol_count"
