#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
HEADER="$ROOT/sdk/c/include/hdds.h"
target_dir=$(cargo metadata --manifest-path "$ROOT/Cargo.toml" --format-version 1 --no-deps |
    jq -r .target_directory)
LIBRARY=${HDDS_C_ABI_TEST_LIBRARY:-"$target_dir/release/libhdds_c.so"}

tmp=$(mktemp -d)
cleanup() {
    rm -rf "$tmp"
}
trap cleanup EXIT

expect_failure() {
    local name=$1
    local pattern=$2
    shift 2

    if "$@" >"$tmp/$name.log" 2>&1; then
        printf 'FAIL: %s unexpectedly passed\n' "$name" >&2
        return 1
    fi
    if ! grep -Fq "$pattern" "$tmp/$name.log"; then
        printf 'FAIL: %s did not report %q\n' "$name" "$pattern" >&2
        sed 's/^/  /' "$tmp/$name.log" >&2
        return 1
    fi
    printf 'PASS(red): %s\n' "$name"
}

[[ -f "$LIBRARY" ]] || {
    printf 'shared library not found: %s\n' "$LIBRARY" >&2
    exit 1
}

"$ROOT/scripts/c-abi/check-c-abi.sh" --no-build --library "$LIBRARY"

sed 's/const char \*hdds_version(void);/int32_t hdds_version(void);/' \
    "$HEADER" >"$tmp/signature.h"
expect_failure signature-change 'baseline entries removed or changed' \
    "$ROOT/scripts/c-abi/check-c-abi.sh" --no-build --library "$LIBRARY" \
    --header "$tmp/signature.h"

sed '0,/uint32_t TOTAL_COUNT;/s//uint64_t TOTAL_COUNT;/' \
    "$HEADER" >"$tmp/layout.h"
expect_failure layout-change 'baseline entries removed or changed' \
    "$ROOT/scripts/c-abi/check-c-abi.sh" --no-build --library "$LIBRARY" \
    --header "$tmp/layout.h"

sed 's/hdds_version(void)/hdds_version_without_symbol(void)/' \
    "$HEADER" >"$tmp/missing-symbol.h"
expect_failure header-library-drift 'header functions missing from libhdds_c' \
    "$ROOT/scripts/c-abi/check-c-abi.sh" --no-build --library "$LIBRARY" \
    --header "$tmp/missing-symbol.h"

# RPC is optional in consumers, but its declarations must be covered against
# the all-feature library, including alongside the ROS 2 preprocessor mode.
sed 's/hdds_rpc_client_call(/hdds_rpc_client_call_missing_export(/' \
    "$HEADER" >"$tmp/rpc-missing-symbol.h"
expect_failure rpc-header-library-drift 'header functions missing from libhdds_c' \
    "$ROOT/scripts/c-abi/check-c-abi.sh" --no-build --library "$LIBRARY" \
    --header "$tmp/rpc-missing-symbol.h"

"$ROOT/scripts/c-abi/generate-c-abi-manifest.sh" "$HEADER" "$LIBRARY" >"$tmp/additive.manifest"
{
    printf 'function\tros2\thdds_future_addition\tvoid (void)\n'
    printf 'function\tstandalone\thdds_future_addition\tvoid (void)\n'
    printf 'symbol\tall\thdds_future_addition\n'
} >>"$tmp/additive.manifest"
LC_ALL=C sort -u -o "$tmp/additive.manifest" "$tmp/additive.manifest"
if LC_ALL=C comm -23 "$ROOT/scripts/c-abi/hdds-c-1.4.0-x86_64-linux.manifest" \
    "$tmp/additive.manifest" | grep -q .; then
    printf 'FAIL: additive manifest rejected\n' >&2
    exit 1
fi
printf 'PASS(green): additive ABI entries are accepted\n'

printf 'C ABI gate self-test PASS.\n'
