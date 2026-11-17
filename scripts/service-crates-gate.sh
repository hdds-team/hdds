#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com
#
# Service-crates gate: hdds-wasm, hdds-xrce, hdds-xrce-client,
# hdds-schema-registry, hdds-influx-sink.
#
# These four crates are announced on the website but are kept out of the
# workspace default-members, so the default `cargo test` at the repository
# root never touches them. This script is the gate that does.
#
# Lanes (every lane is required; a missing tool is a FAILURE, never a skip):
#   1 tests      cargo test with --all-features for every service crate
#   2 clippy     cargo clippy --all-targets --all-features -D warnings
#   3 wasm32     cargo build -p hdds-wasm --target wasm32-unknown-unknown
#                (--no-default-features: the `relay` feature pulls hdds, which
#                 does not compile for wasm32)
#   4 wasm-glue  node driving the wasm32 artefact through the hand-written
#                JS glue (no wasm-bindgen, no network)
#   5 wasm-e2e   node, the same glue and a running hdds-wasm-relay: two
#                browser clients exchange a CDR sample through a DDS domain
#   6 xrce-size  thumbv7em-none-eabihf size measurement of hdds-xrce-client
#
# The `tests` lane runs with --all-features, so it also covers the DDS-wired
# proofs (hdds_bridge_e2e, distribution_e2e, dds_to_influx_e2e,
# relay_dds_roundtrip). Those need a multicast-capable interface: HDDS refuses
# loopback as its primary interface, so this gate is a host gate, not a
# network-isolated sandbox gate.
#
# Usage: scripts/service-crates-gate.sh [lane ...]
#        with no argument every lane runs.

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

SERVICE_CRATES=(hdds-wasm hdds-xrce hdds-xrce-client hdds-schema-registry hdds-influx-sink)

FAILED=()
PASSED=()

run_lane() {
    local name="$1"
    shift
    echo "=== lane ${name}: $* ==="
    if "$@"; then
        PASSED+=("$name")
        echo "--- lane ${name}: PASS"
    else
        FAILED+=("$name")
        echo "--- lane ${name}: FAIL"
    fi
}

lane_tests() {
    local args=()
    for c in "${SERVICE_CRATES[@]}"; do args+=(-p "$c"); done
    cargo test "${args[@]}" --all-features
}

lane_clippy() {
    local args=()
    for c in "${SERVICE_CRATES[@]}"; do args+=(-p "$c"); done
    cargo clippy "${args[@]}" --all-targets --all-features -- -D warnings
}

lane_wasm32() {
    if ! rustup target list --installed | grep -qx wasm32-unknown-unknown; then
        echo "wasm32-unknown-unknown target is not installed (rustup target add wasm32-unknown-unknown)"
        return 1
    fi
    cargo build -p hdds-wasm --no-default-features --target wasm32-unknown-unknown --release
}

lane_wasm_glue() {
    if ! command -v node >/dev/null 2>&1; then
        echo "node is required by this gate and was not found on PATH"
        return 1
    fi
    node --version
    lane_wasm32 || return 1
    local wasm
    wasm="$(find "${CARGO_TARGET_DIR:-target}/wasm32-unknown-unknown/release" -maxdepth 1 -name 'hdds_wasm.wasm' | head -1)"
    if [ -z "$wasm" ]; then
        echo "hdds_wasm.wasm not found after the wasm32 build"
        return 1
    fi
    # The artefact is UNOPTIMISED: wasm-opt is not available on this box, so
    # the .wasm shipped by this gate is exactly what rustc emitted.
    HDDS_WASM_ARTIFACT="$wasm" node crates/hdds-wasm/tests/node/glue_unit.mjs
}

lane_wasm_e2e() {
    if ! command -v node >/dev/null 2>&1; then
        echo "node is required by this gate and was not found on PATH"
        return 1
    fi
    lane_wasm32 || return 1
    local wasm
    wasm="$(find "${CARGO_TARGET_DIR:-target}/wasm32-unknown-unknown/release" -maxdepth 1 -name 'hdds_wasm.wasm' | head -1)"
    if [ -z "$wasm" ]; then
        echo "hdds_wasm.wasm not found after the wasm32 build"
        return 1
    fi
    cargo build -p hdds-wasm --features relay --bin hdds-wasm-relay || return 1

    if ! command -v python3 >/dev/null 2>&1; then
        echo "python3 is required by this gate (it asks the OS for a free port) and was not found on PATH"
        return 1
    fi
    # A free loopback port, asked of the OS rather than guessed.
    local port
    port="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')"
    if [ -z "$port" ]; then
        echo "could not obtain a free loopback port"
        return 1
    fi
    local relay_bin="${CARGO_TARGET_DIR:-target}/debug/hdds-wasm-relay"
    "$relay_bin" --port "$port" --domain 145 &
    local relay_pid=$!
    trap 'kill '"$relay_pid"' 2>/dev/null' RETURN
    sleep 3
    if ! kill -0 "$relay_pid" 2>/dev/null; then
        echo "hdds-wasm-relay exited before the test could connect"
        return 1
    fi

    HDDS_WASM_ARTIFACT="$wasm" HDDS_RELAY_URL="ws://127.0.0.1:${port}/ws" \
        node crates/hdds-wasm/tests/node/roundtrip.mjs
    local rc=$?
    kill "$relay_pid" 2>/dev/null
    wait "$relay_pid" 2>/dev/null
    return $rc
}

lane_xrce_size() {
    scripts/xrce-size-gate.sh
}

LANES=("$@")
if [ ${#LANES[@]} -eq 0 ]; then
    LANES=(tests clippy wasm32 wasm-glue wasm-e2e xrce-size)
fi

for lane in "${LANES[@]}"; do
    case "$lane" in
        tests)     run_lane tests lane_tests ;;
        clippy)    run_lane clippy lane_clippy ;;
        wasm32)    run_lane wasm32 lane_wasm32 ;;
        wasm-glue) run_lane wasm-glue lane_wasm_glue ;;
        wasm-e2e)  run_lane wasm-e2e lane_wasm_e2e ;;
        xrce-size) run_lane xrce-size lane_xrce_size ;;
        *) echo "unknown lane: $lane" >&2; exit 2 ;;
    esac
done

echo
echo "=== service-crates gate summary ==="
for l in "${PASSED[@]:-}"; do [ -n "$l" ] && echo "PASS ${l}"; done
for l in "${FAILED[@]:-}"; do [ -n "$l" ] && echo "FAIL ${l}"; done

if [ ${#FAILED[@]} -gt 0 ]; then
    echo "service-crates gate: FAILED (${#FAILED[@]} lane(s))"
    exit 1
fi
echo "service-crates gate: PASSED (${#PASSED[@]} lane(s))"
