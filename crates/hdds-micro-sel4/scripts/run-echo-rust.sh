#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2026 naskel.com
#
# Rust echo reproducer: apply the hdds-micro-sel4 overlay (which adds a third
# client `client2_rust` to the stock sDDF echo_server), build, boot
# under qemu_virt_aarch64, and round-trip a UDP echo through the
# Rust-backed PD on host port 1241.
#
# Overlay files live at crates/hdds-micro-sel4/microkit/ and replace the upstream
# echo_server's meta.py / echo.mk / core_config/single_core.json.
# The C wrapper + Rust staticlib are added side-by-side via vpath +
# cargo invocation from inside the Microkit Makefile.
#
# Prerequisites (same as run-echo.sh):
#   - MICROKIT_SDK: Microkit SDK 2.2.0 root (required)
#   - SDDF_ROOT: sDDF checkout (required; pinned commit 99034b4...)
#   - clang/lld 19 in /usr/lib/llvm-19/bin
#   - sdfgen 0.29.0 installed (Python + native lib, both 0.29)
#   - qemu-system-aarch64 in PATH
#   - rustup target add aarch64-unknown-none
#
# Usage:
#   crates/hdds-micro-sel4/scripts/run-echo-rust.sh           # overlay + build + boot + test
#   crates/hdds-micro-sel4/scripts/run-echo-rust.sh --no-test # boot only
#   crates/hdds-micro-sel4/scripts/run-echo-rust.sh --build   # force rebuild
#   crates/hdds-micro-sel4/scripts/run-echo-rust.sh --revert  # restore stock upstream
#
# Restore stock upstream manually:
#   cd "$SDDF_ROOT" && git checkout examples/echo_server/

set -euo pipefail

MICROKIT_SDK="${MICROKIT_SDK:?set MICROKIT_SDK to the Microkit SDK root}"
SDDF_ROOT="${SDDF_ROOT:?set SDDF_ROOT to the sDDF checkout}"
ECHO_DIR="${SDDF_ROOT}/examples/echo_server"
BUILD_DIR="${ECHO_DIR}/build"
LOADER_IMG="${BUILD_DIR}/loader.img"
QEMU_LOG="${QEMU_LOG:-/tmp/echo-rust-qemu.log}"
LLVM_BIN="${LLVM_BIN:-/usr/lib/llvm-19/bin}"

# hdds-micro-sel4 checkout (this script's own ancestry).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SEL4_CRATE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
OVERLAY_DIR="${SEL4_CRATE_DIR}/microkit"

DO_TEST=1
FORCE_BUILD=0
DO_REVERT=0
for arg in "$@"; do
    case "$arg" in
        --no-test) DO_TEST=0 ;;
        --build)   FORCE_BUILD=1 ;;
        --revert)  DO_REVERT=1 ;;
        *) echo "unknown arg: $arg" >&2; exit 2 ;;
    esac
done

[[ -d "${MICROKIT_SDK}"  ]] || { echo "MICROKIT_SDK not found: ${MICROKIT_SDK}" >&2; exit 1; }
[[ -d "${ECHO_DIR}"      ]] || { echo "echo_server not found: ${ECHO_DIR}" >&2; exit 1; }
[[ -d "${LLVM_BIN}"      ]] || { echo "LLVM 19 not found: ${LLVM_BIN}" >&2; exit 1; }
[[ -d "${OVERLAY_DIR}"   ]] || { echo "overlay dir not found: ${OVERLAY_DIR}" >&2; exit 1; }
[[ -d "${SEL4_CRATE_DIR}/client2_rust" ]] || { echo "client2_rust crate not found" >&2; exit 1; }
command -v qemu-system-aarch64 >/dev/null || { echo "qemu-system-aarch64 not in PATH" >&2; exit 1; }
command -v cargo >/dev/null || { echo "cargo not in PATH" >&2; exit 1; }

if (( DO_REVERT == 1 )); then
    echo "[run-echo-rust] restoring stock upstream sDDF echo_server"
    (cd "${SDDF_ROOT}" && git checkout examples/echo_server/)
    echo "[run-echo-rust] done. Use crates/hdds-micro-sel4/scripts/run-echo.sh for the baseline."
    exit 0
fi

echo "[run-echo-rust] applying overlay to ${ECHO_DIR}"
cp -f "${OVERLAY_DIR}/meta.py"           "${ECHO_DIR}/meta.py"
cp -f "${OVERLAY_DIR}/echo.mk"           "${ECHO_DIR}/echo.mk"
cp -f "${OVERLAY_DIR}/single_core.json"  "${ECHO_DIR}/core_config/single_core.json"
cp -f "${OVERLAY_DIR}/client2_rust_wrapper.c" "${ECHO_DIR}/client2_rust_wrapper.c"

if (( FORCE_BUILD == 1 )) || [[ ! -f "${LOADER_IMG}" ]]; then
    echo "[run-echo-rust] building (with overlay)..."
    cd "${ECHO_DIR}"
    [[ -d build ]] && rm -rf build
    PATH="${LLVM_BIN}:${PATH}" \
        MICROKIT_SDK="${MICROKIT_SDK}" \
        MICROKIT_BOARD=qemu_virt_aarch64 \
        MICROKIT_CONFIG=debug \
        TOOLCHAIN=clang \
        SEL4_CRATE_DIR="${SEL4_CRATE_DIR}" \
        make BUILD_DIR=build
fi

[[ -f "${LOADER_IMG}" ]] || { echo "build did not produce loader.img" >&2; exit 1; }

echo "[run-echo-rust] starting QEMU (log: ${QEMU_LOG})"
cd "${BUILD_DIR}"
qemu-system-aarch64 \
    -machine virt,virtualization=on -cpu cortex-a53 \
    -m size=2G \
    -serial "file:${QEMU_LOG}" \
    -global virtio-mmio.force-legacy=false \
    -device loader,file=loader.img,addr=0x70000000,cpu-num=0 \
    -device virtio-net-device,netdev=netdev0,bus=virtio-mmio-bus.0 \
    -nographic -display none \
    -netdev user,id=netdev0,hostfwd=udp::1235-10.0.2.15:1235,hostfwd=udp::1238-10.0.2.16:1235,hostfwd=udp::1241-10.0.2.17:1235 \
    -d guest_errors </dev/null >/dev/null 2>&1 &
QEMU_PID=$!
trap 'kill ${QEMU_PID} 2>/dev/null; wait 2>/dev/null || true' EXIT

# Wait for the system to fully boot. "Microkit Monitor started" is the
# earliest possible marker but fires before any PD initialises; tests
# that hit the wire too soon catch SLIRP mid-DHCP and observe spurious
# ARP-warming failures. Wait for both lwIP clients to finish DHCP -
# that guarantees the network stack and our PD are both alive.
for _ in $(seq 1 20); do
    if grep -q "IP address for netif client0" "${QEMU_LOG}" 2>/dev/null \
       && grep -q "IP address for netif client1" "${QEMU_LOG}" 2>/dev/null; then
        break
    fi
    sleep 1
done

if ! grep -q "Microkit Monitor started" "${QEMU_LOG}" 2>/dev/null; then
    echo "[run-echo-rust] BOOT FAILED - Microkit Monitor never started. Last log lines:" >&2
    tail -30 "${QEMU_LOG}" >&2 || true
    exit 1
fi

# Tiny extra settle window - the Rust binding has no log line of its
# own, and DHCP completion only proves lwIP is up. The binding's init
# is non-blocking and happens during the kernel's PD-start phase, so
# 200 ms is generous.
sleep 1

if (( DO_TEST == 0 )); then
    echo "[run-echo-rust] boot OK, sleeping forever (Ctrl-C to stop)"
    wait
    exit 0
fi

# 10 sequential UDP payloads -> each echoed back
# bit-identical via the Rust PD on port 1241.
FAILED=0
for i in $(seq 0 9); do
    TEST_STR="echo-rust-${i}-$(date +%s%N)"
    RESP=$(echo "${TEST_STR}" | timeout 2 nc -u -w1 127.0.0.1 1241 || true)
    if [[ "${RESP}" == "${TEST_STR}" ]]; then
        echo "[run-echo-rust] PASS ${i}: '${TEST_STR}'"
    else
        echo "[run-echo-rust] FAIL ${i}: expected '${TEST_STR}', got '${RESP}'" >&2
        FAILED=1
    fi
done

if (( FAILED == 1 )); then
    echo "--- last 30 lines of QEMU serial log ---" >&2
    tail -30 "${QEMU_LOG}" >&2 || true
    exit 1
fi

echo "[run-echo-rust] ALL 10 round-trips OK on host port 1241 (Rust PD)"
