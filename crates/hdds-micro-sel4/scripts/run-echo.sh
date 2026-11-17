#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2026 naskel.com
#
# Baseline reproducer: boot the unmodified sDDF echo_server under
# qemu_virt_aarch64 and (optionally) round-trip a UDP echo from the host.
#
# Prerequisites:
#   - MICROKIT_SDK: Microkit SDK 2.2.0 root (required)
#   - SDDF_ROOT: sDDF checkout (required; pinned commit 99034b4...)
#   - clang/lld 19 in /usr/lib/llvm-19/bin
#   - sdfgen 0.29.0 installed (Python + native lib, both 0.29)
#   - qemu-system-aarch64 in PATH
#
# Usage:
#   crates/hdds-micro-sel4/scripts/run-echo.sh            # build (if needed) + boot + UDP test
#   crates/hdds-micro-sel4/scripts/run-echo.sh --no-test  # boot only, no UDP test
#   crates/hdds-micro-sel4/scripts/run-echo.sh --build    # rebuild from scratch then run

set -euo pipefail

MICROKIT_SDK="${MICROKIT_SDK:?set MICROKIT_SDK to the Microkit SDK root}"
SDDF_ROOT="${SDDF_ROOT:?set SDDF_ROOT to the sDDF checkout}"
ECHO_DIR="${SDDF_ROOT}/examples/echo_server"
BUILD_DIR="${ECHO_DIR}/build"
LOADER_IMG="${BUILD_DIR}/loader.img"
QEMU_LOG="${QEMU_LOG:-/tmp/echo-qemu.log}"
LLVM_BIN="${LLVM_BIN:-/usr/lib/llvm-19/bin}"

DO_TEST=1
FORCE_BUILD=0
for arg in "$@"; do
    case "$arg" in
        --no-test) DO_TEST=0 ;;
        --build)   FORCE_BUILD=1 ;;
        *) echo "unknown arg: $arg" >&2; exit 2 ;;
    esac
done

[[ -d "${MICROKIT_SDK}" ]] || { echo "MICROKIT_SDK not found: ${MICROKIT_SDK}" >&2; exit 1; }
[[ -d "${ECHO_DIR}"     ]] || { echo "echo_server not found: ${ECHO_DIR}" >&2; exit 1; }
[[ -d "${LLVM_BIN}"     ]] || { echo "LLVM 19 not found: ${LLVM_BIN}" >&2; exit 1; }
command -v qemu-system-aarch64 >/dev/null || { echo "qemu-system-aarch64 not in PATH" >&2; exit 1; }

if (( FORCE_BUILD == 1 )) || [[ ! -f "${LOADER_IMG}" ]]; then
    echo "[run-echo] building echo_server..."
    cd "${ECHO_DIR}"
    [[ -d build ]] && rm -rf build
    PATH="${LLVM_BIN}:${PATH}" \
        MICROKIT_SDK="${MICROKIT_SDK}" \
        MICROKIT_BOARD=qemu_virt_aarch64 \
        MICROKIT_CONFIG=debug \
        TOOLCHAIN=clang \
        make BUILD_DIR=build
fi

[[ -f "${LOADER_IMG}" ]] || { echo "build did not produce loader.img" >&2; exit 1; }

echo "[run-echo] starting QEMU (log: ${QEMU_LOG})"
cd "${BUILD_DIR}"
qemu-system-aarch64 \
    -machine virt,virtualization=on -cpu cortex-a53 \
    -m size=2G \
    -serial "file:${QEMU_LOG}" \
    -global virtio-mmio.force-legacy=false \
    -device loader,file=loader.img,addr=0x70000000,cpu-num=0 \
    -device virtio-net-device,netdev=netdev0,bus=virtio-mmio-bus.0 \
    -nographic -display none \
    -netdev user,id=netdev0,hostfwd=udp::1235-10.0.2.15:1235,hostfwd=tcp::1236-10.0.2.15:1236 \
    -d guest_errors </dev/null >/dev/null 2>&1 &
QEMU_PID=$!
trap 'kill ${QEMU_PID} 2>/dev/null; wait 2>/dev/null || true' EXIT

# Wait for DHCP to complete on client1 (10.0.2.15)
for i in $(seq 1 15); do
    if grep -q "IP address for netif client1 is: 10.0.2.15" "${QEMU_LOG}" 2>/dev/null; then
        break
    fi
    sleep 1
done

if ! grep -q "Microkit Monitor started" "${QEMU_LOG}" 2>/dev/null; then
    echo "[run-echo] BOOT FAILED - Microkit Monitor never started. Last log lines:" >&2
    tail -20 "${QEMU_LOG}" >&2 || true
    exit 1
fi

if (( DO_TEST == 0 )); then
    echo "[run-echo] boot OK, sleeping forever (Ctrl-C to stop)"
    wait
    exit 0
fi

# Round-trip a UDP echo on port 1235.
TEST_STR="echo-$(date +%s%N)"
RESP=$(echo "${TEST_STR}" | timeout 2 nc -u -w1 127.0.0.1 1235 || true)

if [[ "${RESP}" == "${TEST_STR}" ]]; then
    echo "[run-echo] PASS: UDP echo round-trip ok (sent and got '${TEST_STR}')"
    exit 0
else
    echo "[run-echo] FAIL: expected '${TEST_STR}', got '${RESP}'" >&2
    echo "--- last 20 lines of QEMU serial log ---" >&2
    tail -20 "${QEMU_LOG}" >&2 || true
    exit 1
fi
