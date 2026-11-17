#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2026 naskel.com
#
# Publisher integration test: boot the seL4 publisher PD under
# QEMU, drive it with the host-side hdds_sub for up to ~30 s, count
# RTPS samples received and verify sequence-number monotonicity.
# Exit 0 iff >= N_TARGET samples received with strictly increasing
# sequence numbers and zero decode errors.
#
# What it checks: the Sel4Ring wire path carries CDR-encoded RTPS
# DATA submessages produced by hdds-micro's MicroWriter inside the PD.
# If the host-side hdds-micro MicroReader decodes >= N_TARGET samples
# cleanly, the hdds-micro RTPS stack on seL4 interoperates with the
# same stack on Linux.
#
# Usage:
#   crates/hdds-micro-sel4/scripts/test-interop-sel4-to-linux.sh           # default: 100 samples, 30 s
#   crates/hdds-micro-sel4/scripts/test-interop-sel4-to-linux.sh --count 500 --timeout 60
#   crates/hdds-micro-sel4/scripts/test-interop-sel4-to-linux.sh --keep    # leave QEMU + logs running

set -euo pipefail

MICROKIT_SDK="${MICROKIT_SDK:?set MICROKIT_SDK to the Microkit SDK root}"
SDDF_ROOT="${SDDF_ROOT:?set SDDF_ROOT to the sDDF checkout}"
ECHO_DIR="${SDDF_ROOT}/examples/echo_server"
BUILD_DIR="${ECHO_DIR}/build"
LOADER_IMG="${BUILD_DIR}/loader.img"
QEMU_LOG="${QEMU_LOG:-/tmp/hdds-pub-qemu.log}"
SUB_LOG="${SUB_LOG:-/tmp/hdds-pub-sub.log}"
LLVM_BIN="${LLVM_BIN:-/usr/lib/llvm-19/bin}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SEL4_CRATE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
OVERLAY_DIR="${SEL4_CRATE_DIR}/microkit"
HDDS_SUB_DIR="${SEL4_CRATE_DIR}/host-tools/hdds_sub"
HDDS_SUB_BIN="${HDDS_SUB_DIR}/target/release/hdds_sub"

N_TARGET=100
TIMEOUT_SECS=30
KEEP_RUNNING=0
need_value() {
    # $1 = flag name (for error message), $2 = remaining argc
    if (( $2 < 2 )); then
        echo "[test-interop-sel4-to-linux] missing value for $1" >&2
        exit 2
    fi
}
while (( $# )); do
    case "$1" in
        --count)    need_value "$1" "$#"; N_TARGET=$2; shift 2 ;;
        --timeout)  need_value "$1" "$#"; TIMEOUT_SECS=$2; shift 2 ;;
        --keep)     KEEP_RUNNING=1; shift ;;
        -h|--help)
            sed -n '1,30p' "$0"
            exit 0
            ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

[[ -d "${MICROKIT_SDK}" ]] || { echo "MICROKIT_SDK not found: ${MICROKIT_SDK}" >&2; exit 2; }
[[ -d "${ECHO_DIR}"     ]] || { echo "echo_server not found: ${ECHO_DIR}" >&2; exit 2; }
[[ -d "${LLVM_BIN}"     ]] || { echo "LLVM 19 not found: ${LLVM_BIN}" >&2; exit 2; }
command -v qemu-system-aarch64 >/dev/null || { echo "qemu-system-aarch64 not in PATH" >&2; exit 2; }
command -v cargo               >/dev/null || { echo "cargo not in PATH" >&2; exit 2; }
python3 -c 'import importlib.util as u; from importlib.metadata import version; raise SystemExit(u.find_spec("sdfgen") is None or version("sdfgen") != "0.29.0")' \
    || { echo "sdfgen 0.29.0 is required; see crates/hdds-micro-sel4/README.md" >&2; exit 2; }

# ---------------------------------------------------------------- build
echo "[test-interop-sel4-to-linux] applying overlay + building (publisher feature)..."
cp -f "${OVERLAY_DIR}/meta.py"           "${ECHO_DIR}/meta.py"
cp -f "${OVERLAY_DIR}/echo.mk"           "${ECHO_DIR}/echo.mk"
cp -f "${OVERLAY_DIR}/single_core.json"  "${ECHO_DIR}/core_config/single_core.json"
cp -f "${OVERLAY_DIR}/client2_rust_wrapper.c" "${ECHO_DIR}/client2_rust_wrapper.c"

# echo.mk's staticlib rule is FORCE-marked - cargo always runs and
# picks up the CARGO_FEATURES change vs any previous build flavor.

cd "${ECHO_DIR}"
[[ -d build ]] && rm -rf build
PATH="${LLVM_BIN}:${PATH}" \
    MICROKIT_SDK="${MICROKIT_SDK}" \
    MICROKIT_BOARD=qemu_virt_aarch64 \
    MICROKIT_CONFIG=debug \
    TOOLCHAIN=clang \
    SEL4_CRATE_DIR="${SEL4_CRATE_DIR}" \
    CARGO_FEATURES=publisher \
    make BUILD_DIR=build >/dev/null

[[ -f "${LOADER_IMG}" ]] || { echo "[test-interop-sel4-to-linux] build did not produce loader.img" >&2; exit 1; }

# Build the host subscriber (idempotent).
(cd "${HDDS_SUB_DIR}" && cargo build --release >/dev/null 2>&1)
[[ -x "${HDDS_SUB_BIN}" ]] || { echo "[test-interop-sel4-to-linux] hdds_sub binary missing" >&2; exit 1; }

# ----------------------------------------------------------------- boot
echo "[test-interop-sel4-to-linux] booting QEMU (serial log: ${QEMU_LOG})..."
cd "${BUILD_DIR}"
# Pre-arm cleanup with empty PID so an interrupt between `&` and the
# assignment cannot orphan QEMU.
QEMU_PID=''
cleanup() {
    [[ -n "${QEMU_PID}" ]] || return 0
    if (( KEEP_RUNNING == 0 )); then
        kill "${QEMU_PID}" 2>/dev/null || true
        wait "${QEMU_PID}" 2>/dev/null || true
    else
        echo "[test-interop-sel4-to-linux] --keep set, leaving QEMU running as PID ${QEMU_PID}"
        echo "[test-interop-sel4-to-linux] kill with: kill ${QEMU_PID}"
    fi
}
trap cleanup EXIT INT TERM

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

# Boot-ready gate (same as run-echo-rust.sh).
for _ in $(seq 1 20); do
    if grep -q "IP address for netif client0" "${QEMU_LOG}" 2>/dev/null \
       && grep -q "IP address for netif client1" "${QEMU_LOG}" 2>/dev/null; then
        break
    fi
    sleep 1
done

if ! grep -q "Microkit Monitor started" "${QEMU_LOG}" 2>/dev/null; then
    echo "[test-interop-sel4-to-linux] BOOT FAILED - Microkit Monitor never started." >&2
    tail -30 "${QEMU_LOG}" >&2 || true
    exit 1
fi
sleep 1

# ----------------------------------------------------------------- test
echo "[test-interop-sel4-to-linux] running hdds_sub (target=${N_TARGET} samples, timeout=${TIMEOUT_SECS} s)..."
set +e
"${HDDS_SUB_BIN}" --count "${N_TARGET}" --timeout-secs "${TIMEOUT_SECS}" > "${SUB_LOG}" 2>&1
SUB_EXIT=$?
set -e

# ---------------------------------------------------------------- verdict
RX_COUNT=$(grep -c '^RX seq=' "${SUB_LOG}" || true)
echo "[test-interop-sel4-to-linux] hdds_sub exit=${SUB_EXIT}, sample lines counted = ${RX_COUNT}"

if (( RX_COUNT < N_TARGET )); then
    echo "[test-interop-sel4-to-linux] FAIL: ${RX_COUNT} < ${N_TARGET} required" >&2
    echo "--- last 30 lines of hdds_sub log ---" >&2
    tail -30 "${SUB_LOG}" >&2 || true
    echo "--- last 30 lines of QEMU serial ---" >&2
    tail -30 "${QEMU_LOG}" >&2 || true
    exit 1
fi

# Sequence-monotonicity check: parse `seq=<u64>` from each RX line.
# Strict increase required (publisher's MicroWriter::sequence_number
# starts at 1 and increments by 1).
MONOTONIC_OK=1
prev=0
while IFS= read -r seq; do
    if (( seq <= prev )); then
        echo "[test-interop-sel4-to-linux] FAIL: non-monotonic seq ${seq} after ${prev}" >&2
        MONOTONIC_OK=0
        break
    fi
    prev=$seq
done < <(grep -oE '^RX seq=[0-9]+' "${SUB_LOG}" | sed 's/^RX seq=//')

if (( MONOTONIC_OK == 0 )); then
    echo "--- last 30 lines of hdds_sub log ---" >&2
    tail -30 "${SUB_LOG}" >&2 || true
    exit 1
fi

# Any decode error line in the sub log fails the run.
if grep -q 'decode .* failed' "${SUB_LOG}"; then
    echo "[test-interop-sel4-to-linux] FAIL: decode errors observed" >&2
    grep 'decode .* failed' "${SUB_LOG}" >&2 || true
    exit 1
fi

echo "[test-interop-sel4-to-linux] PASS: ${RX_COUNT} samples received, sequence monotonic, zero decode errors"
echo "[test-interop-sel4-to-linux] full sub log: ${SUB_LOG}"
echo "[test-interop-sel4-to-linux] full QEMU log: ${QEMU_LOG}"
exit 0
