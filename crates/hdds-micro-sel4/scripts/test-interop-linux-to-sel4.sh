#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2026 naskel.com
#
# Subscriber integration test: boot the seL4 subscriber PD under
# QEMU, drive it with the host-side hdds_pub for up to ~30 s, then
# count `RX seq=` lines in the QEMU serial log and verify sequence-
# number monotonicity. Exit 0 iff >= N_TARGET samples logged with
# strictly increasing sequence numbers and zero decode-error markers.
#
# What it checks: the symmetric counterpart to test-interop-sel4-to-linux.sh,
# which exercises TX through the Sel4Ring + sDDF net path; this test
# exercises RX with a full RTPS DATA decode via MicroReader. If the PD
# logs >= N_TARGET ordered samples, the embedded RTPS/CDR parser
# decodes what the same stack emits on Linux.
#
# Usage:
#   crates/hdds-micro-sel4/scripts/test-interop-linux-to-sel4.sh           # default: 100, 30 s
#   crates/hdds-micro-sel4/scripts/test-interop-linux-to-sel4.sh --count 500 --timeout 60
#   crates/hdds-micro-sel4/scripts/test-interop-linux-to-sel4.sh --keep    # leave QEMU running

set -euo pipefail

MICROKIT_SDK="${MICROKIT_SDK:?set MICROKIT_SDK to the Microkit SDK root}"
SDDF_ROOT="${SDDF_ROOT:?set SDDF_ROOT to the sDDF checkout}"
ECHO_DIR="${SDDF_ROOT}/examples/echo_server"
BUILD_DIR="${ECHO_DIR}/build"
LOADER_IMG="${BUILD_DIR}/loader.img"
QEMU_LOG="${QEMU_LOG:-/tmp/hdds-sub-qemu.log}"
PUB_LOG="${PUB_LOG:-/tmp/hdds-sub-pub.log}"
LLVM_BIN="${LLVM_BIN:-/usr/lib/llvm-19/bin}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SEL4_CRATE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
OVERLAY_DIR="${SEL4_CRATE_DIR}/microkit"
HDDS_PUB_DIR="${SEL4_CRATE_DIR}/host-tools/hdds_pub"
HDDS_PUB_BIN="${HDDS_PUB_DIR}/target/release/hdds_pub"

# hdds_pub --count = N_PUB; we require N_TARGET samples logged by the
# PD. N_PUB > N_TARGET gives headroom for any BEST_EFFORT drop early in
# the run (e.g. before ARP / SLIRP plumbing settles).
N_TARGET=100
N_PUB=200
TIMEOUT_SECS=30
KEEP_RUNNING=0
need_value() {
    if (( $2 < 2 )); then
        echo "[test-interop-linux-to-sel4] missing value for $1" >&2
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
# Drive 2x target so BEST_EFFORT slack doesn't sink the run.
N_PUB=$(( N_TARGET * 2 ))

[[ -d "${MICROKIT_SDK}" ]] || { echo "MICROKIT_SDK not found: ${MICROKIT_SDK}" >&2; exit 2; }
[[ -d "${ECHO_DIR}"     ]] || { echo "echo_server not found: ${ECHO_DIR}" >&2; exit 2; }
[[ -d "${LLVM_BIN}"     ]] || { echo "LLVM 19 not found: ${LLVM_BIN}" >&2; exit 2; }
command -v qemu-system-aarch64 >/dev/null || { echo "qemu-system-aarch64 not in PATH" >&2; exit 2; }
command -v cargo               >/dev/null || { echo "cargo not in PATH" >&2; exit 2; }
python3 -c 'import importlib.util as u; from importlib.metadata import version; raise SystemExit(u.find_spec("sdfgen") is None or version("sdfgen") != "0.29.0")' \
    || { echo "sdfgen 0.29.0 is required; see crates/hdds-micro-sel4/README.md" >&2; exit 2; }

# ---------------------------------------------------------------- build
echo "[test-interop-linux-to-sel4] applying overlay + building (subscriber feature)..."
cp -f "${OVERLAY_DIR}/meta.py"           "${ECHO_DIR}/meta.py"
cp -f "${OVERLAY_DIR}/echo.mk"           "${ECHO_DIR}/echo.mk"
cp -f "${OVERLAY_DIR}/single_core.json"  "${ECHO_DIR}/core_config/single_core.json"
cp -f "${OVERLAY_DIR}/client2_rust_wrapper.c" "${ECHO_DIR}/client2_rust_wrapper.c"

cd "${ECHO_DIR}"
[[ -d build ]] && rm -rf build
PATH="${LLVM_BIN}:${PATH}" \
    MICROKIT_SDK="${MICROKIT_SDK}" \
    MICROKIT_BOARD=qemu_virt_aarch64 \
    MICROKIT_CONFIG=debug \
    TOOLCHAIN=clang \
    SEL4_CRATE_DIR="${SEL4_CRATE_DIR}" \
    CARGO_FEATURES=subscriber \
    make BUILD_DIR=build >/dev/null

[[ -f "${LOADER_IMG}" ]] || { echo "[test-interop-linux-to-sel4] build did not produce loader.img" >&2; exit 1; }

(cd "${HDDS_PUB_DIR}" && cargo build --release >/dev/null 2>&1)
[[ -x "${HDDS_PUB_BIN}" ]] || { echo "[test-interop-linux-to-sel4] hdds_pub binary missing" >&2; exit 1; }

# ----------------------------------------------------------------- boot
echo "[test-interop-linux-to-sel4] booting QEMU (serial log: ${QEMU_LOG})..."
cd "${BUILD_DIR}"

QEMU_PID=''
cleanup() {
    [[ -n "${QEMU_PID}" ]] || return 0
    if (( KEEP_RUNNING == 0 )); then
        kill "${QEMU_PID}" 2>/dev/null || true
        wait "${QEMU_PID}" 2>/dev/null || true
    else
        echo "[test-interop-linux-to-sel4] --keep set, leaving QEMU running as PID ${QEMU_PID}"
        echo "[test-interop-linux-to-sel4] kill with: kill ${QEMU_PID}"
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

for _ in $(seq 1 20); do
    if grep -q "IP address for netif client0" "${QEMU_LOG}" 2>/dev/null \
       && grep -q "IP address for netif client1" "${QEMU_LOG}" 2>/dev/null; then
        break
    fi
    sleep 1
done

if ! grep -q "Microkit Monitor started" "${QEMU_LOG}" 2>/dev/null; then
    echo "[test-interop-linux-to-sel4] BOOT FAILED - Microkit Monitor never started." >&2
    tail -30 "${QEMU_LOG}" >&2 || true
    exit 1
fi
sleep 1

# Subscriber init banner sanity-check - confirms the right build
# flavor is running before we start blasting samples.
if ! grep -q "hdds-sel4: subscriber ready" "${QEMU_LOG}" 2>/dev/null; then
    echo "[test-interop-linux-to-sel4] subscriber init banner not found - wrong build flavor?" >&2
    tail -30 "${QEMU_LOG}" >&2 || true
    exit 1
fi

# ----------------------------------------------------------------- test
echo "[test-interop-linux-to-sel4] running hdds_pub (sending ${N_PUB} samples, target=${N_TARGET}, timeout=${TIMEOUT_SECS} s)..."
set +e
timeout "${TIMEOUT_SECS}" "${HDDS_PUB_BIN}" --count "${N_PUB}" > "${PUB_LOG}" 2>&1
PUB_EXIT=$?
set -e

# Give the PD a beat to flush any in-flight notifications + serial.
sleep 1

# ---------------------------------------------------------------- verdict
RX_COUNT=$(grep -c '^RX seq=' "${QEMU_LOG}" || true)
echo "[test-interop-linux-to-sel4] hdds_pub exit=${PUB_EXIT}, PD-logged RX lines = ${RX_COUNT}"

if (( RX_COUNT < N_TARGET )); then
    echo "[test-interop-linux-to-sel4] FAIL: ${RX_COUNT} < ${N_TARGET} required" >&2
    echo "--- last 30 lines of hdds_pub log ---" >&2
    tail -30 "${PUB_LOG}" >&2 || true
    echo "--- last 30 lines of QEMU serial ---" >&2
    tail -30 "${QEMU_LOG}" >&2 || true
    exit 1
fi

# Monotonicity: the PD logs `RX seq=<n>` per received sample. Strict
# increase required (publisher's SequenceNumber starts at 1 and
# increments by 1 - BEST_EFFORT drops are allowed but skips, never
# regressions).
MONOTONIC_OK=1
prev=0
while IFS= read -r seq; do
    if (( seq <= prev )); then
        echo "[test-interop-linux-to-sel4] FAIL: non-monotonic seq ${seq} after ${prev}" >&2
        MONOTONIC_OK=0
        break
    fi
    prev=$seq
done < <(grep -oE '^RX seq=[0-9]+' "${QEMU_LOG}" | sed 's/^RX seq=//')

if (( MONOTONIC_OK == 0 )); then
    echo "--- last 30 lines of QEMU serial ---" >&2
    tail -30 "${QEMU_LOG}" >&2 || true
    exit 1
fi

if grep -q "WARN non-monotonic" "${QEMU_LOG}"; then
    # The PD itself flagged a non-monotonic seq - should never happen
    # for a single publisher; surface as a hard fail.
    echo "[test-interop-linux-to-sel4] FAIL: PD logged non-monotonic warning" >&2
    grep "WARN non-monotonic" "${QEMU_LOG}" >&2 || true
    exit 1
fi

if grep -q "WARN decode failed" "${QEMU_LOG}"; then
    # Subscriber rejected a payload that decoded badly. A valid RTPS
    # header followed by a malformed CDR body is a real interop bug,
    # not BEST_EFFORT slack - fail hard so the test harness actually
    # proves CDR decode correctness, not just packet arrival.
    echo "[test-interop-linux-to-sel4] FAIL: PD logged decode failure" >&2
    grep "WARN decode failed" "${QEMU_LOG}" >&2 || true
    exit 1
fi

echo "[test-interop-linux-to-sel4] PASS: ${RX_COUNT} samples received by PD, sequence monotonic"
echo "[test-interop-linux-to-sel4] full QEMU log: ${QEMU_LOG}"
echo "[test-interop-linux-to-sel4] full hdds_pub log: ${PUB_LOG}"
exit 0
