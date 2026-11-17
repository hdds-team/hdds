#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2026 naskel.com
#
# Build the intra-guest pub/sub system (loopback driver PD,
# no NIC) for one Microkit board, without booting it. Used to produce
# images for real hardware (rpi4b_8gb) and for QEMU proxies
# (qemu_virt_aarch64, rpi4b_2gb for QEMU's raspi4b machine).
#
# Usage:
#   crates/hdds-micro-sel4/scripts/build-inguest-board.sh BOARD OUT_DIR
#
# Environment:
#   MICROKIT_SDK  Microkit SDK root (required)
#   SDDF_ROOT     isolated sDDF checkout; examples/echo_server is overwritten
#   SDFGEN_VENV   venv holding sdfgen 0.29.0 (optional, prepended to PATH)
#   CARGO_LOCK    if set, the make run (which invokes cargo) holds flock on it
#
# Prints the loader.img path and its md5 on success.

set -euo pipefail

[[ $# -eq 2 ]] || { echo "usage: $0 BOARD OUT_DIR" >&2; exit 2; }
BOARD="$1"
OUT_DIR="$(realpath -m "$2")"

MICROKIT_SDK="${MICROKIT_SDK:?set MICROKIT_SDK to the Microkit SDK root}"
SDDF_ROOT="${SDDF_ROOT:?SDDF_ROOT must point at an isolated sDDF checkout}"
LLVM_BIN="${LLVM_BIN:-/usr/lib/llvm-19/bin}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SEL4_CRATE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
OVERLAY_DIR="${SEL4_CRATE_DIR}/microkit"
ECHO_DIR="${SDDF_ROOT}/examples/echo_server"

[[ -d "${MICROKIT_SDK}/board/${BOARD}" ]] \
    || { echo "board ${BOARD} not in ${MICROKIT_SDK}" >&2; exit 1; }
[[ -d "${ECHO_DIR}" ]] || { echo "echo_server not found: ${ECHO_DIR}" >&2; exit 1; }

if [[ -n "${SDFGEN_VENV:-}" ]]; then
    PATH="${SDFGEN_VENV}/bin:${PATH}"
fi
python3 -c 'import importlib.util as u; from importlib.metadata import version; raise SystemExit(u.find_spec("sdfgen") is None or version("sdfgen") != "0.29.0")' \
    || { echo "sdfgen 0.29.0 is required (set SDFGEN_VENV)" >&2; exit 1; }

cp -f "${OVERLAY_DIR}/meta_loopback.py"       "${ECHO_DIR}/meta_loopback.py"
cp -f "${OVERLAY_DIR}/echo_loopback.mk"       "${ECHO_DIR}/echo.mk"
cp -f "${OVERLAY_DIR}/loopback_driver.c"      "${ECHO_DIR}/loopback_driver.c"
cp -f "${OVERLAY_DIR}/client2_rust_wrapper.c" "${ECHO_DIR}/client2_rust_wrapper.c"
cp -f "${OVERLAY_DIR}/client3_rust_wrapper.c" "${ECHO_DIR}/client3_rust_wrapper.c"

MAKE_CMD=(make -C "${ECHO_DIR}" BUILD_DIR="${OUT_DIR}"
          MICROKIT_SDK="${MICROKIT_SDK}" MICROKIT_BOARD="${BOARD}"
          MICROKIT_CONFIG=debug TOOLCHAIN=clang
          SEL4_CRATE_DIR="${SEL4_CRATE_DIR}")
if [[ -n "${CARGO_LOCK:-}" ]]; then
    MAKE_CMD=(flock "${CARGO_LOCK}" "${MAKE_CMD[@]}")
fi

PATH="${LLVM_BIN}:${PATH}" "${MAKE_CMD[@]}"

[[ -f "${OUT_DIR}/loader.img" ]] || { echo "build did not produce loader.img" >&2; exit 1; }
md5sum "${OUT_DIR}/loader.img"
