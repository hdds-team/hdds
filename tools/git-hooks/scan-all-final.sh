#!/bin/bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com


################################################################################
# HDDS Full Codebase Scan -- Final Release Mode (v1.0.0)
#
# Zero whitelist, all markers = errors
#
# Usage:
#  ./tools/git-hooks/scan-all-final.sh
#  ./tools/git-hooks/scan-all-final.sh --verbose
################################################################################

set -u

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly FINAL_CHECK="${SCRIPT_DIR}/pre-commit-stubs-check-final"

VERBOSE=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --verbose) VERBOSE=1 ;;
        *) echo "Unknown flag: $1"; exit 1 ;;
    esac
    shift
done

if [[ ! -f "$FINAL_CHECK" ]]; then
    echo "[X] Final check script not found: $FINAL_CHECK"
    exit 1
fi

env HDDS_FINAL_CHECK_VERBOSE=$VERBOSE "$FINAL_CHECK" "codebase"
