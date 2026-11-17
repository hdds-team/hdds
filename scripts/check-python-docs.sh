#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com
#
# Python SDK docs consistency check (called by scripts/test-sdk.sh Layer 1).
#
#  1. No 'maturin' or 'PyO3' anywhere in tracked docs/, sdk/python or
#     scripts/: the Python SDK is a pure-Python ctypes package; those two
#     words describe a build that never existed. A line that legitimately
#     names them (a comparison paragraph, an hdds_gen backend note) carries
#     the marker 'check-python-docs: allow' and is exempt; the rule stays a
#     ban on install recipes, not a repository-wide vocabulary ban.
#  2. No bare "pip install hdds" line in tracked docs/, sdk/python or
#     scripts/: the package is not on PyPI; the only
#     valid install form names a wheel file built from this repository
#     (pip install ... dist/hdds-<ver>-py3-none-any.whl).
#  3. The "Library Discovery Order" block in sdk/python/README.md is
#     byte-identical to the one in sdk/python/hdds/_native.py (single source
#     of truth for the loader's behaviour).
#
# Exit 0 when all hold, 1 otherwise, with the offending lines printed.
# The script refuses to run (exit 1) outside a git checkout: the tracked
# file list is what bounds the scan, and an empty list must never PASS.
# Usage: scripts/check-python-docs.sh [--root DIR]

set -euo pipefail

usage() {
    echo "usage: check-python-docs.sh [--root DIR]" >&2
    exit 1
}

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
if [[ "${1:-}" == "--root" ]]; then
    [[ $# -ge 2 ]] || usage
    ROOT=$(cd "$2" && pwd)
    shift 2
fi
# Any other argument is a typo, never a silently ignored one: the operator
# must not believe a different tree was scanned.
[[ $# -eq 0 ]] || { echo "check-python-docs: unknown argument: $1" >&2; usage; }

NATIVE="$ROOT/sdk/python/hdds/_native.py"
README="$ROOT/sdk/python/README.md"
status=0

if ! git -C "$ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    echo "check-python-docs: $ROOT is not a git checkout; the scan is bounded by 'git ls-files' and cannot run (refusing rather than passing vacuously)"
    exit 1
fi
for f in "$NATIVE" "$README"; do
    if [[ ! -f "$f" ]]; then
        echo "check-python-docs: missing $f"
        exit 1
    fi
done

# Tracked files only (git ls-files) so gitignored private docs never count;
# this script and the delta files that document the rules are excluded.
tracked_files() {
    git -C "$ROOT" ls-files -- docs sdk/python scripts \
        | grep -v -e '^scripts/check-python-docs.sh$' -e '^docs/deltas/'
}
tracked_count=$(tracked_files | wc -l)
if [[ "$tracked_count" -eq 0 ]]; then
    echo "check-python-docs: 'git ls-files' returned no tracked file under docs/, sdk/python, scripts/ in $ROOT"
    exit 1
fi

# --- 1. forbidden words ------------------------------------------------------
forbidden_hits=$(
    cd "$ROOT" && tracked_files | xargs -r grep -H -n -i -E 'maturin|pyo3' 2>/dev/null \
        | grep -v -F 'check-python-docs: allow' || true
)
if [[ -n "$forbidden_hits" ]]; then
    echo "check-python-docs: 'maturin'/'PyO3' must not appear (ctypes package):"
    echo "$forbidden_hits"
    status=1
else
    echo "check-python-docs: no maturin/PyO3 mention in docs/, sdk/python, scripts/ ($tracked_count tracked files)"
fi

# --- 2. no PyPI install line -------------------------------------------------
# A "pip install hdds" that is not followed by a wheel file name promises a
# PyPI package that does not exist. "pip install hdds-*.whl",
# "pip install ./dist/hdds-1.4.0-py3-none-any.whl" and "pip install -e ."
# are fine. Options are matched in any case (-U, --upgrade, -q) and the
# package name may be quoted ("hdds", 'hdds').
pypi_hits=$(
    cd "$ROOT" && tracked_files \
        | xargs -r grep -H -n -E 'pip[0-9]* +install +(-[-A-Za-z0-9]+ +)*["'"'"']?hdds([^-_A-Za-z0-9./]|$)' 2>/dev/null || true
)
if [[ -n "$pypi_hits" ]]; then
    echo "check-python-docs: bare 'pip install hdds' must not appear (not on PyPI; install the wheel built from this repository):"
    echo "$pypi_hits"
    status=1
else
    echo "check-python-docs: no bare 'pip install hdds' line in docs/, sdk/python, scripts/"
fi

# --- 3. discovery order block ------------------------------------------------
# From the marker line to the end of the enclosing block: the docstring
# terminator in _native.py ("""), the fenced-code terminator in README.md
# (```). Everything the docstring says about discovery is compared, not just
# the numbered list (same bounds as tests/test_native_discovery.py).
extract_block() {
    awk '
        /^Library Discovery Order:$/ { on = 1 }
        on && ($0 == "\"\"\"" || $0 == "```") { exit }
        on { print }
    ' "$1"
}

native_block=$(extract_block "$NATIVE")
readme_block=$(extract_block "$README")
if [[ -z "$native_block" ]]; then
    echo "check-python-docs: marker 'Library Discovery Order:' missing in $NATIVE"
    status=1
elif [[ "$native_block" != "$readme_block" ]]; then
    echo "check-python-docs: discovery order in README.md differs from _native.py docstring:"
    diff <(echo "$native_block") <(echo "$readme_block") || true
    status=1
else
    echo "check-python-docs: README.md discovery order == _native.py docstring ($(echo "$native_block" | wc -l) lines)"
fi

exit $status
