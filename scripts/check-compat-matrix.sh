#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com
#
# Compatibility-matrix gate: the two values a pairing is read from must be the
# two values docs/compatibility.md states.
#
# Reads, from this tree:
#   - CODEGEN_ABI in crates/hdds/src/codegen.rs      (what this runtime provides)
#   - version in [workspace.package] of Cargo.toml   (the workspace version)
#
# Fails (non-zero) when either value is not in docs/compatibility.md, so a
# bumped ABI or a bumped version cannot ship beside a stale matrix.
#
# What it does NOT check: the prose and the pairing rows of the matrix. Those
# depend on the separate code generator repository and cannot be re-derived
# from this tree.
#
# The two shapes it anchors on:
#
#   - `CODEGEN_ABI` in `crates/hdds/src/codegen.rs`: <n>
#   - workspace version in `Cargo.toml`: <v>
#
# Usage:  scripts/check-compat-matrix.sh
set -euo pipefail

cd "$(dirname "$0")/.."

DOC="docs/compatibility.md"
CODEGEN_RS="crates/hdds/src/codegen.rs"
MANIFEST="Cargo.toml"
TABLE_KEY="1.5.0"

fail=0
note() { printf 'FAIL: %s\n' "$1" >&2; fail=1; }

if [ ! -f "$DOC" ]; then
  printf 'FAIL: %s does not exist\n' "$DOC" >&2
  exit 1
fi

# --- what the tree says ------------------------------------------------------

if [ ! -f "$CODEGEN_RS" ]; then
  printf 'FAIL: %s does not exist: this runtime provides no CODEGEN_ABI at all\n' \
    "$CODEGEN_RS" >&2
  exit 1
fi

ABI="$(sed -n 's/^pub const CODEGEN_ABI: u32 = \([0-9][0-9]*\);$/\1/p' "$CODEGEN_RS")"
if [ -z "$ABI" ]; then
  printf 'FAIL: no "pub const CODEGEN_ABI: u32 = <n>;" line in %s\n' "$CODEGEN_RS" >&2
  exit 1
fi

# The first `version =` is not the workspace version in every manifest shape,
# so read it inside the [workspace.package] table only.
VERSION="$(awk '
  /^\[/ { in_pkg = ($0 == "[workspace.package]") ; next }
  in_pkg && /^version = "/ { gsub(/^version = "|"$/, ""); print; exit }
' "$MANIFEST")"
if [ -z "$VERSION" ]; then
  printf 'FAIL: no version under [workspace.package] in %s\n' "$MANIFEST" >&2
  exit 1
fi

printf 'tree: CODEGEN_ABI=%s  workspace version=%s\n' "$ABI" "$VERSION"

# --- what the document says --------------------------------------------------

# 1. The literal requirement: the value has to be present at all.
grep -qF -- "$ABI" "$DOC" \
  || note "CODEGEN_ABI value '$ABI' does not appear anywhere in $DOC"

grep -qF -- "$VERSION" "$DOC" \
  || note "workspace version '$VERSION' does not appear anywhere in $DOC"

# 2. The anti-drift part: the "Values this release carries" block must state
#    both numbers next to their source, which is what makes a stale block
#    visible instead of a value that matches by accident somewhere in prose.
grep -qE "^- \`CODEGEN_ABI\` in \`${CODEGEN_RS//./\\.}\`: ${ABI}$" "$DOC" \
  || note "$DOC does not state '- \`CODEGEN_ABI\` in \`$CODEGEN_RS\`: $ABI'"

grep -qE "^- workspace version in \`${MANIFEST//./\\.}\`: ${VERSION}$" "$DOC" \
  || note "$DOC does not state '- workspace version in \`$MANIFEST\`: $VERSION'"

# 3. The current version must own a table row (the table is keyed by hdds
#    version), so a version bump cannot leave the matrix without a row for it.
grep -qE "^\| ${VERSION//./\\.}([^0-9.]|$)" "$DOC" \
  || note "$DOC has no table row starting with '| $VERSION'"

if [ "$fail" -ne 0 ]; then
  printf '\nThe matrix and the tree disagree: update %s or\n' "$DOC" >&2
  printf 'revert the version/ABI change. See %s for the source of each number.\n' "$DOC" >&2
  exit 1
fi

printf 'OK: %s agrees with %s and %s\n' "$DOC" "$CODEGEN_RS" "$MANIFEST"
