#!/bin/bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

# Auto-increment build version on each compile
# Format: MAJOR.MINOR.BUILD
# - BUILD: auto-increment on each build
# - MINOR: auto-increment every 10,000 builds (BUILD resets to 0)
# - MAJOR: manual only
#
# Single-source rule: every SDK carries the workspace version. This script
# is the BUILD COUNTER, not the release tool (a release bump is a hand
# edit of Cargo.toml plus the SDK files below); it only keeps the two in
# step by rewriting
#   sdk/python/hdds/__version__ = "..."   (sdk/python/hdds/__init__.py;
#                                         pyproject.toml reads it dynamically)
#   sdk/typescript/package.json      "version"
#   sdk/typescript/package-lock.json "version" (twice: top level and
#                                         packages[""], which npm keeps in step)
#   sdk/cmake/hdds-config-version.cmake PACKAGE_VERSION (find_package(hdds X.Y))
#   sdk/cxx/CMakeLists.txt           project(hdds_cxx VERSION X.Y.Z ...)
# alongside Cargo.toml. The enforced mechanism is scripts/test-sdk.sh
# Layer 1, which FAILS when the versions diverge. Every SDK file is checked
# to carry the current version BEFORE anything is rewritten, so a drifted
# tree is left untouched (exit 1) rather than half-bumped. Add any new
# version-carrying SDK file to SDK_VERSION_FILES below, never a second
# hand-edited number.
#
# Usage: ./scripts/bump-version.sh [cargo.toml_path]

set -e

CARGO_TOML="${1:-Cargo.toml}"
BUILD_WRAP=10000  # MINOR increments every 10,000 builds

if [ ! -f "$CARGO_TOML" ]; then
    echo "Error: $CARGO_TOML not found"
    exit 1
fi

# Extract current version from workspace.package.version or package.version
CURRENT=$(grep -E '^version\s*=' "$CARGO_TOML" | head -1 | sed 's/.*"\([^"]*\)".*/\1/')

if [ -z "$CURRENT" ]; then
    echo "Error: Could not extract version from $CARGO_TOML"
    exit 1
fi

# Parse MAJOR.MINOR.BUILD
IFS='.' read -r MAJOR MINOR BUILD <<< "$CURRENT"

# Handle case where BUILD might be empty (e.g., "1.0" instead of "1.0.0")
if [ -z "$BUILD" ]; then
    BUILD=0
fi

# Increment BUILD
BUILD=$((BUILD + 1))

# Check if we need to increment MINOR
if [ "$BUILD" -ge "$BUILD_WRAP" ]; then
    MINOR=$((MINOR + 1))
    BUILD=0
    echo ">>> MINOR version bump: $MAJOR.$((MINOR-1)).x -> $MAJOR.$MINOR.0"
fi

NEW_VERSION="$MAJOR.$MINOR.$BUILD"

# SDK files that carry the workspace version; each must hold $CURRENT
# before ANY file is rewritten (no half-bumped tree on drift).
REPO_DIR="$(cd "$(dirname "$CARGO_TOML")" && pwd)"
SDK_VERSION_FILES=(
    "sdk/python/hdds/__init__.py"
    "sdk/typescript/package.json"
    "sdk/typescript/package-lock.json"
    "sdk/cmake/hdds-config-version.cmake"
    "sdk/cxx/CMakeLists.txt"
)
# Version pattern per SDK file, set in the CALLING shell (never in a command
# substitution): a missing arm must abort the whole script, and `exit` inside
# $( ) only leaves the subshell. An empty pattern is refused too, because
# `grep -q ""` matches anything and would turn the pre-check, the rewrite and
# the post-check into no-ops on a file that was never touched.
PATTERN=""
resolve_pattern() {
    PATTERN=""
    case "$1" in
        sdk/python/hdds/__init__.py) PATTERN="^__version__ = \"$2\"" ;;
        sdk/typescript/package.json)      PATTERN="^  \"version\": \"$2\",\$" ;;
        sdk/typescript/package-lock.json) PATTERN="^  \"version\": \"$2\",\$" ;;
        sdk/cmake/hdds-config-version.cmake) PATTERN="^set(PACKAGE_VERSION \"$2\")\$" ;;
        sdk/cxx/CMakeLists.txt) PATTERN="^project(hdds_cxx VERSION $2 LANGUAGES CXX)\$" ;;
        *)
            echo "Error: no version pattern for $1 (add an arm to resolve_pattern and to rewrite_version)" >&2
            exit 1
            ;;
    esac
    if [ -z "$PATTERN" ]; then
        echo "Error: empty version pattern for $1" >&2
        exit 1
    fi
}

rewrite_version() {
    # $1 = repo-relative name, $2 = absolute path, $3 = old, $4 = new
    case "$1" in
        sdk/python/hdds/__init__.py)
            sed -i "s/^__version__ = \"$3\"/__version__ = \"$4\"/" "$2"
            ;;
        sdk/typescript/package.json)
            sed -i "s/^  \"version\": \"$3\",\$/  \"version\": \"$4\",/" "$2"
            ;;
        sdk/cmake/hdds-config-version.cmake)
            sed -i "s/^set(PACKAGE_VERSION \"$3\")\$/set(PACKAGE_VERSION \"$4\")/" "$2"
            ;;
        sdk/cxx/CMakeLists.txt)
            sed -i "s/^project(hdds_cxx VERSION $3 LANGUAGES CXX)\$/project(hdds_cxx VERSION $4 LANGUAGES CXX)/" "$2"
            ;;
        sdk/typescript/package-lock.json)
            # Two lines, and only two: the top-level one and the one inside
            # packages[""] (the package's own entry). Every other "version"
            # in this file belongs to a dependency and must not move, which
            # is why this is an anchored awk and not a global sed.
            awk -v new="$4" '''
                /^  "version": "/ && !top { print "  \"version\": \"" new "\","; top = 1; next }
                /^    "": \{/ { inroot = 1 }
                inroot && /^      "version": "/ {
                    print "      \"version\": \"" new "\","; inroot = 0; next
                }
                { print }
            ''' "$2" > "$2.bump.tmp" && mv "$2.bump.tmp" "$2"
            moved=$(grep -c "\"version\": \"$4\"," "$2" | head -1)
            if [ "$moved" -lt 2 ]; then
                echo "Error: $1 kept fewer than the two expected $4 version lines" >&2
                exit 1
            fi
            ;;
        *)
            echo "Error: no rewrite rule for $1" >&2
            exit 1
            ;;
    esac
}

# Pre-flight: EVERY listed file must carry $CURRENT before anything is
# rewritten, so a drifted tree is left untouched (exit 1) rather than
# half-bumped.
for rel in "${SDK_VERSION_FILES[@]}"; do
    f="$REPO_DIR/$rel"
    [ -f "$f" ] || continue
    resolve_pattern "$rel" "$CURRENT"
    if ! grep -q "$PATTERN" "$f"; then
        echo "Error: $rel does not carry the workspace version $CURRENT; nothing rewritten." >&2
        echo "       Fix it by hand (single-source rule; scripts/test-sdk.sh Layer 1 fails on this drift)." >&2
        exit 1
    fi
done

# Update the version in Cargo.toml
# Handle both workspace.package.version and package.version formats
if grep -q '^\[workspace\.package\]' "$CARGO_TOML"; then
    # Workspace format - update version under [workspace.package]
    sed -i "s/^version = \"$CURRENT\"/version = \"$NEW_VERSION\"/" "$CARGO_TOML"
else
    # Standard format
    sed -i "s/^version = \"$CURRENT\"/version = \"$NEW_VERSION\"/" "$CARGO_TOML"
fi

# Propagate to the SDK files (all verified above to carry $CURRENT).
for rel in "${SDK_VERSION_FILES[@]}"; do
    f="$REPO_DIR/$rel"
    [ -f "$f" ] || continue
    rewrite_version "$rel" "$f" "$CURRENT" "$NEW_VERSION"
    resolve_pattern "$rel" "$NEW_VERSION"
    if ! grep -q "$PATTERN" "$f"; then
        echo "Error: $rel rewrite to $NEW_VERSION failed" >&2
        exit 1
    fi
    echo "  $rel: $CURRENT > $NEW_VERSION"
done

echo "$CURRENT > $NEW_VERSION"
