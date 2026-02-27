#!/bin/bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

# Auto-increment build version on each compile
# Format: MAJOR.MINOR.BUILD
# - BUILD: auto-increment on each build
# - MINOR: auto-increment every 10,000 builds (BUILD resets to 0)
# - MAJOR: manual only
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

# Update the version in Cargo.toml
# Handle both workspace.package.version and package.version formats
if grep -q '^\[workspace\.package\]' "$CARGO_TOML"; then
    # Workspace format - update version under [workspace.package]
    sed -i "s/^version = \"$CURRENT\"/version = \"$NEW_VERSION\"/" "$CARGO_TOML"
else
    # Standard format
    sed -i "s/^version = \"$CURRENT\"/version = \"$NEW_VERSION\"/" "$CARGO_TOML"
fi

echo "$CURRENT > $NEW_VERSION"
