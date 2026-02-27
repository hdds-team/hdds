#!/bin/bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com


################################################################################
# Install HDDS Git Hooks
#
# Usage: ./tools/git-hooks/install.sh
# 
# Installs:
#  - pre-commit-stubs-check -> .git/hooks/pre-commit
#
# Uninstall: rm .git/hooks/pre-commit
################################################################################

set -e

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly GIT_ROOT="$(git rev-parse --show-toplevel 2>/dev/null)"
readonly HOOKS_DIR="${GIT_ROOT}/.git/hooks"

if [[ ! -d "$HOOKS_DIR" ]]; then
    echo "[X] Not in a git repository"
    exit 1
fi

echo "🔗 Installing HDDS git hooks..."

# Install pre-commit hook
PRE_COMMIT_HOOK="${HOOKS_DIR}/pre-commit"
STUB_CHECK_SCRIPT="${SCRIPT_DIR}/pre-commit-stubs-check"

if [[ ! -f "$STUB_CHECK_SCRIPT" ]]; then
    echo "[X] Hook script not found: $STUB_CHECK_SCRIPT"
    exit 1
fi

# Backup existing hook if present
if [[ -f "$PRE_COMMIT_HOOK" ]]; then
    echo "[!]  Backing up existing pre-commit hook..."
    cp "$PRE_COMMIT_HOOK" "${PRE_COMMIT_HOOK}.backup"
fi

# Copy and make executable
cp "$STUB_CHECK_SCRIPT" "$PRE_COMMIT_HOOK"
chmod +x "$PRE_COMMIT_HOOK"

echo "[OK] Installed: $PRE_COMMIT_HOOK"
echo ""
echo "Configuration:"
echo "  HDDS_STUB_CHECK_STRICT=1        # Fail on warnings"
echo "  HDDS_STUB_CHECK_VERBOSE=1       # Show context"
echo "  HDDS_STUB_CHECK_EXCLUDE=tests   # Exclude patterns"
echo ""
echo "Usage:"
echo "  git commit                                    # Normal commit with hook"
echo "  HDDS_STUB_CHECK_STRICT=1 git commit          # Strict mode"
echo "  git commit --no-verify                        # Skip hook"
echo ""
echo "Uninstall: rm $PRE_COMMIT_HOOK"
