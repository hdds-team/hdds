#!/bin/bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com


################################################################################
# Install FINAL Release Pre-Commit Hook (v1.0.0)
#
# Usage: ./tools/git-hooks/install-final.sh
#
# Installs pre-commit-stubs-check-final (strict, no whitelist)
################################################################################

set -e

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly GIT_ROOT="$(git rev-parse --show-toplevel 2>/dev/null)"
readonly HOOKS_DIR="${GIT_ROOT}/.git/hooks"

if [[ ! -d "$HOOKS_DIR" ]]; then
    echo "[X] Not in a git repository"
    exit 1
fi

echo "🔗 Installing HDDS v1.0.0 FINAL pre-commit hook (strict, no whitelist)..."

PRE_COMMIT_HOOK="${HOOKS_DIR}/pre-commit"
FINAL_CHECK_SCRIPT="${SCRIPT_DIR}/pre-commit-stubs-check-final"

if [[ ! -f "$FINAL_CHECK_SCRIPT" ]]; then
    echo "[X] Hook script not found: $FINAL_CHECK_SCRIPT"
    exit 1
fi

# Backup existing
if [[ -f "$PRE_COMMIT_HOOK" ]]; then
    echo "[!]  Backing up existing: $PRE_COMMIT_HOOK"
    cp "$PRE_COMMIT_HOOK" "${PRE_COMMIT_HOOK}.backup.$(date +%s)"
fi

# Create wrapper that calls final version
cat > "$PRE_COMMIT_HOOK" << 'HOOK_WRAPPER'
#!/bin/bash
# Final Release Pre-Commit Hook
exec "$(git rev-parse --show-toplevel)/tools/git-hooks/pre-commit-stubs-check-final" "staged"
HOOK_WRAPPER

chmod +x "$PRE_COMMIT_HOOK"

echo "[OK] Installed: $PRE_COMMIT_HOOK"
echo ""
echo "🔒 FINAL RELEASE MODE (v1.0.0):"
echo "   * Zero whitelist -- ALL markers are errors"
echo "   * Blocks: TODO, FIXME, HACK, XXX, NOTE, panic!()"
echo "   * No exceptions -- production code only"
echo ""
echo "Usage:"
echo "  git commit                           # Hook runs, strict validation"
echo "  git commit --no-verify               # Skip hook (not recommended)"
echo "  make scan-final                      # Full codebase check"
echo ""
echo "To revert to development mode:"
echo "  ./tools/git-hooks/install.sh"
