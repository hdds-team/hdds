#!/usr/bin/env bash
# Fails if any tracked CODE file contains a non-ASCII byte.
# Prose (*.md) is out of scope. Justified exceptions go in
# scripts/ascii-allowlist.txt (one repo-relative path per line, '#' comments).
# Deliberate UTF-8 test vectors should be written as escapes (\u{..} in Rust,
# \x.. in C, \u.... in Python) so the source itself stays ASCII.
# Usage: scripts/check-ascii.sh [-v]   (run from anywhere inside the repo)
set -u
cd "$(git rev-parse --show-toplevel)" || exit 2
allow="scripts/ascii-allowlist.txt"
ext='\.(rs|c|h|cpp|hpp|cc|py|sh|ts|toml|cmake|js|mjs|ino|lua|java|css|html|yaml|yml|idl|in|hooks|xml|json|txt)$'
names='(^|/)(Makefile|CMakeLists\.txt)$|(^|/)pre-commit[^/]*$'
tmp=$(mktemp) || exit 2
trap 'rm -f "$tmp"' EXIT

git ls-files -z | tr '\0' '\n' | grep -E "$ext|$names" | sort -u > "$tmp.list"
trap 'rm -f "$tmp" "$tmp.list"' EXIT

allowed() {
    [ -f "$allow" ] || return 1
    grep -vE '^\s*(#|$)' "$allow" | grep -qxF -- "$1"
}

bad=0
nfiles=0
while IFS= read -r f; do
    [ -f "$f" ] || continue
    nfiles=$((nfiles + 1))
    # LC_ALL=C: match raw bytes, independent of the caller's locale.
    if LC_ALL=C grep -qP '[^\x00-\x7F]' -- "$f" 2>/dev/null; then
        if allowed "$f"; then continue; fi
        bad=$((bad + 1))
        echo "NON-ASCII: $f"
        if [ "${1:-}" = "-v" ]; then
            LC_ALL=C grep -nP '[^\x00-\x7F]' -- "$f" | head -5 | sed 's/^/    /'
        fi
    fi
done < "$tmp.list"

echo "check-ascii: scanned=$nfiles violations=$bad"
[ "$bad" -eq 0 ]
