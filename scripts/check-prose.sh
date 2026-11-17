#!/usr/bin/env bash
# Fails if any tracked PROSE file contains a non-ASCII byte.
# Scope: *.md, *.txt, *.toml, *.yml, *.yaml. Code files are covered by
# scripts/check-ascii.sh. Each offending line is printed as file:line and
# counted once in violations=M.
# Justified exceptions (e.g. an accented person or place name) go in
# scripts/prose-allowlist.txt (one repo-relative path per line, '#' comments).
# Usage: scripts/check-prose.sh   (run from anywhere inside the repo)
set -u
cd "$(git rev-parse --show-toplevel)" || exit 2
allow="scripts/prose-allowlist.txt"
ext='\.(md|txt|toml|yml|yaml)$'
tmp=$(mktemp) || exit 2
trap 'rm -f "$tmp"' EXIT

git ls-files -z | tr '\0' '\n' | grep -E "$ext" | sort -u > "$tmp"

allowed() {
    [ -f "$allow" ] || return 1
    grep -vE '^\s*(#|$)' "$allow" | grep -qxF -- "$1"
}

bad=0
nfiles=0
while IFS= read -r f; do
    [ -f "$f" ] || continue
    nfiles=$((nfiles + 1))
    if allowed "$f"; then continue; fi
    # LC_ALL=C: match raw bytes, independent of the caller's locale.
    while IFS= read -r ln; do
        bad=$((bad + 1))
        echo "NON-ASCII: $f:$ln"
    done < <(LC_ALL=C grep -nP '[^\x00-\x7F]' -- "$f" 2>/dev/null | cut -d: -f1)
done < "$tmp"

echo "check-prose: scanned=$nfiles violations=$bad"
[ "$bad" -eq 0 ]
