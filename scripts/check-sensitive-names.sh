#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# Checks every tracked file (content and file names) against a word list
# supplied through the HDDS_SENSITIVE_NAMES environment variable and fails on
# any match. Matching is case-insensitive and word-ish (a name must not be
# glued to other letters or digits, so 'lambda' does not match a 3-letter
# name).
#
# The word list is not part of the repository. Point HDDS_SENSITIVE_NAMES at a
# file with one name per line ('#' comments and blank lines ignored). A missing
# or empty list is an ERROR (exit 2), never a green: a scan that silently
# checks nothing is worse than none. Only file:line locations are printed,
# never the matched text or the list.
#
# Usage: HDDS_SENSITIVE_NAMES=/path/to/list scripts/check-sensitive-names.sh
set -u
cd "$(git rev-parse --show-toplevel)" || exit 2

list="${HDDS_SENSITIVE_NAMES:-}"
if [ -z "$list" ] || [ ! -r "$list" ]; then
    echo "check-sensitive-names: HDDS_SENSITIVE_NAMES must point to a readable word list" >&2
    exit 2
fi

pat=""
while IFS= read -r name; do
    case "$name" in ''|'#'*) continue ;; esac
    esc=$(printf '%s' "$name" | sed 's/[][\.*^$+?(){}|/-]/\\&/g')
    pat="${pat:+$pat|}$esc"
done < "$list"
if [ -z "$pat" ]; then
    echo "check-sensitive-names: word list is empty: $list" >&2
    exit 2
fi
re="(?<![A-Za-z0-9])(?:$pat)(?![A-Za-z0-9])"

fail=0

# File contents (binary files included: -a), tracked files only.
hits=$(git grep -aniP -e "$re" 2>/dev/null | cut -d: -f1,2 | sort -u)
if [ -n "$hits" ]; then
    echo "SENSITIVE NAME in file content (file:line):"
    echo "$hits" | sed 's/^/    /'
    fail=1
fi

# Tracked file names.
nhits=$(git ls-files | grep -niP -e "$re" || true)
if [ -n "$nhits" ]; then
    echo "SENSITIVE NAME in tracked path:"
    echo "$nhits" | sed 's/^/    /'
    fail=1
fi

nfiles=$(git ls-files | wc -l)
if [ "$fail" -eq 0 ]; then
    echo "check-sensitive-names: scanned=$nfiles files, violations=0"
else
    echo "check-sensitive-names: FAILED (scanned=$nfiles files)"
fi
exit "$fail"
