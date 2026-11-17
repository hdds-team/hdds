#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

"""Validate that diffs between two `.bin` golden vectors are alignment-only.

Used post-encoder-change (e.g. F01 alignment fix, F29 DHEADER framing, future
`decode_cdr2_le_at` migration) to confirm a relock of `golden_vectors.rs`
is safe - i.e., every byte position where the old and new payloads differ
either falls at a CDR2-spec alignment boundary (1/2/4-byte, cap-4 for 8-byte
primitives per DDS-XTypes v1.3 sec. 7.4.3.4.1 Tab.15) and the new byte is the
zero-padding value required by sec. 7.4.3.4.2.

Exit codes:
  0 - every diff position is alignment-induced; relock is safe.
  1 - at least one diff position is NOT explained by alignment; manual
      investigation required (potential bug in the new encoder).
  2 - usage / I/O error.

LIMITATION: the diff is positional (compares old[i] vs new[i] index-by-index).
It correctly classifies TAIL-only zero-padding growth (the F01 case for
fixed-layout struct primitives), but it does NOT handle MIDDLE-insertion
alignment growth where bytes shift inside the payload. Example: F29 DHEADER
framing prepends a 4-byte u32 length at the front of a TypeObject container
- every subsequent byte shifts by 4, and the script will report each
shifted byte as `VALUE_DIFFERS` / `TRAILING_CONTENT` even though the relock
is alignment-only.

For shift-inducing relocks (F29, future DHEADER additions, decode_cdr2_le_at
migrations that may insert leading padding), do NOT rely on this script's
exit code. Either (a) use a sequence-diff tool that handles insertions
(diff/LCS) before falling back to this script, or (b) inspect the hex dump
manually. The script remains useful for: (1) confirming byte-identity in
the no-drift case, (2) auditing tail-only zero-pad growth, (3) catching
suspicious VALUE_DIFFERS at the head of a payload that should not have
shifted.

Example:
    # During a F29 fix, regenerate goldens, then diff each pair:
    GOLDEN_REGEN=1 cargo test --test golden_vectors
    for old in /tmp/old_goldens/*.bin; do
        new=crates/hdds/tests/golden/cdr2/$(basename "$old")
        python3 tools/diff-golden-bytes.py "$old" "$new" || break
    done

The script does NOT replace human review - it surfaces the unexplained
diffs so a human can decide if the change is intentional (spec catch-up)
or a regression.
"""

from __future__ import annotations

import sys
from pathlib import Path


def load(path: Path) -> bytes:
    if not path.exists():
        print(f"ERROR: file not found: {path}", file=sys.stderr)
        sys.exit(2)
    return path.read_bytes()


def is_alignment_boundary(pos: int, align: int) -> bool:
    """Is `pos` an alignment boundary for an `align`-byte primitive?"""
    return pos % align == 0


def classify_diff(pos: int, old: bytes, new: bytes) -> str:
    """Return a one-word classification for the diff at `pos`."""
    # Past the end of one side: tail bytes of the longer encoding. If those
    # tail bytes in `new` are zero, classify as zero-pad growth (encoder
    # added alignment padding at the end). Otherwise it's a real content
    # extension - likely a relock that bears manual review anyway.
    if pos >= len(old):
        return "ZERO_PAD_GROWTH" if new[pos] == 0 else "TRAILING_CONTENT"
    if pos >= len(new):
        return "TRUNCATED" if old[pos] == 0 else "LOST_CONTENT"

    # Padding case: new byte is 0x00 and the position immediately precedes an
    # aligned boundary. Per XCDR2 sec. 7.4.3.4.2 padding bytes are zero-filled.
    if new[pos] == 0:
        # Check whether the next non-zero byte in `new` (or the end) sits at
        # an alignment boundary the old encoding may have skipped.
        for align in (2, 4):
            # Cap-4 covers 8-byte primitives per Tab.15.
            scan = pos
            while scan < len(new) and new[scan] == 0:
                scan += 1
            if is_alignment_boundary(scan, align):
                return f"ZERO_PAD_TO_ALIGN_{align}"

    # Same position but value differs (not zero pad): suspect.
    if old[pos] != new[pos]:
        return "VALUE_DIFFERS"

    return "UNCLASSIFIED"


def diff_pair(old_path: Path, new_path: Path) -> int:
    old = load(old_path)
    new = load(new_path)
    name = new_path.stem

    if old == new:
        print(f"[OK]  {name}: byte-identical ({len(old)} bytes)")
        return 0

    unexplained: list[tuple[int, str]] = []
    explained = 0
    max_len = max(len(old), len(new))
    for pos in range(max_len):
        if pos < len(old) and pos < len(new) and old[pos] == new[pos]:
            continue
        cls = classify_diff(pos, old, new)
        if cls.startswith("ZERO_PAD_TO_ALIGN") or cls == "ZERO_PAD_GROWTH":
            explained += 1
        else:
            unexplained.append((pos, cls))

    if unexplained:
        print(
            f"[FAIL] {name}: {len(unexplained)} unexplained diff(s), "
            f"{explained} alignment-induced - manual review required"
        )
        for pos, cls in unexplained[:8]:
            o = f"0x{old[pos]:02x}" if pos < len(old) else "--"
            n = f"0x{new[pos]:02x}" if pos < len(new) else "--"
            print(f"       offset={pos:#06x} ({pos:>5}) old={o} new={n} class={cls}")
        if len(unexplained) > 8:
            print(f"       ... +{len(unexplained) - 8} more")
        return 1

    print(
        f"[PASS] {name}: {explained} alignment-induced diff(s), "
        f"old={len(old)}b new={len(new)}b - relock safe"
    )
    return 0


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print(
            "usage: diff-golden-bytes.py <old.bin> <new.bin>\n"
            "       diff-golden-bytes.py <old_dir/> <new_dir/>  (batch)",
            file=sys.stderr,
        )
        return 2

    old_path = Path(argv[1])
    new_path = Path(argv[2])

    if old_path.is_dir() and new_path.is_dir():
        bins = sorted(p.name for p in old_path.glob("*.bin"))
        exit_code = 0
        for name in bins:
            rc = diff_pair(old_path / name, new_path / name)
            if rc != 0:
                exit_code = rc
        return exit_code

    return diff_pair(old_path, new_path)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
