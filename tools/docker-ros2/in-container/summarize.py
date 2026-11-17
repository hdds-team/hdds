#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com
"""Turn a directory of performance_test rounds into one summary.json.

Rules this summariser exists to enforce (ZERO BULLSHIT, and the reason the
January "18.4 us" number is not usable):

* EVERY round is accounted for: rounds_total, rounds_failed, rounds_zero_recv.
  The January batch had 9 usable rounds out of 57 and reported the best one.
* min / median / max, never a single figure. Best-of-N is not a measurement -
  and a "min/median/max" computed from ONE usable round is the same single
  figure printed three times, so a minimum usable-round count is enforced too.
* No headline is emitted at all when the measured middleware had a failed or
  zero-receive round: a number computed from a partially failing run cannot be
  compared with anything.
* The provenance stamp (tree SHA, image digest, rustc, performance_test
  commit, cpuset, CPU governor, topology) travels with the numbers.

Usage: summarize.py <rounds-dir> <stamp-json> [--measured-rmw rmw_hdds]
"""
from __future__ import annotations

import csv
import json
import os
import statistics
import sys

# Fewer usable rounds than this and min/median/max is one number wearing three
# hats. Three is the floor at which a median is not simply the only sample.
MIN_USABLE_ROUNDS = 3


def latency_rows(csv_path: str) -> list[float]:
    """Mean per-sample latency in MILLISECONDS of every data row of one round.

    The column read is `latency_mean (ms)`, and every key downstream is
    `latency_ms_*`. Saying "seconds" here would be a factor of 1000 sitting in
    a docstring, next to a historical figure quoted in MICROseconds.
    """
    values: list[float] = []
    try:
        with open(csv_path, newline="") as handle:
            # performance_test prefixes the CSV with a free-form header block;
            # the real table starts at the line whose first field is "T_experiment".
            lines = handle.read().splitlines()
    except OSError:
        return values

    start = None
    for i, line in enumerate(lines):
        if line.startswith("T_experiment"):
            start = i
            break
    if start is None:
        return values

    reader = csv.DictReader(lines[start:])
    for row in reader:
        raw = row.get("latency_mean (ms)") or row.get("latency_mean")
        received = row.get("received") or row.get("received_num") or "0"
        try:
            if float(received) <= 0:
                continue
            values.append(float(raw))
        except (TypeError, ValueError):
            continue
    return values


def main() -> int:
    if len(sys.argv) < 3:
        print(__doc__, file=sys.stderr)
        return 2
    rounds_dir = sys.argv[1]
    stamp_path = sys.argv[2]
    measured_rmw = "rmw_hdds"
    if "--measured-rmw" in sys.argv:
        measured_rmw = sys.argv[sys.argv.index("--measured-rmw") + 1]

    with open(stamp_path) as handle:
        summary = json.load(handle)

    verdicts_path = os.path.join(rounds_dir, "rounds.txt")
    per_rmw: dict[str, dict] = {}

    if os.path.exists(verdicts_path):
        with open(verdicts_path) as handle:
            for line in handle:
                parts = line.split()
                # ROUND <tag> <rmw> <role> <VERDICT> ...
                if len(parts) < 5 or parts[0] != "ROUND":
                    continue
                tag, rmw, role, verdict = parts[1], parts[2], parts[3], parts[4]
                entry = per_rmw.setdefault(
                    rmw,
                    {
                        "rounds_total": 0,
                        "rounds_failed": 0,
                        "rounds_zero_recv": 0,
                        "rounds_skipped": 0,
                        "latency_ms": [],
                    },
                )
                entry["rounds_total"] += 1
                if verdict == "SKIP":
                    entry["rounds_skipped"] += 1
                    continue
                if verdict != "OK":
                    entry["rounds_failed"] += 1
                    continue
                values = latency_rows(os.path.join(rounds_dir, f"{tag}.csv"))
                if not values:
                    entry["rounds_zero_recv"] += 1
                    continue
                entry["latency_ms"].append(statistics.mean(values))
                _ = role

    for rmw, entry in per_rmw.items():
        values = entry.pop("latency_ms")
        if values:
            entry["latency_ms_min"] = round(min(values), 4)
            entry["latency_ms_median"] = round(statistics.median(values), 4)
            entry["latency_ms_max"] = round(max(values), 4)
            entry["rounds_usable"] = len(values)
        else:
            entry["rounds_usable"] = 0
        _ = rmw

    summary["per_rmw"] = per_rmw

    measured = per_rmw.get(measured_rmw)
    if not measured:
        summary["headline"] = None
        summary["headline_withheld_reason"] = (
            f"{measured_rmw} produced no round at all in this run"
        )
    elif measured["rounds_failed"] or measured["rounds_zero_recv"]:
        summary["headline"] = None
        summary["headline_withheld_reason"] = (
            f"{measured_rmw}: {measured['rounds_failed']} failed and "
            f"{measured['rounds_zero_recv']} zero-receive round(s) out of "
            f"{measured['rounds_total']}. A number from a partially failing run "
            f"is not comparable with anything."
        )
    elif measured["rounds_usable"] == 0:
        summary["headline"] = None
        summary["headline_withheld_reason"] = (
            f"{measured_rmw} produced no usable latency row "
            f"({measured['rounds_skipped']} of {measured['rounds_total']} round(s) skipped)"
        )
    elif measured["rounds_usable"] < MIN_USABLE_ROUNDS:
        # min == median == max is not a distribution. This is the shape the
        # January batch had: 9 usable rounds out of 57, and one number quoted.
        summary["headline"] = None
        summary["headline_withheld_reason"] = (
            f"{measured_rmw}: only {measured['rounds_usable']} usable round(s) "
            f"out of {measured['rounds_total']} ({measured['rounds_skipped']} skipped); "
            f"{MIN_USABLE_ROUNDS} are needed before min/median/max means anything"
        )
    elif measured["rounds_skipped"] * 2 > measured["rounds_total"]:
        summary["headline"] = None
        summary["headline_withheld_reason"] = (
            f"{measured_rmw}: {measured['rounds_skipped']} of "
            f"{measured['rounds_total']} round(s) were skipped, so the run is not "
            f"a sweep of the topology it claims to measure"
        )
    else:
        summary["headline"] = {
            "rmw": measured_rmw,
            "latency_ms_min": measured["latency_ms_min"],
            "latency_ms_median": measured["latency_ms_median"],
            "latency_ms_max": measured["latency_ms_max"],
            "rounds": measured["rounds_usable"],
            "rounds_total": measured["rounds_total"],
            "rounds_skipped": measured["rounds_skipped"],
            "note": (
                "median of per-round means; includes the rmw layer's own "
                "per-take allocation, so it is NOT comparable with the engine's "
                "intra-process write latency"
            ),
        }

    out = os.path.join(rounds_dir, "summary.json")
    with open(out, "w") as handle:
        json.dump(summary, handle, indent=2, sort_keys=True)
        handle.write("\n")
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
