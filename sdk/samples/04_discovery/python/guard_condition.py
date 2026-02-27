#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

"""
HDDS Sample: Guard Condition (Python)

Demonstrates manual event signaling with GuardConditions.
A background thread triggers a guard condition after a delay,
waking the main thread's WaitSet.

Usage:
    python guard_condition.py

Expected output:
    [OK] GuardCondition created
    [OK] Attached to WaitSet
    Waiting for trigger (background thread will fire in 2s)...
    [TRIGGER] Guard condition triggered from background thread
    [WAKE] GuardCondition fired!

Key concepts:
- GuardCondition for application-level signaling
- Attach/detach conditions on a WaitSet
- Cross-thread triggering with threading module
"""

import os
import sys
import threading

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'python'))

import hdds

TRIGGER_DELAY_SEC: int = 2


def trigger_func(guard: hdds.GuardCondition) -> None:
    """Background thread: triggers the guard condition after a delay."""
    import time
    print(f"[THREAD] Sleeping {TRIGGER_DELAY_SEC} seconds before triggering...")
    time.sleep(TRIGGER_DELAY_SEC)
    print("[TRIGGER] Guard condition triggered from background thread")
    guard.set_trigger(True)


def main() -> int:
    print("=" * 60)
    print("Guard Condition Demo")
    print("Manual event signaling via GuardCondition")
    print("=" * 60)
    print()

    hdds.logging.init(hdds.LogLevel.INFO)

    # Create participant
    participant = hdds.Participant("GuardCondDemo")
    print("[OK] Participant created")

    # Create guard condition
    guard = hdds.GuardCondition()
    print("[OK] GuardCondition created (trigger_value=False)")

    # Create WaitSet and attach guard condition
    waitset = hdds.WaitSet()
    waitset.attach_guard(guard)
    print("[OK] GuardCondition attached to WaitSet\n")

    # Spawn background trigger thread
    trigger_thread = threading.Thread(target=trigger_func, args=(guard,))
    trigger_thread.start()

    # Wait on WaitSet - blocks until guard is triggered
    print(f"Waiting for trigger (background thread will fire in {TRIGGER_DELAY_SEC}s)...\n")

    if waitset.wait(timeout=5.0):
        print("[WAKE] GuardCondition fired!")
    else:
        print("[TIMEOUT] Guard condition was not triggered in time")

    # Reset guard
    guard.set_trigger(False)
    print("[OK] GuardCondition reset to False")

    # Second trigger cycle (immediate)
    print("\n--- Second trigger (immediate) ---\n")

    guard.set_trigger(True)
    print("[TRIGGER] Guard condition set to True (immediate)")

    if waitset.wait(timeout=1.0):
        print("[WAKE] Immediate trigger detected!")

    # Wait for thread
    trigger_thread.join()

    # Cleanup
    print("\n--- Cleanup ---")
    waitset.detach(guard)
    print("[OK] GuardCondition detached")
    participant.close()

    print("\n=== Guard Condition Demo Complete ===")
    return 0


if __name__ == "__main__":
    sys.exit(main())
