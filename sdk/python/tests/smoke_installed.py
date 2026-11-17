#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

"""Smoke test for an INSTALLED hdds wheel (stdlib only, no pytest).

Run from a directory outside the repository (the gate uses cwd=/) inside
the venv that received the wheel, with HDDS_LIB_PATH pointing at the
directory holding libhdds_c.so:

    HDDS_LIB_PATH=/path/to/target/release python smoke_installed.py

Checks, in order:
  1. ``hdds`` imports from site-packages, not from a source tree.
  2. ``importlib.metadata.version("hdds") == hdds.__version__``.
  3. ``hdds.library_path()`` is the file under HDDS_LIB_PATH and
     ``hdds.version()`` is a non-empty string.
  4. One intra-process write/take round trip (no UDP, no ports).

``--expect-import-error`` inverts the run: the import must fail with
ImportError (used with HDDS_LIB_PATH pointing at an empty directory to
prove the strict override fails closed without probing the system).

Exit code 0 on success, 1 on any failure; every check prints one line.
"""

import importlib.metadata
import os
import sys
import time


def fail(msg: str) -> None:
    print("SMOKE FAIL: " + msg)
    sys.exit(1)


def expect_import_error() -> None:
    try:
        import hdds
        hdds.library_path()
    except ImportError as e:
        text = str(e)
        if "HDDS_LIB_PATH" not in text or "cargo build --release -p hdds-c" not in text:
            fail("ImportError raised but not actionable: " + text)
        print("SMOKE OK: import fails closed: " + text.splitlines()[0])
        return
    fail("import succeeded although the library must be unreachable")


def main() -> None:
    if "--expect-import-error" in sys.argv:
        expect_import_error()
        return

    lib_dir = os.environ.get("HDDS_LIB_PATH")
    if not lib_dir:
        fail("HDDS_LIB_PATH must be set for the positive smoke")

    import hdds

    location = os.path.abspath(hdds.__file__)
    if "site-packages" not in location.split(os.sep):
        fail("hdds imported from " + location + ", not from site-packages")
    print("SMOKE OK: hdds imported from " + location)

    meta = importlib.metadata.version("hdds")
    if meta != hdds.__version__:
        fail(f"metadata version {meta} != hdds.__version__ {hdds.__version__}")
    print("SMOKE OK: package version " + meta)

    resolved = hdds.library_path()
    if os.path.dirname(os.path.abspath(resolved)) != os.path.abspath(lib_dir):
        fail(f"library_path {resolved} is not under HDDS_LIB_PATH {lib_dir}")
    native = hdds.version()
    if not native:
        fail("hdds.version() returned an empty string")
    print(f"SMOKE OK: native library {resolved} reports version {native}")

    payload = b"hello from an installed wheel"
    with hdds.Participant("smoke_installed", transport=hdds.TransportMode.INTRA_PROCESS) as p:
        writer = p.create_writer("smoke/installed")
        reader = p.create_reader("smoke/installed")
        time.sleep(0.05)
        writer.write(payload)
        got = None
        for _ in range(100):
            got = reader.take()
            if got is not None:
                break
            time.sleep(0.01)
    if got != payload:
        fail(f"intra-process round trip returned {got!r}")
    print("SMOKE OK: intra-process round trip " + repr(payload))


if __name__ == "__main__":
    main()
