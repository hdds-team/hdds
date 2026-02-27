#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

"""
fastdds_interop.py — HDDS publisher interop with FastDDS subscriber

Publishes raw CDR messages on "InteropTest" using reliable QoS.
Any RTPS-compliant subscriber on the same domain/topic will receive them.

Run:
    python3 fastdds_interop.py

FastDDS peer: see peer_commands.md

Expected:
    Published 1/20: "Hello from HDDS Python #1"
    ...
"""

import sys
import struct
import time

sys.path.insert(0, "../../../python")
import hdds


def serialize_string_msg(msg_id: int, text: str) -> bytes:
    """Serialize StringMsg {id: u32, message: string} to CDR LE."""
    encoded = text.encode("utf-8") + b"\x00"  # null-terminated
    slen = len(encoded)
    pad = (4 - (slen % 4)) % 4
    return struct.pack("<II", msg_id, slen) + encoded + b"\x00" * pad


def main() -> None:
    hdds.logging.init(hdds.LogLevel.INFO)
    participant = hdds.Participant("FastDDS_Interop")
    qos = hdds.QoS.reliable()
    writer = participant.create_writer("InteropTest", qos=qos)

    print("[HDDS] Publishing 20 messages on 'InteropTopic'...")
    print("[HDDS] Start a FastDDS subscriber on the same topic.\n")

    for i in range(1, 21):
        text = f"Hello from HDDS Python #{i}"
        data = serialize_string_msg(i, text)
        writer.write(data)
        print(f'Published {i}/20: "{text}"')
        time.sleep(0.5)

    print("\nDone.")


if __name__ == "__main__":
    main()
