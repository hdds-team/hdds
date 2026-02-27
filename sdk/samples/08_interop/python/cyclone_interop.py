#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

"""
cyclone_interop.py — HDDS bidirectional pub+sub for CycloneDDS interop

Publishes and subscribes on "InteropTest" simultaneously.  Run a
CycloneDDS peer doing the same to exchange messages bidirectionally.

Run:
    python3 cyclone_interop.py

CycloneDDS peer: see peer_commands.md

Expected:
    [PUB] Sent #1: "HDDS ping #1"
    [SUB] Got 48 bytes: id=1, msg="CycloneDDS pong #1"
    ...
"""

import sys
import struct
import time
import threading

sys.path.insert(0, "../../../python")
import hdds


def serialize_string_msg(msg_id: int, text: str) -> bytes:
    """Serialize StringMsg {id: u32, message: string} to CDR LE."""
    encoded = text.encode("utf-8") + b"\x00"
    slen = len(encoded)
    pad = (4 - (slen % 4)) % 4
    return struct.pack("<II", msg_id, slen) + encoded + b"\x00" * pad


def deserialize_string_msg(data: bytes) -> tuple:
    """Deserialize StringMsg from CDR LE."""
    if len(data) < 8:
        return (0, "")
    msg_id, slen = struct.unpack_from("<II", data, 0)
    if slen == 0 or 8 + slen > len(data):
        return (msg_id, "")
    text = data[8 : 8 + slen - 1].decode("utf-8", errors="replace")
    return (msg_id, text)


def subscriber_loop(reader: hdds.DataReader) -> None:
    """Read incoming messages for ~30 seconds."""
    waitset = hdds.WaitSet()
    cond = reader.get_status_condition()
    waitset.attach(cond)

    for _ in range(60):
        if waitset.wait(timeout=0.5):
            while True:
                data = reader.take()
                if data is None:
                    break
                msg_id, text = deserialize_string_msg(data)
                print(f'[SUB] Got {len(data)} bytes: id={msg_id}, msg="{text}"')


def main() -> None:
    hdds.logging.init(hdds.LogLevel.INFO)
    participant = hdds.Participant("Cyclone_Interop")
    qos = hdds.QoS.reliable()
    writer = participant.create_writer("InteropTest", qos=qos)
    reader = participant.create_reader("InteropTest", qos=qos)

    print("[HDDS] Bidirectional interop on 'InteropTest' (domain 0).")
    print("[HDDS] Start a CycloneDDS peer on the same topic.\n")

    sub = threading.Thread(target=subscriber_loop, args=(reader,), daemon=True)
    sub.start()

    for i in range(1, 21):
        text = f"HDDS ping #{i}"
        data = serialize_string_msg(i, text)
        writer.write(data)
        print(f'[PUB] Sent #{i}: "{text}"')
        time.sleep(0.5)

    sub.join(timeout=5.0)
    print("\nDone.")


if __name__ == "__main__":
    main()
