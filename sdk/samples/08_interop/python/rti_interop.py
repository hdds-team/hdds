#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

"""
rti_interop.py — HDDS subscriber with RTI Connext-compatible QoS

Subscribes on "InteropTest" using QoS.rti_defaults() for wire
compatibility with RTI Connext DDS.

Run:
    python3 rti_interop.py

RTI Connext peer: see peer_commands.md

Expected:
    Received 52 bytes: id=1, msg="Hello from RTI #1"
    ...
"""

import sys
import struct

sys.path.insert(0, "../../../python")
import hdds


def deserialize_string_msg(data: bytes) -> tuple:
    """Deserialize StringMsg {id: u32, message: string} from CDR LE."""
    if len(data) < 8:
        return (0, "")
    msg_id, slen = struct.unpack_from("<II", data, 0)
    if slen == 0 or 8 + slen > len(data):
        return (msg_id, "")
    text = data[8 : 8 + slen - 1].decode("utf-8", errors="replace")
    return (msg_id, text)


def main() -> None:
    hdds.logging.init(hdds.LogLevel.INFO)
    participant = hdds.Participant("RTI_Interop")
    qos = hdds.QoS.rti_defaults()
    reader = participant.create_reader("InteropTest", qos=qos)

    waitset = hdds.WaitSet()
    cond = reader.get_status_condition()
    waitset.attach(cond)

    print("[HDDS] Subscribing on 'InteropTest' (RTI-compatible QoS)...")
    print("[HDDS] Start an RTI Connext publisher on the same topic.\n")

    received = 0
    for _ in range(60):
        if waitset.wait(timeout=1.0):
            while True:
                data = reader.take()
                if data is None:
                    break
                msg_id, text = deserialize_string_msg(data)
                print(f'Received {len(data)} bytes: id={msg_id}, msg="{text}"')
                received += 1

    print(f"\nReceived {received} total messages.")


if __name__ == "__main__":
    main()
