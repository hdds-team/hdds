#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

"""
rti_interop.py - HDDS subscriber for an RTI Connext publisher

Subscribes on "InteropTest" with the QoS.rti_defaults() preset
(Reliable, Volatile, KeepLast(10)). Run a publisher from your own RTI
Connext installation on the same domain/topic to send data.

Run:
    python3 rti_interop.py

RTI Connext peer: see peer_commands.md

Expected: one "Received ..." line per sample the publisher sends.
"""

import os
import sys
import struct

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'python'))
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
    waitset.attach_reader(reader)

    print("[HDDS] Subscribing on 'InteropTest' (rti_defaults preset)...")
    print("[HDDS] Start your publisher on the same topic.\n")

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
