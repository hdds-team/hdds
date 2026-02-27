#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

"""
command_control.py — Command/response with deadline QoS

Commander sends on "rt/cmd/request", responder acks on "rt/cmd/response".
Reliable + Transient Local + 2s deadline for timeout detection.

Run:    python3 command_control.py cmd   # commander
        python3 command_control.py       # responder

Expected (cmd): [CMD] Sent MOVE_TO seq=1 / [CMD] ACK seq=1 status=OK
Expected (rsp): [RSP] Got MOVE_TO seq=1 — sending ACK

Wire: Cmd={u32 seq, u8 type, 3pad, f32 p1, f32 p2} 16B
      Rsp={u32 seq, u8 status, 3pad, u32 error}    12B
"""

import struct, sys, time
sys.path.insert(0, "../../../python")
import hdds

CN = {0: "NOP", 1: "MOVE_TO", 2: "STOP", 3: "SET_SPEED", 4: "RETURN_HOME"}
SN = {0: "OK", 1: "BUSY", 2: "ERROR", 3: "REJECTED"}

def pk_cmd(seq, t, p1, p2):
    b = bytearray(16); struct.pack_into("<I", b, 0, seq); b[4] = t
    struct.pack_into("<f", b, 8, p1); struct.pack_into("<f", b, 12, p2)
    return bytes(b)

def pk_rsp(seq, st, err):
    b = bytearray(12); struct.pack_into("<I", b, 0, seq); b[4] = st
    struct.pack_into("<I", b, 8, err); return bytes(b)

def run_cmd(p, q):
    cw = p.create_writer("rt/cmd/request", qos=q)
    rr = p.create_reader("rt/cmd/response", qos=q)
    ws = hdds.WaitSet(); ws.attach(rr.get_status_condition())
    cmds = [(1,10,20),(3,5,0),(1,30,40),(2,0,0),(4,0,0)]
    print("[CMD] Sending 5 commands...\n")
    for i, (ct, p1, p2) in enumerate(cmds):
        seq = i + 1
        cw.write(pk_cmd(seq, ct, p1, p2))
        print(f"[CMD] Sent {CN.get(ct,'?')} seq={seq}")
        acked = False
        for _ in range(4):
            if acked: break
            if ws.wait(timeout=0.5):
                while True:
                    d = rr.take()
                    if d is None: break
                    rs = struct.unpack_from("<I", d, 0)[0]
                    if rs == seq:
                        print(f"[CMD] ACK seq={rs} status={SN.get(d[4],'?')}")
                        acked = True
        if not acked: print(f"[CMD] DEADLINE MISSED — no ACK for seq={seq}")
        time.sleep(1.0)
    print("\n[CMD] Complete.")

def run_rsp(p, q):
    cr = p.create_reader("rt/cmd/request", qos=q)
    rw = p.create_writer("rt/cmd/response", qos=q)
    ws = hdds.WaitSet(); ws.attach(cr.get_status_condition())
    print("[RSP] Listening for commands...\n")
    for _ in range(120):
        if ws.wait(timeout=0.5):
            while True:
                d = cr.take()
                if d is None: break
                seq = struct.unpack_from("<I", d, 0)[0]
                print(f"[RSP] Got {CN.get(d[4],'?')} seq={seq} — ACK")
                rw.write(pk_rsp(seq, 0, 0))

def main():
    hdds.logging.init(hdds.LogLevel.INFO)
    p = hdds.Participant("CommandControl")
    q = hdds.QoS.reliable(); q.transient_local(); q.deadline(2.0)
    cmd = len(sys.argv) > 1 and sys.argv[1] in ("cmd", "-p")
    if cmd: run_cmd(p, q)
    else: run_rsp(p, q)

if __name__ == "__main__":
    main()
