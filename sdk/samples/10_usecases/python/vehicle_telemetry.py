#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

"""
vehicle_telemetry.py — Vehicle speed/heading/GPS at 10 Hz

Reliable QoS + History(5). Monotonic timestamps for latency tracking.

Run:    python3 vehicle_telemetry.py pub   # vehicle simulator
        python3 vehicle_telemetry.py       # ground station

Expected (pub): [VEH] #1 spd=25.0 hdg=45.0 lat=48.858400 lon=2.294500
Expected (sub): [GND] #1 spd=25.0 hdg=45.0 ... latency=0.12ms

Wire: {u32 seq, 4pad, u64 ts, f32 speed, f32 heading, f64 lat, f64 lon, f32 alt} 48B
"""

import math, struct, sys, time
sys.path.insert(0, "../../../python")
import hdds

def pk(seq, ts, sp, hd, la, lo, al):
    b = bytearray(48)
    struct.pack_into("<I", b, 0, seq); struct.pack_into("<Q", b, 8, ts)
    struct.pack_into("<f", b, 16, sp); struct.pack_into("<f", b, 20, hd)
    struct.pack_into("<d", b, 24, la); struct.pack_into("<d", b, 32, lo)
    struct.pack_into("<f", b, 40, al); return bytes(b)

def now_ns(): return int(time.monotonic_ns())

def run_pub(p, q):
    w = p.create_writer("rt/vehicle/telemetry", qos=q)
    bla, blo, r = 48.8584, 2.2945, 0.001
    print("[VEH] Publishing at 10 Hz on 'rt/vehicle/telemetry'...\n")
    for i in range(1, 201):
        t = i * 0.1; a = t * 0.5
        la = bla + r * math.sin(a); lo = blo + r * math.cos(a)
        sp = 25.0 + 5.0 * math.sin(t * 0.3)
        hd = math.degrees(a) % 360.0
        w.write(pk(i, now_ns(), sp, hd, la, lo, 35.0))
        if i % 10 == 1:
            print(f"[VEH] #{i:<3} spd={sp:.1f} hdg={hd:.1f} lat={la:.6f} lon={lo:.6f}")
        time.sleep(0.1)
    print("\n[VEH] Done (200 samples).")

def run_sub(p, q):
    rd = p.create_reader("rt/vehicle/telemetry", qos=q)
    ws = hdds.WaitSet(); ws.attach(rd.get_status_condition())
    print("[GND] Listening on 'rt/vehicle/telemetry'...\n")
    n = 0
    for _ in range(300):
        if n >= 200: break
        if not ws.wait(timeout=0.2): continue
        while True:
            d = rd.take()
            if d is None: break
            seq = struct.unpack_from("<I", d, 0)[0]
            ts = struct.unpack_from("<Q", d, 8)[0]
            sp = struct.unpack_from("<f", d, 16)[0]
            hd = struct.unpack_from("<f", d, 20)[0]
            la = struct.unpack_from("<d", d, 24)[0]
            lo = struct.unpack_from("<d", d, 32)[0]
            lat_ms = (now_ns() - ts) / 1e6
            if n % 10 == 0:
                print(f"[GND] #{seq:<3} spd={sp:.1f} hdg={hd:.1f}"
                      f" lat={la:.6f} lon={lo:.6f} latency={lat_ms:.2f}ms")
            n += 1
    print(f"\n[GND] Received {n} samples.")

def main():
    hdds.logging.init(hdds.LogLevel.INFO)
    p = hdds.Participant("VehicleTelemetry")
    q = hdds.QoS.reliable(); q.history_depth(5)
    pub = len(sys.argv) > 1 and sys.argv[1] in ("pub", "-p")
    if pub: run_pub(p, q)
    else: run_sub(p, q)

if __name__ == "__main__":
    main()
