#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

"""
sensor_fusion.py — Multi-sensor fusion (radar + lidar + camera)

Reads three topics via one WaitSet. Best-effort QoS for high-rate streams.

Run:    python3 sensor_fusion.py pub   # start 3 sensor simulators
        python3 sensor_fusion.py       # fusion node (subscriber)

Expected (sub):
    [RADAR]  #1 range=45.2m az=12 vel=3.1m/s
    [LIDAR]  #1 points=128
    [CAMERA] #1 frame=1

Wire: all 16B — Radar:{u32,f32,f32,f32} Lidar:{u32,u32,f32,f32} Camera:{u32,u32,u16,u16,u8,3pad}
"""

import math, struct, sys, time, threading
sys.path.insert(0, "../../../python")
import hdds

def sim_radar(w):
    for i in range(1, 101):
        w.write(struct.pack("<Ifff", i, 30.0+20.0*math.sin(i*.1), float(i%360), 5.0*math.cos(i*.05)))
        time.sleep(0.05)

def sim_lidar(w):
    for i in range(1, 101):
        w.write(struct.pack("<IIff", i, 64+(i%128), 0.5, 50.0+float(i%20)))
        time.sleep(0.1)

def sim_camera(w):
    for i in range(1, 101):
        w.write(struct.pack("<IIHHB3x", i, i, 1920, 1080, 30))
        time.sleep(0.033)

def run_pub(p, q):
    wr = p.create_writer("rt/sensor/radar", qos=q)
    wl = p.create_writer("rt/sensor/lidar", qos=q)
    wc = p.create_writer("rt/sensor/camera", qos=q)
    print("[SIM] radar@20Hz lidar@10Hz camera@30Hz\n")
    ts = [threading.Thread(target=f, args=(w,))
          for f, w in [(sim_radar, wr), (sim_lidar, wl), (sim_camera, wc)]]
    for t in ts: t.start()
    for t in ts: t.join()
    print("[SIM] Done.")

def run_fusion(p, q):
    rr = p.create_reader("rt/sensor/radar", qos=q)
    rl = p.create_reader("rt/sensor/lidar", qos=q)
    rc = p.create_reader("rt/sensor/camera", qos=q)
    ws = hdds.WaitSet()
    ws.attach(rr.get_status_condition())
    ws.attach(rl.get_status_condition())
    ws.attach(rc.get_status_condition())
    print("[FUSION] Waiting for sensor data...\n")
    rn, ln, cn = 0, 0, 0
    for _ in range(300):
        if not ws.wait(timeout=0.1): continue
        while True:
            d = rr.take()
            if d is None: break
            seq, r, az, v = struct.unpack_from("<Ifff", d)
            if rn % 10 == 0:
                print(f"[RADAR]  #{seq:<3} range={r:.1f}m az={az:.0f} vel={v:.1f}m/s")
            rn += 1
        while True:
            d = rl.take()
            if d is None: break
            seq, pts = struct.unpack_from("<II", d)
            if ln % 5 == 0: print(f"[LIDAR]  #{seq:<3} points={pts}")
            ln += 1
        while True:
            d = rc.take()
            if d is None: break
            seq, fr = struct.unpack_from("<II", d)
            if cn % 15 == 0: print(f"[CAMERA] #{seq:<3} frame={fr}")
            cn += 1
    print(f"\n[FUSION] radar={rn} lidar={ln} camera={cn}")

def main():
    hdds.logging.init(hdds.LogLevel.INFO)
    p = hdds.Participant("SensorFusion")
    q = hdds.QoS.best_effort()
    pub = len(sys.argv) > 1 and sys.argv[1] in ("pub", "-p")
    if pub: run_pub(p, q)
    else: run_fusion(p, q)

if __name__ == "__main__":
    main()
