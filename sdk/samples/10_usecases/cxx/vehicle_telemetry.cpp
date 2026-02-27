// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/*
 * vehicle_telemetry.cpp — Vehicle speed/heading/GPS at 10 Hz
 *
 * Reliable QoS + History(5). Monotonic timestamps for latency tracking.
 *
 * Build:  g++ -std=c++17 -o vehicle_telemetry vehicle_telemetry.cpp -I../../../cxx/include -lhdds
 * Run:    ./vehicle_telemetry pub   # vehicle simulator
 *         ./vehicle_telemetry       # ground station
 *
 * Expected (pub): [VEH] #1 speed=25.0 heading=45.0 lat=48.858400 lon=2.294500
 * Expected (sub): [GND] #1 speed=25.0 heading=45.0 ... latency=0.12ms
 *
 * IDL: struct { u32 seq; u64 ts; f32 speed,heading; f64 lat,lon; f32 alt; };
 */

#include <hdds.hpp>
#include <iostream>
#include <cmath>
#include <cstring>
#include <chrono>
#include <thread>
#include <vector>

using namespace std::chrono_literals;
using Clock = std::chrono::steady_clock;

static std::vector<uint8_t> pack(uint32_t s, uint64_t t, float sp, float hd,
                                  double la, double lo, float al) {
    std::vector<uint8_t> b(48, 0);
    std::memcpy(b.data(),&s,4); std::memcpy(b.data()+8,&t,8);
    std::memcpy(b.data()+16,&sp,4); std::memcpy(b.data()+20,&hd,4);
    std::memcpy(b.data()+24,&la,8); std::memcpy(b.data()+32,&lo,8);
    std::memcpy(b.data()+40,&al,4);
    return b;
}
static uint64_t now_ns() {
    return static_cast<uint64_t>(Clock::now().time_since_epoch().count());
}

static void run_pub(hdds::Participant &p, hdds::QoS &q) {
    auto w = p.create_writer_raw("rt/vehicle/telemetry", q);
    const double bla=48.8584, blo=2.2945, r=0.001;
    std::cout << "[VEH] Publishing at 10 Hz on 'rt/vehicle/telemetry'...\n\n";
    for (uint32_t i=1; i<=200; i++) {
        double t=i*0.1, a=t*0.5;
        double la=bla+r*std::sin(a), lo=blo+r*std::cos(a);
        float sp=25.f+5.f*std::sin(t*0.3f), hd=float(std::fmod(a*180.0/M_PI,360.0));
        w->write_raw(pack(i, now_ns(), sp, hd, la, lo, 35.f));
        if (i%10==1) std::cout << "[VEH] #" << i << " spd=" << sp
            << " hdg=" << hd << " lat=" << la << " lon=" << lo << "\n";
        std::this_thread::sleep_for(100ms);
    }
    std::cout << "\n[VEH] Done (200 samples).\n";
}

static void run_sub(hdds::Participant &p, hdds::QoS &q) {
    auto rd = p.create_reader_raw("rt/vehicle/telemetry", q);
    hdds::WaitSet ws; ws.attach(rd->get_status_condition());
    std::cout << "[GND] Listening on 'rt/vehicle/telemetry'...\n\n";
    int n=0;
    for (int att=0; att<300 && n<200; att++) {
        if (!ws.wait(200ms)) continue;
        while (auto d = rd->take_raw()) {
            uint32_t seq; uint64_t ts; float sp,hd; double la,lo;
            std::memcpy(&seq,d->data(),4); std::memcpy(&ts,d->data()+8,8);
            std::memcpy(&sp,d->data()+16,4); std::memcpy(&hd,d->data()+20,4);
            std::memcpy(&la,d->data()+24,8); std::memcpy(&lo,d->data()+32,8);
            double lat_ms=double(now_ns()-ts)/1e6;
            if (n%10==0) std::cout << "[GND] #" << seq << " spd=" << sp
                << " hdg=" << hd << " lat=" << la << " lon=" << lo
                << " latency=" << lat_ms << "ms\n";
            n++;
        }
    }
    std::cout << "\n[GND] Received " << n << " samples.\n";
}

int main(int argc, char **argv) {
    bool pub = (argc>1 && std::string(argv[1])=="pub");
    try {
        hdds::logging::init(hdds::LogLevel::Warn);
        hdds::Participant p("VehicleTelemetry");
        auto q = hdds::QoS::reliable().history_depth(5);
        if (pub) run_pub(p, q); else run_sub(p, q);
    } catch (const std::exception &e) {
        std::cerr << "Error: " << e.what() << "\n"; return 1;
    }
    return 0;
}
