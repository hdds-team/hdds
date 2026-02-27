// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/*
 * sensor_fusion.cpp — Multi-sensor fusion (radar + lidar + camera)
 *
 * Reads three topics via one WaitSet. Best-effort QoS for high-rate streams.
 *
 * Build:  g++ -std=c++17 -o sensor_fusion sensor_fusion.cpp -I../../../cxx/include -lhdds -lpthread
 * Run:    ./sensor_fusion pub   # start 3 sensor simulators
 *         ./sensor_fusion       # fusion node (subscriber)
 *
 * Expected (sub):
 *   [RADAR]  #1 range=45.2m az=12 vel=3.1m/s
 *   [LIDAR]  #1 points=128
 *   [CAMERA] #1 frame=1
 *
 * Wire: all 16B — see C version for layout.
 */

#include <hdds.hpp>
#include <iostream>
#include <cmath>
#include <cstring>
#include <chrono>
#include <thread>
#include <vector>

using namespace std::chrono_literals;

static std::vector<uint8_t> pk(uint32_t a,uint32_t b,float c,float d) {
    std::vector<uint8_t> v(16,0);
    std::memcpy(v.data(),&a,4);std::memcpy(v.data()+4,&b,4);
    std::memcpy(v.data()+8,&c,4);std::memcpy(v.data()+12,&d,4);return v;
}
static std::vector<uint8_t> pk_cam(uint32_t s,uint32_t f,uint16_t w,uint16_t h,uint8_t fps) {
    std::vector<uint8_t> v(16,0);
    std::memcpy(v.data(),&s,4);std::memcpy(v.data()+4,&f,4);
    std::memcpy(v.data()+8,&w,2);std::memcpy(v.data()+10,&h,2);v[12]=fps;return v;
}

static void sim_radar(hdds::DataWriter *w) {
    for (uint32_t i=1;i<=100;i++) {
        float r=30.f+20.f*std::sin(i*.1f); uint32_t ri=*(uint32_t*)&r;
        w->write_raw(pk(i,ri,float(i%360),5.f*std::cos(i*.05f)));
        std::this_thread::sleep_for(50ms);
    }
}
static void sim_lidar(hdds::DataWriter *w) {
    for (uint32_t i=1;i<=100;i++) {
        w->write_raw(pk(i,64+(i%128),.5f,50.f+float(i%20)));
        std::this_thread::sleep_for(100ms);
    }
}
static void sim_camera(hdds::DataWriter *w) {
    for (uint32_t i=1;i<=100;i++) {
        w->write_raw(pk_cam(i,i,1920,1080,30));
        std::this_thread::sleep_for(33ms);
    }
}

static void run_pub(hdds::Participant &p, hdds::QoS &q) {
    auto wr=p.create_writer_raw("rt/sensor/radar",q);
    auto wl=p.create_writer_raw("rt/sensor/lidar",q);
    auto wc=p.create_writer_raw("rt/sensor/camera",q);
    std::cout << "[SIM] radar@20Hz lidar@10Hz camera@30Hz\n\n";
    std::thread t1(sim_radar,wr.get()),t2(sim_lidar,wl.get()),t3(sim_camera,wc.get());
    t1.join();t2.join();t3.join();
    std::cout << "[SIM] Done.\n";
}

static void run_fusion(hdds::Participant &p, hdds::QoS &q) {
    auto rr=p.create_reader_raw("rt/sensor/radar",q);
    auto rl=p.create_reader_raw("rt/sensor/lidar",q);
    auto rc=p.create_reader_raw("rt/sensor/camera",q);
    hdds::WaitSet ws;
    ws.attach(rr->get_status_condition());
    ws.attach(rl->get_status_condition());
    ws.attach(rc->get_status_condition());
    std::cout << "[FUSION] Waiting for sensor data...\n\n";
    int rn=0,ln=0,cn=0;
    for (int a=0;a<300;a++) {
        if (!ws.wait(100ms)) continue;
        while (auto d=rr->take_raw()) {
            uint32_t seq; float r,az,v;
            std::memcpy(&seq,d->data(),4);std::memcpy(&r,d->data()+4,4);
            std::memcpy(&az,d->data()+8,4);std::memcpy(&v,d->data()+12,4);
            if (rn%10==0) std::cout<<"[RADAR]  #"<<seq<<" range="<<r<<"m az="<<az<<" vel="<<v<<"m/s\n";
            rn++;
        }
        while (auto d=rl->take_raw()) {
            uint32_t seq,pts; std::memcpy(&seq,d->data(),4);std::memcpy(&pts,d->data()+4,4);
            if (ln%5==0) std::cout<<"[LIDAR]  #"<<seq<<" points="<<pts<<"\n"; ln++;
        }
        while (auto d=rc->take_raw()) {
            uint32_t seq,fr; std::memcpy(&seq,d->data(),4);std::memcpy(&fr,d->data()+4,4);
            if (cn%15==0) std::cout<<"[CAMERA] #"<<seq<<" frame="<<fr<<"\n"; cn++;
        }
    }
    std::cout<<"\n[FUSION] radar="<<rn<<" lidar="<<ln<<" camera="<<cn<<"\n";
}

int main(int argc, char **argv) {
    bool pub=(argc>1 && std::string(argv[1])=="pub");
    try {
        hdds::logging::init(hdds::LogLevel::Warn);
        hdds::Participant p("SensorFusion");
        auto q=hdds::QoS::best_effort();
        if (pub) run_pub(p,q); else run_fusion(p,q);
    } catch (const std::exception &e) {
        std::cerr<<"Error: "<<e.what()<<"\n"; return 1;
    }
    return 0;
}
