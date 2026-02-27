// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/*
 * command_control.cpp — Command/response with deadline QoS
 *
 * Commander sends on "rt/cmd/request", responder acks on "rt/cmd/response".
 * Reliable + Transient Local + 2s deadline for timeout detection.
 *
 * Build:  g++ -std=c++17 -o command_control command_control.cpp -I../../../cxx/include -lhdds
 * Run:    ./command_control cmd   # commander
 *         ./command_control       # responder
 *
 * Expected (cmd): [CMD] Sent MOVE_TO seq=1 / [CMD] ACK seq=1 status=OK
 * Expected (rsp): [RSP] Got MOVE_TO seq=1 — sending ACK
 *
 * Wire: Cmd={u32 seq, u8 type, 3pad, f32 p1, f32 p2} 16B
 *       Rsp={u32 seq, u8 status, 3pad, u32 error}    12B
 */

#include <hdds.hpp>
#include <iostream>
#include <cstring>
#include <chrono>
#include <thread>
#include <vector>

using namespace std::chrono_literals;

static const char *CN[]={"NOP","MOVE_TO","STOP","SET_SPEED","RETURN_HOME"};
static const char *SN[]={"OK","BUSY","ERROR","REJECTED"};

static std::vector<uint8_t> pk_cmd(uint32_t s,uint8_t t,float p1,float p2) {
    std::vector<uint8_t> b(16,0); std::memcpy(b.data(),&s,4); b[4]=t;
    std::memcpy(b.data()+8,&p1,4); std::memcpy(b.data()+12,&p2,4); return b;
}
static std::vector<uint8_t> pk_rsp(uint32_t s,uint8_t st,uint32_t e) {
    std::vector<uint8_t> b(12,0); std::memcpy(b.data(),&s,4); b[4]=st;
    std::memcpy(b.data()+8,&e,4); return b;
}

static void run_cmd(hdds::Participant &p, hdds::QoS &q) {
    auto cw=p.create_writer_raw("rt/cmd/request",q);
    auto rr=p.create_reader_raw("rt/cmd/response",q);
    hdds::WaitSet ws; ws.attach(rr->get_status_condition());
    struct{uint8_t t;float p1,p2;} cmds[]={{1,10,20},{3,5,0},{1,30,40},{2,0,0},{4,0,0}};
    std::cout << "[CMD] Sending 5 commands...\n\n";
    for (int i=0;i<5;i++) {
        uint32_t seq=uint32_t(i+1);
        cw->write_raw(pk_cmd(seq,cmds[i].t,cmds[i].p1,cmds[i].p2));
        std::cout << "[CMD] Sent " << CN[cmds[i].t] << " seq=" << seq << "\n";
        bool acked=false;
        for (int w=0;w<4&&!acked;w++) {
            if (ws.wait(500ms)) {
                while (auto d=rr->take_raw()) {
                    uint32_t rs; std::memcpy(&rs,d->data(),4);
                    if (rs==seq){std::cout<<"[CMD] ACK seq="<<rs<<" status="<<SN[(*d)[4]]<<"\n";acked=true;}
                }
            }
        }
        if (!acked) std::cout << "[CMD] DEADLINE MISSED — no ACK for seq=" << seq << "\n";
        std::this_thread::sleep_for(1s);
    }
    std::cout << "\n[CMD] Complete.\n";
}

static void run_rsp(hdds::Participant &p, hdds::QoS &q) {
    auto cr=p.create_reader_raw("rt/cmd/request",q);
    auto rw=p.create_writer_raw("rt/cmd/response",q);
    hdds::WaitSet ws; ws.attach(cr->get_status_condition());
    std::cout << "[RSP] Listening for commands...\n\n";
    for (int a=0;a<120;a++) {
        if (ws.wait(500ms)) {
            while (auto d=cr->take_raw()) {
                uint32_t seq; std::memcpy(&seq,d->data(),4);
                std::cout<<"[RSP] Got "<<CN[(*d)[4]]<<" seq="<<seq<<" — ACK\n";
                rw->write_raw(pk_rsp(seq,0,0));
            }
        }
    }
}

int main(int argc, char **argv) {
    bool cmd=(argc>1 && std::string(argv[1])=="cmd");
    try {
        hdds::logging::init(hdds::LogLevel::Warn);
        hdds::Participant p("CommandControl");
        auto q=hdds::QoS::reliable().transient_local().deadline(2s);
        if (cmd) run_cmd(p,q); else run_rsp(p,q);
    } catch (const std::exception &e) {
        std::cerr << "Error: " << e.what() << "\n"; return 1;
    }
    return 0;
}
