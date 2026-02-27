// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/*
 * command_control.c — Command/response with deadline QoS
 *
 * Commander sends on "rt/cmd/request", responder acks on "rt/cmd/response".
 * Reliable + Transient Local + 2s deadline for timeout detection.
 *
 * Build:  gcc -o command_control command_control.c -I../../../c/include -lhdds
 * Run:    ./command_control cmd   # commander
 *         ./command_control       # responder
 *
 * Expected (cmd): [CMD] Sent MOVE_TO seq=1  / [CMD] ACK seq=1 status=OK
 * Expected (rsp): [RSP] Got MOVE_TO seq=1 — sending ACK
 *
 * Wire: Command={u32 seq, u8 type, 3pad, f32 p1, f32 p2} 16B
 *       Response={u32 seq, u8 status, 3pad, u32 error}    12B
 */

#include <hdds.h>
#include <stdio.h>
#include <string.h>
#ifndef _WIN32
#include <unistd.h>
#define sleep_ms(ms) usleep((ms)*1000)
#else
#include <windows.h>
#define sleep_ms(ms) Sleep(ms)
#endif

static const char *CN[]={"NOP","MOVE_TO","STOP","SET_SPEED","RETURN_HOME"};
static const char *SN[]={"OK","BUSY","ERROR","REJECTED"};

static void run_cmd(HddsParticipant *p, HddsQoS *q) {
    HddsDataWriter *cw=hdds_writer_create_with_qos(p,"rt/cmd/request",q);
    HddsDataReader *rr=hdds_reader_create_with_qos(p,"rt/cmd/response",q);
    HddsWaitSet *ws=hdds_waitset_create();
    hdds_waitset_attach_status_condition(ws,hdds_reader_get_status_condition(rr));
    struct{uint8_t t;float p1,p2;} cmds[]={{1,10,20},{3,5,0},{1,30,40},{2,0,0},{4,0,0}};
    printf("[CMD] Sending 5 commands...\n\n");
    for (int i=0;i<5;i++) {
        uint32_t seq=(uint32_t)(i+1);
        uint8_t b[16]={0}; memcpy(b,&seq,4); b[4]=cmds[i].t;
        memcpy(b+8,&cmds[i].p1,4); memcpy(b+12,&cmds[i].p2,4);
        hdds_writer_write(cw,b,16);
        printf("[CMD] Sent %s seq=%u\n",CN[cmds[i].t],seq);
        int acked=0;
        for (int w=0;w<4&&!acked;w++) {
            const void *tr[1]; size_t tc=0;
            if (hdds_waitset_wait(ws,500000000LL,tr,1,&tc)==HDDS_OK&&tc>0) {
                uint8_t rb[12]; size_t rl=0;
                while (hdds_reader_take(rr,rb,12,&rl)==HDDS_OK) {
                    uint32_t rs; memcpy(&rs,rb,4);
                    if (rs==seq){printf("[CMD] ACK seq=%u status=%s\n",rs,SN[rb[4]]);acked=1;}
                }
            }
        }
        if (!acked) printf("[CMD] DEADLINE MISSED — no ACK for seq=%u\n",seq);
        sleep_ms(1000);
    }
    printf("\n[CMD] Complete.\n");
    hdds_waitset_destroy(ws); hdds_writer_destroy(cw); hdds_reader_destroy(rr);
}

static void run_rsp(HddsParticipant *p, HddsQoS *q) {
    HddsDataReader *cr=hdds_reader_create_with_qos(p,"rt/cmd/request",q);
    HddsDataWriter *rw=hdds_writer_create_with_qos(p,"rt/cmd/response",q);
    HddsWaitSet *ws=hdds_waitset_create();
    hdds_waitset_attach_status_condition(ws,hdds_reader_get_status_condition(cr));
    printf("[RSP] Listening for commands...\n\n");
    for (int a=0;a<120;a++) {
        const void *tr[1]; size_t tc=0;
        if (hdds_waitset_wait(ws,500000000LL,tr,1,&tc)==HDDS_OK&&tc>0) {
            uint8_t b[16]; size_t len=0;
            while (hdds_reader_take(cr,b,16,&len)==HDDS_OK) {
                uint32_t seq; memcpy(&seq,b,4);
                printf("[RSP] Got %s seq=%u — ACK\n",CN[b[4]],seq);
                uint8_t r[12]={0}; memcpy(r,&seq,4);
                hdds_writer_write(rw,r,12);
            }
        }
    }
    hdds_waitset_destroy(ws); hdds_reader_destroy(cr); hdds_writer_destroy(rw);
}

int main(int argc, char **argv) {
    int cmd=(argc>1&&(strcmp(argv[1],"cmd")==0||strcmp(argv[1],"-p")==0));
    hdds_logging_init(3);
    HddsParticipant *p=hdds_participant_create("CommandControl");
    if (!p) {fprintf(stderr,"Participant failed\n"); return 1;}
    HddsQoS *q=hdds_qos_reliable();
    hdds_qos_set_transient_local(q); hdds_qos_set_deadline_ns(q,2000000000ULL);
    if (cmd) run_cmd(p,q); else run_rsp(p,q);
    hdds_qos_destroy(q); hdds_participant_destroy(p);
    return 0;
}
