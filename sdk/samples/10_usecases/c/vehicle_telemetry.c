// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/*
 * vehicle_telemetry.c — Vehicle speed/heading/GPS at 10 Hz
 *
 * Reliable QoS + History(5). Embeds monotonic timestamp for latency tracking.
 *
 * Build:  gcc -o vehicle_telemetry vehicle_telemetry.c -I../../../c/include -lhdds -lm
 * Run:    ./vehicle_telemetry pub   # vehicle simulator
 *         ./vehicle_telemetry       # ground station
 *
 * Expected (pub): [VEH] #1 spd=25.0 hdg=45.0 lat=48.858400 lon=2.294500
 * Expected (sub): [GND] #1 spd=25.0 hdg=45.0 ... latency=0.12ms
 *
 * IDL: struct VehicleTelemetry {
 *        u32 seq; u64 ts; f32 speed,heading; f64 lat,lon; f32 alt; };  (48B)
 */

#include <hdds.h>
#include <math.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#ifndef _WIN32
#include <unistd.h>
#define sleep_ms(ms) usleep((ms)*1000)
#else
#include <windows.h>
#define sleep_ms(ms) Sleep(ms)
#endif

#define SZ 48
static uint64_t now_ns(void) {
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}
static void pk(uint8_t *b, uint32_t s, uint64_t t, float sp, float hd,
               double la, double lo, float al) {
    memset(b,0,SZ); memcpy(b,&s,4); memcpy(b+8,&t,8);
    memcpy(b+16,&sp,4); memcpy(b+20,&hd,4);
    memcpy(b+24,&la,8); memcpy(b+32,&lo,8); memcpy(b+40,&al,4);
}

static void run_pub(HddsParticipant *p, HddsQoS *q) {
    HddsDataWriter *w = hdds_writer_create_with_qos(p, "rt/vehicle/telemetry", q);
    double bla=48.8584, blo=2.2945, r=0.001;
    printf("[VEH] Publishing at 10 Hz...\n\n");
    for (uint32_t i=1; i<=200; i++) {
        double t=i*0.1, a=t*0.5;
        double la=bla+r*sin(a), lo=blo+r*cos(a);
        float sp=25.0f+5.0f*(float)sin(t*0.3), hd=(float)fmod(a*180.0/M_PI,360.0);
        uint8_t b[SZ]; pk(b, i, now_ns(), sp, hd, la, lo, 35.0f);
        hdds_writer_write(w, b, SZ);
        if (i%10==1) printf("[VEH] #%-3u spd=%.1f hdg=%.1f lat=%.6f lon=%.6f\n",
                            i, sp, hd, la, lo);
        sleep_ms(100);
    }
    printf("\n[VEH] Done (200 samples).\n");
    hdds_writer_destroy(w);
}

static void run_sub(HddsParticipant *p, HddsQoS *q) {
    HddsDataReader *rd = hdds_reader_create_with_qos(p, "rt/vehicle/telemetry", q);
    HddsWaitSet *ws = hdds_waitset_create();
    hdds_waitset_attach_status_condition(ws, hdds_reader_get_status_condition(rd));
    printf("[GND] Listening on 'rt/vehicle/telemetry'...\n\n");
    int n=0;
    for (int att=0; att<300 && n<200; att++) {
        const void *tr[1]; size_t tc=0;
        if (hdds_waitset_wait(ws, 200000000LL, tr, 1, &tc)==HDDS_OK && tc>0) {
            uint8_t b[SZ]; size_t len=0;
            while (hdds_reader_take(rd, b, SZ, &len)==HDDS_OK) {
                uint32_t seq; uint64_t ts; float sp,hd; double la,lo;
                memcpy(&seq,b,4); memcpy(&ts,b+8,8); memcpy(&sp,b+16,4);
                memcpy(&hd,b+20,4); memcpy(&la,b+24,8); memcpy(&lo,b+32,8);
                double lat_ms=(double)(now_ns()-ts)/1e6;
                if (n%10==0) printf("[GND] #%-3u spd=%.1f hdg=%.1f lat=%.6f"
                    " lon=%.6f latency=%.2fms\n", seq,sp,hd,la,lo,lat_ms);
                n++;
            }
        }
    }
    printf("\n[GND] Received %d samples.\n", n);
    hdds_waitset_destroy(ws); hdds_reader_destroy(rd);
}

int main(int argc, char **argv) {
    int pub = (argc>1 && (strcmp(argv[1],"pub")==0 || strcmp(argv[1],"-p")==0));
    hdds_logging_init(3);
    HddsParticipant *p = hdds_participant_create("VehicleTelemetry");
    if (!p) { fprintf(stderr, "Participant failed\n"); return 1; }
    HddsQoS *q = hdds_qos_reliable(); hdds_qos_set_history_depth(q, 5);
    if (pub) run_pub(p, q); else run_sub(p, q);
    hdds_qos_destroy(q); hdds_participant_destroy(p);
    return 0;
}
