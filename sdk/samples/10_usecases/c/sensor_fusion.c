// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/*
 * sensor_fusion.c — Multi-sensor fusion (radar + lidar + camera)
 *
 * Reads three topics via one WaitSet. Best-effort QoS for high-rate streams.
 *
 * Build:  gcc -o sensor_fusion sensor_fusion.c -I../../../c/include -lhdds -lpthread -lm
 * Run:    ./sensor_fusion pub   # start 3 sensor simulators
 *         ./sensor_fusion       # fusion node (subscriber)
 *
 * Expected (sub):
 *   [RADAR]  #1 range=45.2m az=12 vel=3.1m/s
 *   [LIDAR]  #1 points=128
 *   [CAMERA] #1 frame=1
 *
 * Wire formats (16B each):
 *   Radar:  {u32 seq, f32 range, f32 azimuth, f32 velocity}
 *   Lidar:  {u32 seq, u32 points, f32 min_range, f32 max_range}
 *   Camera: {u32 seq, u32 frame, u16 w, u16 h, u8 fps, 3pad}
 */

#include <hdds.h>
#include <math.h>
#include <stdio.h>
#include <string.h>
#ifndef _WIN32
#include <unistd.h>
#include <pthread.h>
#define sleep_ms(ms) usleep((ms)*1000)
#else
#include <windows.h>
#define sleep_ms(ms) Sleep(ms)
#endif

#define S 16

static void *sim_radar(void *arg) {
    HddsDataWriter *w=(HddsDataWriter*)arg;
    for (uint32_t i=1;i<=100;i++) {
        uint8_t b[S]={0}; float r=30.f+20.f*sinf(i*.1f);
        float az=(float)(i%360), v=5.f*cosf(i*.05f);
        memcpy(b,&i,4);memcpy(b+4,&r,4);memcpy(b+8,&az,4);memcpy(b+12,&v,4);
        hdds_writer_write(w,b,S); sleep_ms(50);
    } return NULL;
}
static void *sim_lidar(void *arg) {
    HddsDataWriter *w=(HddsDataWriter*)arg;
    for (uint32_t i=1;i<=100;i++) {
        uint8_t b[S]={0}; uint32_t pts=64+(i%128); float mn=.5f,mx=50.f+(float)(i%20);
        memcpy(b,&i,4);memcpy(b+4,&pts,4);memcpy(b+8,&mn,4);memcpy(b+12,&mx,4);
        hdds_writer_write(w,b,S); sleep_ms(100);
    } return NULL;
}
static void *sim_camera(void *arg) {
    HddsDataWriter *w=(HddsDataWriter*)arg;
    for (uint32_t i=1;i<=100;i++) {
        uint8_t b[S]={0}; uint16_t ww=1920,hh=1080;
        memcpy(b,&i,4);memcpy(b+4,&i,4);memcpy(b+8,&ww,2);memcpy(b+10,&hh,2);b[12]=30;
        hdds_writer_write(w,b,S); sleep_ms(33);
    } return NULL;
}

static void run_pub(HddsParticipant *p, HddsQoS *q) {
    HddsDataWriter *wr=hdds_writer_create_with_qos(p,"rt/sensor/radar",q);
    HddsDataWriter *wl=hdds_writer_create_with_qos(p,"rt/sensor/lidar",q);
    HddsDataWriter *wc=hdds_writer_create_with_qos(p,"rt/sensor/camera",q);
    printf("[SIM] radar@20Hz lidar@10Hz camera@30Hz\n\n");
    pthread_t t1,t2,t3;
    pthread_create(&t1,NULL,sim_radar,wr);
    pthread_create(&t2,NULL,sim_lidar,wl);
    pthread_create(&t3,NULL,sim_camera,wc);
    pthread_join(t1,NULL);pthread_join(t2,NULL);pthread_join(t3,NULL);
    printf("[SIM] Done.\n");
    hdds_writer_destroy(wr);hdds_writer_destroy(wl);hdds_writer_destroy(wc);
}

static void run_fusion(HddsParticipant *p, HddsQoS *q) {
    HddsDataReader *rr=hdds_reader_create_with_qos(p,"rt/sensor/radar",q);
    HddsDataReader *rl=hdds_reader_create_with_qos(p,"rt/sensor/lidar",q);
    HddsDataReader *rc=hdds_reader_create_with_qos(p,"rt/sensor/camera",q);
    HddsWaitSet *ws=hdds_waitset_create();
    hdds_waitset_attach_status_condition(ws,hdds_reader_get_status_condition(rr));
    hdds_waitset_attach_status_condition(ws,hdds_reader_get_status_condition(rl));
    hdds_waitset_attach_status_condition(ws,hdds_reader_get_status_condition(rc));
    printf("[FUSION] Waiting for sensor data...\n\n");
    int rn=0,ln=0,cn=0;
    for (int a=0;a<300;a++) {
        const void *tr[3]; size_t tc=0;
        if (hdds_waitset_wait(ws,100000000LL,tr,3,&tc)!=HDDS_OK) continue;
        uint8_t b[S]; size_t len=0; uint32_t seq;
        while (hdds_reader_take(rr,b,S,&len)==HDDS_OK) {
            float r,az,v; memcpy(&seq,b,4);memcpy(&r,b+4,4);memcpy(&az,b+8,4);memcpy(&v,b+12,4);
            if (rn%10==0) printf("[RADAR]  #%-3u range=%.1fm az=%.0f vel=%.1fm/s\n",seq,r,az,v);
            rn++;
        }
        while (hdds_reader_take(rl,b,S,&len)==HDDS_OK) {
            uint32_t pts; memcpy(&seq,b,4);memcpy(&pts,b+4,4);
            if (ln%5==0) printf("[LIDAR]  #%-3u points=%u\n",seq,pts); ln++;
        }
        while (hdds_reader_take(rc,b,S,&len)==HDDS_OK) {
            uint32_t fr; memcpy(&seq,b,4);memcpy(&fr,b+4,4);
            if (cn%15==0) printf("[CAMERA] #%-3u frame=%u\n",seq,fr); cn++;
        }
    }
    printf("\n[FUSION] radar=%d lidar=%d camera=%d\n",rn,ln,cn);
    hdds_waitset_destroy(ws);
    hdds_reader_destroy(rr);hdds_reader_destroy(rl);hdds_reader_destroy(rc);
}

int main(int argc, char **argv) {
    int pub=(argc>1 && strcmp(argv[1],"pub")==0);
    hdds_logging_init(3);
    HddsParticipant *p=hdds_participant_create("SensorFusion");
    if (!p) {fprintf(stderr,"Participant failed\n"); return 1;}
    HddsQoS *q=hdds_qos_best_effort();
    if (pub) run_pub(p,q); else run_fusion(p,q);
    hdds_qos_destroy(q); hdds_participant_destroy(p);
    return 0;
}
