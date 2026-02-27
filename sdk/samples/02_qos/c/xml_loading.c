// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * HDDS Sample: XML QoS Loading (C)
 *
 * Demonstrates loading QoS profiles from XML files, including
 * standard OMG DDS XML and FastDDS-compatible XML formats.
 *
 * Build:
 *     cd build && cmake .. && make xml_loading
 *
 * Usage:
 *     ./xml_loading
 *
 * Expected output:
 *     [OK] Loaded QoS from XML profile 'reliable_profile'
 *     [OK] Writer created with XML QoS
 *     [OK] Reader created with XML QoS
 *     [OK] Loaded FastDDS-compatible XML profile
 *
 * Key concepts:
 * - Loading QoS from standard OMG DDS XML
 * - Loading FastDDS-compatible XML profiles
 * - Applying loaded QoS to writers and readers
 */

#include <hdds.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "generated/HelloWorld.h"

#define NUM_MESSAGES 5

int main(void)
{
    printf("============================================================\n");
    printf("XML QoS Loading Demo\n");
    printf("Load QoS profiles from XML files\n");
    printf("============================================================\n\n");

    hdds_logging_init(HDDS_LOG_INFO);

    /* Create participant */
    struct HddsParticipant *participant = hdds_participant_create("XmlQosDemo");
    if (!participant) {
        fprintf(stderr, "Failed to create participant\n");
        return 1;
    }
    printf("[OK] Participant created\n\n");

    /* --- Load QoS from standard OMG DDS XML --- */
    printf("--- Standard OMG DDS XML ---\n\n");

    struct HddsQoS *writer_qos = hdds_qos_from_xml("../qos_profile.xml");
    if (writer_qos) {
        printf("[OK] Loaded writer QoS from 'reliable_profile'\n");
    } else {
        printf("[WARN] XML loading failed, falling back to reliable defaults\n");
        writer_qos = hdds_qos_reliable();
    }

    struct HddsQoS *reader_qos = hdds_qos_from_xml("../qos_profile.xml");
    if (reader_qos) {
        printf("[OK] Loaded reader QoS from 'reliable_profile'\n");
    } else {
        printf("[WARN] XML loading failed, falling back to reliable defaults\n");
        reader_qos = hdds_qos_reliable();
    }

    /* Create endpoints with loaded QoS */
    struct HddsDataWriter *writer =
        hdds_writer_create_with_qos(participant, "XmlQosTopic", writer_qos);
    hdds_qos_destroy(writer_qos);

    struct HddsDataReader *reader =
        hdds_reader_create_with_qos(participant, "XmlQosTopic", reader_qos);
    hdds_qos_destroy(reader_qos);

    if (!writer || !reader) {
        fprintf(stderr, "Failed to create endpoints\n");
        if (writer) hdds_writer_destroy(writer);
        if (reader) hdds_reader_destroy(reader);
        hdds_participant_destroy(participant);
        return 1;
    }
    printf("[OK] Writer and Reader created with XML QoS\n\n");

    /* --- Load FastDDS-compatible XML --- */
    printf("--- FastDDS-Compatible XML ---\n\n");

    struct HddsQoS *fastdds_qos =
        hdds_qos_load_fastdds_xml("../qos_profile.xml");
    if (fastdds_qos) {
        printf("[OK] Loaded FastDDS-compatible XML profile\n");
        hdds_qos_destroy(fastdds_qos);
    } else {
        printf("[INFO] FastDDS XML not available (expected with OMG format)\n");
    }

    /* --- Send/receive test --- */
    printf("\n--- Pub/Sub Test with XML QoS ---\n\n");

    struct HddsWaitSet *waitset = hdds_waitset_create();
    const struct HddsStatusCondition *cond = hdds_reader_get_status_condition(reader);
    hdds_waitset_attach_status_condition(waitset, cond);

    for (int i = 0; i < NUM_MESSAGES; i++) {
        HelloWorld msg = {.id = i + 1};
        snprintf(msg.message, sizeof(msg.message), "XML QoS message #%d", i + 1);

        uint8_t buf[256];
        size_t len = HelloWorld_serialize(&msg, buf, sizeof(buf));
        hdds_writer_write(writer, buf, len);
        printf("[SENT] id=%d msg='%s'\n", msg.id, msg.message);
    }

    /* Read back */
    const void *triggered[1];
    size_t triggered_count;
    if (hdds_waitset_wait(waitset, 2000000000LL, triggered, 1, &triggered_count) == HDDS_OK) {
        uint8_t rbuf[512];
        size_t rlen;
        while (hdds_reader_take(reader, rbuf, sizeof(rbuf), &rlen) == HDDS_OK) {
            HelloWorld rmsg;
            if (HelloWorld_deserialize(&rmsg, rbuf, rlen)) {
                printf("[RECV] id=%d msg='%s'\n", rmsg.id, rmsg.message);
            }
        }
    }

    /* Cleanup */
    hdds_waitset_destroy(waitset);
    hdds_reader_destroy(reader);
    hdds_writer_destroy(writer);
    hdds_participant_destroy(participant);

    printf("\n=== XML QoS Loading Complete ===\n");
    return 0;
}
