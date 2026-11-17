/* SPDX-License-Identifier: Apache-2.0 OR MIT */
/* Copyright (c) 2025-2026 naskel.com */

#include <hdds.h>
#include "sdk_keyed.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    assert(argc == 4);
    HddsParticipantConfig *config = hdds_config_create("c_scoped_writer");
    assert(config);
    assert(hdds_config_set_domain_id(config, (uint32_t)strtoul(argv[1], NULL, 10)) == HDDS_OK);
    HddsParticipant *participant = hdds_config_build(config);
    assert(participant);
    HddsQoS *qos = hdds_qos_reliable();
    HddsPublisher *publisher = NULL;
    HddsDataWriter *writer;
    if (strcmp(argv[3], "scoped_publisher") == 0) {
        publisher = hdds_publisher_create(participant);
        assert(publisher);
        writer = m_t_create_keyed_writer_from_publisher(publisher, "sdk_key_identity", qos);
    } else {
        writer = m_t_create_keyed_writer(participant, "sdk_key_identity", qos);
    }
    assert(writer);
    assert(hdds_writer_wait_for_matched_readers(writer, 1, 20000) == HDDS_OK);
    for (int value = 10; value <= 20; value += 10) {
        for (int id = 1; id <= 3; ++id) {
            m_T row = {1, id, value};
            assert(m_t_write(writer, &row) == HDDS_OK);
        }
    }
    assert(hdds_writer_wait_for_acknowledgments(writer, 20000) == HDDS_OK);
    puts("WRITTEN"); fflush(stdout);
    char command[32];
    assert(scanf("%31s", command) == 1 && strcmp(command, "dispose") == 0);
    m_T row = {1, 2, 0};
    assert(m_t_dispose(writer, &row) == HDDS_OK);
    assert(hdds_writer_wait_for_acknowledgments(writer, 20000) == HDDS_OK);
    puts("DISPOSED"); fflush(stdout);
    assert(scanf("%31s", command) == 1 && strcmp(command, "unregister") == 0);
    row.id = 3;
    assert(m_t_unregister_instance(writer, &row) == HDDS_OK);
    assert(hdds_writer_wait_for_acknowledgments(writer, 20000) == HDDS_OK);
    puts("UNREGISTERED"); fflush(stdout);
    assert(scanf("%31s", command) == 1 && strcmp(command, "quit") == 0);
    hdds_writer_destroy(writer);
    if (publisher) hdds_publisher_destroy(publisher);
    hdds_qos_destroy(qos);
    hdds_participant_destroy(participant);
}
