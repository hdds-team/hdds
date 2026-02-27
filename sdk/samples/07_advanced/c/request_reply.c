// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * HDDS Sample: Request-Reply (C)
 *
 * Demonstrates RPC-style communication over DDS.
 * Shows how to implement request-reply patterns using topics.
 *
 * Usage:
 *     ./request_reply              # Run as requester (client)
 *     ./request_reply --server     # Run as replier (server)
 *
 * Key concepts:
 * - Service with request/reply topics
 * - Correlation IDs for matching responses
 * - Timeout handling
 */

#include <hdds.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>

#include "generated/HelloWorld.h"

volatile int running = 1;

void signal_handler(int sig) {
    (void)sig;
    running = 0;
}

uint64_t get_time_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

/* Request message format: "REQ|request_id|client_id|operation|payload" */
/* Reply message format:   "REP|request_id|status_code|result" */

void print_request_reply_overview(void) {
    printf("--- Request-Reply Pattern ---\n\n");
    printf("Request-Reply over DDS:\n\n");
    printf("  Requester                     Replier\n");
    printf("  ---------                     -------\n");
    printf("      |                             |\n");
    printf("      |---- Request (ID=1) ------->|\n");
    printf("      |                             | process\n");
    printf("      |<---- Reply (ID=1) ---------|\n");
    printf("      |                             |\n");
    printf("\n");
    printf("Topics:\n");
    printf("  - Calculator_Request: client -> service\n");
    printf("  - Calculator_Reply: service -> client\n");
    printf("\n");
    printf("Correlation:\n");
    printf("  - request_id: unique per request\n");
    printf("  - client_id: identifies requester\n");
    printf("\n");
}

void run_server(struct HddsParticipant* participant) {
    printf("[OK] Running as SERVICE (replier)\n\n");

    /* Create endpoints */
    struct HddsDataReader* request_reader = hdds_reader_create(participant, "Calculator_Request");
    struct HddsDataWriter* reply_writer = hdds_writer_create(participant, "Calculator_Reply");

    if (!request_reader || !reply_writer) {
        fprintf(stderr, "Failed to create endpoints\n");
        if (request_reader) hdds_reader_destroy(request_reader);
        if (reply_writer) hdds_writer_destroy(reply_writer);
        return;
    }

    printf("[OK] Request reader and reply writer created\n");

    struct HddsWaitSet* waitset = hdds_waitset_create();
    const struct HddsStatusCondition* cond = hdds_reader_get_status_condition(request_reader);
    hdds_waitset_attach_status_condition(waitset, cond);

    printf("--- Service Ready ---\n");
    printf("Listening for requests (Ctrl+C to exit)...\n\n");

    while (running) {
        const void* triggered[1];
        size_t triggered_count;

        if (hdds_waitset_wait(waitset, 1000000000LL, triggered, 1, &triggered_count) == HDDS_OK && triggered_count > 0) {
            uint8_t buffer[512];
            size_t len;

            while (hdds_reader_take(request_reader, buffer, sizeof(buffer), &len) == HDDS_OK) {
                HelloWorld req;
                if (HelloWorld_deserialize(&req, buffer, len)) {
                    /* Parse request: "operation:arg1:arg2" */
                    char operation[32] = {0};
                    int a = 0, b = 0;

                    char* op_end = strchr(req.message, ':');
                    if (op_end) {
                        size_t op_len = (size_t)(op_end - req.message);
                        if (op_len < sizeof(operation)) {
                            strncpy(operation, req.message, op_len);
                        }
                        sscanf(op_end + 1, "%d:%d", &a, &b);
                    } else {
                        strncpy(operation, req.message, sizeof(operation) - 1);
                    }

                    printf("[REQUEST] ID=%d, Op=%s\n", req.id, operation);

                    /* Process request */
                    HelloWorld reply = {.id = req.id};
                    int status = 0;

                    if (strcmp(operation, "add") == 0) {
                        snprintf(reply.message, sizeof(reply.message), "REP:0:%d", a + b);
                    } else if (strcmp(operation, "multiply") == 0) {
                        snprintf(reply.message, sizeof(reply.message), "REP:0:%d", a * b);
                    } else if (strcmp(operation, "echo") == 0) {
                        snprintf(reply.message, sizeof(reply.message), "REP:0:%s", op_end ? op_end + 1 : "");
                    } else {
                        snprintf(reply.message, sizeof(reply.message), "REP:-1:Unknown operation");
                        status = -1;
                    }

                    printf("[REPLY]   ID=%d, Status=%d, Result=%s\n\n",
                           reply.id, status, reply.message + 6);

                    /* Send reply */
                    uint8_t reply_buf[256];
                    size_t reply_len = HelloWorld_serialize(&reply, reply_buf, sizeof(reply_buf));
                    hdds_writer_write(reply_writer, reply_buf, reply_len);
                }
            }
        }
    }

    hdds_waitset_destroy(waitset);
    hdds_reader_destroy(request_reader);
    hdds_writer_destroy(reply_writer);
}

void run_client(struct HddsParticipant* participant, const char* client_id) {
    printf("[OK] Running as CLIENT (requester): %s\n\n", client_id);

    /* Create endpoints */
    struct HddsDataWriter* request_writer = hdds_writer_create(participant, "Calculator_Request");
    struct HddsDataReader* reply_reader = hdds_reader_create(participant, "Calculator_Reply");

    if (!request_writer || !reply_reader) {
        fprintf(stderr, "Failed to create endpoints\n");
        if (request_writer) hdds_writer_destroy(request_writer);
        if (reply_reader) hdds_reader_destroy(reply_reader);
        return;
    }

    printf("[OK] Request writer and reply reader created\n");

    struct HddsWaitSet* waitset = hdds_waitset_create();
    const struct HddsStatusCondition* cond = hdds_reader_get_status_condition(reply_reader);
    hdds_waitset_attach_status_condition(waitset, cond);

    printf("--- Sending Requests ---\n\n");

    /* Test operations */
    struct {
        const char* operation;
        int arg1;
        int arg2;
    } operations[] = {
        {"add", 10, 20},
        {"multiply", 5, 7},
        {"echo", 0, 0},
    };

    for (int i = 0; i < 3; i++) {
        int request_id = i + 1;

        /* Build request */
        HelloWorld req = {.id = request_id};
        if (strcmp(operations[i].operation, "echo") == 0) {
            snprintf(req.message, sizeof(req.message), "echo:Hello DDS");
        } else {
            snprintf(req.message, sizeof(req.message), "%s:%d:%d",
                     operations[i].operation, operations[i].arg1, operations[i].arg2);
        }

        printf("[SEND REQUEST] ID=%d, Op=%s\n", request_id, operations[i].operation);

        /* Send request */
        uint8_t buffer[256];
        size_t len = HelloWorld_serialize(&req, buffer, sizeof(buffer));
        hdds_writer_write(request_writer, buffer, len);

        /* Wait for reply with timeout */
        uint64_t start = get_time_ns();
        int got_reply = 0;

        while ((get_time_ns() - start) < 2000000000ULL) {  /* 2 second timeout */
            const void* triggered[1];
            size_t triggered_count;

            if (hdds_waitset_wait(waitset, 100000000LL, triggered, 1, &triggered_count) == HDDS_OK && triggered_count > 0) {
                uint8_t reply_buf[256];
                size_t reply_len;

                while (hdds_reader_take(reply_reader, reply_buf, sizeof(reply_buf), &reply_len) == HDDS_OK) {
                    HelloWorld reply;
                    if (HelloWorld_deserialize(&reply, reply_buf, reply_len)) {
                        if (reply.id == request_id) {
                            /* Parse "REP:status:result" */
                            int status = 0;
                            char result[128] = {0};
                            char* first_colon = strchr(reply.message, ':');
                            if (first_colon) {
                                char* second_colon = strchr(first_colon + 1, ':');
                                if (second_colon) {
                                    status = atoi(first_colon + 1);
                                    strncpy(result, second_colon + 1, sizeof(result) - 1);
                                }
                            }
                            printf("[GOT REPLY]    ID=%d, Status=%d, Result=%s\n\n",
                                   reply.id, status, result);
                            got_reply = 1;
                            break;
                        }
                    }
                }
            }
            if (got_reply) break;
        }

        if (!got_reply) {
            printf("[TIMEOUT] No reply for request ID=%d\n\n", request_id);
        }
    }

    /* Pattern variations */
    printf("--- Request-Reply Variations ---\n\n");
    printf("1. Synchronous: Block until reply (simple)\n");
    printf("2. Asynchronous: Callback on reply (non-blocking)\n");
    printf("3. Future-based: Returns future, await later\n");
    printf("4. Fire-and-forget: No reply expected\n");
    printf("\n");

    printf("--- Implementation Tips ---\n\n");
    printf("1. Use content filter for client_id to receive only your replies\n");
    printf("2. Include request_id for correlation\n");
    printf("3. Set appropriate timeouts\n");
    printf("4. Handle service unavailability gracefully\n");
    printf("5. Consider retry logic for failed requests\n");

    hdds_waitset_destroy(waitset);
    hdds_writer_destroy(request_writer);
    hdds_reader_destroy(reply_reader);
}

int main(int argc, char* argv[]) {
    printf("============================================================\n");
    printf("Request-Reply Demo\n");
    printf("RPC-style communication over DDS\n");
    printf("============================================================\n\n");

    hdds_logging_init(HDDS_LOG_INFO);

    signal(SIGINT, signal_handler);

    int is_server = 0;
    const char* client_id = "Client1";

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--server") == 0 || strcmp(argv[i], "server") == 0) {
            is_server = 1;
        } else {
            client_id = argv[i];
        }
    }

    print_request_reply_overview();

    /* Create participant */
    struct HddsParticipant* participant = hdds_participant_create("RequestReplyDemo");
    if (!participant) {
        fprintf(stderr, "Failed to create participant\n");
        return 1;
    }

    printf("[OK] Participant created: %s\n", hdds_participant_name(participant));

    if (is_server) {
        run_server(participant);
    } else {
        run_client(participant, client_id);
    }

    hdds_participant_destroy(participant);

    printf("\n=== Request-Reply Demo Complete ===\n");
    return 0;
}
