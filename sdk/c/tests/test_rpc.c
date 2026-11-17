// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/* POSIX RPC lifecycle and concurrency consumer. Checks remain active with NDEBUG. */
#define _POSIX_C_SOURCE 200809L
#include <hdds.h>
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define CHECK(c) do { if (!(c)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #c); abort(); } } while (0)

static int32_t echo(const uint8_t *request, size_t len, uint8_t **reply, size_t *reply_len, void *context) {
    (void)context;
    *reply = (uint8_t *)malloc(len ? len : 1); /* exercises allocated empty reply */
    CHECK(*reply != NULL);
    if (len) memcpy(*reply, request, len);
    *reply_len = len;
    return 0;
}

static int32_t proxy(const uint8_t *request, size_t len, uint8_t **reply, size_t *reply_len, void *context) {
    uint8_t *nested = NULL;
    size_t nested_len = 0;
    CHECK(hdds_rpc_client_call_default((struct HddsRpcClient *)context, request, len, &nested, &nested_len) == HDDS_OK);
    int32_t result = echo(nested, nested_len, reply, reply_len, NULL);
    hdds_rpc_reply_free(nested, nested_len);
    return result;
}

static int32_t invalid_reply(const uint8_t *request, size_t len, uint8_t **reply, size_t *reply_len, void *context) {
    (void)request; (void)len; (void)context;
    *reply = NULL;
    *reply_len = 1;
    return 0;
}

static int32_t remote_error(const uint8_t *request, size_t len, uint8_t **reply, size_t *reply_len, void *context) {
    (void)request; (void)len; (void)context;
    /* Error outputs are ignored, without ownership transfer. */
    *reply = (uint8_t *)(uintptr_t)1;
    *reply_len = 100;
    return HDDS_RPC_INVALID_ARGUMENT;
}

static size_t registrations(const char *name) {
    size_t found = 0;
    for (size_t i = 0; i < hdds_rpc_service_count(); ++i) {
        char buffer[128];
        hdds_rpc_service_name(i, buffer, sizeof(buffer));
        found += strcmp(buffer, name) == 0;
    }
    return found;
}

static void check_echo(struct HddsRpcClient *client, const uint8_t *payload, size_t len) {
    uint8_t *reply = NULL;
    size_t reply_len = 0;
    CHECK(hdds_rpc_client_call_default(client, payload, len, &reply, &reply_len) == HDDS_OK);
    CHECK(reply_len == len);
    if (len) CHECK(memcmp(reply, payload, len) == 0);
    else CHECK(reply == NULL);
    hdds_rpc_reply_free(reply, reply_len);
}

static void *concurrent_calls(void *argument) {
    struct HddsRpcClient *client = (struct HddsRpcClient *)argument;
    for (uint8_t i = 0; i < 16; ++i) {
        uint8_t payload[] = {0, 255, i, 0, 42};
        check_echo(client, payload, sizeof(payload));
    }
    return NULL;
}

static void roundtrip_and_nested(struct HddsParticipant *participant) {
    CHECK(hdds_rpc_server_create(participant, "bad", NULL, NULL) == NULL);
    CHECK(hdds_rpc_client_create(participant, "", 1000) == NULL);
    struct HddsRpcServer *worker = hdds_rpc_server_create(participant, "c_rpc_worker", echo, NULL);
    CHECK(worker != NULL);
    struct HddsRpcServer *duplicate = hdds_rpc_server_create(participant, "c_rpc_worker", echo, NULL);
    CHECK(duplicate != NULL);
    CHECK(registrations("c_rpc_worker") == 1);
    hdds_rpc_server_destroy(duplicate);
    CHECK(registrations("c_rpc_worker") == 1);
    CHECK(!hdds_rpc_server_is_running(worker));
    CHECK(hdds_rpc_server_spin_background(worker) == HDDS_OK);
    CHECK(hdds_rpc_server_is_running(worker));
    CHECK(hdds_rpc_server_spin_background(worker) == HDDS_INVALID_STATE);
    CHECK(hdds_rpc_server_set_request_timeout(worker, 1) == HDDS_INVALID_STATE);
    struct HddsRpcClient *nested = hdds_rpc_client_create(participant, "c_rpc_worker", 2000);
    CHECK(nested != NULL);
    struct HddsRpcServer *server = hdds_rpc_server_create(participant, "c_rpc_proxy", proxy, nested);
    CHECK(server != NULL);
    CHECK(hdds_rpc_server_spin_background(server) == HDDS_OK);
    struct HddsRpcClient *client = hdds_rpc_client_create(participant, "c_rpc_proxy", 2000);
    CHECK(client != NULL);
    const uint8_t data[] = {0, 255, 1, 2, 0, 3};
    check_echo(client, data, sizeof(data));
    check_echo(client, NULL, 0);
    pthread_t callers[4];
    for (size_t i = 0; i < 4; ++i) CHECK(pthread_create(&callers[i], NULL, concurrent_calls, client) == 0);
    for (size_t i = 0; i < 4; ++i) CHECK(pthread_join(callers[i], NULL) == 0);
    uint8_t *reply = (uint8_t *)(uintptr_t)1;
    size_t len = 99;
    CHECK(hdds_rpc_client_call(client, NULL, 1, 1000, &reply, &len) == HDDS_INVALID_ARGUMENT);
    CHECK(reply == NULL && len == 0);
    CHECK(hdds_rpc_client_call(client, data, sizeof(data), 0, &reply, &len) == HDDS_TIMEOUT);
    CHECK(reply == NULL && len == 0);
    hdds_rpc_client_shutdown(client);
    CHECK(hdds_rpc_client_call_default(client, data, sizeof(data), &reply, &len) == HDDS_INVALID_STATE);
    hdds_rpc_client_destroy(client);
    hdds_rpc_server_destroy(server);
    hdds_rpc_client_destroy(nested);
    hdds_rpc_server_destroy(worker);
    CHECK(registrations("c_rpc_worker") == 0);
    CHECK(registrations("c_rpc_proxy") == 0);
}

struct Blocked {
    pthread_mutex_t mutex;
    pthread_cond_t changed;
    int entered, release, finished, destroying, destroyed, call_done;
    struct HddsRpcServer *server;
    struct HddsRpcClient *client;
    enum HddsError result;
};

static void init_blocked(struct Blocked *blocked) {
    memset(blocked, 0, sizeof(*blocked));
    CHECK(pthread_mutex_init(&blocked->mutex, NULL) == 0);
    CHECK(pthread_cond_init(&blocked->changed, NULL) == 0);
}

static struct timespec deadline_ms(long ms) {
    struct timespec deadline;
    CHECK(clock_gettime(CLOCK_REALTIME, &deadline) == 0);
    deadline.tv_sec += ms / 1000;
    deadline.tv_nsec += (ms % 1000) * 1000000;
    if (deadline.tv_nsec >= 1000000000) { deadline.tv_nsec -= 1000000000; ++deadline.tv_sec; }
    return deadline;
}

static void wait_flag(struct Blocked *blocked, const int *flag) {
    struct timespec deadline = deadline_ms(3000);
    while (!*flag) CHECK(pthread_cond_timedwait(&blocked->changed, &blocked->mutex, &deadline) == 0);
}

static int32_t blocked_handler(const uint8_t *request, size_t len, uint8_t **reply, size_t *reply_len, void *context) {
    struct Blocked *blocked = (struct Blocked *)context;
    CHECK(pthread_mutex_lock(&blocked->mutex) == 0);
    blocked->entered = 1;
    CHECK(pthread_cond_broadcast(&blocked->changed) == 0);
    while (!blocked->release) CHECK(pthread_cond_wait(&blocked->changed, &blocked->mutex) == 0);
    blocked->finished = 1;
    CHECK(pthread_mutex_unlock(&blocked->mutex) == 0);
    return echo(request, len, reply, reply_len, NULL);
}

static void *blocked_call(void *argument) {
    struct Blocked *blocked = (struct Blocked *)argument;
    uint8_t *reply = NULL;
    size_t len = 0;
    blocked->result = hdds_rpc_client_call_default(blocked->client, NULL, 0, &reply, &len);
    CHECK(reply == NULL && len == 0);
    CHECK(pthread_mutex_lock(&blocked->mutex) == 0);
    blocked->call_done = 1;
    CHECK(pthread_cond_broadcast(&blocked->changed) == 0);
    CHECK(pthread_mutex_unlock(&blocked->mutex) == 0);
    return NULL;
}

static void *destroy_blocked(void *argument) {
    struct Blocked *blocked = (struct Blocked *)argument;
    CHECK(pthread_mutex_lock(&blocked->mutex) == 0);
    blocked->destroying = 1;
    CHECK(pthread_cond_broadcast(&blocked->changed) == 0);
    CHECK(pthread_mutex_unlock(&blocked->mutex) == 0);
    hdds_rpc_server_destroy(blocked->server);
    CHECK(pthread_mutex_lock(&blocked->mutex) == 0);
    CHECK(blocked->finished);
    blocked->destroyed = 1;
    CHECK(pthread_cond_broadcast(&blocked->changed) == 0);
    CHECK(pthread_mutex_unlock(&blocked->mutex) == 0);
    return NULL;
}

static void timeout_shutdown_and_drain(struct HddsParticipant *participant, int server_timeout) {
    struct Blocked blocked;
    init_blocked(&blocked);
    const char *name = server_timeout ? "c_rpc_timeout" : "c_rpc_cancel";
    blocked.server = hdds_rpc_server_create(participant, name, blocked_handler, &blocked);
    CHECK(blocked.server != NULL);
    if (server_timeout) CHECK(hdds_rpc_server_set_request_timeout(blocked.server, 20) == HDDS_OK);
    CHECK(hdds_rpc_server_spin_background(blocked.server) == HDDS_OK);
    blocked.client = hdds_rpc_client_create(participant, name, 10000);
    CHECK(blocked.client != NULL);
    pthread_t caller, destroyer;
    CHECK(pthread_create(&caller, NULL, blocked_call, &blocked) == 0);
    CHECK(pthread_mutex_lock(&blocked.mutex) == 0);
    wait_flag(&blocked, &blocked.entered);
    CHECK(pthread_mutex_unlock(&blocked.mutex) == 0);
    if (!server_timeout) hdds_rpc_client_shutdown(blocked.client);
    CHECK(pthread_mutex_lock(&blocked.mutex) == 0);
    wait_flag(&blocked, &blocked.call_done); /* Must beat the client's 10-second deadline. */
    CHECK(pthread_mutex_unlock(&blocked.mutex) == 0);
    CHECK(pthread_join(caller, NULL) == 0);
    /* A server-side handler timeout is a remote exception (DDS-RPC has no timeout
       code), so the client sees HDDS_OPERATION_FAILED; only its own deadline is HDDS_TIMEOUT. */
    CHECK(blocked.result == (server_timeout ? HDDS_OPERATION_FAILED : HDDS_INVALID_STATE));
    CHECK(pthread_create(&destroyer, NULL, destroy_blocked, &blocked) == 0);
    CHECK(pthread_mutex_lock(&blocked.mutex) == 0);
    wait_flag(&blocked, &blocked.destroying);
    struct timespec deadline = deadline_ms(50);
    int result = 0;
    while (!blocked.destroyed && result == 0) result = pthread_cond_timedwait(&blocked.changed, &blocked.mutex, &deadline);
    CHECK(result == ETIMEDOUT && !blocked.destroyed && !blocked.finished);
    blocked.release = 1;
    CHECK(pthread_cond_broadcast(&blocked.changed) == 0);
    CHECK(pthread_mutex_unlock(&blocked.mutex) == 0);
    CHECK(pthread_join(destroyer, NULL) == 0);
    CHECK(blocked.destroyed && blocked.finished);
    hdds_rpc_client_destroy(blocked.client);
    CHECK(pthread_cond_destroy(&blocked.changed) == 0);
    CHECK(pthread_mutex_destroy(&blocked.mutex) == 0);
}

static void error_replies(struct HddsParticipant *participant) {
    HddsRpcHandlerFn handlers[] = {invalid_reply, remote_error};
    for (size_t i = 0; i < 2; ++i) {
        const char *name = i ? "c_rpc_remote_error" : "c_rpc_invalid_reply";
        struct HddsRpcServer *server = hdds_rpc_server_create(participant, name, handlers[i], NULL);
        CHECK(server != NULL);
        CHECK(hdds_rpc_server_spin_background(server) == HDDS_OK);
        struct HddsRpcClient *client = hdds_rpc_client_create(participant, name, 2000);
        CHECK(client != NULL);
        uint8_t *reply = NULL;
        size_t len = 0;
        CHECK(hdds_rpc_client_call_default(client, NULL, 0, &reply, &len) == HDDS_OPERATION_FAILED);
        CHECK(reply == NULL && len == 0);
        hdds_rpc_client_destroy(client);
        hdds_rpc_server_destroy(server);
    }
    struct HddsRpcServer *server = hdds_rpc_server_create(participant, "c_rpc_never_started", echo, NULL);
    CHECK(server != NULL);
    hdds_rpc_server_shutdown(server);
    CHECK(hdds_rpc_server_spin_background(server) == HDDS_INVALID_STATE);
    CHECK(!hdds_rpc_server_is_running(server));
    hdds_rpc_server_destroy(server);
}

struct SpinCall { struct HddsRpcServer *server; enum HddsError result; };

static void *spin_blocking(void *argument) {
    struct SpinCall *call = (struct SpinCall *)argument;
    call->result = hdds_rpc_server_spin(call->server);
    return NULL;
}

static void blocking_spin_shutdown(struct HddsParticipant *participant) {
    struct SpinCall call;
    call.server = hdds_rpc_server_create(participant, "c_rpc_blocking_spin", echo, NULL);
    CHECK(call.server != NULL);
    pthread_t spinner;
    CHECK(pthread_create(&spinner, NULL, spin_blocking, &call) == 0);
    struct timespec deadline = deadline_ms(3000);
    while (!hdds_rpc_server_is_running(call.server)) {
        struct timespec now;
        CHECK(clock_gettime(CLOCK_REALTIME, &now) == 0);
        CHECK(now.tv_sec < deadline.tv_sec || (now.tv_sec == deadline.tv_sec && now.tv_nsec < deadline.tv_nsec));
        struct timespec pause = {0, 1000000};
        nanosleep(&pause, NULL);
    }
    hdds_rpc_server_shutdown(call.server);
    CHECK(pthread_join(spinner, NULL) == 0);
    CHECK(call.result == HDDS_OK);
    CHECK(!hdds_rpc_server_is_running(call.server));
    hdds_rpc_server_destroy(call.server);
}

int main(void) {
    alarm(90);
    struct HddsParticipant *participant = hdds_participant_create_with_transport("c_rpc", HDDS_TRANSPORT_INTRA_PROCESS);
    CHECK(participant != NULL);
    roundtrip_and_nested(participant);
    timeout_shutdown_and_drain(participant, 0);
    timeout_shutdown_and_drain(participant, 1);
    error_replies(participant);
    blocking_spin_shutdown(participant);
    hdds_participant_destroy(participant);
    puts("RPC C consumer: PASS");
    return 0;
}
