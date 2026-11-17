/*
 * interop_app.c
 *
 * Single pub/sub binary for the HDDS cross-vendor interop smoke test,
 * built against CycloneDDS. Implements the CLI contract described in
 * scripts/interop-smoke/CONTRACT.md: one process, --mode pub or --mode
 * sub picks the role, everything else (domain, topic, reliability,
 * count, key, timeout) is a flag.
 *
 * Contract lines (EVENT/SENT/SAMPLE/DONE) go to stdout only; anything
 * else this program logs goes to stderr.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>

#include "dds/dds.h"
#include "InteropPing.h"

#define DEFAULT_TOPIC "InteropSmoke"
#define DEFAULT_COUNT 100
#define DEFAULT_KEY 42
#define DEFAULT_TIMEOUT 30

typedef struct {
    const char *mode;
    int domain;
    const char *topic;
    const char *reliability;
    int count;
    int key;
    int timeout;
    int challenge;
} cli_args_t;

/* Hard watchdog: if normal control flow ever fails to finish in time,
 * force the process to report and exit rather than hang forever. Only
 * used by the sub role, per the contract's receive-loop requirement. */
static void on_watchdog_alarm(int sig)
{
    (void)sig;
    static const char msg[] = "DONE timeout_forced\n";
    ssize_t written = write(STDOUT_FILENO, msg, sizeof(msg) - 1);
    (void)written;
    _exit(0);
}

static double now_seconds(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

/* Readiness settle for the publisher: how long to wait after the match
 * event before the first write. Configurable via env var (default 500ms)
 * so the orchestrator can run a no-settle investigation against the same
 * built image without a rebuild. */
static int get_settle_ms(void)
{
    const char *env = getenv("INTEROP_SMOKE_SETTLE_MS");
    if (env == NULL || env[0] == '\0') {
        return 500;
    }
    char *end = NULL;
    long val = strtol(env, &end, 10);
    if (end == env || *end != '\0' || val < 0 || val > 600000) {
        return 500;
    }
    return (int)val;
}

static void usage(const char *prog)
{
    fprintf(stderr,
        "usage: %s --mode pub|sub --domain N [--topic NAME] "
        "--reliability reliable|best_effort [--count N] [--key N] "
        "[--timeout N] [--challenge N]\n",
        prog);
}

static int parse_args(int argc, char **argv, cli_args_t *a)
{
    a->mode = NULL;
    a->domain = -1;
    a->topic = DEFAULT_TOPIC;
    a->reliability = "best_effort";
    a->count = DEFAULT_COUNT;
    a->key = DEFAULT_KEY;
    a->timeout = DEFAULT_TIMEOUT;
    a->challenge = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--mode") == 0 && i + 1 < argc) {
            a->mode = argv[++i];
        } else if (strcmp(argv[i], "--domain") == 0 && i + 1 < argc) {
            a->domain = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--topic") == 0 && i + 1 < argc) {
            a->topic = argv[++i];
        } else if (strcmp(argv[i], "--reliability") == 0 && i + 1 < argc) {
            a->reliability = argv[++i];
        } else if (strcmp(argv[i], "--count") == 0 && i + 1 < argc) {
            a->count = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--key") == 0 && i + 1 < argc) {
            a->key = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--timeout") == 0 && i + 1 < argc) {
            a->timeout = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--challenge") == 0 && i + 1 < argc) {
            a->challenge = atoi(argv[++i]);
        } else {
            fprintf(stderr, "unknown or incomplete argument: %s\n", argv[i]);
            return -1;
        }
    }

    if (a->mode == NULL
        || (strcmp(a->mode, "pub") != 0 && strcmp(a->mode, "sub") != 0)) {
        fprintf(stderr, "--mode must be pub or sub\n");
        return -1;
    }
    if (a->domain < 0) {
        fprintf(stderr, "--domain is required\n");
        return -1;
    }
    if (strcmp(a->reliability, "reliable") != 0
        && strcmp(a->reliability, "best_effort") != 0) {
        fprintf(stderr, "--reliability must be reliable or best_effort\n");
        return -1;
    }
    if (a->count <= 0) {
        fprintf(stderr, "--count must be positive\n");
        return -1;
    }
    if (a->challenge < 0 || a->challenge > 255) {
        fprintf(stderr, "--challenge must be 0-255\n");
        return -1;
    }
    return 0;
}

static dds_qos_t *make_qos(const cli_args_t *a)
{
    dds_qos_t *qos = dds_create_qos();
    if (strcmp(a->reliability, "reliable") == 0) {
        dds_qset_reliability(qos, DDS_RELIABILITY_RELIABLE, DDS_SECS(10));
    } else {
        dds_qset_reliability(qos, DDS_RELIABILITY_BEST_EFFORT, 0);
    }
    /* KEEP_LAST depth >= --count satisfies the contract for both
     * reliability kinds; no separate resource-limits branch needed. */
    dds_qset_history(qos, DDS_HISTORY_KEEP_LAST, a->count);
    return qos;
}

static int run_pub(const cli_args_t *a)
{
    dds_entity_t participant =
        dds_create_participant((dds_domainid_t)a->domain, NULL, NULL);
    if (participant < 0) {
        fprintf(stderr, "create_participant failed: %s\n",
                dds_strretcode(-participant));
        return 2;
    }

    dds_entity_t topic =
        dds_create_topic(participant, &InteropPing_desc, a->topic, NULL, NULL);
    if (topic < 0) {
        fprintf(stderr, "create_topic failed: %s\n", dds_strretcode(-topic));
        dds_delete(participant);
        return 2;
    }

    dds_qos_t *qos = make_qos(a);
    dds_entity_t writer = dds_create_writer(participant, topic, qos, NULL);
    dds_delete_qos(qos);
    if (writer < 0) {
        fprintf(stderr, "create_writer failed: %s\n", dds_strretcode(-writer));
        dds_delete(participant);
        return 2;
    }

    double start = now_seconds();
    bool matched = false;
    for (;;) {
        dds_publication_matched_status_t status;
        if (dds_get_publication_matched_status(writer, &status) == DDS_RETCODE_OK
            && status.current_count > 0) {
            matched = true;
            break;
        }
        if (now_seconds() - start >= (double)a->timeout) {
            break;
        }
        dds_sleepfor(DDS_MSECS(20));
    }

    if (!matched) {
        printf("EVENT no_match\n");
        fflush(stdout);
        dds_delete(participant);
        return 3;
    }
    printf("EVENT matched\n");
    fflush(stdout);

    /* Readiness settle: BEST_EFFORT can lose the first few samples to a
     * socket/association warm-up race right after match. Configurable
     * via env var so the orchestrator can test with/without it against
     * the same built image. */
    int settle_ms = get_settle_ms();
    if (settle_ms > 0) {
        dds_sleepfor(DDS_MSECS(settle_ms));
    }

    int sent_count = 0;
    for (int seq = 0; seq < a->count; seq++) {
        InteropPing sample;
        sample.key = a->key;
        sample.seq = (uint32_t)seq;
        for (int i = 0; i < 32; i++) {
            sample.payload[i] = (uint8_t)((seq + i + a->challenge) % 256);
        }
        dds_return_t rc = dds_write(writer, &sample);
        if (rc != DDS_RETCODE_OK) {
            fprintf(stderr, "write failed at seq=%d: %s\n", seq,
                    dds_strretcode(-rc));
        } else {
            sent_count++;
            printf("SENT seq=%d\n", seq);
            fflush(stdout);
        }
        dds_sleepfor(DDS_MSECS(3));
    }

    dds_sleepfor(DDS_SECS(2));
    printf("DONE sent=%d\n", sent_count);
    fflush(stdout);

    dds_delete(participant);
    return 0;
}

static int run_sub(const cli_args_t *a)
{
    dds_entity_t participant =
        dds_create_participant((dds_domainid_t)a->domain, NULL, NULL);
    if (participant < 0) {
        fprintf(stderr, "create_participant failed: %s\n",
                dds_strretcode(-participant));
        return 2;
    }

    dds_entity_t topic =
        dds_create_topic(participant, &InteropPing_desc, a->topic, NULL, NULL);
    if (topic < 0) {
        fprintf(stderr, "create_topic failed: %s\n", dds_strretcode(-topic));
        dds_delete(participant);
        return 2;
    }

    dds_qos_t *qos = make_qos(a);
    dds_entity_t reader = dds_create_reader(participant, topic, qos, NULL);
    dds_delete_qos(qos);
    if (reader < 0) {
        fprintf(stderr, "create_reader failed: %s\n", dds_strretcode(-reader));
        dds_delete(participant);
        return 2;
    }

    /* Overall safety cap in case the match-wait loop itself never
     * progresses (e.g. an unexpected blocking call). */
    signal(SIGALRM, on_watchdog_alarm);
    alarm((unsigned int)(a->timeout + 15));

    double start = now_seconds();
    bool matched = false;
    for (;;) {
        dds_subscription_matched_status_t status;
        if (dds_get_subscription_matched_status(reader, &status) == DDS_RETCODE_OK
            && status.current_count > 0) {
            matched = true;
            break;
        }
        if (now_seconds() - start >= (double)a->timeout) {
            break;
        }
        dds_sleepfor(DDS_MSECS(20));
    }

    if (!matched) {
        alarm(0);
        printf("EVENT no_match\n");
        fflush(stdout);
        dds_delete(participant);
        return 3;
    }
    printf("EVENT matched\n");
    fflush(stdout);

    /* Re-arm for the receive loop: --timeout + 10s hard cap measured
     * from the match, per the contract. */
    alarm((unsigned int)(a->timeout + 10));

    bool *seen = (bool *)calloc((size_t)a->count, sizeof(bool));
    int distinct = 0;
    int total_msgs = 0;
    double match_time = now_seconds();

    enum { BATCH = 8 };
    void *samples[BATCH];
    dds_sample_info_t infos[BATCH];
    for (int i = 0; i < BATCH; i++) {
        samples[i] = NULL;
    }

    while (distinct < a->count
           && (now_seconds() - match_time) < (double)a->timeout) {
        dds_return_t rc = dds_take(reader, samples, infos, BATCH, BATCH);
        if (rc > 0) {
            for (int i = 0; i < rc; i++) {
                if (!infos[i].valid_data) {
                    continue;
                }
                InteropPing *s = (InteropPing *)samples[i];
                total_msgs++;

                char hex[65];
                for (int b = 0; b < 32; b++) {
                    snprintf(hex + b * 2, 3, "%02x", s->payload[b]);
                }
                hex[64] = '\0';

                printf("SAMPLE seq=%u key=%d payload=%s\n",
                       s->seq, s->key, hex);
                fflush(stdout);

                if (seen != NULL && s->seq < (uint32_t)a->count
                    && !seen[s->seq]) {
                    seen[s->seq] = true;
                    distinct++;
                }
            }
            dds_return_loan(reader, samples, rc);
            for (int i = 0; i < BATCH; i++) {
                samples[i] = NULL;
            }
        } else if (rc < 0) {
            fprintf(stderr, "take failed: %s\n", dds_strretcode(-rc));
            dds_sleepfor(DDS_MSECS(10));
        } else {
            dds_sleepfor(DDS_MSECS(10));
        }
    }

    free(seen);
    alarm(0);
    printf("DONE received=%d distinct=%d\n", total_msgs, distinct);
    fflush(stdout);

    dds_delete(participant);
    return 0;
}

int main(int argc, char **argv)
{
    cli_args_t args;
    if (parse_args(argc, argv, &args) != 0) {
        usage(argv[0]);
        return 2;
    }

    if (strcmp(args.mode, "pub") == 0) {
        return run_pub(&args);
    }
    return run_sub(&args);
}
