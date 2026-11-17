// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com
//
// Drive rmw_take_sequence directly.
//
// rmw_implementation forwards rmw_take_sequence and rcl_take_sequence calls
// it, but no stock ROS 2 node does: rclpy has no binding for it and rclcpp's
// executors take one message at a time. So the entry point shipped with the
// symbol gate as its only proof - and the symbol gate proves PRESENCE, which
// by build-rmw.sh's own comment is not behaviour.
//
// This probe subscribes to /chatter, lets a talker in ANOTHER container fill
// its history, and then asks rmw_take_sequence three questions that only its
// own logic can answer:
//
//   1. count LARGER than what is available -> a SHORT READ: RMW_RET_OK, taken
//      is what was there and no more, and BOTH sequence sizes equal taken.
//   2. count larger than the message capacity -> RMW_RET_INVALID_ARGUMENT,
//      taken == 0, nothing written.
//   3. count larger than the message-INFO capacity (the SECOND check, which a
//      probe that only tested the first would never reach).
//
// It calls rmw_take_sequence rather than rcl_take_sequence on purpose: rcl
// validates capacities itself, so going through rcl would measure rcl.
//
// The publisher is in another container ON PURPOSE. A publisher and a
// subscriber on the SAME participant crash this stack inside rcl_wait - the
// shared-memory shim in rmw_wait.c reaches a mapping the other end of the same
// process just made (observed on humble as "[ros2run]: Segmentation fault", and
// "Bus error" on the variant that took without waiting first). That defect is real; it is not what
// this probe is for.
//
// Prints one "PROBE <name> PASS|FAIL <detail>" line per question and exits
// with the number of failures.

#include <execinfo.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <rcl/rcl.h>
#include <rcl/subscription.h>
#include <rcutils/allocator.h>
#include <rcutils/error_handling.h>
#include <rmw/rmw.h>
#include <rmw/message_sequence.h>
#include <rosidl_runtime_c/string_functions.h>
#include <std_msgs/msg/string.h>

#define TOPIC "/chatter"
#define MIN_EXPECTED 3u
// Bigger than the default rcl history depth (10), so the history can NEVER
// fill the request and the short read is guaranteed rather than lucky.
#define CAPACITY 16u
#define ACCUMULATE_SECONDS 6u

static int failures = 0;

// A crash inside the middleware is the probe's most useful output, so print a
// backtrace instead of leaving "Segmentation fault" as the whole report.
static void crash_handler(int sig)
{
  void * frames[32];
  int n = backtrace(frames, 32);
  fprintf(stderr, "\nprobe: caught signal %d, %d frame(s):\n", sig, n);
  fflush(stderr);
  backtrace_symbols_fd(frames, n, 2);
  _exit(128 + sig);
}

static void report(const char * name, int ok, const char * detail)
{
  printf("PROBE %s %s %s\n", name, ok ? "PASS" : "FAIL", detail);
  fflush(stdout);
  if (!ok) {
    failures++;
  }
}

int main(void)
{
  signal(SIGSEGV, crash_handler);
  signal(SIGBUS, crash_handler);
  signal(SIGABRT, crash_handler);

  rcl_allocator_t allocator = rcl_get_default_allocator();
  rcl_init_options_t init_options = rcl_get_zero_initialized_init_options();
  if (rcl_init_options_init(&init_options, allocator) != RCL_RET_OK) {
    fprintf(stderr, "probe: rcl_init_options_init failed\n");
    return 90;
  }
  rcl_context_t context = rcl_get_zero_initialized_context();
  if (rcl_init(0, NULL, &init_options, &context) != RCL_RET_OK) {
    fprintf(stderr, "probe: rcl_init failed\n");
    return 91;
  }

  rcl_node_t node = rcl_get_zero_initialized_node();
  rcl_node_options_t node_options = rcl_node_get_default_options();
  if (rcl_node_init(&node, "hdds_take_sequence_probe", "", &context, &node_options)
    != RCL_RET_OK)
  {
    fprintf(stderr, "probe: rcl_node_init failed\n");
    return 92;
  }

  const rosidl_message_type_support_t * ts =
    ROSIDL_GET_MSG_TYPE_SUPPORT(std_msgs, msg, String);

  rcl_subscription_t subscription = rcl_get_zero_initialized_subscription();
  rcl_subscription_options_t sub_options = rcl_subscription_get_default_options();
  if (rcl_subscription_init(&subscription, &node, ts, TOPIC, &sub_options) != RCL_RET_OK) {
    fprintf(stderr, "probe: rcl_subscription_init failed\n");
    return 94;
  }

  fprintf(stderr, "probe: subscribed to %s, waiting for the remote talker\n", TOPIC);
  fflush(stderr);

  // Wait first, the way every real caller does: rcl_take_sequence is called
  // from an executor that has just returned from rcl_wait, and the rmw wait
  // path is where a subscription's readiness state is established.
  {
    rcl_wait_set_t wait_set = rcl_get_zero_initialized_wait_set();
    if (rcl_wait_set_init(&wait_set, 1, 0, 0, 0, 0, 0, &context, allocator) != RCL_RET_OK) {
      fprintf(stderr, "probe: rcl_wait_set_init failed\n");
      return 99;
    }
    for (int attempt = 0; attempt < 60; ++attempt) {
      rcl_ret_t clear_ret = rcl_wait_set_clear(&wait_set);
      rcl_ret_t add_ret = rcl_wait_set_add_subscription(&wait_set, &subscription, NULL);
      if (clear_ret != RCL_RET_OK || add_ret != RCL_RET_OK) {
        fprintf(stderr, "probe: wait set setup failed\n");
        return 99;
      }
      rcl_ret_t wait_ret = rcl_wait(&wait_set, RCL_MS_TO_NS(500));
      if (wait_ret == RCL_RET_OK && wait_set.subscriptions[0] != NULL) {
        break;
      }
      rcutils_reset_error();
    }
    rcl_ret_t ws_fini = rcl_wait_set_fini(&wait_set);
    if (ws_fini != RCL_RET_OK) {
      fprintf(stderr, "probe: rcl_wait_set_fini reported %d\n", (int)ws_fini);
    }
  }

  // Let the history fill, WITHOUT taking: rmw_take_sequence is only
  // interesting when several samples are queued at once.
  fprintf(stderr, "probe: accumulating for %us\n", ACCUMULATE_SECONDS); fflush(stderr);
  sleep(ACCUMULATE_SECONDS);

  fprintf(stderr, "probe: taking\n"); fflush(stderr);
  rmw_subscription_t * rmw_sub = rcl_subscription_get_rmw_handle(&subscription);
  if (rmw_sub == NULL) {
    fprintf(stderr, "probe: no rmw subscription handle\n");
    return 96;
  }

  rcutils_allocator_t rcutils_alloc = rcutils_get_default_allocator();
  rmw_message_sequence_t messages;
  rmw_message_info_sequence_t infos;
  if (rmw_message_sequence_init(&messages, CAPACITY, &rcutils_alloc) != RMW_RET_OK ||
    rmw_message_info_sequence_init(&infos, CAPACITY, &rcutils_alloc) != RMW_RET_OK)
  {
    fprintf(stderr, "probe: sequence init failed\n");
    return 97;
  }
  // rmw_message_sequence_init allocates the ARRAY, never the messages.
  for (size_t i = 0; i < CAPACITY; ++i) {
    messages.data[i] = std_msgs__msg__String__create();
    if (messages.data[i] == NULL) {
      fprintf(stderr, "probe: message allocation failed\n");
      return 98;
    }
  }

  char detail[256];

  // 1. Short read: ask for more than was published.
  {
    size_t taken = 99u;
    messages.size = 99u;
    infos.size = 99u;
    rmw_ret_t ret = rmw_take_sequence(rmw_sub, CAPACITY, &messages, &infos, &taken, NULL);
    // A SHORT READ: the history holds fewer than CAPACITY, so the loop must
    // break on the empty take rather than error, and both sizes must be set
    // to what was actually taken.
    int ok = (ret == RMW_RET_OK) && (taken >= MIN_EXPECTED) && (taken < CAPACITY) &&
      (messages.size == taken) && (infos.size == taken);
    snprintf(
      detail, sizeof(detail),
      "asked for %u: ret=%d taken=%zu messages.size=%zu infos.size=%zu "
      "(want ret=0, %u <= taken < %u, both sizes == taken)",
      CAPACITY, (int)ret, taken, messages.size, infos.size, MIN_EXPECTED, CAPACITY);
    report("short_read", ok, detail);

    if (ok) {
      int contents_ok = 1;
      for (size_t i = 0; i < taken; ++i) {
        const std_msgs__msg__String * m = (const std_msgs__msg__String *)messages.data[i];
        if (m->data.data == NULL || strstr(m->data.data, "Hello World") == NULL) {
          contents_ok = 0;
        }
      }
      snprintf(
        detail, sizeof(detail),
        "every one of the %zu taken messages carries its payload (%s)",
        taken, contents_ok ? "yes" : "NO");
      report("short_read_payload", contents_ok, detail);
    }
  }

  // 2. count beyond the message-sequence capacity: refused, nothing taken.
  {
    size_t taken = 99u;
    rmw_ret_t ret = rmw_take_sequence(rmw_sub, CAPACITY + 1u, &messages, &infos, &taken, NULL);
    int ok = (ret == RMW_RET_INVALID_ARGUMENT) && (taken == 0u);
    snprintf(
      detail, sizeof(detail),
      "asked for %u into a %u-message sequence: ret=%d taken=%zu (want ret=%d taken=0)",
      CAPACITY + 1u, CAPACITY, (int)ret, taken, (int)RMW_RET_INVALID_ARGUMENT);
    report("capacity_refused", ok, detail);
    rcutils_reset_error();
  }

  // 3. The SECOND capacity check: message room is fine, info room is not.
  {
    size_t taken = 99u;
    size_t saved = infos.capacity;
    infos.capacity = 1u;
    rmw_ret_t ret = rmw_take_sequence(rmw_sub, CAPACITY, &messages, &infos, &taken, NULL);
    infos.capacity = saved;
    int ok = (ret == RMW_RET_INVALID_ARGUMENT) && (taken == 0u);
    snprintf(
      detail, sizeof(detail),
      "message room %u, info room 1, asked for %u: ret=%d taken=%zu (want ret=%d taken=0)",
      CAPACITY, CAPACITY, (int)ret, taken, (int)RMW_RET_INVALID_ARGUMENT);
    report("info_capacity_refused", ok, detail);
    rcutils_reset_error();
  }

  for (size_t i = 0; i < CAPACITY; ++i) {
    std_msgs__msg__String__destroy((std_msgs__msg__String *)messages.data[i]);
  }
  rmw_message_sequence_fini(&messages);
  rmw_message_info_sequence_fini(&infos);

  // Every one of these is warn_unused_result, and a (void) cast does not
  // silence GCC; a teardown that failed is worth a line anyway.
  rcl_ret_t teardown = RCL_RET_OK;
  teardown |= rcl_subscription_fini(&subscription, &node);
  teardown |= rcl_node_fini(&node);
  teardown |= rcl_shutdown(&context);
  teardown |= rcl_context_fini(&context);
  teardown |= rcl_init_options_fini(&init_options);
  if (teardown != RCL_RET_OK) {
    fprintf(stderr, "probe: teardown reported %d (not a probe failure)\n", (int)teardown);
  }

  printf("PROBE take_sequence done: %d failure(s)\n", failures);
  return failures;
}
