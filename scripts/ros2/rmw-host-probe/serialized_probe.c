// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com
//
// Drives the serialized-message and wait_for_all_acked entry points of a
// built rmw_hdds through the rmw API, with no rcl and no ROS 2 node in
// between. Mode "main" runs the checks; mode "sub" is the remote subscriber
// the acknowledgment check stops and resumes.
#include <rmw/rmw.h>
#include <rmw/error_handling.h>
#include <rmw/serialized_message.h>
#include <rmw/init.h>
#include <rmw/qos_profiles.h>
#include <rcutils/allocator.h>
#include <rosidl_runtime_c/string_functions.h>
#include <std_msgs/msg/detail/string__struct.h>
#include <std_msgs/msg/detail/string__functions.h>
#include <std_msgs/msg/detail/string__rosidl_typesupport_introspection_c.h>
#include <std_msgs/msg/detail/empty__struct.h>
#include <std_msgs/msg/detail/empty__functions.h>
#include <std_msgs/msg/detail/empty__rosidl_typesupport_introspection_c.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/wait.h>

static int failures = 0;
#define CHECK(cond, ...) do { if (!(cond)) { failures++; printf("FAIL %s:%d: ", __FILE__, __LINE__); printf(__VA_ARGS__); printf("\n"); } else { printf("ok   %s\n", #cond); } } while (0)

static void msleep(int ms) { struct timespec t = {ms / 1000, (ms % 1000) * 1000000L}; nanosleep(&t, NULL); }

typedef struct { rmw_context_t ctx; rmw_node_t * node; rmw_init_options_t opts; } env_t;

static int start(env_t * e, const char * name) {
  rcutils_allocator_t a = rcutils_get_default_allocator();
  e->opts = rmw_get_zero_initialized_init_options();
  if (rmw_init_options_init(&e->opts, a) != RMW_RET_OK) { printf("init_options: %s\n", rmw_get_error_string().str); return 1; }
  e->ctx = rmw_get_zero_initialized_context();
  if (rmw_init(&e->opts, &e->ctx) != RMW_RET_OK) { printf("rmw_init: %s\n", rmw_get_error_string().str); return 1; }
  e->node = rmw_create_node(&e->ctx, name, "/");
  if (!e->node) { printf("create_node: %s\n", rmw_get_error_string().str); return 1; }
  return 0;
}

static rmw_qos_profile_t qos(void) {
  rmw_qos_profile_t q = rmw_qos_profile_default;
  q.reliability = RMW_QOS_POLICY_RELIABILITY_RELIABLE;
  q.durability = RMW_QOS_POLICY_DURABILITY_VOLATILE;
  q.history = RMW_QOS_POLICY_HISTORY_KEEP_LAST;
  q.depth = 50;
  return q;
}

static int sub_mode(void) {
  env_t e; if (start(&e, "ack_sub")) return 2;
  const rosidl_message_type_support_t * ts = ROSIDL_TYPESUPPORT_INTERFACE__MESSAGE_SYMBOL_NAME(rosidl_typesupport_introspection_c, std_msgs, msg, String)();
  rmw_qos_profile_t q = qos();
  rmw_subscription_options_t so = rmw_get_default_subscription_options();
  rmw_subscription_t * sub = rmw_create_subscription(e.node, ts, "rt_ack_topic", &q, &so);
  if (!sub) { printf("sub: %s\n", rmw_get_error_string().str); return 2; }
  printf("SUB READY\n"); fflush(stdout);
  int got = 0;
  for (int i = 0; i < 600 && got < 1; i++) {
    std_msgs__msg__String m; std_msgs__msg__String__init(&m);
    bool taken = false;
    if (rmw_take(sub, &m, &taken, NULL) == RMW_RET_OK && taken) got++;
    std_msgs__msg__String__fini(&m);
    msleep(50);
  }
  printf("SUB GOT %d\n", got);
  return got ? 0 : 3;
}

static const uint8_t HELLO[] = {0x00,0x01,0x00,0x00, 0x06,0,0,0, 'h','e','l','l','o',0};
static const uint8_t WORLD[] = {0x00,0x01,0x00,0x00, 0x06,0,0,0, 'w','o','r','l','d',0};

static int try_take_string(rmw_subscription_t * sub, char * out, size_t cap) {
  for (int i = 0; i < 200; i++) {
    std_msgs__msg__String m; std_msgs__msg__String__init(&m);
    bool taken = false;
    rmw_ret_t r = rmw_take(sub, &m, &taken, NULL);
    if (r == RMW_RET_OK && taken) { snprintf(out, cap, "%s", m.data.data); std_msgs__msg__String__fini(&m); return 1; }
    std_msgs__msg__String__fini(&m);
    msleep(20);
  }
  return 0;
}

int main(int argc, char ** argv) {
  if (argc > 1 && strcmp(argv[1], "sub") == 0) return sub_mode();
  env_t e; if (start(&e, "main")) return 2;
  const rosidl_message_type_support_t * ts = ROSIDL_TYPESUPPORT_INTERFACE__MESSAGE_SYMBOL_NAME(rosidl_typesupport_introspection_c, std_msgs, msg, String)();
  const rosidl_message_type_support_t * ets = ROSIDL_TYPESUPPORT_INTERFACE__MESSAGE_SYMBOL_NAME(rosidl_typesupport_introspection_c, std_msgs, msg, Empty)();
  rmw_qos_profile_t q = qos();
  rmw_publisher_options_t po = rmw_get_default_publisher_options();
  rmw_subscription_options_t so = rmw_get_default_subscription_options();
  rmw_publisher_t * pub = rmw_create_publisher(e.node, ts, "rt_local_topic", &q, &po);
  rmw_subscription_t * sub = rmw_create_subscription(e.node, ts, "rt_local_topic", &q, &so);
  if (!pub || !sub) { printf("create pub/sub: %s\n", rmw_get_error_string().str); return 2; }
  for (int i = 0; i < 200; i++) { size_t n = 0; (void)!rmw_publisher_count_matched_subscriptions(pub, &n); if (n >= 1) break; msleep(50); }

  rcutils_allocator_t a = rcutils_get_default_allocator();
  char got[64];

  /* A: serialized publish (with header) -> typed take */
  rmw_serialized_message_t sm = rmw_get_zero_initialized_serialized_message();
  CHECK(rmw_serialized_message_init(&sm, sizeof(HELLO), &a) == RMW_RET_OK, "init");
  memcpy(sm.buffer, HELLO, sizeof(HELLO)); sm.buffer_length = sizeof(HELLO);
  CHECK(rmw_publish_serialized_message(pub, &sm, NULL) == RMW_RET_OK, "publish_serialized: %s", rmw_get_error_string().str);
  CHECK(try_take_string(sub, got, sizeof(got)) && strcmp(got, "hello") == 0, "serialized publish -> typed take gave '%s'", got);

  /* A2: a message without header is refused */
  sm.buffer_length = sizeof(HELLO) - 4; memmove(sm.buffer, HELLO + 4, sm.buffer_length);
  CHECK(rmw_publish_serialized_message(pub, &sm, NULL) == RMW_RET_INVALID_ARGUMENT, "headerless refused");
  rmw_reset_error();

  /* B: typed publish -> serialized take */
  std_msgs__msg__String m; std_msgs__msg__String__init(&m);
  rosidl_runtime_c__String__assign(&m.data, "world");
  CHECK(rmw_publish(pub, &m, NULL) == RMW_RET_OK, "publish");
  rmw_serialized_message_t tk = rmw_get_zero_initialized_serialized_message();
  CHECK(rmw_serialized_message_init(&tk, 1, &a) == RMW_RET_OK, "init2");
  bool taken = false;
  for (int i = 0; i < 200 && !taken; i++) { if (rmw_take_serialized_message(sub, &tk, &taken, NULL) != RMW_RET_OK) break; if (!taken) msleep(20); }
  CHECK(taken, "serialized take got a sample");
  CHECK(taken && tk.buffer_length == sizeof(WORLD) && memcmp(tk.buffer, WORLD, sizeof(WORLD)) == 0, "typed publish -> serialized take bytes (len %zu)", tk.buffer_length);

  /* C: rmw_serialize / rmw_deserialize */
  rmw_serialized_message_t ser = rmw_get_zero_initialized_serialized_message();
  CHECK(rmw_serialized_message_init(&ser, 1, &a) == RMW_RET_OK, "init3");
  CHECK(rmw_serialize(&m, ts, &ser) == RMW_RET_OK, "rmw_serialize");
  CHECK(ser.buffer_length == sizeof(WORLD) && memcmp(ser.buffer, WORLD, sizeof(WORLD)) == 0, "rmw_serialize bytes (len %zu)", ser.buffer_length);
  std_msgs__msg__String back; std_msgs__msg__String__init(&back);
  CHECK(rmw_deserialize(&ser, ts, &back) == RMW_RET_OK, "rmw_deserialize");
  CHECK(strcmp(back.data.data, "world") == 0, "deserialized '%s'", back.data.data);
  size_t sz = 0; (void)sz;

  /* D: empty message, both forms */
  std_msgs__msg__Empty em; std_msgs__msg__Empty__init(&em);
  rmw_serialized_message_t es = rmw_get_zero_initialized_serialized_message();
  CHECK(rmw_serialized_message_init(&es, 1, &a) == RMW_RET_OK, "init4");
  CHECK(rmw_serialize(&em, ets, &es) == RMW_RET_OK, "serialize Empty");
  static const uint8_t EMPTY5[] = {0x00,0x01,0x00,0x00,0x00};
  CHECK(es.buffer_length == 5 && memcmp(es.buffer, EMPTY5, 5) == 0, "Empty serializes to header + 1 byte (len %zu)", es.buffer_length);
  CHECK(rmw_deserialize(&es, ets, &em) == RMW_RET_OK, "deserialize header+1");
  es.buffer_length = 4;
  CHECK(rmw_deserialize(&es, ets, &em) == RMW_RET_OK, "deserialize header only");
  es.buffer_length = 5;
  rmw_publisher_t * epub = rmw_create_publisher(e.node, ets, "rt_empty_topic", &q, &po);
  rmw_subscription_t * esub = rmw_create_subscription(e.node, ets, "rt_empty_topic", &q, &so);
  CHECK(epub && esub, "empty pub/sub");
  for (int i = 0; i < 200; i++) { size_t n = 0; (void)!rmw_publisher_count_matched_subscriptions(epub, &n); if (n >= 1) break; msleep(50); }
  CHECK(rmw_publish_serialized_message(epub, &es, NULL) == RMW_RET_OK, "publish Empty header+1");
  es.buffer_length = 4;
  CHECK(rmw_publish_serialized_message(epub, &es, NULL) == RMW_RET_OK, "publish Empty header only");
  rmw_serialized_message_t et = rmw_get_zero_initialized_serialized_message();
  CHECK(rmw_serialized_message_init(&et, 1, &a) == RMW_RET_OK, "init5");
  int seen = 0;
  for (int i = 0; i < 200 && seen < 2; i++) {
    bool t = false;
    if (rmw_take_serialized_message(esub, &et, &t, NULL) != RMW_RET_OK) break;
    if (t) { seen++; printf("     empty take %d: len %zu\n", seen, et.buffer_length);
      CHECK(et.buffer_length == 5 && memcmp(et.buffer, EMPTY5, 5) == 0, "Empty taken as header + 1 byte"); }
    else msleep(20);
  }
  CHECK(seen == 2, "both Empty publishes taken (%d)", seen);

  /* E: wait_for_all_acked, local reader */
  rmw_time_t one_s = {1, 0};
  CHECK(rmw_publisher_wait_for_all_acked(pub, one_s) == RMW_RET_OK, "wait_for_all_acked local reliable reader");
  CHECK(rmw_publisher_wait_for_all_acked(NULL, one_s) == RMW_RET_INVALID_ARGUMENT, "NULL publisher");
  rmw_reset_error();

  /* F: remote reader that is stopped -> TIMEOUT, then OK once it runs */
  rmw_publisher_t * apub = rmw_create_publisher(e.node, ts, "rt_ack_topic", &q, &po);
  CHECK(apub != NULL, "ack pub");
  pid_t child = fork();
  if (child == 0) { execl(argv[0], argv[0], "sub", (char *)NULL); _exit(99); }
  size_t n = 0;
  for (int i = 0; i < 400; i++) { (void)!rmw_publisher_count_matched_subscriptions(apub, &n); if (n >= 1) break; msleep(50); }
  CHECK(n >= 1, "remote subscriber matched (%zu)", n);
  msleep(500);
  kill(child, SIGSTOP);
  msleep(200);
  CHECK(rmw_publish(apub, &m, NULL) == RMW_RET_OK, "publish to stopped remote");
  rmw_time_t t200 = {0, 200000000};
  struct timespec t0, t1; clock_gettime(CLOCK_MONOTONIC, &t0);
  rmw_ret_t r = rmw_publisher_wait_for_all_acked(apub, t200);
  clock_gettime(CLOCK_MONOTONIC, &t1);
  double ms = (t1.tv_sec - t0.tv_sec) * 1e3 + (t1.tv_nsec - t0.tv_nsec) / 1e6;
  CHECK(r == RMW_RET_TIMEOUT, "stopped reader -> RMW_RET_TIMEOUT (got %d after %.0f ms)", (int)r, ms);
  CHECK(ms >= 190.0 && ms < 2000.0, "timeout lasted %.0f ms", ms);
  kill(child, SIGCONT);
  rmw_time_t t10 = {10, 0};
  CHECK(rmw_publisher_wait_for_all_acked(apub, t10) == RMW_RET_OK, "resumed reader acknowledges");
  int status = 0; waitpid(child, &status, 0);
  CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0, "subscriber took the sample (status %d)", status);

  printf("%s: %d failure(s)\n", failures ? "FAILED" : "PASSED", failures);
  fflush(stdout);
  _exit(failures ? 1 : 0);
}
