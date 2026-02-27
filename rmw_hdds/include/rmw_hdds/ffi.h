#ifndef RMW_HDDS__FFI_H_
#define RMW_HDDS__FFI_H_
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "hdds.h"  // NOLINT(build/include_subdir)
#include "rmw_hdds/types.h"

#ifdef __cplusplus
extern "C" {
#endif

rmw_hdds_error_t rmw_hdds_context_create(
    const char* name,
    struct rmw_hdds_context_t** out_context);

void rmw_hdds_context_destroy(struct rmw_hdds_context_t* context);

rmw_hdds_error_t rmw_hdds_context_graph_guard_key(
    struct rmw_hdds_context_t* context,
    uint64_t* out_key);

rmw_hdds_error_t rmw_hdds_context_guid_prefix(
    struct rmw_hdds_context_t* context,
    uint8_t* out_prefix);

rmw_hdds_error_t rmw_hdds_context_set_guard(
    struct rmw_hdds_context_t* context,
    bool active);

rmw_hdds_error_t rmw_hdds_context_graph_guard_condition(
    struct rmw_hdds_context_t* context,
    const struct HddsGuardCondition** out_guard);

rmw_hdds_error_t rmw_hdds_context_wait_readers(
    struct rmw_hdds_context_t* context,
    int64_t timeout_ns,
    struct HddsDataReader** out_readers,
    size_t max_readers,
    size_t* out_len,
    bool* out_guard_triggered);

rmw_hdds_error_t rmw_hdds_context_create_reader(
    struct rmw_hdds_context_t* context,
    const char* topic_name,
    struct HddsDataReader** out_reader);

rmw_hdds_error_t rmw_hdds_context_create_reader_with_qos(
    struct rmw_hdds_context_t* context,
    const char* topic_name,
    const struct HddsQoS* qos,
    struct HddsDataReader** out_reader);

rmw_hdds_error_t rmw_hdds_context_destroy_reader(
    struct rmw_hdds_context_t* context,
    struct HddsDataReader* reader);

rmw_hdds_error_t rmw_hdds_context_attach_reader(
    struct rmw_hdds_context_t* context,
    struct HddsDataReader* reader,
    uint64_t* out_key);

rmw_hdds_error_t rmw_hdds_context_detach_reader(
    struct rmw_hdds_context_t* context,
    struct HddsDataReader* reader);

rmw_hdds_error_t rmw_hdds_context_create_writer(
    struct rmw_hdds_context_t* context,
    const char* topic_name,
    struct HddsDataWriter** out_writer);

rmw_hdds_error_t rmw_hdds_context_create_writer_with_qos(
    struct rmw_hdds_context_t* context,
    const char* topic_name,
    const struct HddsQoS* qos,
    struct HddsDataWriter** out_writer);

rmw_hdds_error_t rmw_hdds_context_destroy_writer(
    struct rmw_hdds_context_t* context,
    struct HddsDataWriter* writer);

typedef void (*rmw_hdds_topic_visitor_t)(
  const char* topic_name,
  const char* type_name,
  uint32_t writer_count,
  uint32_t reader_count,
  void* user_data);

typedef void (*rmw_hdds_node_visitor_t)(
    const char* node_name,
    const char* node_namespace,
    void* user_data);

typedef void (*rmw_hdds_node_enclave_visitor_t)(
    const char* node_name,
    const char* node_namespace,
    const char* node_enclave,
    void* user_data);

typedef void (*rmw_hdds_endpoint_visitor_t)(
    const char* topic_name,
    const char* type_name,
    const uint8_t* endpoint_gid,
    const rmw_hdds_qos_profile_t* qos_profile,
    void* user_data);

typedef void (*rmw_hdds_locator_visitor_t)(
    const char* address,
    uint16_t port,
    void* user_data);

rmw_hdds_error_t rmw_hdds_context_for_each_topic(
    struct rmw_hdds_context_t* context,
    rmw_hdds_topic_visitor_t visitor,
    void* user_data,
    uint64_t* out_version);

rmw_hdds_error_t rmw_hdds_context_for_each_user_locator(
    struct rmw_hdds_context_t* context,
    rmw_hdds_locator_visitor_t visitor,
    void* user_data,
    size_t* out_count);

rmw_hdds_error_t rmw_hdds_context_bind_topic_type(
    struct rmw_hdds_context_t* context,
    const char* topic_name,
    const rosidl_message_type_support_t* type_support);

rmw_hdds_error_t rmw_hdds_context_register_node(
    struct rmw_hdds_context_t* context,
    const char* node_name,
    const char* node_namespace,
    const char* node_enclave);

rmw_hdds_error_t rmw_hdds_context_unregister_node(
    struct rmw_hdds_context_t* context,
    const char* node_name,
    const char* node_namespace);

rmw_hdds_error_t rmw_hdds_context_register_publisher_endpoint(
    struct rmw_hdds_context_t* context,
    const char* node_name,
    const char* node_namespace,
    const char* topic_name,
    const rosidl_message_type_support_t* type_support,
    const uint8_t* endpoint_gid,
    const rmw_hdds_qos_profile_t* qos_profile);

rmw_hdds_error_t rmw_hdds_context_unregister_publisher_endpoint(
    struct rmw_hdds_context_t* context,
    const char* node_name,
    const char* node_namespace,
    const char* topic_name,
    const uint8_t* endpoint_gid);

rmw_hdds_error_t rmw_hdds_context_register_subscription_endpoint(
    struct rmw_hdds_context_t* context,
    const char* node_name,
    const char* node_namespace,
    const char* topic_name,
    const rosidl_message_type_support_t* type_support,
    const uint8_t* endpoint_gid,
    const rmw_hdds_qos_profile_t* qos_profile);

rmw_hdds_error_t rmw_hdds_context_unregister_subscription_endpoint(
    struct rmw_hdds_context_t* context,
    const char* node_name,
    const char* node_namespace,
    const char* topic_name,
    const uint8_t* endpoint_gid);

rmw_hdds_error_t rmw_hdds_context_for_each_node(
    struct rmw_hdds_context_t* context,
    rmw_hdds_node_visitor_t visitor,
    void* user_data,
    uint64_t* out_version,
    size_t* out_count);

rmw_hdds_error_t rmw_hdds_context_for_each_node_with_enclave(
    struct rmw_hdds_context_t* context,
    rmw_hdds_node_enclave_visitor_t visitor,
    void* user_data,
    uint64_t* out_version,
    size_t* out_count);

rmw_hdds_error_t rmw_hdds_context_for_each_publisher_endpoint(
    struct rmw_hdds_context_t* context,
    const char* node_name,
    const char* node_namespace,
    rmw_hdds_endpoint_visitor_t visitor,
    void* user_data,
    uint64_t* out_version,
    size_t* out_count);

rmw_hdds_error_t rmw_hdds_context_for_each_subscription_endpoint(
    struct rmw_hdds_context_t* context,
    const char* node_name,
    const char* node_namespace,
    rmw_hdds_endpoint_visitor_t visitor,
    void* user_data,
    uint64_t* out_version,
    size_t* out_count);

rmw_hdds_error_t rmw_hdds_context_publish(
    struct rmw_hdds_context_t* context,
    struct HddsDataWriter* writer,
    const rosidl_message_type_support_t* type_support,
    const void* ros_message);

rmw_hdds_error_t rmw_hdds_context_publish_with_codec(
    struct rmw_hdds_context_t* context,
    struct HddsDataWriter* writer,
    uint8_t codec_kind,
    const void* ros_message);

// C++ bridge for fast codec of rcl_interfaces::msg::ParameterEvent
rmw_hdds_error_t rmw_hdds_publish_parameter_event_fast(
    struct rmw_hdds_context_t* context,
    struct HddsDataWriter* writer,
    const void* ros_message);

rmw_hdds_error_t rmw_hdds_publish_string_fast(
    struct rmw_hdds_context_t* context,
    struct HddsDataWriter* writer,
    const void* ros_message);

// Fast codec for rosgraph_msgs::msg::Log (C++ bridge)
rmw_hdds_error_t rmw_hdds_publish_log_fast(
    struct rmw_hdds_context_t* context,
    struct HddsDataWriter* writer,
    const void* ros_message);

rmw_hdds_error_t rmw_hdds_deserialize_with_codec(
    uint8_t codec_kind,
    const uint8_t* data,
    size_t data_len,
    void* ros_message);

// Fast decode into std::string for std_msgs/String (C++).
rmw_hdds_error_t rmw_hdds_deserialize_string_fast(
    const uint8_t* data,
    size_t data_len,
    void* ros_message);

// Fast decode into rcl_interfaces::msg::ParameterEvent (C++).
rmw_hdds_error_t rmw_hdds_deserialize_parameter_event_fast(
    const uint8_t* data,
    size_t data_len,
    void* ros_message);

rmw_hdds_error_t rmw_hdds_deserialize_log_fast(
    const uint8_t* data,
    size_t data_len,
    void* ros_message);

// ============================================
// Dynamic type support for generic subscriptions
// ============================================
// NOTE: hdds_rmw_has_type_descriptor() and hdds_rmw_deserialize_dynamic()
// are declared in hdds.h (cbindgen-generated) - do not redeclare here.
// Use HddsError return type from hdds.h, not rmw_hdds_error_t.

rmw_hdds_error_t rmw_hdds_context_wait_subscriptions(
    struct rmw_hdds_context_t* context,
    int64_t timeout_ns,
    struct HddsDataReader* const* subscriptions,
    size_t subscriptions_len,
    size_t* out_indices,
    size_t max_indices,
    size_t* out_len,
    bool* out_guard_triggered);

rmw_hdds_error_t rmw_hdds_waitset_create(
    struct rmw_hdds_context_t* context,
    struct rmw_hdds_waitset_t** out_waitset);

void rmw_hdds_waitset_destroy(struct rmw_hdds_waitset_t* waitset);

rmw_hdds_error_t rmw_hdds_waitset_attach_reader(
    struct rmw_hdds_waitset_t* waitset,
    struct HddsDataReader* reader);

rmw_hdds_error_t rmw_hdds_waitset_detach_reader(
    struct rmw_hdds_waitset_t* waitset,
    struct HddsDataReader* reader);

rmw_hdds_error_t rmw_hdds_waitset_wait(
    struct rmw_hdds_waitset_t* waitset,
    int64_t timeout_ns,
    struct HddsDataReader** out_readers,
    size_t max_readers,
    size_t* out_len,
    bool* out_guard_triggered);

rmw_hdds_error_t rmw_hdds_waitset_wait_indices(
    struct rmw_hdds_waitset_t* waitset,
    struct HddsDataReader* const* subscriptions,
    size_t subscriptions_len,
    size_t* out_indices,
    size_t max_indices,
    size_t* out_len,
    int64_t timeout_ns,
    bool* out_guard_triggered);

void rmw_hdds_guard_condition_release(const struct HddsGuardCondition* guard);

rmw_hdds_error_t rmw_hdds_wait(
    struct rmw_hdds_waitset_t* waitset,
    int64_t timeout_ns,
    struct HddsDataReader* const* subscriptions,
    size_t subscriptions_len,
    size_t* out_indices,
    size_t max_indices,
    size_t* out_len,
    bool* out_guard_triggered);

// Fallback queue helpers for smoke: enqueue/dequeue std_msgs/String payloads when
// transport backpressure prevents immediate delivery. Implemented in C++ bridge.
// Topic name should be the ROS topic (e.g., "/chatter").
rmw_hdds_error_t rmw_hdds_fallback_enqueue_string_fast(
    const char* topic_name,
    const void* ros_message);

rmw_hdds_error_t rmw_hdds_fallback_try_dequeue_string_fast(
    const char* topic_name,
    void* ros_message_out,
    bool* out_taken);

rmw_hdds_error_t rmw_hdds_fallback_has_string_fast(
    const char* topic_name,
    bool* out_has);

#ifdef __cplusplus
}
#endif

#endif  // RMW_HDDS__FFI_H_
