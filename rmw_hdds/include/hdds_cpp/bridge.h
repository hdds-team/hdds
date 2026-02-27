// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com
#ifndef HDDS_CPP_BRIDGE_H
#define HDDS_CPP_BRIDGE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct rmw_hdds_context_t;
struct HddsDataWriter;
struct rosidl_message_type_support_t;

// Minimal C bridge to C++ helpers (values compatible with rmw_hdds_codec_kind_t)
uint8_t hdds_cpp_select_codec_for_topic(const char *topic_name);

int hdds_cpp_publish_string(
    struct rmw_hdds_context_t *ctx,
    struct HddsDataWriter *writer,
    const void *ros_message);

int hdds_cpp_publish_with_codec(
    struct rmw_hdds_context_t *ctx,
    struct HddsDataWriter *writer,
    uint8_t codec_kind,
    const void *ros_message);

int hdds_cpp_publish_introspection(
    struct rmw_hdds_context_t *ctx,
    struct HddsDataWriter *writer,
    const struct rosidl_message_type_support_t *type_support,
    const void *ros_message);

#ifdef __cplusplus
}
#endif

#endif // HDDS_CPP_BRIDGE_H

