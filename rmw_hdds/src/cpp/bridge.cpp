// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com
#include "hdds_cpp/codecs.hpp"
#include "rmw_hdds/ffi.h"

extern "C" uint8_t hdds_cpp_select_codec_for_topic(const char *topic_name) {
  using hdds_cpp::CodecKind;
  CodecKind k = hdds_cpp::select_codec_for_topic(topic_name);
  switch (k) {
    case CodecKind::String: return 1u;
    case CodecKind::Log: return 2u;
    case CodecKind::ParameterEvent: return 3u;
    default: return 0u;
  }
}

extern "C" int hdds_cpp_publish_string(
    struct rmw_hdds_context_t *ctx,
    struct HddsDataWriter *writer,
    const void *ros_message) {
  return (int)rmw_hdds_publish_string_fast(ctx, writer, ros_message);
}

extern "C" int hdds_cpp_publish_with_codec(
    struct rmw_hdds_context_t *ctx,
    struct HddsDataWriter *writer,
    uint8_t codec_kind,
    const void *ros_message) {
  return (int)rmw_hdds_context_publish_with_codec(ctx, writer, codec_kind, ros_message);
}

extern "C" int hdds_cpp_publish_introspection(
    struct rmw_hdds_context_t *ctx,
    struct HddsDataWriter *writer,
    const struct rosidl_message_type_support_t *type_support,
    const void *ros_message) {
  return (int)rmw_hdds_context_publish(ctx, writer, type_support, ros_message);
}

