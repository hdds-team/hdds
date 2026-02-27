// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com
// Fast codec bridge for rosgraph_msgs::msg::Log (C++).

#include <cstdint>
#include <cstring>
#include <string>

#include <rosgraph_msgs/msg/log.hpp>

extern "C" {
#include "rmw_hdds/ffi.h"
}

// Minimal C layouts matching crates/hdds-c/src/rmw/codec.rs expectations
extern "C" {
struct RosStringC {
  char * data;
  size_t size;
  size_t capacity;
};

struct BuiltinTimeC {
  int32_t sec;
  uint32_t nanosec;
};

struct RclLogC {
  BuiltinTimeC stamp;
  uint8_t level;
  RosStringC name;
  RosStringC msg;
  RosStringC file;
  RosStringC function;
  uint32_t line;
};
}

static inline RosStringC view_of(const std::string & s) noexcept {
  return RosStringC{const_cast<char*>(s.data()), s.size(), s.size()};
}

extern "C" rmw_hdds_error_t rmw_hdds_publish_log_fast(
  struct rmw_hdds_context_t * context,
  struct HddsDataWriter * writer,
  const void * ros_message)
{
  if (context == nullptr || writer == nullptr || ros_message == nullptr) {
    return RMW_HDDS_ERROR_INVALID_ARGUMENT;
  }

  const auto * log = static_cast<const rosgraph_msgs::msg::Log *>(ros_message);

  RclLogC c{};
  c.stamp.sec = static_cast<int32_t>(log->stamp.sec);
  c.stamp.nanosec = log->stamp.nanosec;
  c.level = log->level;
  c.name = view_of(log->name);
  c.msg = view_of(log->msg);
  c.file = view_of(log->file);
  c.function = view_of(log->function);
  c.line = log->line;

  return rmw_hdds_context_publish_with_codec(
    context,
    writer,
    static_cast<uint8_t>(RMW_HDDS_CODEC_LOG),
    &c);
}

extern "C" rmw_hdds_error_t rmw_hdds_deserialize_log_fast(
  const uint8_t * data,
  size_t data_len,
  void * ros_message)
{
  if (ros_message == nullptr) {
    return RMW_HDDS_ERROR_INVALID_ARGUMENT;
  }

  RclLogC tmp{};
  rmw_hdds_error_t status = rmw_hdds_deserialize_with_codec(
    static_cast<uint8_t>(RMW_HDDS_CODEC_LOG),
    data,
    data_len,
    &tmp);
  if (status != RMW_HDDS_ERROR_OK) {
    return status;
  }

  auto * log = static_cast<rosgraph_msgs::msg::Log *>(ros_message);
  log->stamp.sec = tmp.stamp.sec;
  log->stamp.nanosec = tmp.stamp.nanosec;
  log->level = tmp.level;
  if (tmp.name.data && tmp.name.size) log->name.assign(tmp.name.data, tmp.name.size); else log->name.clear();
  if (tmp.msg.data && tmp.msg.size) log->msg.assign(tmp.msg.data, tmp.msg.size); else log->msg.clear();
  if (tmp.file.data && tmp.file.size) log->file.assign(tmp.file.data, tmp.file.size); else log->file.clear();
  if (tmp.function.data && tmp.function.size) log->function.assign(tmp.function.data, tmp.function.size); else log->function.clear();
  log->line = tmp.line;

  // Clean up the C strings allocated under the hood during decode.
  hdds_ros_string_fini(reinterpret_cast<rosidl_runtime_c__String*>(&tmp.name));
  hdds_ros_string_fini(reinterpret_cast<rosidl_runtime_c__String*>(&tmp.msg));
  hdds_ros_string_fini(reinterpret_cast<rosidl_runtime_c__String*>(&tmp.file));
  hdds_ros_string_fini(reinterpret_cast<rosidl_runtime_c__String*>(&tmp.function));

  return RMW_HDDS_ERROR_OK;
}

