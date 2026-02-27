// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com
// Bridge to encode selected C++ ROS 2 messages via HDDS fast codecs.

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

#if defined(__has_include)
#  if __has_include(<rcl_interfaces/msg/parameter_event.hpp>)
#    define HDDS_HAVE_RCL_INTERFACES_CPP 1
#    include <rcl_interfaces/msg/parameter_event.hpp>
#  else
#    define HDDS_HAVE_RCL_INTERFACES_CPP 0
#  endif
#else
#  define HDDS_HAVE_RCL_INTERFACES_CPP 0
#endif

extern "C" {
#include "rmw_hdds/ffi.h"
#include "hdds.h"  // For hdds_rmw_deserialize_with_codec

// Bridge: rmw_hdds_deserialize_with_codec -> hdds_rmw_deserialize_with_codec
// Maps between rmw_hdds_error_t and HddsError
rmw_hdds_error_t rmw_hdds_deserialize_with_codec(
    uint8_t codec_kind,
    const uint8_t* data,
    size_t data_len,
    void* ros_message)
{
    HddsError err = hdds_rmw_deserialize_with_codec(codec_kind, data, data_len, ros_message);
    // Map HddsError to rmw_hdds_error_t (both have OK=0, so direct cast works for success)
    switch (err) {
        case OK: return RMW_HDDS_ERROR_OK;
        case INVALID_ARGUMENT: return RMW_HDDS_ERROR_INVALID_ARGUMENT;
        case NOT_FOUND: return RMW_HDDS_ERROR_NOT_FOUND;
        case OPERATION_FAILED: return RMW_HDDS_ERROR_OPERATION_FAILED;
        case OUT_OF_MEMORY: return RMW_HDDS_ERROR_OUT_OF_MEMORY;
        default: return RMW_HDDS_ERROR_OPERATION_FAILED;
    }
}
}

// Mirror of the minimal C layout expected by crates/hdds-c/src/rmw/codec.rs
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

struct RosStringSequenceC {
  RosStringC * data;
  size_t size;
  size_t capacity;
};

struct RosOctetSequenceC {
  uint8_t * data;
  size_t size;
  size_t capacity;
};

struct RosBoolSequenceC {
  bool * data;
  size_t size;
  size_t capacity;
};

struct RosInt64SequenceC {
  int64_t * data;
  size_t size;
  size_t capacity;
};

struct RosDoubleSequenceC {
  double * data;
  size_t size;
  size_t capacity;
};

struct ParameterValueC {
  uint8_t type_;
  bool bool_value;
  int64_t integer_value;
  double double_value;
  RosStringC string_value;
  RosOctetSequenceC byte_array_value;
  RosBoolSequenceC bool_array_value;
  RosInt64SequenceC integer_array_value;
  RosDoubleSequenceC double_array_value;
  RosStringSequenceC string_array_value;
};

struct ParameterC {
  RosStringC name;
  ParameterValueC value;
};

struct ParameterSequenceC {
  ParameterC * data;
  size_t size;
  size_t capacity;
};

struct ParameterEventC {
  BuiltinTimeC stamp;
  RosStringC node;
  ParameterSequenceC new_parameters;
  ParameterSequenceC changed_parameters;
  ParameterSequenceC deleted_parameters;
};

bool rcl_interfaces__msg__ParameterEvent__init(ParameterEventC * msg);
void rcl_interfaces__msg__ParameterEvent__fini(ParameterEventC * msg);
}

namespace {
struct ParameterEventStorage {
  std::vector<ParameterC> new_params;
  std::vector<ParameterC> changed_params;
  std::vector<ParameterC> deleted_params;
  std::vector<std::unique_ptr<bool[]>> bool_arrays;
  std::vector<std::vector<RosStringC>> string_arrays;
};

static RosStringC make_ros_string(const std::string & value) {
  RosStringC out{};
  if (!value.empty()) {
    out.data = const_cast<char *>(value.data());
    out.size = value.size();
    out.capacity = value.size();
  }
  return out;
}

static RosOctetSequenceC make_octet_sequence(const std::vector<uint8_t> & values) {
  RosOctetSequenceC out{};
  if (!values.empty()) {
    out.data = const_cast<uint8_t *>(values.data());
    out.size = values.size();
    out.capacity = values.size();
  }
  return out;
}

static RosInt64SequenceC make_int64_sequence(const std::vector<int64_t> & values) {
  RosInt64SequenceC out{};
  if (!values.empty()) {
    out.data = const_cast<int64_t *>(values.data());
    out.size = values.size();
    out.capacity = values.size();
  }
  return out;
}

static RosDoubleSequenceC make_double_sequence(const std::vector<double> & values) {
  RosDoubleSequenceC out{};
  if (!values.empty()) {
    out.data = const_cast<double *>(values.data());
    out.size = values.size();
    out.capacity = values.size();
  }
  return out;
}

static RosBoolSequenceC make_bool_sequence(
  const std::vector<bool> & values,
  ParameterEventStorage * storage)
{
  RosBoolSequenceC out{};
  if (values.empty()) {
    return out;
  }

  auto buffer = std::make_unique<bool[]>(values.size());
  for (size_t i = 0; i < values.size(); ++i) {
    buffer[i] = values[i];
  }
  out.data = buffer.get();
  out.size = values.size();
  out.capacity = values.size();
  storage->bool_arrays.push_back(std::move(buffer));
  return out;
}

static RosStringSequenceC make_string_sequence(
  const std::vector<std::string> & values,
  ParameterEventStorage * storage)
{
  RosStringSequenceC out{};
  if (values.empty()) {
    return out;
  }

  storage->string_arrays.emplace_back();
  auto & slot = storage->string_arrays.back();
  slot.reserve(values.size());
  for (const auto & value : values) {
    slot.push_back(make_ros_string(value));
  }
  out.data = slot.data();
  out.size = slot.size();
  out.capacity = slot.size();
  return out;
}

static std::string to_cpp_string(const RosStringC & src) {
  if (src.data == nullptr || src.size == 0) {
    return std::string();
  }
  return std::string(src.data, src.size);
}

#if HDDS_HAVE_RCL_INTERFACES_CPP
static void fill_parameter_value(
  const rcl_interfaces::msg::ParameterValue & src,
  ParameterValueC * dst,
  ParameterEventStorage * storage)
{
  dst->type_ = src.type;
  dst->bool_value = src.bool_value;
  dst->integer_value = src.integer_value;
  dst->double_value = src.double_value;
  dst->string_value = make_ros_string(src.string_value);
  dst->byte_array_value = make_octet_sequence(src.byte_array_value);
  dst->bool_array_value = make_bool_sequence(src.bool_array_value, storage);
  dst->integer_array_value = make_int64_sequence(src.integer_array_value);
  dst->double_array_value = make_double_sequence(src.double_array_value);
  dst->string_array_value = make_string_sequence(src.string_array_value, storage);
}

static void fill_parameter_sequence(
  const std::vector<rcl_interfaces::msg::Parameter> & src,
  std::vector<ParameterC> * dst,
  ParameterSequenceC * seq,
  ParameterEventStorage * storage)
{
  dst->clear();
  if (!src.empty()) {
    dst->reserve(src.size());
    for (const auto & param : src) {
      ParameterC out{};
      out.name = make_ros_string(param.name);
      fill_parameter_value(param.value, &out.value, storage);
      dst->push_back(out);
    }
    seq->data = dst->data();
    seq->size = dst->size();
    seq->capacity = dst->size();
  } else {
    seq->data = nullptr;
    seq->size = 0;
    seq->capacity = 0;
  }
}

static void convert_parameter_value(
  const ParameterValueC & src,
  rcl_interfaces::msg::ParameterValue * dst)
{
  dst->type = src.type_;
  dst->bool_value = src.bool_value;
  dst->integer_value = src.integer_value;
  dst->double_value = src.double_value;
  dst->string_value = to_cpp_string(src.string_value);

  dst->byte_array_value.clear();
  if (src.byte_array_value.data != nullptr && src.byte_array_value.size > 0) {
    dst->byte_array_value.assign(
      src.byte_array_value.data,
      src.byte_array_value.data + src.byte_array_value.size);
  }

  dst->bool_array_value.clear();
  if (src.bool_array_value.data != nullptr && src.bool_array_value.size > 0) {
    dst->bool_array_value.reserve(src.bool_array_value.size);
    for (size_t i = 0; i < src.bool_array_value.size; ++i) {
      dst->bool_array_value.push_back(src.bool_array_value.data[i]);
    }
  }

  dst->integer_array_value.clear();
  if (src.integer_array_value.data != nullptr && src.integer_array_value.size > 0) {
    dst->integer_array_value.assign(
      src.integer_array_value.data,
      src.integer_array_value.data + src.integer_array_value.size);
  }

  dst->double_array_value.clear();
  if (src.double_array_value.data != nullptr && src.double_array_value.size > 0) {
    dst->double_array_value.assign(
      src.double_array_value.data,
      src.double_array_value.data + src.double_array_value.size);
  }

  dst->string_array_value.clear();
  if (src.string_array_value.data != nullptr && src.string_array_value.size > 0) {
    dst->string_array_value.reserve(src.string_array_value.size);
    for (size_t i = 0; i < src.string_array_value.size; ++i) {
      dst->string_array_value.push_back(to_cpp_string(src.string_array_value.data[i]));
    }
  }
}

static void convert_parameter_sequence(
  const ParameterSequenceC & src,
  std::vector<rcl_interfaces::msg::Parameter> * dst)
{
  dst->clear();
  if (src.data == nullptr || src.size == 0) {
    return;
  }

  dst->reserve(src.size);
  for (size_t i = 0; i < src.size; ++i) {
    const ParameterC & param = src.data[i];
    rcl_interfaces::msg::Parameter out;
    out.name = to_cpp_string(param.name);
    convert_parameter_value(param.value, &out.value);
    dst->push_back(std::move(out));
  }
}
#endif
}  // namespace

extern "C" rmw_hdds_error_t rmw_hdds_publish_parameter_event_fast(
  struct rmw_hdds_context_t * context,
  struct HddsDataWriter * writer,
  const void * ros_message)
{
  if (context == nullptr || writer == nullptr || ros_message == nullptr) {
    return RMW_HDDS_ERROR_INVALID_ARGUMENT;
  }

#if HDDS_HAVE_RCL_INTERFACES_CPP
  const auto * event =
    reinterpret_cast<const rcl_interfaces::msg::ParameterEvent *>(ros_message);
  ParameterEventStorage storage;
  ParameterEventC c{};
  c.stamp.sec = event->stamp.sec;
  c.stamp.nanosec = event->stamp.nanosec;
  c.node = make_ros_string(event->node);

  fill_parameter_sequence(
    event->new_parameters,
    &storage.new_params,
    &c.new_parameters,
    &storage);
  fill_parameter_sequence(
    event->changed_parameters,
    &storage.changed_params,
    &c.changed_parameters,
    &storage);
  fill_parameter_sequence(
    event->deleted_parameters,
    &storage.deleted_params,
    &c.deleted_parameters,
    &storage);

  return rmw_hdds_context_publish_with_codec(
    context,
    writer,
    static_cast<uint8_t>(RMW_HDDS_CODEC_PARAMETER_EVENT),
    &c);
#else
  (void)ros_message;
  ParameterEventC c{};
  c.stamp.sec = 0;
  c.stamp.nanosec = 0;
  c.node.data = nullptr;
  c.node.size = 0;
  c.node.capacity = 0;
  c.new_parameters = ParameterSequenceC{nullptr, 0, 0};
  c.changed_parameters = ParameterSequenceC{nullptr, 0, 0};
  c.deleted_parameters = ParameterSequenceC{nullptr, 0, 0};
  return rmw_hdds_context_publish_with_codec(
    context,
    writer,
    static_cast<uint8_t>(RMW_HDDS_CODEC_PARAMETER_EVENT),
    &c);
#endif
}

extern "C" rmw_hdds_error_t rmw_hdds_deserialize_parameter_event_fast(
  const uint8_t * data,
  size_t data_len,
  void * ros_message)
{
  if (ros_message == nullptr) {
    return RMW_HDDS_ERROR_INVALID_ARGUMENT;
  }

#if HDDS_HAVE_RCL_INTERFACES_CPP
  ParameterEventC decoded{};
  if (!rcl_interfaces__msg__ParameterEvent__init(&decoded)) {
    return RMW_HDDS_ERROR_OUT_OF_MEMORY;
  }

  rmw_hdds_error_t status = rmw_hdds_deserialize_with_codec(
    static_cast<uint8_t>(RMW_HDDS_CODEC_PARAMETER_EVENT),
    data,
    data_len,
    &decoded);
  if (status != RMW_HDDS_ERROR_OK) {
    rcl_interfaces__msg__ParameterEvent__fini(&decoded);
    return status;
  }

  auto * out =
    reinterpret_cast<rcl_interfaces::msg::ParameterEvent *>(ros_message);
  out->stamp.sec = decoded.stamp.sec;
  out->stamp.nanosec = decoded.stamp.nanosec;
  out->node = to_cpp_string(decoded.node);
  convert_parameter_sequence(decoded.new_parameters, &out->new_parameters);
  convert_parameter_sequence(decoded.changed_parameters, &out->changed_parameters);
  convert_parameter_sequence(decoded.deleted_parameters, &out->deleted_parameters);

  rcl_interfaces__msg__ParameterEvent__fini(&decoded);
  return RMW_HDDS_ERROR_OK;
#else
  (void)data;
  (void)data_len;
  (void)ros_message;
  return RMW_HDDS_ERROR_OK;
#endif
}

// Fast codec for std_msgs::msg::String without including the message header.
// Relies on the fact that the first data member is `std::string data;` at offset 0.
extern "C" rmw_hdds_error_t rmw_hdds_publish_string_fast(
  struct rmw_hdds_context_t * context,
  struct HddsDataWriter * writer,
  const void * ros_message)
{
  if (context == nullptr || writer == nullptr || ros_message == nullptr) {
    return RMW_HDDS_ERROR_INVALID_ARGUMENT;
  }

  const auto * s = reinterpret_cast<const std::string *>(ros_message);
  RosStringC cstr{
    const_cast<char *>(s->data()),
    s->size(),
    s->size(),
  };

  struct StdMsgsStringC {
    RosStringC data;
  } msg{cstr};

  return rmw_hdds_context_publish_with_codec(
    context,
    writer,
    static_cast<uint8_t>(RMW_HDDS_CODEC_STRING),
    &msg);
}

extern "C" rmw_hdds_error_t rmw_hdds_deserialize_string_fast(
  const uint8_t * data,
  size_t data_len,
  void * ros_message)
{
  if (ros_message == nullptr) {
    return RMW_HDDS_ERROR_INVALID_ARGUMENT;
  }

  // Reuse the C fast codec by decoding into a temporary C layout and then
  // transferring into std::string.
  struct StdMsgsStringC { RosStringC data; } tmp{};
  rmw_hdds_error_t status = rmw_hdds_deserialize_with_codec(
    static_cast<uint8_t>(RMW_HDDS_CODEC_STRING),
    data,
    data_len,
    &tmp);
  if (status != RMW_HDDS_ERROR_OK) {
    return status;
  }

  auto * s = reinterpret_cast<std::string *>(ros_message);
  if (tmp.data.data != nullptr && tmp.data.size > 0) {
    s->assign(tmp.data.data, tmp.data.size);
  } else {
    s->clear();
  }

  // Cleanup temporary C string - just free if allocated
  if (tmp.data.data != nullptr) {
    free(tmp.data.data);
    tmp.data.data = nullptr;
  }
  return RMW_HDDS_ERROR_OK;
}

// ----------------------------------------------------------------------------
// Fallback queue for std_msgs::msg::String (smoke test aid)
// ----------------------------------------------------------------------------

#include <deque>
#include <mutex>
#include <string>
#include <unordered_map>
#include <rcutils/logging_macros.h>

namespace {
struct FallbackBus {
  std::mutex mtx;
  std::unordered_map<std::string, std::deque<std::string>> queues;
} g_fallback_bus;

static inline std::string normalize_topic_cpp(const char *topic) {
  if (topic == nullptr) { return std::string(); }
  if (topic[0] == '/' && topic[1] != '\0') { return std::string(topic + 1); }
  return std::string(topic);
}

}  // namespace

extern "C" rmw_hdds_error_t rmw_hdds_fallback_enqueue_string_fast(
  const char * topic_name,
  const void * ros_message)
{
  if (topic_name == nullptr || ros_message == nullptr) {
    return RMW_HDDS_ERROR_INVALID_ARGUMENT;
  }
  const auto * s = reinterpret_cast<const std::string *>(ros_message);
  const std::string key = normalize_topic_cpp(topic_name);
  // Enqueue for in-process consumers (temporary fallback, will be removed with hdds_cpp)
  std::lock_guard<std::mutex> lock(g_fallback_bus.mtx);
  g_fallback_bus.queues[key].emplace_back(*s);
  RCUTILS_LOG_INFO_NAMED("rmw_hdds", "fallback enqueue string topic '%s' size=%zu", key.c_str(), s->size());
  return RMW_HDDS_ERROR_OK;
}

extern "C" rmw_hdds_error_t rmw_hdds_fallback_try_dequeue_string_fast(
  const char * topic_name,
  void * ros_message_out,
  bool * out_taken)
{
  if (out_taken) { *out_taken = false; }
  if (topic_name == nullptr || ros_message_out == nullptr) {
    return RMW_HDDS_ERROR_INVALID_ARGUMENT;
  }
  const std::string key = normalize_topic_cpp(topic_name);
  std::string value;
  {
    std::lock_guard<std::mutex> lock(g_fallback_bus.mtx);
    auto it = g_fallback_bus.queues.find(key);
    if (it != g_fallback_bus.queues.end() && !it->second.empty()) {
      value = std::move(it->second.front());
      it->second.pop_front();
    }
  }
  if (value.empty()) {
    return RMW_HDDS_ERROR_NOT_FOUND;
  }
  auto * dst = reinterpret_cast<std::string *>(ros_message_out);
  *dst = std::move(value);
  RCUTILS_LOG_INFO_NAMED("rmw_hdds", "fallback dequeue string topic '%s'", key.c_str());
  if (out_taken) { *out_taken = true; }
  return RMW_HDDS_ERROR_OK;
}

extern "C" rmw_hdds_error_t rmw_hdds_fallback_has_string_fast(
  const char * topic_name,
  bool * out_has)
{
  if (out_has) { *out_has = false; }
  if (topic_name == nullptr) {
    return RMW_HDDS_ERROR_INVALID_ARGUMENT;
  }
  const std::string key = normalize_topic_cpp(topic_name);
  bool has = false;
  {
    std::lock_guard<std::mutex> lock(g_fallback_bus.mtx);
    auto it = g_fallback_bus.queues.find(key);
    has = (it != g_fallback_bus.queues.end() && !it->second.empty());
  }
  RCUTILS_LOG_INFO_NAMED("rmw_hdds", "fallback has string topic '%s': %s", key.c_str(), has?"yes":"no");
  if (out_has) { *out_has = has; }
  return RMW_HDDS_ERROR_OK;
}
