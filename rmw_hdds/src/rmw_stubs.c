// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

#include <rmw/rmw.h>
#include <rmw/error_handling.h>
#include <rmw/get_network_flow_endpoints.h>
#include <rmw/network_flow_endpoint.h>
#include <rmw/get_service_names_and_types.h>
#include <rmw/get_topic_endpoint_info.h>
#include <rmw/serialized_message.h>
#include <rmw/subscription_content_filter_options.h>
#include <rmw/qos_profiles.h>
#include <rmw/qos_string_conversions.h>
#include <rmw/features.h>
#include <rmw/convert_rcutils_ret_to_rmw_ret.h>
#include <rmw/topic_endpoint_info_array.h>

#include <rosidl_typesupport_introspection_c/identifier.h>
#include <rosidl_typesupport_introspection_c/message_introspection.h>
#include <rosidl_typesupport_introspection_c/service_introspection.h>
#include <rosidl_runtime_c/message_initialization.h>

#include <rcutils/allocator.h>
#include <rcutils/logging_macros.h>
#include <rcutils/logging.h>
#include <rcutils/macros.h>
#include <rcutils/snprintf.h>
#include <rcutils/strdup.h>
#include <rcutils/types/string_array.h>

#include <ctype.h>
#include <errno.h>
#include <strings.h>
#include <stdlib.h>
#include <stdatomic.h>
#include <stdarg.h>
#include <string.h>

#include "rmw_hdds/ffi.h"
#include "rmw_hdds/types.h"
#include "rmw_hdds/qos.h"

#define RMW_UNSUPPORTED_RET() \
  do { \
    RMW_SET_ERROR_MSG_WITH_FORMAT_STRING("%s unsupported by rmw_hdds", __func__); \
    return RMW_RET_UNSUPPORTED; \
  } while (0)

#define RMW_UNSUPPORTED_PTR() \
  do { \
    RMW_SET_ERROR_MSG_WITH_FORMAT_STRING("%s unsupported by rmw_hdds", __func__); \
    return NULL; \
  } while (0)

#define RMW_UNSUPPORTED_BOOL() \
  do { \
    RMW_SET_ERROR_MSG_WITH_FORMAT_STRING("%s unsupported by rmw_hdds", __func__); \
    return false; \
  } while (0)

static rmw_ret_t
map_hdds_error(rmw_hdds_error_t err)
{
  switch (err) {
    case RMW_HDDS_ERROR_OK:
      return RMW_RET_OK;
    case RMW_HDDS_ERROR_INVALID_ARGUMENT:
      return RMW_RET_INVALID_ARGUMENT;
    case RMW_HDDS_ERROR_OUT_OF_MEMORY:
      return RMW_RET_BAD_ALLOC;
    case RMW_HDDS_ERROR_NOT_FOUND:
    case RMW_HDDS_ERROR_OPERATION_FAILED:
    default:
      return RMW_RET_ERROR;
  }
}

static rmw_ret_t
map_hdds_api_error(HddsError err)
{
  switch (err) {
    case OK:
      return RMW_RET_OK;
    case INVALID_ARGUMENT:
      return RMW_RET_INVALID_ARGUMENT;
    case OUT_OF_MEMORY:
      return RMW_RET_BAD_ALLOC;
    case NOT_FOUND:
    case OPERATION_FAILED:
    default:
      return RMW_RET_ERROR;
  }
}

typedef struct rmw_hdds_flow_endpoint_state
{
  rmw_network_flow_endpoint_array_t * array;
  size_t index;
  rmw_ret_t status;
} rmw_hdds_flow_endpoint_state_t;

static void
rmw_hdds_flow_endpoint_visit(
  const char * address,
  uint16_t port,
  void * user_data)
{
  rmw_hdds_flow_endpoint_state_t * state = (rmw_hdds_flow_endpoint_state_t *)user_data;
  if (state == NULL || state->status != RMW_RET_OK) {
    return;
  }

  if (address == NULL) {
    state->status = RMW_RET_INVALID_ARGUMENT;
    return;
  }

  if (state->index >= state->array->size) {
    state->status = RMW_RET_ERROR;
    return;
  }

  rmw_network_flow_endpoint_t * endpoint =
    &state->array->network_flow_endpoint[state->index];
  *endpoint = rmw_get_zero_initialized_network_flow_endpoint();
  endpoint->transport_protocol = RMW_TRANSPORT_PROTOCOL_UDP;
  endpoint->internet_protocol =
    strchr(address, ':') != NULL ? RMW_INTERNET_PROTOCOL_IPV6 : RMW_INTERNET_PROTOCOL_IPV4;
  endpoint->transport_port = port;
  endpoint->flow_label = 0u;
  endpoint->dscp = 0u;

  rmw_ret_t addr_status =
    rmw_network_flow_endpoint_set_internet_address(endpoint, address, strlen(address));
  if (addr_status != RMW_RET_OK) {
    state->status = addr_status;
    return;
  }

  state->index++;
}

static rmw_ret_t
rmw_hdds_get_network_flow_endpoints(
  const rmw_hdds_context_impl_t * context,
  rcutils_allocator_t * allocator,
  rmw_network_flow_endpoint_array_t * network_flow_endpoint_array)
{
  if (context == NULL || context->native_ctx == NULL) {
    RMW_SET_ERROR_MSG("invalid rmw context");
    return RMW_RET_ERROR;
  }

  size_t count = 0u;
  rmw_hdds_error_t list_status = rmw_hdds_context_for_each_user_locator(
    context->native_ctx,
    NULL,
    NULL,
    &count);
  if (list_status != RMW_HDDS_ERROR_OK) {
    return map_hdds_error(list_status);
  }

  rmw_ret_t init_status =
    rmw_network_flow_endpoint_array_init(network_flow_endpoint_array, count, allocator);
  if (init_status != RMW_RET_OK || count == 0u) {
    return init_status;
  }

  rmw_hdds_flow_endpoint_state_t state = {
    .array = network_flow_endpoint_array,
    .index = 0u,
    .status = RMW_RET_OK,
  };

  list_status = rmw_hdds_context_for_each_user_locator(
    context->native_ctx,
    rmw_hdds_flow_endpoint_visit,
    &state,
    NULL);
  if (list_status != RMW_HDDS_ERROR_OK) {
    rmw_network_flow_endpoint_array_fini(network_flow_endpoint_array);
    return map_hdds_error(list_status);
  }

  if (state.status != RMW_RET_OK) {
    rmw_network_flow_endpoint_array_fini(network_flow_endpoint_array);
    return state.status;
  }

  return RMW_RET_OK;
}

static const char *
rmw_hdds_skip_ws(const char * ptr)
{
  const unsigned char * cursor = (const unsigned char *)ptr;
  if (cursor == NULL) {
    return NULL;
  }
  while (*cursor != '\0' && isspace(*cursor)) {
    cursor++;
  }
  return (const char *)cursor;
}

static bool
rmw_hdds_is_ident_char(char ch)
{
  return isalnum((unsigned char)ch) || ch == '_';
}

static const rosidl_typesupport_introspection_c__MessageMember *
rmw_hdds_find_member(
  const rosidl_typesupport_introspection_c__MessageMembers * members,
  const char * name,
  size_t name_len)
{
  if (members == NULL || name == NULL || name_len == 0u) {
    return NULL;
  }

  const rosidl_typesupport_introspection_c__MessageMember * fields =
    (const rosidl_typesupport_introspection_c__MessageMember *)members->members_;
  if (fields == NULL) {
    return NULL;
  }

  for (size_t idx = 0u; idx < members->member_count_; ++idx) {
    const rosidl_typesupport_introspection_c__MessageMember * member = &fields[idx];
    if (member->name_ == NULL) {
      continue;
    }
    if (strlen(member->name_) == name_len &&
        strncmp(member->name_, name, name_len) == 0)
    {
      return member;
    }
  }

  return NULL;
}

static void
rmw_hdds_content_filter_reset(
  rmw_hdds_subscription_impl_t * impl,
  rcutils_allocator_t allocator)
{
  if (impl == NULL) {
    return;
  }

  if (impl->content_filter_expression != NULL) {
    allocator.deallocate(impl->content_filter_expression, allocator.state);
    impl->content_filter_expression = NULL;
  }

  if (impl->content_filter_parameters.data != NULL ||
    impl->content_filter_parameters.size != 0u)
  {
    rcutils_ret_t fini_status = rcutils_string_array_fini(&impl->content_filter_parameters);
    if (fini_status != RCUTILS_RET_OK) {
      RMW_SET_ERROR_MSG("failed to finalize content filter parameters");
    }
  }

  impl->content_filter_parameters = rcutils_get_zero_initialized_string_array();
  memset(&impl->content_filter, 0, sizeof(impl->content_filter));
}

static rmw_ret_t
rmw_hdds_parse_content_filter_parameter(
  const rosidl_typesupport_introspection_c__MessageMember * member,
  const rcutils_string_array_t * parameters,
  size_t param_index,
  rmw_hdds_content_filter_t * out_filter)
{
  if (member == NULL || parameters == NULL || out_filter == NULL) {
    return RMW_RET_INVALID_ARGUMENT;
  }

  if (param_index >= parameters->size) {
    RMW_SET_ERROR_MSG("content filter parameter index out of range");
    return RMW_RET_INVALID_ARGUMENT;
  }

  const char * param = parameters->data[param_index];
  if (param == NULL) {
    RMW_SET_ERROR_MSG("content filter parameter is null");
    return RMW_RET_INVALID_ARGUMENT;
  }

  errno = 0;
  char * end = NULL;

  switch (member->type_id_) {
    case ROS_TYPE_BOOLEAN: {
      if (strcasecmp(param, "true") == 0 || strcmp(param, "1") == 0) {
        out_filter->parameter.kind = RMW_HDDS_FILTER_VALUE_BOOL;
        out_filter->parameter.boolean = true;
        return RMW_RET_OK;
      }
      if (strcasecmp(param, "false") == 0 || strcmp(param, "0") == 0) {
        out_filter->parameter.kind = RMW_HDDS_FILTER_VALUE_BOOL;
        out_filter->parameter.boolean = false;
        return RMW_RET_OK;
      }
      RMW_SET_ERROR_MSG("invalid boolean parameter for content filter");
      return RMW_RET_INVALID_ARGUMENT;
    }
    case ROS_TYPE_CHAR:
    case ROS_TYPE_OCTET:
    case ROS_TYPE_UINT8:
    case ROS_TYPE_UINT16:
    case ROS_TYPE_UINT32:
    case ROS_TYPE_UINT64:
    case ROS_TYPE_WCHAR: {
      unsigned long long value = strtoull(param, &end, 0);
      if (end == param || *end != '\0' || errno == ERANGE) {
        RMW_SET_ERROR_MSG("invalid unsigned parameter for content filter");
        return RMW_RET_INVALID_ARGUMENT;
      }
      out_filter->parameter.kind = RMW_HDDS_FILTER_VALUE_UNSIGNED;
      out_filter->parameter.unsigned_value = (uint64_t)value;
      return RMW_RET_OK;
    }
    case ROS_TYPE_INT8:
    case ROS_TYPE_INT16:
    case ROS_TYPE_INT32:
    case ROS_TYPE_INT64: {
      long long value = strtoll(param, &end, 0);
      if (end == param || *end != '\0' || errno == ERANGE) {
        RMW_SET_ERROR_MSG("invalid signed parameter for content filter");
        return RMW_RET_INVALID_ARGUMENT;
      }
      out_filter->parameter.kind = RMW_HDDS_FILTER_VALUE_SIGNED;
      out_filter->parameter.signed_value = (int64_t)value;
      return RMW_RET_OK;
    }
    case ROS_TYPE_FLOAT:
    case ROS_TYPE_DOUBLE: {
      double value = strtod(param, &end);
      if (end == param || *end != '\0' || errno == ERANGE) {
        RMW_SET_ERROR_MSG("invalid floating parameter for content filter");
        return RMW_RET_INVALID_ARGUMENT;
      }
      out_filter->parameter.kind = RMW_HDDS_FILTER_VALUE_FLOAT;
      out_filter->parameter.float_value = value;
      return RMW_RET_OK;
    }
    case ROS_TYPE_LONG_DOUBLE: {
      long double value = strtold(param, &end);
      if (end == param || *end != '\0' || errno == ERANGE) {
        RMW_SET_ERROR_MSG("invalid long double parameter for content filter");
        return RMW_RET_INVALID_ARGUMENT;
      }
      out_filter->parameter.kind = RMW_HDDS_FILTER_VALUE_LONG_DOUBLE;
      out_filter->parameter.long_double_value = value;
      return RMW_RET_OK;
    }
    case ROS_TYPE_STRING: {
      out_filter->parameter.kind = RMW_HDDS_FILTER_VALUE_STRING;
      out_filter->parameter.string_value = param;
      out_filter->parameter.string_length = strlen(param);
      return RMW_RET_OK;
    }
    case ROS_TYPE_WSTRING:
    case ROS_TYPE_MESSAGE:
    default:
      RMW_SET_ERROR_MSG("content filter parameter type unsupported");
      return RMW_RET_UNSUPPORTED;
  }
}

static rmw_ret_t
rmw_hdds_parse_content_filter_expression(
  const rosidl_typesupport_introspection_c__MessageMembers * members,
  const char * expression,
  const rcutils_string_array_t * parameters,
  rmw_hdds_content_filter_t * out_filter)
{
  if (members == NULL || expression == NULL || parameters == NULL || out_filter == NULL) {
    return RMW_RET_INVALID_ARGUMENT;
  }

  const char * cursor = rmw_hdds_skip_ws(expression);
  if (cursor == NULL || *cursor == '\0') {
    RMW_SET_ERROR_MSG("content filter expression is empty");
    return RMW_RET_INVALID_ARGUMENT;
  }

  const char * field_start = cursor;
  while (*cursor != '\0' && rmw_hdds_is_ident_char(*cursor)) {
    cursor++;
  }
  if (cursor == field_start) {
    RMW_SET_ERROR_MSG("content filter expression missing field name");
    return RMW_RET_INVALID_ARGUMENT;
  }

  size_t field_len = (size_t)(cursor - field_start);
  const rosidl_typesupport_introspection_c__MessageMember * member =
    rmw_hdds_find_member(members, field_start, field_len);
  if (member == NULL) {
    RMW_SET_ERROR_MSG("content filter field not found");
    return RMW_RET_INVALID_ARGUMENT;
  }

  if (member->is_array_) {
    RMW_SET_ERROR_MSG("content filter does not support arrays or sequences");
    return RMW_RET_UNSUPPORTED;
  }

  cursor = rmw_hdds_skip_ws(cursor);
  if (cursor == NULL || *cursor == '\0') {
    RMW_SET_ERROR_MSG("content filter expression missing operator");
    return RMW_RET_INVALID_ARGUMENT;
  }

  rmw_hdds_filter_op_t op = RMW_HDDS_FILTER_OP_EQ;
  if (strncmp(cursor, "==", 2) == 0 || strncmp(cursor, "=", 1) == 0) {
    op = RMW_HDDS_FILTER_OP_EQ;
    cursor += (cursor[0] == '=' && cursor[1] == '=') ? 2 : 1;
  } else if (strncmp(cursor, "!=", 2) == 0) {
    op = RMW_HDDS_FILTER_OP_NEQ;
    cursor += 2;
  } else if (strncmp(cursor, ">=", 2) == 0) {
    op = RMW_HDDS_FILTER_OP_GTE;
    cursor += 2;
  } else if (strncmp(cursor, "<=", 2) == 0) {
    op = RMW_HDDS_FILTER_OP_LTE;
    cursor += 2;
  } else if (strncmp(cursor, ">", 1) == 0) {
    op = RMW_HDDS_FILTER_OP_GT;
    cursor += 1;
  } else if (strncmp(cursor, "<", 1) == 0) {
    op = RMW_HDDS_FILTER_OP_LT;
    cursor += 1;
  } else {
    RMW_SET_ERROR_MSG("content filter expression has invalid operator");
    return RMW_RET_INVALID_ARGUMENT;
  }

  cursor = rmw_hdds_skip_ws(cursor);
  if (cursor == NULL || *cursor != '%') {
    RMW_SET_ERROR_MSG("content filter expression missing parameter token");
    return RMW_RET_INVALID_ARGUMENT;
  }
  cursor++;

  errno = 0;
  char * end = NULL;
  unsigned long param_index = strtoul(cursor, &end, 10);
  if (end == cursor || errno == ERANGE) {
    RMW_SET_ERROR_MSG("content filter parameter index invalid");
    return RMW_RET_INVALID_ARGUMENT;
  }

  cursor = rmw_hdds_skip_ws(end);
  if (cursor == NULL || *cursor != '\0') {
    RMW_SET_ERROR_MSG("content filter expression has trailing characters");
    return RMW_RET_INVALID_ARGUMENT;
  }

  if ((size_t)param_index >= parameters->size) {
    RMW_SET_ERROR_MSG("content filter parameter index out of range");
    return RMW_RET_INVALID_ARGUMENT;
  }

  memset(out_filter, 0, sizeof(*out_filter));
  out_filter->enabled = true;
  out_filter->op = op;
  out_filter->param_index = (size_t)param_index;
  out_filter->member_offset = (size_t)member->offset_;
  out_filter->member_type = member->type_id_;

  rmw_ret_t param_status = rmw_hdds_parse_content_filter_parameter(
    member, parameters, (size_t)param_index, out_filter);
  if (param_status != RMW_RET_OK) {
    return param_status;
  }

  if (member->type_id_ == ROS_TYPE_STRING) {
    if (op != RMW_HDDS_FILTER_OP_EQ && op != RMW_HDDS_FILTER_OP_NEQ) {
      RMW_SET_ERROR_MSG("content filter string supports only == or !=");
      return RMW_RET_UNSUPPORTED;
    }
  }

  return RMW_RET_OK;
}

static bool
hdds_time_equal(rmw_time_t left, rmw_time_t right)
{
  return left.sec == right.sec && left.nsec == right.nsec;
}

static bool
hdds_time_not_equal(rmw_time_t left, rmw_time_t right)
{
  return !hdds_time_equal(left, right);
}

static bool
hdds_time_less(rmw_time_t left, rmw_time_t right)
{
  if (left.sec < right.sec) {
    return true;
  }
  if (left.sec == right.sec && left.nsec < right.nsec) {
    return true;
  }
  return false;
}

static rmw_time_t
rmw_time_from_ns_u64(uint64_t ns_total)
{
  rmw_time_t out;
  out.sec = ns_total / 1000000000ull;
  out.nsec = ns_total % 1000000000ull;
  return out;
}

static rmw_qos_profile_t
rmw_qos_profile_from_hdds(const rmw_hdds_qos_profile_t * profile)
{
  if (profile == NULL) {
    return rmw_qos_profile_unknown;
  }

  rmw_qos_profile_t out = rmw_qos_profile_unknown;
  out.history = (enum rmw_qos_history_policy_e)profile->history;
  out.depth = (size_t)profile->depth;
  out.reliability = (enum rmw_qos_reliability_policy_e)profile->reliability;
  out.durability = (enum rmw_qos_durability_policy_e)profile->durability;
  out.deadline = rmw_time_from_ns_u64(profile->deadline_ns);
  out.lifespan = rmw_time_from_ns_u64(profile->lifespan_ns);
  out.liveliness = (enum rmw_qos_liveliness_policy_e)profile->liveliness;
  out.liveliness_lease_duration = rmw_time_from_ns_u64(profile->liveliness_lease_ns);
  out.avoid_ros_namespace_conventions = profile->avoid_ros_namespace_conventions;
  return out;
}

static void
rmw_gid_from_bytes(const uint8_t * data, rmw_gid_t * gid)
{
  if (gid == NULL) {
    return;
  }
  gid->implementation_identifier = rmw_get_implementation_identifier();
  memset(gid->data, 0, sizeof(gid->data));
  if (data == NULL) {
    return;
  }
  memcpy(gid->data, data, sizeof(gid->data));
}

static rmw_ret_t
append_to_reason(char * buffer, size_t buffer_size, const char * format, ...)
{
  if (buffer == NULL || buffer_size == 0u) {
    return RMW_RET_OK;
  }
  size_t offset = strnlen(buffer, buffer_size);
  size_t write_size = buffer_size - offset;
  va_list args;
  va_start(args, format);
  int snprintf_ret = rcutils_vsnprintf(buffer + offset, write_size, format, args);
  va_end(args);
  if (snprintf_ret < 0) {
    RMW_SET_ERROR_MSG("failed to append to QoS reason buffer");
    return RMW_RET_ERROR;
  }
  return RMW_RET_OK;
}

static void
hdds_fill_gid(rmw_gid_t * gid, const void * ptr, struct rmw_hdds_context_t * native_ctx)
{
  if (gid == NULL) {
    return;
  }

  gid->implementation_identifier = rmw_get_implementation_identifier();
  memset(gid->data, 0, sizeof(gid->data));

  if (ptr == NULL || native_ctx == NULL) {
    return;
  }

  // First 12 bytes: participant GUID prefix (stable cross-process).
  rmw_hdds_context_guid_prefix(native_ctx, gid->data);

  // Last 4 bytes: entity-specific identifier.
  uint32_t entity_id = (uint32_t)((uintptr_t)ptr & 0xFFFFFFFFu);
  memcpy(gid->data + 12, &entity_id, sizeof(entity_id));
}

typedef struct rmw_hdds_event_impl
{
  rmw_event_type_t event_type;
  rmw_event_callback_t callback;
  const void * user_data;
} rmw_hdds_event_impl_t;

static bool
hdds_event_type_supported_for_publisher(rmw_event_type_t event_type)
{
  switch (event_type) {
    case RMW_EVENT_LIVELINESS_LOST:
    case RMW_EVENT_OFFERED_DEADLINE_MISSED:
    case RMW_EVENT_OFFERED_QOS_INCOMPATIBLE:
      return true;
    default:
      return false;
  }
}

static bool
hdds_event_type_supported_for_subscription(rmw_event_type_t event_type)
{
  switch (event_type) {
    case RMW_EVENT_LIVELINESS_CHANGED:
    case RMW_EVENT_REQUESTED_DEADLINE_MISSED:
    case RMW_EVENT_REQUESTED_QOS_INCOMPATIBLE:
    case RMW_EVENT_MESSAGE_LOST:
      return true;
    default:
      return false;
  }
}

static size_t
hdds_event_info_size(rmw_event_type_t event_type)
{
  switch (event_type) {
    case RMW_EVENT_LIVELINESS_CHANGED:
      return sizeof(rmw_liveliness_changed_status_t);
    case RMW_EVENT_REQUESTED_DEADLINE_MISSED:
      return sizeof(rmw_requested_deadline_missed_status_t);
    case RMW_EVENT_REQUESTED_QOS_INCOMPATIBLE:
      return sizeof(rmw_requested_qos_incompatible_event_status_t);
    case RMW_EVENT_MESSAGE_LOST:
      return sizeof(rmw_message_lost_status_t);
    case RMW_EVENT_LIVELINESS_LOST:
      return sizeof(rmw_liveliness_lost_status_t);
    case RMW_EVENT_OFFERED_DEADLINE_MISSED:
      return sizeof(rmw_offered_deadline_missed_status_t);
    case RMW_EVENT_OFFERED_QOS_INCOMPATIBLE:
      return sizeof(rmw_offered_qos_incompatible_event_status_t);
    default:
      return 0u;
  }
}

typedef struct
{
  const char * topic_name;
  size_t count;
  bool matched;
  bool count_publishers;
} hdds_graph_count_ctx_t;

static void
hdds_graph_count_cb(
  const char * topic_name,
  const char * type_name,
  uint32_t writer_count,
  uint32_t reader_count,
  void * user_data)
{
  (void)type_name;
  hdds_graph_count_ctx_t * ctx = (hdds_graph_count_ctx_t *)user_data;
  if (ctx == NULL || ctx->matched) {
    return;
  }
  if (topic_name != NULL && ctx->topic_name != NULL &&
    strcmp(topic_name, ctx->topic_name) == 0)
  {
    ctx->count = ctx->count_publishers ? (size_t)writer_count : (size_t)reader_count;
    ctx->matched = true;
  }
}

static rcutils_allocator_t
select_node_allocator(const rmw_hdds_node_impl_t * node_impl)
{
  if (node_impl != NULL && rcutils_allocator_is_valid(&node_impl->allocator)) {
    return node_impl->allocator;
  }
  return rcutils_get_default_allocator();
}

static void
safe_string_array_fini(rcutils_string_array_t * array)
{
  if (array == NULL) {
    return;
  }
  rcutils_ret_t ret = rcutils_string_array_fini(array);
  if (ret != RCUTILS_RET_OK) {
    RCUTILS_LOG_WARN_NAMED("rmw_hdds", "rcutils_string_array_fini returned %d", (int)ret);
  }
}

static void
safe_names_and_types_fini(rmw_names_and_types_t * names_and_types)
{
  if (names_and_types == NULL) {
    return;
  }
  rmw_ret_t ret = rmw_names_and_types_fini(names_and_types);
  if (ret != RMW_RET_OK) {
    RCUTILS_LOG_WARN_NAMED("rmw_hdds", "rmw_names_and_types_fini returned %d", (int)ret);
  }
}

static const char *
normalize_topic_name(const char * name)
{
  if (name == NULL) {
    return NULL;
  }
  if (name[0] == '/' && name[1] != '\0') {
    return name + 1;
  }
  return name;
}

static bool
hdds_topic_matches(const char * left, const char * right)
{
  if (left == NULL || right == NULL) {
    return false;
  }
  if (strcmp(left, right) == 0) {
    return true;
  }
  return strcmp(normalize_topic_name(left), normalize_topic_name(right)) == 0;
}

enum { HDDS_SERVICE_HEADER_LEN = 24 };

static void
encode_i64_le(int64_t value, uint8_t out[8])
{
  uint64_t uvalue = (uint64_t)value;
  for (size_t i = 0; i < 8; ++i) {
    out[i] = (uint8_t)((uvalue >> (8u * i)) & 0xFFu);
  }
}

static int64_t
decode_i64_le(const uint8_t in[8])
{
  uint64_t value = 0;
  for (size_t i = 0; i < 8; ++i) {
    value |= ((uint64_t)in[i]) << (8u * i);
  }
  return (int64_t)value;
}

static void
encode_request_id(const rmw_request_id_t * request_id, uint8_t * out)
{
  if (request_id == NULL || out == NULL) {
    return;
  }
  memcpy(out, request_id->writer_guid, sizeof(request_id->writer_guid));
  encode_i64_le(request_id->sequence_number, out + sizeof(request_id->writer_guid));
}

static bool
decode_request_id(const uint8_t * data, size_t len, rmw_request_id_t * out)
{
  if (data == NULL || out == NULL || len < HDDS_SERVICE_HEADER_LEN) {
    return false;
  }
  memcpy(out->writer_guid, data, sizeof(out->writer_guid));
  out->sequence_number = decode_i64_le(data + sizeof(out->writer_guid));
  if (out->sequence_number <= 0) {
    return false;
  }
  bool guid_nonzero = false;
  for (size_t idx = 0u; idx < sizeof(out->writer_guid); ++idx) {
    if (out->writer_guid[idx] != 0u) {
      guid_nonzero = true;
      break;
    }
  }
  if (!guid_nonzero) {
    return false;
  }
  return true;
}

static char *
extract_type_name_from_members(
  const rosidl_typesupport_introspection_c__MessageMembers * members,
  rcutils_allocator_t allocator)
{
  if (members == NULL || members->message_name_ == NULL) {
    return NULL;
  }

  const char * namespace_str = members->message_namespace_;
  const char * name_str = members->message_name_;
  size_t namespace_len = namespace_str != NULL ? strlen(namespace_str) : 0u;
  size_t name_len = strlen(name_str);

  size_t buffer_len = namespace_len + (namespace_len > 0u ? 1u : 0u) + name_len + 1u;
  char * buffer = (char *)allocator.allocate(buffer_len, allocator.state);
  if (buffer == NULL) {
    return NULL;
  }

  size_t out_idx = 0u;
  if (namespace_len > 0u) {
    for (size_t idx = 0u; idx < namespace_len; ) {
      if (namespace_str[idx] == '_' &&
        (idx + 1u) < namespace_len &&
        namespace_str[idx + 1u] == '_')
      {
        buffer[out_idx++] = '/';
        idx += 2u;
      } else {
        buffer[out_idx++] = namespace_str[idx++];
      }
    }

    if (out_idx == 0u || buffer[out_idx - 1u] != '/') {
      buffer[out_idx++] = '/';
    }
  }

  memcpy(buffer + out_idx, name_str, name_len);
  out_idx += name_len;
  buffer[out_idx] = '\0';

  return buffer;
}

static char *
service_type_from_message_type(
  const char * message_type,
  rcutils_allocator_t allocator)
{
  if (message_type == NULL) {
    return NULL;
  }

  const char * suffix = NULL;
  const char * base = strrchr(message_type, '/');
  if (base == NULL) {
    base = message_type;
  } else {
    base += 1;
  }

  const char * request_suffix = "_Request";
  const char * response_suffix = "_Response";
  size_t base_len = strlen(base);
  size_t request_len = strlen(request_suffix);
  size_t response_len = strlen(response_suffix);

  if (base_len > request_len &&
    strcmp(base + (base_len - request_len), request_suffix) == 0)
  {
    suffix = request_suffix;
  } else if (base_len > response_len &&
    strcmp(base + (base_len - response_len), response_suffix) == 0)
  {
    suffix = response_suffix;
  } else {
    return NULL;
  }

  size_t prefix_len = (size_t)(base - message_type);
  size_t trimmed_len = base_len - strlen(suffix);
  size_t total_len = prefix_len + trimmed_len + 1u;

  char * result = (char *)allocator.allocate(total_len, allocator.state);
  if (result == NULL) {
    return NULL;
  }

  if (prefix_len > 0u) {
    memcpy(result, message_type, prefix_len);
  }
  memcpy(result + prefix_len, base, trimmed_len);
  result[prefix_len + trimmed_len] = '\0';
  return result;
}

static char *
create_service_topic(
  const char * service_name,
  const char * prefix,
  rcutils_allocator_t allocator)
{
  if (service_name == NULL || prefix == NULL) {
    return NULL;
  }

  bool leading_slash = service_name[0] == '/';
  const char * normalized = leading_slash ? service_name + 1 : service_name;
  size_t prefix_len = strlen(prefix);
  size_t name_len = strlen(normalized);
  size_t total_len = prefix_len + name_len + 2u + (leading_slash ? 1u : 0u);

  char * buffer = (char *)allocator.allocate(total_len, allocator.state);
  if (buffer == NULL) {
    return NULL;
  }

  size_t idx = 0u;
  if (leading_slash) {
    buffer[idx++] = '/';
  }
  memcpy(buffer + idx, prefix, prefix_len);
  idx += prefix_len;
  buffer[idx++] = '/';
  memcpy(buffer + idx, normalized, name_len);
  idx += name_len;
  buffer[idx] = '\0';

  return buffer;
}

static const rosidl_service_type_support_t *
get_introspection_service_support(
  const rosidl_service_type_support_t * type_support)
{
  if (type_support == NULL) {
    return NULL;
  }

  const rosidl_service_type_support_t * handle =
    get_service_typesupport_handle(type_support, rosidl_typesupport_introspection_c__identifier);
  return handle;
}

static const rosidl_typesupport_introspection_c__MessageMembers *
get_introspection_message_members(
  const rosidl_message_type_support_t * type_support)
{
  if (type_support == NULL) {
    return NULL;
  }

  const rosidl_message_type_support_t * handle =
    get_message_typesupport_handle(type_support, rosidl_typesupport_introspection_c__identifier);
  if (handle == NULL || handle->data == NULL) {
    return NULL;
  }

  return (const rosidl_typesupport_introspection_c__MessageMembers *)handle->data;
}

static void *
allocate_message(
  const rosidl_typesupport_introspection_c__MessageMembers * members,
  rcutils_allocator_t allocator)
{
  if (members == NULL || members->size_of_ == 0u) {
    return NULL;
  }

  if (!rcutils_allocator_is_valid(&allocator)) {
    allocator = rcutils_get_default_allocator();
  }

  void * msg = allocator.allocate(members->size_of_, allocator.state);
  if (msg == NULL) {
    return NULL;
  }

  memset(msg, 0, members->size_of_);
  if (members->init_function != NULL) {
    members->init_function(msg, ROSIDL_RUNTIME_C_MSG_INIT_ALL);
  }
  return msg;
}

static void
free_message(
  void * message,
  const rosidl_typesupport_introspection_c__MessageMembers * members,
  rcutils_allocator_t allocator)
{
  if (message == NULL) {
    return;
  }

  if (members != NULL && members->fini_function != NULL) {
    members->fini_function(message);
  }

  if (!rcutils_allocator_is_valid(&allocator)) {
    allocator = rcutils_get_default_allocator();
  }
  allocator.deallocate(message, allocator.state);
}

static const rosidl_message_type_support_t *
create_message_type_support(
  const rosidl_typesupport_introspection_c__MessageMembers * members,
  rcutils_allocator_t allocator)
{
  typedef struct rmw_hdds_message_type_support_ext {
    const char * typesupport_identifier;
    const void * data;
    rosidl_message_typesupport_handle_function func;
    const void * get_type_hash_func;
    const void * get_type_description_func;
    const void * get_type_description_sources_func;
  } rmw_hdds_message_type_support_ext_t;

  if (members == NULL) {
    return NULL;
  }

  rosidl_message_type_support_t * handle =
    (rosidl_message_type_support_t *)allocator.allocate(
      sizeof(rmw_hdds_message_type_support_ext_t),
      allocator.state);
  if (handle == NULL) {
    return NULL;
  }
  handle->typesupport_identifier = rosidl_typesupport_introspection_c__identifier;
  handle->data = members;
  handle->func = get_message_typesupport_handle_function;
  ((rmw_hdds_message_type_support_ext_t *)handle)->get_type_hash_func = NULL;
  ((rmw_hdds_message_type_support_ext_t *)handle)->get_type_description_func = NULL;
  ((rmw_hdds_message_type_support_ext_t *)handle)->get_type_description_sources_func = NULL;
  return handle;
}

static bool
service_name_from_topic(
  const char * topic_name,
  const char * prefix,
  const char ** out_name)
{
  if (topic_name == NULL || prefix == NULL || out_name == NULL) {
    return false;
  }

  size_t prefix_len = strlen(prefix);
  if (strncmp(topic_name, "/", 1) == 0) {
    size_t leading = 1u + prefix_len;
    if (strncmp(topic_name + 1, prefix, prefix_len) == 0 &&
      topic_name[leading] == '/')
    {
      *out_name = topic_name + leading;
      return true;
    }
  }

  if (strncmp(topic_name, prefix, prefix_len) == 0 && topic_name[prefix_len] == '/') {
    *out_name = topic_name + prefix_len + 1u;
    return true;
  }

  return false;
}

typedef struct
{
  char * name;
  char * type_name;
} hdds_service_entry_t;

typedef struct
{
  hdds_service_entry_t * entries;
  size_t size;
  size_t capacity;
  rcutils_allocator_t allocator;
} hdds_service_list_t;

static void
hdds_service_list_init(hdds_service_list_t * list, rcutils_allocator_t allocator)
{
  if (list == NULL) {
    return;
  }
  list->entries = NULL;
  list->size = 0u;
  list->capacity = 0u;
  list->allocator = allocator;
}

static void
hdds_service_list_fini(hdds_service_list_t * list)
{
  if (list == NULL) {
    return;
  }
  for (size_t i = 0; i < list->size; ++i) {
    if (list->entries[i].name != NULL) {
      list->allocator.deallocate(list->entries[i].name, list->allocator.state);
    }
    if (list->entries[i].type_name != NULL) {
      list->allocator.deallocate(list->entries[i].type_name, list->allocator.state);
    }
  }
  if (list->entries != NULL) {
    list->allocator.deallocate(list->entries, list->allocator.state);
  }
  list->entries = NULL;
  list->size = 0u;
  list->capacity = 0u;
}

static rmw_ret_t
hdds_service_list_add(
  hdds_service_list_t * list,
  const char * service_name,
  const char * service_type)
{
  if (list == NULL || service_name == NULL) {
    return RMW_RET_INVALID_ARGUMENT;
  }

  for (size_t i = 0; i < list->size; ++i) {
    if (strcmp(list->entries[i].name, service_name) == 0) {
      if (list->entries[i].type_name == NULL && service_type != NULL) {
        char * type_copy = rcutils_strdup(service_type, list->allocator);
        if (type_copy == NULL) {
          return RMW_RET_BAD_ALLOC;
        }
        list->entries[i].type_name = type_copy;
      }
      return RMW_RET_OK;
    }
  }

  if (list->size + 1 > list->capacity) {
    size_t new_capacity = list->capacity == 0u ? 4u : list->capacity * 2u;
    void * new_entries = NULL;
    if (list->allocator.reallocate != NULL && list->entries != NULL) {
      new_entries = list->allocator.reallocate(
        list->entries,
        new_capacity * sizeof(hdds_service_entry_t),
        list->allocator.state);
    } else {
      new_entries = list->allocator.allocate(
        new_capacity * sizeof(hdds_service_entry_t),
        list->allocator.state);
      if (new_entries != NULL && list->entries != NULL) {
        memcpy(
          new_entries,
          list->entries,
          list->size * sizeof(hdds_service_entry_t));
        list->allocator.deallocate(list->entries, list->allocator.state);
      }
    }
    if (new_entries == NULL) {
      return RMW_RET_BAD_ALLOC;
    }
    list->entries = (hdds_service_entry_t *)new_entries;
    list->capacity = new_capacity;
  }

  char * name_copy = rcutils_strdup(service_name, list->allocator);
  if (name_copy == NULL) {
    return RMW_RET_BAD_ALLOC;
  }
  char * type_copy = NULL;
  if (service_type != NULL) {
    type_copy = rcutils_strdup(service_type, list->allocator);
    if (type_copy == NULL) {
      list->allocator.deallocate(name_copy, list->allocator.state);
      return RMW_RET_BAD_ALLOC;
    }
  }

  list->entries[list->size++] = (hdds_service_entry_t){
    .name = name_copy,
    .type_name = type_copy,
  };

  return RMW_RET_OK;
}

static rmw_ret_t
fill_names_and_types_from_service_list(
  rmw_names_and_types_t * out,
  hdds_service_list_t * list)
{
  if (out == NULL || list == NULL) {
    return RMW_RET_INVALID_ARGUMENT;
  }

  rmw_ret_t init_status = rmw_names_and_types_init(
    out,
    list->size,
    &list->allocator);
  if (init_status != RMW_RET_OK) {
    return init_status;
  }

  for (size_t i = 0; i < list->size; ++i) {
    out->names.data[i] = list->entries[i].name;
    list->entries[i].name = NULL;

    rcutils_ret_t rcutils_ret = rcutils_string_array_init(
      &out->types[i],
      1u,
      &list->allocator);
    if (rcutils_ret != RCUTILS_RET_OK) {
      safe_names_and_types_fini(out);
      return rmw_convert_rcutils_ret_to_rmw_ret(rcutils_ret);
    }

    char * type_name = list->entries[i].type_name;
    if (type_name == NULL) {
      type_name = rcutils_strdup("", list->allocator);
      if (type_name == NULL) {
        safe_names_and_types_fini(out);
        return RMW_RET_BAD_ALLOC;
      }
    } else {
      list->entries[i].type_name = NULL;
    }

    out->types[i].data[0] = type_name;
    out->types[i].size = 1u;
  }

  out->names.size = list->size;
  return RMW_RET_OK;
}

typedef struct
{
  hdds_service_list_t * list;
  rmw_ret_t status;
  const char * prefix;
} hdds_service_collect_ctx_t;

static void
hdds_collect_service_common(
  const char * topic_name,
  const char * type_name,
  void * user_data)
{
  hdds_service_collect_ctx_t * ctx = (hdds_service_collect_ctx_t *)user_data;
  if (ctx == NULL || ctx->list == NULL || ctx->status != RMW_RET_OK) {
    return;
  }

  const char * service_name = NULL;
  bool matched = false;
  if (ctx->prefix != NULL) {
    matched = service_name_from_topic(topic_name, ctx->prefix, &service_name);
  } else {
    matched = service_name_from_topic(topic_name, "rq", &service_name) ||
      service_name_from_topic(topic_name, "rr", &service_name);
  }

  if (!matched || service_name == NULL) {
    return;
  }

  char * service_type = service_type_from_message_type(type_name, ctx->list->allocator);
  rmw_ret_t add_status = hdds_service_list_add(ctx->list, service_name, service_type);
  if (service_type != NULL) {
    ctx->list->allocator.deallocate(service_type, ctx->list->allocator.state);
  }
  if (add_status != RMW_RET_OK) {
    ctx->status = add_status;
  }
}

static void
hdds_collect_service_endpoint_cb(
  const char * topic_name,
  const char * type_name,
  const uint8_t * endpoint_gid,
  const rmw_hdds_qos_profile_t * qos_profile,
  void * user_data)
{
  (void)endpoint_gid;
  (void)qos_profile;
  hdds_collect_service_common(topic_name, type_name, user_data);
}

static void
hdds_collect_service_topic_cb(
  const char * topic_name,
  const char * type_name,
  uint32_t writer_count,
  uint32_t reader_count,
  void * user_data)
{
  (void)writer_count;
  (void)reader_count;
  hdds_collect_service_common(topic_name, type_name, user_data);
}

typedef struct
{
  const char * topic_name;
  size_t count;
} hdds_endpoint_count_ctx_t;

static void
hdds_endpoint_count_cb(
  const char * topic_name,
  const char * type_name,
  const uint8_t * endpoint_gid,
  const rmw_hdds_qos_profile_t * qos_profile,
  void * user_data)
{
  (void)type_name;
  (void)endpoint_gid;
  (void)qos_profile;
  hdds_endpoint_count_ctx_t * ctx = (hdds_endpoint_count_ctx_t *)user_data;
  if (ctx == NULL) {
    return;
  }
  if (hdds_topic_matches(topic_name, ctx->topic_name)) {
    ctx->count += 1u;
  }
}

typedef struct
{
  struct rmw_hdds_context_t * native_ctx;
  const char * topic_name;
  size_t count;
  rmw_ret_t status;
  bool publishers;
} hdds_topic_endpoint_count_query_t;

static void
hdds_node_count_cb(
  const char * node_name,
  const char * node_namespace,
  void * user_data)
{
  hdds_topic_endpoint_count_query_t * ctx = (hdds_topic_endpoint_count_query_t *)user_data;
  if (ctx == NULL || ctx->status != RMW_RET_OK) {
    return;
  }

  hdds_endpoint_count_ctx_t endpoint_ctx = {
    .topic_name = ctx->topic_name,
    .count = 0u,
  };

  rmw_hdds_error_t err = ctx->publishers
    ? rmw_hdds_context_for_each_publisher_endpoint(
        ctx->native_ctx,
        node_name,
        node_namespace,
        hdds_endpoint_count_cb,
        &endpoint_ctx,
        NULL,
        NULL)
    : rmw_hdds_context_for_each_subscription_endpoint(
        ctx->native_ctx,
        node_name,
        node_namespace,
        hdds_endpoint_count_cb,
        &endpoint_ctx,
        NULL,
        NULL);

  if (err != RMW_HDDS_ERROR_OK) {
    ctx->status = map_hdds_error(err);
    return;
  }

  ctx->count += endpoint_ctx.count;
}

typedef struct
{
  struct rmw_hdds_context_t * native_ctx;
  const char * topic_name;
  rmw_topic_endpoint_info_array_t * info_array;
  rcutils_allocator_t allocator;
  size_t index;
  rmw_ret_t status;
  bool publishers;
  const char * node_name;
  const char * node_namespace;
} hdds_topic_endpoint_fill_query_t;

static void
hdds_endpoint_fill_cb(
  const char * topic_name,
  const char * type_name,
  const uint8_t * endpoint_gid,
  const rmw_hdds_qos_profile_t * qos_profile,
  void * user_data)
{
  hdds_topic_endpoint_fill_query_t * ctx = (hdds_topic_endpoint_fill_query_t *)user_data;
  if (ctx == NULL || ctx->status != RMW_RET_OK) {
    return;
  }

  if (!hdds_topic_matches(topic_name, ctx->topic_name)) {
    return;
  }

  const char * type_name_safe = type_name != NULL ? type_name : "";

  if (ctx->index >= ctx->info_array->size) {
    ctx->status = RMW_RET_ERROR;
    return;
  }

  rmw_topic_endpoint_info_t * info = &ctx->info_array->info_array[ctx->index];
  *info = rmw_get_zero_initialized_topic_endpoint_info();
  info->endpoint_type = ctx->publishers ? RMW_ENDPOINT_PUBLISHER : RMW_ENDPOINT_SUBSCRIPTION;

  rmw_qos_profile_t qos = rmw_qos_profile_from_hdds(qos_profile);
  rmw_ret_t set_status = rmw_topic_endpoint_info_set_qos_profile(info, &qos);
  if (set_status != RMW_RET_OK) {
    ctx->status = set_status;
    return;
  }

  uint8_t gid_bytes[RMW_GID_STORAGE_SIZE] = {0};
  const uint8_t * gid_ptr = gid_bytes;
  if (endpoint_gid != NULL) {
    gid_ptr = endpoint_gid;
  }
  set_status = rmw_topic_endpoint_info_set_gid(info, gid_ptr, RMW_GID_STORAGE_SIZE);
  if (set_status != RMW_RET_OK) {
    ctx->status = set_status;
    return;
  }

  set_status = rmw_topic_endpoint_info_set_node_name(
    info,
    ctx->node_name,
    &ctx->allocator);
  if (set_status != RMW_RET_OK) {
    ctx->status = set_status;
    return;
  }

  set_status = rmw_topic_endpoint_info_set_node_namespace(
    info,
    ctx->node_namespace,
    &ctx->allocator);
  if (set_status != RMW_RET_OK) {
    ctx->status = set_status;
    return;
  }

  set_status = rmw_topic_endpoint_info_set_topic_type(
    info,
    type_name_safe,
    &ctx->allocator);
  if (set_status != RMW_RET_OK) {
    ctx->status = set_status;
    return;
  }

  ctx->index++;
}

static void
hdds_node_fill_cb(
  const char * node_name,
  const char * node_namespace,
  void * user_data)
{
  hdds_topic_endpoint_fill_query_t * ctx = (hdds_topic_endpoint_fill_query_t *)user_data;
  if (ctx == NULL || ctx->status != RMW_RET_OK) {
    return;
  }

  ctx->node_name = node_name;
  ctx->node_namespace = node_namespace;

  rmw_hdds_error_t err = ctx->publishers
    ? rmw_hdds_context_for_each_publisher_endpoint(
        ctx->native_ctx,
        node_name,
        node_namespace,
        hdds_endpoint_fill_cb,
        ctx,
        NULL,
        NULL)
    : rmw_hdds_context_for_each_subscription_endpoint(
        ctx->native_ctx,
        node_name,
        node_namespace,
        hdds_endpoint_fill_cb,
        ctx,
        NULL,
        NULL);

  if (err != RMW_HDDS_ERROR_OK) {
    ctx->status = map_hdds_error(err);
  }
}

rmw_ret_t
rmw_init_publisher_allocation(
  const rosidl_message_type_support_t * type_support,
  const rosidl_runtime_c__Sequence__bound * message_bounds,
  rmw_publisher_allocation_t * allocation)
{
  RCUTILS_UNUSED(type_support);
  RCUTILS_UNUSED(message_bounds);

  RMW_CHECK_ARGUMENT_FOR_NULL(allocation, RMW_RET_INVALID_ARGUMENT);
  allocation->implementation_identifier = rmw_get_implementation_identifier();
  allocation->data = NULL;
  return RMW_RET_OK;
}

rmw_ret_t
rmw_fini_publisher_allocation(rmw_publisher_allocation_t * allocation)
{
  RMW_CHECK_ARGUMENT_FOR_NULL(allocation, RMW_RET_INVALID_ARGUMENT);
  allocation->implementation_identifier = NULL;
  allocation->data = NULL;
  return RMW_RET_OK;
}

rmw_ret_t
rmw_borrow_loaned_message(
  const rmw_publisher_t * publisher,
  const rosidl_message_type_support_t * type_support,
  void ** ros_message)
{
  RMW_CHECK_ARGUMENT_FOR_NULL(publisher, RMW_RET_INVALID_ARGUMENT);
  RMW_CHECK_ARGUMENT_FOR_NULL(type_support, RMW_RET_INVALID_ARGUMENT);
  RMW_CHECK_ARGUMENT_FOR_NULL(ros_message, RMW_RET_INVALID_ARGUMENT);

  if (publisher->implementation_identifier != rmw_get_implementation_identifier()) {
    RMW_SET_ERROR_MSG("rmw_borrow_loaned_message identifier mismatch");
    return RMW_RET_INCORRECT_RMW_IMPLEMENTATION;
  }

  const rmw_hdds_publisher_impl_t * impl =
    (const rmw_hdds_publisher_impl_t *)publisher->data;
  if (impl == NULL) {
    RMW_SET_ERROR_MSG("publisher implementation is null");
    return RMW_RET_ERROR;
  }

  const rosidl_typesupport_introspection_c__MessageMembers * members =
    get_introspection_message_members(type_support);
  if (members == NULL) {
    RMW_SET_ERROR_MSG("introspection type support unavailable");
    return RMW_RET_UNSUPPORTED;
  }

  rcutils_allocator_t allocator = rcutils_get_default_allocator();
  void * msg = allocate_message(members, allocator);
  if (msg == NULL) {
    return RMW_RET_BAD_ALLOC;
  }

  *ros_message = msg;
  return RMW_RET_OK;
}

rmw_ret_t
rmw_return_loaned_message_from_publisher(
  const rmw_publisher_t * publisher,
  void * loaned_message)
{
  RMW_CHECK_ARGUMENT_FOR_NULL(publisher, RMW_RET_INVALID_ARGUMENT);
  RMW_CHECK_ARGUMENT_FOR_NULL(loaned_message, RMW_RET_INVALID_ARGUMENT);

  if (publisher->implementation_identifier != rmw_get_implementation_identifier()) {
    RMW_SET_ERROR_MSG("rmw_return_loaned_message_from_publisher identifier mismatch");
    return RMW_RET_INCORRECT_RMW_IMPLEMENTATION;
  }

  const rmw_hdds_publisher_impl_t * impl =
    (const rmw_hdds_publisher_impl_t *)publisher->data;
  if (impl == NULL || impl->type_support == NULL) {
    RMW_SET_ERROR_MSG("publisher implementation is null");
    return RMW_RET_ERROR;
  }

  const rosidl_typesupport_introspection_c__MessageMembers * members =
    get_introspection_message_members(impl->type_support);
  if (members == NULL) {
    RMW_SET_ERROR_MSG("introspection type support unavailable");
    return RMW_RET_ERROR;
  }

  rcutils_allocator_t allocator = rcutils_get_default_allocator();
  free_message(loaned_message, members, allocator);
  return RMW_RET_OK;
}

rmw_ret_t
rmw_publish_loaned_message(
  const rmw_publisher_t * publisher,
  void * loaned_message,
  rmw_publisher_allocation_t * allocation)
{
  return rmw_publish(publisher, loaned_message, allocation);
}

rmw_ret_t
rmw_publish_serialized_message(
  const rmw_publisher_t * publisher,
  const rmw_serialized_message_t * serialized_message,
  rmw_publisher_allocation_t * allocation)
{
  RCUTILS_UNUSED(allocation);

  RMW_CHECK_ARGUMENT_FOR_NULL(publisher, RMW_RET_INVALID_ARGUMENT);
  RMW_CHECK_ARGUMENT_FOR_NULL(serialized_message, RMW_RET_INVALID_ARGUMENT);

  if (publisher->implementation_identifier != rmw_get_implementation_identifier()) {
    RMW_SET_ERROR_MSG("rmw_publish_serialized_message identifier mismatch");
    return RMW_RET_INCORRECT_RMW_IMPLEMENTATION;
  }

  const rmw_hdds_publisher_impl_t * impl =
    (const rmw_hdds_publisher_impl_t *)publisher->data;
  if (impl == NULL || impl->context == NULL || impl->writer == NULL) {
    RMW_SET_ERROR_MSG("publisher is not fully initialized");
    return RMW_RET_ERROR;
  }

  if (serialized_message->buffer_length == 0u) {
    return RMW_RET_OK;
  }

  if (serialized_message->buffer == NULL) {
    RMW_SET_ERROR_MSG("serialized message buffer is null");
    return RMW_RET_INVALID_ARGUMENT;
  }

  HddsError err = hdds_writer_write(
    impl->writer,
    serialized_message->buffer,
    serialized_message->buffer_length);
  return map_hdds_api_error(err);
}

rmw_ret_t
rmw_publisher_event_init(
  rmw_event_t * rmw_event,
  const rmw_publisher_t * publisher,
  rmw_event_type_t event_type)
{
  RMW_CHECK_ARGUMENT_FOR_NULL(rmw_event, RMW_RET_INVALID_ARGUMENT);
  RMW_CHECK_ARGUMENT_FOR_NULL(publisher, RMW_RET_INVALID_ARGUMENT);

  if (publisher->implementation_identifier != rmw_get_implementation_identifier()) {
    RMW_SET_ERROR_MSG("rmw_publisher_event_init identifier mismatch");
    return RMW_RET_INCORRECT_RMW_IMPLEMENTATION;
  }

  if (!hdds_event_type_supported_for_publisher(event_type)) {
    RMW_SET_ERROR_MSG("publisher event type not supported");
    return RMW_RET_UNSUPPORTED;
  }

  rcutils_allocator_t allocator = rcutils_get_default_allocator();
  rmw_hdds_event_impl_t * impl =
    (rmw_hdds_event_impl_t *)allocator.allocate(sizeof(rmw_hdds_event_impl_t), allocator.state);
  if (impl == NULL) {
    RMW_SET_ERROR_MSG("failed to allocate publisher event");
    return RMW_RET_BAD_ALLOC;
  }

  impl->event_type = event_type;
  impl->callback = NULL;
  impl->user_data = NULL;

  rmw_event->implementation_identifier = rmw_get_implementation_identifier();
  rmw_event->data = impl;
  rmw_event->event_type = event_type;
  return RMW_RET_OK;
}

rmw_ret_t
rmw_publisher_wait_for_all_acked(
  const rmw_publisher_t * publisher,
  rmw_time_t wait_timeout)
{
  RCUTILS_UNUSED(publisher);
  RCUTILS_UNUSED(wait_timeout);
  return RMW_RET_OK;
}

rmw_ret_t
rmw_publisher_assert_liveliness(const rmw_publisher_t * publisher)
{
  RCUTILS_UNUSED(publisher);
  return RMW_RET_OK;
}

rmw_ret_t
rmw_get_serialized_message_size(
  const rosidl_message_type_support_t * type_support,
  const rosidl_runtime_c__Sequence__bound * message_bounds,
  size_t * size)
{
  RCUTILS_UNUSED(message_bounds);
  RMW_CHECK_ARGUMENT_FOR_NULL(type_support, RMW_RET_INVALID_ARGUMENT);
  RMW_CHECK_ARGUMENT_FOR_NULL(size, RMW_RET_INVALID_ARGUMENT);

  const rosidl_typesupport_introspection_c__MessageMembers * members =
    get_introspection_message_members(type_support);
  if (members == NULL) {
    RMW_SET_ERROR_MSG("introspection type support unavailable");
    return RMW_RET_UNSUPPORTED;
  }

  rcutils_allocator_t allocator = rcutils_get_default_allocator();
  void * msg = allocate_message(members, allocator);
  if (msg == NULL) {
    RMW_SET_ERROR_MSG("failed to allocate message for size estimation");
    return RMW_RET_BAD_ALLOC;
  }

  size_t out_len = 0u;
  HddsError err = hdds_rmw_serialize_ros_message(
    type_support,
    msg,
    NULL,
    0u,
    &out_len);

  free_message(msg, members, allocator);
  *size = out_len;

  if (err == OK || err == OUT_OF_MEMORY) {
    return RMW_RET_OK;
  }

  return map_hdds_api_error(err);
}

rmw_ret_t
rmw_publisher_get_network_flow_endpoints(
  const rmw_publisher_t * publisher,
  rcutils_allocator_t * allocator,
  rmw_network_flow_endpoint_array_t * network_flow_endpoint_array)
{
  RMW_CHECK_ARGUMENT_FOR_NULL(publisher, RMW_RET_INVALID_ARGUMENT);
  RMW_CHECK_ARGUMENT_FOR_NULL(allocator, RMW_RET_INVALID_ARGUMENT);
  RMW_CHECK_ARGUMENT_FOR_NULL(network_flow_endpoint_array, RMW_RET_INVALID_ARGUMENT);

  if (publisher->implementation_identifier != rmw_get_implementation_identifier()) {
    RMW_SET_ERROR_MSG("rmw_publisher_get_network_flow_endpoints identifier mismatch");
    return RMW_RET_INCORRECT_RMW_IMPLEMENTATION;
  }

  if (!rcutils_allocator_is_valid(allocator)) {
    RMW_SET_ERROR_MSG("allocator is invalid");
    return RMW_RET_INVALID_ARGUMENT;
  }

  rmw_ret_t zero_status =
    rmw_network_flow_endpoint_array_check_zero(network_flow_endpoint_array);
  if (zero_status != RMW_RET_OK) {
    return zero_status;
  }

  const rmw_hdds_publisher_impl_t * impl = (const rmw_hdds_publisher_impl_t *)publisher->data;
  if (impl == NULL || impl->context == NULL) {
    RMW_SET_ERROR_MSG("invalid publisher implementation");
    return RMW_RET_ERROR;
  }

  return rmw_hdds_get_network_flow_endpoints(
    impl->context,
    allocator,
    network_flow_endpoint_array);
}

rmw_ret_t
rmw_init_subscription_allocation(
  const rosidl_message_type_support_t * type_support,
  const rosidl_runtime_c__Sequence__bound * message_bounds,
  rmw_subscription_allocation_t * allocation)
{
  RCUTILS_UNUSED(type_support);
  RCUTILS_UNUSED(message_bounds);

  RMW_CHECK_ARGUMENT_FOR_NULL(allocation, RMW_RET_INVALID_ARGUMENT);
  allocation->implementation_identifier = rmw_get_implementation_identifier();
  allocation->data = NULL;
  return RMW_RET_OK;
}

rmw_ret_t
rmw_fini_subscription_allocation(rmw_subscription_allocation_t * allocation)
{
  RMW_CHECK_ARGUMENT_FOR_NULL(allocation, RMW_RET_INVALID_ARGUMENT);
  allocation->implementation_identifier = NULL;
  allocation->data = NULL;
  return RMW_RET_OK;
}

rmw_ret_t
rmw_subscription_event_init(
  rmw_event_t * rmw_event,
  const rmw_subscription_t * subscription,
  rmw_event_type_t event_type)
{
  RMW_CHECK_ARGUMENT_FOR_NULL(rmw_event, RMW_RET_INVALID_ARGUMENT);
  RMW_CHECK_ARGUMENT_FOR_NULL(subscription, RMW_RET_INVALID_ARGUMENT);

  if (subscription->implementation_identifier != rmw_get_implementation_identifier()) {
    RMW_SET_ERROR_MSG("rmw_subscription_event_init identifier mismatch");
    return RMW_RET_INCORRECT_RMW_IMPLEMENTATION;
  }

  if (!hdds_event_type_supported_for_subscription(event_type)) {
    RMW_SET_ERROR_MSG("subscription event type not supported");
    return RMW_RET_UNSUPPORTED;
  }

  rcutils_allocator_t allocator = rcutils_get_default_allocator();
  rmw_hdds_event_impl_t * impl =
    (rmw_hdds_event_impl_t *)allocator.allocate(sizeof(rmw_hdds_event_impl_t), allocator.state);
  if (impl == NULL) {
    RMW_SET_ERROR_MSG("failed to allocate subscription event");
    return RMW_RET_BAD_ALLOC;
  }

  impl->event_type = event_type;
  impl->callback = NULL;
  impl->user_data = NULL;

  rmw_event->implementation_identifier = rmw_get_implementation_identifier();
  rmw_event->data = impl;
  rmw_event->event_type = event_type;
  return RMW_RET_OK;
}

rmw_ret_t
rmw_subscription_get_network_flow_endpoints(
  const rmw_subscription_t * subscription,
  rcutils_allocator_t * allocator,
  rmw_network_flow_endpoint_array_t * network_flow_endpoint_array)
{
  RMW_CHECK_ARGUMENT_FOR_NULL(subscription, RMW_RET_INVALID_ARGUMENT);
  RMW_CHECK_ARGUMENT_FOR_NULL(allocator, RMW_RET_INVALID_ARGUMENT);
  RMW_CHECK_ARGUMENT_FOR_NULL(network_flow_endpoint_array, RMW_RET_INVALID_ARGUMENT);

  if (subscription->implementation_identifier != rmw_get_implementation_identifier()) {
    RMW_SET_ERROR_MSG("rmw_subscription_get_network_flow_endpoints identifier mismatch");
    return RMW_RET_INCORRECT_RMW_IMPLEMENTATION;
  }

  if (!rcutils_allocator_is_valid(allocator)) {
    RMW_SET_ERROR_MSG("allocator is invalid");
    return RMW_RET_INVALID_ARGUMENT;
  }

  rmw_ret_t zero_status =
    rmw_network_flow_endpoint_array_check_zero(network_flow_endpoint_array);
  if (zero_status != RMW_RET_OK) {
    return zero_status;
  }

  const rmw_hdds_subscription_impl_t * impl =
    (const rmw_hdds_subscription_impl_t *)subscription->data;
  if (impl == NULL || impl->context == NULL) {
    RMW_SET_ERROR_MSG("invalid subscription implementation");
    return RMW_RET_ERROR;
  }

  return rmw_hdds_get_network_flow_endpoints(
    impl->context,
    allocator,
    network_flow_endpoint_array);
}

rmw_ret_t
rmw_subscription_get_content_filter(
  const rmw_subscription_t * subscription,
  rcutils_allocator_t * allocator,
  rmw_subscription_content_filter_options_t * options)
{
  RMW_CHECK_ARGUMENT_FOR_NULL(subscription, RMW_RET_INVALID_ARGUMENT);
  RMW_CHECK_ARGUMENT_FOR_NULL(allocator, RMW_RET_INVALID_ARGUMENT);
  RMW_CHECK_ARGUMENT_FOR_NULL(options, RMW_RET_INVALID_ARGUMENT);

  if (subscription->implementation_identifier != rmw_get_implementation_identifier()) {
    RMW_SET_ERROR_MSG("rmw_subscription_get_content_filter identifier mismatch");
    return RMW_RET_INCORRECT_RMW_IMPLEMENTATION;
  }

  if (!rcutils_allocator_is_valid(allocator)) {
    RMW_SET_ERROR_MSG("allocator is invalid");
    return RMW_RET_INVALID_ARGUMENT;
  }

  if (options->filter_expression != NULL ||
    options->expression_parameters.data != NULL ||
    options->expression_parameters.size != 0u)
  {
    RMW_SET_ERROR_MSG("content filter options must be zero initialized");
    return RMW_RET_INVALID_ARGUMENT;
  }

  const rmw_hdds_subscription_impl_t * impl =
    (const rmw_hdds_subscription_impl_t *)subscription->data;

  if (impl == NULL) {
    RMW_SET_ERROR_MSG("invalid subscription implementation");
    return RMW_RET_ERROR;
  }

  const char * expression = "";
  size_t param_count = 0u;
  const char ** params = NULL;

  if (impl->content_filter.enabled && impl->content_filter_expression != NULL) {
    expression = impl->content_filter_expression;
    param_count = impl->content_filter_parameters.size;
    params = (const char **)impl->content_filter_parameters.data;
  }

  return rmw_subscription_content_filter_options_init(
    expression,
    param_count,
    params,
    allocator,
    options);
}

rmw_ret_t
rmw_subscription_set_content_filter(
  rmw_subscription_t * subscription,
  const rmw_subscription_content_filter_options_t * options)
{
  RMW_CHECK_ARGUMENT_FOR_NULL(subscription, RMW_RET_INVALID_ARGUMENT);
  RMW_CHECK_ARGUMENT_FOR_NULL(options, RMW_RET_INVALID_ARGUMENT);

  if (subscription->implementation_identifier != rmw_get_implementation_identifier()) {
    RMW_SET_ERROR_MSG("rmw_subscription_set_content_filter identifier mismatch");
    return RMW_RET_INCORRECT_RMW_IMPLEMENTATION;
  }

  if (options->filter_expression == NULL) {
    RMW_SET_ERROR_MSG("content filter expression is null");
    return RMW_RET_INVALID_ARGUMENT;
  }

  rmw_hdds_subscription_impl_t * impl = (rmw_hdds_subscription_impl_t *)subscription->data;
  if (impl == NULL) {
    RMW_SET_ERROR_MSG("invalid subscription implementation");
    return RMW_RET_ERROR;
  }

  rcutils_allocator_t allocator = rcutils_get_default_allocator();
  rmw_hdds_content_filter_reset(impl, allocator);
  subscription->is_cft_enabled = false;

  if (options->filter_expression[0] == '\0' &&
    options->expression_parameters.size == 0u)
  {
    impl->content_filter.enabled = false;
    return RMW_RET_OK;
  }

  const rosidl_typesupport_introspection_c__MessageMembers * members =
    get_introspection_message_members(impl->type_support);
  if (members == NULL) {
    RMW_SET_ERROR_MSG("content filter requires introspection type support");
    return RMW_RET_UNSUPPORTED;
  }

  if (!rcutils_allocator_is_valid(&allocator)) {
    allocator = rcutils_get_default_allocator();
  }

  char * expr_copy = rcutils_strdup(options->filter_expression, allocator);
  if (expr_copy == NULL) {
    RMW_SET_ERROR_MSG("failed to copy content filter expression");
    return RMW_RET_BAD_ALLOC;
  }

  rcutils_string_array_t params_copy = rcutils_get_zero_initialized_string_array();
  if (options->expression_parameters.size > 0u) {
    rcutils_ret_t rc = rcutils_string_array_init(
      &params_copy,
      options->expression_parameters.size,
      &allocator);
    if (rc != RCUTILS_RET_OK) {
      allocator.deallocate(expr_copy, allocator.state);
      RMW_SET_ERROR_MSG("failed to allocate content filter parameters");
      return RMW_RET_BAD_ALLOC;
    }

    for (size_t idx = 0u; idx < options->expression_parameters.size; ++idx) {
      const char * src = options->expression_parameters.data[idx];
      if (src == NULL) {
        safe_string_array_fini(&params_copy);
        allocator.deallocate(expr_copy, allocator.state);
        RMW_SET_ERROR_MSG("content filter parameter is null");
        return RMW_RET_INVALID_ARGUMENT;
      }
      params_copy.data[idx] = rcutils_strdup(src, allocator);
      if (params_copy.data[idx] == NULL) {
        safe_string_array_fini(&params_copy);
        allocator.deallocate(expr_copy, allocator.state);
        RMW_SET_ERROR_MSG("failed to copy content filter parameter");
        return RMW_RET_BAD_ALLOC;
      }
    }
  }

  rmw_hdds_content_filter_t parsed_filter;
  rmw_ret_t parse_status = rmw_hdds_parse_content_filter_expression(
    members,
    expr_copy,
    &params_copy,
    &parsed_filter);
  if (parse_status != RMW_RET_OK) {
    allocator.deallocate(expr_copy, allocator.state);
    if (params_copy.data != NULL || params_copy.size != 0u) {
      rcutils_ret_t fini_status = rcutils_string_array_fini(&params_copy);
      if (fini_status != RCUTILS_RET_OK) {
        RMW_SET_ERROR_MSG("failed to finalize content filter parameters");
      }
    }
    return parse_status;
  }

  impl->content_filter_expression = expr_copy;
  impl->content_filter_parameters = params_copy;
  impl->content_filter = parsed_filter;
  impl->content_filter.enabled = true;
  subscription->is_cft_enabled = true;

  return RMW_RET_OK;
}

rmw_ret_t
rmw_subscription_set_on_new_message_callback(
  rmw_subscription_t * subscription,
  rmw_event_callback_t callback,
  const void * user_data)
{
  RMW_CHECK_ARGUMENT_FOR_NULL(subscription, RMW_RET_INVALID_ARGUMENT);
  if (subscription->implementation_identifier != rmw_get_implementation_identifier()) {
    RMW_SET_ERROR_MSG("rmw_subscription_set_on_new_message_callback identifier mismatch");
    return RMW_RET_INCORRECT_RMW_IMPLEMENTATION;
  }

  rmw_hdds_subscription_impl_t * impl =
    (rmw_hdds_subscription_impl_t *)subscription->data;
  if (impl == NULL) {
    RMW_SET_ERROR_MSG("subscription implementation is null");
    return RMW_RET_ERROR;
  }

  impl->message_callback = callback;
  impl->message_user_data = user_data;
  return RMW_RET_OK;
}

rmw_ret_t
rmw_subscription_set_on_new_intra_process_message_callback(
  rmw_subscription_t * subscription,
  rmw_event_callback_t callback,
  const void * user_data)
{
  return rmw_subscription_set_on_new_message_callback(subscription, callback, user_data);
}

rmw_ret_t
rmw_event_set_callback(
  rmw_event_t * event,
  rmw_event_callback_t callback,
  const void * user_data)
{
  RMW_CHECK_ARGUMENT_FOR_NULL(event, RMW_RET_INVALID_ARGUMENT);

  if (event->implementation_identifier != rmw_get_implementation_identifier()) {
    RMW_SET_ERROR_MSG("rmw_event_set_callback identifier mismatch");
    return RMW_RET_INCORRECT_RMW_IMPLEMENTATION;
  }

  rmw_hdds_event_impl_t * impl = (rmw_hdds_event_impl_t *)event->data;
  if (impl == NULL) {
    RMW_SET_ERROR_MSG("event implementation is null");
    return RMW_RET_INVALID_ARGUMENT;
  }

  impl->callback = callback;
  impl->user_data = user_data;
  return RMW_RET_OK;
}

rmw_ret_t
rmw_take_event(
  const rmw_event_t * event_handle,
  void * event_info,
  bool * taken)
{
  RMW_CHECK_ARGUMENT_FOR_NULL(event_handle, RMW_RET_INVALID_ARGUMENT);
  RMW_CHECK_ARGUMENT_FOR_NULL(taken, RMW_RET_INVALID_ARGUMENT);
  *taken = false;

  if (event_handle->implementation_identifier != rmw_get_implementation_identifier()) {
    RMW_SET_ERROR_MSG("rmw_take_event identifier mismatch");
    return RMW_RET_INCORRECT_RMW_IMPLEMENTATION;
  }

  rmw_hdds_event_impl_t * impl = (rmw_hdds_event_impl_t *)event_handle->data;
  if (impl == NULL) {
    return RMW_RET_OK;
  }

  size_t info_size = hdds_event_info_size(impl->event_type);
  if (event_info != NULL && info_size > 0u) {
    memset(event_info, 0, info_size);
  }
  return RMW_RET_OK;
}

rmw_ret_t
rmw_event_fini(rmw_event_t * event)
{
  RMW_CHECK_ARGUMENT_FOR_NULL(event, RMW_RET_INVALID_ARGUMENT);

  if (event->implementation_identifier != rmw_get_implementation_identifier()) {
    RMW_SET_ERROR_MSG("rmw_event_fini identifier mismatch");
    return RMW_RET_INCORRECT_RMW_IMPLEMENTATION;
  }

  if (event->data != NULL) {
    rcutils_allocator_t allocator = rcutils_get_default_allocator();
    allocator.deallocate(event->data, allocator.state);
    event->data = NULL;
  }

  event->implementation_identifier = NULL;
  event->event_type = RMW_EVENT_INVALID;
  return RMW_RET_OK;
}

rmw_ret_t
rmw_take_loaned_message(
  const rmw_subscription_t * subscription,
  void ** loaned_message,
  bool * taken,
  rmw_subscription_allocation_t * allocation)
{
  RMW_CHECK_ARGUMENT_FOR_NULL(subscription, RMW_RET_INVALID_ARGUMENT);
  RMW_CHECK_ARGUMENT_FOR_NULL(loaned_message, RMW_RET_INVALID_ARGUMENT);
  RMW_CHECK_ARGUMENT_FOR_NULL(taken, RMW_RET_INVALID_ARGUMENT);

  *loaned_message = NULL;
  *taken = false;

  if (subscription->implementation_identifier != rmw_get_implementation_identifier()) {
    RMW_SET_ERROR_MSG("rmw_take_loaned_message identifier mismatch");
    return RMW_RET_INCORRECT_RMW_IMPLEMENTATION;
  }

  const rmw_hdds_subscription_impl_t * impl =
    (const rmw_hdds_subscription_impl_t *)subscription->data;
  if (impl == NULL || impl->type_support == NULL) {
    RMW_SET_ERROR_MSG("subscription implementation is null");
    return RMW_RET_ERROR;
  }

  const rosidl_typesupport_introspection_c__MessageMembers * members =
    get_introspection_message_members(impl->type_support);
  if (members == NULL) {
    RMW_SET_ERROR_MSG("introspection type support unavailable");
    return RMW_RET_UNSUPPORTED;
  }

  rcutils_allocator_t allocator = rcutils_get_default_allocator();
  void * msg = allocate_message(members, allocator);
  if (msg == NULL) {
    return RMW_RET_BAD_ALLOC;
  }

  rmw_ret_t ret = rmw_take(subscription, msg, taken, allocation);
  if (ret != RMW_RET_OK || !*taken) {
    free_message(msg, members, allocator);
    return ret;
  }

  *loaned_message = msg;
  return RMW_RET_OK;
}

rmw_ret_t
rmw_return_loaned_message_from_subscription(
  const rmw_subscription_t * subscription,
  void * loaned_message)
{
  RMW_CHECK_ARGUMENT_FOR_NULL(subscription, RMW_RET_INVALID_ARGUMENT);
  RMW_CHECK_ARGUMENT_FOR_NULL(loaned_message, RMW_RET_INVALID_ARGUMENT);

  if (subscription->implementation_identifier != rmw_get_implementation_identifier()) {
    RMW_SET_ERROR_MSG("rmw_return_loaned_message_from_subscription identifier mismatch");
    return RMW_RET_INCORRECT_RMW_IMPLEMENTATION;
  }

  const rmw_hdds_subscription_impl_t * impl =
    (const rmw_hdds_subscription_impl_t *)subscription->data;
  if (impl == NULL || impl->type_support == NULL) {
    RMW_SET_ERROR_MSG("subscription implementation is null");
    return RMW_RET_ERROR;
  }

  const rosidl_typesupport_introspection_c__MessageMembers * members =
    get_introspection_message_members(impl->type_support);
  if (members == NULL) {
    RMW_SET_ERROR_MSG("introspection type support unavailable");
    return RMW_RET_ERROR;
  }

  rcutils_allocator_t allocator = rcutils_get_default_allocator();
  free_message(loaned_message, members, allocator);
  return RMW_RET_OK;
}

rmw_ret_t
rmw_take_with_info(
  const rmw_subscription_t * subscription,
  void * ros_message,
  bool * taken,
  rmw_message_info_t * message_info,
  rmw_subscription_allocation_t * allocation)
{
  RMW_CHECK_ARGUMENT_FOR_NULL(subscription, RMW_RET_INVALID_ARGUMENT);
  RMW_CHECK_ARGUMENT_FOR_NULL(ros_message, RMW_RET_INVALID_ARGUMENT);
  RMW_CHECK_ARGUMENT_FOR_NULL(taken, RMW_RET_INVALID_ARGUMENT);

  rmw_ret_t ret = rmw_take(subscription, ros_message, taken, allocation);
  if (ret != RMW_RET_OK || !taken || !*taken) {
    return ret;
  }

  if (message_info != NULL) {
    memset(message_info, 0, sizeof(*message_info));
    message_info->publication_sequence_number = RMW_MESSAGE_INFO_SEQUENCE_NUMBER_UNSUPPORTED;
    message_info->reception_sequence_number = RMW_MESSAGE_INFO_SEQUENCE_NUMBER_UNSUPPORTED;
    message_info->from_intra_process = false;
  }

  return RMW_RET_OK;
}

rmw_ret_t
rmw_take_loaned_message_with_info(
  const rmw_subscription_t * subscription,
  void ** loaned_message,
  bool * taken,
  rmw_message_info_t * message_info,
  rmw_subscription_allocation_t * allocation)
{
  rmw_ret_t ret = rmw_take_loaned_message(subscription, loaned_message, taken, allocation);
  if (ret != RMW_RET_OK || !taken || !*taken) {
    return ret;
  }

  if (message_info != NULL) {
    memset(message_info, 0, sizeof(*message_info));
    message_info->publication_sequence_number = RMW_MESSAGE_INFO_SEQUENCE_NUMBER_UNSUPPORTED;
    message_info->reception_sequence_number = RMW_MESSAGE_INFO_SEQUENCE_NUMBER_UNSUPPORTED;
    message_info->from_intra_process = false;
  }

  return RMW_RET_OK;
}

// rmw_take_serialized_message and rmw_take_serialized_message_with_info
// are now implemented in rmw_subscription.c

rmw_ret_t
rmw_take_request(
  const rmw_service_t * service,
  rmw_service_info_t * request_header,
  void * ros_request,
  bool * taken)
{
  RMW_CHECK_ARGUMENT_FOR_NULL(service, RMW_RET_INVALID_ARGUMENT);
  RMW_CHECK_ARGUMENT_FOR_NULL(ros_request, RMW_RET_INVALID_ARGUMENT);
  RMW_CHECK_ARGUMENT_FOR_NULL(taken, RMW_RET_INVALID_ARGUMENT);

  *taken = false;

  if (service->implementation_identifier != rmw_get_implementation_identifier()) {
    RMW_SET_ERROR_MSG("rmw_take_request identifier mismatch");
    return RMW_RET_INCORRECT_RMW_IMPLEMENTATION;
  }

  rmw_hdds_service_impl_t * impl =
    (rmw_hdds_service_impl_t *)service->data;
  if (impl == NULL || impl->request_reader == NULL) {
    RMW_SET_ERROR_MSG("invalid service implementation");
    return RMW_RET_ERROR;
  }
  if (impl->request_type_support == NULL) {
    RMW_SET_ERROR_MSG("service request type support unavailable");
    return RMW_RET_UNSUPPORTED;
  }

  rcutils_allocator_t allocator = rcutils_get_default_allocator();
  size_t buffer_capacity = HDDS_SERVICE_HEADER_LEN + 1024u;
  uint8_t * buffer = (uint8_t *)allocator.allocate(buffer_capacity, allocator.state);
  if (buffer == NULL) {
    RMW_SET_ERROR_MSG("failed to allocate request buffer");
    return RMW_RET_BAD_ALLOC;
  }

  size_t data_len = 0u;
  while (true) {
    HddsError take_status = hdds_reader_take(
      impl->request_reader,
      buffer,
      buffer_capacity,
      &data_len);

    if (take_status == OK) {
      break;
    }
    if (take_status == NOT_FOUND) {
      allocator.deallocate(buffer, allocator.state);
      *taken = false;
      return RMW_RET_OK;
    }
    if (take_status == OUT_OF_MEMORY) {
      uint8_t * new_buffer = NULL;
      if (allocator.reallocate != NULL) {
        new_buffer = (uint8_t *)allocator.reallocate(
          buffer,
          data_len,
          allocator.state);
      } else {
        new_buffer = (uint8_t *)allocator.allocate(data_len, allocator.state);
        if (new_buffer != NULL) {
          allocator.deallocate(buffer, allocator.state);
        }
      }
      if (new_buffer == NULL) {
        allocator.deallocate(buffer, allocator.state);
        RMW_SET_ERROR_MSG("failed to grow request buffer");
        return RMW_RET_BAD_ALLOC;
      }
      buffer = new_buffer;
      buffer_capacity = data_len;
      continue;
    }

    allocator.deallocate(buffer, allocator.state);
    RMW_SET_ERROR_MSG("failed to take service request");
    return RMW_RET_ERROR;
  }

  if (data_len < HDDS_SERVICE_HEADER_LEN) {
    allocator.deallocate(buffer, allocator.state);
    RMW_SET_ERROR_MSG("service request missing header");
    return RMW_RET_ERROR;
  }

  rmw_request_id_t request_id;
  if (!decode_request_id(buffer, data_len, &request_id)) {
    allocator.deallocate(buffer, allocator.state);
    RMW_SET_ERROR_MSG("failed to decode request header");
    return RMW_RET_ERROR;
  }

  const uint8_t * payload = buffer + HDDS_SERVICE_HEADER_LEN;
  size_t payload_len = data_len - HDDS_SERVICE_HEADER_LEN;

  HddsError deserialize_status = OK;
  if (impl->request_use_dynamic_types && impl->request_type_name != NULL) {
    deserialize_status = hdds_rmw_deserialize_dynamic(
      impl->request_type_name,
      payload,
      payload_len,
      ros_request);
  } else {
    deserialize_status = hdds_rmw_deserialize_ros_message(
      impl->request_type_support,
      payload,
      payload_len,
      ros_request);
  }

  allocator.deallocate(buffer, allocator.state);

  if (deserialize_status != OK) {
    RMW_SET_ERROR_MSG("failed to deserialize service request");
    return map_hdds_api_error(deserialize_status);
  }

  if (request_header != NULL) {
    memset(request_header, 0, sizeof(*request_header));
    request_header->request_id = request_id;
  }

  *taken = true;
  return RMW_RET_OK;
}

rmw_ret_t
rmw_take_response(
  const rmw_client_t * client,
  rmw_service_info_t * request_header,
  void * ros_response,
  bool * taken)
{
  RMW_CHECK_ARGUMENT_FOR_NULL(client, RMW_RET_INVALID_ARGUMENT);
  RMW_CHECK_ARGUMENT_FOR_NULL(ros_response, RMW_RET_INVALID_ARGUMENT);
  RMW_CHECK_ARGUMENT_FOR_NULL(taken, RMW_RET_INVALID_ARGUMENT);

  *taken = false;

  if (client->implementation_identifier != rmw_get_implementation_identifier()) {
    RMW_SET_ERROR_MSG("rmw_take_response identifier mismatch");
    return RMW_RET_INCORRECT_RMW_IMPLEMENTATION;
  }

  rmw_hdds_client_impl_t * impl =
    (rmw_hdds_client_impl_t *)client->data;
  if (impl == NULL || impl->response_reader == NULL) {
    RMW_SET_ERROR_MSG("invalid client implementation");
    return RMW_RET_ERROR;
  }
  if (impl->response_type_support == NULL) {
    RMW_SET_ERROR_MSG("client response type support unavailable");
    return RMW_RET_UNSUPPORTED;
  }

  rcutils_allocator_t allocator = rcutils_get_default_allocator();
  size_t buffer_capacity = HDDS_SERVICE_HEADER_LEN + 1024u;
  uint8_t * buffer = (uint8_t *)allocator.allocate(buffer_capacity, allocator.state);
  if (buffer == NULL) {
    RMW_SET_ERROR_MSG("failed to allocate response buffer");
    return RMW_RET_BAD_ALLOC;
  }

  size_t data_len = 0u;
  while (true) {
    HddsError take_status = hdds_reader_take(
      impl->response_reader,
      buffer,
      buffer_capacity,
      &data_len);

    if (take_status == OK) {
      break;
    }
    if (take_status == NOT_FOUND) {
      allocator.deallocate(buffer, allocator.state);
      *taken = false;
      return RMW_RET_OK;
    }
    if (take_status == OUT_OF_MEMORY) {
      uint8_t * new_buffer = NULL;
      if (allocator.reallocate != NULL) {
        new_buffer = (uint8_t *)allocator.reallocate(
          buffer,
          data_len,
          allocator.state);
      } else {
        new_buffer = (uint8_t *)allocator.allocate(data_len, allocator.state);
        if (new_buffer != NULL) {
          allocator.deallocate(buffer, allocator.state);
        }
      }
      if (new_buffer == NULL) {
        allocator.deallocate(buffer, allocator.state);
        RMW_SET_ERROR_MSG("failed to grow response buffer");
        return RMW_RET_BAD_ALLOC;
      }
      buffer = new_buffer;
      buffer_capacity = data_len;
      continue;
    }

    allocator.deallocate(buffer, allocator.state);
    RMW_SET_ERROR_MSG("failed to take service response");
    return RMW_RET_ERROR;
  }

  if (data_len < HDDS_SERVICE_HEADER_LEN) {
    allocator.deallocate(buffer, allocator.state);
    RMW_SET_ERROR_MSG("service response missing header");
    return RMW_RET_ERROR;
  }

  rmw_request_id_t request_id;
  if (!decode_request_id(buffer, data_len, &request_id)) {
    allocator.deallocate(buffer, allocator.state);
    RMW_SET_ERROR_MSG("failed to decode response header");
    return RMW_RET_ERROR;
  }

  const uint8_t * payload = buffer + HDDS_SERVICE_HEADER_LEN;
  size_t payload_len = data_len - HDDS_SERVICE_HEADER_LEN;

  HddsError deserialize_status = OK;
  if (impl->response_use_dynamic_types && impl->response_type_name != NULL) {
    deserialize_status = hdds_rmw_deserialize_dynamic(
      impl->response_type_name,
      payload,
      payload_len,
      ros_response);
  } else {
    deserialize_status = hdds_rmw_deserialize_ros_message(
      impl->response_type_support,
      payload,
      payload_len,
      ros_response);
  }

  allocator.deallocate(buffer, allocator.state);

  if (deserialize_status != OK) {
    RMW_SET_ERROR_MSG("failed to deserialize service response");
    return map_hdds_api_error(deserialize_status);
  }

  if (request_header != NULL) {
    memset(request_header, 0, sizeof(*request_header));
    request_header->request_id = request_id;
  }

  *taken = true;
  return RMW_RET_OK;
}

rmw_ret_t
rmw_send_request(
  const rmw_client_t * client,
  const void * ros_request,
  int64_t * sequence_id)
{
  RMW_CHECK_ARGUMENT_FOR_NULL(client, RMW_RET_INVALID_ARGUMENT);
  RMW_CHECK_ARGUMENT_FOR_NULL(ros_request, RMW_RET_INVALID_ARGUMENT);

  if (client->implementation_identifier != rmw_get_implementation_identifier()) {
    RMW_SET_ERROR_MSG("rmw_send_request identifier mismatch");
    return RMW_RET_INCORRECT_RMW_IMPLEMENTATION;
  }

  rmw_hdds_client_impl_t * impl =
    (rmw_hdds_client_impl_t *)client->data;
  if (impl == NULL || impl->request_writer == NULL) {
    RMW_SET_ERROR_MSG("invalid client implementation");
    return RMW_RET_ERROR;
  }
  if (impl->request_type_support == NULL) {
    RMW_SET_ERROR_MSG("client request type support unavailable");
    return RMW_RET_UNSUPPORTED;
  }

  rmw_request_id_t request_id;
  memcpy(request_id.writer_guid, impl->writer_guid, sizeof(request_id.writer_guid));
  request_id.sequence_number = impl->next_sequence++;
  if (request_id.sequence_number == 0) {
    request_id.sequence_number = impl->next_sequence++;
  }

  if (sequence_id != NULL) {
    *sequence_id = request_id.sequence_number;
  }

  rcutils_allocator_t allocator = rcutils_get_default_allocator();
  size_t payload_capacity = 1024u;
  size_t buffer_capacity = HDDS_SERVICE_HEADER_LEN + payload_capacity;
  uint8_t * buffer = (uint8_t *)allocator.allocate(buffer_capacity, allocator.state);
  if (buffer == NULL) {
    RMW_SET_ERROR_MSG("failed to allocate request buffer");
    return RMW_RET_BAD_ALLOC;
  }

  size_t payload_len = 0u;
  while (true) {
    HddsError serialize_status = hdds_rmw_serialize_ros_message(
      impl->request_type_support,
      ros_request,
      buffer + HDDS_SERVICE_HEADER_LEN,
      payload_capacity,
      &payload_len);

    if (serialize_status == OK) {
      break;
    }

    if (serialize_status == OUT_OF_MEMORY) {
      payload_capacity = payload_len;
      size_t new_capacity = HDDS_SERVICE_HEADER_LEN + payload_capacity;
      uint8_t * new_buffer = NULL;
      if (allocator.reallocate != NULL) {
        new_buffer = (uint8_t *)allocator.reallocate(
          buffer,
          new_capacity,
          allocator.state);
      } else {
        new_buffer = (uint8_t *)allocator.allocate(new_capacity, allocator.state);
        if (new_buffer != NULL) {
          allocator.deallocate(buffer, allocator.state);
        }
      }
      if (new_buffer == NULL) {
        allocator.deallocate(buffer, allocator.state);
        RMW_SET_ERROR_MSG("failed to grow request buffer");
        return RMW_RET_BAD_ALLOC;
      }
      buffer = new_buffer;
      buffer_capacity = new_capacity;
      continue;
    }

    allocator.deallocate(buffer, allocator.state);
    RMW_SET_ERROR_MSG("failed to serialize service request");
    return map_hdds_api_error(serialize_status);
  }

  encode_request_id(&request_id, buffer);
  size_t total_len = HDDS_SERVICE_HEADER_LEN + payload_len;

  HddsError write_status = hdds_writer_write(
    impl->request_writer,
    buffer,
    total_len);

  allocator.deallocate(buffer, allocator.state);

  if (write_status != OK) {
    RMW_SET_ERROR_MSG("failed to publish service request");
    return map_hdds_api_error(write_status);
  }

  return RMW_RET_OK;
}

rmw_ret_t
rmw_send_response(
  const rmw_service_t * service,
  rmw_request_id_t * request_header,
  void * ros_response)
{
  RMW_CHECK_ARGUMENT_FOR_NULL(service, RMW_RET_INVALID_ARGUMENT);
  RMW_CHECK_ARGUMENT_FOR_NULL(request_header, RMW_RET_INVALID_ARGUMENT);
  RMW_CHECK_ARGUMENT_FOR_NULL(ros_response, RMW_RET_INVALID_ARGUMENT);

  if (service->implementation_identifier != rmw_get_implementation_identifier()) {
    RMW_SET_ERROR_MSG("rmw_send_response identifier mismatch");
    return RMW_RET_INCORRECT_RMW_IMPLEMENTATION;
  }

  rmw_hdds_service_impl_t * impl =
    (rmw_hdds_service_impl_t *)service->data;
  if (impl == NULL || impl->response_writer == NULL) {
    RMW_SET_ERROR_MSG("invalid service implementation");
    return RMW_RET_ERROR;
  }
  if (impl->response_type_support == NULL) {
    RMW_SET_ERROR_MSG("service response type support unavailable");
    return RMW_RET_UNSUPPORTED;
  }

  if (request_header->sequence_number <= 0) {
    RMW_SET_ERROR_MSG("invalid request header sequence number");
    return RMW_RET_INVALID_ARGUMENT;
  }
  bool guid_nonzero = false;
  for (size_t idx = 0u; idx < sizeof(request_header->writer_guid); ++idx) {
    if (request_header->writer_guid[idx] != 0u) {
      guid_nonzero = true;
      break;
    }
  }
  if (!guid_nonzero) {
    RMW_SET_ERROR_MSG("invalid request header writer_guid");
    return RMW_RET_INVALID_ARGUMENT;
  }

  rcutils_allocator_t allocator = rcutils_get_default_allocator();
  size_t payload_capacity = 1024u;
  size_t buffer_capacity = HDDS_SERVICE_HEADER_LEN + payload_capacity;
  uint8_t * buffer = (uint8_t *)allocator.allocate(buffer_capacity, allocator.state);
  if (buffer == NULL) {
    RMW_SET_ERROR_MSG("failed to allocate response buffer");
    return RMW_RET_BAD_ALLOC;
  }

  size_t payload_len = 0u;
  while (true) {
    HddsError serialize_status = hdds_rmw_serialize_ros_message(
      impl->response_type_support,
      ros_response,
      buffer + HDDS_SERVICE_HEADER_LEN,
      payload_capacity,
      &payload_len);

    if (serialize_status == OK) {
      break;
    }

    if (serialize_status == OUT_OF_MEMORY) {
      payload_capacity = payload_len;
      size_t new_capacity = HDDS_SERVICE_HEADER_LEN + payload_capacity;
      uint8_t * new_buffer = NULL;
      if (allocator.reallocate != NULL) {
        new_buffer = (uint8_t *)allocator.reallocate(
          buffer,
          new_capacity,
          allocator.state);
      } else {
        new_buffer = (uint8_t *)allocator.allocate(new_capacity, allocator.state);
        if (new_buffer != NULL) {
          allocator.deallocate(buffer, allocator.state);
        }
      }
      if (new_buffer == NULL) {
        allocator.deallocate(buffer, allocator.state);
        RMW_SET_ERROR_MSG("failed to grow response buffer");
        return RMW_RET_BAD_ALLOC;
      }
      buffer = new_buffer;
      buffer_capacity = new_capacity;
      continue;
    }

    allocator.deallocate(buffer, allocator.state);
    RMW_SET_ERROR_MSG("failed to serialize service response");
    return map_hdds_api_error(serialize_status);
  }

  encode_request_id(request_header, buffer);
  size_t total_len = HDDS_SERVICE_HEADER_LEN + payload_len;

  HddsError write_status = hdds_writer_write(
    impl->response_writer,
    buffer,
    total_len);

  allocator.deallocate(buffer, allocator.state);

  if (write_status != OK) {
    RMW_SET_ERROR_MSG("failed to publish service response");
    return map_hdds_api_error(write_status);
  }

  return RMW_RET_OK;
}

rmw_ret_t
rmw_serialize(
  const void * ros_message,
  const rosidl_message_type_support_t * type_support,
  rmw_serialized_message_t * serialized_message)
{
  RMW_CHECK_ARGUMENT_FOR_NULL(ros_message, RMW_RET_INVALID_ARGUMENT);
  RMW_CHECK_ARGUMENT_FOR_NULL(type_support, RMW_RET_INVALID_ARGUMENT);
  RMW_CHECK_ARGUMENT_FOR_NULL(serialized_message, RMW_RET_INVALID_ARGUMENT);

  size_t required_len = 0u;
  HddsError hdds_status = hdds_rmw_serialize_ros_message(
    type_support,
    ros_message,
    serialized_message->buffer,
    serialized_message->buffer_capacity,
    &required_len);

  if (hdds_status == OK) {
    serialized_message->buffer_length = required_len;
    return RMW_RET_OK;
  }

  if (hdds_status != OUT_OF_MEMORY) {
    RMW_SET_ERROR_MSG("failed to serialize ROS message");
    return map_hdds_api_error(hdds_status);
  }

  rcutils_allocator_t allocator = serialized_message->allocator;
  if (!rcutils_allocator_is_valid(&allocator)) {
    if (serialized_message->buffer != NULL || serialized_message->buffer_capacity != 0u) {
      RMW_SET_ERROR_MSG("serialized_message allocator is invalid");
      return RMW_RET_INVALID_ARGUMENT;
    }
    allocator = rcutils_get_default_allocator();
    serialized_message->allocator = allocator;
  }

  rcutils_ret_t resize_ret;
  if (serialized_message->buffer == NULL && serialized_message->buffer_capacity == 0u) {
    resize_ret = rcutils_uint8_array_init(serialized_message, required_len, &allocator);
  } else {
    resize_ret = rcutils_uint8_array_resize(serialized_message, required_len);
  }

  if (resize_ret != RCUTILS_RET_OK) {
    RMW_SET_ERROR_MSG("failed to resize serialized message buffer");
    return rmw_convert_rcutils_ret_to_rmw_ret(resize_ret);
  }

  hdds_status = hdds_rmw_serialize_ros_message(
    type_support,
    ros_message,
    serialized_message->buffer,
    serialized_message->buffer_capacity,
    &required_len);

  if (hdds_status != OK) {
    RMW_SET_ERROR_MSG("failed to serialize ROS message");
    return map_hdds_api_error(hdds_status);
  }

  serialized_message->buffer_length = required_len;
  return RMW_RET_OK;
}

rmw_ret_t
rmw_deserialize(
  const rmw_serialized_message_t * serialized_message,
  const rosidl_message_type_support_t * type_support,
  void * ros_message)
{
  RMW_CHECK_ARGUMENT_FOR_NULL(serialized_message, RMW_RET_INVALID_ARGUMENT);
  RMW_CHECK_ARGUMENT_FOR_NULL(type_support, RMW_RET_INVALID_ARGUMENT);
  RMW_CHECK_ARGUMENT_FOR_NULL(ros_message, RMW_RET_INVALID_ARGUMENT);

  if (serialized_message->buffer_length > 0u && serialized_message->buffer == NULL) {
    RMW_SET_ERROR_MSG("serialized_message buffer is null");
    return RMW_RET_INVALID_ARGUMENT;
  }

  HddsError hdds_status = hdds_rmw_deserialize_ros_message(
    type_support,
    serialized_message->buffer,
    serialized_message->buffer_length,
    ros_message);
  if (hdds_status != OK) {
    RMW_SET_ERROR_MSG("failed to deserialize ROS message");
  }
  return map_hdds_api_error(hdds_status);
}

rmw_service_t *
rmw_create_service(
  const rmw_node_t * node,
  const rosidl_service_type_support_t * type_support,
  const char * service_name,
  const rmw_qos_profile_t * qos_profile)
{
  RMW_CHECK_ARGUMENT_FOR_NULL(node, NULL);
  RMW_CHECK_ARGUMENT_FOR_NULL(type_support, NULL);
  RMW_CHECK_ARGUMENT_FOR_NULL(service_name, NULL);
  if (node->implementation_identifier != rmw_get_implementation_identifier()) {
    RMW_SET_ERROR_MSG("rmw_create_service identifier mismatch");
    return NULL;
  }

  const rmw_hdds_node_impl_t * node_impl =
    (const rmw_hdds_node_impl_t *)node->data;
  if (node_impl == NULL || node_impl->context == NULL) {
    RMW_SET_ERROR_MSG("invalid node implementation");
    return NULL;
  }

  rcutils_allocator_t allocator = select_node_allocator(node_impl);
  const rmw_qos_profile_t * effective_qos =
    qos_profile != NULL ? qos_profile : &rmw_qos_profile_services_default;

  bool has_introspection = true;
  const rosidl_service_type_support_t * introspection_ts =
    get_introspection_service_support(type_support);
  const rosidl_typesupport_introspection_c__ServiceMembers * svc_members = NULL;
  if (introspection_ts == NULL || introspection_ts->data == NULL) {
    has_introspection = false;
    if (rcutils_error_is_set()) {
      RCUTILS_LOG_DEBUG_NAMED(
        "rmw_hdds",
        "Clearing error state after missing service introspection for '%s'",
        service_name);
      rcutils_reset_error();
    }
    RCUTILS_LOG_WARN_NAMED(
      "rmw_hdds",
      "Service introspection type support unavailable for '%s'; requests/responses will be unsupported",
      service_name);
  } else {
    svc_members =
      (const rosidl_typesupport_introspection_c__ServiceMembers *)introspection_ts->data;
    if (svc_members->request_members_ == NULL || svc_members->response_members_ == NULL) {
      RMW_SET_ERROR_MSG("service introspection members missing");
      return NULL;
    }
  }

  char * request_topic = create_service_topic(service_name, "rq", allocator);
  char * response_topic = create_service_topic(service_name, "rr", allocator);
  if (request_topic == NULL || response_topic == NULL) {
    if (request_topic != NULL) {
      allocator.deallocate(request_topic, allocator.state);
    }
    if (response_topic != NULL) {
      allocator.deallocate(response_topic, allocator.state);
    }
    RMW_SET_ERROR_MSG("failed to build service topics");
    return NULL;
  }

  const rosidl_message_type_support_t * request_ts = NULL;
  const rosidl_message_type_support_t * response_ts = NULL;
  char * request_type_name = NULL;
  char * response_type_name = NULL;

  if (has_introspection) {
    request_ts = create_message_type_support(
      svc_members->request_members_, allocator);
    response_ts = create_message_type_support(
      svc_members->response_members_, allocator);
    if (request_ts == NULL || response_ts == NULL) {
      if (request_ts != NULL) {
        allocator.deallocate((void *)request_ts, allocator.state);
      }
      if (response_ts != NULL) {
        allocator.deallocate((void *)response_ts, allocator.state);
      }
      allocator.deallocate(request_topic, allocator.state);
      allocator.deallocate(response_topic, allocator.state);
      RMW_SET_ERROR_MSG("failed to create service type supports");
      return NULL;
    }

    request_type_name =
      extract_type_name_from_members(svc_members->request_members_, allocator);
    response_type_name =
      extract_type_name_from_members(svc_members->response_members_, allocator);

    rmw_hdds_error_t bind_req_status = rmw_hdds_context_bind_topic_type(
      node_impl->context->native_ctx,
      request_topic,
      request_ts);
    if (bind_req_status != RMW_HDDS_ERROR_OK) {
      allocator.deallocate((void *)request_ts, allocator.state);
      allocator.deallocate((void *)response_ts, allocator.state);
      if (request_type_name != NULL) {
        allocator.deallocate(request_type_name, allocator.state);
      }
      if (response_type_name != NULL) {
        allocator.deallocate(response_type_name, allocator.state);
      }
      allocator.deallocate(request_topic, allocator.state);
      allocator.deallocate(response_topic, allocator.state);
      RMW_SET_ERROR_MSG("failed to bind request topic type");
      return NULL;
    }

    rmw_hdds_error_t bind_resp_status = rmw_hdds_context_bind_topic_type(
      node_impl->context->native_ctx,
      response_topic,
      response_ts);
    if (bind_resp_status != RMW_HDDS_ERROR_OK) {
      allocator.deallocate((void *)request_ts, allocator.state);
      allocator.deallocate((void *)response_ts, allocator.state);
      if (request_type_name != NULL) {
        allocator.deallocate(request_type_name, allocator.state);
      }
      if (response_type_name != NULL) {
        allocator.deallocate(response_type_name, allocator.state);
      }
      allocator.deallocate(request_topic, allocator.state);
      allocator.deallocate(response_topic, allocator.state);
      RMW_SET_ERROR_MSG("failed to bind response topic type");
      return NULL;
    }
  }

  struct HddsDataReader * request_reader = NULL;
  struct HddsQoS * service_qos = rmw_hdds_qos_from_profile(effective_qos);
  rmw_hdds_error_t reader_status;
  if (service_qos != NULL) {
    reader_status = rmw_hdds_context_create_reader_with_qos(
      node_impl->context->native_ctx,
      request_topic,
      service_qos,
      &request_reader);
  } else {
    reader_status = rmw_hdds_context_create_reader(
      node_impl->context->native_ctx,
      request_topic,
      &request_reader);
  }
  if (reader_status != RMW_HDDS_ERROR_OK || request_reader == NULL) {
    rmw_hdds_qos_destroy(service_qos);
    allocator.deallocate((void *)request_ts, allocator.state);
    allocator.deallocate((void *)response_ts, allocator.state);
    if (request_type_name != NULL) {
      allocator.deallocate(request_type_name, allocator.state);
    }
    if (response_type_name != NULL) {
      allocator.deallocate(response_type_name, allocator.state);
    }
    allocator.deallocate(request_topic, allocator.state);
    allocator.deallocate(response_topic, allocator.state);
    RMW_SET_ERROR_MSG("failed to create request reader");
    return NULL;
  }

  uint64_t request_key = 0;
  rmw_hdds_error_t attach_status = rmw_hdds_context_attach_reader(
    node_impl->context->native_ctx,
    request_reader,
    &request_key);
  if (attach_status != RMW_HDDS_ERROR_OK) {
    rmw_hdds_context_destroy_reader(node_impl->context->native_ctx, request_reader);
    allocator.deallocate((void *)request_ts, allocator.state);
    allocator.deallocate((void *)response_ts, allocator.state);
    if (request_type_name != NULL) {
      allocator.deallocate(request_type_name, allocator.state);
    }
    if (response_type_name != NULL) {
      allocator.deallocate(response_type_name, allocator.state);
    }
    allocator.deallocate(request_topic, allocator.state);
    allocator.deallocate(response_topic, allocator.state);
    RMW_SET_ERROR_MSG("failed to attach request reader");
    return NULL;
  }
  (void)request_key;

  struct HddsDataWriter * response_writer = NULL;
  rmw_hdds_error_t writer_status;
  if (service_qos != NULL) {
    writer_status = rmw_hdds_context_create_writer_with_qos(
      node_impl->context->native_ctx,
      response_topic,
      service_qos,
      &response_writer);
  } else {
    writer_status = rmw_hdds_context_create_writer(
      node_impl->context->native_ctx,
      response_topic,
      &response_writer);
  }
  rmw_hdds_qos_destroy(service_qos);
  if (writer_status != RMW_HDDS_ERROR_OK || response_writer == NULL) {
    rmw_hdds_context_destroy_reader(node_impl->context->native_ctx, request_reader);
    allocator.deallocate((void *)request_ts, allocator.state);
    allocator.deallocate((void *)response_ts, allocator.state);
    if (request_type_name != NULL) {
      allocator.deallocate(request_type_name, allocator.state);
    }
    if (response_type_name != NULL) {
      allocator.deallocate(response_type_name, allocator.state);
    }
    allocator.deallocate(request_topic, allocator.state);
    allocator.deallocate(response_topic, allocator.state);
    RMW_SET_ERROR_MSG("failed to create response writer");
    return NULL;
  }

  bool request_registered = false;
  bool response_registered = false;
  rmw_hdds_qos_profile_t endpoint_qos = rmw_hdds_qos_profile_from_rmw(effective_qos);
  if (request_ts != NULL) {
    uint8_t request_gid[RMW_GID_STORAGE_SIZE];
    rmw_hdds_gid_from_ptr(request_gid, request_reader, node_impl->context->native_ctx);
    rmw_hdds_error_t register_req = rmw_hdds_context_register_subscription_endpoint(
      node_impl->context->native_ctx,
      node_impl->name,
      node_impl->namespace_,
      request_topic,
      request_ts,
      request_gid,
      &endpoint_qos);
    if (register_req != RMW_HDDS_ERROR_OK) {
      rmw_hdds_context_destroy_writer(node_impl->context->native_ctx, response_writer);
      rmw_hdds_context_destroy_reader(node_impl->context->native_ctx, request_reader);
      allocator.deallocate((void *)request_ts, allocator.state);
      allocator.deallocate((void *)response_ts, allocator.state);
      if (request_type_name != NULL) {
        allocator.deallocate(request_type_name, allocator.state);
      }
      if (response_type_name != NULL) {
        allocator.deallocate(response_type_name, allocator.state);
      }
      allocator.deallocate(request_topic, allocator.state);
      allocator.deallocate(response_topic, allocator.state);
      RMW_SET_ERROR_MSG("failed to register request endpoint");
      return NULL;
    }
    request_registered = true;
  }

  if (response_ts != NULL) {
    uint8_t response_gid[RMW_GID_STORAGE_SIZE];
    rmw_hdds_gid_from_ptr(response_gid, response_writer, node_impl->context->native_ctx);
    rmw_hdds_error_t register_resp = rmw_hdds_context_register_publisher_endpoint(
      node_impl->context->native_ctx,
      node_impl->name,
      node_impl->namespace_,
      response_topic,
      response_ts,
      response_gid,
      &endpoint_qos);
    if (register_resp != RMW_HDDS_ERROR_OK) {
      if (request_registered) {
        uint8_t request_gid[RMW_GID_STORAGE_SIZE];
        rmw_hdds_gid_from_ptr(request_gid, request_reader, node_impl->context->native_ctx);
        (void)rmw_hdds_context_unregister_subscription_endpoint(
          node_impl->context->native_ctx,
          node_impl->name,
          node_impl->namespace_,
          request_topic,
          request_gid);
      }
      rmw_hdds_context_destroy_writer(node_impl->context->native_ctx, response_writer);
      rmw_hdds_context_destroy_reader(node_impl->context->native_ctx, request_reader);
      allocator.deallocate((void *)request_ts, allocator.state);
      allocator.deallocate((void *)response_ts, allocator.state);
      if (request_type_name != NULL) {
        allocator.deallocate(request_type_name, allocator.state);
      }
      if (response_type_name != NULL) {
        allocator.deallocate(response_type_name, allocator.state);
      }
      allocator.deallocate(request_topic, allocator.state);
      allocator.deallocate(response_topic, allocator.state);
      RMW_SET_ERROR_MSG("failed to register response endpoint");
      return NULL;
    }
    response_registered = true;
  }

  rmw_service_t * service =
    (rmw_service_t *)allocator.allocate(sizeof(rmw_service_t), allocator.state);
  if (service == NULL) {
    if (response_registered) {
      uint8_t response_gid[RMW_GID_STORAGE_SIZE];
      rmw_hdds_gid_from_ptr(response_gid, response_writer, node_impl->context->native_ctx);
      (void)rmw_hdds_context_unregister_publisher_endpoint(
        node_impl->context->native_ctx,
        node_impl->name,
        node_impl->namespace_,
        response_topic,
        response_gid);
    }
    if (request_registered) {
      uint8_t request_gid[RMW_GID_STORAGE_SIZE];
      rmw_hdds_gid_from_ptr(request_gid, request_reader, node_impl->context->native_ctx);
      (void)rmw_hdds_context_unregister_subscription_endpoint(
        node_impl->context->native_ctx,
        node_impl->name,
        node_impl->namespace_,
        request_topic,
        request_gid);
    }
    rmw_hdds_context_destroy_writer(node_impl->context->native_ctx, response_writer);
    rmw_hdds_context_destroy_reader(node_impl->context->native_ctx, request_reader);
    allocator.deallocate((void *)request_ts, allocator.state);
    allocator.deallocate((void *)response_ts, allocator.state);
    if (request_type_name != NULL) {
      allocator.deallocate(request_type_name, allocator.state);
    }
    if (response_type_name != NULL) {
      allocator.deallocate(response_type_name, allocator.state);
    }
    allocator.deallocate(request_topic, allocator.state);
    allocator.deallocate(response_topic, allocator.state);
    RMW_SET_ERROR_MSG("failed to allocate rmw_service_t");
    return NULL;
  }
  memset(service, 0, sizeof(*service));

  rmw_hdds_service_impl_t * impl =
    (rmw_hdds_service_impl_t *)allocator.allocate(
      sizeof(rmw_hdds_service_impl_t),
      allocator.state);
  if (impl == NULL) {
    allocator.deallocate(service, allocator.state);
    if (response_registered) {
      uint8_t response_gid[RMW_GID_STORAGE_SIZE];
      rmw_hdds_gid_from_ptr(response_gid, response_writer, node_impl->context->native_ctx);
      (void)rmw_hdds_context_unregister_publisher_endpoint(
        node_impl->context->native_ctx,
        node_impl->name,
        node_impl->namespace_,
        response_topic,
        response_gid);
    }
    if (request_registered) {
      uint8_t request_gid[RMW_GID_STORAGE_SIZE];
      rmw_hdds_gid_from_ptr(request_gid, request_reader, node_impl->context->native_ctx);
      (void)rmw_hdds_context_unregister_subscription_endpoint(
        node_impl->context->native_ctx,
        node_impl->name,
        node_impl->namespace_,
        request_topic,
        request_gid);
    }
    rmw_hdds_context_destroy_writer(node_impl->context->native_ctx, response_writer);
    rmw_hdds_context_destroy_reader(node_impl->context->native_ctx, request_reader);
    allocator.deallocate((void *)request_ts, allocator.state);
    allocator.deallocate((void *)response_ts, allocator.state);
    if (request_type_name != NULL) {
      allocator.deallocate(request_type_name, allocator.state);
    }
    if (response_type_name != NULL) {
      allocator.deallocate(response_type_name, allocator.state);
    }
    allocator.deallocate(request_topic, allocator.state);
    allocator.deallocate(response_topic, allocator.state);
    RMW_SET_ERROR_MSG("failed to allocate service implementation");
    return NULL;
  }
  memset(impl, 0, sizeof(*impl));

  char * name_copy = rcutils_strdup(service_name, allocator);
  if (name_copy == NULL) {
    allocator.deallocate(impl, allocator.state);
    allocator.deallocate(service, allocator.state);
    if (response_registered) {
      uint8_t response_gid[RMW_GID_STORAGE_SIZE];
      rmw_hdds_gid_from_ptr(response_gid, response_writer, node_impl->context->native_ctx);
      (void)rmw_hdds_context_unregister_publisher_endpoint(
        node_impl->context->native_ctx,
        node_impl->name,
        node_impl->namespace_,
        response_topic,
        response_gid);
    }
    if (request_registered) {
      uint8_t request_gid[RMW_GID_STORAGE_SIZE];
      rmw_hdds_gid_from_ptr(request_gid, request_reader, node_impl->context->native_ctx);
      (void)rmw_hdds_context_unregister_subscription_endpoint(
        node_impl->context->native_ctx,
        node_impl->name,
        node_impl->namespace_,
        request_topic,
        request_gid);
    }
    rmw_hdds_context_destroy_writer(node_impl->context->native_ctx, response_writer);
    rmw_hdds_context_destroy_reader(node_impl->context->native_ctx, request_reader);
    allocator.deallocate((void *)request_ts, allocator.state);
    allocator.deallocate((void *)response_ts, allocator.state);
    if (request_type_name != NULL) {
      allocator.deallocate(request_type_name, allocator.state);
    }
    if (response_type_name != NULL) {
      allocator.deallocate(response_type_name, allocator.state);
    }
    allocator.deallocate(request_topic, allocator.state);
    allocator.deallocate(response_topic, allocator.state);
    RMW_SET_ERROR_MSG("failed to duplicate service name");
    return NULL;
  }

  impl->context = node_impl->context;
  impl->service_name = name_copy;
  impl->request_topic = request_topic;
  impl->response_topic = response_topic;
  impl->type_support = type_support;
  impl->request_type_support = request_ts;
  impl->response_type_support = response_ts;
  impl->request_type_name = request_type_name;
  impl->response_type_name = response_type_name;
  impl->request_reader = request_reader;
  impl->response_writer = response_writer;
  impl->qos_profile = *effective_qos;
  impl->request_use_dynamic_types =
    request_type_name != NULL && hdds_rmw_has_type_descriptor(request_type_name);
  impl->response_use_dynamic_types =
    response_type_name != NULL && hdds_rmw_has_type_descriptor(response_type_name);
  impl->request_registered_in_graph = request_registered;
  impl->response_registered_in_graph = response_registered;
  impl->request_callback = NULL;
  impl->request_user_data = NULL;

  service->implementation_identifier = rmw_get_implementation_identifier();
  service->data = impl;
  service->service_name = impl->service_name;

  return service;
}

rmw_ret_t
rmw_destroy_service(rmw_node_t * node, rmw_service_t * service)
{
  RMW_CHECK_ARGUMENT_FOR_NULL(node, RMW_RET_INVALID_ARGUMENT);
  RMW_CHECK_ARGUMENT_FOR_NULL(service, RMW_RET_INVALID_ARGUMENT);

  if (node->implementation_identifier != rmw_get_implementation_identifier() ||
    service->implementation_identifier != rmw_get_implementation_identifier())
  {
    RMW_SET_ERROR_MSG("rmw_destroy_service identifier mismatch");
    return RMW_RET_INCORRECT_RMW_IMPLEMENTATION;
  }

  rmw_hdds_node_impl_t * node_impl = (rmw_hdds_node_impl_t *)node->data;
  bool has_context =
    node_impl != NULL && node_impl->context != NULL && node_impl->context->native_ctx != NULL;
  rcutils_allocator_t allocator = select_node_allocator(node_impl);

  rmw_hdds_service_impl_t * impl =
    (rmw_hdds_service_impl_t *)service->data;
  if (impl != NULL) {
    if (impl->response_registered_in_graph && impl->response_topic != NULL && has_context) {
      uint8_t response_gid[RMW_GID_STORAGE_SIZE];
      rmw_hdds_gid_from_ptr(response_gid, impl->response_writer, node_impl->context->native_ctx);
      (void)rmw_hdds_context_unregister_publisher_endpoint(
        node_impl->context->native_ctx,
        node_impl->name,
        node_impl->namespace_,
        impl->response_topic,
        response_gid);
    }
    if (impl->request_registered_in_graph && impl->request_topic != NULL && has_context) {
      uint8_t request_gid[RMW_GID_STORAGE_SIZE];
      rmw_hdds_gid_from_ptr(request_gid, impl->request_reader, node_impl->context->native_ctx);
      (void)rmw_hdds_context_unregister_subscription_endpoint(
        node_impl->context->native_ctx,
        node_impl->name,
        node_impl->namespace_,
        impl->request_topic,
        request_gid);
    }
    if (impl->response_writer != NULL && has_context) {
      (void)rmw_hdds_context_destroy_writer(
        node_impl->context->native_ctx,
        impl->response_writer);
    }
    impl->response_writer = NULL;
    if (impl->request_reader != NULL && has_context) {
      (void)rmw_hdds_context_destroy_reader(
        node_impl->context->native_ctx,
        impl->request_reader);
    }
    impl->request_reader = NULL;
    if (impl->request_type_support != NULL) {
      allocator.deallocate((void *)impl->request_type_support, allocator.state);
      impl->request_type_support = NULL;
    }
    if (impl->response_type_support != NULL) {
      allocator.deallocate((void *)impl->response_type_support, allocator.state);
      impl->response_type_support = NULL;
    }
    if (impl->request_type_name != NULL) {
      allocator.deallocate(impl->request_type_name, allocator.state);
      impl->request_type_name = NULL;
    }
    if (impl->response_type_name != NULL) {
      allocator.deallocate(impl->response_type_name, allocator.state);
      impl->response_type_name = NULL;
    }
    if (impl->request_topic != NULL) {
      allocator.deallocate(impl->request_topic, allocator.state);
      impl->request_topic = NULL;
    }
    if (impl->response_topic != NULL) {
      allocator.deallocate(impl->response_topic, allocator.state);
      impl->response_topic = NULL;
    }
    if (impl->service_name != NULL) {
      allocator.deallocate(impl->service_name, allocator.state);
      impl->service_name = NULL;
    }
    allocator.deallocate(impl, allocator.state);
    service->data = NULL;
  }

  allocator.deallocate(service, allocator.state);
  return RMW_RET_OK;
}

rmw_client_t *
rmw_create_client(
  const rmw_node_t * node,
  const rosidl_service_type_support_t * type_support,
  const char * service_name,
  const rmw_qos_profile_t * qos_profile)
{
  RMW_CHECK_ARGUMENT_FOR_NULL(node, NULL);
  RMW_CHECK_ARGUMENT_FOR_NULL(type_support, NULL);
  RMW_CHECK_ARGUMENT_FOR_NULL(service_name, NULL);

  if (node->implementation_identifier != rmw_get_implementation_identifier()) {
    RMW_SET_ERROR_MSG("rmw_create_client identifier mismatch");
    return NULL;
  }

  const rmw_hdds_node_impl_t * node_impl =
    (const rmw_hdds_node_impl_t *)node->data;
  if (node_impl == NULL || node_impl->context == NULL) {
    RMW_SET_ERROR_MSG("invalid node implementation");
    return NULL;
  }

  rcutils_allocator_t allocator = select_node_allocator(node_impl);
  const rmw_qos_profile_t * effective_qos =
    qos_profile != NULL ? qos_profile : &rmw_qos_profile_services_default;

  bool has_introspection = true;
  const rosidl_service_type_support_t * introspection_ts =
    get_introspection_service_support(type_support);
  const rosidl_typesupport_introspection_c__ServiceMembers * svc_members = NULL;
  if (introspection_ts == NULL || introspection_ts->data == NULL) {
    has_introspection = false;
    if (rcutils_error_is_set()) {
      RCUTILS_LOG_DEBUG_NAMED(
        "rmw_hdds",
        "Clearing error state after missing client introspection for '%s'",
        service_name);
      rcutils_reset_error();
    }
    RCUTILS_LOG_WARN_NAMED(
      "rmw_hdds",
      "Client introspection type support unavailable for '%s'; requests/responses will be unsupported",
      service_name);
  } else {
    svc_members =
      (const rosidl_typesupport_introspection_c__ServiceMembers *)introspection_ts->data;
    if (svc_members->request_members_ == NULL || svc_members->response_members_ == NULL) {
      RMW_SET_ERROR_MSG("service introspection members missing");
      return NULL;
    }
  }

  char * request_topic = create_service_topic(service_name, "rq", allocator);
  char * response_topic = create_service_topic(service_name, "rr", allocator);
  if (request_topic == NULL || response_topic == NULL) {
    if (request_topic != NULL) {
      allocator.deallocate(request_topic, allocator.state);
    }
    if (response_topic != NULL) {
      allocator.deallocate(response_topic, allocator.state);
    }
    RMW_SET_ERROR_MSG("failed to build service topics");
    return NULL;
  }

  const rosidl_message_type_support_t * request_ts = NULL;
  const rosidl_message_type_support_t * response_ts = NULL;
  char * request_type_name = NULL;
  char * response_type_name = NULL;

  if (has_introspection) {
    request_ts = create_message_type_support(
      svc_members->request_members_, allocator);
    response_ts = create_message_type_support(
      svc_members->response_members_, allocator);
    if (request_ts == NULL || response_ts == NULL) {
      if (request_ts != NULL) {
        allocator.deallocate((void *)request_ts, allocator.state);
      }
      if (response_ts != NULL) {
        allocator.deallocate((void *)response_ts, allocator.state);
      }
      allocator.deallocate(request_topic, allocator.state);
      allocator.deallocate(response_topic, allocator.state);
      RMW_SET_ERROR_MSG("failed to create service type supports");
      return NULL;
    }

    request_type_name =
      extract_type_name_from_members(svc_members->request_members_, allocator);
    response_type_name =
      extract_type_name_from_members(svc_members->response_members_, allocator);

    rmw_hdds_error_t bind_req_status = rmw_hdds_context_bind_topic_type(
      node_impl->context->native_ctx,
      request_topic,
      request_ts);
    if (bind_req_status != RMW_HDDS_ERROR_OK) {
      allocator.deallocate((void *)request_ts, allocator.state);
      allocator.deallocate((void *)response_ts, allocator.state);
      if (request_type_name != NULL) {
        allocator.deallocate(request_type_name, allocator.state);
      }
      if (response_type_name != NULL) {
        allocator.deallocate(response_type_name, allocator.state);
      }
      allocator.deallocate(request_topic, allocator.state);
      allocator.deallocate(response_topic, allocator.state);
      RMW_SET_ERROR_MSG("failed to bind request topic type");
      return NULL;
    }

    rmw_hdds_error_t bind_resp_status = rmw_hdds_context_bind_topic_type(
      node_impl->context->native_ctx,
      response_topic,
      response_ts);
    if (bind_resp_status != RMW_HDDS_ERROR_OK) {
      allocator.deallocate((void *)request_ts, allocator.state);
      allocator.deallocate((void *)response_ts, allocator.state);
      if (request_type_name != NULL) {
        allocator.deallocate(request_type_name, allocator.state);
      }
      if (response_type_name != NULL) {
        allocator.deallocate(response_type_name, allocator.state);
      }
      allocator.deallocate(request_topic, allocator.state);
      allocator.deallocate(response_topic, allocator.state);
      RMW_SET_ERROR_MSG("failed to bind response topic type");
      return NULL;
    }
  }

  struct HddsDataWriter * request_writer = NULL;
  struct HddsQoS * client_qos = rmw_hdds_qos_from_profile(effective_qos);
  rmw_hdds_error_t writer_status;
  if (client_qos != NULL) {
    writer_status = rmw_hdds_context_create_writer_with_qos(
      node_impl->context->native_ctx,
      request_topic,
      client_qos,
      &request_writer);
  } else {
    writer_status = rmw_hdds_context_create_writer(
      node_impl->context->native_ctx,
      request_topic,
      &request_writer);
  }
  if (writer_status != RMW_HDDS_ERROR_OK || request_writer == NULL) {
    rmw_hdds_qos_destroy(client_qos);
    allocator.deallocate((void *)request_ts, allocator.state);
    allocator.deallocate((void *)response_ts, allocator.state);
    if (request_type_name != NULL) {
      allocator.deallocate(request_type_name, allocator.state);
    }
    if (response_type_name != NULL) {
      allocator.deallocate(response_type_name, allocator.state);
    }
    allocator.deallocate(request_topic, allocator.state);
    allocator.deallocate(response_topic, allocator.state);
    RMW_SET_ERROR_MSG("failed to create request writer");
    return NULL;
  }

  struct HddsDataReader * response_reader = NULL;
  rmw_hdds_error_t reader_status;
  if (client_qos != NULL) {
    reader_status = rmw_hdds_context_create_reader_with_qos(
      node_impl->context->native_ctx,
      response_topic,
      client_qos,
      &response_reader);
  } else {
    reader_status = rmw_hdds_context_create_reader(
      node_impl->context->native_ctx,
      response_topic,
      &response_reader);
  }
  rmw_hdds_qos_destroy(client_qos);
  if (reader_status != RMW_HDDS_ERROR_OK || response_reader == NULL) {
    rmw_hdds_context_destroy_writer(node_impl->context->native_ctx, request_writer);
    allocator.deallocate((void *)request_ts, allocator.state);
    allocator.deallocate((void *)response_ts, allocator.state);
    if (request_type_name != NULL) {
      allocator.deallocate(request_type_name, allocator.state);
    }
    if (response_type_name != NULL) {
      allocator.deallocate(response_type_name, allocator.state);
    }
    allocator.deallocate(request_topic, allocator.state);
    allocator.deallocate(response_topic, allocator.state);
    RMW_SET_ERROR_MSG("failed to create response reader");
    return NULL;
  }

  uint64_t response_key = 0;
  rmw_hdds_error_t attach_status = rmw_hdds_context_attach_reader(
    node_impl->context->native_ctx,
    response_reader,
    &response_key);
  if (attach_status != RMW_HDDS_ERROR_OK) {
    rmw_hdds_context_destroy_reader(node_impl->context->native_ctx, response_reader);
    rmw_hdds_context_destroy_writer(node_impl->context->native_ctx, request_writer);
    allocator.deallocate((void *)request_ts, allocator.state);
    allocator.deallocate((void *)response_ts, allocator.state);
    if (request_type_name != NULL) {
      allocator.deallocate(request_type_name, allocator.state);
    }
    if (response_type_name != NULL) {
      allocator.deallocate(response_type_name, allocator.state);
    }
    allocator.deallocate(request_topic, allocator.state);
    allocator.deallocate(response_topic, allocator.state);
    RMW_SET_ERROR_MSG("failed to attach response reader");
    return NULL;
  }
  (void)response_key;

  bool request_registered = false;
  bool response_registered = false;
  rmw_hdds_qos_profile_t endpoint_qos = rmw_hdds_qos_profile_from_rmw(effective_qos);
  if (request_ts != NULL) {
    uint8_t request_gid[RMW_GID_STORAGE_SIZE];
    rmw_hdds_gid_from_ptr(request_gid, request_writer, node_impl->context->native_ctx);
    rmw_hdds_error_t register_req = rmw_hdds_context_register_publisher_endpoint(
      node_impl->context->native_ctx,
      node_impl->name,
      node_impl->namespace_,
      request_topic,
      request_ts,
      request_gid,
      &endpoint_qos);
    if (register_req != RMW_HDDS_ERROR_OK) {
      rmw_hdds_context_destroy_reader(node_impl->context->native_ctx, response_reader);
      rmw_hdds_context_destroy_writer(node_impl->context->native_ctx, request_writer);
      allocator.deallocate((void *)request_ts, allocator.state);
      allocator.deallocate((void *)response_ts, allocator.state);
      if (request_type_name != NULL) {
        allocator.deallocate(request_type_name, allocator.state);
      }
      if (response_type_name != NULL) {
        allocator.deallocate(response_type_name, allocator.state);
      }
      allocator.deallocate(request_topic, allocator.state);
      allocator.deallocate(response_topic, allocator.state);
      RMW_SET_ERROR_MSG("failed to register request endpoint");
      return NULL;
    }
    request_registered = true;
  }

  if (response_ts != NULL) {
    uint8_t response_gid[RMW_GID_STORAGE_SIZE];
    rmw_hdds_gid_from_ptr(response_gid, response_reader, node_impl->context->native_ctx);
    rmw_hdds_error_t register_resp = rmw_hdds_context_register_subscription_endpoint(
      node_impl->context->native_ctx,
      node_impl->name,
      node_impl->namespace_,
      response_topic,
      response_ts,
      response_gid,
      &endpoint_qos);
    if (register_resp != RMW_HDDS_ERROR_OK) {
      if (request_registered) {
        uint8_t request_gid[RMW_GID_STORAGE_SIZE];
        rmw_hdds_gid_from_ptr(request_gid, request_writer, node_impl->context->native_ctx);
        (void)rmw_hdds_context_unregister_publisher_endpoint(
          node_impl->context->native_ctx,
          node_impl->name,
          node_impl->namespace_,
          request_topic,
          request_gid);
      }
      rmw_hdds_context_destroy_reader(node_impl->context->native_ctx, response_reader);
      rmw_hdds_context_destroy_writer(node_impl->context->native_ctx, request_writer);
      allocator.deallocate((void *)request_ts, allocator.state);
      allocator.deallocate((void *)response_ts, allocator.state);
      if (request_type_name != NULL) {
        allocator.deallocate(request_type_name, allocator.state);
      }
      if (response_type_name != NULL) {
        allocator.deallocate(response_type_name, allocator.state);
      }
      allocator.deallocate(request_topic, allocator.state);
      allocator.deallocate(response_topic, allocator.state);
      RMW_SET_ERROR_MSG("failed to register response endpoint");
      return NULL;
    }
    response_registered = true;
  }

  rmw_client_t * client =
    (rmw_client_t *)allocator.allocate(sizeof(rmw_client_t), allocator.state);
  if (client == NULL) {
    if (response_registered) {
      uint8_t response_gid[RMW_GID_STORAGE_SIZE];
      rmw_hdds_gid_from_ptr(response_gid, response_reader, node_impl->context->native_ctx);
      (void)rmw_hdds_context_unregister_subscription_endpoint(
        node_impl->context->native_ctx,
        node_impl->name,
        node_impl->namespace_,
        response_topic,
        response_gid);
    }
    if (request_registered) {
      uint8_t request_gid[RMW_GID_STORAGE_SIZE];
      rmw_hdds_gid_from_ptr(request_gid, request_writer, node_impl->context->native_ctx);
      (void)rmw_hdds_context_unregister_publisher_endpoint(
        node_impl->context->native_ctx,
        node_impl->name,
        node_impl->namespace_,
        request_topic,
        request_gid);
    }
    rmw_hdds_context_destroy_reader(node_impl->context->native_ctx, response_reader);
    rmw_hdds_context_destroy_writer(node_impl->context->native_ctx, request_writer);
    allocator.deallocate((void *)request_ts, allocator.state);
    allocator.deallocate((void *)response_ts, allocator.state);
    if (request_type_name != NULL) {
      allocator.deallocate(request_type_name, allocator.state);
    }
    if (response_type_name != NULL) {
      allocator.deallocate(response_type_name, allocator.state);
    }
    allocator.deallocate(request_topic, allocator.state);
    allocator.deallocate(response_topic, allocator.state);
    RMW_SET_ERROR_MSG("failed to allocate rmw_client_t");
    return NULL;
  }
  memset(client, 0, sizeof(*client));

  rmw_hdds_client_impl_t * impl =
    (rmw_hdds_client_impl_t *)allocator.allocate(
      sizeof(rmw_hdds_client_impl_t),
      allocator.state);
  if (impl == NULL) {
    allocator.deallocate(client, allocator.state);
    if (response_registered) {
      uint8_t response_gid[RMW_GID_STORAGE_SIZE];
      rmw_hdds_gid_from_ptr(response_gid, response_reader, node_impl->context->native_ctx);
      (void)rmw_hdds_context_unregister_subscription_endpoint(
        node_impl->context->native_ctx,
        node_impl->name,
        node_impl->namespace_,
        response_topic,
        response_gid);
    }
    if (request_registered) {
      uint8_t request_gid[RMW_GID_STORAGE_SIZE];
      rmw_hdds_gid_from_ptr(request_gid, request_writer, node_impl->context->native_ctx);
      (void)rmw_hdds_context_unregister_publisher_endpoint(
        node_impl->context->native_ctx,
        node_impl->name,
        node_impl->namespace_,
        request_topic,
        request_gid);
    }
    rmw_hdds_context_destroy_reader(node_impl->context->native_ctx, response_reader);
    rmw_hdds_context_destroy_writer(node_impl->context->native_ctx, request_writer);
    allocator.deallocate((void *)request_ts, allocator.state);
    allocator.deallocate((void *)response_ts, allocator.state);
    if (request_type_name != NULL) {
      allocator.deallocate(request_type_name, allocator.state);
    }
    if (response_type_name != NULL) {
      allocator.deallocate(response_type_name, allocator.state);
    }
    allocator.deallocate(request_topic, allocator.state);
    allocator.deallocate(response_topic, allocator.state);
    RMW_SET_ERROR_MSG("failed to allocate client implementation");
    return NULL;
  }
  memset(impl, 0, sizeof(*impl));

  char * name_copy = rcutils_strdup(service_name, allocator);
  if (name_copy == NULL) {
    allocator.deallocate(impl, allocator.state);
    allocator.deallocate(client, allocator.state);
    if (response_registered) {
      uint8_t response_gid[RMW_GID_STORAGE_SIZE];
      rmw_hdds_gid_from_ptr(response_gid, response_reader, node_impl->context->native_ctx);
      (void)rmw_hdds_context_unregister_subscription_endpoint(
        node_impl->context->native_ctx,
        node_impl->name,
        node_impl->namespace_,
        response_topic,
        response_gid);
    }
    if (request_registered) {
      uint8_t request_gid[RMW_GID_STORAGE_SIZE];
      rmw_hdds_gid_from_ptr(request_gid, request_writer, node_impl->context->native_ctx);
      (void)rmw_hdds_context_unregister_publisher_endpoint(
        node_impl->context->native_ctx,
        node_impl->name,
        node_impl->namespace_,
        request_topic,
        request_gid);
    }
    rmw_hdds_context_destroy_reader(node_impl->context->native_ctx, response_reader);
    rmw_hdds_context_destroy_writer(node_impl->context->native_ctx, request_writer);
    allocator.deallocate((void *)request_ts, allocator.state);
    allocator.deallocate((void *)response_ts, allocator.state);
    if (request_type_name != NULL) {
      allocator.deallocate(request_type_name, allocator.state);
    }
    if (response_type_name != NULL) {
      allocator.deallocate(response_type_name, allocator.state);
    }
    allocator.deallocate(request_topic, allocator.state);
    allocator.deallocate(response_topic, allocator.state);
    RMW_SET_ERROR_MSG("failed to duplicate service name");
    return NULL;
  }

  impl->context = node_impl->context;
  impl->service_name = name_copy;
  impl->request_topic = request_topic;
  impl->response_topic = response_topic;
  impl->type_support = type_support;
  impl->request_type_support = request_ts;
  impl->response_type_support = response_ts;
  impl->request_type_name = request_type_name;
  impl->response_type_name = response_type_name;
  impl->request_writer = request_writer;
  impl->response_reader = response_reader;
  impl->qos_profile = *effective_qos;
  impl->request_use_dynamic_types =
    request_type_name != NULL && hdds_rmw_has_type_descriptor(request_type_name);
  impl->response_use_dynamic_types =
    response_type_name != NULL && hdds_rmw_has_type_descriptor(response_type_name);
  impl->request_registered_in_graph = request_registered;
  impl->response_registered_in_graph = response_registered;
  impl->response_callback = NULL;
  impl->response_user_data = NULL;
  impl->next_sequence = 1;
  memset(impl->writer_guid, 0, sizeof(impl->writer_guid));
  {
    static atomic_uint_least64_t guid_counter = 1;
    uint64_t upper = atomic_fetch_add(&guid_counter, 1u);
    uint64_t lower = (uint64_t)(uintptr_t)impl;
    memcpy(impl->writer_guid, &upper, sizeof(upper));
    memcpy(impl->writer_guid + sizeof(upper), &lower, sizeof(lower));
  }

  client->implementation_identifier = rmw_get_implementation_identifier();
  client->data = impl;
  client->service_name = impl->service_name;

  return client;
}

rmw_ret_t
rmw_destroy_client(rmw_node_t * node, rmw_client_t * client)
{
  RMW_CHECK_ARGUMENT_FOR_NULL(node, RMW_RET_INVALID_ARGUMENT);
  RMW_CHECK_ARGUMENT_FOR_NULL(client, RMW_RET_INVALID_ARGUMENT);

  if (node->implementation_identifier != rmw_get_implementation_identifier() ||
    client->implementation_identifier != rmw_get_implementation_identifier())
  {
    RMW_SET_ERROR_MSG("rmw_destroy_client identifier mismatch");
    return RMW_RET_INCORRECT_RMW_IMPLEMENTATION;
  }

  rmw_hdds_node_impl_t * node_impl = (rmw_hdds_node_impl_t *)node->data;
  bool has_context =
    node_impl != NULL && node_impl->context != NULL && node_impl->context->native_ctx != NULL;
  rcutils_allocator_t allocator = select_node_allocator(node_impl);

  rmw_hdds_client_impl_t * impl =
    (rmw_hdds_client_impl_t *)client->data;
  if (impl != NULL) {
    if (impl->response_registered_in_graph && impl->response_topic != NULL && has_context) {
      uint8_t response_gid[RMW_GID_STORAGE_SIZE];
      rmw_hdds_gid_from_ptr(response_gid, impl->response_reader, node_impl->context->native_ctx);
      (void)rmw_hdds_context_unregister_subscription_endpoint(
        node_impl->context->native_ctx,
        node_impl->name,
        node_impl->namespace_,
        impl->response_topic,
        response_gid);
    }
    if (impl->request_registered_in_graph && impl->request_topic != NULL && has_context) {
      uint8_t request_gid[RMW_GID_STORAGE_SIZE];
      rmw_hdds_gid_from_ptr(request_gid, impl->request_writer, node_impl->context->native_ctx);
      (void)rmw_hdds_context_unregister_publisher_endpoint(
        node_impl->context->native_ctx,
        node_impl->name,
        node_impl->namespace_,
        impl->request_topic,
        request_gid);
    }
    if (impl->response_reader != NULL && has_context) {
      (void)rmw_hdds_context_destroy_reader(
        node_impl->context->native_ctx,
        impl->response_reader);
    }
    impl->response_reader = NULL;
    if (impl->request_writer != NULL && has_context) {
      (void)rmw_hdds_context_destroy_writer(
        node_impl->context->native_ctx,
        impl->request_writer);
    }
    impl->request_writer = NULL;
    if (impl->request_type_support != NULL) {
      allocator.deallocate((void *)impl->request_type_support, allocator.state);
      impl->request_type_support = NULL;
    }
    if (impl->response_type_support != NULL) {
      allocator.deallocate((void *)impl->response_type_support, allocator.state);
      impl->response_type_support = NULL;
    }
    if (impl->request_type_name != NULL) {
      allocator.deallocate(impl->request_type_name, allocator.state);
      impl->request_type_name = NULL;
    }
    if (impl->response_type_name != NULL) {
      allocator.deallocate(impl->response_type_name, allocator.state);
      impl->response_type_name = NULL;
    }
    if (impl->request_topic != NULL) {
      allocator.deallocate(impl->request_topic, allocator.state);
      impl->request_topic = NULL;
    }
    if (impl->response_topic != NULL) {
      allocator.deallocate(impl->response_topic, allocator.state);
      impl->response_topic = NULL;
    }
    if (impl->service_name != NULL) {
      allocator.deallocate(impl->service_name, allocator.state);
      impl->service_name = NULL;
    }
    allocator.deallocate(impl, allocator.state);
    client->data = NULL;
  }

  allocator.deallocate(client, allocator.state);
  return RMW_RET_OK;
}

rmw_ret_t
rmw_service_server_is_available(
  const rmw_node_t * node,
  const rmw_client_t * client,
  bool * is_available)
{
  RMW_CHECK_ARGUMENT_FOR_NULL(node, RMW_RET_INVALID_ARGUMENT);
  RMW_CHECK_ARGUMENT_FOR_NULL(client, RMW_RET_INVALID_ARGUMENT);
  RMW_CHECK_ARGUMENT_FOR_NULL(is_available, RMW_RET_INVALID_ARGUMENT);

  if (node->implementation_identifier != rmw_get_implementation_identifier() ||
    client->implementation_identifier != rmw_get_implementation_identifier())
  {
    RMW_SET_ERROR_MSG("rmw_service_server_is_available identifier mismatch");
    return RMW_RET_INCORRECT_RMW_IMPLEMENTATION;
  }

  const rmw_hdds_node_impl_t * node_impl =
    (const rmw_hdds_node_impl_t *)node->data;
  if (node_impl == NULL || node_impl->context == NULL || node_impl->context->native_ctx == NULL) {
    RMW_SET_ERROR_MSG("invalid node implementation");
    return RMW_RET_ERROR;
  }

  const rmw_hdds_client_impl_t * impl =
    (const rmw_hdds_client_impl_t *)client->data;
  if (impl == NULL || impl->request_topic == NULL || impl->response_topic == NULL) {
    RMW_SET_ERROR_MSG("invalid client implementation");
    return RMW_RET_ERROR;
  }

  hdds_graph_count_ctx_t req_ctx = {
    .topic_name = impl->request_topic,
    .count = 0u,
    .matched = false,
    .count_publishers = false,
  };

  rmw_hdds_error_t err = rmw_hdds_context_for_each_topic(
    node_impl->context->native_ctx,
    hdds_graph_count_cb,
    &req_ctx,
    NULL);
  if (err != RMW_HDDS_ERROR_OK) {
    return map_hdds_error(err);
  }

  hdds_graph_count_ctx_t resp_ctx = {
    .topic_name = impl->response_topic,
    .count = 0u,
    .matched = false,
    .count_publishers = true,
  };

  err = rmw_hdds_context_for_each_topic(
    node_impl->context->native_ctx,
    hdds_graph_count_cb,
    &resp_ctx,
    NULL);
  if (err != RMW_HDDS_ERROR_OK) {
    return map_hdds_error(err);
  }

  *is_available = (req_ctx.count > 0u) && (resp_ctx.count > 0u);
  return RMW_RET_OK;
}

rmw_ret_t
rmw_service_set_on_new_request_callback(
  rmw_service_t * service,
  rmw_event_callback_t callback,
  const void * user_data)
{
  RMW_CHECK_ARGUMENT_FOR_NULL(service, RMW_RET_INVALID_ARGUMENT);
  if (service->implementation_identifier != rmw_get_implementation_identifier()) {
    RMW_SET_ERROR_MSG("rmw_service_set_on_new_request_callback identifier mismatch");
    return RMW_RET_INCORRECT_RMW_IMPLEMENTATION;
  }

  rmw_hdds_service_impl_t * impl =
    (rmw_hdds_service_impl_t *)service->data;
  if (impl == NULL) {
    RMW_SET_ERROR_MSG("service implementation is null");
    return RMW_RET_ERROR;
  }

  impl->request_callback = callback;
  impl->request_user_data = user_data;
  return RMW_RET_OK;
}

rmw_ret_t
rmw_client_set_on_new_response_callback(
  rmw_client_t * client,
  rmw_event_callback_t callback,
  const void * user_data)
{
  RMW_CHECK_ARGUMENT_FOR_NULL(client, RMW_RET_INVALID_ARGUMENT);
  if (client->implementation_identifier != rmw_get_implementation_identifier()) {
    RMW_SET_ERROR_MSG("rmw_client_set_on_new_response_callback identifier mismatch");
    return RMW_RET_INCORRECT_RMW_IMPLEMENTATION;
  }

  rmw_hdds_client_impl_t * impl = (rmw_hdds_client_impl_t *)client->data;
  if (impl == NULL) {
    RMW_SET_ERROR_MSG("client implementation is null");
    return RMW_RET_ERROR;
  }

  impl->response_callback = callback;
  impl->response_user_data = user_data;
  return RMW_RET_OK;
}

rmw_ret_t
rmw_service_request_subscription_get_actual_qos(
  const rmw_service_t * service,
  rmw_qos_profile_t * qos)
{
  RMW_CHECK_ARGUMENT_FOR_NULL(service, RMW_RET_INVALID_ARGUMENT);
  RMW_CHECK_ARGUMENT_FOR_NULL(qos, RMW_RET_INVALID_ARGUMENT);

  if (service->implementation_identifier != rmw_get_implementation_identifier()) {
    RMW_SET_ERROR_MSG("rmw_service_request_subscription_get_actual_qos identifier mismatch");
    return RMW_RET_INCORRECT_RMW_IMPLEMENTATION;
  }

  const rmw_hdds_service_impl_t * impl =
    (const rmw_hdds_service_impl_t *)service->data;
  if (impl == NULL) {
    RMW_SET_ERROR_MSG("service implementation is null");
    return RMW_RET_ERROR;
  }

  *qos = impl->qos_profile;
  return RMW_RET_OK;
}

rmw_ret_t
rmw_service_response_publisher_get_actual_qos(
  const rmw_service_t * service,
  rmw_qos_profile_t * qos)
{
  return rmw_service_request_subscription_get_actual_qos(service, qos);
}

rmw_ret_t
rmw_client_request_publisher_get_actual_qos(
  const rmw_client_t * client,
  rmw_qos_profile_t * qos)
{
  RMW_CHECK_ARGUMENT_FOR_NULL(client, RMW_RET_INVALID_ARGUMENT);
  RMW_CHECK_ARGUMENT_FOR_NULL(qos, RMW_RET_INVALID_ARGUMENT);

  if (client->implementation_identifier != rmw_get_implementation_identifier()) {
    RMW_SET_ERROR_MSG("rmw_client_request_publisher_get_actual_qos identifier mismatch");
    return RMW_RET_INCORRECT_RMW_IMPLEMENTATION;
  }

  const rmw_hdds_client_impl_t * impl =
    (const rmw_hdds_client_impl_t *)client->data;
  if (impl == NULL) {
    RMW_SET_ERROR_MSG("client implementation is null");
    return RMW_RET_ERROR;
  }

  *qos = impl->qos_profile;
  return RMW_RET_OK;
}

rmw_ret_t
rmw_client_response_subscription_get_actual_qos(
  const rmw_client_t * client,
  rmw_qos_profile_t * qos)
{
  return rmw_client_request_publisher_get_actual_qos(client, qos);
}

rmw_ret_t
rmw_get_client_names_and_types_by_node(
  const rmw_node_t * node,
  rcutils_allocator_t * allocator,
  const char * node_name,
  const char * node_namespace,
  rmw_names_and_types_t * names_and_types)
{
  RMW_CHECK_ARGUMENT_FOR_NULL(node, RMW_RET_INVALID_ARGUMENT);
  RMW_CHECK_ARGUMENT_FOR_NULL(node_name, RMW_RET_INVALID_ARGUMENT);
  RMW_CHECK_ARGUMENT_FOR_NULL(node_namespace, RMW_RET_INVALID_ARGUMENT);
  RMW_CHECK_ARGUMENT_FOR_NULL(names_and_types, RMW_RET_INVALID_ARGUMENT);

  if (node->implementation_identifier != rmw_get_implementation_identifier()) {
    RMW_SET_ERROR_MSG("rmw_get_client_names_and_types_by_node identifier mismatch");
    return RMW_RET_INCORRECT_RMW_IMPLEMENTATION;
  }

  rcutils_allocator_t effective_allocator =
    allocator != NULL ? *allocator : rcutils_get_default_allocator();
  if (!rcutils_allocator_is_valid(&effective_allocator)) {
    RMW_SET_ERROR_MSG("allocator is invalid");
    return RMW_RET_INVALID_ARGUMENT;
  }

  rmw_ret_t zero_status = rmw_names_and_types_check_zero(names_and_types);
  if (zero_status != RMW_RET_OK) {
    return zero_status;
  }

  const rmw_hdds_node_impl_t * node_impl =
    (const rmw_hdds_node_impl_t *)node->data;
  if (node_impl == NULL || node_impl->context == NULL || node_impl->context->native_ctx == NULL) {
    RMW_SET_ERROR_MSG("invalid node implementation");
    return RMW_RET_ERROR;
  }

  hdds_service_list_t list;
  hdds_service_list_init(&list, effective_allocator);

  hdds_service_collect_ctx_t ctx = {
    .list = &list,
    .status = RMW_RET_OK,
    .prefix = "rq",
  };

  rmw_hdds_error_t list_status = rmw_hdds_context_for_each_publisher_endpoint(
    node_impl->context->native_ctx,
    node_name,
    node_namespace,
    hdds_collect_service_endpoint_cb,
    &ctx,
    NULL,
    NULL);

  if (list_status == RMW_HDDS_ERROR_NOT_FOUND) {
    hdds_service_list_fini(&list);
    return RMW_RET_NODE_NAME_NON_EXISTENT;
  }

  if (list_status != RMW_HDDS_ERROR_OK) {
    hdds_service_list_fini(&list);
    return map_hdds_error(list_status);
  }

  ctx.prefix = "rr";
  list_status = rmw_hdds_context_for_each_subscription_endpoint(
    node_impl->context->native_ctx,
    node_name,
    node_namespace,
    hdds_collect_service_endpoint_cb,
    &ctx,
    NULL,
    NULL);

  if (list_status == RMW_HDDS_ERROR_NOT_FOUND) {
    hdds_service_list_fini(&list);
    return RMW_RET_NODE_NAME_NON_EXISTENT;
  }

  if (list_status != RMW_HDDS_ERROR_OK) {
    hdds_service_list_fini(&list);
    return map_hdds_error(list_status);
  }

  if (ctx.status != RMW_RET_OK) {
    hdds_service_list_fini(&list);
    return ctx.status;
  }

  rmw_ret_t init_status = fill_names_and_types_from_service_list(
    names_and_types,
    &list);
  hdds_service_list_fini(&list);
  return init_status;
}

rmw_ret_t
rmw_get_service_names_and_types(
  const rmw_node_t * node,
  rcutils_allocator_t * allocator,
  rmw_names_and_types_t * service_names_and_types)
{
  RMW_CHECK_ARGUMENT_FOR_NULL(node, RMW_RET_INVALID_ARGUMENT);
  RMW_CHECK_ARGUMENT_FOR_NULL(service_names_and_types, RMW_RET_INVALID_ARGUMENT);

  if (node->implementation_identifier != rmw_get_implementation_identifier()) {
    RMW_SET_ERROR_MSG("rmw_get_service_names_and_types identifier mismatch");
    return RMW_RET_INCORRECT_RMW_IMPLEMENTATION;
  }

  rcutils_allocator_t effective_allocator =
    allocator != NULL ? *allocator : rcutils_get_default_allocator();
  if (!rcutils_allocator_is_valid(&effective_allocator)) {
    RMW_SET_ERROR_MSG("allocator is invalid");
    return RMW_RET_INVALID_ARGUMENT;
  }

  rmw_ret_t zero_status = rmw_names_and_types_check_zero(service_names_and_types);
  if (zero_status != RMW_RET_OK) {
    return zero_status;
  }

  const rmw_hdds_node_impl_t * node_impl =
    (const rmw_hdds_node_impl_t *)node->data;
  if (node_impl == NULL || node_impl->context == NULL || node_impl->context->native_ctx == NULL) {
    RMW_SET_ERROR_MSG("invalid node implementation");
    return RMW_RET_ERROR;
  }

  hdds_service_list_t list;
  hdds_service_list_init(&list, effective_allocator);

  hdds_service_collect_ctx_t ctx = {
    .list = &list,
    .status = RMW_RET_OK,
    .prefix = NULL,
  };

  rmw_hdds_error_t list_status = rmw_hdds_context_for_each_topic(
    node_impl->context->native_ctx,
    hdds_collect_service_topic_cb,
    &ctx,
    NULL);

  if (list_status != RMW_HDDS_ERROR_OK) {
    hdds_service_list_fini(&list);
    return map_hdds_error(list_status);
  }

  if (ctx.status != RMW_RET_OK) {
    hdds_service_list_fini(&list);
    return ctx.status;
  }

  rmw_ret_t init_status = fill_names_and_types_from_service_list(
    service_names_and_types,
    &list);
  hdds_service_list_fini(&list);
  return init_status;
}

rmw_ret_t
rmw_get_service_names_and_types_by_node(
  const rmw_node_t * node,
  rcutils_allocator_t * allocator,
  const char * node_name,
  const char * node_namespace,
  rmw_names_and_types_t * service_names_and_types)
{
  RMW_CHECK_ARGUMENT_FOR_NULL(node, RMW_RET_INVALID_ARGUMENT);
  RMW_CHECK_ARGUMENT_FOR_NULL(node_name, RMW_RET_INVALID_ARGUMENT);
  RMW_CHECK_ARGUMENT_FOR_NULL(node_namespace, RMW_RET_INVALID_ARGUMENT);
  RMW_CHECK_ARGUMENT_FOR_NULL(service_names_and_types, RMW_RET_INVALID_ARGUMENT);

  if (node->implementation_identifier != rmw_get_implementation_identifier()) {
    RMW_SET_ERROR_MSG("rmw_get_service_names_and_types_by_node identifier mismatch");
    return RMW_RET_INCORRECT_RMW_IMPLEMENTATION;
  }

  rcutils_allocator_t effective_allocator =
    allocator != NULL ? *allocator : rcutils_get_default_allocator();
  if (!rcutils_allocator_is_valid(&effective_allocator)) {
    RMW_SET_ERROR_MSG("allocator is invalid");
    return RMW_RET_INVALID_ARGUMENT;
  }

  rmw_ret_t zero_status = rmw_names_and_types_check_zero(service_names_and_types);
  if (zero_status != RMW_RET_OK) {
    return zero_status;
  }

  const rmw_hdds_node_impl_t * node_impl =
    (const rmw_hdds_node_impl_t *)node->data;
  if (node_impl == NULL || node_impl->context == NULL || node_impl->context->native_ctx == NULL) {
    RMW_SET_ERROR_MSG("invalid node implementation");
    return RMW_RET_ERROR;
  }

  hdds_service_list_t list;
  hdds_service_list_init(&list, effective_allocator);

  hdds_service_collect_ctx_t ctx = {
    .list = &list,
    .status = RMW_RET_OK,
    .prefix = "rq",
  };

  rmw_hdds_error_t list_status = rmw_hdds_context_for_each_subscription_endpoint(
    node_impl->context->native_ctx,
    node_name,
    node_namespace,
    hdds_collect_service_endpoint_cb,
    &ctx,
    NULL,
    NULL);

  if (list_status == RMW_HDDS_ERROR_NOT_FOUND) {
    hdds_service_list_fini(&list);
    return RMW_RET_NODE_NAME_NON_EXISTENT;
  }

  if (list_status != RMW_HDDS_ERROR_OK) {
    hdds_service_list_fini(&list);
    return map_hdds_error(list_status);
  }

  ctx.prefix = "rr";
  list_status = rmw_hdds_context_for_each_publisher_endpoint(
    node_impl->context->native_ctx,
    node_name,
    node_namespace,
    hdds_collect_service_endpoint_cb,
    &ctx,
    NULL,
    NULL);

  if (list_status == RMW_HDDS_ERROR_NOT_FOUND) {
    hdds_service_list_fini(&list);
    return RMW_RET_NODE_NAME_NON_EXISTENT;
  }

  if (list_status != RMW_HDDS_ERROR_OK) {
    hdds_service_list_fini(&list);
    return map_hdds_error(list_status);
  }

  if (ctx.status != RMW_RET_OK) {
    hdds_service_list_fini(&list);
    return ctx.status;
  }

  rmw_ret_t init_status = fill_names_and_types_from_service_list(
    service_names_and_types,
    &list);
  hdds_service_list_fini(&list);
  return init_status;
}

rmw_ret_t
rmw_get_publishers_info_by_topic(
  const rmw_node_t * node,
  rcutils_allocator_t * allocator,
  const char * topic_name,
  bool no_mangle,
  rmw_topic_endpoint_info_array_t * publishers_info)
{
  RCUTILS_UNUSED(no_mangle);
  RMW_CHECK_ARGUMENT_FOR_NULL(node, RMW_RET_INVALID_ARGUMENT);
  RMW_CHECK_ARGUMENT_FOR_NULL(topic_name, RMW_RET_INVALID_ARGUMENT);
  RMW_CHECK_ARGUMENT_FOR_NULL(publishers_info, RMW_RET_INVALID_ARGUMENT);

  if (node->implementation_identifier != rmw_get_implementation_identifier()) {
    RMW_SET_ERROR_MSG("rmw_get_publishers_info_by_topic identifier mismatch");
    return RMW_RET_INCORRECT_RMW_IMPLEMENTATION;
  }

  rcutils_allocator_t effective_allocator =
    allocator != NULL ? *allocator : rcutils_get_default_allocator();
  if (!rcutils_allocator_is_valid(&effective_allocator)) {
    RMW_SET_ERROR_MSG("allocator is invalid");
    return RMW_RET_INVALID_ARGUMENT;
  }

  rmw_ret_t zero_status = rmw_topic_endpoint_info_array_check_zero(publishers_info);
  if (zero_status != RMW_RET_OK) {
    return zero_status;
  }

  const rmw_hdds_node_impl_t * node_impl = (const rmw_hdds_node_impl_t *)node->data;
  if (node_impl == NULL || node_impl->context == NULL || node_impl->context->native_ctx == NULL) {
    RMW_SET_ERROR_MSG("invalid node implementation");
    return RMW_RET_ERROR;
  }

  const size_t max_attempts = 3;
  for (size_t attempt = 0; attempt < max_attempts; ++attempt) {
    hdds_topic_endpoint_count_query_t count_ctx = {
      .native_ctx = node_impl->context->native_ctx,
      .topic_name = topic_name,
      .count = 0u,
      .status = RMW_RET_OK,
      .publishers = true,
    };

    uint64_t version_before = 0;
    rmw_hdds_error_t list_status = rmw_hdds_context_for_each_node(
      node_impl->context->native_ctx,
      hdds_node_count_cb,
      &count_ctx,
      &version_before,
      NULL);
    if (list_status != RMW_HDDS_ERROR_OK) {
      return map_hdds_error(list_status);
    }
    if (count_ctx.status != RMW_RET_OK) {
      return count_ctx.status;
    }

    rmw_ret_t init_status = rmw_topic_endpoint_info_array_init_with_size(
      publishers_info,
      count_ctx.count,
      &effective_allocator);
    if (init_status != RMW_RET_OK) {
      return init_status;
    }
    if (count_ctx.count == 0u) {
      return RMW_RET_OK;
    }

    hdds_topic_endpoint_fill_query_t fill_ctx = {
      .native_ctx = node_impl->context->native_ctx,
      .topic_name = topic_name,
      .info_array = publishers_info,
      .allocator = effective_allocator,
      .index = 0u,
      .status = RMW_RET_OK,
      .publishers = true,
      .node_name = NULL,
      .node_namespace = NULL,
    };

    uint64_t version_after = 0;
    list_status = rmw_hdds_context_for_each_node(
      node_impl->context->native_ctx,
      hdds_node_fill_cb,
      &fill_ctx,
      &version_after,
      NULL);
    if (list_status != RMW_HDDS_ERROR_OK) {
      rmw_ret_t fini_status =
        rmw_topic_endpoint_info_array_fini(publishers_info, &effective_allocator);
      if (fini_status != RMW_RET_OK) {
        return fini_status;
      }
      return map_hdds_error(list_status);
    }
    if (fill_ctx.status != RMW_RET_OK) {
      rmw_ret_t fini_status =
        rmw_topic_endpoint_info_array_fini(publishers_info, &effective_allocator);
      if (fini_status != RMW_RET_OK) {
        return fini_status;
      }
      return fill_ctx.status;
    }

    if (version_before == version_after && fill_ctx.index == count_ctx.count) {
      return RMW_RET_OK;
    }

    (void)rmw_topic_endpoint_info_array_fini(publishers_info, &effective_allocator);
  }

  RMW_SET_ERROR_MSG("graph changed while collecting publishers info");
  return RMW_RET_ERROR;
}

rmw_ret_t
rmw_get_subscriptions_info_by_topic(
  const rmw_node_t * node,
  rcutils_allocator_t * allocator,
  const char * topic_name,
  bool no_mangle,
  rmw_topic_endpoint_info_array_t * subscriptions_info)
{
  RCUTILS_UNUSED(no_mangle);
  RMW_CHECK_ARGUMENT_FOR_NULL(node, RMW_RET_INVALID_ARGUMENT);
  RMW_CHECK_ARGUMENT_FOR_NULL(allocator, RMW_RET_INVALID_ARGUMENT);
  RMW_CHECK_ARGUMENT_FOR_NULL(topic_name, RMW_RET_INVALID_ARGUMENT);
  RMW_CHECK_ARGUMENT_FOR_NULL(subscriptions_info, RMW_RET_INVALID_ARGUMENT);

  if (node->implementation_identifier != rmw_get_implementation_identifier()) {
    RMW_SET_ERROR_MSG("rmw_get_subscriptions_info_by_topic identifier mismatch");
    return RMW_RET_INCORRECT_RMW_IMPLEMENTATION;
  }

  rcutils_allocator_t effective_allocator =
    allocator != NULL ? *allocator : rcutils_get_default_allocator();
  if (!rcutils_allocator_is_valid(&effective_allocator)) {
    RMW_SET_ERROR_MSG("allocator is invalid");
    return RMW_RET_INVALID_ARGUMENT;
  }

  rmw_ret_t zero_status = rmw_topic_endpoint_info_array_check_zero(subscriptions_info);
  if (zero_status != RMW_RET_OK) {
    return zero_status;
  }

  const rmw_hdds_node_impl_t * node_impl = (const rmw_hdds_node_impl_t *)node->data;
  if (node_impl == NULL || node_impl->context == NULL || node_impl->context->native_ctx == NULL) {
    RMW_SET_ERROR_MSG("invalid node implementation");
    return RMW_RET_ERROR;
  }

  const size_t max_attempts = 3;
  for (size_t attempt = 0; attempt < max_attempts; ++attempt) {
    hdds_topic_endpoint_count_query_t count_ctx = {
      .native_ctx = node_impl->context->native_ctx,
      .topic_name = topic_name,
      .count = 0u,
      .status = RMW_RET_OK,
      .publishers = false,
    };

    uint64_t version_before = 0;
    rmw_hdds_error_t list_status = rmw_hdds_context_for_each_node(
      node_impl->context->native_ctx,
      hdds_node_count_cb,
      &count_ctx,
      &version_before,
      NULL);
    if (list_status != RMW_HDDS_ERROR_OK) {
      return map_hdds_error(list_status);
    }
    if (count_ctx.status != RMW_RET_OK) {
      return count_ctx.status;
    }

    rmw_ret_t init_status = rmw_topic_endpoint_info_array_init_with_size(
      subscriptions_info,
      count_ctx.count,
      &effective_allocator);
    if (init_status != RMW_RET_OK) {
      return init_status;
    }
    if (count_ctx.count == 0u) {
      return RMW_RET_OK;
    }

    hdds_topic_endpoint_fill_query_t fill_ctx = {
      .native_ctx = node_impl->context->native_ctx,
      .topic_name = topic_name,
      .info_array = subscriptions_info,
      .allocator = effective_allocator,
      .index = 0u,
      .status = RMW_RET_OK,
      .publishers = false,
      .node_name = NULL,
      .node_namespace = NULL,
    };

    uint64_t version_after = 0;
    list_status = rmw_hdds_context_for_each_node(
      node_impl->context->native_ctx,
      hdds_node_fill_cb,
      &fill_ctx,
      &version_after,
      NULL);
    if (list_status != RMW_HDDS_ERROR_OK) {
      rmw_ret_t fini_status =
        rmw_topic_endpoint_info_array_fini(subscriptions_info, &effective_allocator);
      if (fini_status != RMW_RET_OK) {
        return fini_status;
      }
      return map_hdds_error(list_status);
    }
    if (fill_ctx.status != RMW_RET_OK) {
      rmw_ret_t fini_status =
        rmw_topic_endpoint_info_array_fini(subscriptions_info, &effective_allocator);
      if (fini_status != RMW_RET_OK) {
        return fini_status;
      }
      return fill_ctx.status;
    }

    if (version_before == version_after && fill_ctx.index == count_ctx.count) {
      return RMW_RET_OK;
    }

    (void)rmw_topic_endpoint_info_array_fini(subscriptions_info, &effective_allocator);
  }

  RMW_SET_ERROR_MSG("graph changed while collecting subscriptions info");
  return RMW_RET_ERROR;
}

rmw_ret_t
rmw_count_publishers(
  const rmw_node_t * node,
  const char * topic_name,
  size_t * count)
{
  RMW_CHECK_ARGUMENT_FOR_NULL(node, RMW_RET_INVALID_ARGUMENT);
  RMW_CHECK_ARGUMENT_FOR_NULL(topic_name, RMW_RET_INVALID_ARGUMENT);
  RMW_CHECK_ARGUMENT_FOR_NULL(count, RMW_RET_INVALID_ARGUMENT);

  if (node->implementation_identifier != rmw_get_implementation_identifier()) {
    RMW_SET_ERROR_MSG("rmw_count_publishers identifier mismatch");
    return RMW_RET_INCORRECT_RMW_IMPLEMENTATION;
  }

  const rmw_hdds_node_impl_t * node_impl = (const rmw_hdds_node_impl_t *)node->data;
  if (node_impl == NULL || node_impl->context == NULL || node_impl->context->native_ctx == NULL) {
    RMW_SET_ERROR_MSG("invalid node implementation");
    return RMW_RET_ERROR;
  }

  hdds_graph_count_ctx_t ctx = {
    .topic_name = topic_name,
    .count = 0u,
    .matched = false,
    .count_publishers = true,
  };

  rmw_hdds_error_t err = rmw_hdds_context_for_each_topic(
    node_impl->context->native_ctx,
    hdds_graph_count_cb,
    &ctx,
    NULL);
  if (err != RMW_HDDS_ERROR_OK) {
    return map_hdds_error(err);
  }

  *count = ctx.count;
  return RMW_RET_OK;
}

rmw_ret_t
rmw_count_subscribers(
  const rmw_node_t * node,
  const char * topic_name,
  size_t * count)
{
  RMW_CHECK_ARGUMENT_FOR_NULL(node, RMW_RET_INVALID_ARGUMENT);
  RMW_CHECK_ARGUMENT_FOR_NULL(topic_name, RMW_RET_INVALID_ARGUMENT);
  RMW_CHECK_ARGUMENT_FOR_NULL(count, RMW_RET_INVALID_ARGUMENT);

  if (node->implementation_identifier != rmw_get_implementation_identifier()) {
    RMW_SET_ERROR_MSG("rmw_count_subscribers identifier mismatch");
    return RMW_RET_INCORRECT_RMW_IMPLEMENTATION;
  }

  const rmw_hdds_node_impl_t * node_impl = (const rmw_hdds_node_impl_t *)node->data;
  if (node_impl == NULL || node_impl->context == NULL || node_impl->context->native_ctx == NULL) {
    RMW_SET_ERROR_MSG("invalid node implementation");
    return RMW_RET_ERROR;
  }

  hdds_graph_count_ctx_t ctx = {
    .topic_name = topic_name,
    .count = 0u,
    .matched = false,
    .count_publishers = false,
  };

  rmw_hdds_error_t err = rmw_hdds_context_for_each_topic(
    node_impl->context->native_ctx,
    hdds_graph_count_cb,
    &ctx,
    NULL);
  if (err != RMW_HDDS_ERROR_OK) {
    return map_hdds_error(err);
  }

  *count = ctx.count;
  return RMW_RET_OK;
}

rmw_ret_t
rmw_get_gid_for_publisher(const rmw_publisher_t * publisher, rmw_gid_t * gid)
{
  RMW_CHECK_ARGUMENT_FOR_NULL(publisher, RMW_RET_INVALID_ARGUMENT);
  RMW_CHECK_ARGUMENT_FOR_NULL(gid, RMW_RET_INVALID_ARGUMENT);

  if (publisher->implementation_identifier != rmw_get_implementation_identifier()) {
    RMW_SET_ERROR_MSG("rmw_get_gid_for_publisher identifier mismatch");
    return RMW_RET_INCORRECT_RMW_IMPLEMENTATION;
  }

  const rmw_hdds_publisher_impl_t * impl =
    (const rmw_hdds_publisher_impl_t *)publisher->data;
  if (impl == NULL || impl->writer == NULL || impl->context == NULL) {
    RMW_SET_ERROR_MSG("invalid publisher implementation");
    return RMW_RET_ERROR;
  }

  hdds_fill_gid(gid, impl->writer, impl->context->native_ctx);
  return RMW_RET_OK;
}

rmw_ret_t
rmw_get_gid_for_subscription(const rmw_subscription_t * subscription, rmw_gid_t * gid)
{
  RMW_CHECK_ARGUMENT_FOR_NULL(subscription, RMW_RET_INVALID_ARGUMENT);
  RMW_CHECK_ARGUMENT_FOR_NULL(gid, RMW_RET_INVALID_ARGUMENT);

  if (subscription->implementation_identifier != rmw_get_implementation_identifier()) {
    RMW_SET_ERROR_MSG("rmw_get_gid_for_subscription identifier mismatch");
    return RMW_RET_INCORRECT_RMW_IMPLEMENTATION;
  }

  const rmw_hdds_subscription_impl_t * impl =
    (const rmw_hdds_subscription_impl_t *)subscription->data;
  if (impl == NULL || impl->reader == NULL || impl->context == NULL) {
    RMW_SET_ERROR_MSG("invalid subscription implementation");
    return RMW_RET_ERROR;
  }

  hdds_fill_gid(gid, impl->reader, impl->context->native_ctx);
  return RMW_RET_OK;
}

rmw_ret_t
rmw_compare_gids_equal(
  const rmw_gid_t * gid1,
  const rmw_gid_t * gid2,
  bool * result)
{
  RMW_CHECK_ARGUMENT_FOR_NULL(result, RMW_RET_INVALID_ARGUMENT);
  if (gid1 == NULL || gid2 == NULL) {
    *result = false;
    RMW_SET_ERROR_MSG("gid arguments must not be null");
    return RMW_RET_INVALID_ARGUMENT;
  }

  if ((gid1->implementation_identifier == NULL) ||
      (gid2->implementation_identifier == NULL))
  {
    *result = false;
    return RMW_RET_INVALID_ARGUMENT;
  }

  *result = (gid1->implementation_identifier == gid2->implementation_identifier) &&
    (memcmp(gid1->data, gid2->data, sizeof(gid1->data)) == 0);
  return RMW_RET_OK;
}

rmw_ret_t
rmw_qos_profile_check_compatible(
  const rmw_qos_profile_t publisher_profile,
  const rmw_qos_profile_t subscription_profile,
  rmw_qos_compatibility_type_t * compatibility,
  char * reason,
  size_t reason_size)
{
  if (compatibility == NULL) {
    RMW_SET_ERROR_MSG("compatibility parameter is null");
    return RMW_RET_INVALID_ARGUMENT;
  }

  if (reason == NULL && reason_size != 0u) {
    RMW_SET_ERROR_MSG("reason parameter is null, but reason_size parameter is not zero");
    return RMW_RET_INVALID_ARGUMENT;
  }

  *compatibility = RMW_QOS_COMPATIBILITY_OK;

  if (reason != NULL && reason_size != 0u) {
    reason[0] = '\0';
  }

  if (publisher_profile.reliability == RMW_QOS_POLICY_RELIABILITY_BEST_EFFORT &&
    subscription_profile.reliability == RMW_QOS_POLICY_RELIABILITY_RELIABLE)
  {
    *compatibility = RMW_QOS_COMPATIBILITY_ERROR;
    rmw_ret_t append_ret = append_to_reason(
      reason,
      reason_size,
      "ERROR: Best effort publisher and reliable subscription;");
    if (append_ret != RMW_RET_OK) {
      return append_ret;
    }
  }

  if (publisher_profile.durability == RMW_QOS_POLICY_DURABILITY_VOLATILE &&
    subscription_profile.durability == RMW_QOS_POLICY_DURABILITY_TRANSIENT_LOCAL)
  {
    *compatibility = RMW_QOS_COMPATIBILITY_ERROR;
    rmw_ret_t append_ret = append_to_reason(
      reason,
      reason_size,
      "ERROR: Volatile publisher and transient local subscription;");
    if (append_ret != RMW_RET_OK) {
      return append_ret;
    }
  }

  rmw_time_t pub_deadline = publisher_profile.deadline;
  rmw_time_t sub_deadline = subscription_profile.deadline;
  rmw_time_t deadline_default = RMW_QOS_DEADLINE_DEFAULT;

  if (hdds_time_equal(pub_deadline, deadline_default) &&
    hdds_time_not_equal(sub_deadline, deadline_default))
  {
    *compatibility = RMW_QOS_COMPATIBILITY_ERROR;
    rmw_ret_t append_ret = append_to_reason(
      reason,
      reason_size,
      "ERROR: Subscription has a deadline, but publisher does not;");
    if (append_ret != RMW_RET_OK) {
      return append_ret;
    }
  }

  if (hdds_time_not_equal(pub_deadline, deadline_default) &&
    hdds_time_not_equal(sub_deadline, deadline_default))
  {
    if (hdds_time_less(sub_deadline, pub_deadline)) {
      *compatibility = RMW_QOS_COMPATIBILITY_ERROR;
      rmw_ret_t append_ret = append_to_reason(
        reason,
        reason_size,
        "ERROR: Subscription deadline is less than publisher deadline;");
      if (append_ret != RMW_RET_OK) {
        return append_ret;
      }
    }
  }

  rmw_time_t pub_lifespan = publisher_profile.lifespan;
  rmw_time_t sub_lifespan = subscription_profile.lifespan;
  rmw_time_t lifespan_default = RMW_QOS_LIFESPAN_DEFAULT;

  if (*compatibility != RMW_QOS_COMPATIBILITY_ERROR) {
    if (hdds_time_equal(pub_lifespan, lifespan_default) &&
      hdds_time_not_equal(sub_lifespan, lifespan_default))
    {
      *compatibility = RMW_QOS_COMPATIBILITY_WARNING;
      rmw_ret_t append_ret = append_to_reason(
        reason,
        reason_size,
        "WARNING: Subscription has a lifespan, but publisher does not;");
      if (append_ret != RMW_RET_OK) {
        return append_ret;
      }
    } else if (hdds_time_not_equal(pub_lifespan, lifespan_default) &&
      hdds_time_equal(sub_lifespan, lifespan_default))
    {
      *compatibility = RMW_QOS_COMPATIBILITY_WARNING;
      rmw_ret_t append_ret = append_to_reason(
        reason,
        reason_size,
        "WARNING: Publisher has a lifespan, but subscription does not;");
      if (append_ret != RMW_RET_OK) {
        return append_ret;
      }
    } else if (hdds_time_not_equal(pub_lifespan, lifespan_default) &&
      hdds_time_not_equal(sub_lifespan, lifespan_default))
    {
      if (hdds_time_less(sub_lifespan, pub_lifespan)) {
        *compatibility = RMW_QOS_COMPATIBILITY_WARNING;
        rmw_ret_t append_ret = append_to_reason(
          reason,
          reason_size,
          "WARNING: Subscription lifespan is less than publisher lifespan;");
        if (append_ret != RMW_RET_OK) {
          return append_ret;
        }
      }
    }
  }

  if (publisher_profile.liveliness == RMW_QOS_POLICY_LIVELINESS_AUTOMATIC &&
    subscription_profile.liveliness == RMW_QOS_POLICY_LIVELINESS_MANUAL_BY_TOPIC)
  {
    *compatibility = RMW_QOS_COMPATIBILITY_ERROR;
    rmw_ret_t append_ret = append_to_reason(
      reason,
      reason_size,
      "ERROR: Publisher's liveliness is automatic and subscription's is manual by topic;");
    if (append_ret != RMW_RET_OK) {
      return append_ret;
    }
  }

  rmw_time_t pub_lease = publisher_profile.liveliness_lease_duration;
  rmw_time_t sub_lease = subscription_profile.liveliness_lease_duration;
  rmw_time_t lease_default = RMW_QOS_LIVELINESS_LEASE_DURATION_DEFAULT;

  if (hdds_time_equal(pub_lease, lease_default) &&
    hdds_time_not_equal(sub_lease, lease_default))
  {
    *compatibility = RMW_QOS_COMPATIBILITY_ERROR;
    rmw_ret_t append_ret = append_to_reason(
      reason,
      reason_size,
      "ERROR: Subscription has a liveliness lease duration, but publisher does not;");
    if (append_ret != RMW_RET_OK) {
      return append_ret;
    }
  }

  if (hdds_time_not_equal(pub_lease, lease_default) &&
    hdds_time_not_equal(sub_lease, lease_default))
  {
    if (hdds_time_less(sub_lease, pub_lease)) {
      *compatibility = RMW_QOS_COMPATIBILITY_ERROR;
      rmw_ret_t append_ret = append_to_reason(
        reason,
        reason_size,
        "ERROR: Subscription liveliness lease duration is less than publisher;");
      if (append_ret != RMW_RET_OK) {
        return append_ret;
      }
    }
  }

  if (*compatibility == RMW_QOS_COMPATIBILITY_OK) {
    bool pub_reliability_unknown =
      publisher_profile.reliability == RMW_QOS_POLICY_RELIABILITY_SYSTEM_DEFAULT ||
      publisher_profile.reliability == RMW_QOS_POLICY_RELIABILITY_UNKNOWN;
    bool sub_reliability_unknown =
      subscription_profile.reliability == RMW_QOS_POLICY_RELIABILITY_SYSTEM_DEFAULT ||
      subscription_profile.reliability == RMW_QOS_POLICY_RELIABILITY_UNKNOWN;
    bool pub_durability_unknown =
      publisher_profile.durability == RMW_QOS_POLICY_DURABILITY_SYSTEM_DEFAULT ||
      publisher_profile.durability == RMW_QOS_POLICY_DURABILITY_UNKNOWN;
    bool sub_durability_unknown =
      subscription_profile.durability == RMW_QOS_POLICY_DURABILITY_SYSTEM_DEFAULT ||
      subscription_profile.durability == RMW_QOS_POLICY_DURABILITY_UNKNOWN;
    bool pub_liveliness_unknown =
      publisher_profile.liveliness == RMW_QOS_POLICY_LIVELINESS_SYSTEM_DEFAULT ||
      publisher_profile.liveliness == RMW_QOS_POLICY_LIVELINESS_UNKNOWN;
    bool sub_liveliness_unknown =
      subscription_profile.liveliness == RMW_QOS_POLICY_LIVELINESS_SYSTEM_DEFAULT ||
      subscription_profile.liveliness == RMW_QOS_POLICY_LIVELINESS_UNKNOWN;

    const char * pub_reliability_str =
      rmw_qos_reliability_policy_to_str(publisher_profile.reliability);
    if (pub_reliability_str == NULL) {
      pub_reliability_str = "unknown";
    }
    const char * sub_reliability_str =
      rmw_qos_reliability_policy_to_str(subscription_profile.reliability);
    if (sub_reliability_str == NULL) {
      sub_reliability_str = "unknown";
    }
    const char * pub_durability_str =
      rmw_qos_durability_policy_to_str(publisher_profile.durability);
    if (pub_durability_str == NULL) {
      pub_durability_str = "unknown";
    }
    const char * sub_durability_str =
      rmw_qos_durability_policy_to_str(subscription_profile.durability);
    if (sub_durability_str == NULL) {
      sub_durability_str = "unknown";
    }
    const char * pub_liveliness_str =
      rmw_qos_liveliness_policy_to_str(publisher_profile.liveliness);
    if (pub_liveliness_str == NULL) {
      pub_liveliness_str = "unknown";
    }
    const char * sub_liveliness_str =
      rmw_qos_liveliness_policy_to_str(subscription_profile.liveliness);
    if (sub_liveliness_str == NULL) {
      sub_liveliness_str = "unknown";
    }

    if (pub_reliability_unknown && sub_reliability_unknown) {
      *compatibility = RMW_QOS_COMPATIBILITY_WARNING;
      rmw_ret_t append_ret = append_to_reason(
        reason,
        reason_size,
        "WARNING: Publisher reliability is %s and subscription reliability is %s;",
        pub_reliability_str,
        sub_reliability_str);
      if (append_ret != RMW_RET_OK) {
        return append_ret;
      }
    } else if (pub_reliability_unknown &&
      subscription_profile.reliability == RMW_QOS_POLICY_RELIABILITY_RELIABLE)
    {
      *compatibility = RMW_QOS_COMPATIBILITY_WARNING;
      rmw_ret_t append_ret = append_to_reason(
        reason,
        reason_size,
        "WARNING: Reliable subscription, but publisher is %s;",
        pub_reliability_str);
      if (append_ret != RMW_RET_OK) {
        return append_ret;
      }
    } else if (publisher_profile.reliability == RMW_QOS_POLICY_RELIABILITY_BEST_EFFORT &&
      sub_reliability_unknown)
    {
      *compatibility = RMW_QOS_COMPATIBILITY_WARNING;
      rmw_ret_t append_ret = append_to_reason(
        reason,
        reason_size,
        "WARNING: Best effort publisher, but subscription is %s;",
        sub_reliability_str);
      if (append_ret != RMW_RET_OK) {
        return append_ret;
      }
    }

    if (pub_durability_unknown && sub_durability_unknown) {
      *compatibility = RMW_QOS_COMPATIBILITY_WARNING;
      rmw_ret_t append_ret = append_to_reason(
        reason,
        reason_size,
        "WARNING: Publisher durabilty is %s and subscription durability is %s;",
        pub_durability_str,
        sub_durability_str);
      if (append_ret != RMW_RET_OK) {
        return append_ret;
      }
    } else if (pub_durability_unknown &&
      subscription_profile.durability == RMW_QOS_POLICY_DURABILITY_TRANSIENT_LOCAL)
    {
      *compatibility = RMW_QOS_COMPATIBILITY_WARNING;
      rmw_ret_t append_ret = append_to_reason(
        reason,
        reason_size,
        "WARNING: Transient local subscription, but publisher is %s;",
        pub_durability_str);
      if (append_ret != RMW_RET_OK) {
        return append_ret;
      }
    } else if (publisher_profile.durability == RMW_QOS_POLICY_DURABILITY_VOLATILE &&
      sub_durability_unknown)
    {
      *compatibility = RMW_QOS_COMPATIBILITY_WARNING;
      rmw_ret_t append_ret = append_to_reason(
        reason,
        reason_size,
        "WARNING: Volatile publisher, but subscription is %s;",
        sub_durability_str);
      if (append_ret != RMW_RET_OK) {
        return append_ret;
      }
    }

    if (pub_liveliness_unknown && sub_liveliness_unknown) {
      *compatibility = RMW_QOS_COMPATIBILITY_WARNING;
      rmw_ret_t append_ret = append_to_reason(
        reason,
        reason_size,
        "WARNING: Publisher liveliness is %s and subscription liveliness is %s;",
        pub_liveliness_str,
        sub_liveliness_str);
      if (append_ret != RMW_RET_OK) {
        return append_ret;
      }
    } else if (pub_liveliness_unknown &&
      subscription_profile.liveliness == RMW_QOS_POLICY_LIVELINESS_MANUAL_BY_TOPIC)
    {
      *compatibility = RMW_QOS_COMPATIBILITY_WARNING;
      rmw_ret_t append_ret = append_to_reason(
        reason,
        reason_size,
        "WARNING: Subscription's liveliness is manual by topic, but publisher's is %s;",
        pub_liveliness_str);
      if (append_ret != RMW_RET_OK) {
        return append_ret;
      }
    } else if (publisher_profile.liveliness == RMW_QOS_POLICY_LIVELINESS_AUTOMATIC &&
      sub_liveliness_unknown)
    {
      *compatibility = RMW_QOS_COMPATIBILITY_WARNING;
      rmw_ret_t append_ret = append_to_reason(
        reason,
        reason_size,
        "WARNING: Publisher's liveliness is automatic, but subscription's is %s;",
        sub_liveliness_str);
      if (append_ret != RMW_RET_OK) {
        return append_ret;
      }
    }
  }

  return RMW_RET_OK;
}

rmw_ret_t
rmw_set_log_severity(rmw_log_severity_t severity)
{
  rcutils_ret_t rc = rcutils_logging_set_logger_level("rmw_hdds", (int)severity);
  if (rc != RCUTILS_RET_OK) {
    return rmw_convert_rcutils_ret_to_rmw_ret(rc);
  }
  return RMW_RET_OK;
}

typedef struct
{
  rcutils_allocator_t allocator;
  rcutils_string_array_t * node_names;
  rcutils_string_array_t * node_namespaces;
  rcutils_string_array_t * enclaves;
  size_t index;
  rmw_ret_t status;
} hdds_node_enclave_fill_ctx_t;

static void
hdds_node_enclave_fill_cb(
  const char * node_name,
  const char * node_namespace,
  const char * node_enclave,
  void * user_data)
{
  hdds_node_enclave_fill_ctx_t * ctx = (hdds_node_enclave_fill_ctx_t *)user_data;
  if (ctx == NULL || ctx->status != RMW_RET_OK) {
    return;
  }

  if (ctx->index >= ctx->node_names->size) {
    ctx->status = RMW_RET_ERROR;
    return;
  }

  const char * enclave_safe = node_enclave != NULL ? node_enclave : "";

  char * name_copy = rcutils_strdup(node_name, ctx->allocator);
  if (name_copy == NULL) {
    ctx->status = RMW_RET_BAD_ALLOC;
    return;
  }

  char * namespace_copy = rcutils_strdup(node_namespace, ctx->allocator);
  if (namespace_copy == NULL) {
    ctx->allocator.deallocate(name_copy, ctx->allocator.state);
    ctx->status = RMW_RET_BAD_ALLOC;
    return;
  }

  char * enclave_copy = rcutils_strdup(enclave_safe, ctx->allocator);
  if (enclave_copy == NULL) {
    ctx->allocator.deallocate(name_copy, ctx->allocator.state);
    ctx->allocator.deallocate(namespace_copy, ctx->allocator.state);
    ctx->status = RMW_RET_BAD_ALLOC;
    return;
  }

  ctx->node_names->data[ctx->index] = name_copy;
  ctx->node_namespaces->data[ctx->index] = namespace_copy;
  ctx->enclaves->data[ctx->index] = enclave_copy;
  ctx->index++;
}

rmw_ret_t
rmw_get_node_names_with_enclaves(
  const rmw_node_t * node,
  rcutils_string_array_t * node_names,
  rcutils_string_array_t * node_namespaces,
  rcutils_string_array_t * enclaves)
{
  RMW_CHECK_ARGUMENT_FOR_NULL(node, RMW_RET_INVALID_ARGUMENT);
  RMW_CHECK_ARGUMENT_FOR_NULL(node_names, RMW_RET_INVALID_ARGUMENT);
  RMW_CHECK_ARGUMENT_FOR_NULL(node_namespaces, RMW_RET_INVALID_ARGUMENT);
  RMW_CHECK_ARGUMENT_FOR_NULL(enclaves, RMW_RET_INVALID_ARGUMENT);

  if (node->implementation_identifier != rmw_get_implementation_identifier()) {
    RMW_SET_ERROR_MSG("rmw_get_node_names_with_enclaves identifier mismatch");
    return RMW_RET_INCORRECT_RMW_IMPLEMENTATION;
  }

  if (node_names->data != NULL || node_names->size != 0) {
    RMW_SET_ERROR_MSG("node_names must be zero initialized");
    return RMW_RET_INVALID_ARGUMENT;
  }

  if (node_namespaces->data != NULL || node_namespaces->size != 0) {
    RMW_SET_ERROR_MSG("node_namespaces must be zero initialized");
    return RMW_RET_INVALID_ARGUMENT;
  }

  if (enclaves->data != NULL || enclaves->size != 0) {
    RMW_SET_ERROR_MSG("enclaves must be zero initialized");
    return RMW_RET_INVALID_ARGUMENT;
  }

  const rmw_hdds_node_impl_t * node_impl = (const rmw_hdds_node_impl_t *)node->data;
  if (node_impl == NULL || node_impl->context == NULL || node_impl->context->native_ctx == NULL) {
    RMW_SET_ERROR_MSG("invalid node implementation");
    return RMW_RET_ERROR;
  }
  rcutils_allocator_t allocator = select_node_allocator(node_impl);

  const size_t max_attempts = 3;
  for (size_t attempt = 0; attempt < max_attempts; ++attempt) {
    size_t node_count = 0;
    uint64_t version_before = 0;
    rmw_hdds_error_t list_status = rmw_hdds_context_for_each_node_with_enclave(
      node_impl->context->native_ctx,
      NULL,
      NULL,
      &version_before,
      &node_count);
    if (list_status != RMW_HDDS_ERROR_OK) {
      return map_hdds_error(list_status);
    }

    rcutils_ret_t rcutils_ret = rcutils_string_array_init(node_names, node_count, &allocator);
    if (rcutils_ret != RCUTILS_RET_OK) {
      return rmw_convert_rcutils_ret_to_rmw_ret(rcutils_ret);
    }
    rcutils_ret = rcutils_string_array_init(node_namespaces, node_count, &allocator);
    if (rcutils_ret != RCUTILS_RET_OK) {
      safe_string_array_fini(node_names);
      return rmw_convert_rcutils_ret_to_rmw_ret(rcutils_ret);
    }
    rcutils_ret = rcutils_string_array_init(enclaves, node_count, &allocator);
    if (rcutils_ret != RCUTILS_RET_OK) {
      safe_string_array_fini(node_names);
      safe_string_array_fini(node_namespaces);
      return rmw_convert_rcutils_ret_to_rmw_ret(rcutils_ret);
    }

    if (node_count == 0u) {
      return RMW_RET_OK;
    }

    hdds_node_enclave_fill_ctx_t fill_ctx = {
      .allocator = allocator,
      .node_names = node_names,
      .node_namespaces = node_namespaces,
      .enclaves = enclaves,
      .index = 0u,
      .status = RMW_RET_OK,
    };

    uint64_t version_after = 0;
    list_status = rmw_hdds_context_for_each_node_with_enclave(
      node_impl->context->native_ctx,
      hdds_node_enclave_fill_cb,
      &fill_ctx,
      &version_after,
      NULL);
    if (list_status != RMW_HDDS_ERROR_OK) {
      safe_string_array_fini(node_names);
      safe_string_array_fini(node_namespaces);
      safe_string_array_fini(enclaves);
      return map_hdds_error(list_status);
    }

    if (fill_ctx.status != RMW_RET_OK) {
      safe_string_array_fini(node_names);
      safe_string_array_fini(node_namespaces);
      safe_string_array_fini(enclaves);
      return fill_ctx.status;
    }

    if (version_before == version_after && fill_ctx.index == node_count) {
      node_names->size = fill_ctx.index;
      node_namespaces->size = fill_ctx.index;
      enclaves->size = fill_ctx.index;
      return RMW_RET_OK;
    }

    safe_string_array_fini(node_names);
    safe_string_array_fini(node_namespaces);
    safe_string_array_fini(enclaves);
  }

  RMW_SET_ERROR_MSG("graph changed while collecting node names with enclaves");
  return RMW_RET_ERROR;
}

bool
rmw_feature_supported(rmw_feature_t feature)
{
  switch (feature) {
    case RMW_FEATURE_MESSAGE_INFO_PUBLICATION_SEQUENCE_NUMBER:
    case RMW_FEATURE_MESSAGE_INFO_RECEPTION_SEQUENCE_NUMBER:
    default:
      return false;
  }
}
