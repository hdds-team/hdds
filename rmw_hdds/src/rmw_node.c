// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

#include <string.h>

#include <rmw/rmw.h>
#include <rmw/error_handling.h>
#include <rmw/get_node_info_and_types.h>
#include <rmw/get_topic_names_and_types.h>
#include <rmw/convert_rcutils_ret_to_rmw_ret.h>

#include <rcutils/allocator.h>
#include <rcutils/strdup.h>
#include <rcutils/types/string_array.h>
#include <rcutils/error_handling.h>
#include <rcutils/logging_macros.h>
#include <rcutils/macros.h>
#include <rosidl_typesupport_introspection_c/message_introspection.h>

#include "rmw_hdds/ffi.h"
#include "rmw_hdds/types.h"

static char *
hdds_duplicate_type_name(
  const rosidl_message_type_support_t * type_support,
  rcutils_allocator_t allocator)
{
  if (type_support == NULL || type_support->data == NULL) {
    return NULL;
  }

  const rosidl_typesupport_introspection_c__MessageMembers * members =
    (const rosidl_typesupport_introspection_c__MessageMembers *)type_support->data;
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

static void safe_names_and_types_fini(rmw_names_and_types_t * names_and_types)
{
  if (names_and_types == NULL) {
    return;
  }
  rmw_ret_t fini_ret = rmw_names_and_types_fini(names_and_types);
  if (fini_ret != RMW_RET_OK) {
    RCUTILS_LOG_WARN_NAMED("rmw_hdds", "rmw_names_and_types_fini returned %d", (int)fini_ret);
  }
}

static void safe_string_array_fini(rcutils_string_array_t * array)
{
  if (array == NULL) {
    return;
  }
  rcutils_ret_t fini_ret = rcutils_string_array_fini(array);
  if (fini_ret != RCUTILS_RET_OK) {
    RCUTILS_LOG_WARN_NAMED("rmw_hdds", "rcutils_string_array_fini returned %d", (int)fini_ret);
  }
}

static rmw_ret_t
hdds_fill_names_and_types(
  const rmw_hdds_endpoint_set_t * set,
  rcutils_allocator_t allocator,
  rmw_names_and_types_t * topic_names_and_types)
{
  rmw_ret_t status = rmw_names_and_types_init(
    topic_names_and_types,
    set->size,
    &allocator);
  if (status != RMW_RET_OK) {
    return status;
  }

  for (size_t idx = 0u; idx < set->size; ++idx) {
    const rmw_hdds_endpoint_entry_t * entry = &set->entries[idx];

    char * name_copy = rcutils_strdup(entry->topic_name, allocator);
    if (name_copy == NULL) {
      safe_names_and_types_fini(topic_names_and_types);
      return RMW_RET_BAD_ALLOC;
    }
    topic_names_and_types->names.data[idx] = name_copy;

    rcutils_string_array_t * type_array = &topic_names_and_types->types[idx];
    rcutils_ret_t rcutils_ret = rcutils_string_array_init(type_array, 1u, &allocator);
    if (rcutils_ret != RCUTILS_RET_OK) {
      safe_names_and_types_fini(topic_names_and_types);
      return rmw_convert_rcutils_ret_to_rmw_ret(rcutils_ret);
    }

    char * type_copy = hdds_duplicate_type_name(entry->type_support, allocator);
    if (type_copy == NULL) {
      safe_names_and_types_fini(topic_names_and_types);
      return RMW_RET_BAD_ALLOC;
    }

    type_array->data[0] = type_copy;
    type_array->size = 1u;
  }

  topic_names_and_types->names.size = set->size;
  return RMW_RET_OK;
}

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

rmw_node_t* rmw_create_node(
    rmw_context_t* context,
    const char* name,
    const char* namespace_)
{
    RMW_CHECK_ARGUMENT_FOR_NULL(context, NULL);
    RMW_CHECK_ARGUMENT_FOR_NULL(name, NULL);
    RMW_CHECK_ARGUMENT_FOR_NULL(namespace_, NULL);

    if (context->implementation_identifier != rmw_get_implementation_identifier()) {
        RMW_SET_ERROR_MSG("rmw_create_node identifier mismatch");
        return NULL;
    }

    rmw_hdds_context_impl_t* ctx_impl = (rmw_hdds_context_impl_t*)context->impl;
    if (ctx_impl == NULL || ctx_impl->native_ctx == NULL) {
        RMW_SET_ERROR_MSG("context is missing HDDS state");
        return NULL;
    }

    rcutils_allocator_t allocator = context->options.allocator;
    if (!rcutils_allocator_is_valid(&allocator)) {
        allocator = rcutils_get_default_allocator();
    }

    rmw_node_t* node =
        (rmw_node_t*)allocator.allocate(sizeof(rmw_node_t), allocator.state);
    if (node == NULL) {
        RMW_SET_ERROR_MSG("failed to allocate rmw_node_t");
        return NULL;
    }
    memset(node, 0, sizeof(rmw_node_t));

    rmw_hdds_node_impl_t* impl =
        (rmw_hdds_node_impl_t*)allocator.allocate(sizeof(rmw_hdds_node_impl_t), allocator.state);
    if (impl == NULL) {
        allocator.deallocate(node, allocator.state);
        RMW_SET_ERROR_MSG("failed to allocate node impl");
        return NULL;
    }
    memset(impl, 0, sizeof(*impl));
    rmw_hdds_endpoint_set_init(&impl->publishers);
    rmw_hdds_endpoint_set_init(&impl->subscriptions);

    char* name_copy = rcutils_strdup(name, allocator);
    if (name_copy == NULL) {
        allocator.deallocate(impl, allocator.state);
        allocator.deallocate(node, allocator.state);
        RMW_SET_ERROR_MSG("failed to duplicate node name");
        return NULL;
    }

    char* namespace_copy = rcutils_strdup(namespace_, allocator);
    if (namespace_copy == NULL) {
        allocator.deallocate(name_copy, allocator.state);
        allocator.deallocate(impl, allocator.state);
        allocator.deallocate(node, allocator.state);
        RMW_SET_ERROR_MSG("failed to duplicate node namespace");
        return NULL;
    }

    const struct HddsGuardCondition* guard_ptr = NULL;
    rmw_hdds_error_t guard_status = rmw_hdds_context_graph_guard_condition(
        ctx_impl->native_ctx, &guard_ptr);
    if (guard_status != RMW_HDDS_ERROR_OK || guard_ptr == NULL) {
        allocator.deallocate(namespace_copy, allocator.state);
        allocator.deallocate(name_copy, allocator.state);
        allocator.deallocate(impl, allocator.state);
        allocator.deallocate(node, allocator.state);
        RMW_SET_ERROR_MSG("failed to acquire graph guard condition");
        return NULL;
    }

    rmw_guard_condition_t* graph_guard =
        (rmw_guard_condition_t*)allocator.allocate(sizeof(rmw_guard_condition_t), allocator.state);
    if (graph_guard == NULL) {
        rmw_hdds_guard_condition_release(guard_ptr);
        allocator.deallocate(namespace_copy, allocator.state);
        allocator.deallocate(name_copy, allocator.state);
        allocator.deallocate(impl, allocator.state);
        allocator.deallocate(node, allocator.state);
        RMW_SET_ERROR_MSG("failed to allocate graph guard wrapper");
        return NULL;
    }
    memset(graph_guard, 0, sizeof(rmw_guard_condition_t));
    graph_guard->implementation_identifier = rmw_get_implementation_identifier();
    graph_guard->data = (void*)guard_ptr;
    graph_guard->context = context;

    impl->context = ctx_impl;
    impl->name = name_copy;
    impl->namespace_ = namespace_copy;
    impl->graph_guard = guard_ptr;
    impl->rmw_guard = graph_guard;
    impl->allocator = allocator;

    const char* enclave = context->options.enclave != NULL ? context->options.enclave : "";
    rmw_hdds_error_t register_status = rmw_hdds_context_register_node(
        ctx_impl->native_ctx,
        name,
        namespace_,
        enclave);
    if (register_status != RMW_HDDS_ERROR_OK) {
        rmw_destroy_guard_condition(impl->rmw_guard);
        allocator.deallocate(impl->namespace_, allocator.state);
        allocator.deallocate(impl->name, allocator.state);
        allocator.deallocate(impl, allocator.state);
        allocator.deallocate(node, allocator.state);
        RMW_SET_ERROR_MSG("failed to register node in graph cache");
        return NULL;
    }

    node->implementation_identifier = rmw_get_implementation_identifier();
    node->data = impl;
    node->name = impl->name;
    node->namespace_ = impl->namespace_;
    node->context = context;

    return node;
}

rmw_ret_t rmw_destroy_node(rmw_node_t* node) {
    RMW_CHECK_ARGUMENT_FOR_NULL(node, RMW_RET_INVALID_ARGUMENT);

    if (node->implementation_identifier != rmw_get_implementation_identifier()) {
        RMW_SET_ERROR_MSG("rmw_destroy_node identifier mismatch");
        return RMW_RET_INCORRECT_RMW_IMPLEMENTATION;
    }

    rmw_hdds_node_impl_t* impl = (rmw_hdds_node_impl_t*)node->data;
    if (impl == NULL) {
        RMW_SET_ERROR_MSG("invalid node implementation");
        return RMW_RET_ERROR;
    }

    rcutils_allocator_t allocator = impl->allocator;
    if (!rcutils_allocator_is_valid(&allocator)) {
        allocator = rcutils_get_default_allocator();
    }

    if (impl->context != NULL && impl->context->native_ctx != NULL) {
        (void)rmw_hdds_context_unregister_node(
            impl->context->native_ctx,
            impl->name != NULL ? impl->name : "",
            impl->namespace_ != NULL ? impl->namespace_ : "");
    }

    rmw_hdds_endpoint_set_fini(&impl->publishers, allocator);
    rmw_hdds_endpoint_set_fini(&impl->subscriptions, allocator);

    // Release the graph guard through the rmw wrapper (single ownership path).
    // rmw_destroy_guard_condition releases the underlying HddsGuardCondition
    // and frees the rmw_guard_condition_t wrapper in one call.
    if (impl->rmw_guard != NULL) {
        rmw_destroy_guard_condition(impl->rmw_guard);
        impl->rmw_guard = NULL;
        impl->graph_guard = NULL;  // owned by rmw_guard, already released
    }

    if (impl->name != NULL) {
        allocator.deallocate(impl->name, allocator.state);
        impl->name = NULL;
    }

    if (impl->namespace_ != NULL) {
        allocator.deallocate(impl->namespace_, allocator.state);
        impl->namespace_ = NULL;
    }

    allocator.deallocate(impl, allocator.state);
    allocator.deallocate(node, allocator.state);

    return RMW_RET_OK;
}

const rmw_guard_condition_t* rmw_node_get_graph_guard_condition(const rmw_node_t* node) {
    RMW_CHECK_ARGUMENT_FOR_NULL(node, NULL);

    if (node->implementation_identifier != rmw_get_implementation_identifier()) {
        RMW_SET_ERROR_MSG("rmw_node_get_graph_guard_condition identifier mismatch");
        return NULL;
    }

    const rmw_hdds_node_impl_t* impl = (const rmw_hdds_node_impl_t*)node->data;
    if (impl == NULL || impl->rmw_guard == NULL) {
        RMW_SET_ERROR_MSG("graph guard condition not available");
        return NULL;
    }

    return impl->rmw_guard;
}

typedef struct
{
  size_t count;
} hdds_topic_count_ctx_t;

static void
hdds_topic_count_cb(
  const char * topic_name,
  const char * type_name,
  uint32_t writer_count,
  uint32_t reader_count,
  void * user_data)
{
  (void)topic_name;
  (void)type_name;
  (void)writer_count;
  (void)reader_count;
  hdds_topic_count_ctx_t * ctx = (hdds_topic_count_ctx_t *)user_data;
  ctx->count++;
}

typedef struct
{
  rcutils_allocator_t allocator;
  rmw_names_and_types_t * names_and_types;
  size_t index;
  rmw_ret_t status;
} hdds_topic_fill_ctx_t;

static void
hdds_topic_fill_cb(
  const char * topic_name,
  const char * type_name,
  uint32_t writer_count,
  uint32_t reader_count,
  void * user_data)
{
  (void)writer_count;
  (void)reader_count;
  hdds_topic_fill_ctx_t * ctx = (hdds_topic_fill_ctx_t *)user_data;
  if (ctx->status != RMW_RET_OK) {
    return;
  }

  if (ctx->index >= ctx->names_and_types->names.size) {
    ctx->status = RMW_RET_ERROR;
    return;
  }

  char * name_copy = rcutils_strdup(topic_name, ctx->allocator);
  if (name_copy == NULL) {
    ctx->status = RMW_RET_BAD_ALLOC;
    return;
  }

  ctx->names_and_types->names.data[ctx->index] = name_copy;

  rcutils_string_array_t * type_array = &ctx->names_and_types->types[ctx->index];
  rcutils_ret_t rcutils_ret = rcutils_string_array_init(type_array, 1, &ctx->allocator);
  if (rcutils_ret != RCUTILS_RET_OK) {
    ctx->allocator.deallocate(name_copy, ctx->allocator.state);
    ctx->names_and_types->names.data[ctx->index] = NULL;
    ctx->status = rmw_convert_rcutils_ret_to_rmw_ret(rcutils_ret);
    return;
  }

  char * type_copy = rcutils_strdup(type_name, ctx->allocator);
  if (type_copy == NULL) {
    safe_string_array_fini(type_array);
    ctx->allocator.deallocate(name_copy, ctx->allocator.state);
    ctx->names_and_types->names.data[ctx->index] = NULL;
    ctx->status = RMW_RET_BAD_ALLOC;
    return;
  }

  type_array->data[0] = type_copy;
  type_array->size = 1;
  ctx->index++;
}

typedef struct
{
  rcutils_allocator_t allocator;
  rcutils_string_array_t * node_names;
  rcutils_string_array_t * node_namespaces;
  size_t index;
  rmw_ret_t status;
} hdds_node_fill_ctx_t;

static void
hdds_node_fill_cb(
  const char * node_name,
  const char * node_namespace,
  void * user_data)
{
  hdds_node_fill_ctx_t * ctx = (hdds_node_fill_ctx_t *)user_data;
  if (ctx->status != RMW_RET_OK) {
    return;
  }

  if (ctx->index >= ctx->node_names->size) {
    ctx->status = RMW_RET_ERROR;
    return;
  }

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

  ctx->node_names->data[ctx->index] = name_copy;
  ctx->node_namespaces->data[ctx->index] = namespace_copy;
  ctx->index++;
}

typedef struct
{
  rcutils_allocator_t allocator;
  rmw_names_and_types_t * names_and_types;
  size_t index;
  rmw_ret_t status;
} hdds_endpoint_fill_ctx_t;

static void
hdds_endpoint_fill_cb(
  const char * topic_name,
  const char * type_name,
  const uint8_t * endpoint_gid,
  const rmw_hdds_qos_profile_t * qos_profile,
  void * user_data)
{
  (void)endpoint_gid;
  (void)qos_profile;
  hdds_endpoint_fill_ctx_t * ctx = (hdds_endpoint_fill_ctx_t *)user_data;
  if (ctx->status != RMW_RET_OK) {
    return;
  }

  if (ctx->index >= ctx->names_and_types->names.size) {
    ctx->status = RMW_RET_ERROR;
    return;
  }

  char * topic_copy = rcutils_strdup(topic_name, ctx->allocator);
  if (topic_copy == NULL) {
    ctx->status = RMW_RET_BAD_ALLOC;
    return;
  }

  rcutils_string_array_t * type_array = &ctx->names_and_types->types[ctx->index];
  rcutils_ret_t rcutils_ret = rcutils_string_array_init(type_array, 1u, &ctx->allocator);
  if (rcutils_ret != RCUTILS_RET_OK) {
    ctx->allocator.deallocate(topic_copy, ctx->allocator.state);
    ctx->status = rmw_convert_rcutils_ret_to_rmw_ret(rcutils_ret);
    return;
  }

  char * type_copy = rcutils_strdup(type_name, ctx->allocator);
  if (type_copy == NULL) {
    ctx->allocator.deallocate(topic_copy, ctx->allocator.state);
    safe_string_array_fini(type_array);
    ctx->status = RMW_RET_BAD_ALLOC;
    return;
  }

  ctx->names_and_types->names.data[ctx->index] = topic_copy;
  type_array->data[0] = type_copy;
  type_array->size = 1u;
  ctx->index++;
}

rmw_ret_t rmw_get_topic_names_and_types(
    const rmw_node_t * node,
    rcutils_allocator_t * allocator,
    bool no_demangle,
    rmw_names_and_types_t * topic_names_and_types)
{
    RCUTILS_UNUSED(no_demangle);

    RMW_CHECK_ARGUMENT_FOR_NULL(node, RMW_RET_INVALID_ARGUMENT);
    RMW_CHECK_ARGUMENT_FOR_NULL(topic_names_and_types, RMW_RET_INVALID_ARGUMENT);

    if (node->implementation_identifier != rmw_get_implementation_identifier()) {
        RMW_SET_ERROR_MSG("rmw_get_topic_names_and_types identifier mismatch");
        return RMW_RET_INCORRECT_RMW_IMPLEMENTATION;
    }

    rmw_hdds_node_impl_t * impl = (rmw_hdds_node_impl_t *)node->data;
    if (impl == NULL || impl->context == NULL || impl->context->native_ctx == NULL) {
        RMW_SET_ERROR_MSG("invalid node implementation");
        return RMW_RET_ERROR;
    }

    rcutils_allocator_t effective_allocator =
        allocator != NULL ? *allocator : rcutils_get_default_allocator();
    if (!rcutils_allocator_is_valid(&effective_allocator)) {
        RMW_SET_ERROR_MSG("allocator is invalid");
        return RMW_RET_INVALID_ARGUMENT;
    }

    rmw_ret_t status = rmw_names_and_types_check_zero(topic_names_and_types);
    if (status != RMW_RET_OK) {
        return status;
    }

    const size_t max_attempts = 3;
    for (size_t attempt = 0; attempt < max_attempts; ++attempt) {
        hdds_topic_count_ctx_t count_ctx = {0};
        uint64_t version_before = 0;
        rmw_hdds_error_t err = rmw_hdds_context_for_each_topic(
            impl->context->native_ctx,
            hdds_topic_count_cb,
            &count_ctx,
            &version_before);
        if (err != RMW_HDDS_ERROR_OK) {
            return map_hdds_error(err);
        }

        status = rmw_names_and_types_init(
            topic_names_and_types,
            count_ctx.count,
            &effective_allocator);
        if (status != RMW_RET_OK) {
            return status;
        }

        hdds_topic_fill_ctx_t fill_ctx = {
            .allocator = effective_allocator,
            .names_and_types = topic_names_and_types,
            .index = 0,
            .status = RMW_RET_OK,
        };

        uint64_t version_after = 0;
        err = rmw_hdds_context_for_each_topic(
            impl->context->native_ctx,
            hdds_topic_fill_cb,
            &fill_ctx,
            &version_after);
        if (err != RMW_HDDS_ERROR_OK) {
            safe_names_and_types_fini(topic_names_and_types);
            return map_hdds_error(err);
        }

        if (fill_ctx.status != RMW_RET_OK) {
            safe_names_and_types_fini(topic_names_and_types);
            return fill_ctx.status;
        }

        if (version_before == version_after && fill_ctx.index == count_ctx.count) {
            topic_names_and_types->names.size = fill_ctx.index;
            return RMW_RET_OK;
        }

        safe_names_and_types_fini(topic_names_and_types);
    }

    RMW_SET_ERROR_MSG("graph changed while collecting topic names");
    return RMW_RET_ERROR;
}

rmw_ret_t rmw_get_subscriber_names_and_types_by_node(
    const rmw_node_t * node,
    rcutils_allocator_t * allocator,
    const char * node_name,
    const char * node_namespace,
    bool no_demangle,
    rmw_names_and_types_t * topic_names_and_types)
{
    RCUTILS_UNUSED(no_demangle);

    RMW_CHECK_ARGUMENT_FOR_NULL(node, RMW_RET_INVALID_ARGUMENT);
    RMW_CHECK_ARGUMENT_FOR_NULL(node_name, RMW_RET_INVALID_ARGUMENT);
    RMW_CHECK_ARGUMENT_FOR_NULL(node_namespace, RMW_RET_INVALID_ARGUMENT);
    RMW_CHECK_ARGUMENT_FOR_NULL(topic_names_and_types, RMW_RET_INVALID_ARGUMENT);

    if (node->implementation_identifier != rmw_get_implementation_identifier()) {
        RMW_SET_ERROR_MSG("rmw_get_subscriber_names_and_types_by_node identifier mismatch");
        return RMW_RET_INCORRECT_RMW_IMPLEMENTATION;
    }

    rmw_ret_t zero_status = rmw_names_and_types_check_zero(topic_names_and_types);
    if (zero_status != RMW_RET_OK) {
        return zero_status;
    }

    rmw_hdds_node_impl_t * impl = (rmw_hdds_node_impl_t *)node->data;
    if (impl == NULL || impl->context == NULL || impl->context->native_ctx == NULL) {
        RMW_SET_ERROR_MSG("invalid node implementation");
        return RMW_RET_ERROR;
    }

    rcutils_allocator_t effective_allocator = allocator != NULL
        ? *allocator
        : rcutils_get_default_allocator();
    if (!rcutils_allocator_is_valid(&effective_allocator)) {
        RMW_SET_ERROR_MSG("allocator is invalid");
        return RMW_RET_INVALID_ARGUMENT;
    }

    size_t endpoint_count = 0;
    rmw_hdds_error_t list_status = rmw_hdds_context_for_each_subscription_endpoint(
        impl->context->native_ctx,
        node_name,
        node_namespace,
        NULL,
        NULL,
        NULL,
        &endpoint_count);

    if (list_status == RMW_HDDS_ERROR_NOT_FOUND) {
        return RMW_RET_NODE_NAME_NON_EXISTENT;
    }

    if (list_status != RMW_HDDS_ERROR_OK) {
        return map_hdds_error(list_status);
    }

    rmw_ret_t init_status = rmw_names_and_types_init(
        topic_names_and_types,
        endpoint_count,
        &effective_allocator);
    if (init_status != RMW_RET_OK) {
        return init_status;
    }

    if (endpoint_count == 0) {
        return RMW_RET_OK;
    }

    hdds_endpoint_fill_ctx_t fill_ctx = {
        .allocator = effective_allocator,
        .names_and_types = topic_names_and_types,
        .index = 0,
        .status = RMW_RET_OK,
    };

    list_status = rmw_hdds_context_for_each_subscription_endpoint(
        impl->context->native_ctx,
        node_name,
        node_namespace,
        hdds_endpoint_fill_cb,
        &fill_ctx,
        NULL,
        NULL);

    if (list_status != RMW_HDDS_ERROR_OK) {
        safe_names_and_types_fini(topic_names_and_types);
        return map_hdds_error(list_status);
    }

    if (fill_ctx.status != RMW_RET_OK) {
        safe_names_and_types_fini(topic_names_and_types);
        return fill_ctx.status;
    }

    topic_names_and_types->names.size = fill_ctx.index;

    return RMW_RET_OK;
}

rmw_ret_t rmw_get_publisher_names_and_types_by_node(
    const rmw_node_t * node,
    rcutils_allocator_t * allocator,
    const char * node_name,
    const char * node_namespace,
    bool no_demangle,
    rmw_names_and_types_t * topic_names_and_types)
{
    RCUTILS_UNUSED(no_demangle);

    RMW_CHECK_ARGUMENT_FOR_NULL(node, RMW_RET_INVALID_ARGUMENT);
    RMW_CHECK_ARGUMENT_FOR_NULL(node_name, RMW_RET_INVALID_ARGUMENT);
    RMW_CHECK_ARGUMENT_FOR_NULL(node_namespace, RMW_RET_INVALID_ARGUMENT);
    RMW_CHECK_ARGUMENT_FOR_NULL(topic_names_and_types, RMW_RET_INVALID_ARGUMENT);

    if (node->implementation_identifier != rmw_get_implementation_identifier()) {
        RMW_SET_ERROR_MSG("rmw_get_publisher_names_and_types_by_node identifier mismatch");
        return RMW_RET_INCORRECT_RMW_IMPLEMENTATION;
    }

    rmw_ret_t zero_status = rmw_names_and_types_check_zero(topic_names_and_types);
    if (zero_status != RMW_RET_OK) {
        return zero_status;
    }

    rmw_hdds_node_impl_t * impl = (rmw_hdds_node_impl_t *)node->data;
    if (impl == NULL || impl->context == NULL || impl->context->native_ctx == NULL) {
        RMW_SET_ERROR_MSG("invalid node implementation");
        return RMW_RET_ERROR;
    }

    rcutils_allocator_t effective_allocator = allocator != NULL
        ? *allocator
        : rcutils_get_default_allocator();
    if (!rcutils_allocator_is_valid(&effective_allocator)) {
        RMW_SET_ERROR_MSG("allocator is invalid");
        return RMW_RET_INVALID_ARGUMENT;
    }

    size_t endpoint_count = 0;
    rmw_hdds_error_t list_status = rmw_hdds_context_for_each_publisher_endpoint(
        impl->context->native_ctx,
        node_name,
        node_namespace,
        NULL,
        NULL,
        NULL,
        &endpoint_count);

    if (list_status == RMW_HDDS_ERROR_NOT_FOUND) {
        return RMW_RET_NODE_NAME_NON_EXISTENT;
    }

    if (list_status != RMW_HDDS_ERROR_OK) {
        return map_hdds_error(list_status);
    }

    rmw_ret_t init_status = rmw_names_and_types_init(
        topic_names_and_types,
        endpoint_count,
        &effective_allocator);
    if (init_status != RMW_RET_OK) {
        return init_status;
    }

    if (endpoint_count == 0) {
        return RMW_RET_OK;
    }

    hdds_endpoint_fill_ctx_t fill_ctx = {
        .allocator = effective_allocator,
        .names_and_types = topic_names_and_types,
        .index = 0,
        .status = RMW_RET_OK,
    };

    list_status = rmw_hdds_context_for_each_publisher_endpoint(
        impl->context->native_ctx,
        node_name,
        node_namespace,
        hdds_endpoint_fill_cb,
        &fill_ctx,
        NULL,
        NULL);

    if (list_status != RMW_HDDS_ERROR_OK) {
        safe_names_and_types_fini(topic_names_and_types);
        return map_hdds_error(list_status);
    }

    if (fill_ctx.status != RMW_RET_OK) {
        safe_names_and_types_fini(topic_names_and_types);
        return fill_ctx.status;
    }

    topic_names_and_types->names.size = fill_ctx.index;

    return RMW_RET_OK;
}

rmw_ret_t rmw_get_node_names(
    const rmw_node_t * node,
    rcutils_string_array_t * node_names,
    rcutils_string_array_t * node_namespaces)
{
    RMW_CHECK_ARGUMENT_FOR_NULL(node, RMW_RET_INVALID_ARGUMENT);
    RMW_CHECK_ARGUMENT_FOR_NULL(node_names, RMW_RET_INVALID_ARGUMENT);
    RMW_CHECK_ARGUMENT_FOR_NULL(node_namespaces, RMW_RET_INVALID_ARGUMENT);

    if (node->implementation_identifier != rmw_get_implementation_identifier()) {
        RMW_SET_ERROR_MSG("rmw_get_node_names identifier mismatch");
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

    rmw_hdds_node_impl_t * impl = (rmw_hdds_node_impl_t *)node->data;
    if (impl == NULL || impl->context == NULL || impl->context->native_ctx == NULL) {
        RMW_SET_ERROR_MSG("invalid node implementation");
        return RMW_RET_ERROR;
    }

    rcutils_allocator_t allocator = impl->allocator;
    if (!rcutils_allocator_is_valid(&allocator)) {
        allocator = rcutils_get_default_allocator();
    }

    const size_t max_attempts = 3;
    for (size_t attempt = 0; attempt < max_attempts; ++attempt) {
        size_t node_count = 0;
        uint64_t version_before = 0;
        rmw_hdds_error_t list_status = rmw_hdds_context_for_each_node(
            impl->context->native_ctx,
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

        if (node_count == 0) {
            return RMW_RET_OK;
        }

        hdds_node_fill_ctx_t fill_ctx = {
            .allocator = allocator,
            .node_names = node_names,
            .node_namespaces = node_namespaces,
            .index = 0,
            .status = RMW_RET_OK,
        };

        uint64_t version_after = 0;
        list_status = rmw_hdds_context_for_each_node(
            impl->context->native_ctx,
            hdds_node_fill_cb,
            &fill_ctx,
            &version_after,
            NULL);
        if (list_status != RMW_HDDS_ERROR_OK) {
            safe_string_array_fini(node_names);
            safe_string_array_fini(node_namespaces);
            return map_hdds_error(list_status);
        }

        if (fill_ctx.status != RMW_RET_OK) {
            safe_string_array_fini(node_names);
            safe_string_array_fini(node_namespaces);
            return fill_ctx.status;
        }

        if (version_before == version_after && fill_ctx.index == node_count) {
            node_names->size = fill_ctx.index;
            node_namespaces->size = fill_ctx.index;
            return RMW_RET_OK;
        }

        safe_string_array_fini(node_names);
        safe_string_array_fini(node_namespaces);
    }

    RMW_SET_ERROR_MSG("graph changed while collecting node names");
    return RMW_RET_ERROR;
}
