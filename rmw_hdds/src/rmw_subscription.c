// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

#include <rmw/rmw.h>
#include <rmw/error_handling.h>
#include <rmw/subscription_options.h>

#include <rosidl_runtime_c/message_type_support_struct.h>
#include <rosidl_runtime_c/string.h>
#include <rosidl_runtime_c/u16string.h>
#include <rosidl_typesupport_introspection_c/identifier.h>
#include <rosidl_typesupport_introspection_c/message_introspection.h>

#include <rcutils/allocator.h>
#include <rcutils/error_handling.h>
#include <rcutils/logging_macros.h>
#include <rcutils/strdup.h>
#include <string.h>

#include "hdds.h"  // NOLINT(build/include_subdir)
#include "rmw_hdds/ffi.h"
#include "rmw_hdds/types.h"
#include "rmw_hdds/qos.h"

static const rosidl_message_type_support_t *
get_typesupport_handle(
    const rosidl_message_type_support_t * type_support,
    const char * identifier)
{
    if (type_support == NULL || identifier == NULL) {
        return NULL;
    }

    const rosidl_message_type_support_t * handle =
        get_message_typesupport_handle(type_support, identifier);
    if (handle != NULL) {
        return handle;
    }

    return NULL;
}

static rcutils_allocator_t
select_allocator(const rcutils_allocator_t *allocator)
{
    if (allocator != NULL && rcutils_allocator_is_valid(allocator)) {
        return *allocator;
    }
    return rcutils_get_default_allocator();
}

static const char *
normalize_topic(const char * topic_name)
{
    if (topic_name == NULL) {
        return NULL;
    }
    if (topic_name[0] == '/' && topic_name[1] != '\0') {
        return topic_name + 1;
    }
    return topic_name;
}

static bool
rmw_hdds_compare_signed(int64_t lhs, rmw_hdds_filter_op_t op, int64_t rhs)
{
    switch (op) {
        case RMW_HDDS_FILTER_OP_EQ:
            return lhs == rhs;
        case RMW_HDDS_FILTER_OP_NEQ:
            return lhs != rhs;
        case RMW_HDDS_FILTER_OP_LT:
            return lhs < rhs;
        case RMW_HDDS_FILTER_OP_LTE:
            return lhs <= rhs;
        case RMW_HDDS_FILTER_OP_GT:
            return lhs > rhs;
        case RMW_HDDS_FILTER_OP_GTE:
            return lhs >= rhs;
        default:
            return false;
    }
}

static bool
rmw_hdds_compare_unsigned(uint64_t lhs, rmw_hdds_filter_op_t op, uint64_t rhs)
{
    switch (op) {
        case RMW_HDDS_FILTER_OP_EQ:
            return lhs == rhs;
        case RMW_HDDS_FILTER_OP_NEQ:
            return lhs != rhs;
        case RMW_HDDS_FILTER_OP_LT:
            return lhs < rhs;
        case RMW_HDDS_FILTER_OP_LTE:
            return lhs <= rhs;
        case RMW_HDDS_FILTER_OP_GT:
            return lhs > rhs;
        case RMW_HDDS_FILTER_OP_GTE:
            return lhs >= rhs;
        default:
            return false;
    }
}

static bool
rmw_hdds_compare_double(double lhs, rmw_hdds_filter_op_t op, double rhs)
{
    switch (op) {
        case RMW_HDDS_FILTER_OP_EQ:
            return lhs == rhs;
        case RMW_HDDS_FILTER_OP_NEQ:
            return lhs != rhs;
        case RMW_HDDS_FILTER_OP_LT:
            return lhs < rhs;
        case RMW_HDDS_FILTER_OP_LTE:
            return lhs <= rhs;
        case RMW_HDDS_FILTER_OP_GT:
            return lhs > rhs;
        case RMW_HDDS_FILTER_OP_GTE:
            return lhs >= rhs;
        default:
            return false;
    }
}

static bool
rmw_hdds_compare_long_double(long double lhs, rmw_hdds_filter_op_t op, long double rhs)
{
    switch (op) {
        case RMW_HDDS_FILTER_OP_EQ:
            return lhs == rhs;
        case RMW_HDDS_FILTER_OP_NEQ:
            return lhs != rhs;
        case RMW_HDDS_FILTER_OP_LT:
            return lhs < rhs;
        case RMW_HDDS_FILTER_OP_LTE:
            return lhs <= rhs;
        case RMW_HDDS_FILTER_OP_GT:
            return lhs > rhs;
        case RMW_HDDS_FILTER_OP_GTE:
            return lhs >= rhs;
        default:
            return false;
    }
}

static bool
rmw_hdds_content_filter_matches(
    const rmw_hdds_subscription_impl_t * impl,
    const void * ros_message)
{
    if (impl == NULL || ros_message == NULL) {
        return true;
    }

    if (!impl->content_filter.enabled) {
        return true;
    }

    const rmw_hdds_content_filter_t * filter = &impl->content_filter;
    const uint8_t * base = (const uint8_t *)ros_message + filter->member_offset;

    switch (filter->member_type) {
        case ROS_TYPE_BOOLEAN: {
            bool value = *(const bool *)base;
            if (filter->parameter.kind != RMW_HDDS_FILTER_VALUE_BOOL) {
                return false;
            }
            return rmw_hdds_compare_signed(value ? 1 : 0, filter->op,
                filter->parameter.boolean ? 1 : 0);
        }
        case ROS_TYPE_CHAR:
        case ROS_TYPE_OCTET:
        case ROS_TYPE_UINT8: {
            uint8_t value = *(const uint8_t *)base;
            if (filter->parameter.kind != RMW_HDDS_FILTER_VALUE_UNSIGNED) {
                return false;
            }
            return rmw_hdds_compare_unsigned(value, filter->op, filter->parameter.unsigned_value);
        }
        case ROS_TYPE_WCHAR:
        case ROS_TYPE_UINT16: {
            uint16_t value = *(const uint16_t *)base;
            if (filter->parameter.kind != RMW_HDDS_FILTER_VALUE_UNSIGNED) {
                return false;
            }
            return rmw_hdds_compare_unsigned(value, filter->op, filter->parameter.unsigned_value);
        }
        case ROS_TYPE_UINT32: {
            uint32_t value = *(const uint32_t *)base;
            if (filter->parameter.kind != RMW_HDDS_FILTER_VALUE_UNSIGNED) {
                return false;
            }
            return rmw_hdds_compare_unsigned(value, filter->op, filter->parameter.unsigned_value);
        }
        case ROS_TYPE_UINT64: {
            uint64_t value = *(const uint64_t *)base;
            if (filter->parameter.kind != RMW_HDDS_FILTER_VALUE_UNSIGNED) {
                return false;
            }
            return rmw_hdds_compare_unsigned(value, filter->op, filter->parameter.unsigned_value);
        }
        case ROS_TYPE_INT8: {
            int8_t value = *(const int8_t *)base;
            if (filter->parameter.kind != RMW_HDDS_FILTER_VALUE_SIGNED) {
                return false;
            }
            return rmw_hdds_compare_signed(value, filter->op, filter->parameter.signed_value);
        }
        case ROS_TYPE_INT16: {
            int16_t value = *(const int16_t *)base;
            if (filter->parameter.kind != RMW_HDDS_FILTER_VALUE_SIGNED) {
                return false;
            }
            return rmw_hdds_compare_signed(value, filter->op, filter->parameter.signed_value);
        }
        case ROS_TYPE_INT32: {
            int32_t value = *(const int32_t *)base;
            if (filter->parameter.kind != RMW_HDDS_FILTER_VALUE_SIGNED) {
                return false;
            }
            return rmw_hdds_compare_signed(value, filter->op, filter->parameter.signed_value);
        }
        case ROS_TYPE_INT64: {
            int64_t value = *(const int64_t *)base;
            if (filter->parameter.kind != RMW_HDDS_FILTER_VALUE_SIGNED) {
                return false;
            }
            return rmw_hdds_compare_signed(value, filter->op, filter->parameter.signed_value);
        }
        case ROS_TYPE_FLOAT: {
            float value = *(const float *)base;
            if (filter->parameter.kind != RMW_HDDS_FILTER_VALUE_FLOAT) {
                return false;
            }
            return rmw_hdds_compare_double(value, filter->op, filter->parameter.float_value);
        }
        case ROS_TYPE_DOUBLE: {
            double value = *(const double *)base;
            if (filter->parameter.kind != RMW_HDDS_FILTER_VALUE_FLOAT) {
                return false;
            }
            return rmw_hdds_compare_double(value, filter->op, filter->parameter.float_value);
        }
        case ROS_TYPE_LONG_DOUBLE: {
            long double value = *(const long double *)base;
            if (filter->parameter.kind != RMW_HDDS_FILTER_VALUE_LONG_DOUBLE) {
                return false;
            }
            return rmw_hdds_compare_long_double(
                value,
                filter->op,
                filter->parameter.long_double_value);
        }
        case ROS_TYPE_STRING: {
            const rosidl_runtime_c__String * str = (const rosidl_runtime_c__String *)base;
            if (filter->parameter.kind != RMW_HDDS_FILTER_VALUE_STRING ||
                filter->parameter.string_value == NULL)
            {
                return false;
            }
            const char * data = str->data != NULL ? str->data : "";
            size_t len = str->data != NULL ? str->size : 0u;
            bool equal = len == filter->parameter.string_length &&
                strncmp(data, filter->parameter.string_value, len) == 0;
            if (filter->op == RMW_HDDS_FILTER_OP_EQ) {
                return equal;
            }
            if (filter->op == RMW_HDDS_FILTER_OP_NEQ) {
                return !equal;
            }
            return false;
        }
        default:
            return true;
    }
}

static void *
rmw_hdds_allocate_message(
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
rmw_hdds_free_message(
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

// Extract the ROS2 type name from introspection type support
// Returns format like "std_msgs/msg/Int32"
static char *
extract_type_name_from_introspection(
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

    // Format: "package/msg/TypeName"
    // The namespace comes as "package__msg" (with double underscores)
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

/// Try to extract the raw struct size from introspection type support.
/// Returns 0 if introspection is unavailable.
static size_t
rmw_hdds_get_message_size_from_introspection(const rosidl_message_type_support_t * introspection_ts)
{
    if (introspection_ts == NULL) {
        return 0u;
    }
    const rosidl_typesupport_introspection_c__MessageMembers * members =
        (const rosidl_typesupport_introspection_c__MessageMembers *)introspection_ts->data;
    if (members == NULL) {
        return 0u;
    }
    return members->size_of_;
}

static rmw_hdds_codec_kind_t
select_codec_for_topic(const char * topic_name)
{
    const char * normalized = normalize_topic(topic_name);
    if (normalized == NULL) {
        return RMW_HDDS_CODEC_NONE;
    }
    if (strcmp(normalized, "chatter") == 0) {
        return RMW_HDDS_CODEC_STRING;
    }
    if (strcmp(normalized, "rosout") == 0) {
        return RMW_HDDS_CODEC_LOG;
    }
    if (strcmp(normalized, "parameter_events") == 0) {
        return RMW_HDDS_CODEC_PARAMETER_EVENT;
    }
    return RMW_HDDS_CODEC_NONE;
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

typedef struct {
    const char * topic_name;
    size_t count;
    bool matched;
} hdds_topic_match_ctx_t;

static void
hdds_match_topic_writers_cb(
    const char * topic_name,
    const char * type_name,
    uint32_t writer_count,
    uint32_t reader_count,
    void * user_data)
{
    (void)type_name;
    (void)reader_count;
    hdds_topic_match_ctx_t * ctx = (hdds_topic_match_ctx_t *)user_data;
    if (ctx == NULL || ctx->matched) {
        return;
    }
    if (topic_name != NULL && ctx->topic_name != NULL &&
        strcmp(topic_name, ctx->topic_name) == 0) {
        ctx->count = (size_t)writer_count;
        ctx->matched = true;
    }
}

rmw_subscription_t * rmw_create_subscription(
    const rmw_node_t * node,
    const rosidl_message_type_support_t * type_support,
    const char * topic_name,
    const rmw_qos_profile_t * qos_profile,
    const rmw_subscription_options_t * subscription_options)
{
    RMW_CHECK_ARGUMENT_FOR_NULL(node, NULL);
    RMW_CHECK_ARGUMENT_FOR_NULL(type_support, NULL);
    RMW_CHECK_ARGUMENT_FOR_NULL(topic_name, NULL);
    RMW_CHECK_ARGUMENT_FOR_NULL(qos_profile, NULL);

    if (node->implementation_identifier != rmw_get_implementation_identifier()) {
        RMW_SET_ERROR_MSG("rmw_create_subscription identifier mismatch");
        return NULL;
    }

    const rmw_hdds_node_impl_t * node_impl = (const rmw_hdds_node_impl_t *)node->data;
    if (node_impl == NULL || node_impl->context == NULL || node_impl->context->native_ctx == NULL) {
        RMW_SET_ERROR_MSG("invalid node implementation");
        return NULL;
    }

    rcutils_allocator_t allocator = select_allocator(&node_impl->allocator);

    rmw_subscription_t * subscription = (rmw_subscription_t *)allocator.allocate(
        sizeof(rmw_subscription_t), allocator.state);
    if (subscription == NULL) {
        RMW_SET_ERROR_MSG("failed to allocate rmw_subscription_t");
        return NULL;
    }
    memset(subscription, 0, sizeof(*subscription));

    bool has_introspection = true;
    bool use_dynamic_types = false;
    rmw_hdds_codec_kind_t codec_kind = RMW_HDDS_CODEC_NONE;
    char * type_name_extracted = NULL;

    const rosidl_message_type_support_t * introspection_ts =
        get_typesupport_handle(type_support, rosidl_typesupport_introspection_c__identifier);
    if (introspection_ts != NULL) {
        // Extract type name for dynamic types support
        type_name_extracted = extract_type_name_from_introspection(introspection_ts, allocator);

        rmw_hdds_error_t bind_status = rmw_hdds_context_bind_topic_type(
            node_impl->context->native_ctx,
            topic_name,
            introspection_ts);
        if (bind_status != RMW_HDDS_ERROR_OK) {
            if (type_name_extracted != NULL) {
                allocator.deallocate(type_name_extracted, allocator.state);
            }
            allocator.deallocate(subscription, allocator.state);
            RMW_SET_ERROR_MSG("failed to bind topic type");
            return NULL;
        }

        if (type_name_extracted != NULL) {
            use_dynamic_types = hdds_rmw_has_type_descriptor(type_name_extracted);
            if (use_dynamic_types) {
                RCUTILS_LOG_DEBUG_NAMED(
                    "rmw_hdds",
                    "Dynamic type descriptor available for '%s' on topic '%s'",
                    type_name_extracted,
                    topic_name);
            }
        }
    } else {
        has_introspection = false;
        introspection_ts = type_support;
        if (rcutils_error_is_set()) {
            RCUTILS_LOG_DEBUG_NAMED(
                "rmw_hdds",
                "Clearing error state after missing introspection for subscription on '%s'",
                topic_name);
            rcutils_reset_error();
        }
        codec_kind = select_codec_for_topic(topic_name);
        if (codec_kind == RMW_HDDS_CODEC_NONE) {
            RCUTILS_LOG_DEBUG_NAMED(
                "rmw_hdds",
                "Checking for dynamic type support for subscription '%s'",
                topic_name);
        } else if (strcmp(normalize_topic(topic_name), "parameter_events") != 0) {
            RCUTILS_LOG_DEBUG_NAMED(
                "rmw_hdds",
                "Using HDDS fast codec path for subscription '%s'",
                topic_name);
        }
        if (codec_kind == RMW_HDDS_CODEC_NONE) {
            RCUTILS_LOG_WARN_NAMED(
                "rmw_hdds",
                "Introspection type support unavailable for subscription '%s'; will try dynamic types if type is discovered",
                topic_name);
        } else {
            RCUTILS_LOG_WARN_NAMED(
                "rmw_hdds",
                "Introspection type support unavailable for subscription '%s'; metadata-dependent features disabled",
                topic_name);
        }
    }

    rmw_hdds_subscription_impl_t * impl = (rmw_hdds_subscription_impl_t *)allocator.allocate(
        sizeof(rmw_hdds_subscription_impl_t), allocator.state);
    if (impl == NULL) {
        if (type_name_extracted != NULL) {
            allocator.deallocate(type_name_extracted, allocator.state);
        }
        allocator.deallocate(subscription, allocator.state);
        RMW_SET_ERROR_MSG("failed to allocate subscription impl");
        return NULL;
    }
    memset(impl, 0, sizeof(*impl));
    impl->content_filter_parameters = rcutils_get_zero_initialized_string_array();

    char * topic_copy = rcutils_strdup(topic_name, allocator);
    if (topic_copy == NULL) {
        allocator.deallocate(impl, allocator.state);
        if (type_name_extracted != NULL) {
            allocator.deallocate(type_name_extracted, allocator.state);
        }
        allocator.deallocate(subscription, allocator.state);
        RMW_SET_ERROR_MSG("failed to duplicate topic name");
        return NULL;
    }

    struct HddsDataReader * reader_ptr = NULL;
    struct HddsQoS * hdds_qos = rmw_hdds_qos_from_profile(qos_profile);
    rmw_hdds_error_t reader_status;
    if (hdds_qos != NULL) {
        reader_status = rmw_hdds_context_create_reader_with_qos(
            node_impl->context->native_ctx,
            topic_name,
            hdds_qos,
            &reader_ptr);
        rmw_hdds_qos_destroy(hdds_qos);
    } else {
        reader_status = rmw_hdds_context_create_reader(
            node_impl->context->native_ctx,
            topic_name,
            &reader_ptr);
    }
    if (reader_status != RMW_HDDS_ERROR_OK || reader_ptr == NULL) {
        allocator.deallocate(topic_copy, allocator.state);
        allocator.deallocate(impl, allocator.state);
        if (type_name_extracted != NULL) {
            allocator.deallocate(type_name_extracted, allocator.state);
        }
        allocator.deallocate(subscription, allocator.state);
        RMW_SET_ERROR_MSG("failed to create HDDS reader");
        return NULL;
    }

    uint64_t condition_key = 0;
    rmw_hdds_error_t attach_status = rmw_hdds_context_attach_reader(
        node_impl->context->native_ctx,
        reader_ptr,
        &condition_key);
    if (attach_status != RMW_HDDS_ERROR_OK) {
        rmw_hdds_context_destroy_reader(node_impl->context->native_ctx, reader_ptr);
        allocator.deallocate(topic_copy, allocator.state);
        allocator.deallocate(impl, allocator.state);
        if (type_name_extracted != NULL) {
            allocator.deallocate(type_name_extracted, allocator.state);
        }
        allocator.deallocate(subscription, allocator.state);
        RMW_SET_ERROR_MSG("failed to attach reader to waitset");
        return NULL;
    }

    rmw_subscription_options_t options = subscription_options != NULL
        ? *subscription_options
        : rmw_get_default_subscription_options();

    impl->reader = reader_ptr;
    impl->context = node_impl->context;
    impl->condition_key = condition_key;
    impl->topic_name = topic_copy;
    impl->type_name = type_name_extracted;  // Already allocated, ownership transferred
    impl->type_support = introspection_ts;
    impl->qos_profile = *qos_profile;
    impl->has_introspection = has_introspection;
    impl->use_dynamic_types = use_dynamic_types;
    impl->registered_in_graph = false;
    impl->codec_kind = codec_kind;
    if (has_introspection) {
        impl->raw_message_size = rmw_hdds_get_message_size_from_introspection(introspection_ts);
    } else {
        impl->raw_message_size = 0u;
        if (type_support != NULL && type_support->func != NULL) {
            const rosidl_message_type_support_t * retry_ts =
                type_support->func(type_support, rosidl_typesupport_introspection_c__identifier);
            if (rcutils_error_is_set()) { rcutils_reset_error(); }
            if (retry_ts != NULL) {
                impl->raw_message_size = rmw_hdds_get_message_size_from_introspection(retry_ts);
                if (impl->raw_message_size > 0) {
                    impl->type_support = retry_ts;
                    impl->has_introspection = true;
                }
            }
            if (impl->raw_message_size == 0u) {
                static const char * const cpp_introspection_id =
                    "rosidl_typesupport_introspection_cpp";
                retry_ts = type_support->func(type_support, cpp_introspection_id);
                if (rcutils_error_is_set()) { rcutils_reset_error(); }
                if (retry_ts != NULL) {
                    impl->raw_message_size = rmw_hdds_get_message_size_from_introspection(retry_ts);
                }
            }
        }
    }

    RCUTILS_LOG_INFO_NAMED(
        "rmw_hdds",
        "SUB-CREATE topic='%s' has_introspection=%d codec=%u raw_msg_size=%zu dynamic=%d",
        topic_name,
        (int)impl->has_introspection,
        (unsigned)impl->codec_kind,
        impl->raw_message_size,
        (int)impl->use_dynamic_types);

    rmw_hdds_node_impl_t * node_impl_mut = (rmw_hdds_node_impl_t *)node_impl;
    rmw_ret_t track_status = rmw_hdds_endpoint_set_add(
        &node_impl_mut->subscriptions,
        impl->topic_name,
        impl->type_support,
        allocator);
    if (track_status != RMW_RET_OK) {
        rmw_hdds_context_detach_reader(node_impl->context->native_ctx, impl->reader);
        rmw_hdds_context_destroy_reader(node_impl->context->native_ctx, impl->reader);
        allocator.deallocate(impl->topic_name, allocator.state);
        if (impl->type_name != NULL) {
            allocator.deallocate(impl->type_name, allocator.state);
        }
        allocator.deallocate(impl, allocator.state);
        allocator.deallocate(subscription, allocator.state);
        RMW_SET_ERROR_MSG("failed to register subscription topic");
        return NULL;
    }

    {
        uint8_t endpoint_gid[RMW_GID_STORAGE_SIZE];
        rmw_hdds_gid_from_ptr(endpoint_gid, impl->reader, node_impl->context->native_ctx);
        rmw_hdds_qos_profile_t endpoint_qos = rmw_hdds_qos_profile_from_rmw(&impl->qos_profile);
        rmw_hdds_error_t endpoint_status = rmw_hdds_context_register_subscription_endpoint(
            node_impl->context->native_ctx,
            node_impl->name,
            node_impl->namespace_,
            impl->topic_name,
            impl->type_support,
            endpoint_gid,
            &endpoint_qos);
        if (endpoint_status != RMW_HDDS_ERROR_OK) {
            (void)rmw_hdds_endpoint_set_remove(
                &node_impl_mut->subscriptions,
                impl->topic_name,
                impl->type_support);
            rmw_hdds_context_detach_reader(node_impl->context->native_ctx, impl->reader);
            rmw_hdds_context_destroy_reader(node_impl->context->native_ctx, impl->reader);
            allocator.deallocate(impl->topic_name, allocator.state);
            if (impl->type_name != NULL) {
                allocator.deallocate(impl->type_name, allocator.state);
            }
            allocator.deallocate(impl, allocator.state);
            allocator.deallocate(subscription, allocator.state);
            RMW_SET_ERROR_MSG("failed to register subscription endpoint in graph cache");
            return NULL;
        }
        impl->registered_in_graph = true;
        RCUTILS_LOG_INFO_NAMED(
            "rmw_hdds",
            "registered subscription endpoint topic='%s' type='%s'",
            impl->topic_name,
            (impl->type_support && impl->type_support->typesupport_identifier) ?
                impl->type_support->typesupport_identifier :
                "<unknown>");
    }

    subscription->implementation_identifier = rmw_get_implementation_identifier();
    subscription->data = impl;
    subscription->topic_name = impl->topic_name;
    subscription->options = options;
    subscription->can_loan_messages = false;
    subscription->is_cft_enabled = false;

    return subscription;
}

rmw_ret_t rmw_destroy_subscription(rmw_node_t * node, rmw_subscription_t * subscription)
{
    RMW_CHECK_ARGUMENT_FOR_NULL(node, RMW_RET_INVALID_ARGUMENT);
    RMW_CHECK_ARGUMENT_FOR_NULL(subscription, RMW_RET_INVALID_ARGUMENT);

    if (node->implementation_identifier != rmw_get_implementation_identifier() ||
        subscription->implementation_identifier != rmw_get_implementation_identifier())
    {
        RMW_SET_ERROR_MSG("rmw_destroy_subscription identifier mismatch");
        return RMW_RET_INCORRECT_RMW_IMPLEMENTATION;
    }

    rmw_hdds_node_impl_t * node_impl = (rmw_hdds_node_impl_t *)node->data;
    rmw_hdds_subscription_impl_t * impl = (rmw_hdds_subscription_impl_t *)subscription->data;

    if (node_impl == NULL || impl == NULL) {
        RMW_SET_ERROR_MSG("invalid subscription or node implementation");
        return RMW_RET_ERROR;
    }

    bool has_context = node_impl->context != NULL && node_impl->context->native_ctx != NULL;

    if (impl->registered_in_graph && has_context) {
        uint8_t endpoint_gid[RMW_GID_STORAGE_SIZE];
        rmw_hdds_gid_from_ptr(endpoint_gid, impl->reader, node_impl->context->native_ctx);
        (void)rmw_hdds_context_unregister_subscription_endpoint(
            node_impl->context->native_ctx,
            node_impl->name,
            node_impl->namespace_,
            impl->topic_name,
            endpoint_gid);
        impl->registered_in_graph = false;
    }

    rcutils_allocator_t allocator = select_allocator(&node_impl->allocator);
    rmw_ret_t final_status = RMW_RET_OK;

    if (impl->reader != NULL && has_context) {
        rmw_ret_t detach_status = map_hdds_error(
            rmw_hdds_context_detach_reader(node_impl->context->native_ctx, impl->reader));
        if (detach_status != RMW_RET_OK) {
            RMW_SET_ERROR_MSG("failed to detach reader from waitset");
            final_status = detach_status;
        }

        rmw_ret_t destroy_status = map_hdds_error(
            rmw_hdds_context_destroy_reader(node_impl->context->native_ctx, impl->reader));
        if (destroy_status != RMW_RET_OK) {
            RMW_SET_ERROR_MSG("failed to destroy HDDS reader");
            final_status = destroy_status;
        }
    }
    impl->reader = NULL;

    if (impl->topic_name != NULL && impl->type_support != NULL) {
        rmw_ret_t untrack_status = rmw_hdds_endpoint_set_remove(
            &node_impl->subscriptions,
            impl->topic_name,
            impl->type_support);
        if (untrack_status != RMW_RET_OK && final_status == RMW_RET_OK) {
            RMW_SET_ERROR_MSG("failed to unregister subscription topic");
            final_status = untrack_status;
        }
    }

    if (impl->topic_name != NULL) {
        allocator.deallocate(impl->topic_name, allocator.state);
        impl->topic_name = NULL;
    }

    if (impl->type_name != NULL) {
        allocator.deallocate(impl->type_name, allocator.state);
        impl->type_name = NULL;
    }

    if (impl->content_filter_expression != NULL) {
        allocator.deallocate(impl->content_filter_expression, allocator.state);
        impl->content_filter_expression = NULL;
    }
    if (impl->content_filter_parameters.data != NULL ||
        impl->content_filter_parameters.size != 0u)
    {
        rcutils_ret_t fini_status = rcutils_string_array_fini(&impl->content_filter_parameters);
        if (fini_status != RCUTILS_RET_OK && final_status == RMW_RET_OK) {
            RMW_SET_ERROR_MSG("failed to finalize content filter parameters");
            final_status = RMW_RET_ERROR;
        }
    }

    allocator.deallocate(impl, allocator.state);
    allocator.deallocate(subscription, allocator.state);

    return final_status;
}

rmw_ret_t rmw_take(
    const rmw_subscription_t * subscription,
    void * ros_message,
    bool * taken,
    rmw_subscription_allocation_t * allocation)
{
    (void)allocation;

    RMW_CHECK_ARGUMENT_FOR_NULL(subscription, RMW_RET_INVALID_ARGUMENT);
    RMW_CHECK_ARGUMENT_FOR_NULL(ros_message, RMW_RET_INVALID_ARGUMENT);
    RMW_CHECK_ARGUMENT_FOR_NULL(taken, RMW_RET_INVALID_ARGUMENT);

    *taken = false;

    if (subscription->implementation_identifier != rmw_get_implementation_identifier()) {
        RMW_SET_ERROR_MSG("rmw_take identifier mismatch");
        return RMW_RET_INCORRECT_RMW_IMPLEMENTATION;
    }

    rmw_hdds_subscription_impl_t * impl = (rmw_hdds_subscription_impl_t *)subscription->data;
    if (impl == NULL || impl->reader == NULL || impl->type_support == NULL) {
        RMW_SET_ERROR_MSG("invalid subscription implementation");
        return RMW_RET_ERROR;
    }

    // SHM fast path: try to read from shared memory first (inter-process same machine)
    if (impl->context != NULL && impl->context->native_ctx != NULL
        && impl->topic_name != NULL && impl->raw_message_size > 0)
    {
        size_t shm_len = 0;
        size_t shm_buf_size = impl->raw_message_size;
        uint8_t shm_stack_buf[4096];
        uint8_t * shm_buf = shm_buf_size <= sizeof(shm_stack_buf) ? shm_stack_buf : NULL;
        rcutils_allocator_t shm_alloc = rcutils_get_default_allocator();
        if (shm_buf == NULL) {
            shm_buf = (uint8_t *)shm_alloc.allocate(shm_buf_size, shm_alloc.state);
        }
        if (shm_buf != NULL) {
            HddsError shm_status = hdds_rmw_context_shm_try_take(
                (struct HddsRmwContext *)impl->context->native_ctx,
                impl->topic_name,
                shm_buf,
                shm_buf_size,
                &shm_len);
            if (shm_status == OK && shm_len > 0 && shm_len == impl->raw_message_size) {
                memcpy(ros_message, shm_buf, shm_len);
                if (shm_buf != shm_stack_buf) {
                    shm_alloc.deallocate(shm_buf, shm_alloc.state);
                }
                *taken = true;
                return RMW_RET_OK;
            }
            if (shm_buf != shm_stack_buf) {
                shm_alloc.deallocate(shm_buf, shm_alloc.state);
            }
        }
    }

    // RTPS path (network + intra-process fallback)
    rcutils_allocator_t allocator = rcutils_get_default_allocator();
    size_t buffer_capacity = 1024u;
    uint8_t * buffer = (uint8_t *)allocator.allocate(buffer_capacity, allocator.state);
    if (buffer == NULL) {
        RMW_SET_ERROR_MSG("failed to allocate take buffer");
        return RMW_RET_BAD_ALLOC;
    }

    size_t data_len = 0u;

    while (true) {
        HddsError take_status = hdds_reader_take(
            impl->reader,
            buffer,
            buffer_capacity,
            &data_len);

        RCUTILS_LOG_DEBUG_NAMED(
            "rmw_hdds",
            "reader take topic='%s' status=%d buffer_capacity=%zu data_len=%zu",
            impl->topic_name != NULL ? impl->topic_name : "<unknown>",
            (int)take_status,
            buffer_capacity,
            data_len);

        if (take_status == OK) {
            break;
        }

        if (take_status == NOT_FOUND) {
            if (!impl->has_introspection && impl->codec_kind == RMW_HDDS_CODEC_STRING) {
                bool fallback_taken = false;
                rmw_hdds_error_t fb_status = rmw_hdds_fallback_try_dequeue_string_fast(
                    impl->topic_name,
                    ros_message,
                    &fallback_taken);
                if (fb_status == RMW_HDDS_ERROR_OK && fallback_taken) {
                    RCUTILS_LOG_DEBUG_NAMED(
                        "rmw_hdds",
                        "fallback dequeue succeeded for topic '%s'",
                        impl->topic_name != NULL ? impl->topic_name : "<unknown>");
                    allocator.deallocate(buffer, allocator.state);
                    *taken = true;
                    return RMW_RET_OK;
                }
                if (fb_status != RMW_HDDS_ERROR_OK && fb_status != RMW_HDDS_ERROR_NOT_FOUND) {
                    RCUTILS_LOG_DEBUG_NAMED(
                        "rmw_hdds",
                        "string fallback dequeue failed for topic '%s' (status=%d)",
                        impl->topic_name != NULL ? impl->topic_name : "<unknown>",
                        (int)fb_status);
                }
            }
            allocator.deallocate(buffer, allocator.state);
            if (taken != NULL) {
                *taken = false;
            }
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
                RMW_SET_ERROR_MSG("failed to grow take buffer");
                return RMW_RET_BAD_ALLOC;
            }
            buffer = new_buffer;
            buffer_capacity = data_len;
            continue;
        }

        allocator.deallocate(buffer, allocator.state);
        RMW_SET_ERROR_MSG("failed to take reader sample");
        return RMW_RET_ERROR;
    }

    if (data_len == 0) {
        allocator.deallocate(buffer, allocator.state);
        *taken = true;
        return RMW_RET_OK;
    }

    HddsError deserialize_status = OK;

    // Priority: when publisher used raw memcpy (no introspection), the received
    // payload is the raw struct bytes (CDR2-unwrapped by hdds_reader_take).
    // If data_len matches raw_message_size exactly, skip all other decode paths.
    if (!impl->has_introspection && impl->codec_kind == RMW_HDDS_CODEC_NONE
        && impl->raw_message_size > 0 && data_len == impl->raw_message_size)
    {
        memcpy(ros_message, buffer, impl->raw_message_size);
        deserialize_status = OK;
    } else if (impl->has_introspection) {
        deserialize_status = hdds_rmw_deserialize_ros_message(
            impl->type_support,
            buffer,
            data_len,
            ros_message);
        if (deserialize_status != OK && impl->use_dynamic_types && impl->type_name != NULL) {
            RCUTILS_LOG_DEBUG_NAMED(
                "rmw_hdds",
                "Introspection decode failed, attempting dynamic decode for topic '%s' type '%s'",
                impl->topic_name != NULL ? impl->topic_name : "<unknown>",
                impl->type_name);
            rmw_hdds_error_t dyn_status = hdds_rmw_deserialize_dynamic(
                impl->type_name,
                buffer,
                data_len,
                ros_message);
            if (dyn_status == RMW_HDDS_ERROR_OK) {
                deserialize_status = OK;
            }
        }
    } else if (impl->codec_kind != RMW_HDDS_CODEC_NONE) {
        if (impl->codec_kind == RMW_HDDS_CODEC_PARAMETER_EVENT) {
            deserialize_status = rmw_hdds_deserialize_parameter_event_fast(
                buffer,
                data_len,
                ros_message);
        } else if (impl->codec_kind == RMW_HDDS_CODEC_STRING) {
            deserialize_status = rmw_hdds_deserialize_string_fast(
                buffer,
                data_len,
                ros_message);
        } else if (impl->codec_kind == RMW_HDDS_CODEC_LOG) {
#ifdef HDDS_HAVE_ROSLOG_FAST
            deserialize_status = rmw_hdds_deserialize_log_fast(
                buffer,
                data_len,
                ros_message);
#else
            deserialize_status = OK; // drop silently if fast codec not present
#endif
        } else {
            deserialize_status = hdds_rmw_deserialize_with_codec(
                (uint8_t)impl->codec_kind,
                buffer,
                data_len,
                ros_message);
        }
    } else if (impl->use_dynamic_types && impl->type_name != NULL) {
        // Try dynamic type deserialization using pre-computed TypeDescriptor
        RCUTILS_LOG_DEBUG_NAMED(
            "rmw_hdds",
            "Using dynamic type deserialization for topic '%s' type '%s'",
            impl->topic_name != NULL ? impl->topic_name : "<unknown>",
            impl->type_name);
        rmw_hdds_error_t dyn_status = hdds_rmw_deserialize_dynamic(
            impl->type_name,
            buffer,
            data_len,
            ros_message);
        if (dyn_status != RMW_HDDS_ERROR_OK) {
            deserialize_status = OPERATION_FAILED;
        }
    } else {
        // No introspection, no codec, no dynamic types: try raw memcpy fallback.
        // The publisher sent raw struct bytes; copy them back into ros_message.
        if (impl->raw_message_size > 0 && data_len >= impl->raw_message_size) {
            memcpy(ros_message, buffer, impl->raw_message_size);
            deserialize_status = OK;
        } else {
            // Try introspection deserialize anyway (type support may have resolved)
            deserialize_status = hdds_rmw_deserialize_ros_message(
                impl->type_support,
                buffer,
                data_len,
                ros_message);
            if (deserialize_status != OK) {
                allocator.deallocate(buffer, allocator.state);
                const char * topic_name = impl->topic_name != NULL ? impl->topic_name : "<unknown>";
                RCUTILS_LOG_DEBUG_NAMED(
                    "rmw_hdds",
                    "Dropping sample on topic '%s': no codec, no introspection, msg_size=%zu data_len=%zu",
                    topic_name,
                    impl->raw_message_size,
                    data_len);
                return RMW_RET_OK;
            }
        }
    }

    allocator.deallocate(buffer, allocator.state);

    if (deserialize_status != OK) {
        RCUTILS_LOG_DEBUG_NAMED(
            "rmw_hdds",
            "fast codec deserialization failed for topic '%s' (status=%d)",
            impl->topic_name != NULL ? impl->topic_name : "<unknown>",
            (int)deserialize_status);
        switch (deserialize_status) {
            case INVALID_ARGUMENT:
                RMW_SET_ERROR_MSG("invalid argument during deserialization");
                return RMW_RET_INVALID_ARGUMENT;
            case OUT_OF_MEMORY:
                RMW_SET_ERROR_MSG("memory allocation failed during deserialization");
                return RMW_RET_BAD_ALLOC;
            default:
                RMW_SET_ERROR_MSG("deserialization failed");
                return RMW_RET_ERROR;
        }
    }

    if (!rmw_hdds_content_filter_matches(impl, ros_message)) {
        *taken = false;
        return RMW_RET_OK;
    }

    RCUTILS_LOG_DEBUG_NAMED(
        "rmw_hdds",
        "reader delivered sample topic='%s' size=%zu",
        impl->topic_name != NULL ? impl->topic_name : "<unknown>",
        data_len);

    *taken = true;
    return RMW_RET_OK;
}

// Take raw serialized CDR message without deserialization
// This is used by ros2 topic echo and other generic subscription tools
rmw_ret_t rmw_take_serialized_message(
    const rmw_subscription_t * subscription,
    rmw_serialized_message_t * serialized_message,
    bool * taken,
    rmw_subscription_allocation_t * allocation)
{
    (void)allocation;

    RMW_CHECK_ARGUMENT_FOR_NULL(subscription, RMW_RET_INVALID_ARGUMENT);
    RMW_CHECK_ARGUMENT_FOR_NULL(serialized_message, RMW_RET_INVALID_ARGUMENT);
    RMW_CHECK_ARGUMENT_FOR_NULL(taken, RMW_RET_INVALID_ARGUMENT);

    *taken = false;

    if (subscription->implementation_identifier != rmw_get_implementation_identifier()) {
        RMW_SET_ERROR_MSG("rmw_take_serialized_message identifier mismatch");
        return RMW_RET_INCORRECT_RMW_IMPLEMENTATION;
    }

    rmw_hdds_subscription_impl_t * impl = (rmw_hdds_subscription_impl_t *)subscription->data;
    if (impl == NULL || impl->reader == NULL) {
        RMW_SET_ERROR_MSG("invalid subscription implementation");
        return RMW_RET_ERROR;
    }

    rcutils_allocator_t allocator = rcutils_get_default_allocator();
    size_t buffer_capacity = 1024u;
    uint8_t * buffer = (uint8_t *)allocator.allocate(buffer_capacity, allocator.state);
    if (buffer == NULL) {
        RMW_SET_ERROR_MSG("failed to allocate take buffer");
        return RMW_RET_BAD_ALLOC;
    }

    size_t data_len = 0u;

    while (true) {
        HddsError take_status = hdds_reader_take(
            impl->reader,
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
                RMW_SET_ERROR_MSG("failed to grow take buffer");
                return RMW_RET_BAD_ALLOC;
            }
            buffer = new_buffer;
            buffer_capacity = data_len;
            continue;
        }

        allocator.deallocate(buffer, allocator.state);
        RMW_SET_ERROR_MSG("failed to take reader sample");
        return RMW_RET_ERROR;
    }

    if (data_len == 0) {
        allocator.deallocate(buffer, allocator.state);
        *taken = true;
        return RMW_RET_OK;
    }

    if (impl->content_filter.enabled) {
        if (!impl->has_introspection || impl->type_support == NULL ||
            impl->type_support->data == NULL)
        {
            allocator.deallocate(buffer, allocator.state);
            RMW_SET_ERROR_MSG("content filter requires introspection for serialized take");
            return RMW_RET_UNSUPPORTED;
        }

        const rosidl_typesupport_introspection_c__MessageMembers * members =
            (const rosidl_typesupport_introspection_c__MessageMembers *)impl->type_support->data;
        void * tmp_msg = rmw_hdds_allocate_message(members, allocator);
        if (tmp_msg == NULL) {
            allocator.deallocate(buffer, allocator.state);
            RMW_SET_ERROR_MSG("failed to allocate content filter message");
            return RMW_RET_BAD_ALLOC;
        }

        HddsError deserialize_status = hdds_rmw_deserialize_ros_message(
            impl->type_support,
            buffer,
            data_len,
            tmp_msg);
        if (deserialize_status != OK) {
            rmw_hdds_free_message(tmp_msg, members, allocator);
            allocator.deallocate(buffer, allocator.state);
            RMW_SET_ERROR_MSG("content filter deserialization failed");
            return RMW_RET_ERROR;
        }

        bool matches = rmw_hdds_content_filter_matches(impl, tmp_msg);
        rmw_hdds_free_message(tmp_msg, members, allocator);
        if (!matches) {
            allocator.deallocate(buffer, allocator.state);
            *taken = false;
            return RMW_RET_OK;
        }
    }

    // Resize the serialized message buffer if needed
    if (serialized_message->buffer_capacity < data_len) {
        rcutils_ret_t resize_ret = rcutils_uint8_array_resize(serialized_message, data_len);
        if (resize_ret != RCUTILS_RET_OK) {
            allocator.deallocate(buffer, allocator.state);
            RMW_SET_ERROR_MSG("failed to resize serialized message");
            return RMW_RET_BAD_ALLOC;
        }
    }

    // Copy raw CDR data to the serialized message
    memcpy(serialized_message->buffer, buffer, data_len);
    serialized_message->buffer_length = data_len;

    allocator.deallocate(buffer, allocator.state);

    RCUTILS_LOG_DEBUG_NAMED(
        "rmw_hdds",
        "take_serialized_message delivered topic='%s' size=%zu",
        impl->topic_name != NULL ? impl->topic_name : "<unknown>",
        data_len);

    *taken = true;
    return RMW_RET_OK;
}

rmw_ret_t rmw_take_serialized_message_with_info(
    const rmw_subscription_t * subscription,
    rmw_serialized_message_t * serialized_message,
    bool * taken,
    rmw_message_info_t * message_info,
    rmw_subscription_allocation_t * allocation)
{
    // For now, call the basic version and zero the message info
    rmw_ret_t ret = rmw_take_serialized_message(subscription, serialized_message, taken, allocation);
    if (ret == RMW_RET_OK && message_info != NULL) {
        // Zero-initialize message info since we don't have detailed info from HDDS yet
        memset(message_info, 0, sizeof(rmw_message_info_t));
        message_info->publication_sequence_number = RMW_MESSAGE_INFO_SEQUENCE_NUMBER_UNSUPPORTED;
        message_info->reception_sequence_number = RMW_MESSAGE_INFO_SEQUENCE_NUMBER_UNSUPPORTED;
        message_info->from_intra_process = false;
    }
    return ret;
}

rmw_ret_t rmw_subscription_count_matched_publishers(
    const rmw_subscription_t * subscription,
    size_t * publisher_count)
{
    RMW_CHECK_ARGUMENT_FOR_NULL(subscription, RMW_RET_INVALID_ARGUMENT);
    RMW_CHECK_ARGUMENT_FOR_NULL(publisher_count, RMW_RET_INVALID_ARGUMENT);

    if (subscription->implementation_identifier != rmw_get_implementation_identifier()) {
        RMW_SET_ERROR_MSG("rmw_subscription_count_matched_publishers identifier mismatch");
        return RMW_RET_INCORRECT_RMW_IMPLEMENTATION;
    }

    const rmw_hdds_subscription_impl_t * impl =
        (const rmw_hdds_subscription_impl_t *)subscription->data;
    if (impl == NULL || impl->context == NULL || impl->context->native_ctx == NULL ||
        impl->topic_name == NULL) {
        RMW_SET_ERROR_MSG("subscription implementation is invalid");
        return RMW_RET_ERROR;
    }

    hdds_topic_match_ctx_t ctx = {
        .topic_name = impl->topic_name,
        .count = 0u,
        .matched = false,
    };

    rmw_hdds_error_t err = rmw_hdds_context_for_each_topic(
        impl->context->native_ctx,
        hdds_match_topic_writers_cb,
        &ctx,
        NULL);
    if (err != RMW_HDDS_ERROR_OK) {
        return map_hdds_error(err);
    }

    *publisher_count = ctx.count;
    return RMW_RET_OK;
}

rmw_ret_t rmw_subscription_get_actual_qos(
    const rmw_subscription_t * subscription,
    rmw_qos_profile_t * qos)
{
    RMW_CHECK_ARGUMENT_FOR_NULL(subscription, RMW_RET_INVALID_ARGUMENT);
    RMW_CHECK_ARGUMENT_FOR_NULL(qos, RMW_RET_INVALID_ARGUMENT);

    if (subscription->implementation_identifier != rmw_get_implementation_identifier()) {
        RMW_SET_ERROR_MSG("rmw_subscription_get_actual_qos identifier mismatch");
        return RMW_RET_INCORRECT_RMW_IMPLEMENTATION;
    }

    const rmw_hdds_subscription_impl_t * impl =
        (const rmw_hdds_subscription_impl_t *)subscription->data;
    if (impl == NULL) {
        RMW_SET_ERROR_MSG("subscription implementation is null");
        return RMW_RET_ERROR;
    }

    *qos = impl->qos_profile;
    return RMW_RET_OK;
}
