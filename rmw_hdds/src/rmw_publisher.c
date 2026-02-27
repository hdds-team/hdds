// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

#include <rmw/rmw.h>
#include <rmw/error_handling.h>
#include <rmw/publisher_options.h>

#include <rosidl_runtime_c/message_type_support_struct.h>
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

/// Try to extract the raw struct size from introspection type support.
/// Returns 0 if introspection is unavailable.
static size_t
get_message_size_from_introspection(const rosidl_message_type_support_t * introspection_ts)
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
select_allocator(const rcutils_allocator_t * allocator)
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
hdds_match_topic_readers_cb(
    const char * topic_name,
    const char * type_name,
    uint32_t writer_count,
    uint32_t reader_count,
    void * user_data)
{
    (void)type_name;
    (void)writer_count;
    hdds_topic_match_ctx_t * ctx = (hdds_topic_match_ctx_t *)user_data;
    if (ctx == NULL || ctx->matched) {
        return;
    }
    if (topic_name != NULL && ctx->topic_name != NULL &&
        strcmp(topic_name, ctx->topic_name) == 0) {
        ctx->count = (size_t)reader_count;
        ctx->matched = true;
    }
}

rmw_publisher_t * rmw_create_publisher(
    const rmw_node_t * node,
    const rosidl_message_type_support_t * type_support,
    const char * topic_name,
    const rmw_qos_profile_t * qos_profile,
    const rmw_publisher_options_t * publisher_options)
{
    RMW_CHECK_ARGUMENT_FOR_NULL(node, NULL);
    RMW_CHECK_ARGUMENT_FOR_NULL(type_support, NULL);
    RMW_CHECK_ARGUMENT_FOR_NULL(topic_name, NULL);
    RMW_CHECK_ARGUMENT_FOR_NULL(qos_profile, NULL);

    if (node->implementation_identifier != rmw_get_implementation_identifier()) {
        RMW_SET_ERROR_MSG("rmw_create_publisher identifier mismatch");
        return NULL;
    }

    const rmw_hdds_node_impl_t * node_impl = (const rmw_hdds_node_impl_t *)node->data;
    if (node_impl == NULL || node_impl->context == NULL || node_impl->context->native_ctx == NULL) {
        RMW_SET_ERROR_MSG("invalid node implementation");
        return NULL;
    }

    rcutils_allocator_t allocator = select_allocator(&node_impl->allocator);

    rmw_publisher_t * publisher =
        (rmw_publisher_t *)allocator.allocate(sizeof(rmw_publisher_t), allocator.state);
    if (publisher == NULL) {
        RMW_SET_ERROR_MSG("failed to allocate rmw_publisher_t");
        return NULL;
    }
    memset(publisher, 0, sizeof(*publisher));

    rmw_hdds_publisher_impl_t * impl =
        (rmw_hdds_publisher_impl_t *)allocator.allocate(
            sizeof(rmw_hdds_publisher_impl_t),
            allocator.state);
    if (impl == NULL) {
        allocator.deallocate(publisher, allocator.state);
        RMW_SET_ERROR_MSG("failed to allocate publisher impl");
        return NULL;
    }
    memset(impl, 0, sizeof(*impl));

    char * topic_copy = rcutils_strdup(topic_name, allocator);
    if (topic_copy == NULL) {
        allocator.deallocate(impl, allocator.state);
        allocator.deallocate(publisher, allocator.state);
        RMW_SET_ERROR_MSG("failed to duplicate topic name");
        return NULL;
    }

    bool has_introspection = true;
    rmw_hdds_codec_kind_t codec_kind = RMW_HDDS_CODEC_NONE;
    const rosidl_message_type_support_t * introspection_ts =
        get_typesupport_handle(type_support, rosidl_typesupport_introspection_c__identifier);
    if (introspection_ts == NULL) {
        has_introspection = false;
        introspection_ts = type_support;
        if (rcutils_error_is_set()) {
            RCUTILS_LOG_DEBUG_NAMED(
                "rmw_hdds",
                "Clearing error state after missing introspection for publisher on '%s'",
                topic_name);
            rcutils_reset_error();
        }
        codec_kind = select_codec_for_topic(topic_name);
        if (codec_kind == RMW_HDDS_CODEC_NONE) {
            RCUTILS_LOG_WARN_NAMED(
                "rmw_hdds",
                "Introspection type support unavailable for topic '%s'; messages will be dropped unless a fast codec is registered",
                topic_name);
        } else if (strcmp(normalize_topic(topic_name), "parameter_events") != 0) {
            RCUTILS_LOG_DEBUG_NAMED(
                "rmw_hdds",
                "Using HDDS fast codec path for publisher topic '%s'",
                topic_name);
        }
        RCUTILS_LOG_WARN_NAMED(
            "rmw_hdds",
            "Introspection type support unavailable for topic '%s'; metadata-dependent features disabled",
            topic_name);
    } else {
        rmw_hdds_error_t bind_status = rmw_hdds_context_bind_topic_type(
            node_impl->context->native_ctx,
            topic_name,
            introspection_ts);
        if (bind_status != RMW_HDDS_ERROR_OK) {
            allocator.deallocate(topic_copy, allocator.state);
            allocator.deallocate(impl, allocator.state);
            allocator.deallocate(publisher, allocator.state);
            RMW_SET_ERROR_MSG("failed to bind topic type");
            return NULL;
        }
    }

    struct HddsDataWriter * writer_ptr = NULL;
    struct HddsQoS * hdds_qos = rmw_hdds_qos_from_profile(qos_profile);
    rmw_hdds_error_t writer_status;
    if (hdds_qos != NULL) {
        writer_status = rmw_hdds_context_create_writer_with_qos(
            node_impl->context->native_ctx,
            topic_name,
            hdds_qos,
            &writer_ptr);
        rmw_hdds_qos_destroy(hdds_qos);
    } else {
        writer_status = rmw_hdds_context_create_writer(
            node_impl->context->native_ctx,
            topic_name,
            &writer_ptr);
    }
    if (writer_status != RMW_HDDS_ERROR_OK || writer_ptr == NULL) {
        allocator.deallocate(topic_copy, allocator.state);
        allocator.deallocate(impl, allocator.state);
        allocator.deallocate(publisher, allocator.state);
        RMW_SET_ERROR_MSG("failed to create HDDS writer");
        return NULL;
    }

    rmw_publisher_options_t options = publisher_options != NULL
        ? *publisher_options
        : rmw_get_default_publisher_options();

    impl->context = node_impl->context;
    impl->writer = writer_ptr;
    impl->topic_name = topic_copy;
    impl->type_support = introspection_ts;
    impl->qos_profile = *qos_profile;
    impl->has_introspection = has_introspection;
    impl->registered_in_graph = false;
    impl->codec_kind = codec_kind;
    if (has_introspection) {
        impl->raw_message_size = get_message_size_from_introspection(introspection_ts);
    } else {
        // Try harder to get message size for raw fallback.
        // The type_support may be C++ (rosidl_typesupport_cpp) -- try both
        // C and C++ introspection redirects.
        impl->raw_message_size = 0u;
        if (type_support != NULL && type_support->func != NULL) {
            // Try C introspection first
            const rosidl_message_type_support_t * retry_ts =
                type_support->func(type_support, rosidl_typesupport_introspection_c__identifier);
            if (rcutils_error_is_set()) { rcutils_reset_error(); }
            if (retry_ts != NULL) {
                impl->raw_message_size = get_message_size_from_introspection(retry_ts);
                // Also update the stored type_support for future introspection publish
                if (impl->raw_message_size > 0) {
                    impl->type_support = retry_ts;
                    impl->has_introspection = true;
                }
            }
            // Try C++ introspection if C failed (performance_test uses cpp type support)
            if (impl->raw_message_size == 0u) {
                static const char * const cpp_introspection_id =
                    "rosidl_typesupport_introspection_cpp";
                retry_ts = type_support->func(type_support, cpp_introspection_id);
                if (rcutils_error_is_set()) { rcutils_reset_error(); }
                if (retry_ts != NULL) {
                    // C++ MessageMembers has the same layout as C for size_of_
                    impl->raw_message_size = get_message_size_from_introspection(retry_ts);
                }
            }
        }
    }

    RCUTILS_LOG_INFO_NAMED(
        "rmw_hdds",
        "PUB-CREATE topic='%s' has_introspection=%d codec=%u raw_msg_size=%zu",
        topic_name,
        (int)impl->has_introspection,
        (unsigned)impl->codec_kind,
        impl->raw_message_size);

    rmw_hdds_node_impl_t * node_impl_mut = (rmw_hdds_node_impl_t *)node_impl;
    rmw_ret_t track_status = rmw_hdds_endpoint_set_add(
        &node_impl_mut->publishers,
        impl->topic_name,
        impl->type_support,
        allocator);
    if (track_status != RMW_RET_OK) {
        rmw_hdds_context_destroy_writer(node_impl->context->native_ctx, impl->writer);
        allocator.deallocate(impl->topic_name, allocator.state);
        allocator.deallocate(impl, allocator.state);
        allocator.deallocate(publisher, allocator.state);
        RMW_SET_ERROR_MSG("failed to register publisher topic");
        return NULL;
    }

    {
        uint8_t endpoint_gid[RMW_GID_STORAGE_SIZE];
        rmw_hdds_gid_from_ptr(endpoint_gid, impl->writer, node_impl->context->native_ctx);
        rmw_hdds_qos_profile_t endpoint_qos = rmw_hdds_qos_profile_from_rmw(&impl->qos_profile);
        rmw_hdds_error_t endpoint_status = rmw_hdds_context_register_publisher_endpoint(
            node_impl->context->native_ctx,
            node_impl->name,
            node_impl->namespace_,
            impl->topic_name,
            impl->type_support,
            endpoint_gid,
            &endpoint_qos);
        if (endpoint_status != RMW_HDDS_ERROR_OK) {
            rmw_hdds_endpoint_set_remove(
                &node_impl_mut->publishers,
                impl->topic_name,
                impl->type_support);
            rmw_hdds_context_destroy_writer(node_impl->context->native_ctx, impl->writer);
            allocator.deallocate(impl->topic_name, allocator.state);
            allocator.deallocate(impl, allocator.state);
            allocator.deallocate(publisher, allocator.state);
            RMW_SET_ERROR_MSG("failed to register publisher endpoint in graph cache");
            return NULL;
        }
        impl->registered_in_graph = true;
        RCUTILS_LOG_INFO_NAMED(
            "rmw_hdds",
            "registered publisher endpoint topic='%s' type='%s'",
            impl->topic_name,
            (impl->type_support && impl->type_support->typesupport_identifier) ?
                impl->type_support->typesupport_identifier :
                "<unknown>");
    }

    publisher->implementation_identifier = rmw_get_implementation_identifier();
    publisher->data = impl;
    publisher->topic_name = impl->topic_name;
    publisher->options = options;
    publisher->can_loan_messages = false;

    return publisher;
}

rmw_ret_t rmw_destroy_publisher(rmw_node_t * node, rmw_publisher_t * publisher)
{
    RMW_CHECK_ARGUMENT_FOR_NULL(node, RMW_RET_INVALID_ARGUMENT);
    RMW_CHECK_ARGUMENT_FOR_NULL(publisher, RMW_RET_INVALID_ARGUMENT);

    if (node->implementation_identifier != rmw_get_implementation_identifier() ||
        publisher->implementation_identifier != rmw_get_implementation_identifier())
    {
        RMW_SET_ERROR_MSG("rmw_destroy_publisher identifier mismatch");
        return RMW_RET_INCORRECT_RMW_IMPLEMENTATION;
    }

    rmw_hdds_node_impl_t * node_impl = (rmw_hdds_node_impl_t *)node->data;
    rmw_hdds_publisher_impl_t * impl = (rmw_hdds_publisher_impl_t *)publisher->data;

    if (node_impl == NULL || impl == NULL) {
        RMW_SET_ERROR_MSG("invalid publisher or node implementation");
        return RMW_RET_ERROR;
    }

    bool has_context = node_impl->context != NULL && node_impl->context->native_ctx != NULL;

    if (impl->registered_in_graph && has_context) {
        uint8_t endpoint_gid[RMW_GID_STORAGE_SIZE];
        rmw_hdds_gid_from_ptr(endpoint_gid, impl->writer, node_impl->context->native_ctx);
        (void)rmw_hdds_context_unregister_publisher_endpoint(
            node_impl->context->native_ctx,
            node_impl->name,
            node_impl->namespace_,
            impl->topic_name,
            endpoint_gid);
        impl->registered_in_graph = false;
    }

    rcutils_allocator_t allocator = select_allocator(&node_impl->allocator);
    rmw_ret_t final_status = RMW_RET_OK;

    if (impl->writer != NULL && has_context) {
        rmw_ret_t destroy_status = map_hdds_error(
            rmw_hdds_context_destroy_writer(node_impl->context->native_ctx, impl->writer));
        if (destroy_status != RMW_RET_OK) {
            RMW_SET_ERROR_MSG("failed to destroy HDDS writer");
            final_status = destroy_status;
        }
    }
    impl->writer = NULL;

    if (impl->topic_name != NULL && impl->type_support != NULL) {
        rmw_ret_t untrack_status = rmw_hdds_endpoint_set_remove(
            &node_impl->publishers,
            impl->topic_name,
            impl->type_support);
        if (untrack_status != RMW_RET_OK && final_status == RMW_RET_OK) {
            RMW_SET_ERROR_MSG("failed to unregister publisher topic");
            final_status = untrack_status;
        }
    }

    if (impl->topic_name != NULL) {
        allocator.deallocate(impl->topic_name, allocator.state);
        impl->topic_name = NULL;
    }

    allocator.deallocate(impl, allocator.state);
    allocator.deallocate(publisher, allocator.state);

    return final_status;
}

rmw_ret_t rmw_publish(
    const rmw_publisher_t * publisher,
    const void * ros_message,
    rmw_publisher_allocation_t * allocation)
{
    (void)allocation;

    RMW_CHECK_ARGUMENT_FOR_NULL(publisher, RMW_RET_INVALID_ARGUMENT);
    RMW_CHECK_ARGUMENT_FOR_NULL(ros_message, RMW_RET_INVALID_ARGUMENT);

    if (publisher->implementation_identifier != rmw_get_implementation_identifier()) {
        RMW_SET_ERROR_MSG("rmw_publish identifier mismatch");
        return RMW_RET_INCORRECT_RMW_IMPLEMENTATION;
    }

    const rmw_hdds_publisher_impl_t * impl =
        (const rmw_hdds_publisher_impl_t *)publisher->data;

    if (impl == NULL || impl->context == NULL || impl->context->native_ctx == NULL ||
        impl->writer == NULL || impl->type_support == NULL)
    {
        RMW_SET_ERROR_MSG("publisher is not fully initialized");
        return RMW_RET_ERROR;
    }

    rmw_ret_t status = RMW_RET_OK;

    if (!impl->has_introspection) {
        if (impl->codec_kind == RMW_HDDS_CODEC_NONE) {
            // No introspection and no fast codec: use raw struct memcpy
            // if we got the message size from C++ introspection at creation time.
            if (impl->raw_message_size > 0) {
                enum HddsError raw_err = hdds_writer_write(
                    impl->writer,
                    ros_message,
                    impl->raw_message_size);
                if (raw_err == HDDS_OK) {
                    status = RMW_RET_OK;
                    goto publish_done;
                }
            } else {
                RCUTILS_LOG_WARN_NAMED(
                    "rmw_hdds",
                    "Dropping message on topic '%s': no introspection, no codec, raw_size=0",
                    impl->topic_name != NULL ? impl->topic_name : "<unknown>");
            }
            // Raw fallback unavailable or failed; silently succeed to avoid spamming
            return RMW_RET_OK;
        }

        RCUTILS_LOG_ERROR_NAMED(
            "rmw_hdds",
            "Publishing via fast codec %u for topic '%s'",
            (unsigned)impl->codec_kind,
            impl->topic_name != NULL ? impl->topic_name : "<unknown>");

        if (impl->codec_kind == RMW_HDDS_CODEC_PARAMETER_EVENT) {
            status = map_hdds_error(
                rmw_hdds_publish_parameter_event_fast(
                    impl->context->native_ctx,
                    impl->writer,
                    ros_message));
        } else if (impl->codec_kind == RMW_HDDS_CODEC_STRING) {
            // Bounded retry to push through transient backpressure
            rmw_hdds_error_t hdds_status = RMW_HDDS_ERROR_OPERATION_FAILED;
            for (int i = 0; i < 256; ++i) {
                hdds_status = rmw_hdds_publish_string_fast(
                    impl->context->native_ctx,
                    impl->writer,
                    ros_message);
                if (hdds_status == RMW_HDDS_ERROR_OK) {
                    RCUTILS_LOG_INFO_NAMED(
                        "rmw_hdds",
                        "fast codec publish succeeded topic='%s' attempt=%d",
                        impl->topic_name != NULL ? impl->topic_name : "<unknown>",
                        i + 1);
                    break;
                }
            }
            if (hdds_status != RMW_HDDS_ERROR_OK) {
                RCUTILS_LOG_INFO_NAMED(
                    "rmw_hdds",
                    "fast codec publish failed topic='%s' status=%d; enqueuing fallback",
                    impl->topic_name != NULL ? impl->topic_name : "<unknown>",
                    (int)hdds_status);
            }
            status = map_hdds_error(hdds_status);
            if (status != RMW_RET_OK) {
                rmw_hdds_error_t fb_status = rmw_hdds_fallback_enqueue_string_fast(
                    impl->topic_name,
                    ros_message);
                if (fb_status != RMW_HDDS_ERROR_OK) {
                    RCUTILS_LOG_DEBUG_NAMED(
                        "rmw_hdds",
                        "string fallback enqueue failed for topic '%s' (status=%d)",
                        impl->topic_name != NULL ? impl->topic_name : "<unknown>",
                        (int)fb_status);
                }
                status = RMW_RET_OK;
            }
        } else if (impl->codec_kind == RMW_HDDS_CODEC_LOG) {
#ifdef HDDS_HAVE_ROSLOG_FAST
            status = map_hdds_error(
                rmw_hdds_publish_log_fast(
                    impl->context->native_ctx,
                    impl->writer,
                    ros_message));
#else
            // Fallback: ignore rosout publish if fast codec not available
            return RMW_RET_OK;
#endif
        } else {
            status = map_hdds_error(
                rmw_hdds_context_publish_with_codec(
                    impl->context->native_ctx,
                    impl->writer,
                    (uint8_t)impl->codec_kind,
                    ros_message));
        }

        if (status != RMW_RET_OK) {
            RCUTILS_LOG_WARN_NAMED(
                "rmw_hdds",
                "fast codec publish failed for topic '%s' (status=%d); temporary skip",
                impl->topic_name != NULL ? impl->topic_name : "<unknown>",
                (int)status);
            status = RMW_RET_OK;
        }
    } else {
        status = map_hdds_error(
            rmw_hdds_context_publish(
                impl->context->native_ctx,
                impl->writer,
                impl->type_support,
                ros_message));

        if (status != RMW_RET_OK) {
            RCUTILS_LOG_WARN_NAMED(
                "rmw_hdds",
                "publish via introspection failed for topic '%s' (status=%d); temporary skip",
                impl->topic_name != NULL ? impl->topic_name : "<unknown>",
                (int)status);
            status = RMW_RET_OK;
        }
    }

publish_done:
    if (status == RMW_RET_OK) {
        rmw_hdds_error_t guard_status = rmw_hdds_context_set_guard(
            impl->context->native_ctx,
            true);
        if (guard_status != RMW_HDDS_ERROR_OK) {
            RCUTILS_LOG_DEBUG_NAMED(
                "rmw_hdds",
                "failed to signal context guard after publish (status=%d)",
                (int)guard_status);
        }
    }

    return status;
}

rmw_ret_t rmw_publisher_count_matched_subscriptions(
    const rmw_publisher_t * publisher,
    size_t * subscription_count)
{
    RMW_CHECK_ARGUMENT_FOR_NULL(publisher, RMW_RET_INVALID_ARGUMENT);
    RMW_CHECK_ARGUMENT_FOR_NULL(subscription_count, RMW_RET_INVALID_ARGUMENT);

    if (publisher->implementation_identifier != rmw_get_implementation_identifier()) {
        RMW_SET_ERROR_MSG("rmw_publisher_count_matched_subscriptions identifier mismatch");
        return RMW_RET_INCORRECT_RMW_IMPLEMENTATION;
    }

    rmw_hdds_publisher_impl_t * impl = (rmw_hdds_publisher_impl_t *)publisher->data;
    if (impl == NULL || impl->context == NULL || impl->context->native_ctx == NULL ||
        impl->topic_name == NULL) {
        RMW_SET_ERROR_MSG("publisher implementation is invalid");
        return RMW_RET_ERROR;
    }

    hdds_topic_match_ctx_t ctx = {
        .topic_name = impl->topic_name,
        .count = 0u,
        .matched = false,
    };

    rmw_hdds_error_t err = rmw_hdds_context_for_each_topic(
        impl->context->native_ctx,
        hdds_match_topic_readers_cb,
        &ctx,
        NULL);
    if (err != RMW_HDDS_ERROR_OK) {
        return map_hdds_error(err);
    }

    *subscription_count = ctx.count;
    return RMW_RET_OK;
}

rmw_ret_t rmw_publisher_get_actual_qos(
    const rmw_publisher_t * publisher,
    rmw_qos_profile_t * qos)
{
    RMW_CHECK_ARGUMENT_FOR_NULL(publisher, RMW_RET_INVALID_ARGUMENT);
    RMW_CHECK_ARGUMENT_FOR_NULL(qos, RMW_RET_INVALID_ARGUMENT);

    if (publisher->implementation_identifier != rmw_get_implementation_identifier()) {
        RMW_SET_ERROR_MSG("rmw_publisher_get_actual_qos identifier mismatch");
        return RMW_RET_INCORRECT_RMW_IMPLEMENTATION;
    }

    rmw_hdds_publisher_impl_t * impl = (rmw_hdds_publisher_impl_t *)publisher->data;
    if (impl == NULL) {
        RMW_SET_ERROR_MSG("publisher has no implementation data");
        return RMW_RET_ERROR;
    }

    *qos = impl->qos_profile;
    return RMW_RET_OK;
}
