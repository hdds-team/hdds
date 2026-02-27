#ifndef RMW_HDDS__TYPES_H_
#define RMW_HDDS__TYPES_H_
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <rosidl_runtime_c/message_type_support_struct.h>
#include <rosidl_runtime_c/service_type_support_struct.h>
#include <rosidl_typesupport_introspection_c/field_types.h>

#include <rmw/event_callback_type.h>
#include <rmw/qos_profiles.h>
#include <rmw/types.h>
#include <string.h>

#include <rcutils/allocator.h>
#include <rcutils/types/string_array.h>

#ifndef ROS_TYPE_BOOLEAN
#define ROS_TYPE_BOOLEAN rosidl_typesupport_introspection_c__ROS_TYPE_BOOLEAN
#define ROS_TYPE_CHAR rosidl_typesupport_introspection_c__ROS_TYPE_CHAR
#define ROS_TYPE_OCTET rosidl_typesupport_introspection_c__ROS_TYPE_OCTET
#define ROS_TYPE_UINT8 rosidl_typesupport_introspection_c__ROS_TYPE_UINT8
#define ROS_TYPE_UINT16 rosidl_typesupport_introspection_c__ROS_TYPE_UINT16
#define ROS_TYPE_UINT32 rosidl_typesupport_introspection_c__ROS_TYPE_UINT32
#define ROS_TYPE_UINT64 rosidl_typesupport_introspection_c__ROS_TYPE_UINT64
#define ROS_TYPE_WCHAR rosidl_typesupport_introspection_c__ROS_TYPE_WCHAR
#define ROS_TYPE_INT8 rosidl_typesupport_introspection_c__ROS_TYPE_INT8
#define ROS_TYPE_INT16 rosidl_typesupport_introspection_c__ROS_TYPE_INT16
#define ROS_TYPE_INT32 rosidl_typesupport_introspection_c__ROS_TYPE_INT32
#define ROS_TYPE_INT64 rosidl_typesupport_introspection_c__ROS_TYPE_INT64
#define ROS_TYPE_FLOAT rosidl_typesupport_introspection_c__ROS_TYPE_FLOAT
#define ROS_TYPE_DOUBLE rosidl_typesupport_introspection_c__ROS_TYPE_DOUBLE
#define ROS_TYPE_LONG_DOUBLE rosidl_typesupport_introspection_c__ROS_TYPE_LONG_DOUBLE
#define ROS_TYPE_STRING rosidl_typesupport_introspection_c__ROS_TYPE_STRING
#define ROS_TYPE_WSTRING rosidl_typesupport_introspection_c__ROS_TYPE_WSTRING
#define ROS_TYPE_MESSAGE rosidl_typesupport_introspection_c__ROS_TYPE_MESSAGE
#endif

/* HddsError short aliases (hdds.h uses HDDS_ prefix since v1.0) */
#ifndef OK
#define OK HDDS_OK
#define NOT_FOUND HDDS_NOT_FOUND
#define OPERATION_FAILED HDDS_OPERATION_FAILED
#define OUT_OF_MEMORY HDDS_OUT_OF_MEMORY
#define INVALID_ARGUMENT HDDS_INVALID_ARGUMENT
#endif

#ifdef __cplusplus
extern "C" {
#endif

struct HddsDataReader;
struct HddsDataWriter;
struct HddsGuardCondition;
struct rmw_hdds_context_t;
struct rmw_hdds_waitset_t;
struct rmw_guard_condition_s;

typedef enum rmw_hdds_codec_kind_e {
    RMW_HDDS_CODEC_NONE = 0,
    RMW_HDDS_CODEC_STRING = 1,
    RMW_HDDS_CODEC_LOG = 2,
    RMW_HDDS_CODEC_PARAMETER_EVENT = 3,
} rmw_hdds_codec_kind_t;

typedef enum rmw_hdds_error_e {
    RMW_HDDS_ERROR_OK = 0,
    RMW_HDDS_ERROR_INVALID_ARGUMENT = 1,
    RMW_HDDS_ERROR_NOT_FOUND = 2,
    RMW_HDDS_ERROR_OPERATION_FAILED = 3,
    RMW_HDDS_ERROR_OUT_OF_MEMORY = 4,
} rmw_hdds_error_t;

typedef enum rmw_hdds_filter_op_e {
    RMW_HDDS_FILTER_OP_EQ = 0,
    RMW_HDDS_FILTER_OP_NEQ = 1,
    RMW_HDDS_FILTER_OP_LT = 2,
    RMW_HDDS_FILTER_OP_LTE = 3,
    RMW_HDDS_FILTER_OP_GT = 4,
    RMW_HDDS_FILTER_OP_GTE = 5,
} rmw_hdds_filter_op_t;

typedef enum rmw_hdds_filter_value_kind_e {
    RMW_HDDS_FILTER_VALUE_NONE = 0,
    RMW_HDDS_FILTER_VALUE_BOOL = 1,
    RMW_HDDS_FILTER_VALUE_SIGNED = 2,
    RMW_HDDS_FILTER_VALUE_UNSIGNED = 3,
    RMW_HDDS_FILTER_VALUE_FLOAT = 4,
    RMW_HDDS_FILTER_VALUE_LONG_DOUBLE = 5,
    RMW_HDDS_FILTER_VALUE_STRING = 6,
} rmw_hdds_filter_value_kind_t;

typedef struct rmw_hdds_content_filter_value {
    rmw_hdds_filter_value_kind_t kind;
    bool boolean;
    int64_t signed_value;
    uint64_t unsigned_value;
    double float_value;
    long double long_double_value;
    const char* string_value;
    size_t string_length;
} rmw_hdds_content_filter_value_t;

typedef struct rmw_hdds_content_filter {
    bool enabled;
    rmw_hdds_filter_op_t op;
    size_t param_index;
    size_t member_offset;
    uint8_t member_type;
    rmw_hdds_content_filter_value_t parameter;
} rmw_hdds_content_filter_t;

typedef struct rmw_hdds_qos_profile_t {
    uint8_t history;
    uint32_t depth;
    uint8_t reliability;
    uint8_t durability;
    uint64_t deadline_ns;
    uint64_t lifespan_ns;
    uint8_t liveliness;
    uint64_t liveliness_lease_ns;
    bool avoid_ros_namespace_conventions;
} rmw_hdds_qos_profile_t;

typedef struct rmw_hdds_context_impl {
    uint32_t domain_id;
    struct rmw_hdds_context_t* native_ctx;
    bool owns_context;
} rmw_hdds_context_impl_t;

typedef struct rmw_hdds_endpoint_entry {
    const char* topic_name;
    const rosidl_message_type_support_t* type_support;
    size_t refcount;
} rmw_hdds_endpoint_entry_t;

typedef struct rmw_hdds_endpoint_set {
    rmw_hdds_endpoint_entry_t* entries;
   size_t size;
    size_t capacity;
} rmw_hdds_endpoint_set_t;

static inline void
rmw_hdds_endpoint_set_init(rmw_hdds_endpoint_set_t* set)
{
    if (set == NULL) {
        return;
    }
    set->entries = NULL;
    set->size = 0;
    set->capacity = 0;
}

static inline void
rmw_hdds_endpoint_set_fini(rmw_hdds_endpoint_set_t* set, rcutils_allocator_t allocator)
{
    if (set == NULL) {
        return;
    }
    if (set->entries != NULL) {
        allocator.deallocate(set->entries, allocator.state);
        set->entries = NULL;
    }
    set->size = 0;
    set->capacity = 0;
}

static inline rmw_ret_t
rmw_hdds_endpoint_set_reserve(
    rmw_hdds_endpoint_set_t* set,
    size_t new_capacity,
    rcutils_allocator_t allocator)
{
    if (set->capacity >= new_capacity) {
        return RMW_RET_OK;
    }

    void* new_entries = NULL;
    if (allocator.reallocate != NULL && set->entries != NULL) {
        new_entries = allocator.reallocate(
            set->entries,
            new_capacity * sizeof(rmw_hdds_endpoint_entry_t),
            allocator.state);
    } else {
        new_entries = allocator.allocate(
            new_capacity * sizeof(rmw_hdds_endpoint_entry_t),
            allocator.state);
        if (new_entries != NULL && set->entries != NULL) {
            memcpy(
                new_entries,
                set->entries,
                set->size * sizeof(rmw_hdds_endpoint_entry_t));
            allocator.deallocate(set->entries, allocator.state);
        }
    }

    if (new_entries == NULL) {
        return RMW_RET_BAD_ALLOC;
    }

    set->entries = (rmw_hdds_endpoint_entry_t*)new_entries;
    set->capacity = new_capacity;
    return RMW_RET_OK;
}

static inline rmw_ret_t
rmw_hdds_endpoint_set_add(
    rmw_hdds_endpoint_set_t* set,
    const char* topic_name,
    const rosidl_message_type_support_t* type_support,
    rcutils_allocator_t allocator)
{
    if (set == NULL || topic_name == NULL || type_support == NULL) {
        return RMW_RET_INVALID_ARGUMENT;
    }

    for (size_t idx = 0; idx < set->size; ++idx) {
        rmw_hdds_endpoint_entry_t* entry = &set->entries[idx];
        if (entry->type_support == type_support &&
            strcmp(entry->topic_name, topic_name) == 0) {
            entry->refcount++;
            return RMW_RET_OK;
        }
    }

    if (set->size + 1 > set->capacity) {
        size_t target_capacity = set->capacity == 0 ? 4u : set->capacity * 2u;
        rmw_ret_t reserve_status =
            rmw_hdds_endpoint_set_reserve(set, target_capacity, allocator);
        if (reserve_status != RMW_RET_OK) {
            return reserve_status;
        }
    }

    set->entries[set->size++] = (rmw_hdds_endpoint_entry_t){
        .topic_name = topic_name,
        .type_support = type_support,
        .refcount = 1u,
    };

    return RMW_RET_OK;
}

static inline rmw_ret_t
rmw_hdds_endpoint_set_remove(
    rmw_hdds_endpoint_set_t* set,
    const char* topic_name,
    const rosidl_message_type_support_t* type_support)
{
    if (set == NULL || topic_name == NULL || type_support == NULL) {
        return RMW_RET_INVALID_ARGUMENT;
    }

    for (size_t idx = 0; idx < set->size; ++idx) {
        rmw_hdds_endpoint_entry_t* entry = &set->entries[idx];
        if (entry->type_support == type_support &&
            strcmp(entry->topic_name, topic_name) == 0) {
            if (entry->refcount > 1u) {
                entry->refcount--;
                return RMW_RET_OK;
            }

            if (idx + 1u < set->size) {
                set->entries[idx] = set->entries[set->size - 1u];
            }
            set->size--;
            return RMW_RET_OK;
        }
    }

    return RMW_RET_ERROR;
}

typedef struct rmw_hdds_node_impl {
    rmw_hdds_context_impl_t* context;
    char* name;
    char* namespace_;
    const struct HddsGuardCondition* graph_guard;
    struct rmw_guard_condition_s* rmw_guard;
    rcutils_allocator_t allocator;
    rmw_hdds_endpoint_set_t publishers;
    rmw_hdds_endpoint_set_t subscriptions;
} rmw_hdds_node_impl_t;

typedef struct rmw_hdds_wait_set_impl {
    rmw_hdds_context_impl_t* context;
    struct rmw_hdds_waitset_t* waitset;
    rcutils_allocator_t allocator;
} rmw_hdds_wait_set_impl_t;

typedef struct rmw_hdds_guard_condition_impl {
    uint32_t magic;
    const struct HddsGuardCondition* handle;
} rmw_hdds_guard_condition_impl_t;

#define RMW_HDDS_GUARD_MAGIC 0x48444453u

typedef struct rmw_hdds_subscription_impl {
    rmw_hdds_context_impl_t* context;
    struct HddsDataReader* reader;
    uint64_t condition_key;
    char* topic_name;
    char* type_name;  // ROS2 type name (e.g., "std_msgs/msg/Int32") for dynamic types
    const rosidl_message_type_support_t* type_support;
    rmw_qos_profile_t qos_profile;
    bool has_introspection;
    bool use_dynamic_types;  // true if dynamic type descriptor is available
    bool registered_in_graph;
    rmw_hdds_codec_kind_t codec_kind;
    size_t raw_message_size;  // size_of from introspection, 0 if unknown
    char* content_filter_expression;
    rcutils_string_array_t content_filter_parameters;
    rmw_hdds_content_filter_t content_filter;
    rmw_event_callback_t message_callback;
    const void* message_user_data;
} rmw_hdds_subscription_impl_t;

typedef struct rmw_hdds_publisher_impl {
    rmw_hdds_context_impl_t* context;
    struct HddsDataWriter* writer;
    char* topic_name;
    const rosidl_message_type_support_t* type_support;
    rmw_qos_profile_t qos_profile;
    bool has_introspection;
    bool registered_in_graph;
    rmw_hdds_codec_kind_t codec_kind;
    size_t raw_message_size;  // size_of from introspection, 0 if unknown
} rmw_hdds_publisher_impl_t;

typedef struct rmw_hdds_service_impl {
    rmw_hdds_context_impl_t* context;
    char* service_name;
    char* request_topic;
    char* response_topic;
    const rosidl_service_type_support_t* type_support;
    const rosidl_message_type_support_t* request_type_support;
    const rosidl_message_type_support_t* response_type_support;
    char* request_type_name;
    char* response_type_name;
    struct HddsDataReader* request_reader;
    struct HddsDataWriter* response_writer;
    rmw_qos_profile_t qos_profile;
    bool request_use_dynamic_types;
    bool response_use_dynamic_types;
    bool request_registered_in_graph;
    bool response_registered_in_graph;
    rmw_event_callback_t request_callback;
    const void* request_user_data;
} rmw_hdds_service_impl_t;

typedef struct rmw_hdds_client_impl {
    rmw_hdds_context_impl_t* context;
    char* service_name;
    char* request_topic;
    char* response_topic;
    const rosidl_service_type_support_t* type_support;
    const rosidl_message_type_support_t* request_type_support;
    const rosidl_message_type_support_t* response_type_support;
    char* request_type_name;
    char* response_type_name;
    struct HddsDataWriter* request_writer;
    struct HddsDataReader* response_reader;
    rmw_qos_profile_t qos_profile;
    bool request_use_dynamic_types;
    bool response_use_dynamic_types;
    bool request_registered_in_graph;
    bool response_registered_in_graph;
    rmw_event_callback_t response_callback;
    const void* response_user_data;
    int8_t writer_guid[16];
    int64_t next_sequence;
} rmw_hdds_client_impl_t;

// Forward declaration (defined in ffi.h / Rust FFI).
rmw_hdds_error_t rmw_hdds_context_guid_prefix(
    struct rmw_hdds_context_t* context,
    uint8_t* out_prefix);

/// Build a 16-byte GID from the participant GUID prefix (12 bytes) and an
/// entity-specific hash derived from the pointer (4 bytes).  This produces
/// cross-process stable identifiers (the prefix is the same for every
/// participant instance with the same RTPS GUID).
static inline void
rmw_hdds_gid_from_ptr(
    uint8_t gid_out[RMW_GID_STORAGE_SIZE],
    const void * ptr,
    struct rmw_hdds_context_t * native_ctx)
{
    if (gid_out == NULL) {
        return;
    }
    memset(gid_out, 0, RMW_GID_STORAGE_SIZE);
    if (ptr == NULL || native_ctx == NULL) {
        return;
    }

    // First 12 bytes: participant GUID prefix (stable cross-process).
    rmw_hdds_context_guid_prefix(native_ctx, gid_out);

    // Last 4 bytes: entity-specific identifier for intra-participant uniqueness.
    uint32_t entity_id = (uint32_t)((uintptr_t)ptr & 0xFFFFFFFFu);
    memcpy(gid_out + 12, &entity_id, sizeof(entity_id));
}

static inline uint64_t
rmw_hdds_time_to_ns(rmw_time_t time)
{
    if (time.sec == 0u && time.nsec == 0u) {
        return 0u;
    }
    const uint64_t sec_ns = 1000000000ull;
    if (time.sec > (UINT64_MAX / sec_ns)) {
        return UINT64_MAX;
    }
    uint64_t base = time.sec * sec_ns;
    if (UINT64_MAX - base < time.nsec) {
        return UINT64_MAX;
    }
    return base + time.nsec;
}

static inline rmw_hdds_qos_profile_t
rmw_hdds_qos_profile_from_rmw(const rmw_qos_profile_t * profile)
{
    rmw_hdds_qos_profile_t out = {0};
    if (profile == NULL) {
        return out;
    }

    out.history = (uint8_t)profile->history;
    out.depth = (uint32_t)profile->depth;
    out.reliability = (uint8_t)profile->reliability;
    out.durability = (uint8_t)profile->durability;
    out.deadline_ns = rmw_hdds_time_to_ns(profile->deadline);
    out.lifespan_ns = rmw_hdds_time_to_ns(profile->lifespan);
    out.liveliness = (uint8_t)profile->liveliness;
    out.liveliness_lease_ns = rmw_hdds_time_to_ns(profile->liveliness_lease_duration);
    out.avoid_ros_namespace_conventions = profile->avoid_ros_namespace_conventions;

    return out;
}

#ifdef __cplusplus
}
#endif

#endif  // RMW_HDDS__TYPES_H_
