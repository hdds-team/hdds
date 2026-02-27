// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

#include <inttypes.h>
#include <rmw/rmw.h>
#include <rmw/error_handling.h>
#include <rcutils/allocator.h>
#include <rcutils/logging_macros.h>
#include <stdio.h>

#include <limits.h>
#include "rmw_hdds/ffi.h"
#include "rmw_hdds/types.h"

static rmw_ret_t map_error(rmw_hdds_error_t err) {
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

static int64_t timeout_to_ns(const rmw_time_t* wait_timeout) {
    if (!wait_timeout) {
        return -1;
    }

    const int64_t sec_component = (int64_t)wait_timeout->sec * 1000000000LL;
    const int64_t nsec_component = (int64_t)wait_timeout->nsec;

    if (sec_component < 0 || nsec_component < 0) {
        return -1;
    }

    if (sec_component > INT64_MAX - nsec_component) {
        return -1;
    }

    return sec_component + nsec_component;
}

static rcutils_allocator_t select_allocator(const rmw_context_t* context) {
    if (context && rcutils_allocator_is_valid(&context->options.allocator)) {
        return context->options.allocator;
    }
    return rcutils_get_default_allocator();
}

static const struct HddsGuardCondition*
native_guard_from_entry(void* entry) {
    if (!entry) {
        return NULL;
    }

    rmw_guard_condition_t* guard = (rmw_guard_condition_t*)entry;
    if (guard->implementation_identifier != rmw_get_implementation_identifier()) {
        return NULL;
    }

    if (guard->data == NULL) {
        return NULL;
    }

    rmw_hdds_guard_condition_impl_t* impl =
        (rmw_hdds_guard_condition_impl_t*)guard->data;
    if (impl->magic == RMW_HDDS_GUARD_MAGIC) {
        return impl->handle;
    }

    return (const struct HddsGuardCondition*)guard->data;
}

static rmw_hdds_subscription_impl_t*
subscription_impl_from_entry(void* entry) {
    if (!entry) {
        return NULL;
    }
    rmw_subscription_t* handle = (rmw_subscription_t*)entry;
    if (handle->implementation_identifier == rmw_get_implementation_identifier()) {
        return (rmw_hdds_subscription_impl_t*)handle->data;
    }
    return (rmw_hdds_subscription_impl_t*)entry;
}

static rmw_hdds_service_impl_t*
service_impl_from_entry(void* entry) {
    if (!entry) {
        return NULL;
    }
    rmw_service_t* handle = (rmw_service_t*)entry;
    if (handle->implementation_identifier == rmw_get_implementation_identifier()) {
        return (rmw_hdds_service_impl_t*)handle->data;
    }
    return (rmw_hdds_service_impl_t*)entry;
}

static rmw_hdds_client_impl_t*
client_impl_from_entry(void* entry) {
    if (!entry) {
        return NULL;
    }
    rmw_client_t* handle = (rmw_client_t*)entry;
    if (handle->implementation_identifier == rmw_get_implementation_identifier()) {
        return (rmw_hdds_client_impl_t*)handle->data;
    }
    return (rmw_hdds_client_impl_t*)entry;
}

static void
detach_context_guards(
    rmw_hdds_context_impl_t* ctx_impl,
    const uint64_t* keys,
    size_t count) {
    if (!ctx_impl || !ctx_impl->native_ctx || !keys) {
        return;
    }
    for (size_t i = 0; i < count; ++i) {
        (void)hdds_rmw_context_detach_condition(
            (struct HddsRmwContext*)ctx_impl->native_ctx,
            keys[i]);
    }
}

rmw_wait_set_t* rmw_create_wait_set(rmw_context_t* context, size_t max_conditions) {
    (void)max_conditions;

    RMW_CHECK_ARGUMENT_FOR_NULL(context, NULL);

    if (context->implementation_identifier != rmw_get_implementation_identifier()) {
        RMW_SET_ERROR_MSG("rmw_create_wait_set identifier mismatch");
        return NULL;
    }

    rmw_hdds_context_impl_t* ctx_impl =
        (rmw_hdds_context_impl_t*)context->impl;
    if (!ctx_impl || !ctx_impl->native_ctx) {
        RMW_SET_ERROR_MSG("context is missing HDDS native handle");
        return NULL;
    }

    rcutils_allocator_t allocator = select_allocator(context);

    rmw_wait_set_t* wait_set = (rmw_wait_set_t*)allocator.allocate(
        sizeof(rmw_wait_set_t), allocator.state);
    if (!wait_set) {
        RMW_SET_ERROR_MSG("failed to allocate wait set");
        return NULL;
    }

    rmw_hdds_wait_set_impl_t* impl = (rmw_hdds_wait_set_impl_t*)allocator.allocate(
        sizeof(rmw_hdds_wait_set_impl_t), allocator.state);
    if (!impl) {
        allocator.deallocate(wait_set, allocator.state);
        RMW_SET_ERROR_MSG("failed to allocate wait set impl");
        return NULL;
    }

    impl->context = ctx_impl;
    impl->waitset = NULL;
    impl->allocator = allocator;

    struct rmw_hdds_waitset_t* native_waitset = NULL;
    rmw_hdds_error_t err = rmw_hdds_waitset_create(ctx_impl->native_ctx, &native_waitset);
    if (err != RMW_HDDS_ERROR_OK) {
        allocator.deallocate(impl, allocator.state);
        allocator.deallocate(wait_set, allocator.state);
        RMW_SET_ERROR_MSG("failed to create HDDS wait set");
        return NULL;
    }

    impl->waitset = native_waitset;

    rmw_guard_conditions_t* guard_conditions =
        (rmw_guard_conditions_t*)allocator.allocate(
            sizeof(rmw_guard_conditions_t), allocator.state);
    if (!guard_conditions) {
        rmw_hdds_waitset_destroy(native_waitset);
        allocator.deallocate(impl, allocator.state);
        allocator.deallocate(wait_set, allocator.state);
        RMW_SET_ERROR_MSG("failed to allocate guard conditions");
        return NULL;
    }

    guard_conditions->guard_condition_count = 0;
    guard_conditions->guard_conditions = NULL;

    wait_set->implementation_identifier = rmw_get_implementation_identifier();
    wait_set->guard_conditions = guard_conditions;
    wait_set->data = impl;

    return wait_set;
}

rmw_ret_t rmw_destroy_wait_set(rmw_wait_set_t* wait_set) {
    RMW_CHECK_ARGUMENT_FOR_NULL(wait_set, RMW_RET_INVALID_ARGUMENT);

    if (wait_set->implementation_identifier != rmw_get_implementation_identifier()) {
        RMW_SET_ERROR_MSG("rmw_destroy_wait_set identifier mismatch");
        return RMW_RET_INCORRECT_RMW_IMPLEMENTATION;
    }

    rmw_hdds_wait_set_impl_t* impl =
        (rmw_hdds_wait_set_impl_t*)wait_set->data;
    if (!impl) {
        RMW_SET_ERROR_MSG("wait set missing implementation data");
        return RMW_RET_INVALID_ARGUMENT;
    }

    if (impl->waitset) {
        rmw_hdds_waitset_destroy(impl->waitset);
        impl->waitset = NULL;
    }

    rcutils_allocator_t allocator = impl->allocator;
    if (!rcutils_allocator_is_valid(&allocator)) {
        allocator = rcutils_get_default_allocator();
    }

    allocator.deallocate(impl, allocator.state);
    if (wait_set->guard_conditions) {
        allocator.deallocate(wait_set->guard_conditions, allocator.state);
        wait_set->guard_conditions = NULL;
    }
    allocator.deallocate(wait_set, allocator.state);

    return RMW_RET_OK;
}

rmw_ret_t rmw_wait(
    rmw_subscriptions_t* subscriptions,
    rmw_guard_conditions_t* guard_conditions,
    rmw_services_t* services,
    rmw_clients_t* clients,
    rmw_events_t* events,
    rmw_wait_set_t* wait_set,
    const rmw_time_t* wait_timeout)
{
    (void)guard_conditions;

    RMW_CHECK_ARGUMENT_FOR_NULL(wait_set, RMW_RET_INVALID_ARGUMENT);

    if (wait_set->implementation_identifier != rmw_get_implementation_identifier()) {
        RMW_SET_ERROR_MSG("rmw_wait identifier mismatch");
        return RMW_RET_INCORRECT_RMW_IMPLEMENTATION;
    }

    size_t ignored_events = events ? events->event_count : 0u;
    if (ignored_events > 0u) {
        RCUTILS_LOG_DEBUG_NAMED(
            "rmw_hdds",
            "Ignoring %zu event(s) during wait: not supported by rmw_hdds",
            ignored_events);
        if (events && events->events != NULL) {
            for (size_t i = 0; i < events->event_count; ++i) {
                events->events[i] = NULL;
            }
        }
    }

    rmw_hdds_wait_set_impl_t* impl =
        (rmw_hdds_wait_set_impl_t*)wait_set->data;
    if (!impl || !impl->waitset || !impl->context || !impl->context->native_ctx) {
        // During shutdown, rcl_wait may be called after resources are torn down.
        // Treat this as a no-op instead of surfacing an error to avoid spurious aborts.
        RCUTILS_LOG_DEBUG_NAMED("rmw_hdds", "wait set not initialized; treating as no-op");
        return RMW_RET_OK;
    }

    rcutils_allocator_t allocator = impl->allocator;
    if (!rcutils_allocator_is_valid(&allocator)) {
        allocator = rcutils_get_default_allocator();
    }

    size_t attached_guard_count = 0;
    uint64_t* guard_keys = NULL;

    if (guard_conditions && guard_conditions->guard_condition_count > 0 &&
        guard_conditions->guard_conditions != NULL)
    {
        guard_keys = (uint64_t*)allocator.zero_allocate(
            guard_conditions->guard_condition_count,
            sizeof(uint64_t),
            allocator.state);
        if (guard_keys == NULL) {
            RMW_SET_ERROR_MSG("failed to allocate guard attachment array");
            return RMW_RET_BAD_ALLOC;
        }

        for (size_t i = 0; i < guard_conditions->guard_condition_count; ++i) {
            void* entry = guard_conditions->guard_conditions[i];
            if (entry == NULL) {
                continue;
            }

            const struct HddsGuardCondition* native_guard = native_guard_from_entry(entry);
            if (native_guard == NULL) {
                RCUTILS_LOG_DEBUG_NAMED(
                    "rmw_hdds",
                    "Ignoring guard condition without native handle");
                continue;
            }

            uint64_t key = 0u;
            HddsError attach_res = hdds_rmw_context_attach_guard_condition(
                (struct HddsRmwContext*)impl->context->native_ctx,
                native_guard,
                &key);
            if (attach_res != OK) {
                detach_context_guards(impl->context, guard_keys, attached_guard_count);
                allocator.deallocate(guard_keys, allocator.state);
                RMW_SET_ERROR_MSG("failed to attach guard condition to waitset");
                return map_error((rmw_hdds_error_t)attach_res);
            }

            guard_keys[attached_guard_count++] = key;
        }
    }

    size_t subscription_count = 0;
    size_t service_count = 0;
    size_t client_count = 0;
    if (subscriptions) {
        subscription_count = subscriptions->subscriber_count;
        if (subscription_count > 0 && !subscriptions->subscribers) {
            RMW_SET_ERROR_MSG("subscriptions array is null");
            return RMW_RET_INVALID_ARGUMENT;
        }
    }
    if (services) {
        service_count = services->service_count;
        if (service_count > 0 && !services->services) {
            RMW_SET_ERROR_MSG("services array is null");
            return RMW_RET_INVALID_ARGUMENT;
        }
    }
    if (clients) {
        client_count = clients->client_count;
        if (client_count > 0 && !clients->clients) {
            RMW_SET_ERROR_MSG("clients array is null");
            return RMW_RET_INVALID_ARGUMENT;
        }
    }

    struct HddsDataReader** subscription_readers = NULL;
    struct HddsDataReader** service_readers = NULL;
    struct HddsDataReader** client_readers = NULL;

    if (subscription_count > 0) {
        subscription_readers = (struct HddsDataReader**)allocator.allocate(
            subscription_count * sizeof(struct HddsDataReader*),
            allocator.state);
        if (!subscription_readers) {
            detach_context_guards(impl->context, guard_keys, attached_guard_count);
            allocator.deallocate(guard_keys, allocator.state);
            RMW_SET_ERROR_MSG("failed to allocate subscription reader array");
            return RMW_RET_BAD_ALLOC;
        }
        for (size_t i = 0; i < subscription_count; ++i) {
            if (!subscriptions->subscribers[i]) {
                subscription_readers[i] = NULL;
                continue;
            }
            rmw_hdds_subscription_impl_t* sub_impl =
                subscription_impl_from_entry(subscriptions->subscribers[i]);
            subscription_readers[i] = sub_impl ? sub_impl->reader : NULL;
        }
    }

    if (service_count > 0) {
        service_readers = (struct HddsDataReader**)allocator.allocate(
            service_count * sizeof(struct HddsDataReader*),
            allocator.state);
        if (!service_readers) {
            if (subscription_readers) {
                allocator.deallocate(subscription_readers, allocator.state);
            }
            detach_context_guards(impl->context, guard_keys, attached_guard_count);
            allocator.deallocate(guard_keys, allocator.state);
            RMW_SET_ERROR_MSG("failed to allocate service reader array");
            return RMW_RET_BAD_ALLOC;
        }
        for (size_t i = 0; i < service_count; ++i) {
            if (!services->services[i]) {
                service_readers[i] = NULL;
                continue;
            }
            rmw_hdds_service_impl_t* svc_impl =
                service_impl_from_entry(services->services[i]);
            service_readers[i] = svc_impl ? svc_impl->request_reader : NULL;
        }
    }

    if (client_count > 0) {
        client_readers = (struct HddsDataReader**)allocator.allocate(
            client_count * sizeof(struct HddsDataReader*),
            allocator.state);
        if (!client_readers) {
            if (service_readers) {
                allocator.deallocate(service_readers, allocator.state);
            }
            if (subscription_readers) {
                allocator.deallocate(subscription_readers, allocator.state);
            }
            detach_context_guards(impl->context, guard_keys, attached_guard_count);
            allocator.deallocate(guard_keys, allocator.state);
            RMW_SET_ERROR_MSG("failed to allocate client reader array");
            return RMW_RET_BAD_ALLOC;
        }
        for (size_t i = 0; i < client_count; ++i) {
            if (!clients->clients[i]) {
                client_readers[i] = NULL;
                continue;
            }
            rmw_hdds_client_impl_t* cli_impl =
                client_impl_from_entry(clients->clients[i]);
            client_readers[i] = cli_impl ? cli_impl->response_reader : NULL;
        }
    }

    size_t total_readers = subscription_count + service_count + client_count;
    size_t ready_len = 0;
    bool guard_triggered = false;
    const int64_t timeout_ns = timeout_to_ns(wait_timeout);

    size_t out_len = 0;
    struct HddsDataReader** ready_readers = NULL;
    if (total_readers > 0) {
        ready_readers = (struct HddsDataReader**)allocator.allocate(
            total_readers * sizeof(struct HddsDataReader*), allocator.state);
        if (!ready_readers) {
            if (client_readers) { allocator.deallocate(client_readers, allocator.state); }
            if (service_readers) { allocator.deallocate(service_readers, allocator.state); }
            if (subscription_readers) { allocator.deallocate(subscription_readers, allocator.state); }
            detach_context_guards(impl->context, guard_keys, attached_guard_count);
            allocator.deallocate(guard_keys, allocator.state);
            RMW_SET_ERROR_MSG("failed to allocate ready readers array");
            return RMW_RET_BAD_ALLOC;
        }
    }

    RCUTILS_LOG_DEBUG_NAMED(
        "rmw_hdds",
        "waitset waiting: subscriptions=%zu services=%zu clients=%zu timeout_ns=%" PRId64,
        subscription_count,
        service_count,
        client_count,
        timeout_ns);

    /* SHM pre-check: before blocking on RTPS wait, check if any subscription
     * has SHM data already available. If so, mark those as ready and return
     * immediately without blocking. */
    bool shm_ready = false;
    bool* shm_sub_ready = NULL;
    if (subscription_count > 0 && impl->context && impl->context->native_ctx) {
        shm_sub_ready = (bool*)allocator.zero_allocate(
            subscription_count, sizeof(bool), allocator.state);
        if (shm_sub_ready) {
            for (size_t i = 0; i < subscription_count; ++i) {
                if (!subscriptions->subscribers[i]) {
                    continue;
                }
                rmw_hdds_subscription_impl_t* sub_impl =
                    subscription_impl_from_entry(subscriptions->subscribers[i]);
                if (sub_impl && sub_impl->topic_name && sub_impl->raw_message_size > 0) {
                    if (hdds_rmw_context_shm_has_data(
                            (struct HddsRmwContext*)impl->context->native_ctx,
                            sub_impl->topic_name))
                    {
                        shm_sub_ready[i] = true;
                        shm_ready = true;
                    }
                }
            }
        }
    }

    /* If SHM data was found, skip the blocking RTPS wait entirely */
    if (shm_ready) {
        /* Mark SHM-ready subscriptions and null-out the rest */
        for (size_t i = 0; i < subscription_count; ++i) {
            if (!shm_sub_ready[i]) {
                subscriptions->subscribers[i] = NULL;
            }
        }
        /* Null-out services, clients, guard_conditions (not ready via SHM) */
        if (services) {
            for (size_t i = 0; i < service_count; ++i) {
                services->services[i] = NULL;
            }
        }
        if (clients) {
            for (size_t i = 0; i < client_count; ++i) {
                clients->clients[i] = NULL;
            }
        }
        if (guard_conditions && guard_conditions->guard_conditions) {
            for (size_t i = 0; i < guard_conditions->guard_condition_count; ++i) {
                guard_conditions->guard_conditions[i] = NULL;
            }
        }
        if (events && events->events) {
            for (size_t i = 0; i < events->event_count; ++i) {
                events->events[i] = NULL;
            }
        }
        allocator.deallocate(shm_sub_ready, allocator.state);
        detach_context_guards(impl->context, guard_keys, attached_guard_count);
        if (guard_keys) { allocator.deallocate(guard_keys, allocator.state); }
        if (ready_readers) { allocator.deallocate(ready_readers, allocator.state); }
        if (subscription_readers) { allocator.deallocate(subscription_readers, allocator.state); }
        if (service_readers) { allocator.deallocate(service_readers, allocator.state); }
        if (client_readers) { allocator.deallocate(client_readers, allocator.state); }
        return RMW_RET_OK;
    }
    if (shm_sub_ready) {
        allocator.deallocate(shm_sub_ready, allocator.state);
    }

    /* Use context-level wait instead of waitset wait. The readers are already
     * attached to the context in rmw_create_subscription, so context_wait_readers
     * returns triggered reader pointers directly without needing per-call
     * attach/detach on a separate waitset object. */
    rmw_hdds_error_t err = rmw_hdds_context_wait_readers(
        impl->context->native_ctx,
        timeout_ns,
        ready_readers,
        total_readers,
        &out_len,
        &guard_triggered);

    if (err != RMW_HDDS_ERROR_OK) {
        RCUTILS_LOG_ERROR_NAMED(
            "rmw_hdds",
            "waitset_wait returned %d (subscriptions=%zu services=%zu clients=%zu)",
            (int)err,
            subscription_count,
            service_count,
            client_count);
        detach_context_guards(impl->context, guard_keys, attached_guard_count);
        allocator.deallocate(guard_keys, allocator.state);
        if (ready_readers) { allocator.deallocate(ready_readers, allocator.state); }
        if (subscription_readers) { allocator.deallocate(subscription_readers, allocator.state); }
        if (service_readers) { allocator.deallocate(service_readers, allocator.state); }
        if (client_readers) { allocator.deallocate(client_readers, allocator.state); }
        RMW_SET_ERROR_MSG("waitset wait failed");
        return map_error(err);
    }

    bool* sub_triggered = NULL;
    bool* service_triggered = NULL;
    bool* client_triggered = NULL;
    if (subscription_count > 0) {
        sub_triggered = (bool*)allocator.zero_allocate(
            subscription_count, sizeof(bool), allocator.state);
    }
    if (service_count > 0) {
        service_triggered = (bool*)allocator.zero_allocate(
            service_count, sizeof(bool), allocator.state);
    }
    if (client_count > 0) {
        client_triggered = (bool*)allocator.zero_allocate(
            client_count, sizeof(bool), allocator.state);
    }

    if ((subscription_count > 0 && !sub_triggered) ||
        (service_count > 0 && !service_triggered) ||
        (client_count > 0 && !client_triggered))
    {
        if (sub_triggered) { allocator.deallocate(sub_triggered, allocator.state); }
        if (service_triggered) { allocator.deallocate(service_triggered, allocator.state); }
        if (client_triggered) { allocator.deallocate(client_triggered, allocator.state); }
        if (ready_readers) { allocator.deallocate(ready_readers, allocator.state); }
        if (client_readers) { allocator.deallocate(client_readers, allocator.state); }
        if (service_readers) { allocator.deallocate(service_readers, allocator.state); }
        if (subscription_readers) { allocator.deallocate(subscription_readers, allocator.state); }
        detach_context_guards(impl->context, guard_keys, attached_guard_count);
        allocator.deallocate(guard_keys, allocator.state);
        RMW_SET_ERROR_MSG("failed to allocate trigger bitmap");
        return RMW_RET_BAD_ALLOC;
    }

    if (out_len > 0 && ready_readers) {
        for (size_t i = 0; i < out_len; ++i) {
            struct HddsDataReader* rr = ready_readers[i];
            for (size_t j = 0; j < subscription_count; ++j) {
                if (subscription_readers && subscription_readers[j] == rr) {
                    if (!sub_triggered[j]) {
                        sub_triggered[j] = true;
                        ready_len++;
                    }
                    break;
                }
            }
            for (size_t j = 0; j < service_count; ++j) {
                if (service_readers && service_readers[j] == rr) {
                    if (!service_triggered[j]) {
                        service_triggered[j] = true;
                        ready_len++;
                    }
                    break;
                }
            }
            for (size_t j = 0; j < client_count; ++j) {
                if (client_readers && client_readers[j] == rr) {
                    if (!client_triggered[j]) {
                        client_triggered[j] = true;
                        ready_len++;
                    }
                    break;
                }
            }
        }
    }

    if (out_len > 0) {
        if (subscriptions && subscription_count > 0 && sub_triggered) {
            for (size_t i = 0; i < subscription_count; ++i) {
                if (!sub_triggered[i] || !subscriptions->subscribers[i]) {
                    continue;
                }
                rmw_hdds_subscription_impl_t* sub_impl =
                    subscription_impl_from_entry(subscriptions->subscribers[i]);
                if (sub_impl && sub_impl->message_callback) {
                    sub_impl->message_callback(sub_impl->message_user_data, 1u);
                }
            }
        }
        if (services && service_count > 0 && service_triggered) {
            for (size_t i = 0; i < service_count; ++i) {
                if (!service_triggered[i] || !services->services[i]) {
                    continue;
                }
                rmw_hdds_service_impl_t* svc_impl =
                    service_impl_from_entry(services->services[i]);
                if (svc_impl && svc_impl->request_callback) {
                    svc_impl->request_callback(svc_impl->request_user_data, 1u);
                }
            }
        }
        if (clients && client_count > 0 && client_triggered) {
            for (size_t i = 0; i < client_count; ++i) {
                if (!client_triggered[i] || !clients->clients[i]) {
                    continue;
                }
                rmw_hdds_client_impl_t* cli_impl =
                    client_impl_from_entry(clients->clients[i]);
                if (cli_impl && cli_impl->response_callback) {
                    cli_impl->response_callback(cli_impl->response_user_data, 1u);
                }
            }
        }
    }

    RCUTILS_LOG_DEBUG_NAMED(
        "rmw_hdds",
        "waitset result err=%d guard_triggered=%s ready_len=%zu",
        (int)err,
        guard_triggered ? "true" : "false",
        ready_len);

    // Guard condition triggers (e.g. graph changes) should NOT mark
    // subscriptions/services/clients as ready. Only actual data availability
    // should trigger those. The guard conditions are reported separately
    // via the guard_conditions output array.

    if (subscriptions && subscription_count > 0) {
        for (size_t i = 0; i < subscription_count; ++i) {
            if (!sub_triggered[i]) {
                subscriptions->subscribers[i] = NULL;
            }
        }
    }
    if (services && service_count > 0) {
        for (size_t i = 0; i < service_count; ++i) {
            if (!service_triggered[i]) {
                services->services[i] = NULL;
            }
        }
    }
    if (clients && client_count > 0) {
        for (size_t i = 0; i < client_count; ++i) {
            if (!client_triggered[i]) {
                clients->clients[i] = NULL;
            }
        }
    }

    if (sub_triggered) { allocator.deallocate(sub_triggered, allocator.state); }
    if (service_triggered) { allocator.deallocate(service_triggered, allocator.state); }
    if (client_triggered) { allocator.deallocate(client_triggered, allocator.state); }

    if (ready_readers) {
        allocator.deallocate(ready_readers, allocator.state);
        ready_readers = NULL;
    }
    if (client_readers) {
        allocator.deallocate(client_readers, allocator.state);
        client_readers = NULL;
    }
    if (service_readers) {
        allocator.deallocate(service_readers, allocator.state);
        service_readers = NULL;
    }
    if (subscription_readers) {
        allocator.deallocate(subscription_readers, allocator.state);
        subscription_readers = NULL;
    }

    // Check each guard condition individually: keep triggered ones, null-out
    // the rest. This avoids blanket reporting (all or none) based on the graph
    // guard alone.
    if (guard_conditions && guard_conditions->guard_conditions) {
        for (size_t i = 0; i < guard_conditions->guard_condition_count; ++i) {
            void* entry = guard_conditions->guard_conditions[i];
            if (entry == NULL) {
                continue;
            }
            const struct HddsGuardCondition* native_guard = native_guard_from_entry(entry);
            if (native_guard == NULL ||
                !hdds_guard_condition_get_trigger(native_guard))
            {
                guard_conditions->guard_conditions[i] = NULL;
            }
        }
    }

    // Only reset the graph guard when it specifically triggered, not when an
    // unrelated user guard condition fired.
    if (guard_triggered) {
        rmw_hdds_error_t guard_reset = rmw_hdds_context_set_guard(
            impl->context->native_ctx,
            false);
        if (guard_reset != RMW_HDDS_ERROR_OK) {
            RCUTILS_LOG_DEBUG_NAMED(
                "rmw_hdds",
                "failed to reset context guard after wait (status=%d)",
                (int)guard_reset);
        }
    }

    detach_context_guards(impl->context, guard_keys, attached_guard_count);
    if (guard_keys) {
        allocator.deallocate(guard_keys, allocator.state);
    }

    return RMW_RET_OK;
}
