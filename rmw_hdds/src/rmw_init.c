// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

#include <rmw/rmw.h>
#include <rmw/error_handling.h>
#include <rcutils/allocator.h>
#include <rcutils/logging_macros.h>

#include <stdio.h>
#include <string.h>

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

const char* rmw_get_implementation_identifier(void) {
    return "rmw_hdds";
}

const char* rmw_get_serialization_format(void) {
    return "cdr";
}

rmw_ret_t rmw_init_options_init(
    rmw_init_options_t* init_options,
    rcutils_allocator_t allocator)
{
    RMW_CHECK_ARGUMENT_FOR_NULL(init_options, RMW_RET_INVALID_ARGUMENT);
    
    init_options->instance_id = 0;
    init_options->implementation_identifier = rmw_get_implementation_identifier();
    init_options->allocator = allocator;
    init_options->impl = NULL;
    init_options->enclave = NULL;
    init_options->domain_id = RMW_DEFAULT_DOMAIN_ID;
    init_options->security_options = rmw_get_zero_initialized_security_options();
    
    RCUTILS_LOG_INFO_NAMED("rmw_hdds", "Init options initialized");
    return RMW_RET_OK;
}

rmw_ret_t rmw_init_options_copy(
    const rmw_init_options_t* src,
    rmw_init_options_t* dst)
{
    RMW_CHECK_ARGUMENT_FOR_NULL(src, RMW_RET_INVALID_ARGUMENT);
    RMW_CHECK_ARGUMENT_FOR_NULL(dst, RMW_RET_INVALID_ARGUMENT);

    rcutils_allocator_t allocator = src->allocator;
    if (!rcutils_allocator_is_valid(&allocator)) {
        allocator = rcutils_get_default_allocator();
    }

    *dst = *src;
    // impl is per-context; the copy must not share ownership.
    dst->impl = NULL;

    // Deep-copy the enclave string to avoid double-free on fini.
    if (src->enclave != NULL) {
        size_t len = strlen(src->enclave) + 1;
        char* dup = (char*)allocator.allocate(len, allocator.state);
        if (dup == NULL) {
            RMW_SET_ERROR_MSG("failed to allocate enclave copy");
            return RMW_RET_BAD_ALLOC;
        }
        memcpy(dup, src->enclave, len);
        dst->enclave = dup;
    }

    return RMW_RET_OK;
}

rmw_ret_t rmw_init_options_fini(rmw_init_options_t* init_options) {
    RMW_CHECK_ARGUMENT_FOR_NULL(init_options, RMW_RET_INVALID_ARGUMENT);

    rcutils_allocator_t allocator = init_options->allocator;
    if (!rcutils_allocator_is_valid(&allocator)) {
        allocator = rcutils_get_default_allocator();
    }

    if (init_options->enclave != NULL) {
        allocator.deallocate((void*)init_options->enclave, allocator.state);
        init_options->enclave = NULL;
    }

    init_options->impl = NULL;
    init_options->instance_id = 0;
    init_options->domain_id = RMW_DEFAULT_DOMAIN_ID;

    return RMW_RET_OK;
}

rmw_ret_t rmw_init(
    const rmw_init_options_t* options,
    rmw_context_t* context)
{
    RMW_CHECK_ARGUMENT_FOR_NULL(options, RMW_RET_INVALID_ARGUMENT);
    RMW_CHECK_ARGUMENT_FOR_NULL(context, RMW_RET_INVALID_ARGUMENT);

    RCUTILS_LOG_INFO_NAMED("rmw_hdds", "Initializing RMW HDDS");

    if (context->implementation_identifier) {
        RMW_SET_ERROR_MSG("context is already initialized");
        return RMW_RET_INVALID_ARGUMENT;
    }

    if (options->implementation_identifier &&
        options->implementation_identifier != rmw_get_implementation_identifier()) {
        RMW_SET_ERROR_MSG("rmw init options identifier mismatch");
        return RMW_RET_INCORRECT_RMW_IMPLEMENTATION;
    }

    rmw_hdds_context_impl_t* impl = 
        (rmw_hdds_context_impl_t*)options->allocator.allocate(
            sizeof(rmw_hdds_context_impl_t), 
            options->allocator.state);

    if (!impl) {
        RMW_SET_ERROR_MSG("failed to allocate context");
        return RMW_RET_BAD_ALLOC;
    }

    impl->domain_id = options->domain_id;
    impl->native_ctx = NULL;
    impl->owns_context = false;

    char ctx_name[64];
    int name_len = snprintf(
        ctx_name,
        sizeof(ctx_name),
        "rmw_hdds_ctx_%llu",
        (unsigned long long)options->instance_id);
    if (name_len < 0 || (size_t)name_len >= sizeof(ctx_name)) {
        options->allocator.deallocate(impl, options->allocator.state);
        RMW_SET_ERROR_MSG("failed to compose context name");
        return RMW_RET_ERROR;
    }

    struct rmw_hdds_context_t* native_ctx = NULL;
    rmw_hdds_error_t err = rmw_hdds_context_create(ctx_name, &native_ctx);
    if (err != RMW_HDDS_ERROR_OK) {
        RCUTILS_LOG_ERROR_NAMED(
            "rmw_hdds",
            "rmw_hdds_context_create('%s') returned %d",
            ctx_name,
            (int)err);
        fprintf(
            stderr,
            "[rmw_hdds] rmw_hdds_context_create('%s') failed with code %d\n",
            ctx_name,
            (int)err);
        fflush(stderr);
        options->allocator.deallocate(impl, options->allocator.state);
        RMW_SET_ERROR_MSG("failed to create HDDS context");
        return map_error(err);
    }

    impl->native_ctx = native_ctx;
    impl->owns_context = true;

    context->instance_id = options->instance_id;
    context->implementation_identifier = rmw_get_implementation_identifier();
    context->options = *options;
    context->actual_domain_id = options->domain_id;
    context->impl = (rmw_context_impl_t*)impl;

    RCUTILS_LOG_INFO_NAMED(
        "rmw_hdds",
        "RMW HDDS initialized (domain %zu)",
        options->domain_id);

    return RMW_RET_OK;
}

rmw_ret_t rmw_shutdown(rmw_context_t* context) {
    RMW_CHECK_ARGUMENT_FOR_NULL(context, RMW_RET_INVALID_ARGUMENT);

    if (context->implementation_identifier != rmw_get_implementation_identifier()) {
        RMW_SET_ERROR_MSG("rmw shutdown identifier mismatch");
        return RMW_RET_INCORRECT_RMW_IMPLEMENTATION;
    }

    RCUTILS_LOG_INFO_NAMED("rmw_hdds", "Shutting down RMW HDDS");

    rmw_hdds_context_impl_t* impl =
        (rmw_hdds_context_impl_t*)context->impl;
    if (impl && impl->native_ctx && impl->owns_context) {
        rmw_hdds_context_destroy(impl->native_ctx);
        impl->native_ctx = NULL;
        impl->owns_context = false;
    }

    return RMW_RET_OK;
}

rmw_ret_t rmw_context_fini(rmw_context_t* context) {
    RMW_CHECK_ARGUMENT_FOR_NULL(context, RMW_RET_INVALID_ARGUMENT);

    if (context->impl) {
        rmw_hdds_context_impl_t* impl =
            (rmw_hdds_context_impl_t*)context->impl;
        if (impl->native_ctx && impl->owns_context) {
            rmw_hdds_context_destroy(impl->native_ctx);
            impl->native_ctx = NULL;
            impl->owns_context = false;
        }

        rcutils_allocator_t allocator = context->options.allocator;
        if (!rcutils_allocator_is_valid(&allocator)) {
            allocator = rcutils_get_default_allocator();
        }
        allocator.deallocate(context->impl, allocator.state);
        context->impl = NULL;
    }

    context->implementation_identifier = NULL;
    context->instance_id = 0;
    context->actual_domain_id = 0;

    return RMW_RET_OK;
}
