// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

#include <rmw/rmw.h>
#include <rmw/error_handling.h>
#include <rcutils/allocator.h>
#include <rcutils/logging_macros.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "rmw_hdds/ffi.h"
#include "rmw_hdds/types.h"

// rmw_init_options_t gained `rmw_discovery_options_t discovery_options` in
// Iron. Its header is the marker this file uses for "Iron or later": the
// struct member itself cannot be probed by the preprocessor.
#if __has_include(<rmw/discovery_options.h>)
#include <rmw/discovery_options.h>
#define RMW_HDDS_HAS_DISCOVERY_OPTIONS 1
#endif

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
#ifdef RMW_HDDS_HAS_DISCOVERY_OPTIONS
    // Iron and later: rcl reads this struct back after rmw_init_options_init,
    // so leaving it as whatever was on the stack is a real defect.
    init_options->discovery_options = rmw_get_zero_initialized_discovery_options();
#endif

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

    // security_options carries an owned string too: the struct copy above
    // duplicated the POINTER, so a fini on both copies would free it twice.
    dst->security_options = rmw_get_zero_initialized_security_options();
    rmw_ret_t sec_ret = rmw_security_options_copy(
        &src->security_options, &allocator, &dst->security_options);
    if (sec_ret != RMW_RET_OK) {
        if (dst->enclave != NULL && dst->enclave != src->enclave) {
            allocator.deallocate((void*)dst->enclave, allocator.state);
            dst->enclave = NULL;
        }
        return sec_ret;
    }

#ifdef RMW_HDDS_HAS_DISCOVERY_OPTIONS
    dst->discovery_options = rmw_get_zero_initialized_discovery_options();
    rmw_ret_t disc_ret = rmw_discovery_options_copy(
        &src->discovery_options, &allocator, &dst->discovery_options);
    if (disc_ret != RMW_RET_OK) {
        rmw_ret_t sec_undo = rmw_security_options_fini(&dst->security_options, &allocator);
        if (sec_undo != RMW_RET_OK) {
            RCUTILS_LOG_WARN_NAMED(
                "rmw_hdds", "rmw_security_options_fini returned %d during copy rollback",
                (int)sec_undo);
        }
        if (dst->enclave != NULL && dst->enclave != src->enclave) {
            allocator.deallocate((void*)dst->enclave, allocator.state);
            dst->enclave = NULL;
        }
        return disc_ret;
    }
#endif

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

    /* Both are warn_unused_result and a (void) cast does not silence GCC. */
    rmw_ret_t sec_fini = rmw_security_options_fini(&init_options->security_options, &allocator);
    if (sec_fini != RMW_RET_OK) {
        RCUTILS_LOG_WARN_NAMED("rmw_hdds", "rmw_security_options_fini returned %d", (int)sec_fini);
    }
#ifdef RMW_HDDS_HAS_DISCOVERY_OPTIONS
    rmw_ret_t disc_fini = rmw_discovery_options_fini(&init_options->discovery_options);
    if (disc_fini != RMW_RET_OK) {
        RCUTILS_LOG_WARN_NAMED("rmw_hdds", "rmw_discovery_options_fini returned %d", (int)disc_fini);
    }
#endif

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

    /* Fail closed on ROS security.
     *
     * rcl fills options->security_options from ROS_SECURITY_ENABLE,
     * ROS_SECURITY_STRATEGY and the keystore lookup. rmw_hdds implements no
     * keystore loading at all: nothing in rmw_hdds/src reads
     * security_root_path, and no participant it creates enables DDS-Security.
     * A node started with ROS_SECURITY_STRATEGY=Enforce therefore used to come
     * up UNSECURED while believing it was protected - security theatre, and the
     * exact opposite of what Enforce means. Refuse instead. Permissive stays
     * allowed (that is what Permissive is for) with a warning that says plainly
     * that the node is running without security. */
    if (options->security_options.enforce_security == RMW_SECURITY_ENFORCEMENT_ENFORCE) {
        RMW_SET_ERROR_MSG(
            "rmw_hdds does not implement the ROS 2 security keystore, so it cannot honour "
            "ROS_SECURITY_STRATEGY=Enforce; refusing to start unsecured");
        RCUTILS_LOG_ERROR_NAMED(
            "rmw_hdds",
            "ROS_SECURITY_STRATEGY=Enforce requested (enclave '%s') but rmw_hdds has no "
            "keystore support: refusing to start rather than run unsecured",
            options->enclave != NULL ? options->enclave : "<none>");
        return RMW_RET_ERROR;
    }
    if (options->security_options.security_root_path != NULL) {
        RCUTILS_LOG_WARN_NAMED(
            "rmw_hdds",
            "a security keystore was resolved ('%s') but rmw_hdds ignores it: this node runs "
            "WITHOUT DDS-Security",
            options->security_options.security_root_path);
    }

    rmw_hdds_context_impl_t* impl = 
        (rmw_hdds_context_impl_t*)options->allocator.allocate(
            sizeof(rmw_hdds_context_impl_t), 
            options->allocator.state);

    if (!impl) {
        RMW_SET_ERROR_MSG("failed to allocate context");
        return RMW_RET_BAD_ALLOC;
    }

    /* Resolve domain ID: RMW_DEFAULT_DOMAIN_ID means "no explicit domain from
     * rcl", i.e. the environment decides: HDDS_DOMAIN_ID, then ROS_DOMAIN_ID,
     * then 0. The rule and its validator live in Rust (rmw_hdds_env_domain_id),
     * so a malformed value is refused here instead of being read as 0. An
     * explicit domain that rcl passed in is the caller's, not the environment's. */
    size_t resolved_domain_id = options->domain_id;
    if (resolved_domain_id == RMW_DEFAULT_DOMAIN_ID) {
        uint32_t env_domain = 0;
        if (!rmw_hdds_env_domain_id(&env_domain)) {
            options->allocator.deallocate(impl, options->allocator.state);
            RMW_SET_ERROR_MSG("HDDS_DOMAIN_ID or ROS_DOMAIN_ID is not a domain id in 0..232");
            return RMW_RET_INVALID_ARGUMENT;
        }
        resolved_domain_id = (size_t)env_domain;
    }
    /* RTPS derives every discovery port from the domain id, and the formula
     * runs out of port space past 232 (DDS-RTPS 2.5 section 9.6.1.1). Refuse
     * a domain we cannot honour instead of silently landing somewhere else. */
    if (resolved_domain_id > 232u) {
        options->allocator.deallocate(impl, options->allocator.state);
        RMW_SET_ERROR_MSG("domain id out of range (RTPS allows 0..232)");
        return RMW_RET_INVALID_ARGUMENT;
    }
    impl->domain_id = resolved_domain_id;
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

    /* The resolved domain has to reach the participant: without this every
     * ROS 2 node landed on DDS domain 0 regardless of ROS_DOMAIN_ID. */
    struct rmw_hdds_context_t* native_ctx = NULL;
    rmw_hdds_error_t err = rmw_hdds_context_create_with_domain(
        ctx_name, (uint32_t)resolved_domain_id, &native_ctx);
    if (err != RMW_HDDS_ERROR_OK) {
        RCUTILS_LOG_ERROR_NAMED(
            "rmw_hdds",
            "rmw_hdds_context_create_with_domain('%s', %zu) returned %d",
            ctx_name,
            resolved_domain_id,
            (int)err);
        fprintf(
            stderr,
            "[rmw_hdds] rmw_hdds_context_create_with_domain('%s', %zu) failed with code %d\n",
            ctx_name,
            resolved_domain_id,
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
    /* OWN the options, do not alias the caller's. `context->options =
     * *options` is a shallow struct copy: enclave and
     * security_options.security_root_path would point at memory the caller
     * frees in rcl_init_options_fini, and rmw_node.c reads context->options
     * .enclave for the whole life of the context. rmw_fastrtps copies here for
     * the same reason. */
    context->options = rmw_get_zero_initialized_init_options();
    rmw_ret_t opt_copy = rmw_init_options_copy(options, &context->options);
    if (opt_copy != RMW_RET_OK) {
        rmw_hdds_context_destroy(native_ctx);
        options->allocator.deallocate(impl, options->allocator.state);
        RMW_SET_ERROR_MSG("failed to copy init options into the context");
        return opt_copy;
    }
    context->actual_domain_id = resolved_domain_id;
    context->impl = (rmw_context_impl_t*)impl;

    RCUTILS_LOG_INFO_NAMED(
        "rmw_hdds",
        "RMW HDDS initialized (domain %zu)",
        resolved_domain_id);

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

    /* rmw_init deep-copied the options into the context, so the context owns
     * them: release them here, not in the caller. */
    rmw_ret_t opt_fini = rmw_init_options_fini(&context->options);
    if (opt_fini != RMW_RET_OK) {
        RCUTILS_LOG_WARN_NAMED(
            "rmw_hdds", "rmw_init_options_fini returned %d in rmw_context_fini", (int)opt_fini);
    }

    context->implementation_identifier = NULL;
    context->instance_id = 0;
    context->actual_domain_id = 0;

    return RMW_RET_OK;
}
