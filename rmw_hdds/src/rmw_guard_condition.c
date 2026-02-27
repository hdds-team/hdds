// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

#include <rmw/rmw.h>
#include <rmw/error_handling.h>

#include <rcutils/allocator.h>
#include "hdds.h"  // NOLINT(build/include_subdir)
#include "rmw_hdds/ffi.h"
#include "rmw_hdds/types.h"

static rcutils_allocator_t
select_allocator(const rmw_context_t * context)
{
  if (context != NULL && rcutils_allocator_is_valid(&context->options.allocator)) {
    return context->options.allocator;
  }
  return rcutils_get_default_allocator();
}

static const struct HddsGuardCondition *
guard_handle_from_data(const rmw_guard_condition_t * guard_condition)
{
  if (guard_condition == NULL) {
    return NULL;
  }

  if (guard_condition->implementation_identifier != rmw_get_implementation_identifier()) {
    return NULL;
  }

  if (guard_condition->data == NULL) {
    return NULL;
  }

  const rmw_hdds_guard_condition_impl_t * impl =
    (const rmw_hdds_guard_condition_impl_t *)guard_condition->data;
  if (impl->magic == RMW_HDDS_GUARD_MAGIC) {
    return impl->handle;
  }

  /* Fallback for guard conditions backed directly by a native pointer (graph guard). */
  return (const struct HddsGuardCondition *)guard_condition->data;
}

rmw_guard_condition_t *
rmw_create_guard_condition(rmw_context_t * context)
{
  RMW_CHECK_ARGUMENT_FOR_NULL(context, NULL);

  if (context->implementation_identifier != rmw_get_implementation_identifier()) {
    RMW_SET_ERROR_MSG("rmw_create_guard_condition identifier mismatch");
    return NULL;
  }

  rcutils_allocator_t allocator = select_allocator(context);

  rmw_guard_condition_t * guard =
    (rmw_guard_condition_t *)allocator.allocate(sizeof(rmw_guard_condition_t), allocator.state);
  if (guard == NULL) {
    RMW_SET_ERROR_MSG("failed to allocate guard condition handle");
    return NULL;
  }

  rmw_hdds_guard_condition_impl_t * impl = (rmw_hdds_guard_condition_impl_t *)allocator.allocate(
    sizeof(rmw_hdds_guard_condition_impl_t), allocator.state);
  if (impl == NULL) {
    allocator.deallocate(guard, allocator.state);
    RMW_SET_ERROR_MSG("failed to allocate guard condition impl");
    return NULL;
  }

  const struct HddsGuardCondition * handle = hdds_guard_condition_create();
  if (handle == NULL) {
    allocator.deallocate(impl, allocator.state);
    allocator.deallocate(guard, allocator.state);
    RMW_SET_ERROR_MSG("failed to create native guard condition");
    return NULL;
  }

  impl->magic = RMW_HDDS_GUARD_MAGIC;
  impl->handle = handle;

  guard->implementation_identifier = rmw_get_implementation_identifier();
  guard->data = impl;
  guard->context = context;

  return guard;
}

rmw_ret_t
rmw_destroy_guard_condition(rmw_guard_condition_t * guard_condition)
{
  RMW_CHECK_ARGUMENT_FOR_NULL(guard_condition, RMW_RET_INVALID_ARGUMENT);

  if (guard_condition->implementation_identifier != rmw_get_implementation_identifier()) {
    RMW_SET_ERROR_MSG("rmw_destroy_guard_condition identifier mismatch");
    return RMW_RET_INCORRECT_RMW_IMPLEMENTATION;
  }

  rcutils_allocator_t allocator = select_allocator(guard_condition->context);

  const struct HddsGuardCondition * handle = NULL;

  if (guard_condition->data != NULL) {
    rmw_hdds_guard_condition_impl_t * impl =
      (rmw_hdds_guard_condition_impl_t *)guard_condition->data;
    if (impl->magic == RMW_HDDS_GUARD_MAGIC) {
      handle = impl->handle;
      allocator.deallocate(impl, allocator.state);
    } else {
      handle = (const struct HddsGuardCondition *)guard_condition->data;
    }
  }

  if (handle != NULL) {
    hdds_guard_condition_release(handle);
  }

  allocator.deallocate(guard_condition, allocator.state);
  return RMW_RET_OK;
}

rmw_ret_t
rmw_trigger_guard_condition(const rmw_guard_condition_t * guard_condition)
{
  RMW_CHECK_ARGUMENT_FOR_NULL(guard_condition, RMW_RET_INVALID_ARGUMENT);

  if (guard_condition->implementation_identifier != rmw_get_implementation_identifier()) {
    RMW_SET_ERROR_MSG("rmw_trigger_guard_condition identifier mismatch");
    return RMW_RET_INCORRECT_RMW_IMPLEMENTATION;
  }

  const struct HddsGuardCondition * handle = guard_handle_from_data(guard_condition);
  if (handle == NULL) {
    RMW_SET_ERROR_MSG("guard condition missing native handle");
    return RMW_RET_ERROR;
  }

  hdds_guard_condition_set_trigger(handle, true);
  return RMW_RET_OK;
}
