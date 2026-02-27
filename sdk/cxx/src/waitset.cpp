// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * @file waitset.cpp
 * @brief HDDS C++ WaitSet and GuardCondition implementation
 */

#include <hdds.hpp>

extern "C" {
#include <hdds.h>
}

namespace hdds {

// =============================================================================
// GuardCondition
// =============================================================================

GuardCondition::GuardCondition() {
    // Cast away const - we need a mutable handle for operations
    handle_ = const_cast<HddsGuardCondition*>(hdds_guard_condition_create());
    if (!handle_) {
        throw Error("Failed to create guard condition");
    }
}

GuardCondition::~GuardCondition() {
    if (handle_) {
        hdds_guard_condition_release(handle_);
        handle_ = nullptr;
    }
}

GuardCondition::GuardCondition(GuardCondition&& other) noexcept
    : handle_(other.handle_) {
    other.handle_ = nullptr;
}

GuardCondition& GuardCondition::operator=(GuardCondition&& other) noexcept {
    if (this != &other) {
        if (handle_) {
            hdds_guard_condition_release(handle_);
        }
        handle_ = other.handle_;
        other.handle_ = nullptr;
    }
    return *this;
}

void GuardCondition::trigger() {
    if (!handle_) {
        throw Error("Guard condition has been destroyed");
    }
    hdds_guard_condition_set_trigger(handle_, true);
}

// =============================================================================
// WaitSet
// =============================================================================

WaitSet::WaitSet() {
    handle_ = hdds_waitset_create();
    if (!handle_) {
        throw Error("Failed to create waitset");
    }
}

WaitSet::~WaitSet() {
    if (handle_) {
        hdds_waitset_destroy(handle_);
        handle_ = nullptr;
    }
}

WaitSet::WaitSet(WaitSet&& other) noexcept
    : handle_(other.handle_) {
    other.handle_ = nullptr;
}

WaitSet& WaitSet::operator=(WaitSet&& other) noexcept {
    if (this != &other) {
        if (handle_) {
            hdds_waitset_destroy(handle_);
        }
        handle_ = other.handle_;
        other.handle_ = nullptr;
    }
    return *this;
}

void WaitSet::attach(HddsStatusCondition* cond) {
    if (!handle_) {
        throw Error("WaitSet has been destroyed");
    }
    HddsError err = hdds_waitset_attach_status_condition(handle_, cond);
    if (err != HDDS_OK) {
        throw Error("Failed to attach status condition");
    }
}

void WaitSet::attach(GuardCondition& cond) {
    if (!handle_) {
        throw Error("WaitSet has been destroyed");
    }
    HddsError err = hdds_waitset_attach_guard_condition(handle_, cond.c_handle());
    if (err != HDDS_OK) {
        throw Error("Failed to attach guard condition");
    }
}

void WaitSet::detach(HddsStatusCondition* cond) {
    if (!handle_) {
        throw Error("WaitSet has been destroyed");
    }
    hdds_waitset_detach_condition(handle_, cond);
}

void WaitSet::detach(GuardCondition& cond) {
    if (!handle_) {
        throw Error("WaitSet has been destroyed");
    }
    hdds_waitset_detach_condition(handle_, cond.c_handle());
}

bool WaitSet::wait_impl(int64_t timeout_ns) {
    if (!handle_) {
        throw Error("WaitSet has been destroyed");
    }

    // Simple wait - we don't need the triggered conditions array for basic usage
    const void* triggered_conditions[16];
    size_t num_triggered = 0;

    HddsError err = hdds_waitset_wait(handle_, timeout_ns, triggered_conditions, 16, &num_triggered);

    if (err == HDDS_OK) {
        return num_triggered > 0;
    } else if (err == HDDS_NOT_FOUND) {
        return false;  // Timeout
    } else {
        throw Error("Wait failed with error: " + std::to_string(err));
    }
}

} // namespace hdds
