// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

#include "rmw_hdds/qos.h"

#include <stdint.h>
#include <rmw/time.h>
#include <rcutils/logging_macros.h>

static uint32_t clamp_depth(size_t depth) {
    if (depth == 0u) {
        return 0u;
    }
    if (depth > UINT32_MAX) {
        return UINT32_MAX;
    }
    return (uint32_t)depth;
}

static bool rmw_time_is_unspecified(rmw_time_t time) {
    return time.sec == 0u && time.nsec == 0u;
}

static bool rmw_time_is_infinite(rmw_time_t time) {
    rmw_time_t infinite = RMW_DURATION_INFINITE;
    return time.sec == infinite.sec && time.nsec == infinite.nsec;
}

static uint64_t rmw_time_to_ns(rmw_time_t time) {
    if (rmw_time_is_unspecified(time)) {
        return 0u;
    }
    if (rmw_time_is_infinite(time)) {
        return UINT64_MAX;
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

struct HddsQoS* rmw_hdds_qos_from_profile(const rmw_qos_profile_t* profile) {
    struct HddsQoS* qos = hdds_qos_default();
    if (qos == NULL) {
        return NULL;
    }
    if (profile == NULL) {
        return qos;
    }

    switch (profile->reliability) {
        case RMW_QOS_POLICY_RELIABILITY_RELIABLE:
            (void)hdds_qos_set_reliable(qos);
            break;
        case RMW_QOS_POLICY_RELIABILITY_BEST_EFFORT:
            (void)hdds_qos_set_best_effort(qos);
            break;
        case RMW_QOS_POLICY_RELIABILITY_SYSTEM_DEFAULT:
        default:
            break;
    }

    switch (profile->durability) {
        case RMW_QOS_POLICY_DURABILITY_TRANSIENT_LOCAL:
            (void)hdds_qos_set_transient_local(qos);
            break;
        case RMW_QOS_POLICY_DURABILITY_VOLATILE:
            (void)hdds_qos_set_volatile(qos);
            break;
#if defined(RMW_QOS_POLICY_DURABILITY_TRANSIENT) || defined(RMW_QOS_POLICY_DURABILITY_PERSISTENT)
#if defined(RMW_QOS_POLICY_DURABILITY_TRANSIENT)
        case RMW_QOS_POLICY_DURABILITY_TRANSIENT:
#endif
#if defined(RMW_QOS_POLICY_DURABILITY_PERSISTENT)
        case RMW_QOS_POLICY_DURABILITY_PERSISTENT:
#endif
            (void)hdds_qos_set_persistent(qos);
            break;
#endif
        case RMW_QOS_POLICY_DURABILITY_SYSTEM_DEFAULT:
        default:
            break;
    }

    switch (profile->history) {
        case RMW_QOS_POLICY_HISTORY_KEEP_LAST: {
            uint32_t depth = clamp_depth(profile->depth);
            if (depth > 0u) {
                (void)hdds_qos_set_history_depth(qos, depth);
            } else {
                RCUTILS_LOG_WARN_NAMED(
                    "rmw_hdds",
                    "History KEEP_LAST with depth=0; keeping default history");
            }
            break;
        }
        case RMW_QOS_POLICY_HISTORY_KEEP_ALL:
            (void)hdds_qos_set_history_keep_all(qos);
            break;
        case RMW_QOS_POLICY_HISTORY_SYSTEM_DEFAULT:
        default:
            break;
    }

    uint64_t deadline_ns = rmw_time_to_ns(profile->deadline);
    if (deadline_ns != 0u && deadline_ns != UINT64_MAX) {
        (void)hdds_qos_set_deadline_ns(qos, deadline_ns);
    }

    uint64_t lifespan_ns = rmw_time_to_ns(profile->lifespan);
    if (lifespan_ns != 0u && lifespan_ns != UINT64_MAX) {
        (void)hdds_qos_set_lifespan_ns(qos, lifespan_ns);
    }

    uint64_t lease_ns = rmw_time_to_ns(profile->liveliness_lease_duration);
    if (lease_ns == 0u || lease_ns == UINT64_MAX) {
        lease_ns = UINT64_MAX;
    }

    switch (profile->liveliness) {
        case RMW_QOS_POLICY_LIVELINESS_AUTOMATIC:
            (void)hdds_qos_set_liveliness_automatic_ns(qos, lease_ns);
            break;
#if defined(RMW_QOS_POLICY_LIVELINESS_MANUAL_BY_NODE)
        case RMW_QOS_POLICY_LIVELINESS_MANUAL_BY_NODE:
            (void)hdds_qos_set_liveliness_manual_participant_ns(qos, lease_ns);
            break;
#endif
        case RMW_QOS_POLICY_LIVELINESS_MANUAL_BY_TOPIC:
            (void)hdds_qos_set_liveliness_manual_topic_ns(qos, lease_ns);
            break;
        case RMW_QOS_POLICY_LIVELINESS_SYSTEM_DEFAULT:
        case RMW_QOS_POLICY_LIVELINESS_UNKNOWN:
        default:
            break;
    }

    return qos;
}

void rmw_hdds_qos_destroy(struct HddsQoS* qos) {
    if (qos != NULL) {
        hdds_qos_destroy(qos);
    }
}
