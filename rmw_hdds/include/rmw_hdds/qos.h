// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

#ifndef RMW_HDDS__QOS_H_
#define RMW_HDDS__QOS_H_

#include <rmw/qos_profiles.h>
#include <rmw/types.h>

#include "hdds.h"  // NOLINT(build/include_subdir)

#ifdef __cplusplus
extern "C" {
#endif

struct HddsQoS* rmw_hdds_qos_from_profile(const rmw_qos_profile_t* profile);

void rmw_hdds_qos_destroy(struct HddsQoS* qos);

#ifdef __cplusplus
}
#endif

#endif  // RMW_HDDS__QOS_H_
