// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * @file logging.cpp
 * @brief HDDS C++ Logging implementation
 */

#include <hdds.hpp>

extern "C" {
#include <hdds.h>
}

namespace hdds {
namespace logging {

void init(LogLevel level) {
    HddsError err = hdds_logging_init(static_cast<HddsLogLevel>(level));
    if (err != HDDS_OK) {
        throw Error("Failed to initialize logging (already initialized?)");
    }
}

void init_env(LogLevel default_level) {
    HddsError err = hdds_logging_init_env(static_cast<HddsLogLevel>(default_level));
    if (err != HDDS_OK) {
        throw Error("Failed to initialize logging");
    }
}

void init_filter(const std::string& filter) {
    HddsError err = hdds_logging_init_with_filter(filter.c_str());
    if (err != HDDS_OK) {
        throw Error("Failed to initialize logging with filter");
    }
}

} // namespace logging
} // namespace hdds
