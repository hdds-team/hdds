// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * @file telemetry.cpp
 * @brief HDDS C++ Telemetry implementation
 */

#include <hdds.hpp>

extern "C" {
#include <hdds.h>
}

namespace hdds {

// =============================================================================
// Metrics
// =============================================================================

Metrics::Metrics(HddsMetrics* handle) : handle_(handle) {}

Metrics::~Metrics() {
    if (handle_) {
        hdds_telemetry_release(handle_);
        handle_ = nullptr;
    }
}

Metrics::Metrics(Metrics&& other) noexcept : handle_(other.handle_) {
    other.handle_ = nullptr;
}

Metrics& Metrics::operator=(Metrics&& other) noexcept {
    if (this != &other) {
        if (handle_) {
            hdds_telemetry_release(handle_);
        }
        handle_ = other.handle_;
        other.handle_ = nullptr;
    }
    return *this;
}

MetricsSnapshot Metrics::snapshot() {
    if (!handle_) {
        throw Error("Metrics handle is null");
    }

    HddsMetricsSnapshot raw{};
    HddsError err = hdds_telemetry_snapshot(handle_, &raw);
    if (err != HDDS_OK) {
        throw Error("Failed to take metrics snapshot");
    }

    MetricsSnapshot result;
    result.timestamp_ns = raw.TIMESTAMP_NS;
    result.messages_sent = raw.MESSAGES_SENT;
    result.messages_received = raw.MESSAGES_RECEIVED;
    result.messages_dropped = raw.MESSAGES_DROPPED;
    result.bytes_sent = raw.BYTES_SENT;
    result.latency_p50_ns = raw.LATENCY_P50_NS;
    result.latency_p99_ns = raw.LATENCY_P99_NS;
    result.latency_p999_ns = raw.LATENCY_P999_NS;
    result.merge_full_count = raw.MERGE_FULL_COUNT;
    result.would_block_count = raw.WOULD_BLOCK_COUNT;
    return result;
}

void Metrics::record_latency(uint64_t start_ns, uint64_t end_ns) {
    if (handle_) {
        hdds_telemetry_record_latency(handle_, start_ns, end_ns);
    }
}

// =============================================================================
// TelemetryExporter
// =============================================================================

TelemetryExporter::TelemetryExporter(HddsTelemetryExporter* handle) : handle_(handle) {}

TelemetryExporter::~TelemetryExporter() {
    stop();
}

TelemetryExporter::TelemetryExporter(TelemetryExporter&& other) noexcept
    : handle_(other.handle_) {
    other.handle_ = nullptr;
}

TelemetryExporter& TelemetryExporter::operator=(TelemetryExporter&& other) noexcept {
    if (this != &other) {
        stop();
        handle_ = other.handle_;
        other.handle_ = nullptr;
    }
    return *this;
}

void TelemetryExporter::stop() {
    if (handle_) {
        hdds_telemetry_stop_exporter(handle_);
        handle_ = nullptr;
    }
}

// =============================================================================
// Namespace functions
// =============================================================================

namespace telemetry {

Metrics init() {
    HddsMetrics* handle = hdds_telemetry_init();
    if (!handle) {
        throw Error("Failed to initialize telemetry");
    }
    return Metrics(handle);
}

Metrics get() {
    HddsMetrics* handle = hdds_telemetry_get();
    if (!handle) {
        throw Error("Telemetry not initialized (call telemetry::init() first)");
    }
    return Metrics(handle);
}

TelemetryExporter start_exporter(const std::string& bind_addr, uint16_t port) {
    HddsTelemetryExporter* handle = hdds_telemetry_start_exporter(bind_addr.c_str(), port);
    if (!handle) {
        throw Error("Failed to start telemetry exporter on " + bind_addr + ":" + std::to_string(port));
    }
    return TelemetryExporter(handle);
}

} // namespace telemetry
} // namespace hdds
