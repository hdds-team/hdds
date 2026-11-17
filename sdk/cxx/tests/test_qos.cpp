// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * @file test_qos.cpp
 * @brief HDDS C++ SDK: QoS tests
 *
 * Tests:
 *   - max_blocking_time() reaches the underlying C QoS handle (set then get,
 *     through the raw C API, since the C++ wrapper does not expose a getter
 *     for it, same as deadline()/lifespan())
 *   - A QoS left at its default reaches the C handle at the DDS v1.4
 *     Sec.2.2.3.14 default of 100ms
 *   - A RELIABLE writer created with a custom max_blocking_time() blocks
 *     for approximately that long, not the 100ms default, once a matched
 *     RELIABLE KEEP_ALL reader's resource limits are full and it never
 *     calls take()
 *
 * Build (from the repository root, after `cargo build -p hdds-c --release`):
 *   g++ -std=c++17 -Wall -Wextra -o test_qos_cpp sdk/cxx/tests/test_qos.cpp \
 *       sdk/cxx/src/{participant,writer,reader,qos,waitset,logging,telemetry,pubsub}.cpp \
 *       -Isdk/cxx/include -Isdk/c/include \
 *       -Ltarget/release -lhdds_c -lpthread -ldl -lm
 *   LD_LIBRARY_PATH=target/release ./test_qos_cpp
 */

#include <hdds.hpp>

extern "C" {
#include <hdds.h>
}

#include <chrono>
#include <cstdio>
#include <cstdlib>

namespace {

int passed = 0;

#define CHECK(cond)                                                              \
    do {                                                                         \
        if (!(cond)) {                                                           \
            std::fprintf(stderr, "\n%s:%d: CHECK failed: %s\n", __FILE__,        \
                         __LINE__, #cond);                                       \
            std::exit(1);                                                        \
        }                                                                        \
    } while (0)

#define RUN_TEST(fn)                                                             \
    do {                                                                         \
        std::printf("  %-58s", #fn);                                             \
        std::fflush(stdout);                                                     \
        fn();                                                                    \
        std::printf("[PASS]\n");                                                 \
        passed++;                                                                \
    } while (0)

void test_default_max_blocking_time_is_100ms() {
    auto qos = hdds::QoS::reliable();
    CHECK(hdds_qos_get_max_blocking_time_ns(qos.c_handle()) == 100'000'000ULL);
}

void test_max_blocking_time_reaches_the_c_handle() {
    auto qos = hdds::QoS::reliable().max_blocking_time(std::chrono::milliseconds(300));
    CHECK(hdds_qos_get_max_blocking_time_ns(qos.c_handle()) == 300'000'000ULL);
}

// A full RELIABLE KEEP_ALL reader that never calls take() makes the matched
// writer's write() block for its QoS max_blocking_time (DDS v1.4
// Sec.2.2.3.14), then fail. IntraProcess transport plus a shared topic name
// auto-binds reader and writer through the domain registry, with no
// discovery delay.
void test_writer_blocks_for_its_qos_max_blocking_time() {
    hdds::Participant p("cxx_qos_max_blocking_time", hdds::TransportMode::IntraProcess);

    auto reader_qos = hdds::QoS::reliable().history_keep_all().resource_limits(1, 1, 1);
    auto reader = p.create_reader_raw("cxx_qos_max_blocking_time_topic", reader_qos);

    const auto configured = std::chrono::milliseconds(300);
    auto writer_qos = hdds::QoS::reliable().history_keep_all().resource_limits(1, 1, 1)
                           .max_blocking_time(configured);
    auto writer = p.create_writer_raw("cxx_qos_max_blocking_time_topic", writer_qos);

    // Fills the reader's one slot of room; the reader never takes it.
    writer->write_raw(reinterpret_cast<const uint8_t*>("first"), 5);

    auto start = std::chrono::steady_clock::now();
    bool refused = false;
    try {
        writer->write_raw(reinterpret_cast<const uint8_t*>("second"), 6);
    } catch (const hdds::Error&) {
        refused = true;
    }
    auto waited = std::chrono::steady_clock::now() - start;
    auto waited_ms = std::chrono::duration_cast<std::chrono::milliseconds>(waited);

    CHECK(refused);
    // A tight band around the configured 300ms proves the QoS value was
    // actually used, not the DDS default of 100ms.
    CHECK(waited_ms >= std::chrono::milliseconds(250));
    CHECK(waited_ms < std::chrono::milliseconds(600));

    (void)reader;
}

} // namespace

int main() {
    std::printf("HDDS C++ SDK: QoS tests\n");
    std::printf("========================\n");

    RUN_TEST(test_default_max_blocking_time_is_100ms);
    RUN_TEST(test_max_blocking_time_reaches_the_c_handle);
    RUN_TEST(test_writer_blocks_for_its_qos_max_blocking_time);

    std::printf("\n%d tests passed\n", passed);
    return 0;
}
