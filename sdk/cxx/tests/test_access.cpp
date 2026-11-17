// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * @file test_access.cpp
 * @brief HDDS C++ SDK: Subscriber access brackets
 *
 * The access brackets of a Subscriber (DDS v1.4 Sec.2.2.2.5.2.8): the RAII
 * guard and begin_access/end_access, nested; end_access() without
 * begin_access() throws. The C++ QoS carries no PRESENTATION: a C++
 * Subscriber is of the default access scope, where a bracket has no effect
 * and its readers read inside and outside one.
 *
 * Build (from the repository root, after `cargo build -p hdds-c --release`):
 *   g++ -std=c++17 -Wall -Wextra -o test_access_cpp sdk/cxx/tests/test_access.cpp \
 *       sdk/cxx/src/{participant,writer,reader,qos,waitset,logging,telemetry,pubsub}.cpp \
 *       -Isdk/cxx/include -Isdk/c/include \
 *       -Ltarget/release -lhdds_c -lpthread -ldl -lm
 *   LD_LIBRARY_PATH=target/release ./test_access_cpp
 */

#include <hdds.hpp>

#include <cstdio>
#include <cstdlib>
#include <stdexcept>
#include <utility>

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

bool end_access_throws(hdds::Subscriber& subscriber) {
    try {
        subscriber.end_access();
    } catch (const hdds::Error&) {
        return true;
    }
    return false;
}

void test_brackets_nest_and_hold_nothing_outside_group_scope() {
    hdds::Participant participant("cxx_access", hdds::TransportMode::IntraProcess);
    auto subscriber = participant.create_subscriber();
    auto reader = subscriber->create_reader_raw("cxx_access_topic");
    CHECK(!reader->take_raw().has_value());
    {
        auto bracket = subscriber->access();
        CHECK(!reader->take_raw().has_value());
        {
            auto nested = subscriber->access();
            CHECK(!reader->take_raw().has_value());
        }
        CHECK(!reader->take_raw().has_value());
    }
    // The guards closed both brackets.
    CHECK(end_access_throws(*subscriber));
    subscriber->begin_access();
    subscriber->end_access();
    CHECK(end_access_throws(*subscriber));
}

/// An exception thrown inside a guarded bracket closes it as it unwinds;
/// a moved guard closes its bracket once.
void test_the_guard_closes_on_exception_and_once_when_moved() {
    hdds::Participant participant("cxx_access_exc", hdds::TransportMode::IntraProcess);
    auto subscriber = participant.create_subscriber();
    try {
        auto bracket = subscriber->access();
        throw std::runtime_error("an application error inside the bracket");
    } catch (const std::runtime_error&) {
    }
    CHECK(end_access_throws(*subscriber));
    {
        auto first = subscriber->access();
        auto second = std::move(first);
    }
    CHECK(end_access_throws(*subscriber));
}

}  // namespace

int main() {
    std::printf("HDDS C++ SDK: access brackets\n");
    RUN_TEST(test_brackets_nest_and_hold_nothing_outside_group_scope);
    RUN_TEST(test_the_guard_closes_on_exception_and_once_when_moved);
    std::printf("%d passed\n", passed);
    return 0;
}
