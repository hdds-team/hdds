// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * @file test_listener.cpp
 * @brief HDDS C++ SDK: listener tests
 *
 * Tests:
 *   - std::function callbacks: on_data_available with the written bytes, on
 *     the writer's thread for a reader of the same participant
 *   - A shared_ptr<ReaderListener> (virtual interface) owned by the reader
 *   - An exception thrown by a callback is caught at the C boundary and
 *     reported; later callbacks still fire
 *   - A callback that clears its own listener finishes on live captures
 *   - Destroying the reader while a callback runs on another thread waits
 *   - Concurrent set_listener calls on one reader, racing a writer, never
 *     free the callbacks that end up installed (run under ASan)
 *   - Matched statuses between two UDP participants, and data over the
 *     network on an HDDS thread
 *
 * Build (from the repository root, after `cargo build -p hdds-c --release`):
 *   g++ -std=c++17 -Wall -Wextra -o test_listener_cpp sdk/cxx/tests/test_listener.cpp \
 *       sdk/cxx/src/{participant,writer,reader,qos,waitset,logging,telemetry,pubsub}.cpp \
 *       -Isdk/cxx/include -Isdk/c/include \
 *       -Ltarget/release -lhdds_c -lpthread -ldl -lm
 *   LD_LIBRARY_PATH=target/release ./test_listener_cpp
 */

#include <hdds.hpp>
#include <hdds_listener.hpp>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

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

template<typename F>
bool wait_until(F done, int timeout_ms) {
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    while (std::chrono::steady_clock::now() < deadline) {
        if (done()) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    return done();
}

hdds::QoS keep_last() { return hdds::QoS::reliable().history_depth(64); }

void write_str(hdds::DataWriter& w, const std::string& s) {
    w.write_raw(reinterpret_cast<const uint8_t*>(s.data()), s.size());
}

void test_function_callbacks_intra_process() {
    hdds::Participant p("cxx_listener_intra", hdds::TransportMode::IntraProcess);
    auto reader = p.create_reader_raw("cxx_listener_intra", keep_last());
    auto writer = p.create_writer_raw("cxx_listener_intra", keep_last());

    std::vector<std::string> got;
    bool on_writer_thread = true;
    const auto me = std::this_thread::get_id();
    hdds::ReaderCallbacks cb;
    cb.on_data_available = [&](const uint8_t* data, size_t len) {
        got.emplace_back(reinterpret_cast<const char*>(data), len);
        if (std::this_thread::get_id() != me) on_writer_thread = false;
    };
    hdds::set_listener(*reader, std::move(cb));

    write_str(*writer, "a");
    write_str(*writer, "bc");
    // Same participant: delivered inside write().
    CHECK(got.size() == 2);
    CHECK(got[0] == "a" && got[1] == "bc");
    CHECK(on_writer_thread);

    hdds::clear_listener(*reader);
    write_str(*writer, "after");
    CHECK(got.size() == 2);
    int taken = 0;
    while (reader->take_raw()) taken++;
    CHECK(taken == 3);
}

struct CountingListener : hdds::ReaderListener {
    std::atomic<int> data{0};
    void on_data_available(const uint8_t*, size_t) override { data++; }
};

void test_shared_virtual_listener() {
    hdds::Participant p("cxx_listener_virtual", hdds::TransportMode::IntraProcess);
    auto reader = p.create_reader_raw("cxx_listener_virtual", keep_last());
    auto writer = p.create_writer_raw("cxx_listener_virtual", keep_last());
    auto listener = std::make_shared<CountingListener>();
    std::weak_ptr<CountingListener> weak = listener;
    hdds::set_listener(*reader, listener);
    listener.reset();  // the reader keeps it alive
    write_str(*writer, "x");
    write_str(*writer, "y");
    CHECK(!weak.expired());
    CHECK(weak.lock()->data == 2);
    hdds::clear_listener(*reader);
    CHECK(weak.expired());  // released once cleared
}

std::atomic<int> g_reported{0};
std::string g_last_callback;
void record_exception(const char* callback, const char* what) {
    g_last_callback = callback;
    (void)what;
    g_reported++;
}

void test_exception_is_caught_at_the_boundary() {
    hdds::set_listener_exception_handler(&record_exception);
    hdds::Participant p("cxx_listener_throw", hdds::TransportMode::IntraProcess);
    auto reader = p.create_reader_raw("cxx_listener_throw", keep_last());
    auto writer = p.create_writer_raw("cxx_listener_throw", keep_last());
    int calls = 0;
    hdds::ReaderCallbacks cb;
    cb.on_data_available = [&](const uint8_t*, size_t) {
        calls++;
        throw std::runtime_error("listener failure (expected by this test)");
    };
    hdds::set_listener(*reader, std::move(cb));
    write_str(*writer, "1");  // must not throw out of write()
    write_str(*writer, "2");
    CHECK(calls == 2);
    CHECK(g_reported == 2);
    CHECK(g_last_callback == "on_data_available");
    hdds::set_listener_exception_handler(nullptr);
}

void test_clear_from_inside_own_callback() {
    hdds::Participant p("cxx_listener_self_clear", hdds::TransportMode::IntraProcess);
    auto reader = p.create_reader_raw("cxx_listener_self_clear", keep_last());
    auto writer = p.create_writer_raw("cxx_listener_self_clear", keep_last());
    auto token = std::make_shared<std::string>("still alive");
    int calls = 0;
    std::string seen_after_clear;
    hdds::DataReader& r = *reader;
    hdds::ReaderCallbacks cb;
    cb.on_data_available = [&calls, &seen_after_clear, &r, token](const uint8_t*, size_t) {
        calls++;
        hdds::clear_listener(r);
        // The callbacks object (and this lambda's captures) must still be
        // alive here: ASan reports a use-after-free otherwise.
        seen_after_clear = *token;
    };
    hdds::set_listener(r, std::move(cb));
    write_str(*writer, "a");
    write_str(*writer, "b");
    CHECK(calls == 1);
    CHECK(seen_after_clear == "still alive");
}

void test_destroy_waits_for_running_callback() {
    hdds::Participant p("cxx_listener_destroy", hdds::TransportMode::IntraProcess);
    auto reader = p.create_reader_raw("cxx_listener_destroy", keep_last());
    auto writer = p.create_writer_raw("cxx_listener_destroy", keep_last());
    std::atomic<bool> entered{false};
    std::atomic<bool> finished{false};
    hdds::ReaderCallbacks cb;
    cb.on_data_available = [&](const uint8_t*, size_t) {
        entered = true;
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
        finished = true;
    };
    hdds::set_listener(*reader, std::move(cb));
    std::thread t([&] { write_str(*writer, "slow"); });
    CHECK(wait_until([&] { return entered.load(); }, 2000));
    reader.reset();  // ~DataReader -> hdds_reader_destroy waits
    CHECK(finished.load());
    t.join();
}

void test_concurrent_set_listener() {
    hdds::Participant p("cxx_listener_concurrent", hdds::TransportMode::IntraProcess);
    auto reader = p.create_reader_raw("cxx_listener_concurrent", keep_last());
    auto writer = p.create_writer_raw("cxx_listener_concurrent", keep_last());
    std::atomic<bool> stop{false};
    std::atomic<long> calls{0};
    auto install_loop = [&](int salt) {
        for (int i = 0; i < 300; i++) {
            auto token = std::make_shared<int>(salt * 1000 + i);
            hdds::ReaderCallbacks cb;
            cb.on_data_available = [&calls, token](const uint8_t*, size_t) {
                // Touch the capture: a freed box is a use-after-free here.
                if (*token >= 0) calls++;
            };
            hdds::set_listener(*reader, std::move(cb));
        }
    };
    std::thread w([&] {
        while (!stop.load()) {
            write_str(*writer, "c");
            while (reader->take_raw()) {}
        }
    });
    std::thread a(install_loop, 1);
    std::thread b(install_loop, 2);
    a.join();
    b.join();
    // Whatever listener won, it is installed and alive: it must still fire.
    long before = calls.load();
    CHECK(wait_until([&] { return calls.load() > before; }, 5000));
    stop = true;
    w.join();
    hdds::clear_listener(*reader);
}

void test_matched_and_network_data() {
    hdds::Participant sub("cxx_listener_net_sub");
    hdds::Participant pub("cxx_listener_net_pub");
    auto reader = sub.create_reader_raw("cxx_listener_net", keep_last());

    std::mutex mu;
    hdds::SubscriptionMatchedStatus last_sub{};
    std::atomic<int> sub_calls{0};
    std::atomic<int> data{0};
    std::atomic<bool> data_on_other_thread{false};
    const auto me = std::this_thread::get_id();
    hdds::ReaderCallbacks rcb;
    rcb.on_subscription_matched = [&](const hdds::SubscriptionMatchedStatus& s) {
        std::lock_guard<std::mutex> g(mu);
        last_sub = s;
        sub_calls++;
    };
    rcb.on_data_available = [&](const uint8_t*, size_t) {
        if (std::this_thread::get_id() != me) data_on_other_thread = true;
        data++;
    };
    hdds::set_listener(*reader, std::move(rcb));

    auto writer = pub.create_writer_raw("cxx_listener_net", keep_last());
    std::atomic<int> written{0};
    hdds::PublicationMatchedStatus last_pub{};
    std::atomic<int> pub_calls{0};
    hdds::WriterCallbacks wcb;
    wcb.on_sample_written = [&](const uint8_t*, size_t, uint64_t) { written++; };
    wcb.on_publication_matched = [&](const hdds::PublicationMatchedStatus& s) {
        std::lock_guard<std::mutex> g(mu);
        last_pub = s;
        pub_calls++;
    };
    hdds::set_listener(*writer, std::move(wcb));

    CHECK(wait_until([&] { return sub_calls.load() >= 1; }, 10000));
    {
        std::lock_guard<std::mutex> g(mu);
        CHECK(last_sub.total_count == 1);
        CHECK(last_sub.total_count_change == 1);
        CHECK(last_sub.current_count == 1);
        CHECK(last_sub.current_count_change == 1);
    }
    for (int i = 0; i < 5; i++) write_str(*writer, "net-" + std::to_string(i));
    CHECK(written == 5);
    CHECK(wait_until([&] { return data.load() >= 5; }, 10000));
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    CHECK(data == 5);
    CHECK(data_on_other_thread.load());

    int before = pub_calls.load();
    auto reader2 = sub.create_reader_raw("cxx_listener_net", keep_last());
    CHECK(wait_until([&] { return pub_calls.load() > before; }, 10000));
    {
        std::lock_guard<std::mutex> g(mu);
        CHECK(last_pub.current_count == 2);
        CHECK(last_pub.current_count_change == 1);
    }
}

} // namespace

int main() {
    std::printf("=== HDDS C++ SDK: Listener Tests ===\n\n");
    RUN_TEST(test_function_callbacks_intra_process);
    RUN_TEST(test_shared_virtual_listener);
    RUN_TEST(test_exception_is_caught_at_the_boundary);
    RUN_TEST(test_clear_from_inside_own_callback);
    RUN_TEST(test_destroy_waits_for_running_callback);
    RUN_TEST(test_concurrent_set_listener);
    RUN_TEST(test_matched_and_network_data);
    std::printf("\n%d tests passed\n", passed);
    return 0;
}
