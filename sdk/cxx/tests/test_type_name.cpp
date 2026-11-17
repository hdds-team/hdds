// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * @file test_type_name.cpp
 * @brief HDDS C++ SDK: a typed endpoint announces its type's own name
 *
 * DDS-XTypes 1.3 Sec.7.6.3.4.2 Step 2: with no TypeObject the type names of
 * a writer and a reader must be equal. A type hddsgen generated says its
 * qualified IDL name (`static constexpr const char* hdds_type_name`);
 * create_writer<T>() / create_reader<T>() announce it, and never adopt the
 * name a peer announces (only a genuinely raw create_*_raw does). A type
 * without it (older hddsgen) announces the placeholder "RawBytes"
 * explicitly. The announced name is the intra-process match key too, so
 * delivery tells which name an endpoint announced.
 *
 * Build (from the repository root, after `cargo build -p hdds-c --release`):
 *   g++ -std=c++17 -Wall -Wextra -o test_type_name_cpp sdk/cxx/tests/test_type_name.cpp \
 *       sdk/cxx/src/{participant,writer,reader,qos,waitset,logging,telemetry,pubsub}.cpp \
 *       -Isdk/cxx/include -Isdk/c/include \
 *       -Ltarget/release -lhdds_c -lpthread -ldl -lm
 *   LD_LIBRARY_PATH=target/release ./test_type_name_cpp
 */

#include <hdds.hpp>

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <optional>
#include <thread>

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
        std::printf("  %-64s", #fn);                                             \
        std::fflush(stdout);                                                     \
        fn();                                                                    \
        std::printf("[PASS]\n");                                                 \
        passed++;                                                                \
    } while (0)

/// The shape of an hddsgen type: a codec, its extensibility and its
/// qualified IDL name.
struct Named {
    static constexpr std::uint32_t hdds_extensibility = 0;
    static constexpr const char* hdds_type_name = "Mod::Named";
    std::int32_t v = 0;
    int encode_cdr2_le(std::uint8_t* dst, std::size_t len) const noexcept {
        if (len < 4) return -1;
        std::memcpy(dst, &v, 4);
        return 4;
    }
    int decode_cdr2_le(const std::uint8_t* src, std::size_t len) noexcept {
        if (len < 4) return -1;
        std::memcpy(&v, src, 4);
        return 4;
    }
};

/// Another type, another name.
struct Other : Named {
    static constexpr const char* hdds_type_name = "Mod::Other";
};

/// A type of an older hddsgen: no name.
struct Unnamed {
    std::int32_t v = 0;
    int encode_cdr2_le(std::uint8_t* dst, std::size_t len) const noexcept {
        if (len < 4) return -1;
        std::memcpy(dst, &v, 4);
        return 4;
    }
    int decode_cdr2_le(const std::uint8_t* src, std::size_t len) noexcept {
        if (len < 4) return -1;
        std::memcpy(&v, src, 4);
        return 4;
    }
};

/// A type that says no name: it must announce the placeholder, never reach
/// the C ABI with a NULL or empty name (which adopts a peer's).
struct NullName : Named {
    static constexpr const char* hdds_type_name = nullptr;
};
struct EmptyName : Named {
    static constexpr const char* hdds_type_name = "";
};

static_assert(hdds::detail::has_hdds_type_name<Named>::value, "named");
static_assert(hdds::detail::has_hdds_type_name<Other>::value, "other");
static_assert(!hdds::detail::has_hdds_type_name<Unnamed>::value, "unnamed");

void the_detector_reads_the_generated_name() {
    CHECK(std::strcmp(hdds::detail::type_name_of<Named>(), "Mod::Named") == 0);
    CHECK(std::strcmp(hdds::detail::type_name_of<Other>(), "Mod::Other") == 0);
    // A type of an older hddsgen keeps the placeholder, explicitly.
    CHECK(std::strcmp(hdds::detail::type_name_of<Unnamed>(), "RawBytes") == 0);
    // An empty or null declared name is no name.
    CHECK(std::strcmp(hdds::detail::type_name_of<NullName>(), "RawBytes") == 0);
    CHECK(std::strcmp(hdds::detail::type_name_of<EmptyName>(), "RawBytes") == 0);
}

/// The sample `reader` receives within a short delay, if any.
template<typename Reader, typename V = decltype(std::declval<Reader&>().take())>
V receive(Reader& reader, bool expect) {
    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::milliseconds(expect ? 2000 : 150);
    for (;;) {
        auto sample = reader.take();
        if (sample || std::chrono::steady_clock::now() >= deadline) return sample;
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
}

template<typename W, typename S>
void send(W& writer, S sample) {
    sample.v = 7;
    writer.write(sample);
}

void same_type_writer_and_reader_match() {
    hdds::Participant p("cxx_tn_same", hdds::TransportMode::IntraProcess);
    auto writer = p.create_writer<Named>("cxx_tn_same");
    auto reader = p.create_reader<Named>("cxx_tn_same");
    send(writer, Named{});
    auto got = receive(reader, true);
    CHECK(got.has_value() && got->v == 7);
}

void a_typed_reader_never_adopts_a_peers_name() {
    hdds::Participant p("cxx_tn_foreign", hdds::TransportMode::IntraProcess);
    auto writer = p.create_writer<Named>("cxx_tn_foreign");
    auto other = p.create_reader<Other>("cxx_tn_foreign");
    auto unnamed = p.create_reader<Unnamed>("cxx_tn_foreign");
    send(writer, Named{});
    CHECK(!receive(other, false).has_value());
    CHECK(!receive(unnamed, false).has_value());
}

void a_typed_writer_never_adopts_a_peers_name() {
    hdds::Participant p("cxx_tn_foreign_w", hdds::TransportMode::IntraProcess);
    auto reader = p.create_reader<Named>("cxx_tn_foreign_w");
    auto other = p.create_writer<Other>("cxx_tn_foreign_w");
    auto unnamed = p.create_writer<Unnamed>("cxx_tn_foreign_w");
    send(other, Other{});
    send(unnamed, Unnamed{});
    CHECK(!receive(reader, false).has_value());
}

void a_type_that_says_no_name_never_adopts() {
    hdds::Participant p("cxx_tn_noname", hdds::TransportMode::IntraProcess);
    auto writer = p.create_writer<Named>("cxx_tn_noname");
    auto empty = p.create_reader<EmptyName>("cxx_tn_noname");
    auto null_name = p.create_reader<NullName>("cxx_tn_noname");
    send(writer, Named{});
    CHECK(!receive(empty, false).has_value());
    CHECK(!receive(null_name, false).has_value());
    // Publisher and Subscriber entries as well.
    auto publisher = p.create_publisher();
    auto subscriber = p.create_subscriber();
    auto pub_writer = publisher->create_writer<Named>("cxx_tn_noname_ps");
    auto sub_empty = subscriber->create_reader<EmptyName>("cxx_tn_noname_ps");
    auto sub_null = subscriber->create_reader<NullName>("cxx_tn_noname_ps");
    auto sub_ok = subscriber->create_reader<Named>("cxx_tn_noname_ps");
    send(pub_writer, Named{});
    CHECK(receive(sub_ok, true).has_value());
    CHECK(!receive(sub_empty, false).has_value());
    CHECK(!receive(sub_null, false).has_value());
    // A nameless writer of such a type does not feed a named reader either.
    auto reader = p.create_reader<Named>("cxx_tn_noname_w");
    auto empty_writer = p.create_writer<EmptyName>("cxx_tn_noname_w");
    auto pub_empty_writer = publisher->create_writer<NullName>("cxx_tn_noname_w");
    send(empty_writer, EmptyName{});
    send(pub_empty_writer, NullName{});
    CHECK(!receive(reader, false).has_value());
}

void a_genuinely_raw_endpoint_adopts_the_name() {
    hdds::Participant p("cxx_tn_raw", hdds::TransportMode::IntraProcess);
    auto writer = p.create_writer<Named>("cxx_tn_raw");
    hdds::TypedDataReader<Named> raw(p.create_reader_raw("cxx_tn_raw"));
    send(writer, Named{});
    auto got = receive(raw, true);
    CHECK(got.has_value() && got->v == 7);
}

void unnamed_types_keep_the_placeholder_and_meet_each_other() {
    hdds::Participant p("cxx_tn_old", hdds::TransportMode::IntraProcess);
    auto writer = p.create_writer<Unnamed>("cxx_tn_old");
    auto reader = p.create_reader<Unnamed>("cxx_tn_old");
    send(writer, Unnamed{});
    auto got = receive(reader, true);
    CHECK(got.has_value() && got->v == 7);
}

void publisher_and_subscriber_endpoints_announce_their_own_name() {
    hdds::Participant p("cxx_tn_pubsub", hdds::TransportMode::IntraProcess);
    auto publisher = p.create_publisher();
    auto subscriber = p.create_subscriber();
    auto writer = publisher->create_writer<Named>("cxx_tn_pubsub");
    auto same = subscriber->create_reader<Named>("cxx_tn_pubsub");
    auto other = subscriber->create_reader<Other>("cxx_tn_pubsub");
    auto qos_other = subscriber->create_reader<Other>("cxx_tn_pubsub", hdds::QoS::reliable());
    send(writer, Named{});
    auto got = receive(same, true);
    CHECK(got.has_value() && got->v == 7);
    CHECK(!receive(other, false).has_value());
    CHECK(!receive(qos_other, false).has_value());
}

}  // namespace

int main() {
    std::printf("HDDS C++ SDK: typed endpoints announce their type's name\n");
    RUN_TEST(the_detector_reads_the_generated_name);
    RUN_TEST(same_type_writer_and_reader_match);
    RUN_TEST(a_typed_reader_never_adopts_a_peers_name);
    RUN_TEST(a_typed_writer_never_adopts_a_peers_name);
    RUN_TEST(a_type_that_says_no_name_never_adopts);
    RUN_TEST(a_genuinely_raw_endpoint_adopts_the_name);
    RUN_TEST(unnamed_types_keep_the_placeholder_and_meet_each_other);
    RUN_TEST(publisher_and_subscriber_endpoints_announce_their_own_name);
    std::printf("%d passed\n", passed);
    return 0;
}
