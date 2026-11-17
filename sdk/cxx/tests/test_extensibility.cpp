// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * @file test_extensibility.cpp
 * @brief HDDS C++ SDK: a typed writer labels its samples with the type's
 * extensibility
 *
 * DDS-XTypes 1.3 7.6.3.1.2, Table 60: the encapsulation identifier of a
 * sample names its type's extensibility. A type hddsgen 2.0 generated says
 * it (`static constexpr std::uint32_t hdds_extensibility`: 0 FINAL, 1
 * APPENDABLE, 2 MUTABLE); create_writer<T>() of a Participant or a
 * Publisher hands it to the C ABI writer, which labels every sample with
 * it (the bytes on the wire are checked by scripts/test-sdk-typed.sh). A
 * type without it keeps the writer of earlier releases (every sample
 * CDR2_LE). A value the C ABI does not know is refused, which shows the
 * marker reaches it.
 *
 * Build (from the repository root, after `cargo build -p hdds-c --release`):
 *   g++ -std=c++17 -Wall -Wextra -o test_extensibility_cpp sdk/cxx/tests/test_extensibility.cpp \
 *       sdk/cxx/src/{participant,writer,reader,qos,waitset,logging,telemetry,pubsub}.cpp \
 *       -Isdk/cxx/include -Isdk/c/include \
 *       -Ltarget/release -lhdds_c -lpthread -ldl -lm
 *   LD_LIBRARY_PATH=target/release ./test_extensibility_cpp
 */

#include <hdds.hpp>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <memory>

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

/// The shape of an hddsgen type: an encoder, and (1.3 and later) its
/// extensibility.
template<std::uint32_t Ext>
struct Marked {
    static constexpr std::uint32_t hdds_extensibility = Ext;
    int encode_cdr2_le(std::uint8_t* dst, std::size_t len) const noexcept {
        if (len < 8) return -1;
        const std::uint8_t body[8] = {4, 0, 0, 0, 0x2a, 0, 0, 0};
        for (int i = 0; i < 8; ++i) dst[i] = body[i];
        return 8;
    }
};

using Final = Marked<0>;
using Appendable = Marked<1>;
using Mutable = Marked<2>;
/// No extensibility the C ABI knows.
using Unknown = Marked<3>;

/// A type of hddsgen 1.x: no extensibility.
struct Unmarked {
    int encode_cdr2_le(std::uint8_t*, std::size_t) const noexcept { return 0; }
};

static_assert(hdds::detail::has_hdds_extensibility<Final>::value, "final");
static_assert(hdds::detail::has_hdds_extensibility<Mutable>::value, "mutable");
static_assert(!hdds::detail::has_hdds_extensibility<Unmarked>::value, "unmarked");
static_assert(hdds::detail::extensibility_of<Final>() == hdds::Extensibility::Final, "0");
static_assert(hdds::detail::extensibility_of<Appendable>() == hdds::Extensibility::Appendable,
              "1");
static_assert(hdds::detail::extensibility_of<Mutable>() == hdds::Extensibility::Mutable, "2");

template<typename F>
bool throws(F f) {
    try {
        f();
    } catch (const hdds::Error&) {
        return true;
    }
    return false;
}

void a_participant_writer_hands_the_marker_to_the_c_abi() {
    hdds::Participant p("cxx_ext_participant", hdds::TransportMode::IntraProcess);
    hdds::QoS qos = hdds::QoS::reliable();
    auto f = p.create_writer<Final>("cxx_ext_f");
    auto a = p.create_writer<Appendable>("cxx_ext_a", qos);
    auto m = p.create_writer<Mutable>("cxx_ext_m");
    auto u = p.create_writer<Unmarked>("cxx_ext_u", qos);
    a.write(Appendable{});
    m.write(Mutable{});
    // The marker is what the C ABI receives: one it does not know is
    // refused, with and without a QoS.
    CHECK(throws([&] { p.create_writer<Unknown>("cxx_ext_x"); }));
    CHECK(throws([&] { p.create_writer<Unknown>("cxx_ext_xq", qos); }));
}

void a_publisher_writer_hands_the_marker_to_the_c_abi() {
    hdds::Participant p("cxx_ext_publisher", hdds::TransportMode::IntraProcess);
    auto publisher = p.create_publisher();
    hdds::QoS qos = hdds::QoS::reliable();
    auto a = publisher->create_writer<Appendable>("cxx_pub_ext_a");
    auto m = publisher->create_writer<Mutable>("cxx_pub_ext_m", qos);
    auto u = publisher->create_writer<Unmarked>("cxx_pub_ext_u");
    m.write(Mutable{});
    CHECK(throws([&] { publisher->create_writer<Unknown>("cxx_pub_ext_x"); }));
    CHECK(throws([&] { publisher->create_writer<Unknown>("cxx_pub_ext_xq", qos); }));
}

}  // namespace

int main() {
    std::printf("HDDS C++ SDK: writer extensibility\n");
    RUN_TEST(a_participant_writer_hands_the_marker_to_the_c_abi);
    RUN_TEST(a_publisher_writer_hands_the_marker_to_the_c_abi);
    std::printf("%d passed\n", passed);
    return 0;
}
