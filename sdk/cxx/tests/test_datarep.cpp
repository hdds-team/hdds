// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * @file test_datarep.cpp
 * @brief HDDS C++ SDK: DATA_REPRESENTATION of typed readers
 *
 * DDS-XTypes 1.3 7.6.3.1.1: a reader requests what its decoders read.
 *   - create_reader<T>() for a type with decode_by_encapsulation (hddsgen
 *     1.3) requests [XCDR, XCDR2]; take() hands each sample to it with its
 *     encapsulation identifier (0x0001 XCDR1, 0x0007 XCDR2)
 *   - for a type with decode_cdr2_le only it requests XCDR2 and is never
 *     matched with a writer that offers XCDR
 *   - such a type, at a reader whose QoS requested XCDR by hand, refuses an
 *     XCDR1 sample (Error) instead of misreading it
 *   - QoS::data_representation reaches the C handle, and an explicit list
 *     is kept by create_reader<T>()
 *
 * Build (from the repository root, after `cargo build -p hdds-c --release`):
 *   g++ -std=c++17 -Wall -Wextra -o test_datarep_cpp sdk/cxx/tests/test_datarep.cpp \
 *       sdk/cxx/src/{participant,writer,reader,qos,waitset,logging,telemetry,pubsub}.cpp \
 *       -Isdk/cxx/include -Isdk/c/include \
 *       -Ltarget/release -lhdds_c -lpthread -ldl -lm
 *   LD_LIBRARY_PATH=target/release ./test_datarep_cpp
 */

#include <hdds.hpp>

extern "C" {
#include <hdds.h>
}

#include <cstdint>
#include <cstdio>
#include <cstdlib>
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
        std::printf("  %-64s", #fn);                                             \
        std::fflush(stdout);                                                     \
        fn();                                                                    \
        std::printf("[PASS]\n");                                                 \
        passed++;                                                                \
    } while (0)

/// A type of hddsgen 2.0: decodes XCDR1 and XCDR2, by identifier.
struct BothVersions {
    std::uint16_t id = 0;
    std::vector<std::uint8_t> bytes;
    int decode_cdr2_le(const std::uint8_t* src, std::size_t len) noexcept {
        return decode_by_encapsulation(0x0007, src, len);
    }
    int decode_by_encapsulation(std::uint16_t encapsulation_id, const std::uint8_t* src,
                                std::size_t len) noexcept {
        id = encapsulation_id;
        bytes.assign(src, src + len);
        return static_cast<int>(len);
    }
};

/// A type of hddsgen 1.x: XCDR2 only.
struct Xcdr2Only {
    std::vector<std::uint8_t> bytes;
    int decode_cdr2_le(const std::uint8_t* src, std::size_t len) noexcept {
        bytes.assign(src, src + len);
        return static_cast<int>(len);
    }
};

static_assert(hdds::detail::has_decode_by_encapsulation<BothVersions>::value, "");
static_assert(!hdds::detail::has_decode_by_encapsulation<Xcdr2Only>::value, "");

std::vector<std::int16_t> c_list(const hdds::QoS& qos) {
    std::int16_t ids[8];
    std::size_t count = 0;
    CHECK(hdds_qos_get_data_representation(qos.c_handle(), ids, 8, &count) == HDDS_OK);
    return std::vector<std::int16_t>(ids, ids + count);
}

void the_qos_list_reaches_the_c_handle() {
    auto qos = hdds::QoS::reliable();
    CHECK(c_list(qos).empty());
    qos.data_representation({HDDS_XCDR_DATA_REPRESENTATION, HDDS_XCDR2_DATA_REPRESENTATION});
    CHECK((c_list(qos) == std::vector<std::int16_t>{0, 2}));
    auto copy = qos;
    CHECK((copy.get_data_representation() == std::vector<std::int16_t>{0, 2}));
    bool refused = false;
    try {
        auto bad = hdds::QoS::reliable();
        bad.data_representation({1});
        (void)bad.c_handle();
    } catch (const hdds::Error&) {
        refused = true;
    }
    CHECK(refused);
}

void a_reader_of_a_type_decoding_xcdr1_takes_both_representations() {
    hdds::Participant p("cxx_datarep", hdds::TransportMode::IntraProcess);
    auto x1_qos = hdds::QoS::reliable();
    x1_qos.data_representation({HDDS_XCDR_DATA_REPRESENTATION});
    auto x1 = p.create_writer_raw("cxx_datarep", x1_qos);
    auto x2 = p.create_writer_raw("cxx_datarep", hdds::QoS::reliable());
    auto reader = p.create_reader<BothVersions>("cxx_datarep", hdds::QoS::reliable());

    const std::uint8_t a[4] = {1, 2, 3, 4};
    const std::uint8_t b[4] = {5, 6, 7, 8};
    x1->write_raw(a, 4);
    x2->write_raw(b, 4);
    auto first = reader.take();
    CHECK(first.has_value());
    CHECK(first->id == 0x0001);
    CHECK((first->bytes == std::vector<std::uint8_t>{1, 2, 3, 4}));
    auto second = reader.take();
    CHECK(second.has_value());
    CHECK(second->id == 0x0007);
    CHECK((second->bytes == std::vector<std::uint8_t>{5, 6, 7, 8}));
    CHECK(!reader.take().has_value());
}

void a_reader_of_an_xcdr2_only_type_misses_an_xcdr1_writer() {
    hdds::Participant p("cxx_datarep_old", hdds::TransportMode::IntraProcess);
    auto reader = p.create_reader<Xcdr2Only>("cxx_datarep_old", hdds::QoS::reliable());
    auto x1_qos = hdds::QoS::reliable();
    x1_qos.data_representation({HDDS_XCDR_DATA_REPRESENTATION});
    auto x1 = p.create_writer_raw("cxx_datarep_old", x1_qos);
    const std::uint8_t a[4] = {1, 0, 0, 0};
    x1->write_raw(a, 4);
    CHECK(!reader.take().has_value());
}

void an_xcdr2_only_type_refuses_an_xcdr1_sample() {
    hdds::Participant p("cxx_datarep_refuse", hdds::TransportMode::IntraProcess);
    auto both = hdds::QoS::reliable();
    both.data_representation({HDDS_XCDR_DATA_REPRESENTATION, HDDS_XCDR2_DATA_REPRESENTATION});
    // An explicit list is kept, whatever the type.
    auto reader = p.create_reader<Xcdr2Only>("cxx_datarep_refuse", both);
    auto x1_qos = hdds::QoS::reliable();
    x1_qos.data_representation({HDDS_XCDR_DATA_REPRESENTATION});
    auto x1 = p.create_writer_raw("cxx_datarep_refuse", x1_qos);
    const std::uint8_t a[4] = {1, 0, 0, 0};
    x1->write_raw(a, 4);
    bool refused = false;
    try {
        (void)reader.take();
    } catch (const hdds::Error&) {
        refused = true;
    }
    CHECK(refused);
}

}  // namespace

int main() {
    std::printf("HDDS C++ SDK: DATA_REPRESENTATION\n");
    RUN_TEST(the_qos_list_reaches_the_c_handle);
    RUN_TEST(a_reader_of_a_type_decoding_xcdr1_takes_both_representations);
    RUN_TEST(a_reader_of_an_xcdr2_only_type_misses_an_xcdr1_writer);
    RUN_TEST(an_xcdr2_only_type_refuses_an_xcdr1_sample);
    std::printf("%d passed\n", passed);
    return 0;
}
