// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

#include <hdds.hpp>
extern "C" {
#include <hdds.h>
}
#include "sdk_keyed.hpp"
#include <cassert>
#include <iostream>

// The interface of an older codec, before per-instance key hooks existed.
struct OldCodec {
    static constexpr std::uint32_t hdds_extensibility = 0;
    std::uint8_t tag = 0;
    std::int64_t id = 0;
    std::int32_t value = 0;
    int encode_cdr2_le(std::uint8_t* bytes, std::size_t size) const {
        Keyed row{}; row.tag = tag; row.id = id; row.value = value;
        return row.encode_cdr2_le(bytes, size);
    }
};

struct NonDefault : Keyed {
    NonDefault() = delete;
    explicit NonDefault(int v) { tag = 1; id = 1; value = v; }
};

template<typename T>
void publish(hdds::DataWriter& writer, const std::string& mode) {
    assert(hdds_writer_wait_for_matched_readers(writer.c_handle(), 1, 20000) == HDDS_OK);
    for (int value : {10, 20}) {
        for (int id : {1, 2, 3}) {
            T row{}; row.tag = 1; row.id = id; row.value = value;
            if (mode == "bytes") {
                std::uint8_t bytes[64];
                const int size = row.encode_cdr2_le(bytes, sizeof(bytes));
                assert(size > 0);
                writer.write_raw(bytes, static_cast<std::size_t>(size));
            } else {
                writer.write(row);
            }
        }
    }
    assert(writer.wait_for_acknowledgments(std::chrono::seconds(20)));
    std::cout << "WRITTEN" << std::endl;
    std::string command;
    if (mode != "legacy" && mode != "oldcodec") {
        std::cin >> command; assert(command == "dispose");
        T row{}; row.tag = 1; row.id = 2;
        writer.dispose(row);
        assert(writer.wait_for_acknowledgments(std::chrono::seconds(20)));
        std::cout << "DISPOSED" << std::endl;
        std::cin >> command; assert(command == "unregister");
        row.id = 3; writer.unregister_instance(row);
        assert(writer.wait_for_acknowledgments(std::chrono::seconds(20)));
        std::cout << "UNREGISTERED" << std::endl;
    }
    std::cin >> command; assert(command == "quit");
}

int main(int argc, char** argv) {
    assert(argc == 4);
    hdds::Participant participant("cpp_sdk_constructor", std::stoul(argv[1]));
    const std::string mode = argv[3];
    auto qos = hdds::QoS::reliable();
    auto custom = participant.create_writer<NonDefault>("sdk_nondefault_codec", qos);
    custom.write(NonDefault(42));
    if (mode == "legacy") {
        auto writer = participant.create_writer_raw("sdk_key_identity", qos);
        publish<Keyed>(*writer, mode);
    } else if (mode == "scoped") {
        hdds::TypedDataWriter<m::T> writer(participant.create_keyed_writer_raw(
            "sdk_key_identity", qos, hdds::Extensibility::Final, "m::T"));
        publish<m::T>(*writer.raw(), mode);
    } else if (mode == "oldcodec") {
        auto writer = participant.create_writer<OldCodec>("sdk_key_identity", qos);
        publish<OldCodec>(*writer.raw(), mode);
    } else {
        auto writer = participant.create_writer<Keyed>("sdk_key_identity", qos);
        publish<Keyed>(*writer.raw(), mode);
    }
}
