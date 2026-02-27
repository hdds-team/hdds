// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/*
 * fastdds_interop.cpp — HDDS publisher interop with FastDDS subscriber
 *
 * Publishes raw CDR messages on "InteropTest" using standard RTPS QoS.
 * Any DDS vendor subscribing on the same domain/topic will receive them.
 *
 * Build:
 *   g++ -std=c++17 -o fastdds_interop fastdds_interop.cpp -I../../../cxx/include -lhdds
 *
 * Run:
 *   ./fastdds_interop
 *
 * FastDDS peer: see peer_commands.md
 *
 * Expected:
 *   Published 1/20: "Hello from HDDS C++ #1"
 *   ...
 */

#include <hdds.hpp>
#include <iostream>
#include <thread>
#include <chrono>
#include <vector>
#include <cstring>

using namespace std::chrono_literals;

/* Serialize a StringMsg {id: u32, message: string} to CDR LE. */
static std::vector<uint8_t> serialize_string_msg(uint32_t id,
                                                  const std::string &msg)
{
    uint32_t slen = static_cast<uint32_t>(msg.size() + 1); /* with null */
    size_t pad = (4 - (slen % 4)) % 4;
    std::vector<uint8_t> buf(4 + 4 + slen + pad, 0);

    std::memcpy(buf.data(), &id, 4);
    std::memcpy(buf.data() + 4, &slen, 4);
    std::memcpy(buf.data() + 8, msg.c_str(), slen);
    return buf;
}

int main()
{
    try {
        hdds::logging::init(hdds::LogLevel::Warn);
        hdds::Participant participant("FastDDS_Interop");
        auto qos = hdds::QoS::reliable();
        auto writer = participant.create_writer_raw("InteropTest", qos);

        std::cout << "[HDDS] Publishing 20 messages on 'InteropTopic'...\n"
                  << "[HDDS] Start a FastDDS subscriber on the same topic.\n\n";

        for (uint32_t i = 1; i <= 20; i++) {
            auto data = serialize_string_msg(i, "Hello from HDDS C++ #"
                                                + std::to_string(i));
            writer->write_raw(data);
            std::cout << "Published " << i << "/20: \"Hello from HDDS C++ #"
                      << i << "\"\n";
            std::this_thread::sleep_for(500ms);
        }

        std::cout << "\nDone.\n";
    } catch (const std::exception &e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
    return 0;
}
