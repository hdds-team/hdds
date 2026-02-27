// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/*
 * cyclone_interop.cpp — HDDS bidirectional pub+sub for CycloneDDS interop
 *
 * Publishes and subscribes on "InteropTest" simultaneously.  Run a
 * CycloneDDS peer doing the same to exchange messages bidirectionally.
 *
 * Build:
 *   g++ -std=c++17 -o cyclone_interop cyclone_interop.cpp -I../../../cxx/include -lhdds -lpthread
 *
 * Run:
 *   ./cyclone_interop
 *
 * CycloneDDS peer: see peer_commands.md
 *
 * Expected:
 *   [PUB] Sent #1: "HDDS ping #1"
 *   [SUB] Got 48 bytes: id=1, msg="CycloneDDS pong #1"
 *   ...
 */

#include <hdds.hpp>
#include <iostream>
#include <thread>
#include <chrono>
#include <vector>
#include <cstring>

using namespace std::chrono_literals;

/* CDR LE serialize/deserialize for StringMsg {id: u32, message: string}. */
static std::vector<uint8_t> serialize(uint32_t id, const std::string &msg)
{
    uint32_t slen = static_cast<uint32_t>(msg.size() + 1);
    size_t pad = (4 - (slen % 4)) % 4;
    std::vector<uint8_t> buf(4 + 4 + slen + pad, 0);
    std::memcpy(buf.data(), &id, 4);
    std::memcpy(buf.data() + 4, &slen, 4);
    std::memcpy(buf.data() + 8, msg.c_str(), slen);
    return buf;
}

struct StringMsg {
    uint32_t    id = 0;
    std::string message;

    static StringMsg deserialize(const uint8_t *data, size_t len) {
        StringMsg m;
        if (len < 8) return m;
        std::memcpy(&m.id, data, 4);
        uint32_t slen = 0;
        std::memcpy(&slen, data + 4, 4);
        if (slen > 0 && 8 + slen <= len)
            m.message.assign(reinterpret_cast<const char *>(data + 8),
                             slen - 1);
        return m;
    }
};

/* Subscriber runs in a separate thread. */
static void subscriber_loop(hdds::DataReader *reader)
{
    hdds::WaitSet ws;
    ws.attach(reader->get_status_condition());

    for (int i = 0; i < 60; i++) {
        if (ws.wait(500ms)) {
            while (auto data = reader->take_raw()) {
                auto msg = StringMsg::deserialize(data->data(), data->size());
                std::cout << "[SUB] Got " << data->size()
                          << " bytes: id=" << msg.id
                          << ", msg=\"" << msg.message << "\"\n";
            }
        }
    }
}

int main()
{
    try {
        hdds::logging::init(hdds::LogLevel::Warn);
        hdds::Participant participant("Cyclone_Interop");
        auto qos    = hdds::QoS::reliable();
        auto writer = participant.create_writer_raw("InteropTest", qos);
        auto reader = participant.create_reader_raw("InteropTest", qos);

        std::cout << "[HDDS] Bidirectional interop on 'InteropTest' (domain 0).\n"
                  << "[HDDS] Start a CycloneDDS peer on the same topic.\n\n";

        /* Start subscriber in background */
        std::thread sub_thread(subscriber_loop, reader.get());

        /* Publish 20 messages */
        for (uint32_t i = 1; i <= 20; i++) {
            auto data = serialize(i, "HDDS ping #" + std::to_string(i));
            writer->write_raw(data);
            std::cout << "[PUB] Sent #" << i << ": \"HDDS ping #"
                      << i << "\"\n";
            std::this_thread::sleep_for(500ms);
        }

        sub_thread.join();
        std::cout << "\nDone.\n";
    } catch (const std::exception &e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
    return 0;
}
