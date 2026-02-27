// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/*
 * rti_interop.cpp — HDDS subscriber with RTI Connext-compatible QoS
 *
 * Subscribes on "InteropTest" using QoS::rti_defaults() for wire
 * compatibility with RTI Connext DDS.
 *
 * Build:
 *   g++ -std=c++17 -o rti_interop rti_interop.cpp -I../../../cxx/include -lhdds
 *
 * Run:
 *   ./rti_interop
 *
 * RTI Connext peer: see peer_commands.md
 *
 * Expected:
 *   Received 52 bytes: id=1, msg="Hello from RTI #1"
 *   ...
 */

#include <hdds.hpp>
#include <iostream>
#include <chrono>
#include <cstring>

using namespace std::chrono_literals;

/* Deserialize StringMsg {id: u32, message: string} from CDR LE buffer. */
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
                             slen - 1); /* strip null */
        return m;
    }
};

int main()
{
    try {
        hdds::logging::init(hdds::LogLevel::Warn);
        hdds::Participant participant("RTI_Interop");
        auto qos    = hdds::QoS::rti_defaults();
        auto reader = participant.create_reader_raw("InteropTest", qos);

        hdds::WaitSet waitset;
        waitset.attach(reader->get_status_condition());

        std::cout << "[HDDS] Subscribing on 'InteropTest' (RTI QoS)...\n"
                  << "[HDDS] Start an RTI Connext publisher on the same topic.\n\n";

        int received = 0;
        for (int attempt = 0; attempt < 60; attempt++) {
            if (waitset.wait(1s)) {
                while (auto data = reader->take_raw()) {
                    auto msg = StringMsg::deserialize(data->data(), data->size());
                    std::cout << "Received " << data->size()
                              << " bytes: id=" << msg.id
                              << ", msg=\"" << msg.message << "\"\n";
                    received++;
                }
            }
        }

        std::cout << "\nReceived " << received << " total messages.\n";
    } catch (const std::exception &e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
    return 0;
}
