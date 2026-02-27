// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * HDDS Sample: Transport Selection (C++)
 *
 * Demonstrates creating participants with explicit transport selection.
 * Shows UdpMulticast (default) and IntraProcess modes.
 *
 * Build:
 *     cd build && cmake .. && make transport_select
 *
 * Usage:
 *     ./transport_select              # Default UDP multicast transport
 *     ./transport_select intra        # IntraProcess transport
 *     ./transport_select udp          # Explicit UDP multicast transport
 *
 * Expected output:
 *     [OK] Participant created with udp transport
 *     [SENT] Transport test message #1
 *     ...
 *
 * Key concepts:
 * - Default transport is UDP multicast (LAN discovery)
 * - IntraProcess transport for same-process communication (zero-copy)
 * - Transport selected at participant creation
 */

#include <hdds.hpp>
#include <iostream>
#include <string>
#include <thread>
#include <chrono>
#include <cstring>

#include "generated/HelloWorld.hpp"

using namespace hdds_samples;
using namespace std::chrono_literals;

constexpr int NUM_MESSAGES = 5;

int main(int argc, char **argv) {
    std::string transport = "udp";
    if (argc > 1) {
        transport = argv[1];
    }

    std::cout << std::string(60, '=') << "\n";
    std::cout << "Transport Selection Demo\n";
    std::cout << "Selected transport: " << transport << "\n";
    std::cout << std::string(60, '=') << "\n\n";

    try {
        hdds::logging::init(hdds::LogLevel::Warn);

        std::cout << "--- Available Transports ---\n";
        std::cout << "  udp    - UDP multicast (default, LAN discovery)\n";
        std::cout << "  intra  - IntraProcess (same-process, zero-copy)\n";
        std::cout << "\n";

        // Create participant with selected transport
        hdds::TransportMode mode = (transport == "intra")
            ? hdds::TransportMode::IntraProcess
            : hdds::TransportMode::UdpMulticast;

        hdds::Participant participant("TransportDemo", mode);

        std::cout << "[OK] Participant created with " << transport << " transport\n";

        // Create endpoints
        auto writer = participant.create_writer_raw("TransportTopic");
        std::cout << "[OK] DataWriter created on 'TransportTopic'\n";

        auto reader = participant.create_reader_raw("TransportTopic");
        std::cout << "[OK] DataReader created on 'TransportTopic'\n\n";

        // Send messages
        std::cout << "--- Sending " << NUM_MESSAGES << " messages via "
                  << transport << " ---\n\n";

        for (int i = 0; i < NUM_MESSAGES; i++) {
            HelloWorld msg(i + 1, "Transport test #" + std::to_string(i + 1) +
                                   " (" + transport + ")");
            std::uint8_t buffer[4096];
            int bytes = msg.encode_cdr2_le(buffer, sizeof(buffer));
            if (bytes > 0) {
                writer->write_raw(buffer, static_cast<size_t>(bytes));
            }
            std::cout << "[SENT] id=" << msg.id << " msg='" << msg.message << "'\n";
            std::this_thread::sleep_for(200ms);
        }

        // Read back
        std::cout << "\n--- Reading messages ---\n\n";

        hdds::WaitSet waitset;
        waitset.attach(reader->get_status_condition());

        if (waitset.wait(2s)) {
            while (auto data = reader->take_raw()) {
                HelloWorld msg;
                if (msg.decode_cdr2_le(data->data(), data->size()) > 0) {
                    std::cout << "[RECV] id=" << msg.id
                              << " msg='" << msg.message << "'\n";
                }
            }
        } else {
            std::cout << "[TIMEOUT] No messages received "
                      << "(run two instances to test)\n";
        }

    } catch (const hdds::Error& e) {
        std::cerr << "HDDS Error: " << e.what() << std::endl;
        return 1;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    std::cout << "\n=== Transport Selection Complete ===\n";
    return 0;
}
