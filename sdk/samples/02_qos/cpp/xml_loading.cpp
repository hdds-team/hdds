// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * HDDS Sample: XML QoS Loading (C++)
 *
 * Demonstrates loading QoS profiles from XML files.
 *
 * Build:
 *     cd build && cmake .. && make xml_loading
 *
 * Usage:
 *     ./xml_loading
 *
 * Expected output:
 *     [OK] Loaded QoS from XML
 *     [OK] Writer and Reader created with XML QoS
 *     [SENT] / [RECV] messages
 *
 * Key concepts:
 * - Loading QoS from OMG DDS XML
 * - Applying loaded QoS to typed writers and readers
 */

#include <hdds.hpp>
#include <iostream>
#include <string>
#include <thread>
#include <chrono>

#include "generated/HelloWorld.hpp"

using namespace hdds_samples;
using namespace std::chrono_literals;

constexpr int NUM_MESSAGES = 5;

int main() {
    std::cout << std::string(60, '=') << "\n";
    std::cout << "XML QoS Loading Demo\n";
    std::cout << "Load QoS profiles from XML files\n";
    std::cout << std::string(60, '=') << "\n\n";

    try {
        hdds::logging::init(hdds::LogLevel::Warn);

        hdds::Participant participant("XmlQosDemo");
        std::cout << "[OK] Participant created\n\n";

        // --- Load QoS from OMG DDS XML ---
        std::cout << "--- OMG DDS XML QoS ---\n\n";

        auto qos = [&]() -> hdds::QoS {
            try {
                auto loaded = hdds::QoS::from_xml("../qos_profile.xml");
                std::cout << "[OK] Loaded QoS from ../qos_profile.xml\n";
                return loaded;
            } catch (const hdds::Error&) {
                std::cout << "[WARN] XML loading failed, falling back to reliable defaults\n";
                return hdds::QoS::reliable();
            }
        }();

        auto writer = participant.create_writer<HelloWorld>("XmlQosTopic", qos);
        auto reader = participant.create_reader<HelloWorld>("XmlQosTopic", qos);
        std::cout << "[OK] Writer and Reader created with XML QoS\n\n";

        // --- Send/receive test ---
        std::cout << "--- Pub/Sub Test with XML QoS ---\n\n";

        hdds::WaitSet waitset;
        waitset.attach(reader.get_status_condition());

        for (int i = 0; i < NUM_MESSAGES; i++) {
            HelloWorld msg(i + 1, "XML QoS message #" + std::to_string(i + 1));
            writer.write(msg);
            std::cout << "[SENT] id=" << msg.id << " msg='" << msg.message << "'\n";
        }

        if (waitset.wait(2s)) {
            while (auto msg = reader.take()) {
                std::cout << "[RECV] id=" << msg->id << " msg='" << msg->message << "'\n";
            }
        }

    } catch (const hdds::Error& e) {
        std::cerr << "HDDS Error: " << e.what() << std::endl;
        return 1;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    std::cout << "\n=== XML QoS Loading Complete ===\n";
    return 0;
}
