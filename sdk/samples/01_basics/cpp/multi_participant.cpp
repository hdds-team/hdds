// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * HDDS Sample: Multi-Participant (C++)
 *
 * Demonstrates multiple DDS participants in the same process.
 *
 * Usage:
 *     ./multi_participant
 */

#include <hdds.hpp>
#include <iostream>
#include <thread>
#include <chrono>
#include <vector>

#include "generated/HelloWorld.hpp"

using namespace hdds_samples;
using namespace std::chrono_literals;

void publisher_thread(const std::string& name, const std::string& topic) {
    std::cout << "[" << name << "] Creating participant...\n";
    hdds::Participant participant(name);

    auto writer = participant.create_writer_raw(topic);
    std::cout << "[" << name << "] Publishing to '" << topic << "'...\n";

    for (int i = 0; i < 5; i++) {
        std::string msg_text = "From " + name;
        HelloWorld msg(i, msg_text);
        std::uint8_t buffer[4096];
        int bytes = msg.encode_cdr2_le(buffer, sizeof(buffer));
        if (bytes > 0) {
            writer->write_raw(buffer, static_cast<size_t>(bytes));
        }
        std::cout << "[" << name << "] Sent: " << msg.message << " #" << msg.id << "\n";
        std::this_thread::sleep_for(300ms);
    }

    std::cout << "[" << name << "] Done.\n";
}

void subscriber_thread(const std::string& name, const std::string& topic) {
    std::cout << "[" << name << "] Creating participant...\n";
    hdds::Participant participant(name);

    auto reader = participant.create_reader_raw(topic);
    hdds::WaitSet waitset;
    waitset.attach(reader->get_status_condition());

    std::cout << "[" << name << "] Subscribing to '" << topic << "'...\n";
    int received = 0;

    while (received < 10) {
        if (waitset.wait(2s)) {
            while (auto data = reader->take_raw()) {
                HelloWorld msg;
                if (msg.decode_cdr2_le(data->data(), data->size()) > 0) {
                    std::cout << "[" << name << "] Received: " << msg.message
                              << " #" << msg.id << "\n";
                    received++;
                }
            }
        }
    }

    std::cout << "[" << name << "] Done.\n";
}

int main() {
    try {
        hdds::logging::init(hdds::LogLevel::Warn);

        std::cout << std::string(60, '=') << "\n";
        std::cout << "Multi-Participant Demo\n";
        std::cout << "Creating 3 participants: 2 publishers + 1 subscriber\n";
        std::cout << std::string(60, '=') << "\n";

        const std::string topic = "MultiParticipantTopic";

        // Start subscriber first
        std::thread sub(subscriber_thread, "Subscriber", topic);
        std::this_thread::sleep_for(200ms);

        std::thread pub_a(publisher_thread, "Publisher-A", topic);
        std::thread pub_b(publisher_thread, "Publisher-B", topic);

        sub.join();
        pub_a.join();
        pub_b.join();

        std::cout << std::string(60, '=') << "\n";
        std::cout << "All participants finished.\n";
        std::cout << std::string(60, '=') << "\n";

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }

    return 0;
}
