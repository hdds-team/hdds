// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * HDDS Sample: Multi-Topic (C++)
 *
 * Demonstrates pub/sub on multiple topics from a single participant.
 *
 * Usage:
 *     ./multi_topic        # Subscriber
 *     ./multi_topic pub    # Publisher
 */

#include <hdds.hpp>
#include <iostream>
#include <thread>
#include <chrono>
#include <map>
#include <vector>
#include <cstring>

#include "generated/HelloWorld.hpp"

using namespace hdds_samples;
using namespace std::chrono_literals;

const std::vector<std::string> TOPICS = {"SensorData", "Commands", "Status"};

void run_publisher(hdds::Participant& participant) {
    std::map<std::string, std::unique_ptr<hdds::DataWriter>> writers;

    for (const auto& topic : TOPICS) {
        writers[topic] = participant.create_writer_raw(topic);
        std::cout << "  Created writer for '" << topic << "'\n";
    }

    std::cout << "\nPublishing to all topics...\n";

    for (int i = 0; i < 5; i++) {
        for (const auto& topic : TOPICS) {
            std::string msg_text = topic + " message";
            HelloWorld msg(i, msg_text);
            std::uint8_t buffer[4096];
            int bytes = msg.encode_cdr2_le(buffer, sizeof(buffer));
            if (bytes > 0) {
                writers[topic]->write_raw(buffer, static_cast<size_t>(bytes));
            }
            std::cout << "  [" << topic << "] Sent #" << i << "\n";
        }
        std::this_thread::sleep_for(500ms);
    }

    std::cout << "Done publishing.\n";
}

void run_subscriber(hdds::Participant& participant) {
    std::map<std::string, std::unique_ptr<hdds::DataReader>> readers;
    std::map<std::string, int> received;
    hdds::WaitSet waitset;

    for (const auto& topic : TOPICS) {
        auto reader = participant.create_reader_raw(topic);
        waitset.attach(reader->get_status_condition());
        readers[topic] = std::move(reader);
        received[topic] = 0;
        std::cout << "  Created reader for '" << topic << "'\n";
    }

    std::cout << "\nWaiting for messages on all topics...\n";
    int total_expected = TOPICS.size() * 5;
    int total_received = 0;

    while (total_received < total_expected) {
        if (waitset.wait(3s)) {
            for (const auto& topic : TOPICS) {
                while (auto data = readers[topic]->take_raw()) {
                    HelloWorld msg;
                    if (msg.decode_cdr2_le(data->data(), data->size()) > 0) {
                        std::cout << "  [" << topic << "] Received: " << msg.message
                                  << " #" << msg.id << "\n";
                        received[topic]++;
                        total_received++;
                    }
                }
            }
        } else {
            std::cout << "  (timeout)\n";
        }
    }

    std::cout << "\nReceived counts:\n";
    for (const auto& topic : TOPICS) {
        std::cout << "  " << topic << ": " << received[topic] << " messages\n";
    }
    std::cout << "Done receiving.\n";
}

int main(int argc, char** argv) {
    bool is_publisher = (argc > 1 && std::strcmp(argv[1], "pub") == 0);

    try {
        hdds::logging::init(hdds::LogLevel::Warn);

        std::cout << std::string(60, '=') << "\n";
        std::cout << "Multi-Topic Demo\n";
        std::cout << "Topics: ";
        for (size_t i = 0; i < TOPICS.size(); i++) {
            std::cout << TOPICS[i];
            if (i < TOPICS.size() - 1) std::cout << ", ";
        }
        std::cout << "\n" << std::string(60, '=') << "\n";

        hdds::Participant participant("MultiTopicDemo");

        if (is_publisher) {
            run_publisher(participant);
        } else {
            run_subscriber(participant);
        }

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }

    return 0;
}
