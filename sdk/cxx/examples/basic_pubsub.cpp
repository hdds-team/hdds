// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * @file basic_pubsub.cpp
 * @brief Basic HDDS C++ pub/sub example
 */

#include <hdds.hpp>
#include <iostream>
#include <thread>
#include <chrono>

int main() {
    try {
        // Create participant
        hdds::Participant participant("cpp_example");
        std::cout << "Created participant: " << participant.name() << std::endl;

        // Configure QoS
        auto qos = hdds::QoS::reliable()
            .transient_local()
            .history_depth(10)
            .deadline(std::chrono::milliseconds(500));

        // Create writer
        auto writer = participant.create_writer_raw("HelloWorld", qos);
        std::cout << "Created writer on topic: " << writer->topic_name() << std::endl;

        // Create reader
        auto reader = participant.create_reader_raw("HelloWorld", qos);
        std::cout << "Created reader on topic: " << reader->topic_name() << std::endl;

        // Wait for discovery
        std::this_thread::sleep_for(std::chrono::seconds(1));

        // Publish
        std::string message = "Hello from C++!";
        writer->write_raw(reinterpret_cast<const uint8_t*>(message.data()), message.size());
        std::cout << "Published: " << message << std::endl;

        // Read
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        auto data = reader->take_raw();
        if (data) {
            std::string received(data->begin(), data->end());
            std::cout << "Received: " << received << std::endl;
        } else {
            std::cout << "No data received" << std::endl;
        }

        return 0;
    } catch (const hdds::Error& e) {
        std::cerr << "HDDS error: " << e.what() << std::endl;
        return 1;
    }
}
