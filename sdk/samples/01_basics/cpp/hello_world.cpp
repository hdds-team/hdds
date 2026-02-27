// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * HDDS Sample: Hello World (C++)
 *
 * Demonstrates basic pub/sub with HDDS C++ API.
 *
 * Usage:
 *     # Terminal 1 - Subscriber
 *     ./hello_world
 *
 *     # Terminal 2 - Publisher
 *     ./hello_world pub
 */

#include <hdds.hpp>
#include <iostream>
#include <thread>
#include <chrono>
#include <cstring>

#include "generated/HelloWorld.hpp"

using namespace hdds_samples;
using namespace std::chrono_literals;

void run_publisher(hdds::Participant& participant) {
    std::cout << "Creating writer..." << std::endl;
    auto writer = participant.create_writer<HelloWorld>("HelloWorldTopic");

    std::cout << "Publishing messages..." << std::endl;

    for (int i = 0; i < 10; i++) {
        // Typed API: CDR2 serialization handled automatically
        writer.write(HelloWorld{i, "Hello from HDDS C++!"});

        // Raw API equivalent (manual buffer management):
        //   auto raw_writer = participant.create_writer_raw("HelloWorldTopic");
        //   HelloWorld msg(i, "Hello from HDDS C++!");
        //   std::uint8_t buffer[4096];
        //   int bytes = msg.encode_cdr2_le(buffer, sizeof(buffer));
        //   if (bytes > 0) raw_writer->write_raw(buffer, static_cast<size_t>(bytes));

        std::cout << "  Published: id=" << i << std::endl;

        std::this_thread::sleep_for(500ms);
    }

    std::cout << "Done publishing." << std::endl;
}

void run_subscriber(hdds::Participant& participant) {
    std::cout << "Creating reader..." << std::endl;
    auto reader = participant.create_reader<HelloWorld>("HelloWorldTopic");

    // Create waitset and attach reader's status condition
    hdds::WaitSet waitset;
    waitset.attach(reader.get_status_condition());

    std::cout << "Waiting for messages (Ctrl+C to exit)..." << std::endl;

    int received = 0;
    while (received < 10) {
        if (waitset.wait(5s)) {
            // Typed API: no need to re-specify <HelloWorld> -- reader already knows the type
            while (auto msg = reader.take()) {
                std::cout << "  Received: " << msg->message << " (id=" << msg->id << ")" << std::endl;
                received++;
            }

            // Raw API equivalent (manual buffer management):
            //   auto raw_reader = participant.create_reader_raw("HelloWorldTopic");
            //   while (auto data = raw_reader->take_raw()) {
            //       HelloWorld msg;
            //       if (msg.decode_cdr2_le(data->data(), data->size()) > 0) { ... }
            //   }
        } else {
            std::cout << "  (timeout - no messages)" << std::endl;
        }
    }

    std::cout << "Done receiving." << std::endl;
}

int main(int argc, char** argv) {
    bool is_publisher = (argc > 1 && std::strcmp(argv[1], "pub") == 0);

    try {
        hdds::logging::init(hdds::LogLevel::Warn);

        std::cout << std::string(60, '=') << std::endl;
        std::cout << "Hello World Sample" << std::endl;
        std::cout << "Mode: " << (is_publisher ? "Publisher" : "Subscriber") << std::endl;
        std::cout << std::string(60, '=') << std::endl;

        hdds::Participant participant("HelloWorld");
        std::cout << "Participant created: " << participant.name() << std::endl;

        if (is_publisher) {
            run_publisher(participant);
        } else {
            run_subscriber(participant);
        }

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
