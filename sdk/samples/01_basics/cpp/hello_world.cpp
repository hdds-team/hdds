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
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <thread>
#include <chrono>
#include <cstring>

#include "generated/HelloWorld.hpp"

using namespace hdds_samples;
using namespace std::chrono_literals;

// The publisher gives up if no subscriber matches within this time.
constexpr std::chrono::seconds kDiscoveryTimeout{30};
// The subscriber exits when no message arrives for this long.
constexpr std::chrono::seconds kIdleTimeout{30};

int run_publisher(hdds::Participant& participant) {
    std::cout << "Creating writer..." << std::endl;
    auto writer = participant.create_writer<HelloWorld>("HelloWorldTopic");

    // A sample written before discovery completes is never delivered,
    // so wait until a subscriber has matched.
    std::cout << "Waiting for a subscriber..." << std::endl;
    auto deadline = std::chrono::steady_clock::now() + kDiscoveryTimeout;
    while (writer.get_publication_matched_status().current_count == 0) {
        if (std::chrono::steady_clock::now() >= deadline) {
            std::cerr << "No subscriber matched within " << kDiscoveryTimeout.count()
                      << " s; start the subscriber first" << std::endl;
            return 1;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

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
    return 0;
}

void run_subscriber(hdds::Participant& participant) {
    std::cout << "Creating reader..." << std::endl;
    auto reader = participant.create_reader<HelloWorld>("HelloWorldTopic");

    // Create waitset and attach reader's status condition
    hdds::WaitSet waitset;
    waitset.attach(reader.get_status_condition());

    std::cout << "Waiting for messages (Ctrl+C to exit)..." << std::endl;

    // Poll in 1 s steps and stop once no message has arrived for kIdleTimeout,
    // so a lost sample ends the run instead of leaving it waiting forever.
    int received = 0;
    auto last_message = std::chrono::steady_clock::now();
    while (received < 10) {
        if (waitset.wait(1s)) {
            // Typed API: no need to re-specify <HelloWorld> -- reader already knows the type
            while (auto msg = reader.take()) {
                std::cout << "  Received: " << msg->message << " (id=" << msg->id << ")" << std::endl;
                received++;
                last_message = std::chrono::steady_clock::now();
            }

            // Raw API equivalent (manual buffer management):
            //   auto raw_reader = participant.create_reader_raw("HelloWorldTopic");
            //   while (auto data = raw_reader->take_raw()) {
            //       HelloWorld msg;
            //       if (msg.decode_cdr2_le(data->data(), data->size()) > 0) { ... }
            //   }
        }
        if (std::chrono::steady_clock::now() - last_message >= kIdleTimeout) {
            std::cout << "  No message for " << kIdleTimeout.count() << " s, giving up." << std::endl;
            break;
        }
    }

    std::cout << "Done receiving. Got " << received << " of 10 messages." << std::endl;
}

int main(int argc, char** argv) {
    bool is_publisher = (argc > 1 && std::strcmp(argv[1], "pub") == 0);

    try {
        hdds::logging::init(hdds::LogLevel::Warn);

        std::cout << std::string(60, '=') << std::endl;
        std::cout << "Hello World Sample" << std::endl;
        std::cout << "Mode: " << (is_publisher ? "Publisher" : "Subscriber") << std::endl;
        std::cout << std::string(60, '=') << std::endl;

        // No domain is passed: the library reads HDDS_DOMAIN_ID (a malformed value
        // throws), else uses domain 0.
        hdds::Participant participant("HelloWorld");
        std::cout << "Participant created: " << participant.name() << " (domain " << participant.domain_id() << ")" << std::endl;

        int status = 0;
        if (is_publisher) {
            status = run_publisher(participant);
        } else {
            run_subscriber(participant);
        }
        return status;

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
