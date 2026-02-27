// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * HDDS Sample: Instance Keys (C++)
 *
 * Demonstrates keyed instances in DDS.
 *
 * Usage:
 *     ./instance_keys        # Subscriber
 *     ./instance_keys pub    # Publisher
 */

#include <hdds.hpp>
#include <iostream>
#include <thread>
#include <chrono>
#include <map>
#include <cstring>

#include "generated/KeyedData.hpp"

using namespace hdds_samples;
using namespace std::chrono_literals;

constexpr int NUM_INSTANCES = 3;

void run_publisher(hdds::Participant& participant) {
    auto writer = participant.create_writer_raw("SensorTopic");
    std::cout << "Publishing updates for " << NUM_INSTANCES << " sensor instances...\n\n";

    for (int seq = 0; seq < 5; seq++) {
        for (int sensor_id = 0; sensor_id < NUM_INSTANCES; sensor_id++) {
            KeyedData msg(sensor_id, "Sensor-" + std::to_string(sensor_id) + " reading", seq);
            std::uint8_t buffer[4096];
            int bytes = msg.encode_cdr2_le(buffer, sizeof(buffer));
            if (bytes > 0) {
                writer->write_raw(buffer, static_cast<size_t>(bytes));
            }

            std::cout << "  [Sensor " << sensor_id << "] seq=" << seq
                      << " -> '" << msg.data << "'\n";
        }
        std::this_thread::sleep_for(500ms);
    }

    std::cout << "\nDone publishing.\n";
}

void run_subscriber(hdds::Participant& participant) {
    auto reader = participant.create_reader_raw("SensorTopic");
    hdds::WaitSet waitset;
    waitset.attach(reader->get_status_condition());

    // Track state per instance
    std::map<int32_t, int> instance_state;
    for (int i = 0; i < NUM_INSTANCES; i++) {
        instance_state[i] = -1;
    }

    std::cout << "Subscribing to " << NUM_INSTANCES << " sensor instances...\n\n";
    int total_expected = NUM_INSTANCES * 5;
    int received = 0;

    while (received < total_expected) {
        if (waitset.wait(3s)) {
            while (auto data = reader->take_raw()) {
                KeyedData msg;
                if (msg.decode_cdr2_le(data->data(), data->size()) > 0) {
                    int prev_seq = instance_state[msg.id];
                    instance_state[msg.id] = msg.sequence_num;

                    std::cout << "  [Sensor " << msg.id << "] seq=" << msg.sequence_num
                              << " (prev=" << prev_seq << ") -> '" << msg.data << "'\n";
                    received++;
                }
            }
        } else {
            std::cout << "  (timeout)\n";
        }
    }

    std::cout << "\nFinal instance states:\n";
    for (const auto& [id, last_seq] : instance_state) {
        std::cout << "  Sensor " << id << ": last_seq=" << last_seq << "\n";
    }

    std::cout << "Done.\n";
}

int main(int argc, char** argv) {
    bool is_publisher = (argc > 1 && std::strcmp(argv[1], "pub") == 0);

    try {
        hdds::logging::init(hdds::LogLevel::Warn);

        std::cout << std::string(60, '=') << "\n";
        std::cout << "Instance Keys Demo\n";
        std::cout << "Simulating " << NUM_INSTANCES << " sensor instances with keyed data\n";
        std::cout << std::string(60, '=') << "\n";

        hdds::Participant participant("InstanceKeysDemo");

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
