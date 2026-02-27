// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * HDDS Sample: Transport Priority (C++)
 *
 * Demonstrates TRANSPORT_PRIORITY QoS for network-level prioritization.
 * High-priority data (e.g. alarms) can be mapped to higher DSCP values,
 * enabling QoS-aware network infrastructure to prioritize delivery.
 *
 * Usage:
 *     ./transport_priority        # Subscriber (receives from both topics)
 *     ./transport_priority pub    # Publisher (sends alarms + telemetry)
 */

#include <hdds.hpp>
#include <iostream>
#include <thread>
#include <chrono>
#include <cstring>
#include <iomanip>

#include "generated/HelloWorld.hpp"

using namespace hdds_samples;
using namespace std::chrono_literals;
using Clock = std::chrono::steady_clock;

constexpr int NUM_MESSAGES = 5;
constexpr int PRIORITY_HIGH = 10;
constexpr int PRIORITY_LOW = 0;

void run_publisher(hdds::Participant& participant) {
    /* High-priority writer for alarms */
    auto qos_alarm = hdds::QoS::reliable()
        .transport_priority(PRIORITY_HIGH);
    auto writer_alarm = participant.create_writer<HelloWorld>("AlarmTopic", qos_alarm);

    /* Low-priority writer for telemetry */
    auto qos_telemetry = hdds::QoS::reliable()
        .transport_priority(PRIORITY_LOW);
    auto writer_telemetry = participant.create_writer<HelloWorld>("TelemetryTopic", qos_telemetry);

    std::cout << "Publishing bursts on two topics:\n";
    std::cout << "  - AlarmTopic:     priority=" << PRIORITY_HIGH
              << " (high - maps to higher DSCP)\n";
    std::cout << "  - TelemetryTopic: priority=" << PRIORITY_LOW
              << " (low  - best effort network)\n\n";

    auto start = Clock::now();

    /* Send telemetry burst first */
    std::cout << "Sending telemetry burst (priority=" << PRIORITY_LOW << ")...\n";
    for (int i = 0; i < NUM_MESSAGES; i++) {
        HelloWorld msg(i + 1, "Telemetry #" + std::to_string(i + 1));
        writer_telemetry.write(msg);

        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            Clock::now() - start).count();
        std::cout << "  [" << std::setw(5) << elapsed
                  << "ms] Sent Telemetry id=" << msg.id
                  << " (priority=" << PRIORITY_LOW << ")\n";
    }

    /* Send alarm burst immediately after */
    std::cout << "\nSending alarm burst (priority=" << PRIORITY_HIGH << ")...\n";
    for (int i = 0; i < NUM_MESSAGES; i++) {
        HelloWorld msg(i + 1, "ALARM #" + std::to_string(i + 1));
        writer_alarm.write(msg);

        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            Clock::now() - start).count();
        std::cout << "  [" << std::setw(5) << elapsed
                  << "ms] Sent Alarm     id=" << msg.id
                  << " (priority=" << PRIORITY_HIGH << ")\n";
    }

    auto total = std::chrono::duration_cast<std::chrono::milliseconds>(
        Clock::now() - start).count();
    std::cout << "\nAll messages sent in " << total << "ms.\n";
    std::cout << "On QoS-enabled networks, alarm traffic should arrive first.\n";
}

void run_subscriber(hdds::Participant& participant) {
    /* Create readers for both topics */
    auto qos_alarm = hdds::QoS::reliable()
        .transport_priority(PRIORITY_HIGH);
    auto reader_alarm = participant.create_reader<HelloWorld>("AlarmTopic", qos_alarm);

    auto qos_telemetry = hdds::QoS::reliable()
        .transport_priority(PRIORITY_LOW);
    auto reader_telemetry = participant.create_reader<HelloWorld>("TelemetryTopic", qos_telemetry);

    hdds::WaitSet waitset;
    waitset.attach(reader_alarm.get_status_condition());
    waitset.attach(reader_telemetry.get_status_condition());

    std::cout << "Subscribing to AlarmTopic (priority=" << PRIORITY_HIGH
              << ") and TelemetryTopic (priority=" << PRIORITY_LOW << ")...\n";
    std::cout << "Observing arrival order...\n\n";

    int recv_alarm = 0;
    int recv_telemetry = 0;
    int total_expected = NUM_MESSAGES * 2;
    int timeouts = 0;
    int order = 0;
    auto start = Clock::now();

    while ((recv_alarm + recv_telemetry) < total_expected && timeouts < 3) {
        if (waitset.wait(2s)) {
            while (auto msg = reader_alarm.take()) {
                auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                    Clock::now() - start).count();
                order++;
                std::cout << "  [" << std::setw(5) << elapsed
                          << "ms] #" << std::setw(2) << order
                          << " ALARM     id=" << msg->id
                          << " (priority=" << PRIORITY_HIGH << ")\n";
                recv_alarm++;
            }
            while (auto msg = reader_telemetry.take()) {
                auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                    Clock::now() - start).count();
                order++;
                std::cout << "  [" << std::setw(5) << elapsed
                          << "ms] #" << std::setw(2) << order
                          << " TELEMETRY id=" << msg->id
                          << " (priority=" << PRIORITY_LOW << ")\n";
                recv_telemetry++;
            }
            timeouts = 0;
        } else {
            timeouts++;
        }
    }

    std::cout << "\n" << std::string(60, '-') << "\n";
    std::cout << "Summary:\n";
    std::cout << "  Alarm messages (priority=" << PRIORITY_HIGH << "):     "
              << recv_alarm << " received\n";
    std::cout << "  Telemetry messages (priority=" << PRIORITY_LOW << "):  "
              << recv_telemetry << " received\n";
    std::cout << "\nNote: TRANSPORT_PRIORITY maps to DSCP values in IP headers.\n";
    std::cout << "Actual prioritization depends on OS socket options and\n";
    std::cout << "network infrastructure (routers/switches with QoS support).\n";
    std::cout << "On localhost, arrival order may not differ significantly.\n";
    std::cout << std::string(60, '-') << "\n";
}

int main(int argc, char** argv) {
    bool is_publisher = (argc > 1 && std::strcmp(argv[1], "pub") == 0);

    try {
        hdds::logging::init(hdds::LogLevel::Warn);

        std::cout << std::string(60, '=') << "\n";
        std::cout << "Transport Priority Demo\n";
        std::cout << "QoS: TRANSPORT_PRIORITY - network-level prioritization\n";
        std::cout << std::string(60, '=') << "\n";

        hdds::Participant participant("TransportPriorityDemo");

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
