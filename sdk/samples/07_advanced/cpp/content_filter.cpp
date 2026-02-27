// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * Content Filter Sample - Demonstrates content-filtered topics
 *
 * Content filters allow subscribers to receive only data matching
 * SQL-like filter expressions, reducing network and CPU overhead.
 *
 * Key concepts:
 * - ContentFilteredTopic creation
 * - SQL filter expressions
 * - Filter parameters
 * - Dynamic filter updates
 *
 * Note: HDDS implements content filtering at the application level.
 * This sample demonstrates the filtering pattern using the real
 * HDDS C++ API for pub/sub operations.
 *
 * NOTE: CONCEPT DEMO - This sample demonstrates the APPLICATION PATTERN for ContentFilteredTopic.
 * The native ContentFilteredTopic API is not yet exported to the C/C++/Python SDK.
 * This sample uses standard participant/writer/reader API to show the concept.
 */

#include <hdds.hpp>
#include <iostream>
#include <string>
#include <vector>
#include <random>
#include <ctime>
#include <iomanip>
#include <thread>
#include <chrono>
#include <cstring>
#include <functional>

#include "generated/HelloWorld.hpp"

using namespace hdds_samples;
using namespace std::chrono_literals;

// Sensor data structure for demonstration
struct SensorData {
    uint32_t sensor_id = 0;
    std::string location;
    float temperature = 0;
    float humidity = 0;
    uint64_t timestamp = 0;

    // Serialize to bytes for transmission
    std::vector<uint8_t> serialize() const {
        std::vector<uint8_t> data;
        // Simple serialization: id (4) + location (64) + temp (4) + humidity (4) + timestamp (8)
        data.resize(84);
        std::memcpy(data.data(), &sensor_id, 4);
        std::memset(data.data() + 4, 0, 64);
        std::memcpy(data.data() + 4, location.c_str(), std::min(location.size(), size_t(63)));
        std::memcpy(data.data() + 68, &temperature, 4);
        std::memcpy(data.data() + 72, &humidity, 4);
        std::memcpy(data.data() + 76, &timestamp, 8);
        return data;
    }

    static SensorData deserialize(const uint8_t* buf, size_t len) {
        SensorData s;
        if (len >= 84) {
            std::memcpy(&s.sensor_id, buf, 4);
            char loc[65] = {0};
            std::memcpy(loc, buf + 4, 64);
            s.location = loc;
            std::memcpy(&s.temperature, buf + 68, 4);
            std::memcpy(&s.humidity, buf + 72, 4);
            std::memcpy(&s.timestamp, buf + 76, 8);
        }
        return s;
    }
};

// Content filter definition - application-level filtering
class ContentFilter {
public:
    using FilterFunc = std::function<bool(const SensorData&)>;

    ContentFilter(const std::string& name, FilterFunc filter)
        : name_(name), filter_(filter) {}

    bool matches(const SensorData& data) const {
        return filter_(data);
    }

    const std::string& name() const { return name_; }

private:
    std::string name_;
    FilterFunc filter_;
};

void print_filter_info() {
    std::cout << "--- Content Filter Overview ---\n\n";
    std::cout << "Content filters use SQL-like WHERE clause syntax:\n\n";
    std::cout << "  Filter Expression          | Description\n";
    std::cout << "  ---------------------------|---------------------------\n";
    std::cout << "  temperature > 25.0         | High temperature readings\n";
    std::cout << "  location = 'Room1'         | Specific location only\n";
    std::cout << "  sensor_id BETWEEN 1 AND 10 | Sensor ID range\n";
    std::cout << "  humidity > %0              | Parameterized threshold\n";
    std::cout << "  location LIKE 'Building%'  | Pattern matching\n";
    std::cout << "\n";
    std::cout << "This sample demonstrates application-level filtering\n";
    std::cout << "using the HDDS C++ API for actual pub/sub transport.\n\n";
}

void run_publisher(hdds::Participant& participant) {
    std::cout << "Creating writer for SensorData topic..." << std::endl;
    auto writer = participant.create_writer_raw("SensorDataTopic", hdds::QoS::reliable());

    std::vector<std::string> locations = {"ServerRoom", "Office1", "Lobby", "DataCenter"};

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_real_distribution<> temp_dist(20.0, 40.0);
    std::uniform_real_distribution<> hum_dist(40.0, 80.0);

    std::cout << "\n--- Publishing Sensor Data ---\n\n";

    for (int i = 0; i < 10; i++) {
        SensorData data;
        data.sensor_id = i + 1;
        data.location = locations[i % 4];
        data.temperature = static_cast<float>(temp_dist(gen));
        data.humidity = static_cast<float>(hum_dist(gen));
        data.timestamp = static_cast<uint64_t>(std::time(nullptr));

        auto bytes = data.serialize();

        std::cout << std::fixed << std::setprecision(1);
        std::cout << "Publishing: sensor=" << data.sensor_id
                  << ", loc=" << data.location
                  << ", temp=" << data.temperature
                  << ", hum=" << data.humidity << "\n";

        writer->write_raw(bytes);
        std::this_thread::sleep_for(200ms);
    }

    std::cout << "\nDone publishing." << std::endl;
}

void run_subscriber(hdds::Participant& participant) {
    std::cout << "Creating reader for SensorData topic..." << std::endl;
    auto reader = participant.create_reader_raw("SensorDataTopic", hdds::QoS::reliable());

    // Create content filters (application-level)
    std::cout << "\n--- Creating Content Filters ---\n\n";

    ContentFilter high_temp_filter("HighTemperature", [](const SensorData& s) {
        return s.temperature > 30.0f;
    });
    std::cout << "[OK] Filter 1: temperature > 30.0 (high temperature alerts)\n";

    ContentFilter server_room_filter("ServerRoom", [](const SensorData& s) {
        return s.location == "ServerRoom";
    });
    std::cout << "[OK] Filter 2: location = 'ServerRoom'\n";

    ContentFilter alert_filter("EnvironmentAlert", [](const SensorData& s) {
        return s.temperature > 25.0f && s.humidity > 60.0f;
    });
    std::cout << "[OK] Filter 3: temperature > 25.0 AND humidity > 60.0\n\n";

    // Create waitset for efficient waiting
    hdds::WaitSet waitset;
    waitset.attach(reader->get_status_condition());

    std::cout << "--- Waiting for Sensor Data ---\n\n";

    int received = 0;
    int high_temp_matches = 0;
    int server_room_matches = 0;
    int alert_matches = 0;

    while (received < 10) {
        if (waitset.wait(5s)) {
            while (auto sample = reader->take_raw()) {
                auto data = SensorData::deserialize(sample->data(), sample->size());
                received++;

                std::cout << std::fixed << std::setprecision(1);
                std::cout << "Received: sensor=" << data.sensor_id
                          << ", loc=" << data.location
                          << ", temp=" << data.temperature
                          << ", hum=" << data.humidity;

                // Apply filters
                std::vector<std::string> matched_filters;
                if (high_temp_filter.matches(data)) {
                    matched_filters.push_back("HighTemp");
                    high_temp_matches++;
                }
                if (server_room_filter.matches(data)) {
                    matched_filters.push_back("ServerRoom");
                    server_room_matches++;
                }
                if (alert_filter.matches(data)) {
                    matched_filters.push_back("Alert");
                    alert_matches++;
                }

                if (!matched_filters.empty()) {
                    std::cout << " [MATCH:";
                    for (size_t i = 0; i < matched_filters.size(); i++) {
                        if (i > 0) std::cout << ",";
                        std::cout << matched_filters[i];
                    }
                    std::cout << "]";
                }
                std::cout << "\n";
            }
        } else {
            std::cout << "  (timeout - no messages)\n";
        }
    }

    // Summary
    std::cout << "\n--- Filter Summary ---\n\n";
    std::cout << "Total samples received: " << received << "\n";
    std::cout << "High temperature matches: " << high_temp_matches << "\n";
    std::cout << "ServerRoom matches: " << server_room_matches << "\n";
    std::cout << "Environment alert matches: " << alert_matches << "\n";
}

int main(int argc, char* argv[]) {
    std::cout << "=== HDDS Content Filter Sample ===\n\n";
    std::cout << "NOTE: CONCEPT DEMO - Native ContentFilteredTopic API not yet in SDK.\n"
              << "      Using standard pub/sub API to demonstrate the pattern.\n\n";

    bool is_publisher = (argc > 1) &&
        (std::strcmp(argv[1], "pub") == 0 ||
         std::strcmp(argv[1], "publisher") == 0 ||
         std::strcmp(argv[1], "-p") == 0);

    print_filter_info();

    try {
        // Initialize logging
        hdds::logging::init(hdds::LogLevel::Warn);

        // Create participant
        std::cout << "Creating participant..." << std::endl;
        hdds::Participant participant("ContentFilterDemo");
        std::cout << "[OK] Participant created\n\n";

        if (is_publisher) {
            run_publisher(participant);
        } else {
            run_subscriber(participant);
        }

        // Benefits summary
        std::cout << "\n--- Content Filter Benefits ---\n\n";
        std::cout << "1. Network Efficiency: Filtering at source reduces traffic\n";
        std::cout << "2. CPU Efficiency: Subscriber processes only relevant data\n";
        std::cout << "3. Flexibility: SQL-like expressions for complex filters\n";
        std::cout << "4. Dynamic Updates: Change filters without recreating readers\n";
        std::cout << "5. Parameterization: Use %0, %1 for runtime values\n";

        std::cout << "\n=== Sample Complete ===\n";

    } catch (const hdds::Error& e) {
        std::cerr << "HDDS Error: " << e.what() << std::endl;
        return 1;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
