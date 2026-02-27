// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * Access Control Sample - Demonstrates DDS Security permissions concepts
 *
 * This sample teaches DDS Security access control concepts:
 * - Governance document (domain-level rules)
 * - Permissions document (participant-level rules)
 * - Topic read/write permissions
 * - Domain and partition access
 *
 * Note: HDDS security plugins are not yet fully implemented.
 * This sample demonstrates concepts while using basic HDDS pub/sub.
 *
 * Key concepts:
 * - Governance XML defines domain security policies
 * - Permissions XML defines per-participant access rights
 * - Signed permissions for tamper protection
 *
 * NOTE: CONCEPT DEMO - This sample demonstrates the APPLICATION PATTERN for DDS Security Access Control.
 * The native DDS Security Access Control API is not yet exported to the C/C++/Python SDK.
 * This sample uses standard participant/writer/reader API to show the concept.
 *
 * Usage:
 *     # Terminal 1 - Subscriber
 *     ./access_control
 *
 *     # Terminal 2 - Publisher
 *     ./access_control pub
 */

#include <hdds.hpp>
#include <iostream>
#include <string>
#include <vector>
#include <chrono>
#include <thread>
#include <cstring>

#include "generated/HelloWorld.hpp"

using namespace hdds_samples;
using namespace std::chrono_literals;

void print_sample_governance() {
    std::cout << "Sample Governance Document:\n";
    std::cout << "  <domain_access_rules>\n";
    std::cout << "    <domain_rule>\n";
    std::cout << "      <domains><id>0</id></domains>\n";
    std::cout << "      <allow_unauthenticated_participants>false</allow_unauthenticated_participants>\n";
    std::cout << "      <enable_discovery_protection>true</enable_discovery_protection>\n";
    std::cout << "      <topic_access_rules>\n";
    std::cout << "        <topic_rule>\n";
    std::cout << "          <topic_expression>*</topic_expression>\n";
    std::cout << "          <enable_data_protection>true</enable_data_protection>\n";
    std::cout << "        </topic_rule>\n";
    std::cout << "      </topic_access_rules>\n";
    std::cout << "    </domain_rule>\n";
    std::cout << "  </domain_access_rules>\n\n";
}

void print_sample_permissions(const std::string& subject) {
    std::cout << "Sample Permissions Document for " << subject << ":\n";
    std::cout << "  <permissions>\n";
    std::cout << "    <grant name=\"ParticipantGrant\">\n";
    std::cout << "      <subject_name>" << subject << "</subject_name>\n";
    std::cout << "      <validity><not_before>2024-01-01</not_before></validity>\n";
    std::cout << "      <allow_rule>\n";
    std::cout << "        <domains><id>0</id></domains>\n";
    std::cout << "        <publish><topics><topic>SensorData</topic></topics></publish>\n";
    std::cout << "        <subscribe><topics><topic>*</topic></topics></subscribe>\n";
    std::cout << "      </allow_rule>\n";
    std::cout << "      <deny_rule>\n";
    std::cout << "        <domains><id>0</id></domains>\n";
    std::cout << "        <publish><topics><topic>RestrictedTopic</topic></topics></publish>\n";
    std::cout << "      </deny_rule>\n";
    std::cout << "    </grant>\n";
    std::cout << "  </permissions>\n\n";
}

bool check_permission(const std::string& topic, bool publish) {
    // Simulated permission check
    if (topic == "RestrictedTopic" && publish) {
        return false;
    }
    return true;
}

void run_publisher(hdds::Participant& participant) {
    std::cout << "--- Testing Topic Permissions ---\n\n";

    std::vector<std::string> test_topics = {
        "SensorData",
        "CommandTopic",
        "RestrictedTopic",
        "LogData"
    };

    for (const auto& topic : test_topics) {
        bool can_pub = check_permission(topic, true);
        bool can_sub = check_permission(topic, false);

        std::cout << "Topic '" << topic << "':\n";
        std::cout << "  Publish:   " << (can_pub ? "ALLOWED" : "DENIED") << "\n";
        std::cout << "  Subscribe: " << (can_sub ? "ALLOWED" : "DENIED") << "\n\n";
    }

    // Create writer for allowed topic
    std::cout << "--- Creating Endpoints ---\n\n";

    std::cout << "Creating writer for 'SensorData'...\n";
    if (check_permission("SensorData", true)) {
        auto writer = participant.create_writer_raw("SensorData");
        std::cout << "[OK] DataWriter created - permission granted\n\n";

        // Send some messages
        std::cout << "--- Sending Access-Controlled Messages ---\n\n";

        for (int i = 1; i <= 3; ++i) {
            HelloWorld msg(i, "Sensor reading from authorized publisher");
            auto data = msg.serialize();

            std::cout << "[SEND] " << msg.message << " (id=" << msg.id << ")\n";
            std::cout << "       Topic: SensorData (ALLOWED)\n";

            writer->write_raw(data);
            std::this_thread::sleep_for(1s);
        }
    }

    std::cout << "\nAttempting writer for 'RestrictedTopic'...\n";
    if (check_permission("RestrictedTopic", true)) {
        auto writer = participant.create_writer_raw("RestrictedTopic");
        std::cout << "[OK] DataWriter created\n";
    } else {
        std::cout << "[DENIED] No publish permission for this topic\n";
        std::cout << "         (In secure DDS, endpoint creation would fail)\n";
    }
}

void run_subscriber(hdds::Participant& participant) {
    std::cout << "Creating reader for 'SensorData'...\n";

    if (check_permission("SensorData", false)) {
        auto reader = participant.create_reader_raw("SensorData");
        std::cout << "[OK] DataReader created - permission granted\n\n";

        std::cout << "--- Waiting for Access-Controlled Messages ---\n\n";

        hdds::WaitSet waitset;
        waitset.attach(reader->get_status_condition());

        int received = 0;
        while (received < 3) {
            if (waitset.wait(5s)) {
                auto data = reader->take_raw();
                if (data) {
                    auto msg = HelloWorld::deserialize(data->data(), data->size());
                    std::cout << "[RECV] " << msg.message << " (id=" << msg.id << ")\n";
                    std::cout << "       (Sender's permissions verified by DDS Security)\n";
                    received++;
                }
            } else {
                std::cout << "  (waiting for authorized publishers...)\n";
            }
        }
    }
}

int main(int argc, char* argv[]) {
    std::cout << "=== HDDS Access Control Sample ===\n\n";
    std::cout << "NOTE: CONCEPT DEMO - Native DDS Security Access Control API not yet in SDK.\n"
              << "      Using standard pub/sub API to demonstrate the pattern.\n\n";

    bool is_publisher = false;
    for (int i = 1; i < argc; i++) {
        if (std::strcmp(argv[i], "pub") == 0 ||
            std::strcmp(argv[i], "publisher") == 0 ||
            std::strcmp(argv[i], "-p") == 0) {
            is_publisher = true;
        }
    }

    std::string participant_name = "SensorNode";
    std::string subject_name = "CN=SensorNode,O=HDDS,C=US";

    std::cout << "--- DDS Security Access Control Concepts ---\n";
    std::cout << "Access control uses two XML documents:\n";
    std::cout << "1. Governance: Domain-wide security policies\n";
    std::cout << "2. Permissions: Per-participant access rights\n\n";

    // Show example documents
    print_sample_governance();
    print_sample_permissions(subject_name);

    // Show configuration
    std::cout << "Access Control Configuration (conceptual):\n";
    std::cout << "  Governance:     ../certs/governance.xml\n";
    std::cout << "  Permissions:    ../certs/permissions.xml\n";
    std::cout << "  Permissions CA: ../certs/permissions_ca.pem\n\n";

    try {
        // Initialize logging
        hdds::logging::init(hdds::LogLevel::Warn);

        // Create participant
        std::cout << "Creating DomainParticipant with access control...\n";
        hdds::Participant participant(participant_name);

        std::cout << "[OK] Participant created: " << participant_name << "\n";
        std::cout << "     Subject: " << subject_name << "\n\n";

        if (is_publisher) {
            run_publisher(participant);
        } else {
            run_subscriber(participant);
        }

        // Summary
        std::cout << "\n--- Access Control Summary ---\n";
        std::cout << "Participant: " << participant_name << "\n";
        std::cout << "Subject DN: " << subject_name << "\n";
        std::cout << "\nDDS Security Access Control provides:\n";
        std::cout << "  - Fine-grained topic permissions (read/write)\n";
        std::cout << "  - Domain access restrictions\n";
        std::cout << "  - Partition-level access control\n";
        std::cout << "  - Signed permissions to prevent tampering\n";
        std::cout << "\nNote: Permissions are enforced at endpoint creation time.\n";
        std::cout << "      Attempts to access denied topics will fail.\n";

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
