// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * Secure Discovery Sample - Demonstrates authenticated discovery concepts
 *
 * This sample teaches DDS Security secure discovery concepts:
 * - Authenticated SPDP (Simple Participant Discovery Protocol)
 * - Discovery protection settings
 * - Liveliness with authentication
 * - Secure endpoint matching
 *
 * Note: HDDS security plugins are not yet fully implemented.
 * This sample demonstrates concepts while using basic HDDS pub/sub.
 *
 * Key concepts:
 * - Discovery protection in governance
 * - Authenticated participant announcements
 * - Secure builtin endpoints
 *
 * NOTE: CONCEPT DEMO - This sample demonstrates the APPLICATION PATTERN for DDS Security Secure Discovery.
 * The native DDS Security Secure Discovery API is not yet exported to the C/C++/Python SDK.
 * This sample uses standard participant/writer/reader API to show the concept.
 *
 * Usage:
 *     # Terminal 1 - Subscriber
 *     ./secure_discovery SecureNode1
 *
 *     # Terminal 2 - Publisher
 *     ./secure_discovery SecureNode2 pub
 */

#include <hdds.hpp>
#include <iostream>
#include <string>
#include <vector>
#include <chrono>
#include <thread>
#include <cstring>
#include <ctime>

#include "generated/HelloWorld.hpp"

using namespace hdds_samples;
using namespace std::chrono_literals;

std::string get_certs_dir() {
    return "../certs";
}

void print_discovery_security_info() {
    std::cout << "--- Secure Discovery Concepts ---\n\n";
    std::cout << "Standard SPDP sends participant info in plaintext.\n";
    std::cout << "Secure SPDP adds:\n";
    std::cout << "  1. Authentication of participant announcements\n";
    std::cout << "  2. Encryption of discovery metadata\n";
    std::cout << "  3. Rejection of unauthenticated participants\n";
    std::cout << "  4. Secure liveliness assertions\n\n";

    std::cout << "Governance Settings:\n";
    std::cout << "  <enable_discovery_protection>true</enable_discovery_protection>\n";
    std::cout << "  <enable_liveliness_protection>true</enable_liveliness_protection>\n";
    std::cout << "  <allow_unauthenticated_participants>false</allow_unauthenticated_participants>\n\n";

    std::cout << "Secure Discovery Process:\n";
    std::cout << "  1. Send authenticated SPDP announcement\n";
    std::cout << "  2. Receive and verify peer announcements\n";
    std::cout << "  3. Perform mutual authentication handshake\n";
    std::cout << "  4. Exchange encrypted endpoint info (SEDP)\n";
    std::cout << "  5. Establish secure data channels\n\n";
}

void run_publisher(hdds::Participant& participant, const std::string& participant_name) {
    std::cout << "Creating writer for 'SecureDiscoveryTopic'...\n";
    auto writer = participant.create_writer_raw("SecureDiscoveryTopic");

    std::cout << "[OK] DataWriter created\n\n";

    std::cout << "--- Broadcasting via Secure Discovery ---\n";
    std::cout << "(In secure DDS, discovery messages would be authenticated)\n\n";

    for (int i = 1; i <= 5; ++i) {
        std::string msg_text = "Secure broadcast from " + participant_name;
        HelloWorld msg(i, msg_text);
        auto data = msg.serialize();

        std::cout << "[BROADCAST] " << msg.message << " (id=" << msg.id << ")\n";
        std::cout << "            (Discovery: authenticated, SEDP: encrypted)\n";

        writer->write_raw(data);

        // Simulate discovery events
        if (i == 2) {
            std::cout << "\n[DISCOVERED] Authenticated Participant\n";
            std::cout << "  GUID:    01.0f.ab.cd.00.00.00.01\n";
            std::cout << "  Name:    SecurePeer1\n";
            std::cout << "  Subject: CN=SecurePeer1,O=HDDS,C=US\n";
            std::cout << "  Status:  AUTHENTICATED\n\n";
        }

        std::this_thread::sleep_for(2s);
    }
}

void run_subscriber(hdds::Participant& participant, const std::string& participant_name) {
    std::cout << "Creating reader for 'SecureDiscoveryTopic'...\n";
    auto reader = participant.create_reader_raw("SecureDiscoveryTopic");

    std::cout << "[OK] DataReader created\n\n";

    std::cout << "--- Waiting for Authenticated Peers ---\n";
    std::cout << "(In secure DDS, only authenticated peers can be discovered)\n\n";

    hdds::WaitSet waitset;
    waitset.attach(reader->get_status_condition());

    int received = 0;
    int discovery_events = 0;

    while (received < 5) {
        if (waitset.wait(3s)) {
            auto data = reader->take_raw();
            if (data) {
                auto msg = HelloWorld::deserialize(data->data(), data->size());
                std::cout << "[RECV] " << msg.message << " (id=" << msg.id << ")\n";
                std::cout << "       (Sender authenticated via secure discovery)\n\n";
                received++;
            }
        } else {
            discovery_events++;
            if (discovery_events == 1) {
                std::cout << "[DISCOVERY] Sending authenticated SPDP announcement...\n";
                std::cout << "            Subject: CN=" << participant_name << ",O=HDDS,C=US\n\n";
            } else if (discovery_events == 2) {
                std::cout << "[DISCOVERED] Authenticated Participant\n";
                std::cout << "  GUID:    01.0f.ab.cd.00.00.00.02\n";
                std::cout << "  Name:    SecurePublisher\n";
                std::cout << "  Subject: CN=SecurePublisher,O=HDDS,C=US\n";
                std::cout << "  Status:  AUTHENTICATED\n\n";
            } else {
                std::cout << "  (waiting for authenticated peers...)\n";
            }
        }
    }
}

int main(int argc, char* argv[]) {
    std::cout << "=== HDDS Secure Discovery Sample ===\n\n";
    std::cout << "NOTE: CONCEPT DEMO - Native DDS Security Secure Discovery API not yet in SDK.\n"
              << "      Using standard pub/sub API to demonstrate the pattern.\n\n";

    std::string participant_name = "SecureDiscovery";
    bool is_publisher = false;

    // Parse arguments
    for (int i = 1; i < argc; i++) {
        if (std::strcmp(argv[i], "pub") == 0 ||
            std::strcmp(argv[i], "publisher") == 0 ||
            std::strcmp(argv[i], "-p") == 0) {
            is_publisher = true;
        } else {
            participant_name = argv[i];
        }
    }

    std::string certs_dir = get_certs_dir();

    print_discovery_security_info();

    // Show secure discovery configuration (conceptual)
    std::cout << "Secure Discovery Configuration (conceptual):\n";
    std::cout << "  Discovery Protection:  ENABLED\n";
    std::cout << "  Liveliness Protection: ENABLED\n";
    std::cout << "  Allow Unauthenticated: NO\n";
    std::cout << "  Identity CA:           " << certs_dir << "/ca_cert.pem\n";
    std::cout << "  Identity Cert:         " << certs_dir << "/" << participant_name << "_cert.pem\n";
    std::cout << "  Private Key:           " << certs_dir << "/" << participant_name << "_key.pem\n\n";

    try {
        // Initialize logging
        hdds::logging::init(hdds::LogLevel::Warn);

        // Create participant
        std::cout << "Creating DomainParticipant with secure discovery...\n";
        hdds::Participant participant(participant_name);

        std::cout << "[OK] Participant created: " << participant_name << "\n";
        std::cout << "[OK] Secure discovery enabled (conceptual)\n";
        std::cout << "[OK] Builtin endpoints protected (conceptual)\n\n";

        if (is_publisher) {
            run_publisher(participant, participant_name);
        } else {
            run_subscriber(participant, participant_name);
        }

        // Show discovery summary
        std::cout << "\n--- Secure Discovery Summary ---\n\n";
        std::cout << "Simulated authenticated participants discovered: 2\n\n";

        std::cout << "Participant 1:\n";
        std::cout << "  Name: SecurePeer1\n";
        std::cout << "  Subject: CN=SecurePeer1,O=HDDS,C=US\n";
        std::cout << "  Authenticated: YES\n\n";

        std::cout << "Participant 2:\n";
        std::cout << "  Name: SecurePublisher\n";
        std::cout << "  Subject: CN=SecurePublisher,O=HDDS,C=US\n";
        std::cout << "  Authenticated: YES\n\n";

        std::cout << "Security Benefits:\n";
        std::cout << "  - Only trusted participants can join the domain\n";
        std::cout << "  - Discovery metadata is encrypted on the wire\n";
        std::cout << "  - Prevents rogue participant injection attacks\n";
        std::cout << "  - Protects endpoint information from eavesdropping\n";
        std::cout << "  - Liveliness assertions are authenticated\n";

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
