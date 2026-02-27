// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * Authentication Sample - Demonstrates PKI-based participant authentication concepts
 *
 * This sample teaches DDS Security authentication concepts:
 * - Certificate-based identity (X.509)
 * - CA trust chain validation
 * - Mutual authentication between participants
 *
 * Note: HDDS security plugins are not yet fully implemented.
 * This sample demonstrates concepts while using basic HDDS pub/sub.
 *
 * Key concepts:
 * - Identity Certificate and Private Key
 * - Certificate Authority (CA) for trust
 * - Authentication plugin configuration
 *
 * NOTE: CONCEPT DEMO - This sample demonstrates the APPLICATION PATTERN for DDS Security Authentication.
 * The native DDS Security Authentication API is not yet exported to the C/C++/Python SDK.
 * This sample uses standard participant/writer/reader API to show the concept.
 *
 * Usage:
 *     # Terminal 1 - Subscriber
 *     ./authentication Participant1
 *
 *     # Terminal 2 - Publisher
 *     ./authentication Participant2 pub
 */

#include <hdds.hpp>
#include <iostream>
#include <string>
#include <filesystem>
#include <chrono>
#include <thread>
#include <cstring>

#include "generated/HelloWorld.hpp"

namespace fs = std::filesystem;
using namespace hdds_samples;
using namespace std::chrono_literals;

std::string get_certs_dir() {
    return "../certs";
}

void print_cert_info(const std::string& label, const std::string& path) {
    std::cout << "  " << label << ": " << path;
    if (fs::exists(path)) {
        std::cout << " [OK]\n";
    } else {
        std::cout << " [NOT FOUND]\n";
    }
}

void print_authentication_concepts() {
    std::cout << "\n--- DDS Security Authentication Concepts ---\n";
    std::cout << "Authentication uses X.509 PKI:\n";
    std::cout << "1. Each participant has an identity certificate\n";
    std::cout << "2. Certificates are signed by a trusted CA\n";
    std::cout << "3. Participants validate each other's certificates\n";
    std::cout << "4. Only authenticated participants can communicate\n\n";

    std::cout << "Certificate files typically include:\n";
    std::cout << "  - ca_cert.pem:          Certificate Authority public cert\n";
    std::cout << "  - participant_cert.pem: Participant's identity certificate\n";
    std::cout << "  - participant_key.pem:  Participant's private key\n\n";

    std::cout << "Authentication handshake:\n";
    std::cout << "  1. Participant A sends certificate to B\n";
    std::cout << "  2. B validates A's cert against CA\n";
    std::cout << "  3. B sends its certificate to A\n";
    std::cout << "  4. A validates B's cert against CA\n";
    std::cout << "  5. Mutual authentication complete\n\n";
}

void run_publisher(hdds::Participant& participant, const std::string& participant_name) {
    std::cout << "Creating writer for 'AuthenticatedTopic'...\n";
    auto writer = participant.create_writer_raw("AuthenticatedTopic");

    std::cout << "[OK] DataWriter created\n\n";

    std::cout << "--- Sending Authenticated Messages ---\n";
    std::cout << "(In a secure DDS system, these would be cryptographically signed)\n\n";

    for (int i = 1; i <= 5; ++i) {
        std::string msg_text = "Authenticated message from " + participant_name;
        HelloWorld msg(i, msg_text);
        auto data = msg.serialize();

        std::cout << "[SEND] " << msg.message << " (id=" << msg.id << ")\n";
        std::cout << "       Identity: CN=" << participant_name << ",O=HDDS,C=US\n";

        writer->write_raw(data);

        std::this_thread::sleep_for(2s);
    }
}

void run_subscriber(hdds::Participant& participant, const std::string& participant_name) {
    std::cout << "Creating reader for 'AuthenticatedTopic'...\n";
    auto reader = participant.create_reader_raw("AuthenticatedTopic");

    std::cout << "[OK] DataReader created\n\n";

    std::cout << "--- Waiting for Authenticated Messages ---\n";
    std::cout << "(In a secure DDS system, sender identity would be verified)\n\n";

    hdds::WaitSet waitset;
    waitset.attach(reader->get_status_condition());

    int received = 0;
    while (received < 5) {
        if (waitset.wait(5s)) {
            auto data = reader->take_raw();
            if (data) {
                auto msg = HelloWorld::deserialize(data->data(), data->size());
                std::cout << "[RECV] " << msg.message << " (id=" << msg.id << ")\n";
                std::cout << "       (Sender would be authenticated via certificate)\n";
                received++;
            }
        } else {
            std::cout << "  (waiting for authenticated peers...)\n";
        }
    }
}

int main(int argc, char* argv[]) {
    std::cout << "=== HDDS Authentication Sample ===\n\n";
    std::cout << "NOTE: CONCEPT DEMO - Native DDS Security Authentication API not yet in SDK.\n"
              << "      Using standard pub/sub API to demonstrate the pattern.\n\n";

    std::string participant_name = "Participant1";
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

    // Show security configuration (conceptual)
    std::cout << "Security Configuration (conceptual):\n";
    print_cert_info("CA Certificate", certs_dir + "/ca_cert.pem");
    print_cert_info("Identity Cert ", certs_dir + "/" + participant_name + "_cert.pem");
    print_cert_info("Private Key   ", certs_dir + "/" + participant_name + "_key.pem");

    print_authentication_concepts();

    try {
        // Initialize logging
        hdds::logging::init(hdds::LogLevel::Warn);

        // Create participant
        std::cout << "Creating DomainParticipant '" << participant_name << "'...\n";
        hdds::Participant participant(participant_name);

        std::cout << "[OK] Participant created\n";
        std::cout << "     (In secure mode, identity would be validated by CA)\n\n";

        // Simulated authentication status
        std::cout << "Authentication Status (simulated):\n";
        std::cout << "  Authenticated: YES\n";
        std::cout << "  Local Identity: CN=" << participant_name << ",O=HDDS,C=US\n";
        std::cout << "  Status: AUTHENTICATED\n\n";

        if (is_publisher) {
            run_publisher(participant, participant_name);
        } else {
            run_subscriber(participant, participant_name);
        }

        // Show authentication summary
        std::cout << "\n--- Authentication Summary ---\n";
        std::cout << "This participant: " << participant_name << "\n";
        std::cout << "Mode: " << (is_publisher ? "Publisher" : "Subscriber") << "\n";
        std::cout << "\nDDS Security Authentication provides:\n";
        std::cout << "  - Identity verification via X.509 certificates\n";
        std::cout << "  - Rejection of unauthenticated participants\n";
        std::cout << "  - Mutual authentication (both sides verify)\n";
        std::cout << "  - Protection against impersonation\n";

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
