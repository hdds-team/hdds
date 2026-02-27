// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * Encryption Sample - Demonstrates DDS data encryption concepts
 *
 * This sample teaches DDS Security cryptographic protection:
 * - Data encryption (AES-GCM)
 * - Message authentication (GMAC)
 * - Key exchange protocols
 * - Per-topic encryption settings
 *
 * Note: HDDS security plugins are not yet fully implemented.
 * This sample demonstrates concepts while using basic HDDS pub/sub.
 *
 * Key concepts:
 * - Crypto plugin configuration
 * - Protection kinds (encrypt, sign, none)
 * - Shared secret key exchange
 *
 * NOTE: CONCEPT DEMO - This sample demonstrates the APPLICATION PATTERN for DDS Security Encryption.
 * The native DDS Security Encryption API is not yet exported to the C/C++/Python SDK.
 * This sample uses standard participant/writer/reader API to show the concept.
 *
 * Usage:
 *     # Terminal 1 - Subscriber
 *     ./encryption
 *
 *     # Terminal 2 - Publisher
 *     ./encryption pub
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

// Simulated protection kinds for educational purposes
enum class ProtectionKind {
    None,
    Sign,           // GMAC - integrity only
    Encrypt,        // AES-GCM - confidentiality + integrity
    SignEncrypt     // Sign then encrypt
};

std::string protection_kind_str(ProtectionKind kind) {
    switch (kind) {
        case ProtectionKind::None: return "NONE";
        case ProtectionKind::Sign: return "SIGN (GMAC)";
        case ProtectionKind::Encrypt: return "ENCRYPT (AES-GCM)";
        case ProtectionKind::SignEncrypt: return "SIGN+ENCRYPT";
        default: return "UNKNOWN";
    }
}

void print_crypto_info() {
    std::cout << "--- DDS Security Cryptography Concepts ---\n\n";
    std::cout << "Encryption Algorithms:\n";
    std::cout << "  - AES-128-GCM: Fast, hardware-accelerated encryption\n";
    std::cout << "  - AES-256-GCM: Stronger encryption for sensitive data\n";
    std::cout << "  - GMAC: Message authentication without encryption\n\n";

    std::cout << "Protection Levels:\n";
    std::cout << "  - RTPS Protection: Protects entire RTPS messages\n";
    std::cout << "  - Metadata Protection: Protects discovery information\n";
    std::cout << "  - Data Protection: Protects user data payload\n\n";

    std::cout << "Key Exchange:\n";
    std::cout << "  - DH + AES Key Wrap for shared secrets\n";
    std::cout << "  - Per-endpoint session keys\n";
    std::cout << "  - Key rotation supported\n\n";
}

void run_publisher(hdds::Participant& participant) {
    std::cout << "Creating writer for 'EncryptedTopic'...\n";
    auto writer = participant.create_writer_raw("EncryptedTopic");

    std::cout << "[OK] DataWriter created (data would be encrypted in secure mode)\n\n";

    std::cout << "--- Sending Encrypted Messages ---\n";
    std::cout << "(In secure DDS, these would be AES-GCM encrypted on the wire)\n\n";

    std::vector<std::string> sensitive_messages = {
        "Sensitive data: credit_card=4111-XXXX-XXXX-1111",
        "Private key: [REDACTED]",
        "Password: [REDACTED]",
        "API token: sk_test_EXAMPLE",
        "Patient record: SSN=000-00-0000"
    };

    for (size_t i = 0; i < sensitive_messages.size(); ++i) {
        HelloWorld msg(static_cast<int32_t>(i + 1), sensitive_messages[i]);
        auto data = msg.serialize();

        std::cout << "Original:    \"" << msg.message << "\"\n";
        std::cout << "Wire format: [AES-GCM encrypted, " << data.size() << " bytes + 16 byte auth tag]\n";
        std::cout << "[SENT] Message " << (i + 1) << " (would be encrypted)\n\n";

        writer->write_raw(data);
        std::this_thread::sleep_for(1s);
    }
}

void run_subscriber(hdds::Participant& participant) {
    std::cout << "Creating reader for 'EncryptedTopic'...\n";
    auto reader = participant.create_reader_raw("EncryptedTopic");

    std::cout << "[OK] DataReader created (data would be decrypted in secure mode)\n\n";

    std::cout << "--- Receiving Encrypted Messages ---\n";
    std::cout << "(In secure DDS, incoming data would be decrypted and verified)\n\n";

    hdds::WaitSet waitset;
    waitset.attach(reader->get_status_condition());

    int received = 0;
    while (received < 5) {
        if (waitset.wait(5s)) {
            auto data = reader->take_raw();
            if (data) {
                auto msg = HelloWorld::deserialize(data->data(), data->size());
                std::cout << "[RECV] Decrypted: \"" << msg.message << "\" (id=" << msg.id << ")\n";
                std::cout << "       (Authentication tag verified, integrity OK)\n\n";
                received++;
            }
        } else {
            std::cout << "  (waiting for encrypted messages...)\n";
        }
    }
}

int main(int argc, char* argv[]) {
    std::cout << "=== HDDS Encryption Sample ===\n\n";
    std::cout << "NOTE: CONCEPT DEMO - Native DDS Security Encryption API not yet in SDK.\n"
              << "      Using standard pub/sub API to demonstrate the pattern.\n\n";

    bool is_publisher = false;
    for (int i = 1; i < argc; i++) {
        if (std::strcmp(argv[i], "pub") == 0 ||
            std::strcmp(argv[i], "publisher") == 0 ||
            std::strcmp(argv[i], "-p") == 0) {
            is_publisher = true;
        }
    }

    print_crypto_info();

    // Show crypto configuration (conceptual)
    ProtectionKind rtps_protection = ProtectionKind::Encrypt;
    ProtectionKind metadata_protection = ProtectionKind::Sign;
    ProtectionKind data_protection = ProtectionKind::Encrypt;

    std::cout << "Crypto Configuration (conceptual):\n";
    std::cout << "  RTPS Protection:     " << protection_kind_str(rtps_protection) << "\n";
    std::cout << "  Metadata Protection: " << protection_kind_str(metadata_protection) << "\n";
    std::cout << "  Data Protection:     " << protection_kind_str(data_protection) << "\n\n";

    try {
        // Initialize logging
        hdds::logging::init(hdds::LogLevel::Warn);

        // Create participant
        std::cout << "Creating DomainParticipant with encryption...\n";
        hdds::Participant participant("EncryptedNode");

        std::cout << "[OK] Participant created\n";
        std::cout << "     (In secure mode, crypto keys would be established)\n\n";

        if (is_publisher) {
            run_publisher(participant);
        } else {
            run_subscriber(participant);
        }

        // Show encryption statistics (simulated)
        std::cout << "--- Encryption Statistics (simulated) ---\n\n";
        std::cout << "Bytes encrypted:     4096\n";
        std::cout << "Bytes decrypted:     2048\n";
        std::cout << "Messages sent:       5\n";
        std::cout << "Messages received:   5\n";
        std::cout << "Auth failures:       0\n";

        // Show protection comparison
        std::cout << "\n--- Protection Level Comparison ---\n\n";
        std::cout << "| Level          | Confidentiality | Integrity | Overhead |\n";
        std::cout << "|----------------|-----------------|-----------|----------|\n";
        std::cout << "| NONE           | No              | No        | 0 bytes  |\n";
        std::cout << "| SIGN (GMAC)    | No              | Yes       | 16 bytes |\n";
        std::cout << "| ENCRYPT (GCM)  | Yes             | Yes       | 16 bytes |\n";
        std::cout << "| SIGN+ENCRYPT   | Yes             | Yes       | 32 bytes |\n";

        std::cout << "\nRecommendations:\n";
        std::cout << "  - Use ENCRYPT for sensitive user data\n";
        std::cout << "  - Use SIGN for discovery metadata (performance)\n";
        std::cout << "  - Use NONE only for non-sensitive data in trusted networks\n";

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
