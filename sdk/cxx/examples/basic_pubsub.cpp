// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * @file basic_pubsub.cpp
 * @brief Basic HDDS C++ pub/sub example using typed API
 *
 * Demonstrates the typed DataWriter/DataReader template API
 * with automatic CDR2 serialization. This is the recommended
 * approach for C++ — see create_writer_raw() for manual buffer
 * management if needed.
 */

#include <hdds.hpp>
#include <iostream>
#include <thread>
#include <chrono>
#include <cstdint>
#include <string>

// Simple inline type with CDR2 codec (normally hddsgen-generated)
struct HelloWorld {
    std::int32_t id = 0;
    std::string message;

    int encode_cdr2_le(std::uint8_t* dst, std::size_t cap) const noexcept {
        std::size_t offset = 0;
        // id (i32)
        if (cap < offset + 4) return -1;
        std::memcpy(dst + offset, &id, 4);
        offset += 4;
        // message length (u32) + bytes
        auto len = static_cast<std::uint32_t>(message.size());
        if (cap < offset + 4 + len) return -1;
        std::memcpy(dst + offset, &len, 4);
        offset += 4;
        std::memcpy(dst + offset, message.data(), len);
        offset += len;
        return static_cast<int>(offset);
    }

    int decode_cdr2_le(const std::uint8_t* src, std::size_t len) noexcept {
        std::size_t offset = 0;
        if (len < offset + 4) return -1;
        std::memcpy(&id, src + offset, 4);
        offset += 4;
        if (len < offset + 4) return -1;
        std::uint32_t slen = 0;
        std::memcpy(&slen, src + offset, 4);
        offset += 4;
        if (len < offset + slen) return -1;
        message.assign(reinterpret_cast<const char*>(src + offset), slen);
        offset += slen;
        return static_cast<int>(offset);
    }
};

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

        // Typed writer — CDR2 serialization is automatic
        auto writer = participant.create_writer<HelloWorld>("HelloWorld", qos);
        std::cout << "Created typed writer on: " << writer.topic_name() << std::endl;

        // Typed reader — CDR2 deserialization is automatic
        auto reader = participant.create_reader<HelloWorld>("HelloWorld", qos);
        std::cout << "Created typed reader on: " << reader.topic_name() << std::endl;

        // Wait for discovery
        std::this_thread::sleep_for(std::chrono::seconds(1));

        // Publish typed data — no manual buffer management
        writer.write(HelloWorld{42, "Hello from C++!"});
        std::cout << "Published: id=42, message=Hello from C++!" << std::endl;

        // Read typed data — returns std::optional<HelloWorld>
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        auto msg = reader.take();
        if (msg) {
            std::cout << "Received: id=" << msg->id
                      << ", message=" << msg->message << std::endl;
        } else {
            std::cout << "No data received" << std::endl;
        }

        return 0;
    } catch (const hdds::Error& e) {
        std::cerr << "HDDS error: " << e.what() << std::endl;
        return 1;
    }
}
