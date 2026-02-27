// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * Request-Reply Sample - Demonstrates RPC-style communication over DDS
 *
 * This sample shows how to implement request-reply patterns:
 * - Service with request/reply topics
 * - Correlation IDs for matching responses
 * - Timeout handling
 * - Multiple concurrent requests
 *
 * Key concepts:
 * - Requester: sends requests, waits for replies
 * - Replier: receives requests, sends replies
 * - Correlation: matching requests to replies
 *
 * Uses the real HDDS C++ API for pub/sub transport.
 */

#include <hdds.hpp>
#include <iostream>
#include <string>
#include <map>
#include <chrono>
#include <thread>
#include <cstring>
#include <ctime>
#include <atomic>

#include "generated/HelloWorld.hpp"

using namespace hdds_samples;
using namespace std::chrono_literals;

// Request message structure
struct Request {
    uint64_t request_id = 0;
    char client_id[32] = {0};
    char operation[32] = {0};
    char payload[128] = {0};
    uint64_t timestamp = 0;

    std::vector<uint8_t> serialize() const {
        std::vector<uint8_t> data(sizeof(Request));
        std::memcpy(data.data(), this, sizeof(Request));
        return data;
    }

    static Request deserialize(const uint8_t* buf, size_t len) {
        Request req;
        if (len >= sizeof(Request)) {
            std::memcpy(&req, buf, sizeof(Request));
        }
        return req;
    }
};

// Reply message structure
struct Reply {
    uint64_t request_id = 0;  // Correlation ID
    char client_id[32] = {0};
    int32_t status_code = 0;
    char result[128] = {0};
    uint64_t timestamp = 0;

    std::vector<uint8_t> serialize() const {
        std::vector<uint8_t> data(sizeof(Reply));
        std::memcpy(data.data(), this, sizeof(Reply));
        return data;
    }

    static Reply deserialize(const uint8_t* buf, size_t len) {
        Reply rep;
        if (len >= sizeof(Reply)) {
            std::memcpy(&rep, buf, sizeof(Reply));
        }
        return rep;
    }
};

// Service implementation
class CalculatorService {
public:
    Reply process(const Request& req) {
        Reply reply;
        reply.request_id = req.request_id;
        std::strncpy(reply.client_id, req.client_id, sizeof(reply.client_id) - 1);
        reply.timestamp = static_cast<uint64_t>(std::time(nullptr));

        std::string op(req.operation);
        std::string payload(req.payload);

        if (op == "add") {
            int a = 0, b = 0;
            std::sscanf(payload.c_str(), "%d %d", &a, &b);
            std::snprintf(reply.result, sizeof(reply.result), "%d", a + b);
            reply.status_code = 0;
        } else if (op == "echo") {
            std::strncpy(reply.result, payload.c_str(), sizeof(reply.result) - 1);
            reply.status_code = 0;
        } else if (op == "time") {
            std::snprintf(reply.result, sizeof(reply.result), "%lu",
                         static_cast<unsigned long>(std::time(nullptr)));
            reply.status_code = 0;
        } else {
            std::strncpy(reply.result, "Unknown operation", sizeof(reply.result) - 1);
            reply.status_code = -1;
        }

        return reply;
    }
};

void print_request_reply_overview() {
    std::cout << "--- Request-Reply Pattern ---\n\n";
    std::cout << "Request-Reply over DDS:\n\n";
    std::cout << "  Requester                     Replier\n";
    std::cout << "  ---------                     -------\n";
    std::cout << "      |                             |\n";
    std::cout << "      |---- Request (ID=1) ------->|\n";
    std::cout << "      |                             | process\n";
    std::cout << "      |<---- Reply (ID=1) ---------|\n";
    std::cout << "      |                             |\n";
    std::cout << "\n";
    std::cout << "Topics:\n";
    std::cout << "  - Calculator_Request: client -> service\n";
    std::cout << "  - Calculator_Reply: service -> client\n";
    std::cout << "\n";
    std::cout << "Correlation:\n";
    std::cout << "  - request_id: unique per request\n";
    std::cout << "  - client_id: identifies requester\n";
    std::cout << "\n";
}

void run_server(hdds::Participant& participant, CalculatorService& service) {
    std::cout << "[OK] Running as SERVICE (replier)\n\n";

    // Create request reader and reply writer
    auto request_reader = participant.create_reader_raw(
        "Calculator_Request", hdds::QoS::reliable());
    auto reply_writer = participant.create_writer_raw(
        "Calculator_Reply", hdds::QoS::reliable());

    // Create waitset for efficient waiting
    hdds::WaitSet waitset;
    waitset.attach(request_reader->get_status_condition());

    // Guard condition for shutdown
    hdds::GuardCondition shutdown_guard;
    waitset.attach(shutdown_guard);

    std::cout << "--- Service Ready ---\n";
    std::cout << "Listening for requests on 'Calculator_Request'...\n";
    std::cout << "(Run with 'pub' argument to send requests)\n\n";

    int requests_processed = 0;
    while (requests_processed < 10) {
        if (waitset.wait(5s)) {
            while (auto sample = request_reader->take_raw()) {
                auto req = Request::deserialize(sample->data(), sample->size());

                std::cout << "[REQUEST] ID=" << req.request_id
                          << ", Client=" << req.client_id
                          << ", Op=" << req.operation
                          << ", Payload='" << req.payload << "'\n";

                // Process and send reply
                Reply reply = service.process(req);
                auto reply_bytes = reply.serialize();
                reply_writer->write_raw(reply_bytes);

                std::cout << "[REPLY]   ID=" << reply.request_id
                          << ", Status=" << reply.status_code
                          << ", Result='" << reply.result << "'\n\n";

                requests_processed++;
            }
        } else {
            std::cout << "  (waiting for requests...)\n";
        }
    }

    std::cout << "Processed " << requests_processed << " requests.\n";
}

void run_client(hdds::Participant& participant, const std::string& client_id) {
    std::cout << "[OK] Running as CLIENT (requester): " << client_id << "\n\n";

    // Create request writer and reply reader
    auto request_writer = participant.create_writer_raw(
        "Calculator_Request", hdds::QoS::reliable());
    auto reply_reader = participant.create_reader_raw(
        "Calculator_Reply", hdds::QoS::reliable());

    // Create waitset for reply waiting
    hdds::WaitSet waitset;
    waitset.attach(reply_reader->get_status_condition());

    // Allow time for discovery
    std::cout << "Waiting for service discovery...\n";
    std::this_thread::sleep_for(1s);

    std::cout << "\n--- Sending Requests ---\n\n";

    // Track pending requests
    std::map<uint64_t, std::string> pending_requests;

    // Send requests
    std::vector<std::pair<std::string, std::string>> operations = {
        {"add", "10 20"},
        {"echo", "Hello DDS"},
        {"time", ""},
    };

    uint64_t next_id = 1;
    for (const auto& [op, payload] : operations) {
        Request req;
        req.request_id = next_id++;
        std::strncpy(req.client_id, client_id.c_str(), sizeof(req.client_id) - 1);
        std::strncpy(req.operation, op.c_str(), sizeof(req.operation) - 1);
        std::strncpy(req.payload, payload.c_str(), sizeof(req.payload) - 1);
        req.timestamp = static_cast<uint64_t>(std::time(nullptr));

        std::cout << "[SEND REQUEST] ID=" << req.request_id
                  << ", Op=" << req.operation
                  << ", Payload='" << req.payload << "'\n";

        pending_requests[req.request_id] = op;
        auto bytes = req.serialize();
        request_writer->write_raw(bytes);
    }

    // Wait for replies with timeout
    std::cout << "\n--- Waiting for Replies ---\n\n";

    auto start = std::chrono::steady_clock::now();
    auto timeout = 5s;

    while (!pending_requests.empty()) {
        auto elapsed = std::chrono::steady_clock::now() - start;
        if (elapsed >= timeout) {
            std::cout << "[TIMEOUT] No more replies received\n";
            break;
        }

        auto remaining = std::chrono::duration_cast<std::chrono::seconds>(timeout - elapsed);
        if (waitset.wait(remaining)) {
            while (auto sample = reply_reader->take_raw()) {
                auto reply = Reply::deserialize(sample->data(), sample->size());

                // Check if this reply is for us
                if (std::string(reply.client_id) != client_id) {
                    continue;
                }

                auto it = pending_requests.find(reply.request_id);
                if (it != pending_requests.end()) {
                    std::cout << "[GOT REPLY]    ID=" << reply.request_id
                              << ", Status=" << reply.status_code
                              << ", Result='" << reply.result << "'\n";
                    pending_requests.erase(it);
                }
            }
        }
    }

    if (!pending_requests.empty()) {
        std::cout << "\n[WARNING] " << pending_requests.size()
                  << " request(s) did not receive replies\n";
    }
}

int main(int argc, char* argv[]) {
    std::cout << "=== HDDS Request-Reply Sample ===\n\n";

    bool is_server = (argc > 1 && std::string(argv[1]) == "--server");
    bool is_client = (argc > 1) &&
        (std::strcmp(argv[1], "pub") == 0 ||
         std::strcmp(argv[1], "client") == 0 ||
         std::strcmp(argv[1], "-c") == 0);

    std::string client_id = (argc > 2) ? argv[2] : "Client1";

    print_request_reply_overview();

    try {
        // Initialize logging
        hdds::logging::init(hdds::LogLevel::Warn);

        // Create participant
        std::cout << "Creating participant..." << std::endl;
        hdds::Participant participant("RequestReplyDemo");
        std::cout << "[OK] Participant created\n\n";

        CalculatorService service;

        if (is_client) {
            run_client(participant, client_id);
        } else {
            // Default to server mode
            run_server(participant, service);
        }

        // Pattern variations
        std::cout << "\n--- Request-Reply Variations ---\n\n";
        std::cout << "1. Synchronous: Block until reply (simple)\n";
        std::cout << "2. Asynchronous: Callback on reply (non-blocking)\n";
        std::cout << "3. Future-based: Returns future, await later\n";
        std::cout << "4. Fire-and-forget: No reply expected\n";
        std::cout << "\n";

        std::cout << "--- Implementation Tips ---\n\n";
        std::cout << "1. Use content filter for client_id to receive only your replies\n";
        std::cout << "2. Include request_id for correlation\n";
        std::cout << "3. Set appropriate timeouts\n";
        std::cout << "4. Handle service unavailability gracefully\n";
        std::cout << "5. Consider retry logic for failed requests\n";

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
