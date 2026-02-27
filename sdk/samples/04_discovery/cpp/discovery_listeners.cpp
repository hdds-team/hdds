// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * Discovery Listeners Sample - Demonstrates callback-based event monitoring
 *
 * This sample shows two approaches to event handling:
 * 1. WaitSet (polling) - used for data reception
 * 2. Callback listeners (hdds_listener.hpp) - used for match/status events
 *
 * Key concepts:
 * - ReaderListener / WriterListener virtual callbacks
 * - set_listener() / clear_listener() for installing callbacks
 * - WaitSet for event-driven data reception
 */

#include <hdds.hpp>
#include <hdds_listener.hpp>
#include <iostream>
#include <string>
#include <chrono>
#include <thread>
#include <atomic>
#include <cstdint>

using namespace std::chrono_literals;

// =============================================================================
// Callback listeners (override only the methods you care about)
// =============================================================================

class MyReaderListener : public hdds::ReaderListener {
public:
    std::atomic<int> match_count{0};

    void on_subscription_matched(const hdds::SubscriptionMatchedStatus& s) override {
        match_count = static_cast<int>(s.current_count);
        std::cout << "[LISTENER] Reader matched "
                  << s.current_count << " writer(s)"
                  << " (change: " << s.current_count_change << ")\n";
    }

    void on_data_available(const uint8_t* /*data*/, size_t len) override {
        std::cout << "[LISTENER] Data available: " << len << " bytes\n";
    }
};

class MyWriterListener : public hdds::WriterListener {
public:
    std::atomic<int> match_count{0};

    void on_publication_matched(const hdds::PublicationMatchedStatus& s) override {
        match_count = static_cast<int>(s.current_count);
        std::cout << "[LISTENER] Writer matched "
                  << s.current_count << " reader(s)"
                  << " (change: " << s.current_count_change << ")\n";
    }
};

// =============================================================================

int main() {
    std::cout << "=== HDDS Discovery Listeners Sample ===\n\n";

    try {
        hdds::logging::init(hdds::LogLevel::Warn);

        hdds::Participant participant("DiscoveryListeners");
        std::cout << "[OK] Participant created: " << participant.name() << "\n";

        auto qos = hdds::QoS::reliable().transient_local().history_depth(10);

        // Create writer and reader (raw API since we don't need typed for this demo)
        auto writer = participant.create_writer_raw("ListenerDemo", qos);
        auto reader = participant.create_reader_raw("ListenerDemo", qos);
        std::cout << "[OK] Writer + Reader created on topic 'ListenerDemo'\n";

        // --- Install callback listeners ---
        MyReaderListener reader_listener;
        MyWriterListener writer_listener;
        hdds::set_listener(reader->c_handle(), &reader_listener);
        hdds::set_listener(writer->c_handle(), &writer_listener);
        std::cout << "[OK] Listeners installed\n\n";

        // Give discovery time to match
        std::this_thread::sleep_for(500ms);

        // Send some messages
        for (int i = 1; i <= 5; i++) {
            std::string payload = "Message #" + std::to_string(i);
            writer->write_raw(
                reinterpret_cast<const uint8_t*>(payload.data()),
                payload.size());
            std::cout << "[SENT] " << payload << "\n";
            std::this_thread::sleep_for(200ms);
        }

        // Read messages via WaitSet (complementary to callback listeners)
        hdds::WaitSet waitset;
        waitset.attach(reader->get_status_condition());

        int received = 0;
        while (waitset.wait(2s)) {
            while (auto data = reader->take_raw()) {
                std::string msg(reinterpret_cast<const char*>(data->data()), data->size());
                received++;
                std::cout << "[RECV] " << msg << "\n";
            }
        }

        // --- Clean up listeners before destruction ---
        hdds::clear_listener(reader->c_handle());
        hdds::clear_listener(writer->c_handle());

        std::cout << "\n--- Summary ---\n";
        std::cout << "Messages sent: 5\n";
        std::cout << "Messages received: " << received << "\n";
        std::cout << "Reader matched writers: " << reader_listener.match_count.load() << "\n";
        std::cout << "Writer matched readers: " << writer_listener.match_count.load() << "\n";
        std::cout << "\n=== Sample Complete ===\n";

    } catch (const hdds::Error& e) {
        std::cerr << "HDDS Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
