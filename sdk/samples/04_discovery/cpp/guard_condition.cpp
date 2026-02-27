// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * HDDS Sample: Guard Condition (C++)
 *
 * Demonstrates manual event signaling with GuardConditions.
 * A background thread triggers a guard condition after a delay,
 * waking the main thread's WaitSet.
 *
 * Build:
 *     cd build && cmake .. && make guard_condition
 *
 * Usage:
 *     ./guard_condition
 *
 * Expected output:
 *     [OK] GuardCondition created
 *     [OK] Attached to WaitSet
 *     Waiting for trigger (background thread will fire in 2s)...
 *     [TRIGGER] Guard condition triggered from background thread
 *     [WAKE] GuardCondition fired!
 *
 * Key concepts:
 * - GuardCondition for application-level signaling
 * - RAII-based resource management
 * - Cross-thread triggering with std::thread
 */

#include <hdds.hpp>
#include <iostream>
#include <thread>
#include <chrono>

using namespace std::chrono_literals;

constexpr int TRIGGER_DELAY_SEC = 2;

int main() {
    std::cout << std::string(60, '=') << "\n";
    std::cout << "Guard Condition Demo\n";
    std::cout << "Manual event signaling via GuardCondition\n";
    std::cout << std::string(60, '=') << "\n\n";

    try {
        hdds::logging::init(hdds::LogLevel::Warn);

        // Create participant
        hdds::Participant participant("GuardCondDemo");
        std::cout << "[OK] Participant created\n";

        // Create guard condition
        hdds::GuardCondition guard;
        std::cout << "[OK] GuardCondition created (trigger_value=false)\n";

        // Create WaitSet and attach guard condition
        hdds::WaitSet waitset;
        waitset.attach(guard);
        std::cout << "[OK] GuardCondition attached to WaitSet\n\n";

        // Spawn background trigger thread
        std::thread trigger_thread([&guard]() {
            std::cout << "[THREAD] Sleeping " << TRIGGER_DELAY_SEC
                      << " seconds before triggering...\n";
            std::this_thread::sleep_for(std::chrono::seconds(TRIGGER_DELAY_SEC));
            std::cout << "[TRIGGER] Guard condition triggered from background thread\n";
            guard.trigger();
        });

        // Wait on WaitSet - blocks until guard is triggered
        std::cout << "Waiting for trigger (background thread will fire in "
                  << TRIGGER_DELAY_SEC << "s)...\n\n";

        if (waitset.wait(5s)) {
            std::cout << "[WAKE] GuardCondition fired!\n";
        } else {
            std::cout << "[TIMEOUT] Guard condition was not triggered in time\n";
        }

        // GuardCondition auto-resets after WaitSet wakes
        std::cout << "[OK] GuardCondition consumed by WaitSet\n";

        // Second trigger cycle (immediate)
        std::cout << "\n--- Second trigger (immediate) ---\n\n";

        guard.trigger();
        std::cout << "[TRIGGER] Guard condition set to true (immediate)\n";

        if (waitset.wait(1s)) {
            std::cout << "[WAKE] Immediate trigger detected!\n";
        }

        // Wait for thread
        trigger_thread.join();

        // Cleanup (RAII handles WaitSet, guard, participant)
        std::cout << "\n--- Cleanup ---\n";
        waitset.detach(guard);
        std::cout << "[OK] GuardCondition detached (RAII handles the rest)\n";

    } catch (const hdds::Error& e) {
        std::cerr << "HDDS Error: " << e.what() << std::endl;
        return 1;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    std::cout << "\n=== Guard Condition Demo Complete ===\n";
    return 0;
}
