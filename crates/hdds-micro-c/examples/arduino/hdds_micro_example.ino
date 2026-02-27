/*
 * HDDS Micro - Arduino Example
 *
 * Demonstrates using HDDS Micro SDK with ESP32 and HC-12 radio.
 * Publishes temperature readings over DDS/RTPS protocol.
 *
 * Hardware:
 *   - ESP32 (any variant)
 *   - HC-12 433MHz radio module (powered at 5V!)
 *   - Optional: DHT22 temperature sensor
 *
 * Wiring (HC-12):
 *   HC-12 VCC -> 5V (external supply)
 *   HC-12 GND -> GND (common ground)
 *   HC-12 TX  -> ESP32 GPIO16 (RX2)
 *   HC-12 RX  -> ESP32 GPIO17 (TX2)
 *
 * Copyright (c) 2025-2026 naskel.com
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

#include "hdds_micro.h"

// HC-12 serial port (ESP32 UART2)
#define HC12_SERIAL Serial2
#define HC12_BAUD   9600
#define HC12_RX_PIN 16
#define HC12_TX_PIN 17

// Node ID (unique per device)
#define NODE_ID 0x42

// Global handles
HddsMicroTransport* transport = NULL;
HddsMicroParticipant* participant = NULL;
HddsMicroWriter* temp_writer = NULL;

// UART callbacks for transport
int32_t uart_write(const uint8_t* data, size_t len, void* user_data) {
    return HC12_SERIAL.write(data, len);
}

int32_t uart_read(uint8_t* buf, size_t max_len, uint32_t timeout_ms, void* user_data) {
    unsigned long start = millis();
    size_t received = 0;

    while (received < max_len) {
        if (HC12_SERIAL.available()) {
            buf[received++] = HC12_SERIAL.read();
        }

        // Check timeout (0 = non-blocking)
        if (timeout_ms > 0 && (millis() - start) >= timeout_ms) {
            break;
        }

        // Non-blocking: return immediately if no data
        if (timeout_ms == 0 && received == 0) {
            break;
        }
    }

    return received;
}

void setup() {
    // Debug serial
    Serial.begin(115200);
    while (!Serial) delay(10);

    Serial.println("========================================");
    Serial.println("  HDDS Micro - Arduino Example");
    Serial.print("  Version: ");
    Serial.println(hdds_micro_version());
    Serial.println("========================================");

    // Initialize HC-12 serial
    HC12_SERIAL.begin(HC12_BAUD, SERIAL_8N1, HC12_RX_PIN, HC12_TX_PIN);
    Serial.println("[OK] HC-12 initialized");

    // Create transport using UART callbacks
    transport = hdds_micro_transport_create_serial(
        uart_write,
        uart_read,
        NODE_ID,
        NULL  // user_data
    );

    if (!transport) {
        Serial.println("[ERROR] Failed to create transport!");
        while (1) delay(1000);
    }
    Serial.println("[OK] Transport created");

    // Create DDS participant
    participant = hdds_micro_participant_create(0, transport);
    if (!participant) {
        Serial.println("[ERROR] Failed to create participant!");
        while (1) delay(1000);
    }
    Serial.printf("[OK] Participant created (domain=%d)\n",
                  hdds_micro_participant_domain_id(participant));

    // Create writer for temperature topic
    temp_writer = hdds_micro_writer_create(
        participant,
        "sensor/temperature",
        NULL  // default QoS
    );

    if (!temp_writer) {
        Serial.println("[ERROR] Failed to create writer!");
        while (1) delay(1000);
    }
    Serial.println("[OK] Writer created for topic: sensor/temperature");

    Serial.println("\nReady! Publishing temperature every 2 seconds...\n");
}

void loop() {
    static uint32_t seq = 0;
    static unsigned long last_publish = 0;

    // Publish every 2 seconds
    if (millis() - last_publish >= 2000) {
        last_publish = millis();
        seq++;

        // Simulate temperature (or read from sensor)
        float temperature = 20.0 + (seq % 100) * 0.1;
        uint64_t timestamp = millis();

        // Encode CDR payload: sensor_id(u32) + temperature(f32) + timestamp(u64)
        uint8_t buffer[64];
        int32_t pos = 0;
        int32_t len;

        // Encode sensor_id
        len = hdds_micro_encode_u32(buffer + pos, sizeof(buffer) - pos, NODE_ID);
        if (len < 0) {
            Serial.println("[ERROR] Failed to encode sensor_id");
            return;
        }
        pos += len;

        // Encode temperature
        len = hdds_micro_encode_f32(buffer + pos, sizeof(buffer) - pos, temperature);
        if (len < 0) {
            Serial.println("[ERROR] Failed to encode temperature");
            return;
        }
        pos += len;

        // Encode timestamp
        len = hdds_micro_encode_u64(buffer + pos, sizeof(buffer) - pos, timestamp);
        if (len < 0) {
            Serial.println("[ERROR] Failed to encode timestamp");
            return;
        }
        pos += len;

        // Write to DDS
        HddsMicroError err = hdds_micro_write(temp_writer, buffer, pos);

        if (err == HDDS_MICRO_ERROR_OK) {
            Serial.printf("[TX] seq=%d T=%.2f°C ts=%llu\n",
                          seq, temperature, timestamp);
        } else {
            Serial.printf("[ERROR] Write failed: %d\n", err);
        }
    }
}
