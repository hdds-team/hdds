/*
 * HDDS Micro - Complete Pub/Sub Example
 *
 * Demonstrates full DDS pub/sub with ESP32:
 *   - Publisher: publishes temperature readings
 *   - Subscriber: receives and displays commands
 *
 * This example shows how to use both writer and reader APIs.
 *
 * Hardware:
 *   - ESP32 (any variant)
 *   - HC-12 433MHz radio module (powered at 5V!)
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

// ============================================================================
// CONFIGURATION
// ============================================================================

// HC-12 serial port (ESP32 UART2)
#define HC12_SERIAL Serial2
#define HC12_BAUD   9600
#define HC12_RX_PIN 16
#define HC12_TX_PIN 17

// Node configuration
#define NODE_ID     0x42
#define DOMAIN_ID   0

// Topics
#define TOPIC_TEMPERATURE "sensor/temperature"
#define TOPIC_COMMAND     "device/command"

// Timing
#define PUBLISH_INTERVAL_MS 2000
#define READ_TIMEOUT_MS     100

// ============================================================================
// DATA STRUCTURES
// ============================================================================

// Temperature message structure
typedef struct {
    uint32_t sensor_id;
    float    temperature;
    uint64_t timestamp;
} TemperatureMsg;

// Command message structure
typedef struct {
    uint32_t command_id;
    int32_t  param1;
    int32_t  param2;
    char     name[32];
} CommandMsg;

// ============================================================================
// GLOBAL STATE
// ============================================================================

HddsMicroTransport*   g_transport   = NULL;
HddsMicroParticipant* g_participant = NULL;
HddsMicroWriter*      g_temp_writer = NULL;
HddsMicroReader*      g_cmd_reader  = NULL;

uint8_t g_rx_buffer[256];  // Receive buffer
uint8_t g_tx_buffer[256];  // Transmit buffer

// ============================================================================
// UART CALLBACKS
// ============================================================================

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
        if (timeout_ms == 0 && !HC12_SERIAL.available()) {
            break;
        }
    }

    return received;
}

// ============================================================================
// MESSAGE ENCODING/DECODING HELPERS
// ============================================================================

// Encode a TemperatureMsg into CDR format
int32_t encode_temperature(uint8_t* buf, size_t buf_len, const TemperatureMsg* msg) {
    int32_t pos = 0;
    int32_t len;

    // sensor_id (u32)
    len = hdds_micro_encode_u32(buf + pos, buf_len - pos, msg->sensor_id);
    if (len < 0) return -1;
    pos += len;

    // temperature (f32)
    len = hdds_micro_encode_f32(buf + pos, buf_len - pos, msg->temperature);
    if (len < 0) return -1;
    pos += len;

    // timestamp (u64)
    len = hdds_micro_encode_u64(buf + pos, buf_len - pos, msg->timestamp);
    if (len < 0) return -1;
    pos += len;

    return pos;
}

// Decode a CommandMsg from CDR format
int32_t decode_command(const uint8_t* buf, size_t buf_len, CommandMsg* msg) {
    int32_t pos = 0;
    int32_t len;

    // command_id (u32)
    len = hdds_micro_decode_u32(buf + pos, buf_len - pos, &msg->command_id);
    if (len < 0) return -1;
    pos += len;

    // param1 (i32)
    len = hdds_micro_decode_i32(buf + pos, buf_len - pos, &msg->param1);
    if (len < 0) return -1;
    pos += len;

    // param2 (i32)
    len = hdds_micro_decode_i32(buf + pos, buf_len - pos, &msg->param2);
    if (len < 0) return -1;
    pos += len;

    // name (string)
    len = hdds_micro_decode_string(buf + pos, buf_len - pos, msg->name, sizeof(msg->name));
    if (len < 0) return -1;
    pos += len;

    return pos;
}

// ============================================================================
// INITIALIZATION
// ============================================================================

bool init_dds() {
    Serial.println("Initializing HDDS Micro...");

    // Create transport
    g_transport = hdds_micro_transport_create_serial(
        uart_write, uart_read, NODE_ID, NULL
    );
    if (!g_transport) {
        Serial.println("[ERROR] Failed to create transport");
        return false;
    }
    Serial.println("[OK] Transport created");

    // Create participant
    g_participant = hdds_micro_participant_create(DOMAIN_ID, g_transport);
    if (!g_participant) {
        Serial.println("[ERROR] Failed to create participant");
        return false;
    }
    Serial.printf("[OK] Participant created (domain=%d)\n",
                  hdds_micro_participant_domain_id(g_participant));

    // Create temperature writer (publisher)
    g_temp_writer = hdds_micro_writer_create(g_participant, TOPIC_TEMPERATURE, NULL);
    if (!g_temp_writer) {
        Serial.println("[ERROR] Failed to create temperature writer");
        return false;
    }
    Serial.printf("[OK] Writer created: %s\n", TOPIC_TEMPERATURE);

    // Create command reader (subscriber)
    g_cmd_reader = hdds_micro_reader_create(g_participant, TOPIC_COMMAND, NULL);
    if (!g_cmd_reader) {
        Serial.println("[ERROR] Failed to create command reader");
        return false;
    }
    Serial.printf("[OK] Reader created: %s\n", TOPIC_COMMAND);

    return true;
}

void cleanup_dds() {
    if (g_cmd_reader) {
        hdds_micro_reader_destroy(g_cmd_reader);
        g_cmd_reader = NULL;
    }
    if (g_temp_writer) {
        hdds_micro_writer_destroy(g_temp_writer);
        g_temp_writer = NULL;
    }
    if (g_participant) {
        hdds_micro_participant_destroy(g_participant);
        g_participant = NULL;
    }
    // Note: transport is owned by participant, destroyed with it
    g_transport = NULL;
}

// ============================================================================
// PUBLISH/SUBSCRIBE
// ============================================================================

void publish_temperature() {
    static uint32_t seq = 0;
    seq++;

    // Prepare message
    TemperatureMsg msg;
    msg.sensor_id = NODE_ID;
    msg.temperature = 20.0f + (seq % 100) * 0.1f;  // Simulate temperature
    msg.timestamp = millis();

    // Encode to CDR
    int32_t len = encode_temperature(g_tx_buffer, sizeof(g_tx_buffer), &msg);
    if (len < 0) {
        Serial.println("[ERROR] Failed to encode temperature message");
        return;
    }

    // Publish
    HddsMicroError err = hdds_micro_write(g_temp_writer, g_tx_buffer, len);
    if (err == HDDS_MICRO_ERROR_OK) {
        Serial.printf("[PUB] seq=%lu temp=%.2f C ts=%llu\n",
                      seq, msg.temperature, msg.timestamp);
    } else {
        Serial.printf("[ERROR] Write failed: %s\n", hdds_micro_error_str(err));
    }
}

void check_commands() {
    size_t len = 0;
    HddsMicroSampleInfo info;

    // Try to read (non-blocking)
    HddsMicroError err = hdds_micro_read(
        g_cmd_reader,
        g_rx_buffer,
        sizeof(g_rx_buffer),
        &len,
        &info
    );

    if (err == HDDS_MICRO_ERROR_OK && len > 0) {
        // Decode command
        CommandMsg cmd;
        if (decode_command(g_rx_buffer, len, &cmd) > 0) {
            Serial.println("----------------------------------------");
            Serial.printf("[SUB] Received command!\n");
            Serial.printf("      Command ID: %lu\n", cmd.command_id);
            Serial.printf("      Param1: %d\n", cmd.param1);
            Serial.printf("      Param2: %d\n", cmd.param2);
            Serial.printf("      Name: %s\n", cmd.name);
            Serial.printf("      Seq#: %lld\n", info.sequence_number);
            Serial.println("----------------------------------------");

            // Handle command
            handle_command(&cmd);
        } else {
            Serial.printf("[ERROR] Failed to decode command (len=%d)\n", len);
        }
    }
    // HDDS_MICRO_ERROR_TIMEOUT means no data available - this is normal
}

void handle_command(const CommandMsg* cmd) {
    switch (cmd->command_id) {
        case 1:  // LED control
            Serial.printf("-> LED command: state=%d\n", cmd->param1);
            // digitalWrite(LED_PIN, cmd->param1 ? HIGH : LOW);
            break;

        case 2:  // Set publish interval
            Serial.printf("-> Set interval: %d ms\n", cmd->param1);
            // g_publish_interval = cmd->param1;
            break;

        case 3:  // Reboot
            Serial.println("-> Reboot requested!");
            // ESP.restart();
            break;

        default:
            Serial.printf("-> Unknown command: %lu\n", cmd->command_id);
            break;
    }
}

// ============================================================================
// MAIN
// ============================================================================

void setup() {
    // Debug serial
    Serial.begin(115200);
    while (!Serial) delay(10);

    Serial.println();
    Serial.println("========================================");
    Serial.println("  HDDS Micro - Pub/Sub Example");
    Serial.print("  Version: ");
    Serial.println(hdds_micro_version());
    Serial.println("========================================");
    Serial.println();

    // Initialize HC-12
    HC12_SERIAL.begin(HC12_BAUD, SERIAL_8N1, HC12_RX_PIN, HC12_TX_PIN);
    Serial.println("[OK] HC-12 initialized");

    // Initialize DDS
    if (!init_dds()) {
        Serial.println("\n[FATAL] DDS initialization failed!");
        while (1) delay(1000);
    }

    Serial.println("\n[READY] Publishing temperature, waiting for commands...\n");
}

void loop() {
    static unsigned long last_publish = 0;

    // Publish temperature periodically
    if (millis() - last_publish >= PUBLISH_INTERVAL_MS) {
        last_publish = millis();
        publish_temperature();
    }

    // Check for incoming commands (non-blocking)
    check_commands();

    // Small delay to prevent busy-loop
    delay(10);
}
