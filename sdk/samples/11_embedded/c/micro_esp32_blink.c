// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * Micro ESP32 Blink - Subscribe to "cmd/led" and toggle GPIO
 *
 * ESP32-targeted example using hdds-micro: subscribes to a bool topic,
 * decodes the command, and toggles an LED GPIO pin.
 * On non-ESP32 hosts, GPIO calls are stubbed for testing.
 *
 * Target: ESP32 (esp-idf) or any POSIX host for simulation
 * Build (ESP32): idf.py build
 * Build (host):  gcc -o micro_esp32_blink micro_esp32_blink.c -lhdds_micro
 */

#include <hdds_micro.h>
#include <stdio.h>

/* --- GPIO abstraction --- */
#ifdef ESP32
#include "driver/gpio.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#define LED_GPIO     GPIO_NUM_2
#define DELAY_MS(ms) vTaskDelay(pdMS_TO_TICKS(ms))
static void gpio_init_led(void) {
    gpio_config_t cfg = { .pin_bit_mask = (1ULL << LED_GPIO),
        .mode = GPIO_MODE_OUTPUT };
    gpio_config(&cfg);
}
static void gpio_set_led(int on) { gpio_set_level(LED_GPIO, on ? 1 : 0); }
#else
#include <unistd.h>
#define LED_GPIO     2
#define DELAY_MS(ms) usleep((ms) * 1000)
static void gpio_init_led(void) {
    printf("[SIM] GPIO %d configured as output\n", LED_GPIO);
}
static void gpio_set_led(int on) { (void)on; }
#endif

#ifdef ESP32
void app_main(void) {
#else
int main(void) {
#endif
    printf("=== HDDS Micro ESP32 Blink ===\n\n");
    gpio_init_led();

    /* Null transport for testing; real ESP32: hdds_micro_transport_create_serial() */
    HddsMicroTransport *transport = hdds_micro_transport_create_null();
    HddsMicroParticipant *p = transport ?
        hdds_micro_participant_create(42, transport) : NULL;
    HddsMicroReader *reader = p ?
        hdds_micro_reader_create(p, "cmd/led", NULL) : NULL;
    if (!reader) {
        fprintf(stderr, "Init failed\n");
        if (reader) hdds_micro_reader_destroy(reader);
        if (p) hdds_micro_participant_destroy(p);
        if (transport) hdds_micro_transport_destroy(transport);
#ifdef ESP32
        return;
#else
        return 1;
#endif
    }
    printf("[OK] domain=%u, topic='cmd/led'\nWaiting for commands...\n\n",
           hdds_micro_participant_domain_id(p));

    int led_state = 0, iters = 0;
#ifdef ESP32
    while (1) {
#else
    while (iters < 100) {
#endif
        uint8_t buf[16];
        size_t len = 0;
        HddsMicroSampleInfo info;
        if (hdds_micro_take(reader, buf, sizeof(buf), &len, &info) == HDDS_MICRO_OK
            && len > 0) {
            bool cmd = false;
            if (hdds_micro_decode_bool(buf, len, &cmd) > 0) {
                led_state = cmd ? 1 : 0;
                gpio_set_led(led_state);
                printf("  [ESP32] LED %s (GPIO %d)\n",
                       led_state ? "ON " : "OFF", LED_GPIO);
            }
        }
        iters++;
        DELAY_MS(50);
    }

    hdds_micro_reader_destroy(reader);
    hdds_micro_participant_destroy(p);
    printf("\n=== ESP32 Blink stopped ===\n");
#ifndef ESP32
    return 0;
#endif
}
