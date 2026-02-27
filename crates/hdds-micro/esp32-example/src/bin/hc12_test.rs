// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com
// HC-12 Radio Test for ESP32
//
// Wiring:
//   ESP32 GPIO17 (TX2) -> HC-12 RX
//   ESP32 GPIO16 (RX2) -> HC-12 TX
//   ESP32 3.3V -> HC-12 VCC
//   ESP32 GND -> HC-12 GND

use esp_idf_svc::hal::gpio;
use esp_idf_svc::hal::peripherals::Peripherals;
use esp_idf_svc::hal::uart::{config::Config, UartDriver};
use log::*;
use std::time::Duration;

// Mode: "tx" or "rx"
const MODE: &str = "rx";

fn main() -> anyhow::Result<()> {
    esp_idf_svc::sys::link_patches();
    esp_idf_svc::log::EspLogger::initialize_default();

    info!("========================================");
    info!("  HC-12 Radio Test");
    info!("========================================");
    info!("Mode: {}", MODE);

    let peripherals = Peripherals::take()?;

    // Configure UART2 for HC-12 (default 9600 baud)
    let config = Config::default().baudrate(esp_idf_svc::hal::units::Hertz(9600));

    let uart = UartDriver::new(
        peripherals.uart2,
        peripherals.pins.gpio17, // TX
        peripherals.pins.gpio16, // RX
        Option::<gpio::Gpio0>::None,
        Option::<gpio::Gpio1>::None,
        &config,
    )?;

    info!("UART2 initialized at 9600 baud");
    info!("HC-12 should be ready...");

    match MODE {
        "tx" => run_transmitter(&uart)?,
        "rx" => run_receiver(&uart)?,
        _ => error!("Invalid MODE"),
    }

    loop {
        std::thread::sleep(Duration::from_secs(1));
    }
}

fn run_transmitter(uart: &UartDriver) -> anyhow::Result<()> {
    info!("Starting HC-12 Transmitter...");

    let mut seq: u32 = 0;
    loop {
        seq += 1;
        let msg = format!("HDDS#{:04}:temp={:.1}C\n", seq, 20.0 + (seq as f32 * 0.1) % 10.0);

        uart.write(msg.as_bytes())?;
        info!("TX: {}", msg.trim());

        std::thread::sleep(Duration::from_secs(2));

        if seq >= 20 {
            info!("Done - 20 messages sent!");
            break;
        }
    }
    Ok(())
}

fn run_receiver(uart: &UartDriver) -> anyhow::Result<()> {
    info!("Starting HC-12 Receiver...");

    let mut buf = [0u8; 64];
    let mut count = 0;

    loop {
        match uart.read(&mut buf, 100) {
            Ok(len) if len > 0 => {
                if let Ok(msg) = std::str::from_utf8(&buf[..len]) {
                    count += 1;
                    info!("RX #{}: {}", count, msg.trim());
                }
            }
            _ => {}
        }

        if count >= 20 {
            info!("Done - 20 messages received!");
            break;
        }
    }
    Ok(())
}
