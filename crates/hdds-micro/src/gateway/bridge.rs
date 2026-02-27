// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! LoRa <-> WiFi/UDP Bridge implementation

use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use super::config::GatewayConfig;
use super::routing::Router;
use super::stats::{GatewayStats, TopicRateLimiter};

/// Message from LoRa side
#[derive(Debug)]
pub struct LoRaMessage {
    /// Source node ID
    pub node_id: u8,
    /// RSSI value
    pub rssi: i16,
    /// SNR value
    pub snr: i8,
    /// Message payload
    pub payload: Vec<u8>,
}

/// Bridge between LoRa and WiFi/UDP networks
pub struct Bridge {
    /// Configuration
    config: GatewayConfig,
    /// Message router
    router: Router,
    /// Statistics
    stats: Arc<GatewayStats>,
    /// Rate limiter
    rate_limiter: TopicRateLimiter,
    /// Running flag
    running: Arc<AtomicBool>,
    /// UDP socket for WiFi side
    udp_socket: Option<UdpSocket>,
    /// Multicast address
    multicast_addr: SocketAddr,
}

impl Bridge {
    /// Create a new bridge
    pub fn new(config: GatewayConfig) -> io::Result<Self> {
        let stats = Arc::new(GatewayStats::new());
        let rate_limiter = TopicRateLimiter::new(
            config.max_messages_per_second,
            config.max_messages_per_second / 10,
        );

        let mut router = Router::new();

        // Apply topic filters
        if !config.bridge_all_topics {
            let lora_topics: Vec<_> = config.lora_to_wifi_topics.iter().cloned().collect();
            let wifi_topics: Vec<_> = config.wifi_to_lora_topics.iter().cloned().collect();

            if !lora_topics.is_empty() {
                router.set_lora_to_wifi_filter(lora_topics);
            }
            if !wifi_topics.is_empty() {
                router.set_wifi_to_lora_filter(wifi_topics);
            }
        }

        let multicast_addr: SocketAddr =
            format!("{}:{}", config.multicast_address, config.udp_port)
                .parse()
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

        Ok(Self {
            config,
            router,
            stats,
            rate_limiter,
            running: Arc::new(AtomicBool::new(false)),
            udp_socket: None,
            multicast_addr,
        })
    }

    /// Bind UDP socket for WiFi communication
    pub fn bind(&mut self) -> io::Result<()> {
        let bind_addr = format!("0.0.0.0:{}", self.config.udp_port);
        let socket = UdpSocket::bind(&bind_addr)?;

        // Join multicast group
        let multicast_ip: std::net::Ipv4Addr = self
            .config
            .multicast_address
            .parse()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

        socket.join_multicast_v4(&multicast_ip, &std::net::Ipv4Addr::UNSPECIFIED)?;
        socket.set_nonblocking(true)?;
        socket.set_read_timeout(Some(Duration::from_millis(100)))?;

        self.udp_socket = Some(socket);
        Ok(())
    }

    /// Get statistics reference
    pub fn stats(&self) -> Arc<GatewayStats> {
        Arc::clone(&self.stats)
    }

    /// Process a message received from LoRa
    pub fn process_lora_message(&mut self, msg: LoRaMessage) -> io::Result<bool> {
        self.stats.record_lora_rx(msg.payload.len());

        // Try to extract topic from RTPS message
        let topic = self.router.extract_topic_from_rtps(&msg.payload);

        // Check topic filter
        if !self.router.should_forward_to_wifi(topic.as_deref()) {
            self.stats.record_filter_drop();
            return Ok(false);
        }

        // Check rate limit
        if !self.rate_limiter.try_acquire(topic.as_deref()) {
            self.stats.record_rate_limit_drop();
            return Ok(false);
        }

        // Update routing info
        if let Some(ref t) = topic {
            self.router.register_lora_node(msg.node_id, t);
            self.router.update_topic_stats(t, msg.node_id as u32);
        }

        // Forward to WiFi/UDP
        self.send_to_wifi(&msg.payload)?;
        Ok(true)
    }

    /// Process a message received from WiFi/UDP
    pub fn process_wifi_message(
        &mut self,
        data: &[u8],
        _src: SocketAddr,
    ) -> io::Result<Option<Vec<u8>>> {
        self.stats.record_wifi_rx(data.len());

        // Try to extract topic
        let topic = self.router.extract_topic_from_rtps(data);

        // Check topic filter
        if !self.router.should_forward_to_lora(topic.as_deref()) {
            self.stats.record_filter_drop();
            return Ok(None);
        }

        // Check rate limit
        if !self.rate_limiter.try_acquire(topic.as_deref()) {
            self.stats.record_rate_limit_drop();
            return Ok(None);
        }

        // Update stats
        if let Some(ref t) = topic {
            self.router.update_topic_stats(t, 0);
        }

        // Return data to be sent to LoRa
        self.stats.record_lora_tx(data.len());
        Ok(Some(data.to_vec()))
    }

    /// Send data to WiFi/UDP network
    fn send_to_wifi(&mut self, data: &[u8]) -> io::Result<()> {
        if let Some(ref socket) = self.udp_socket {
            socket.send_to(data, self.multicast_addr)?;
            self.stats.record_wifi_tx(data.len());
        }
        Ok(())
    }

    /// Receive from WiFi/UDP (non-blocking)
    pub fn recv_wifi(&self) -> io::Result<Option<(Vec<u8>, SocketAddr)>> {
        if let Some(ref socket) = self.udp_socket {
            let mut buf = vec![0u8; 2048];
            match socket.recv_from(&mut buf) {
                Ok((len, src)) => {
                    buf.truncate(len);
                    Ok(Some((buf, src)))
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(None),
                Err(e) => Err(e),
            }
        } else {
            Ok(None)
        }
    }

    /// Check if bridge is running
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }

    /// Signal bridge to stop
    pub fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
    }

    /// Get running flag for external use
    pub fn running_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.running)
    }

    /// Start the bridge with provided LoRa callbacks
    ///
    /// This runs the bridge loop, polling WiFi and calling the provided
    /// callbacks for LoRa interaction.
    ///
    /// # Arguments
    /// * `lora_recv` - Closure to receive from LoRa, returns Option<LoRaMessage>
    /// * `lora_send` - Closure to send to LoRa
    pub fn run<FR, FS>(&mut self, mut lora_recv: FR, mut lora_send: FS) -> io::Result<()>
    where
        FR: FnMut() -> Option<LoRaMessage>,
        FS: FnMut(&[u8]) -> io::Result<()>,
    {
        self.running.store(true, Ordering::Relaxed);
        let stats_interval = Duration::from_secs(self.config.stats_interval_secs);
        let mut last_stats = std::time::Instant::now();

        while self.running.load(Ordering::Relaxed) {
            // Process LoRa -> WiFi
            if let Some(msg) = lora_recv() {
                if let Err(e) = self.process_lora_message(msg) {
                    eprintln!("Error processing LoRa message: {}", e);
                    self.stats.record_parse_error();
                }
            }

            // Process WiFi -> LoRa
            match self.recv_wifi() {
                Ok(Some((data, src))) => match self.process_wifi_message(&data, src) {
                    Ok(Some(to_send)) => {
                        if let Err(e) = lora_send(&to_send) {
                            eprintln!("Error sending to LoRa: {}", e);
                        }
                    }
                    Ok(None) => {}
                    Err(e) => {
                        eprintln!("Error processing WiFi message: {}", e);
                        self.stats.record_parse_error();
                    }
                },
                Ok(None) => {}
                Err(e) if e.kind() != io::ErrorKind::WouldBlock => {
                    eprintln!("UDP receive error: {}", e);
                }
                _ => {}
            }

            // Print stats periodically
            if self.config.enable_stats && last_stats.elapsed() >= stats_interval {
                println!("{}", self.stats.format_summary());
                last_stats = std::time::Instant::now();
            }

            // Small sleep to avoid busy loop
            thread::sleep(Duration::from_millis(1));
        }

        Ok(())
    }

    /// Get router reference (for external topic queries)
    pub fn router(&self) -> &Router {
        &self.router
    }

    /// Get mutable router reference
    pub fn router_mut(&mut self) -> &mut Router {
        &mut self.router
    }
}

/// Bridge builder for easier configuration
pub struct BridgeBuilder {
    config: GatewayConfig,
}

impl BridgeBuilder {
    /// Create a new builder with default config
    pub fn new() -> Self {
        Self {
            config: GatewayConfig::default(),
        }
    }

    /// Set UDP port
    pub fn udp_port(mut self, port: u16) -> Self {
        self.config.udp_port = port;
        self
    }

    /// Set domain ID
    pub fn domain_id(mut self, id: u32) -> Self {
        self.config.domain_id = id;
        self
    }

    /// Set node ID
    pub fn node_id(mut self, id: u8) -> Self {
        self.config.node_id = id;
        self
    }

    /// Add topic to LoRa->WiFi filter
    pub fn lora_to_wifi_topic(mut self, topic: &str) -> Self {
        self.config.bridge_all_topics = false;
        self.config.lora_to_wifi_topics.insert(topic.to_string());
        self
    }

    /// Add topic to WiFi->LoRa filter
    pub fn wifi_to_lora_topic(mut self, topic: &str) -> Self {
        self.config.bridge_all_topics = false;
        self.config.wifi_to_lora_topics.insert(topic.to_string());
        self
    }

    /// Bridge all topics
    pub fn bridge_all(mut self) -> Self {
        self.config.bridge_all_topics = true;
        self
    }

    /// Set rate limit
    pub fn rate_limit(mut self, msgs_per_sec: u32) -> Self {
        self.config.max_messages_per_second = msgs_per_sec;
        self
    }

    /// Set multicast address
    pub fn multicast_address(mut self, addr: &str) -> Self {
        self.config.multicast_address = addr.to_string();
        self
    }

    /// Enable or disable stats
    pub fn enable_stats(mut self, enable: bool) -> Self {
        self.config.enable_stats = enable;
        self
    }

    /// Build the bridge
    pub fn build(self) -> io::Result<Bridge> {
        Bridge::new(self.config)
    }
}

impl Default for BridgeBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bridge_creation() {
        let bridge = Bridge::new(GatewayConfig::default());
        assert!(bridge.is_ok());
    }

    #[test]
    fn test_bridge_builder() {
        let bridge = BridgeBuilder::new()
            .udp_port(17402)
            .domain_id(1)
            .node_id(200)
            .lora_to_wifi_topic("Temperature")
            .wifi_to_lora_topic("Command")
            .rate_limit(50)
            .build();

        assert!(bridge.is_ok());
    }

    #[test]
    fn test_process_lora_message() {
        let mut bridge = BridgeBuilder::new()
            .udp_port(17403)
            .bridge_all()
            .build()
            .unwrap();

        let msg = LoRaMessage {
            node_id: 1,
            rssi: -80,
            snr: 10,
            payload: vec![0x52, 0x54, 0x50, 0x53, 0x02, 0x01], // RTPS header start
        };

        // Should process (not forwarded since no socket, but no error)
        let result = bridge.process_lora_message(msg);
        assert!(result.is_ok());

        // Stats should be updated
        let stats = bridge.stats();
        assert_eq!(stats.snapshot().lora_rx_count, 1);
    }

    #[test]
    fn test_topic_filtering() {
        let mut bridge = BridgeBuilder::new()
            .udp_port(17404)
            .lora_to_wifi_topic("Temperature")
            .build()
            .unwrap();

        // Message without recognizable topic - should pass (unknown topics pass)
        let msg = LoRaMessage {
            node_id: 1,
            rssi: -80,
            snr: 10,
            payload: vec![1, 2, 3, 4],
        };

        let result = bridge.process_lora_message(msg);
        assert!(result.is_ok());
    }

    #[test]
    fn test_rate_limiting() {
        let mut bridge = BridgeBuilder::new()
            .udp_port(17405)
            .bridge_all()
            .rate_limit(5)
            .build()
            .unwrap();

        // Send more messages than rate limit allows
        for i in 0..20 {
            let msg = LoRaMessage {
                node_id: 1,
                rssi: -80,
                snr: 10,
                payload: vec![i as u8],
            };
            let _ = bridge.process_lora_message(msg);
        }

        let stats = bridge.stats();
        let snap = stats.snapshot();

        // Some should have been dropped
        assert!(snap.dropped_rate_limit > 0);
        assert!(snap.lora_rx_count == 20); // All received
    }

    #[test]
    fn test_running_flag() {
        let bridge = Bridge::new(GatewayConfig::default()).unwrap();

        assert!(!bridge.is_running());

        let flag = bridge.running_flag();
        flag.store(true, Ordering::Relaxed);
        assert!(bridge.is_running());

        bridge.stop();
        assert!(!bridge.is_running());
    }
}
