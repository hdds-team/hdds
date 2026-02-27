// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Admin API client (TCP binary protocol).

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

/// Admin API commands
#[derive(Debug, Clone, Copy)]
#[repr(u8)]
#[allow(clippy::enum_variant_names)]
pub enum Command {
    GetMesh = 0x01,
    GetTopics = 0x02,
    GetMetrics = 0x03,
    GetHealth = 0x04,
    GetWriters = 0x05,
    GetReaders = 0x06,
}

/// Admin API client
#[derive(Clone)]
pub struct AdminClient {
    stream: Arc<std::sync::Mutex<TcpStream>>,
}

impl AdminClient {
    /// Connect to Admin API server
    pub fn connect(addr: &str) -> Result<Self, std::io::Error> {
        let stream = TcpStream::connect_timeout(
            &addr.parse().map_err(|e| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("{}", e))
            })?,
            Duration::from_secs(5),
        )?;

        stream.set_nodelay(true)?;
        stream.set_read_timeout(Some(Duration::from_secs(10)))?;
        stream.set_write_timeout(Some(Duration::from_secs(5)))?;

        Ok(Self {
            stream: Arc::new(std::sync::Mutex::new(stream)),
        })
    }

    /// Check if connection is still valid
    pub fn is_connected(&self) -> bool {
        if let Ok(stream) = self.stream.lock() {
            stream.peek(&mut [0u8; 1]).is_ok()
                || stream.take_error().map(|e| e.is_none()).unwrap_or(false)
        } else {
            false
        }
    }

    /// Send command and receive JSON response
    pub fn request(&self, cmd: Command) -> Result<String, std::io::Error> {
        let mut stream = self
            .stream
            .lock()
            .map_err(|_| std::io::Error::other("Lock poisoned"))?;

        // Send command frame: [cmd_id: u8][payload_len: u32]
        let mut frame = [0u8; 5];
        frame[0] = cmd as u8;
        frame[1..5].copy_from_slice(&0u32.to_le_bytes());

        stream.write_all(&frame)?;
        stream.flush()?;

        // Read response header: [status: u8][len: u32]
        let mut header = [0u8; 5];
        stream.read_exact(&mut header)?;

        let status = header[0];
        let len = u32::from_le_bytes([header[1], header[2], header[3], header[4]]);

        if status != 0x00 {
            return Err(std::io::Error::other(format!(
                "Admin API error: status=0x{:02x}",
                status
            )));
        }

        // Read JSON payload
        let mut buf = vec![0u8; len as usize];
        stream.read_exact(&mut buf)?;

        String::from_utf8(buf).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }

    pub fn get_mesh(&self) -> Result<String, std::io::Error> {
        self.request(Command::GetMesh)
    }

    pub fn get_topics(&self) -> Result<String, std::io::Error> {
        self.request(Command::GetTopics)
    }

    pub fn get_metrics(&self) -> Result<String, std::io::Error> {
        self.request(Command::GetMetrics)
    }

    pub fn get_health(&self) -> Result<String, std::io::Error> {
        self.request(Command::GetHealth)
    }

    pub fn get_writers(&self) -> Result<String, std::io::Error> {
        self.request(Command::GetWriters)
    }

    pub fn get_readers(&self) -> Result<String, std::io::Error> {
        self.request(Command::GetReaders)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "Requires Admin API running"]
    fn test_client_connect() {
        let client = AdminClient::connect("127.0.0.1:4243");
        assert!(client.is_ok());
    }

    #[test]
    #[ignore = "Requires Admin API running"]
    fn test_client_get_health() {
        let client = AdminClient::connect("127.0.0.1:4243").unwrap();
        let response = client.get_health().unwrap();
        assert!(response.contains(r#""status":"ok""#));
    }
}
