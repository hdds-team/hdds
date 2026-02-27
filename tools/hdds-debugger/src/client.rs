// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

use std::io::{Read, Write};
use std::net::TcpStream;

pub struct AdminClient {
    stream: TcpStream,
}

#[derive(Debug)]
#[repr(u8)]
pub enum Command {
    Mesh = 0x01,
    Topics = 0x02,
    Metrics = 0x03,
    Health = 0x04,
}

impl AdminClient {
    /// Connect to Admin API on specified address
    pub fn connect(addr: &str) -> Result<Self, std::io::Error> {
        let stream = TcpStream::connect(addr)?;
        stream.set_nodelay(true)?; // Disable Nagle for low latency
        Ok(Self { stream })
    }

    /// Send command and receive JSON response
    pub fn request(&mut self, cmd: Command) -> Result<String, std::io::Error> {
        // Send command frame: [cmd_id: u8][payload_len: u32]
        let cmd_byte = cmd as u8;
        let payload_len = 0u32; // No payload for requests

        let mut frame = [0u8; 5];
        frame[0] = cmd_byte;
        frame[1..5].copy_from_slice(&payload_len.to_le_bytes());

        self.stream.write_all(&frame)?;

        // Read response header: [status: u8][len: u32]
        let mut header = [0u8; 5];
        self.stream.read_exact(&mut header)?;

        let status = header[0];
        let len = u32::from_le_bytes([header[1], header[2], header[3], header[4]]);

        if status != 0x00 {
            return Err(std::io::Error::other(format!(
                "Admin API error: status={status}"
            )));
        }

        // Read JSON payload
        let mut buf = vec![0u8; len as usize];
        self.stream.read_exact(&mut buf)?;

        String::from_utf8(buf).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }

    pub fn get_mesh(&mut self) -> Result<String, std::io::Error> {
        self.request(Command::Mesh)
    }

    pub fn get_topics(&mut self) -> Result<String, std::io::Error> {
        self.request(Command::Topics)
    }

    pub fn get_metrics(&mut self) -> Result<String, std::io::Error> {
        self.request(Command::Metrics)
    }

    pub fn get_health(&mut self) -> Result<String, std::io::Error> {
        self.request(Command::Health)
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
        let mut client = AdminClient::connect("127.0.0.1:4243").unwrap();
        let response = client.get_health().unwrap();
        assert!(response.contains(r#""status":"ok""#));
    }

    #[test]
    #[ignore = "Requires Admin API running"]
    fn test_client_get_mesh() {
        let mut client = AdminClient::connect("127.0.0.1:4243").unwrap();
        let response = client.get_mesh().unwrap();
        assert!(response.contains(r#""schema_version":"1.0""#));
        assert!(response.contains(r#""participants""#));
    }
}
