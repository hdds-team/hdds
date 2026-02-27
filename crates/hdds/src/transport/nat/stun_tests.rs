// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

    /// Helper: create a StunClient for testing.
    fn test_client() -> StunClient {
        let server = SocketAddr::from(([198, 51, 100, 1], 3478));
        StunClient::new(server, Duration::from_secs(3), 3)
    }

    /// Helper: build a STUN Binding Response with XOR-MAPPED-ADDRESS.
    ///
    /// Returns the response bytes for the given public IP and port,
    /// using the supplied transaction ID.
    fn build_xor_mapped_response_ipv4(
        transaction_id: &[u8; 12],
        public_ip: Ipv4Addr,
        public_port: u16,
    ) -> Vec<u8> {
        let mut resp = Vec::new();

        // -- Attribute: XOR-MAPPED-ADDRESS --
        let x_port = public_port ^ MAGIC_COOKIE_PORT_XOR;
        let ip_u32 = u32::from(public_ip);
        let x_addr = ip_u32 ^ MAGIC_COOKIE;

        let mut attr = Vec::new();
        attr.extend_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes()); // type
        attr.extend_from_slice(&8u16.to_be_bytes()); // length
        attr.push(0x00); // reserved
        attr.push(ADDRESS_FAMILY_IPV4); // family
        attr.extend_from_slice(&x_port.to_be_bytes());
        attr.extend_from_slice(&x_addr.to_be_bytes());

        // -- Header --
        let msg_len = attr.len() as u16;
        resp.extend_from_slice(&BINDING_RESPONSE.to_be_bytes());
        resp.extend_from_slice(&msg_len.to_be_bytes());
        resp.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        resp.extend_from_slice(transaction_id);

        // -- Attributes --
        resp.extend_from_slice(&attr);

        resp
    }

    /// Helper: build a STUN Binding Response with MAPPED-ADDRESS (legacy).
    fn build_mapped_response_ipv4(
        transaction_id: &[u8; 12],
        public_ip: Ipv4Addr,
        public_port: u16,
    ) -> Vec<u8> {
        let mut resp = Vec::new();

        // -- Attribute: MAPPED-ADDRESS --
        let mut attr = Vec::new();
        attr.extend_from_slice(&ATTR_MAPPED_ADDRESS.to_be_bytes()); // type
        attr.extend_from_slice(&8u16.to_be_bytes()); // length
        attr.push(0x00); // reserved
        attr.push(ADDRESS_FAMILY_IPV4); // family
        attr.extend_from_slice(&public_port.to_be_bytes());
        attr.extend_from_slice(&public_ip.octets());

        // -- Header --
        let msg_len = attr.len() as u16;
        resp.extend_from_slice(&BINDING_RESPONSE.to_be_bytes());
        resp.extend_from_slice(&msg_len.to_be_bytes());
        resp.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        resp.extend_from_slice(transaction_id);

        // -- Attributes --
        resp.extend_from_slice(&attr);

        resp
    }

    /// Helper: build a STUN Binding Response with XOR-MAPPED-ADDRESS (IPv6).
    fn build_xor_mapped_response_ipv6(
        transaction_id: &[u8; 12],
        public_ip: Ipv6Addr,
        public_port: u16,
    ) -> Vec<u8> {
        let mut resp = Vec::new();

        // XOR key = magic_cookie || transaction_id
        let mut xor_key = [0u8; 16];
        xor_key[..4].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
        xor_key[4..16].copy_from_slice(transaction_id);

        let x_port = public_port ^ MAGIC_COOKIE_PORT_XOR;
        let ip_bytes = public_ip.octets();
        let mut x_addr = [0u8; 16];
        for i in 0..16 {
            x_addr[i] = ip_bytes[i] ^ xor_key[i];
        }

        // -- Attribute --
        let mut attr = Vec::new();
        attr.extend_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
        attr.extend_from_slice(&20u16.to_be_bytes()); // length: 1+1+2+16 = 20
        attr.push(0x00); // reserved
        attr.push(ADDRESS_FAMILY_IPV6); // family
        attr.extend_from_slice(&x_port.to_be_bytes());
        attr.extend_from_slice(&x_addr);

        // -- Header --
        let msg_len = attr.len() as u16;
        resp.extend_from_slice(&BINDING_RESPONSE.to_be_bytes());
        resp.extend_from_slice(&msg_len.to_be_bytes());
        resp.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        resp.extend_from_slice(transaction_id);

        // -- Attributes --
        resp.extend_from_slice(&attr);

        resp
    }

    // -- Test 1: Build binding request format --
    #[test]
    fn test_build_binding_request_format() {
        let mut client = test_client();
        let req = client.build_binding_request();

        assert_eq!(req.len(), STUN_HEADER_SIZE, "request must be exactly 20 bytes");

        // Message type: Binding Request
        let msg_type = u16::from_be_bytes([req[0], req[1]]);
        assert_eq!(msg_type, BINDING_REQUEST);

        // Message length: 0 (no attributes)
        let msg_len = u16::from_be_bytes([req[2], req[3]]);
        assert_eq!(msg_len, 0);

        // Magic cookie
        let cookie = u32::from_be_bytes([req[4], req[5], req[6], req[7]]);
        assert_eq!(cookie, MAGIC_COOKIE);

        // Transaction ID is non-zero (with very high probability)
        let tid = &req[8..20];
        assert_ne!(tid, &[0u8; 12], "transaction ID should not be all zeros");
    }

    // -- Test 2: Parse binding response with XOR-MAPPED-ADDRESS --
    #[test]
    fn test_parse_xor_mapped_address_ipv4() {
        let mut client = test_client();
        let _req = client.build_binding_request();
        let tid = *client.last_transaction_id();

        let public_ip = Ipv4Addr::new(203, 0, 113, 42);
        let public_port = 54321;

        let response = build_xor_mapped_response_ipv4(&tid, public_ip, public_port);
        let result = client.parse_binding_response(&response);

        assert!(result.is_ok(), "parse should succeed: {:?}", result.err());
        let addr = result.unwrap();
        assert_eq!(addr.ip, IpAddr::V4(public_ip));
        assert_eq!(addr.port, public_port);
    }

    // -- Test 3: Parse binding response with MAPPED-ADDRESS (legacy) --
    #[test]
    fn test_parse_mapped_address_legacy() {
        let mut client = test_client();
        let _req = client.build_binding_request();
        let tid = *client.last_transaction_id();

        let public_ip = Ipv4Addr::new(198, 51, 100, 99);
        let public_port = 12345;

        let response = build_mapped_response_ipv4(&tid, public_ip, public_port);
        let result = client.parse_binding_response(&response);

        assert!(result.is_ok(), "legacy MAPPED-ADDRESS should parse: {:?}", result.err());
        let addr = result.unwrap();
        assert_eq!(addr.ip, IpAddr::V4(public_ip));
        assert_eq!(addr.port, public_port);
    }

    // -- Test 4: XOR decode IPv4 address --
    #[test]
    fn test_xor_decode_ipv4() {
        let client = test_client();
        let tid = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C];

        // Public address: 192.0.2.1:8080
        let public_ip = Ipv4Addr::new(192, 0, 2, 1);
        let public_port: u16 = 8080;

        let x_port = public_port ^ MAGIC_COOKIE_PORT_XOR;
        let x_addr = u32::from(public_ip) ^ MAGIC_COOKIE;

        let mut attr_data = vec![0x00, ADDRESS_FAMILY_IPV4];
        attr_data.extend_from_slice(&x_port.to_be_bytes());
        attr_data.extend_from_slice(&x_addr.to_be_bytes());

        let result = client.xor_decode_address(&attr_data, &tid);
        assert!(result.is_ok());
        let (ip, port) = result.unwrap();
        assert_eq!(ip, IpAddr::V4(public_ip));
        assert_eq!(port, public_port);
    }

    // -- Test 5: XOR decode IPv6 address --
    #[test]
    fn test_xor_decode_ipv6() {
        let client = test_client();
        let tid = [0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x07, 0x18, 0x29, 0x3A, 0x4B, 0x5C];

        let public_ip = Ipv6Addr::new(0x2001, 0x0DB8, 0, 0, 0, 0, 0, 1);
        let public_port: u16 = 9090;

        // Build XOR key
        let mut xor_key = [0u8; 16];
        xor_key[..4].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
        xor_key[4..16].copy_from_slice(&tid);

        let x_port = public_port ^ MAGIC_COOKIE_PORT_XOR;
        let ip_bytes = public_ip.octets();
        let mut x_addr = [0u8; 16];
        for i in 0..16 {
            x_addr[i] = ip_bytes[i] ^ xor_key[i];
        }

        let mut attr_data = vec![0x00, ADDRESS_FAMILY_IPV6];
        attr_data.extend_from_slice(&x_port.to_be_bytes());
        attr_data.extend_from_slice(&x_addr);

        let result = client.xor_decode_address(&attr_data, &tid);
        assert!(result.is_ok());
        let (ip, port) = result.unwrap();
        assert_eq!(ip, IpAddr::V6(public_ip));
        assert_eq!(port, public_port);
    }

    // -- Test 6: Parse error response --
    #[test]
    fn test_parse_error_response() {
        let mut client = test_client();
        let _req = client.build_binding_request();
        let tid = *client.last_transaction_id();

        let mut response = Vec::new();
        response.extend_from_slice(&BINDING_ERROR.to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes()); // no attributes
        response.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        response.extend_from_slice(&tid);

        let result = client.parse_binding_response(&response);
        assert!(result.is_err());
        match result.unwrap_err() {
            NatError::ServerError(msg) => {
                assert!(msg.contains("Error Response"), "got: {}", msg);
            }
            other => panic!("expected ServerError, got: {:?}", other),
        }
    }

    // -- Test 7: Reject response too short --
    #[test]
    fn test_reject_too_short() {
        let client = test_client();
        let result = client.parse_binding_response(&[0u8; 10]);
        assert!(result.is_err());
        match result.unwrap_err() {
            NatError::MalformedResponse(msg) => {
                assert!(msg.contains("too short"), "got: {}", msg);
            }
            other => panic!("expected MalformedResponse, got: {:?}", other),
        }
    }

    // -- Test 8: Reject wrong magic cookie --
    #[test]
    fn test_reject_wrong_magic_cookie() {
        let mut client = test_client();
        let _req = client.build_binding_request();
        let tid = *client.last_transaction_id();

        let mut response = Vec::new();
        response.extend_from_slice(&BINDING_RESPONSE.to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());
        response.extend_from_slice(&0xDEAD_BEEFu32.to_be_bytes()); // wrong cookie
        response.extend_from_slice(&tid);

        let result = client.parse_binding_response(&response);
        assert!(result.is_err());
        match result.unwrap_err() {
            NatError::MalformedResponse(msg) => {
                assert!(msg.contains("magic cookie"), "got: {}", msg);
            }
            other => panic!("expected MalformedResponse, got: {:?}", other),
        }
    }

    // -- Test 9: Reject wrong transaction ID --
    #[test]
    fn test_reject_wrong_transaction_id() {
        let mut client = test_client();
        let _req = client.build_binding_request();

        // Build response with a DIFFERENT transaction ID
        let wrong_tid = [0xFF; 12];
        let mut response = Vec::new();
        response.extend_from_slice(&BINDING_RESPONSE.to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());
        response.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        response.extend_from_slice(&wrong_tid);

        let result = client.parse_binding_response(&response);
        assert!(result.is_err());
        match result.unwrap_err() {
            NatError::MalformedResponse(msg) => {
                assert!(msg.contains("transaction ID"), "got: {}", msg);
            }
            other => panic!("expected MalformedResponse, got: {:?}", other),
        }
    }

    // -- Test 10: Transaction ID uniqueness --
    #[test]
    fn test_transaction_id_uniqueness() {
        let mut client = test_client();

        let req1 = client.build_binding_request();
        let tid1 = *client.last_transaction_id();

        // Small sleep to vary time-based seed
        std::thread::sleep(Duration::from_millis(1));

        let req2 = client.build_binding_request();
        let tid2 = *client.last_transaction_id();

        assert_ne!(req1[8..20], req2[8..20], "transaction IDs should differ");
        assert_ne!(tid1, tid2, "stored transaction IDs should differ");
    }

    // -- Test 11: XOR-MAPPED-ADDRESS preferred over MAPPED-ADDRESS --
    #[test]
    fn test_xor_mapped_preferred_over_mapped() {
        let mut client = test_client();
        let _req = client.build_binding_request();
        let tid = *client.last_transaction_id();

        let xor_ip = Ipv4Addr::new(203, 0, 113, 1);
        let xor_port: u16 = 50000;
        let mapped_ip = Ipv4Addr::new(10, 0, 0, 1);
        let mapped_port: u16 = 60000;

        // Build response with BOTH attributes (MAPPED first, then XOR)
        let mut resp = Vec::new();

        // MAPPED-ADDRESS attribute
        let mut attr1 = Vec::new();
        attr1.extend_from_slice(&ATTR_MAPPED_ADDRESS.to_be_bytes());
        attr1.extend_from_slice(&8u16.to_be_bytes());
        attr1.push(0x00);
        attr1.push(ADDRESS_FAMILY_IPV4);
        attr1.extend_from_slice(&mapped_port.to_be_bytes());
        attr1.extend_from_slice(&mapped_ip.octets());

        // XOR-MAPPED-ADDRESS attribute
        let x_port = xor_port ^ MAGIC_COOKIE_PORT_XOR;
        let x_addr = u32::from(xor_ip) ^ MAGIC_COOKIE;
        let mut attr2 = Vec::new();
        attr2.extend_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
        attr2.extend_from_slice(&8u16.to_be_bytes());
        attr2.push(0x00);
        attr2.push(ADDRESS_FAMILY_IPV4);
        attr2.extend_from_slice(&x_port.to_be_bytes());
        attr2.extend_from_slice(&x_addr.to_be_bytes());

        let msg_len = (attr1.len() + attr2.len()) as u16;
        resp.extend_from_slice(&BINDING_RESPONSE.to_be_bytes());
        resp.extend_from_slice(&msg_len.to_be_bytes());
        resp.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        resp.extend_from_slice(&tid);
        resp.extend_from_slice(&attr1);
        resp.extend_from_slice(&attr2);

        let result = client.parse_binding_response(&resp).unwrap();
        // XOR-MAPPED-ADDRESS should be preferred
        assert_eq!(result.ip, IpAddr::V4(xor_ip));
        assert_eq!(result.port, xor_port);
    }

    // -- Test 12: Response with no address attributes --
    #[test]
    fn test_no_address_attributes() {
        let mut client = test_client();
        let _req = client.build_binding_request();
        let tid = *client.last_transaction_id();

        // Build response with empty attributes section
        let mut response = Vec::new();
        response.extend_from_slice(&BINDING_RESPONSE.to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());
        response.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        response.extend_from_slice(&tid);

        let result = client.parse_binding_response(&response);
        assert!(result.is_err());
        match result.unwrap_err() {
            NatError::MalformedResponse(msg) => {
                assert!(msg.contains("no XOR-MAPPED-ADDRESS"), "got: {}", msg);
            }
            other => panic!("expected MalformedResponse, got: {:?}", other),
        }
    }

    // -- Test 13: Full roundtrip with mock socket --
    #[test]
    fn test_full_roundtrip_mock_socket() {
        // We simulate a full roundtrip by having a local UDP "server"
        // that responds to STUN requests.

        let server_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let server_addr = server_socket.local_addr().unwrap();
        server_socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();

        let simulated_public_ip = Ipv4Addr::new(203, 0, 113, 42);
        let simulated_public_port: u16 = 54321;

        // Spawn a "STUN server" thread
        let handle = std::thread::spawn(move || {
            let mut buf = [0u8; 576];
            let (len, client_addr) = server_socket.recv_from(&mut buf).unwrap();

            // Validate it's a Binding Request
            assert_eq!(len, STUN_HEADER_SIZE);
            let msg_type = u16::from_be_bytes([buf[0], buf[1]]);
            assert_eq!(msg_type, BINDING_REQUEST);

            // Extract transaction ID
            let mut tid = [0u8; 12];
            tid.copy_from_slice(&buf[8..20]);

            // Build a response
            let response = build_xor_mapped_response_ipv4(
                &tid,
                simulated_public_ip,
                simulated_public_port,
            );

            server_socket.send_to(&response, client_addr).unwrap();
        });

        // Client side
        let mut client = StunClient::new(server_addr, Duration::from_secs(2), 1);
        let result = client.discover_reflexive_address();

        handle.join().unwrap();

        assert!(result.is_ok(), "roundtrip should succeed: {:?}", result.err());
        let addr = result.unwrap();
        assert_eq!(addr.ip, IpAddr::V4(simulated_public_ip));
        assert_eq!(addr.port, simulated_public_port);
        assert_eq!(addr.server_used, server_addr);
    }

    // -- Test 14: Reject unknown message type --
    #[test]
    fn test_reject_unknown_message_type() {
        let mut client = test_client();
        let _req = client.build_binding_request();
        let tid = *client.last_transaction_id();

        let mut response = Vec::new();
        response.extend_from_slice(&0xFFFFu16.to_be_bytes()); // unknown type
        response.extend_from_slice(&0u16.to_be_bytes());
        response.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        response.extend_from_slice(&tid);

        let result = client.parse_binding_response(&response);
        assert!(result.is_err());
        match result.unwrap_err() {
            NatError::MalformedResponse(msg) => {
                assert!(msg.contains("unexpected message type"), "got: {}", msg);
            }
            other => panic!("expected MalformedResponse, got: {:?}", other),
        }
    }

    // -- Test 15: XOR decode with known test vector --
    #[test]
    fn test_xor_decode_known_vector() {
        // RFC 5769 test vector (simplified):
        // Public IP: 192.0.2.1, Port: 32853
        let client = test_client();
        let tid = [0xB7, 0xE7, 0xA7, 0x01, 0xBC, 0x34, 0xD6, 0x86, 0xFA, 0x87, 0xDF, 0xAE];

        let public_ip = Ipv4Addr::new(192, 0, 2, 1);
        let public_port: u16 = 32853;

        // Manually encode XOR-MAPPED-ADDRESS
        let x_port = public_port ^ MAGIC_COOKIE_PORT_XOR;
        let x_addr = u32::from(public_ip) ^ MAGIC_COOKIE;

        let mut data = vec![0x00, ADDRESS_FAMILY_IPV4];
        data.extend_from_slice(&x_port.to_be_bytes());
        data.extend_from_slice(&x_addr.to_be_bytes());

        let (ip, port) = client.xor_decode_address(&data, &tid).unwrap();
        assert_eq!(ip, IpAddr::V4(public_ip));
        assert_eq!(port, public_port);
    }

    // -- Test 16: Build request has correct two MSBs cleared (RFC 5389 sec 6) --
    #[test]
    fn test_request_two_msb_cleared() {
        let mut client = test_client();
        let req = client.build_binding_request();
        // The two most significant bits of the first byte MUST be 0
        assert_eq!(req[0] & 0xC0, 0, "top 2 bits of message type must be 0");
    }

    // -- Test 17: Parse XOR-MAPPED-ADDRESS with IPv6 --
    #[test]
    fn test_parse_xor_mapped_address_ipv6() {
        let mut client = test_client();
        let _req = client.build_binding_request();
        let tid = *client.last_transaction_id();

        let public_ip = Ipv6Addr::new(0x2001, 0x0DB8, 0, 0, 0, 0, 0, 1);
        let public_port: u16 = 9090;

        let response = build_xor_mapped_response_ipv6(&tid, public_ip, public_port);
        let result = client.parse_binding_response(&response);

        assert!(result.is_ok(), "IPv6 parse should succeed: {:?}", result.err());
        let addr = result.unwrap();
        assert_eq!(addr.ip, IpAddr::V6(public_ip));
        assert_eq!(addr.port, public_port);
    }
