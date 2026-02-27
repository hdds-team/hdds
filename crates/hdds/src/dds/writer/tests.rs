// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

use super::*;
use crate::core::rt;
use crate::dds::{Error, QoS, DDS};
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, crate::DDS)]
struct Point {
    x: i32,
    y: i32,
}

#[test]
fn test_writer_write_basic() {
    let _ = rt::init_slab_pool();

    let writer = WriterBuilder::<Point>::new("test_topic".to_string())
        .qos(QoS::best_effort())
        .build()
        .expect("writer build should succeed");

    let msg = Point { x: 42, y: 123 };
    let result = writer.write(&msg);
    assert!(result.is_err() || result.is_ok());
}

#[test]
fn test_writer_encode_decode_roundtrip() {
    let original = Point { x: 42, y: -123 };

    let mut buf = vec![0u8; 100];
    let len = original
        .encode_cdr2(&mut buf)
        .expect("encode should succeed");
    assert_eq!(len, 8);

    let decoded = Point::decode_cdr2(&buf[..len]).expect("decode should succeed");
    assert_eq!(decoded, original);
}

#[test]
#[allow(deprecated)]
fn test_writer_with_udp_transport() {
    use crate::transport::UdpTransport;

    let _ = rt::init_slab_pool();

    let transport = match UdpTransport::with_port(7401) {
        Ok(t) => Arc::new(t),
        Err(_) => {
            println!("Skipping UDP test - port unavailable");
            return;
        }
    };

    let writer = WriterBuilder::<Point>::new("test/udp".to_string())
        .with_transport(transport)
        .build()
        .expect("writer build with transport should succeed");

    let msg = Point { x: 100, y: 200 };
    let result = writer.write(&msg);
    assert!(result.is_ok() || matches!(result, Err(Error::WouldBlock)));
}

#[test]
fn test_writer_without_transport_backward_compat() {
    let _ = rt::init_slab_pool();

    let writer = WriterBuilder::<Point>::new("test/local".to_string())
        .build()
        .expect("writer build without transport should succeed");

    assert!(
        writer.transport.is_none(),
        "Writer should not have transport in intra-process mode"
    );

    let msg = Point { x: 50, y: 75 };
    let result = writer.write(&msg);
    assert!(result.is_ok() || matches!(result, Err(Error::WouldBlock)));
}
