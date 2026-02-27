// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! # HDDS Sample: Request-Reply Pattern
//!
//! Demonstrates **RPC-style communication** over DDS - synchronous request/response
//! using two topics with correlation IDs.
//!
//! ## Request-Reply Flow
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────┐
//! │                                                                     │
//! │   Client (Requester)                    Server (Replier)           │
//! │   ──────────────────                    ────────────────           │
//! │          │                                     │                   │
//! │          │──── Request ───────────────────────►│                   │
//! │          │     ID=1, op="add", args="10 20"    │                   │
//! │          │                                     │ process()         │
//! │          │◄──── Reply ─────────────────────────│                   │
//! │          │      ID=1, status=0, result="30"   │                   │
//! │          │                                     │                   │
//! │                                                                     │
//! │   Topics:                                                          │
//! │     Calculator_Request: client → service                           │
//! │     Calculator_Reply:   service → client                           │
//! └─────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Correlation Mechanism
//!
//! ```text
//! Request:                         Reply:
//! ┌────────────────────────┐      ┌────────────────────────┐
//! │ request_id: 42         │ ───► │ request_id: 42 (match!)│
//! │ client_id: "Client-A"  │      │ client_id: "Client-A"  │
//! │ operation: "add"       │      │ status_code: 0         │
//! │ payload: "10 20"       │      │ result: "30"           │
//! └────────────────────────┘      └────────────────────────┘
//!
//! Client filters replies by: client_id AND request_id
//! ```
//!
//! ## Pattern Variations
//!
//! | Pattern           | Behavior                      | Use Case          |
//! |-------------------|-------------------------------|-------------------|
//! | Synchronous       | Block until reply             | Simple RPC        |
//! | Asynchronous      | Callback on reply             | Non-blocking      |
//! | Fire-and-forget   | No reply expected             | Commands          |
//! | Pub/Sub + Reply   | Broadcast request, one reply  | Service discovery |
//!
//! ## Running the Sample
//!
//! ```bash
//! # Terminal 1 - Start service (server)
//! cargo run --bin request_reply -- server
//!
//! # Terminal 2 - Run client (sends requests)
//! cargo run --bin request_reply
//!
//! # Available operations: add, multiply, echo, uppercase
//! ```

use std::env;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

// =============================================================================
// Generated Types
// =============================================================================

#[allow(dead_code)]
mod generated {
    include!("../../generated/rpc_types.rs");
}

use generated::{Reply, Request};

/// Process a request and generate a reply
fn process_request(req: &Request) -> Reply {
    let (status_code, result) = match req.operation.as_str() {
        "add" => {
            let parts: Vec<&str> = req.payload.split_whitespace().collect();
            if parts.len() >= 2 {
                let a: i32 = parts[0].parse().unwrap_or(0);
                let b: i32 = parts[1].parse().unwrap_or(0);
                (0, (a + b).to_string())
            } else {
                (-1, "Invalid payload: expected two numbers".to_string())
            }
        }
        "multiply" => {
            let parts: Vec<&str> = req.payload.split_whitespace().collect();
            if parts.len() >= 2 {
                let a: i32 = parts[0].parse().unwrap_or(0);
                let b: i32 = parts[1].parse().unwrap_or(0);
                (0, (a * b).to_string())
            } else {
                (-1, "Invalid payload: expected two numbers".to_string())
            }
        }
        "echo" => (0, req.payload.clone()),
        "uppercase" => (0, req.payload.to_uppercase()),
        _ => (-1, format!("Unknown operation: {}", req.operation)),
    };

    Reply::new(req.request_id, &req.client_id, status_code, &result)
}

fn print_request_reply_overview() {
    println!("--- Request-Reply Pattern ---\n");
    println!("Request-Reply over DDS:\n");
    println!("  Requester                     Replier");
    println!("  ---------                     -------");
    println!("      |                             |");
    println!("      |---- Request (ID=1) ------->|");
    println!("      |                             | process");
    println!("      |<---- Reply (ID=1) ---------|");
    println!("      |                             |");
    println!();
    println!("Topics:");
    println!("  - Calculator_Request: client -> service");
    println!("  - Calculator_Reply: service -> client");
    println!();
    println!("Correlation:");
    println!("  - request_id: unique per request");
    println!("  - client_id: identifies requester for reply filtering");
    println!();
}

fn run_server(participant: &Arc<hdds::Participant>) -> Result<(), hdds::Error> {
    println!("[Server] Creating request reader and reply writer...");

    let request_reader =
        participant.create_reader::<Request>("Calculator_Request", hdds::QoS::default())?;
    let reply_writer =
        participant.create_writer::<Reply>("Calculator_Reply", hdds::QoS::default())?;

    let waitset = hdds::WaitSet::new();
    waitset.attach(&request_reader)?;

    // Create a guard condition for shutdown
    let _shutdown = Arc::new(hdds::GuardCondition::new());
    // Note: Could attach shutdown guard if needed for external shutdown signal

    println!("[Server] Service ready. Waiting for requests...\n");
    println!("Available operations: add, multiply, echo, uppercase\n");

    let mut request_count = 0u32;
    let max_requests = 10; // Process up to 10 requests then exit

    while request_count < max_requests {
        match waitset.wait(Some(Duration::from_secs(5))) {
            Ok(triggered) => {
                if !triggered.is_empty() {
                    while let Some(req) = request_reader.take()? {
                        request_count += 1;
                        println!(
                            "[REQUEST #{}] ID={}, Client={}, Op={}, Payload='{}'",
                            request_count,
                            req.request_id,
                            req.client_id,
                            req.operation,
                            req.payload
                        );

                        // Process and send reply
                        let reply = process_request(&req);
                        reply_writer.write(&reply)?;

                        println!(
                            "[REPLY   #{}] ID={}, Status={}, Result='{}'\n",
                            request_count, reply.request_id, reply.status_code, reply.result
                        );
                    }
                }
            }
            Err(hdds::Error::WouldBlock) => {
                println!("  (waiting for requests...)");
            }
            Err(e) => {
                eprintln!("Wait error: {:?}", e);
                break;
            }
        }
    }

    println!(
        "[Server] Processed {} requests. Shutting down.",
        request_count
    );
    Ok(())
}

fn run_client(participant: &Arc<hdds::Participant>, client_id: &str) -> Result<(), hdds::Error> {
    println!(
        "[Client {}] Creating request writer and reply reader...",
        client_id
    );

    let request_writer =
        participant.create_writer::<Request>("Calculator_Request", hdds::QoS::default())?;
    let reply_reader =
        participant.create_reader::<Reply>("Calculator_Reply", hdds::QoS::default())?;

    let waitset = hdds::WaitSet::new();
    waitset.attach(&reply_reader)?;

    println!("[Client {}] Ready. Sending requests...\n", client_id);

    // Define requests to send
    let requests = vec![
        Request::new(1, client_id, "add", "10 20"),
        Request::new(2, client_id, "multiply", "6 7"),
        Request::new(3, client_id, "echo", "Hello DDS"),
        Request::new(4, client_id, "uppercase", "make me loud"),
        Request::new(5, client_id, "unknown", "test"),
    ];

    for req in requests {
        println!(
            "[SEND] ID={}, Op={}, Payload='{}'",
            req.request_id, req.operation, req.payload
        );

        request_writer.write(&req)?;

        // Wait for reply with timeout
        let reply_received = match waitset.wait(Some(Duration::from_secs(2))) {
            Ok(triggered) => {
                if triggered.is_empty() {
                    false
                } else {
                    let mut found = false;
                    while let Some(reply) = reply_reader.take()? {
                        // Check if this reply is for us and matches our request
                        if reply.client_id == client_id && reply.request_id == req.request_id {
                            println!(
                                "[RECV] ID={}, Status={}, Result='{}'\n",
                                reply.request_id, reply.status_code, reply.result
                            );
                            found = true;
                            break;
                        }
                    }
                    found
                }
            }
            Err(hdds::Error::WouldBlock) => false,
            Err(_) => false,
        };

        if !reply_received {
            println!(
                "[TIMEOUT] No reply received for request {}\n",
                req.request_id
            );
        }

        thread::sleep(Duration::from_millis(200));
    }

    println!("[Client {}] Done sending requests.", client_id);
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    let is_server = args
        .get(1)
        .map(|s| s == "server" || s == "--server")
        .unwrap_or(false);
    let client_id = args.get(2).map(|s| s.as_str()).unwrap_or("Client1");

    println!("{}", "=".repeat(60));
    println!("HDDS Request-Reply Sample");
    println!("{}", "=".repeat(60));
    println!();

    print_request_reply_overview();

    let participant = hdds::Participant::builder("RequestReplyDemo")
        .with_transport(hdds::TransportMode::IntraProcess)
        .build()?;
    println!("[OK] Participant created\n");

    if is_server {
        run_server(&participant)?;
    } else {
        run_client(&participant, client_id)?;
    }

    // Pattern variations summary
    println!("\n--- Request-Reply Variations ---");
    println!("1. Synchronous: Block until reply (simple)");
    println!("2. Asynchronous: Callback on reply (non-blocking)");
    println!("3. Future-based: Returns future, await later");
    println!("4. Fire-and-forget: No reply expected");

    println!("\n--- Implementation Tips ---");
    println!("1. Use content filter for client_id to receive only your replies");
    println!("2. Include request_id for correlation");
    println!("3. Set appropriate timeouts");
    println!("4. Handle service unavailability gracefully");
    println!("5. Consider retry logic for failed requests");

    println!("\n=== Sample Complete ===");
    Ok(())
}
