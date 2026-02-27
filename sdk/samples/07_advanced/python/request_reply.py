#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

"""
Request-Reply Sample - Demonstrates RPC-style communication over DDS

This sample shows how to implement request-reply patterns:
- Service with request/reply topics
- Correlation IDs for matching responses
- Timeout handling
- Multiple concurrent requests

Key concepts:
- Requester: sends requests, waits for replies
- Replier: receives requests, sends replies
- Correlation: matching requests to replies
"""

import os
import sys
import time
import struct
from dataclasses import dataclass
from typing import Optional, Dict

# Add SDK to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'python'))

import hdds


@dataclass
class Request:
    """Request message"""
    request_id: int = 0
    client_id: str = ""
    operation: str = ""
    payload: str = ""
    timestamp: int = 0

    def serialize(self) -> bytes:
        """Serialize to bytes."""
        client_bytes = self.client_id.encode('utf-8')
        op_bytes = self.operation.encode('utf-8')
        payload_bytes = self.payload.encode('utf-8')
        return struct.pack(
            f'<qI{len(client_bytes)}sI{len(op_bytes)}sI{len(payload_bytes)}sq',
            self.request_id,
            len(client_bytes), client_bytes,
            len(op_bytes), op_bytes,
            len(payload_bytes), payload_bytes,
            self.timestamp
        )

    @classmethod
    def deserialize(cls, data: bytes) -> 'Request':
        """Deserialize from bytes."""
        offset = 0
        request_id, client_len = struct.unpack_from('<qI', data, offset)
        offset += 12
        client_id = data[offset:offset + client_len].decode('utf-8')
        offset += client_len

        op_len, = struct.unpack_from('<I', data, offset)
        offset += 4
        operation = data[offset:offset + op_len].decode('utf-8')
        offset += op_len

        payload_len, = struct.unpack_from('<I', data, offset)
        offset += 4
        payload = data[offset:offset + payload_len].decode('utf-8')
        offset += payload_len

        timestamp, = struct.unpack_from('<q', data, offset)
        return cls(request_id, client_id, operation, payload, timestamp)


@dataclass
class Reply:
    """Reply message"""
    request_id: int = 0
    client_id: str = ""
    status_code: int = 0
    result: str = ""
    timestamp: int = 0

    def serialize(self) -> bytes:
        """Serialize to bytes."""
        client_bytes = self.client_id.encode('utf-8')
        result_bytes = self.result.encode('utf-8')
        return struct.pack(
            f'<qI{len(client_bytes)}siI{len(result_bytes)}sq',
            self.request_id,
            len(client_bytes), client_bytes,
            self.status_code,
            len(result_bytes), result_bytes,
            self.timestamp
        )

    @classmethod
    def deserialize(cls, data: bytes) -> 'Reply':
        """Deserialize from bytes."""
        offset = 0
        request_id, client_len = struct.unpack_from('<qI', data, offset)
        offset += 12
        client_id = data[offset:offset + client_len].decode('utf-8')
        offset += client_len

        status_code, result_len = struct.unpack_from('<iI', data, offset)
        offset += 8
        result = data[offset:offset + result_len].decode('utf-8')
        offset += result_len

        timestamp, = struct.unpack_from('<q', data, offset)
        return cls(request_id, client_id, status_code, result, timestamp)


class CalculatorService:
    """Service implementation"""

    def process(self, req: Request) -> Reply:
        reply = Reply(
            request_id=req.request_id,
            client_id=req.client_id,
            timestamp=int(time.time() * 1000)
        )

        if req.operation == "add":
            parts = req.payload.split()
            if len(parts) >= 2:
                a, b = int(parts[0]), int(parts[1])
                reply.result = str(a + b)
                reply.status_code = 0
            else:
                reply.result = "Invalid payload"
                reply.status_code = -2
        elif req.operation == "echo":
            reply.result = req.payload
            reply.status_code = 0
        elif req.operation == "time":
            reply.result = str(int(time.time()))
            reply.status_code = 0
        else:
            reply.result = "Unknown operation"
            reply.status_code = -1

        return reply


def print_request_reply_overview():
    print("--- Request-Reply Pattern ---\n")
    print("Request-Reply over DDS:\n")
    print("  Requester                     Replier")
    print("  ---------                     -------")
    print("      |                             |")
    print("      |---- Request (ID=1) ------->|")
    print("      |                             | process")
    print("      |<---- Reply (ID=1) ---------|")
    print("      |                             |")
    print()
    print("Topics:")
    print("  - ServiceName_Request: client -> service")
    print("  - ServiceName_Reply: service -> client")
    print()
    print("Correlation:")
    print("  - request_id: unique per request")
    print("  - client_id: identifies requester")
    print()


def run_server(participant: hdds.Participant, service: CalculatorService):
    """Run as server/replier."""
    print("[OK] Running as SERVICE (replier)\n")

    # Create request reader and reply writer
    request_reader = participant.create_reader(
        "Calculator_Request",
        qos=hdds.QoS.reliable().transient_local()
    )
    reply_writer = participant.create_writer(
        "Calculator_Reply",
        qos=hdds.QoS.reliable().transient_local()
    )

    # Create waitset for efficient waiting
    waitset = hdds.WaitSet()
    waitset.attach_reader(request_reader)

    # Guard condition for shutdown
    shutdown = hdds.GuardCondition()
    waitset.attach_guard(shutdown)

    print("--- Service Ready ---")
    print("Listening for requests (Ctrl+C to stop)...\n")

    try:
        request_count = 0
        while request_count < 10:  # Process up to 10 requests for demo
            # Wait for requests
            if waitset.wait(timeout=1.0):
                while True:
                    data = request_reader.take()
                    if data is None:
                        break

                    req = Request.deserialize(data)
                    request_count += 1

                    print(f"[REQUEST] ID={req.request_id}, Client={req.client_id}, "
                          f"Op={req.operation}, Payload='{req.payload}'")

                    # Process and send reply
                    reply = service.process(req)

                    print(f"[REPLY]   ID={reply.request_id}, Status={reply.status_code}, "
                          f"Result='{reply.result}'\n")

                    reply_writer.write(reply.serialize())
    except KeyboardInterrupt:
        print("\nShutdown requested...")

    shutdown.close()


def run_client(participant: hdds.Participant, client_id: str, service: CalculatorService):
    """Run as client/requester."""
    print(f"[OK] Running as CLIENT (requester): {client_id}\n")

    # Create request writer and reply reader
    request_writer = participant.create_writer(
        "Calculator_Request",
        qos=hdds.QoS.reliable().transient_local()
    )
    reply_reader = participant.create_reader(
        "Calculator_Reply",
        qos=hdds.QoS.reliable().transient_local()
    )

    # Create waitset for waiting on replies
    waitset = hdds.WaitSet()
    waitset.attach_reader(reply_reader)

    # Pending requests map
    pending: Dict[int, Request] = {}

    print("--- Sending Requests ---\n")

    # Send requests
    requests = [
        Request(1, client_id, "add", "10 20", 0),
        Request(2, client_id, "echo", "Hello DDS", 0),
        Request(3, client_id, "time", "", 0),
    ]

    for req in requests:
        req.timestamp = int(time.time() * 1000)
        pending[req.request_id] = req

        print(f"[SEND REQUEST] ID={req.request_id}, Op={req.operation}, "
              f"Payload='{req.payload}'")

        request_writer.write(req.serialize())

    # Wait for replies with timeout
    timeout_secs = 2.0
    received = 0

    while received < len(requests):
        if waitset.wait(timeout=timeout_secs):
            while True:
                data = reply_reader.take()
                if data is None:
                    break

                reply = Reply.deserialize(data)

                # Check if this reply is for us
                if reply.client_id == client_id and reply.request_id in pending:
                    del pending[reply.request_id]
                    received += 1

                    print(f"[GOT REPLY]    ID={reply.request_id}, Status={reply.status_code}, "
                          f"Result='{reply.result}'\n")
        else:
            print("[TIMEOUT] No reply received within timeout\n")
            break

    # Demonstrate timeout handling
    print("--- Timeout Handling ---\n")
    print("Request with 1 second timeout...")

    timeout_req = Request(99, client_id, "slow_operation", "", int(time.time() * 1000))
    pending[timeout_req.request_id] = timeout_req

    print(f"[SEND REQUEST] ID={timeout_req.request_id}, Op={timeout_req.operation}")
    request_writer.write(timeout_req.serialize())

    if not waitset.wait(timeout=1.0):
        print("[TIMEOUT] No reply received within 1 second\n")


def main():
    print("=== HDDS Request-Reply Sample ===\n")

    is_server = len(sys.argv) > 1 and sys.argv[1] == "--server"
    client_id = sys.argv[2] if len(sys.argv) > 2 else "Client1"

    print_request_reply_overview()

    # Initialize logging
    hdds.logging.init(hdds.LogLevel.INFO)

    # Create participant
    participant = hdds.Participant("RequestReply")
    print("[OK] Participant created")

    service = CalculatorService()

    try:
        if is_server:
            run_server(participant, service)
        else:
            run_client(participant, client_id, service)
    except KeyboardInterrupt:
        print("\nInterrupted.")

    # Pattern variations
    print("--- Request-Reply Variations ---\n")
    print("1. Synchronous: Block until reply (simple)")
    print("2. Asynchronous: Callback on reply (non-blocking)")
    print("3. Future-based: Returns future, await later")
    print("4. Fire-and-forget: No reply expected")
    print()

    print("--- Implementation Tips ---\n")
    print("1. Use content filter for client_id to receive only your replies")
    print("2. Include request_id for correlation")
    print("3. Set appropriate timeouts")
    print("4. Handle service unavailability gracefully")
    print("5. Consider retry logic for failed requests")

    print("\n=== Sample Complete ===")
    return 0


if __name__ == "__main__":
    sys.exit(main())
