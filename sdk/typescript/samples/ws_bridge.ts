// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * ws_bridge - reach DDS over the hdds-ws WebSocket bridge instead of the
 * native koffi binding.
 *
 * The rest of this SDK is a native FFI binding to libhdds_c.so: it needs the
 * shared library and therefore a Node (or Electron) process. This sample is
 * the other announced path -- the one a BROWSER can take -- and it needs
 * neither the library nor an npm dependency: `tools/hdds-ws` speaks a JSON
 * protocol over WebSocket, and Node >= 22 (and every current browser) ships a
 * global WebSocket client.
 *
 * Protocol (tools/hdds-ws/src/protocol.rs):
 *   client -> {"type":"subscribe","topic":"..."}
 *             {"type":"publish","topic":"...","data":{...}}
 *             {"type":"ping","id":N}
 *   server -> {"type":"welcome","version":"...","domain":N}
 *             {"type":"subscribed","topic":"...","subscription_id":"..."}
 *             {"type":"data","topic":"...","sample":{...},"info":{...}}
 *             {"type":"published","topic":"...","sequence":N}
 *             {"type":"pong","id":N}
 *             {"type":"error","code":"...","message":"..."}
 *
 * Start the bridge first (domain 39 = the HDDS project domain):
 *   cargo run --release -p hdds-ws -- --port 9090 --domain 39
 *
 * Then:
 *   cd sdk/typescript && npm ci && npm run build:samples
 *   node dist-samples/ws_bridge.js ws://127.0.0.1:9090/ws temperature
 *
 * HddsWsClient below is the browser-portable half: it imports nothing, uses
 * only the platform's global WebSocket, and can be bundled as-is. The main()
 * demo underneath it is the Node CLI wrapper and reads process.argv, so the
 * entry-point guard tests for `process` before touching it -- importing this
 * module in a browser must not throw.
 */

interface WelcomeMessage {
  type: "welcome";
  version: string;
  domain: number;
}

interface SubscribedMessage {
  type: "subscribed";
  topic: string;
  subscription_id: string;
}

interface DataMessage {
  type: "data";
  topic: string;
  subscription_id: string;
  sample: unknown;
  info?: {
    source_timestamp_ms?: number;
    reception_timestamp_ms?: number;
    sequence?: number;
    writer_guid?: string;
  };
}

interface PublishedMessage {
  type: "published";
  topic: string;
  sequence: number;
}

interface PongMessage {
  type: "pong";
  id?: number;
}

interface ErrorMessage {
  type: "error";
  code: string;
  message: string;
  topic?: string;
}

type ServerMessage =
  | WelcomeMessage
  | SubscribedMessage
  | DataMessage
  | PublishedMessage
  | PongMessage
  | ErrorMessage
  | { type: string; [key: string]: unknown };

/**
 * A minimal, dependency-free client for the hdds-ws JSON protocol.
 *
 * `WebSocket` is resolved from the global scope: Node >= 22 and every current
 * browser provide it. On Node 18/20 the global does not exist and the
 * constructor throws with an actionable message rather than failing later.
 */
export class HddsWsClient {
  private readonly socket: WebSocket;
  private readonly handlers = new Map<string, (msg: ServerMessage) => void>();

  constructor(url: string) {
    const ctor = (globalThis as { WebSocket?: typeof WebSocket }).WebSocket;
    if (typeof ctor !== "function") {
      throw new Error(
        "No global WebSocket. This sample needs Node >= 22 (or a browser); " +
          "the native SDK path in ../src has no such requirement."
      );
    }
    this.socket = new ctor(url);
    this.socket.addEventListener("message", (event: MessageEvent) => {
      let msg: ServerMessage;
      try {
        msg = JSON.parse(String(event.data)) as ServerMessage;
      } catch {
        console.error(`malformed frame: ${String(event.data)}`);
        return;
      }
      const handler = this.handlers.get(msg.type);
      if (handler) {
        handler(msg);
      } else {
        console.log(`<- ${JSON.stringify(msg)}`);
      }
    });
  }

  on(type: string, handler: (msg: ServerMessage) => void): void {
    this.handlers.set(type, handler);
  }

  open(): Promise<void> {
    return new Promise((resolve, reject) => {
      this.socket.addEventListener("open", () => resolve(), { once: true });
      this.socket.addEventListener(
        "error",
        () => reject(new Error("WebSocket connection failed")),
        { once: true }
      );
    });
  }

  private send(payload: unknown): void {
    this.socket.send(JSON.stringify(payload));
  }

  subscribe(topic: string): void {
    this.send({ type: "subscribe", topic });
  }

  unsubscribe(topic: string): void {
    this.send({ type: "unsubscribe", topic });
  }

  publish(topic: string, data: unknown): void {
    this.send({ type: "publish", topic, data });
  }

  ping(id: number): void {
    this.send({ type: "ping", id });
  }

  close(): void {
    this.socket.close();
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function main(): Promise<number> {
  const url = process.argv[2] ?? "ws://127.0.0.1:9090/ws";
  const topic = process.argv[3] ?? "temperature";
  const count = Number(process.argv[4] ?? 3);

  console.log(`hdds-ws bridge sample: url=${url} topic=${topic}`);

  const client = new HddsWsClient(url);
  client.on("welcome", (msg) => {
    const w = msg as WelcomeMessage;
    console.log(`welcome: hdds-ws ${w.version} on domain ${w.domain}`);
  });
  let ackSubscribed: () => void = () => {};
  const subscribed = new Promise<void>((resolve) => {
    ackSubscribed = resolve;
  });
  client.on("subscribed", (msg) => {
    const s = msg as SubscribedMessage;
    console.log(`subscribed to "${s.topic}" (${s.subscription_id})`);
    ackSubscribed();
  });
  client.on("error", (msg) => {
    const e = msg as ErrorMessage;
    console.error(`bridge error ${e.code}: ${e.message}`);
  });

  let received = 0;
  const done = new Promise<void>((resolve) => {
    client.on("data", (msg) => {
      const d = msg as DataMessage;
      received += 1;
      console.log(`received ${JSON.stringify(d.sample)}`);
      if (received >= count) resolve();
    });
  });

  await client.open();
  client.subscribe(topic);

  // The bridge creates the DDS reader when it handles "subscribe" and the
  // writer lazily on the first "publish". Publishing before the ack arrives
  // races reader/writer matching and the samples are simply lost, so wait for
  // the ack and then settle, exactly as the cross-language driver does.
  const ack = await Promise.race([
    subscribed.then(() => "ok" as const),
    new Promise<"timeout">((resolve) =>
      setTimeout(() => resolve("timeout"), 5_000)
    ),
  ]);
  if (ack === "timeout") {
    console.error(`FAIL: bridge never acknowledged the subscription to ${topic}`);
    client.close();
    return 1;
  }
  await sleep(300);

  for (let i = 0; i < count; i += 1) {
    client.publish(topic, { sensor: topic, celsius: 20 + i, seq: i });
  }

  const timeout = new Promise<"timeout">((resolve) =>
    setTimeout(() => resolve("timeout"), 10_000)
  );
  const outcome = await Promise.race([done.then(() => "done" as const), timeout]);
  client.close();

  if (outcome === "timeout") {
    console.error(`FAIL: received ${received}/${count} samples`);
    return 1;
  }
  console.log(`Done: received ${received}/${count} samples over the bridge`);
  return 0;
}

// Only run the demo when this file is the entry point, so the class above can
// be imported by a browser bundle. `process` is a Node-only global: testing
// for it with typeof is what keeps a plain browser import from throwing
// ReferenceError before HddsWsClient can be used.
if (
  typeof process !== "undefined" &&
  process.argv[1] !== undefined &&
  process.argv[1].endsWith("ws_bridge.js")
) {
  main().then((code) => process.exit(code));
}
