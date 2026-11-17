// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * Sample proof: every file advertised by sdk/samples/12_typescript is compiled
 * and RUN here, and its success line is asserted. A sample that is only listed
 * in a README is not a shipped sample.
 *
 * Prerequisites (scripts/test-sdk.sh Layer 1c does both):
 *   npm run build && npm run build:samples
 *   HDDS_LIB_PATH=<cargo target>/release
 *
 * ws_bridge.ts additionally needs the hdds-ws binary; the case is driven by
 * HDDS_WS_BIN and fails closed when that variable points at nothing.
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { spawn, spawnSync } from "node:child_process";
import * as fs from "node:fs";
import * as path from "node:path";
import * as net from "node:net";
import * as vm from "node:vm";
import { leaseDomain } from "../scripts/domain-lease.js";

const SDK_DIR = path.resolve(__dirname, "..");
const SAMPLES_DIR = path.join(SDK_DIR, "dist-samples");
const LIB_DIR = process.env["HDDS_LIB_PATH"];
const WS_BIN = process.env["HDDS_WS_BIN"];

const ENABLED = Boolean(LIB_DIR) && fs.existsSync(SAMPLES_DIR);
const suite = ENABLED ? describe : describe.skip;

if (!ENABLED) {
  console.warn(
    "[samples.test.ts] SKIPPED: needs HDDS_LIB_PATH and a compiled " +
      "dist-samples/ (npm run build && npm run build:samples)."
  );
}

/** Every sample the 12_typescript README advertises must exist and compile. */
const ADVERTISED = [
  "hello_world",
  "publisher",
  "subscriber",
  "qos_example",
  "ws_bridge",
];

function runSample(
  name: string,
  args: string[] = [],
  timeoutMs = 30_000
): { code: number | null; stdout: string; stderr: string } {
  const result = spawnSync(
    process.execPath,
    [path.join(SAMPLES_DIR, `${name}.js`), ...args],
    {
      env: { ...process.env, HDDS_LIB_PATH: LIB_DIR },
      encoding: "utf8",
      timeout: timeoutMs,
      killSignal: "SIGKILL",
    }
  );
  return {
    code: result.status,
    stdout: result.stdout ?? "",
    stderr: result.stderr ?? "",
  };
}

/**
 * The ws_bridge module claims HddsWsClient is browser-portable. Proof: evaluate
 * the COMPILED module in a context that has no `process` at all (a browser has
 * none) and require it to load and export the class. Before the typeof guard
 * the module-level entry check dereferenced process.argv and this threw
 * ReferenceError, which no Node-hosted run could ever see.
 */
const browserSuite = fs.existsSync(SAMPLES_DIR) ? describe : describe.skip;

browserSuite("ws_bridge is importable without Node globals", () => {
  it("ws_bridge_module_loads_in_a_context_with_no_process_global", () => {
    const compiled = path.join(SAMPLES_DIR, "ws_bridge.js");
    expect(fs.existsSync(compiled), `missing ${compiled}`).toBe(true);
    const code = fs.readFileSync(compiled, "utf8");

    const sandbox: Record<string, unknown> = {
      console,
      setTimeout,
      clearTimeout,
      // A browser has a WebSocket and no process; the sandbox mirrors that.
      WebSocket: function FakeWebSocket() {
        throw new Error("not connected in this proof");
      },
    };
    sandbox["exports"] = {};
    sandbox["module"] = { exports: sandbox["exports"] };
    expect("process" in sandbox).toBe(false);

    expect(() =>
      vm.runInNewContext(code, sandbox, { filename: "ws_bridge.js" })
    ).not.toThrow();

    const exported = (sandbox["module"] as { exports: Record<string, unknown> })
      .exports;
    expect(typeof exported["HddsWsClient"]).toBe("function");
  });
});

describe("advertised samples exist", () => {
  it("every_sample_named_in_the_readme_has_a_source_file", () => {
    for (const name of ADVERTISED) {
      const src = path.join(SDK_DIR, "samples", `${name}.ts`);
      expect(fs.existsSync(src), `missing sample source ${src}`).toBe(true);
    }
  });
});

suite("samples run", () => {
  // Leased once for the whole suite (see scripts/domain-lease.js, the Node
  // counterpart of crates/hdds/src/test_support/domains.rs): the publisher
  // and subscriber below MUST share one domain to talk to each other, but
  // that domain must not be a literal number, or this suite collides with
  // native.test.ts's own leased-domain case (a separate vitest worker
  // process) and with any Rust test running at the same time.
  // Declared here, in beforeAll, and released in afterAll, so it outlives
  // every child process this suite spawns.
  let domainLease: Awaited<ReturnType<typeof leaseDomain>>;

  beforeAll(async () => {
    domainLease = await leaseDomain();
  });

  afterAll(async () => {
    await domainLease.release();
  });

  it("sample_hello_world_round_trips_five_samples", () => {
    const r = runSample("hello_world");
    expect(r.stdout + r.stderr).toContain("Done: 5/5 samples");
    expect(r.code).toBe(0);
  });

  it("sample_qos_example_shows_transient_local_serving_a_late_joiner", () => {
    const r = runSample("qos_example");
    // The sample's contract is "transient_local serves the full depth and
    // volatile serves strictly fewer", NOT "volatile serves exactly zero":
    // a volatile late joiner that legitimately catches one live sample is a
    // PASS for the sample and must not be a FAIL here.
    expect(r.stdout + r.stderr).toMatch(
      /Done: transient_local kept 5 samples for the late joiner, volatile kept \d+/
    );
    expect(r.code).toBe(0);
  });

  it("sample_publisher_and_subscriber_pair_over_udp", async () => {
    // UDP on the domain leased above: the topic ALSO carries the pid, since
    // the lease only guarantees this domain is not held by another test --
    // a second run of this same test file (a re-run, a flaky-test retry)
    // is a second process and would take a different lease.
    const topic = `ts_sample_${process.pid}`;
    const count = 3;
    const domain = String(domainLease.domain);

    const sub = spawn(
      process.execPath,
      [
        path.join(SAMPLES_DIR, "subscriber.js"),
        topic,
        String(count),
        "25",
        domain,
      ],
      { env: { ...process.env, HDDS_LIB_PATH: LIB_DIR } }
    );
    let subOut = "";
    sub.stdout.on("data", (b) => (subOut += String(b)));
    sub.stderr.on("data", (b) => (subOut += String(b)));

    // Let the subscriber finish discovery before the publisher starts.
    await new Promise((r) => setTimeout(r, 1500));

    const pub = runSample("publisher", [topic, "100", String(count), domain]);
    expect(pub.stdout + pub.stderr).toContain(
      `Done: published ${count} samples on "${topic}"`
    );
    expect(pub.code).toBe(0);

    const subCode = await new Promise<number | null>((resolve) => {
      sub.on("exit", (code) => resolve(code));
      setTimeout(() => {
        sub.kill("SIGKILL");
      }, 30_000);
    });

    expect(subOut).toContain(
      `Done: received ${count}/${count} samples on "${topic}"`
    );
    expect(subCode).toBe(0);
  }, 60_000);
});

/**
 * The announced browser architecture (sdk/samples/12_typescript): TypeScript
 * client -> hdds-ws JSON over WebSocket -> DDS. Driven against the REAL
 * hdds-ws binary, not a stub, so the sample is proven against the protocol
 * the bridge actually speaks.
 */
const WS_ENABLED = ENABLED && Boolean(WS_BIN);
const wsSuite = WS_ENABLED ? describe : describe.skip;

if (ENABLED && !WS_ENABLED) {
  console.warn(
    "[samples.test.ts] ws_bridge case SKIPPED: set HDDS_WS_BIN to the " +
      "hdds-ws binary (cargo build --release -p hdds-ws)."
  );
}

async function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.on("error", reject);
    srv.listen(0, "127.0.0.1", () => {
      const addr = srv.address();
      const port = typeof addr === "object" && addr ? addr.port : 0;
      srv.close(() => resolve(port));
    });
  });
}

async function waitForPort(port: number, timeoutMs: number): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const open = await new Promise<boolean>((resolve) => {
      const sock = net.connect({ port, host: "127.0.0.1" });
      sock.on("connect", () => {
        sock.destroy();
        resolve(true);
      });
      sock.on("error", () => resolve(false));
    });
    if (open) return true;
    await new Promise((r) => setTimeout(r, 200));
  }
  return false;
}

wsSuite("ws_bridge sample", () => {
  let port = 0;
  let bridge: ReturnType<typeof spawn> | null = null;
  let bridgeExited: Promise<void> = Promise.resolve();
  // Own lease: this is a separate describe block from "samples run" above,
  // and hdds-ws needs a real domain the moment it is spawned, so it is
  // leased here rather than shared. See scripts/domain-lease.js.
  let domainLease: Awaited<ReturnType<typeof leaseDomain>>;

  beforeAll(async () => {
    if (!WS_BIN || !fs.existsSync(WS_BIN)) {
      throw new Error(`HDDS_WS_BIN=${WS_BIN} does not exist`);
    }
    domainLease = await leaseDomain();
    port = await freePort();
    bridge = spawn(
      WS_BIN,
      [
        "--port",
        String(port),
        "--bind",
        "127.0.0.1",
        "--domain",
        String(domainLease.domain),
        // "intra" cannot publish (hdds-ws reports "Transport not
        // initialized"); the bridge needs a real transport, so the case runs
        // UDP on the leased domain with a pid-suffixed topic like the pair
        // above.
        "--transport",
        "udp",
      ],
      { stdio: "ignore" }
    );
    bridgeExited = new Promise((resolve) => bridge?.once("exit", () => resolve()));
    const up = await waitForPort(port, 20_000);
    if (!up) {
      bridge.kill("SIGKILL");
      bridge = null;
      await bridgeExited;
      await domainLease.release();
      throw new Error(`hdds-ws did not listen on 127.0.0.1:${port}`);
    }
  }, 40_000);

  // beforeAll spawns a real participant on the leased domain. Reaping it in
  // the test body only works when the body runs: a filtered or aborted case
  // would leave hdds-ws holding a UDP participant and a listening port. The
  // lease is released only AFTER the bridge process has actually exited
  // (not just been sent SIGKILL), so the domain is not handed to another
  // test while hdds-ws's UDP socket may still be closing.
  afterAll(async () => {
    bridge?.kill("SIGKILL");
    bridge = null;
    await bridgeExited;
    await domainLease.release();
  });

  it("sample_ws_bridge_publishes_and_receives_over_hdds_ws", async () => {
    const r = runSample(
      "ws_bridge",
      [`ws://127.0.0.1:${port}/ws`, `ws_sample_${process.pid}`, "3"],
      40_000
    );
    expect(r.stdout + r.stderr).toContain(
      "Done: received 3/3 samples over the bridge"
    );
    expect(r.code).toBe(0);
  }, 60_000);
});
