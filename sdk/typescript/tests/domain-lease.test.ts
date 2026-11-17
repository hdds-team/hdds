// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * Proof suite for scripts/domain-lease.js, the Node counterpart of
 * crates/hdds/src/test_support/domains.rs.
 *
 * Three layers, cheapest first:
 *   1. Pool invariants -- pure structural checks, mirroring domains.rs's own
 *      unit tests (pool_never_contains_a_fleet_domain and friends). Catches a
 *      transcription mistake in the hand-ported constants.
 *   2. Node-vs-Node collision -- spawns a SEPARATE Node process holding a
 *      domain via the CLI, and proves this process's leaseDomain() cannot
 *      get the same one while it is held, and can once it is released.
 *   3. Node-vs-Rust collision -- the actual cross-language proof this
 *      module exists for. Compiles, with `rustc` (no cargo project, no
 *      dependency on the hdds crate), a standalone reimplementation of
 *      EXACTLY the 3-line bind_token() body from domains.rs's Linux #[cfg]
 *      arm, runs it as a real separate process, and proves this file's
 *      tryBindToken() collides with it and, after it exits, does not.
 *      Skipped with an explicit reason if rustc is unavailable or the
 *      platform is not Linux -- same fail-closed-with-a-reason policy as
 *      native.test.ts uses for HDDS_LIB_PATH, never a silent green skip.
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { spawn, spawnSync } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import {
  FLEET_RESERVED_DOMAINS,
  TEST_PINNED_DOMAINS,
  MAX_DOMAIN_ID,
  DOMAIN_POOL,
  touchesEphemeralRange,
  isLinux,
  tryBindToken,
  leaseDomain,
  DomainPoolExhaustedError,
} from "../scripts/domain-lease.js";

const CLI = path.resolve(__dirname, "..", "scripts", "domain-lease.js");

describe("domain pool invariants (mirrors domains.rs's own unit tests)", () => {
  it("pool_never_contains_a_fleet_domain", () => {
    for (const d of DOMAIN_POOL) {
      expect(FLEET_RESERVED_DOMAINS).not.toContain(d);
    }
  });

  it("pool_never_contains_a_test_pinned_domain", () => {
    for (const d of DOMAIN_POOL) {
      expect(TEST_PINNED_DOMAINS).not.toContain(d);
    }
  });

  it("pool_never_touches_the_ephemeral_range", () => {
    for (const d of DOMAIN_POOL) {
      expect(touchesEphemeralRange(d)).toBe(false);
    }
  });

  it("pool_never_exceeds_the_rtps_domain_ceiling_or_goes_below_one", () => {
    for (const d of DOMAIN_POOL) {
      expect(d).toBeGreaterThanOrEqual(1);
      expect(d).toBeLessThanOrEqual(MAX_DOMAIN_ID);
    }
  });

  it("pool_is_large_enough_for_a_parallel_suite", () => {
    // domains.rs asserts >= 32 for the same reason; it does not assert an
    // exact count, and neither does this (MAX_DOMAIN_ID or the fleet table
    // can grow without this test needing an update).
    expect(DOMAIN_POOL.length).toBeGreaterThanOrEqual(32);
  });

  it("ephemeral_exclusion_matches_docs_reference_limits_md", () => {
    // docs/reference/limits.md: "domains 102 through 214 -- 113 of the 233
    // that exist -- have their RTPS ports inside" the Linux default
    // ephemeral range.
    const touching = [];
    for (let d = 1; d <= MAX_DOMAIN_ID; d += 1) {
      if (touchesEphemeralRange(d)) touching.push(d);
    }
    expect(touching[0]).toBe(102);
    expect(touching[touching.length - 1]).toBe(214);
    expect(touching.length).toBe(113);
  });
});

describe("leaseDomain basics", () => {
  it("leases a domain from the pool and releases it", async () => {
    const lease = await leaseDomain();
    expect(DOMAIN_POOL).toContain(lease.domain);
    await lease.release();
  });

  it("two concurrent leases in this process never collide", async () => {
    const a = await leaseDomain();
    const b = await leaseDomain();
    expect(a.domain).not.toBe(b.domain);
    await a.release();
    await b.release();
  });

  it("exhaustion is reported, never silently handed out anyway", async () => {
    // A private one-domain pool this test fully owns: force it to look busy
    // by holding the only slot, then ask for a lease from that same pool.
    const held = await tryBindToken(9300);
    await expect(leaseDomain({ pool: [9300] })).rejects.toBeInstanceOf(
      DomainPoolExhaustedError
    );
    await held.release();
    // Now that it is free, the same private pool must succeed.
    const lease = await leaseDomain({ pool: [9300] });
    expect(lease.domain).toBe(9300);
    await lease.release();
  });
});

describe("Node-vs-Node cross-process collision (CLI helper)", () => {
  it("a domain held by a separate node process refuses this process's tryBindToken", async () => {
    const holder = spawn(process.execPath, [CLI, "lease"], {
      stdio: ["ignore", "pipe", "pipe"],
    });
    let out = "";
    holder.stdout.on("data", (b) => (out += String(b)));
    holder.stderr.on("data", (b) => (out += String(b)));

    const leasedId = await new Promise<number>((resolve, reject) => {
      const deadline = Date.now() + 5000;
      const poll = () => {
        const m = out.match(/^LEASED (\d+)$/m);
        if (m) {
          resolve(Number(m[1]));
        } else if (Date.now() > deadline) {
          reject(new Error(`holder never printed LEASED: ${out}`));
        } else {
          setTimeout(poll, 20);
        }
      };
      poll();
    });

    await expect(tryBindToken(leasedId)).rejects.toMatchObject({
      code: "EADDRINUSE",
    });

    holder.kill("SIGTERM");
    await new Promise<void>((resolve) => holder.once("exit", () => resolve()));

    // Freed once the holder process is gone (kernel-side close-on-exit).
    const after = await tryBindToken(leasedId);
    expect(after.domain).toBe(leasedId);
    await after.release();
  }, 15_000);
});

const rustcAvailable = (() => {
  try {
    const r = spawnSync("rustc", ["--version"]);
    return r.status === 0;
  } catch {
    return false;
  }
})();
const crossLangEnabled = isLinux() && rustcAvailable;
const crossLangSuite = crossLangEnabled ? describe : describe.skip;

if (!crossLangEnabled) {
  console.warn(
    "[domain-lease.test.ts] SKIPPED cross-language proof: needs Linux + rustc " +
      `on PATH (isLinux=${isLinux()}, rustc=${rustcAvailable}).`
  );
}

crossLangSuite("Node-vs-Rust cross-language collision (the actual point of this module)", () => {
  let workdir = "";
  let binPath = "";

  beforeAll(() => {
    workdir = fs.mkdtempSync(path.join(os.tmpdir(), "hdds-domain-lease-rust-"));
    const src = path.join(workdir, "holder.rs");
    binPath = path.join(workdir, "holder");
    // Reimplements ONLY the documented bind_token() body from
    // crates/hdds/src/test_support/domains.rs's Linux #[cfg] arm, verbatim.
    // Does not import or depend on the hdds crate -- this file never reads
    // or touches anything under crates/.
    fs.writeFileSync(
      src,
      `use std::os::linux::net::SocketAddrExt;
use std::os::unix::net::{SocketAddr, UnixListener};

fn bind_token(domain: &str) -> std::io::Result<UnixListener> {
    let name = format!("hdds-test-domain.v1.{domain}");
    let addr = SocketAddr::from_abstract_name(name.as_bytes())?;
    UnixListener::bind_addr(&addr)
}

fn main() {
    let mut args = std::env::args().skip(1);
    let domain = args.next().expect("usage: holder <domain> <hold-seconds>");
    let hold_secs: u64 = args
        .next()
        .expect("usage: holder <domain> <hold-seconds>")
        .parse()
        .expect("hold-seconds must be an integer");
    match bind_token(&domain) {
        Ok(_listener) => {
            println!("HELD {domain}");
            use std::io::Write;
            std::io::stdout().flush().ok();
            std::thread::sleep(std::time::Duration::from_secs(hold_secs));
        }
        Err(e) => {
            println!("REFUSED {domain} {e}");
            std::process::exit(1);
        }
    }
}
`
    );
    const rustc = spawnSync("rustc", ["-O", src, "-o", binPath], {
      encoding: "utf8",
    });
    if (rustc.status !== 0) {
      throw new Error(`rustc failed:\n${rustc.stderr}`);
    }
  }, 60_000);

  afterAll(() => {
    if (workdir) fs.rmSync(workdir, { recursive: true, force: true });
  });

  it("a domain held by the Rust probe refuses Node's tryBindToken, and frees on exit", async () => {
    const PROBE_DOMAIN = 9102; // above MAX_DOMAIN_ID: never a real lease.
    const holder = spawn(binPath, [String(PROBE_DOMAIN), "3"], {
      stdio: ["ignore", "pipe", "pipe"],
    });
    let out = "";
    holder.stdout.on("data", (b) => (out += String(b)));

    await new Promise<void>((resolve, reject) => {
      const deadline = Date.now() + 5000;
      const poll = () => {
        if (out.includes(`HELD ${PROBE_DOMAIN}`)) resolve();
        else if (Date.now() > deadline)
          reject(new Error(`rust probe never reported HELD: ${out}`));
        else setTimeout(poll, 10);
      };
      poll();
    });

    await expect(tryBindToken(PROBE_DOMAIN)).rejects.toMatchObject({
      code: "EADDRINUSE",
    });

    await new Promise<void>((resolve) => holder.once("exit", () => resolve()));

    const after = await tryBindToken(PROBE_DOMAIN);
    expect(after.domain).toBe(PROBE_DOMAIN);
    await after.release();
  }, 15_000);
});
