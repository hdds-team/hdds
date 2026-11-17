#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * Cross-language counterpart to crates/hdds/src/test_support/domains.rs.
 *
 * This file is a hand-port of that module's protocol, not a wrapper around
 * it (Node cannot link Rust code, and vice versa): a domain leased by a Rust
 * test and a domain leased by this file come from the SAME kernel-arbitrated
 * token table, so the two allocators can never hand out the same domain at
 * the same time. There is no shared source of truth across languages -- if
 * FLEET_RESERVED_DOMAINS, TEST_PINNED_DOMAINS, or the ephemeral-port
 * exclusion in domains.rs ever change, this file has to change with it by
 * hand.
 *
 * The protocol, copied from domains.rs:
 *   - Token: on Linux, an abstract Unix socket named
 *     "hdds-test-domain.v1.<domain>". Binding an abstract name that is
 *     already bound fails with EADDRINUSE, machine-wide and across
 *     processes and even across languages (proven empirically against a
 *     real Rust std::os::unix::net::UnixListener::bind_addr and against
 *     socat's ABSTRACT-LISTEN while writing this file -- see
 *     scripts/domain-lease-interop-check.sh and
 *     sdk/typescript/tests/domain-lease.test.ts). The kernel frees the name
 *     when the last descriptor holding it closes, including an abrupt
 *     process death, so a dead holder needs no special handling here either.
 *   - Pool: domains 1..=232 (crate::config::MAX_DOMAIN_ID) minus
 *     FLEET_RESERVED_DOMAINS (domains used by HDDS's own long-running
 *     tools), minus TEST_PINNED_DOMAINS (domains a Rust test asserts by
 *     literal value), minus every domain whose 70-port RTPS block
 *     (PORT_BASE=7400 + DOMAIN_ID_GAIN=250 * domain) overlaps the Linux
 *     default ephemeral port range 32768-60999 (docs/reference/limits.md:
 *     domains 102-214).
 *   - Non-Linux: there is no abstract socket namespace outside Linux.
 *     domains.rs itself falls back to a loopback TCP listener at
 *     127.0.0.1:(6900+domain) there, and says that path "is not exercised on
 *     the Linux CI box". This file does the SAME fallback (see
 *     tryBindToken below) so it still interoperates with a domains.rs test
 *     running on the same non-Linux host. It never silently reuses a fixed
 *     domain: on an unsupported platform (there are none today -- Node's
 *     os.platform() is one of 'linux', 'darwin', 'win32', ...) tryBindToken
 *     throws instead of guessing.
 *
 * Usage from a test:
 *   const { leaseDomain } = require("../scripts/domain-lease.js");
 *   const lease = await leaseDomain();
 *   try {
 *     // ... use lease.domain ...
 *   } finally {
 *     await lease.release();
 *   }
 *
 * CLI usage from a plain shell script (no build step needed, just `node`):
 *   node scripts/domain-lease.js lease [--hold SECONDS]
 *     Leases a domain, prints "LEASED <id>" to stdout, then holds it until
 *     SIGINT/SIGTERM or --hold elapses, then prints "RELEASED <id>" and
 *     exits 0. Exits 1 with "EXHAUSTED" on the stderr if the pool is full.
 *   node scripts/domain-lease.js check <id>
 *     One-shot probe: binds and immediately releases <id>, printing
 *     "FREE <id>" (exit 0) or "TAKEN <id>" (exit 1). Does not hold anything.
 */

"use strict";

const net = require("node:net");
const os = require("node:os");

// ---------------------------------------------------------------------------
// Mirrors crates/hdds/src/test_support/domains.rs. Keep these in sync BY HAND
// with that file; there is no codegen link between the two languages.
// ---------------------------------------------------------------------------

/** Verbatim from domains.rs FLEET_RESERVED_DOMAINS (39 hdds, 70 hdds-gen, 137 hdds-micro). */
const FLEET_RESERVED_DOMAINS = Object.freeze([39, 70, 137]);

/** crate::config::MAX_DOMAIN_ID. */
const MAX_DOMAIN_ID = 232;

/** domains.rs TEST_PINNED_DOMAINS: {1, MAX_DOMAIN_ID}. */
const TEST_PINNED_DOMAINS = Object.freeze([1, MAX_DOMAIN_ID]);

const FIRST_POOL_DOMAIN = 1;
const LAST_POOL_DOMAIN = MAX_DOMAIN_ID;

/** crate::config::PORT_BASE / DOMAIN_ID_GAIN, and domains.rs's own constants. */
const PORT_BASE = 7400;
const DOMAIN_ID_GAIN = 250;
const DOMAIN_PORT_BLOCK = 70;
const EPHEMERAL_PORT_LOW = 32768;
const EPHEMERAL_PORT_HIGH = 60999;

/** The abstract-socket token name domains.rs binds on Linux. */
const TOKEN_NAME_PREFIX = "hdds-test-domain.v1.";

/** domains.rs's own non-Linux fallback band (platform::bind_token). */
const NON_LINUX_TOKEN_PORT_BASE = 6900;
const NON_LINUX_MAX_TOKEN_ID = 499;

function touchesEphemeralRange(domain) {
  const first = PORT_BASE + DOMAIN_ID_GAIN * domain;
  const last = first + DOMAIN_PORT_BLOCK - 1;
  return last >= EPHEMERAL_PORT_LOW && first <= EPHEMERAL_PORT_HIGH;
}

function isExcluded(domain) {
  return (
    FLEET_RESERVED_DOMAINS.includes(domain) ||
    TEST_PINNED_DOMAINS.includes(domain) ||
    touchesEphemeralRange(domain)
  );
}

function computePool() {
  const pool = [];
  for (let d = FIRST_POOL_DOMAIN; d <= LAST_POOL_DOMAIN; d += 1) {
    if (!isExcluded(d)) pool.push(d);
  }
  return pool;
}

/** Same guarantee as domains.rs's DOMAIN_POOL: no 0, no fleet domain, no
 * pinned domain, nothing above MAX_DOMAIN_ID, nothing touching the Linux
 * ephemeral range. */
const DOMAIN_POOL = Object.freeze(computePool());

function isLinux() {
  return os.platform() === "linux";
}

let warnedNonLinuxOnce = false;
function warnNonLinuxOnce() {
  if (warnedNonLinuxOnce) return;
  warnedNonLinuxOnce = true;
  process.stderr.write(
    "[domain-lease] non-Linux platform (" +
      os.platform() +
      "): abstract Unix sockets do not exist here. Falling back to the SAME " +
      "loopback-TCP token scheme crates/hdds/src/test_support/domains.rs " +
      "itself uses off Linux (127.0.0.1:" +
      NON_LINUX_TOKEN_PORT_BASE +
      "+domain). This interoperates with a Rust test on THIS SAME host and " +
      "platform, not with Linux's abstract-socket table -- domains.rs says " +
      "this path 'is not exercised on the Linux CI box'. It is a documented " +
      "fallback, never a fixed domain.\n"
  );
}

/**
 * Error thrown when a domain id is refused, not just contested. Mirrors
 * DomainAllocError::Io: reported, never silently treated as "try the next
 * one".
 */
class DomainTokenError extends Error {}

/**
 * Error thrown when every domain in the pool is held by a live process.
 * Mirrors DomainAllocError::Exhausted.
 */
class DomainPoolExhaustedError extends Error {
  constructor(poolLen) {
    super(
      `all ${poolLen} test domains are leased by live processes; ` +
        "either too many tests are running at once or a caller is leaking " +
        "a domain lease"
    );
    this.name = "DomainPoolExhaustedError";
    this.poolLen = poolLen;
  }
}

/**
 * Try to bind the token for exactly one domain. Resolves
 * { domain, release() } on success (release() closes the listener,
 * synchronously freeing the token even before the process exits). Rejects
 * with an Error whose `.code === "EADDRINUSE"` on collision -- callers walk
 * the pool on that code and propagate anything else, exactly like
 * lease_from_pool's `Err(e) if e.kind() == io::ErrorKind::AddrInUse => {}`.
 */
function tryBindToken(domain) {
  return new Promise((resolve, reject) => {
    if (!Number.isInteger(domain) || domain < 0) {
      reject(new DomainTokenError(`invalid domain id: ${domain}`));
      return;
    }
    if (!isLinux()) {
      warnNonLinuxOnce();
      if (domain > NON_LINUX_MAX_TOKEN_ID) {
        reject(
          new DomainTokenError(
            `token id ${domain} exceeds the ${NON_LINUX_MAX_TOKEN_ID} this ` +
              "platform's token band can express"
          )
        );
        return;
      }
      const srv = net.createServer();
      srv.once("error", (err) => reject(err));
      srv.listen(
        { host: "127.0.0.1", port: NON_LINUX_TOKEN_PORT_BASE + domain },
        () => {
          resolve({
            domain,
            release: () => new Promise((res) => srv.close(() => res())),
          });
        }
      );
      return;
    }
    const name = TOKEN_NAME_PREFIX + domain;
    const srv = net.createServer();
    srv.once("error", (err) => reject(err));
    // Node's net module treats a path starting with "\0" as the Linux
    // abstract-namespace form: the leading NUL is the marker, exactly what
    // SocketAddr::from_abstract_name prepends on the Rust side. Verified
    // against a real Rust UnixListener::bind_addr and against socat's
    // ABSTRACT-LISTEN (both directions of collision, both directions of
    // release-then-release) while building this file.
    srv.listen({ path: "\0" + name }, () => {
      resolve({
        domain,
        release: () => new Promise((res) => srv.close(() => res())),
      });
    });
  });
}

/**
 * Lease a DDS domain no other concurrently running test -- in this process,
 * another Node process, a shell script using scripts/domain-lease.sh, or a
 * Rust test using domains.rs::unique_domain() -- can hold at the same time.
 *
 * `startHint` spreads concurrent callers over the pool instead of racing on
 * slot 0 (a contention optimisation only, same role as try_unique_domain's
 * process::id() seed); correctness comes entirely from the kernel-arbitrated
 * token in tryBindToken.
 */
async function leaseDomain({ startHint = process.pid, pool = DOMAIN_POOL } = {}) {
  if (pool.length === 0) {
    throw new DomainTokenError("leaseDomain: pool must not be empty");
  }
  const start = ((startHint % pool.length) + pool.length) % pool.length;
  for (let offset = 0; offset < pool.length; offset += 1) {
    const domain = pool[(start + offset) % pool.length];
    try {
      // eslint-disable-next-line no-await-in-loop -- sequential probing is the point
      return await tryBindToken(domain);
    } catch (err) {
      if (err && err.code === "EADDRINUSE") continue;
      throw err;
    }
  }
  throw new DomainPoolExhaustedError(pool.length);
}

module.exports = {
  FLEET_RESERVED_DOMAINS,
  TEST_PINNED_DOMAINS,
  MAX_DOMAIN_ID,
  DOMAIN_POOL,
  TOKEN_NAME_PREFIX,
  NON_LINUX_TOKEN_PORT_BASE,
  NON_LINUX_MAX_TOKEN_ID,
  computePool,
  touchesEphemeralRange,
  isExcluded,
  isLinux,
  tryBindToken,
  leaseDomain,
  DomainTokenError,
  DomainPoolExhaustedError,
};

// ---------------------------------------------------------------------------
// CLI: usable directly with `node scripts/domain-lease.js ...`, no build step.
// ---------------------------------------------------------------------------
if (require.main === module) {
  const args = process.argv.slice(2);
  const cmd = args[0];

  const fail = (msg) => {
    process.stderr.write(`domain-lease: ${msg}\n`);
    process.exit(1);
  };

  if (cmd === "lease") {
    let holdSeconds = 0;
    for (let i = 1; i < args.length; i += 1) {
      if (args[i] === "--hold") {
        holdSeconds = Number(args[i + 1]);
        i += 1;
      }
    }
    leaseDomain()
      .then((lease) => {
        console.log(`LEASED ${lease.domain}`);
        let released = false;
        const release = () => {
          if (released) return;
          released = true;
          lease.release().then(() => {
            console.log(`RELEASED ${lease.domain}`);
            process.exit(0);
          });
        };
        process.once("SIGINT", release);
        process.once("SIGTERM", release);
        if (holdSeconds > 0) {
          setTimeout(release, holdSeconds * 1000);
        }
        // Otherwise: block until a signal arrives. An open server keeps the
        // event loop alive, so no extra keep-alive handle is needed.
      })
      .catch((err) => {
        if (err instanceof DomainPoolExhaustedError) {
          fail(`EXHAUSTED: ${err.message}`);
        } else {
          fail(err && err.message ? err.message : String(err));
        }
      });
  } else if (cmd === "check") {
    const domain = Number(args[1]);
    if (!Number.isInteger(domain)) {
      fail("usage: domain-lease.js check <domain-id>");
    } else {
      tryBindToken(domain)
        .then((lease) => lease.release())
        .then(() => {
          console.log(`FREE ${domain}`);
          process.exit(0);
        })
        .catch((err) => {
          if (err && err.code === "EADDRINUSE") {
            console.log(`TAKEN ${domain}`);
            process.exit(1);
          }
          fail(err && err.message ? err.message : String(err));
        });
    }
  } else {
    process.stderr.write(
      "usage: domain-lease.js lease [--hold SECONDS] | check <domain-id>\n"
    );
    process.exit(2);
  }
}
