// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * Native integration tests for the HDDS TypeScript SDK.
 *
 * Unlike tests/basic.test.ts, every case here DOES require libhdds_c.so: the
 * point is to execute the koffi FFI path end to end against a library built
 * from this tree. Run them with
 *
 *   cargo build --release -p hdds-c
 *   HDDS_LIB_PATH=$CARGO_TARGET_DIR/release npx vitest run tests/native.test.ts
 *
 * scripts/test-sdk.sh Layer 1c does exactly that, and treats "0 tests found"
 * as a failure.
 *
 * Loading policy, fail-closed:
 *   - HDDS_LIB_PATH set   -> the library MUST load; a failure fails the suite,
 *                            it never turns into a skip.
 *   - HDDS_LIB_PATH unset -> the suite is skipped with an explicit reason so
 *                            `npm test` stays usable on a machine that has not
 *                            built the Rust workspace.
 *
 * Transport: every case is INTRA_PROCESS (no sockets) except
 * `participant_reports_the_requested_domain_id`, which opens a UDP participant
 * and touches no topic. Its domain is LEASED (see
 * scripts/domain-lease.js, the Node counterpart of
 * crates/hdds/src/test_support/domains.rs), not hardcoded: this suite runs in
 * its own vitest worker process in parallel with samples.test.ts and with any
 * Rust test suite that happens to be running on the same machine, and a
 * literal domain number here could collide with both.
 */

import { describe, it, expect, afterEach } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";

import {
  Participant,
  QoS,
  WaitSet,
  GuardCondition,
  TransportMode,
  HddsError,
  version,
  loadNativeLibrary,
  getNativeLib,
} from "../src/index.js";
import { leaseDomain } from "../scripts/domain-lease.js";

const LIB_DIR = process.env["HDDS_LIB_PATH"];

/**
 * A native test file with no library reachable is not evidence, so the
 * decision is explicit and printed:
 *   - HDDS_LIB_PATH set but wrong   -> throw here, the whole file fails.
 *   - HDDS_LIB_PATH unset           -> describe.skip with a reason.
 */
function libraryIsUsable(): boolean {
  if (!LIB_DIR) {
    return false;
  }
  const candidate = path.join(LIB_DIR, "libhdds_c.so");
  if (!fs.existsSync(candidate)) {
    throw new Error(
      `HDDS_LIB_PATH=${LIB_DIR} does not contain libhdds_c.so. ` +
        `Build it with: cargo build --release -p hdds-c`
    );
  }
  return true;
}

const ENABLED = libraryIsUsable();
const suite = ENABLED ? describe : describe.skip;

if (!ENABLED) {
  // Printed once, so a green "skipped" line can never be mistaken for a pass.
  console.warn(
    "[native.test.ts] SKIPPED: HDDS_LIB_PATH is unset. " +
      "Build hdds-c and set HDDS_LIB_PATH=<target>/release to run these tests."
  );
}

/** Unique per process: several suites share this box and this domain pool. */
const TAG = `ts${process.pid}`;
let topicSeq = 0;
function topic(name: string): string {
  topicSeq += 1;
  return `${name}_${TAG}_${topicSeq}`;
}

const disposables: Array<{ dispose(): void }> = [];
function track<T extends { dispose(): void }>(value: T): T {
  disposables.push(value);
  return value;
}

afterEach(() => {
  while (disposables.length > 0) {
    const d = disposables.pop();
    try {
      d?.dispose();
    } catch {
      // A test that asserts use-after-dispose has already disposed it.
    }
  }
});

function intraParticipant(name: string): Participant {
  return track(
    Participant.create(`${name}_${TAG}`, {
      transport: TransportMode.INTRA_PROCESS,
    })
  );
}

suite("native library load", () => {
  /**
   * loadNativeLibrary() binds EVERY symbol eagerly (one koffi lib.func call
   * per entry in native.ts), so this single case validates every koffi type
   * name in the file. It is the regression test for the five hdds_config_*
   * declarations that used the non-existent type name "pointer" and made the
   * shipped SDK throw before any call. Do not replace it with per-symbol
   * tests: the value is that it is exhaustive by construction.
   */
  it("native_loads_and_reports_version", () => {
    const lib = loadNativeLibrary();
    expect(lib).toBeTruthy();
    const v = version();
    expect(typeof v).toBe("string");
    expect(v).toMatch(/^\d+\.\d+\.\d+/);
  });
});

suite("participant", () => {
  it("participant_create_intra_process_reports_its_name", () => {
    const p = intraParticipant("named");
    expect(p.name).toContain("named");
  });

  it("participant_reports_the_requested_domain_id", async () => {
    // A leased domain, not a hardcoded one: this is a real UDP participant,
    // and a literal number here can collide with another suite (TypeScript
    // or Rust) running at the same time on this machine. No topic is
    // created, so the case still cannot cross-talk with another suite's
    // sample data even though it shares the pool with everything else.
    //
    // Ordering matters (see scripts/domain-lease.js / domains.rs): the lease
    // must outlive the participant, so it is released only in the `finally`
    // AFTER the participant is disposed, not handed to the shared
    // `disposables`/afterEach stack, whose ordering relative to a
    // describe-scoped afterEach is not guaranteed to put this release last.
    const lease = await leaseDomain();
    try {
      const p = Participant.create(`domain_${TAG}`, {
        domainId: lease.domain,
        transport: TransportMode.UDP_MULTICAST,
      });
      try {
        expect(p.domainId).toBe(lease.domain);
      } finally {
        p.dispose();
      }
    } finally {
      await lease.release();
    }
  });

  it("participant_use_after_dispose_throws", () => {
    const p = Participant.create(`disposed_${TAG}`, {
      transport: TransportMode.INTRA_PROCESS,
    });
    p.dispose();
    p.dispose(); // idempotent
    expect(() => p.createWriter("never")).toThrow(HddsError);
  });
});

suite("write / take round trip", () => {
  it("write_then_take_returns_the_same_bytes", () => {
    const p = intraParticipant("rt");
    const qos = QoS.reliable().transientLocal().historyDepth(8);
    const t = topic("NativeRoundTrip");
    const w = p.createWriter(t, qos);
    const r = p.createReader(t, qos);
    const ws = track(new WaitSet());
    ws.attachReader(r);

    w.write(Buffer.from("hello-native"));
    expect(ws.wait(2.0)).toBe(true);

    const got = r.take();
    expect(got).not.toBeNull();
    expect(got!.toString()).toBe("hello-native");
  });

  it("take_on_an_empty_reader_returns_null", () => {
    const p = intraParticipant("empty");
    const qos = QoS.reliable().historyDepth(4);
    const r = p.createReader(topic("NativeEmpty"), qos);
    expect(r.take()).toBeNull();
  });

  it("multiple_samples_arrive_in_write_order", () => {
    const p = intraParticipant("order");
    const qos = QoS.reliable().transientLocal().historyDepth(16);
    const t = topic("NativeOrder");
    const w = p.createWriter(t, qos);
    const r = p.createReader(t, qos);
    const ws = track(new WaitSet());
    ws.attachReader(r);

    const count = 5;
    for (let i = 0; i < count; i += 1) {
      w.write(Buffer.from(`SAMPLE-${i}`));
    }

    const received: string[] = [];
    const deadline = Date.now() + 10_000;
    while (received.length < count && Date.now() < deadline) {
      if (ws.wait(1.0)) {
        for (;;) {
          const data = r.take();
          if (data === null) break;
          received.push(data.toString());
        }
      }
    }
    expect(received).toEqual([
      "SAMPLE-0",
      "SAMPLE-1",
      "SAMPLE-2",
      "SAMPLE-3",
      "SAMPLE-4",
    ]);
  });

  it("explicit_type_name_round_trips", () => {
    // The four other cross-language drivers announce "RawBytes"; a TypeScript
    // endpoint that names it explicitly must behave identically.
    const p = intraParticipant("typed");
    const qos = QoS.reliable().transientLocal().historyDepth(8);
    const t = topic("NativeTypeName");
    const w = p.createWriter(t, qos, "RawBytes");
    const r = p.createReader(t, qos, "RawBytes");
    const ws = track(new WaitSet());
    ws.attachReader(r);

    w.write(Buffer.from([0x00, 0x01, 0x00, 0x00, 0x2a]));
    expect(ws.wait(2.0)).toBe(true);
    const got = r.take();
    expect(got).not.toBeNull();
    expect([...got!]).toEqual([0x00, 0x01, 0x00, 0x00, 0x2a]);
  });

  it("writer_use_after_dispose_throws", () => {
    const p = intraParticipant("wdisp");
    const w = p.createWriter(topic("NativeWriterDisposed"), QoS.reliable());
    w.dispose();
    expect(() => w.write(Buffer.from("x"))).toThrow(HddsError);
  });
});

suite("waitset", () => {
  it("wait_times_out_and_returns_false", () => {
    const p = intraParticipant("timeout");
    const r = p.createReader(topic("NativeTimeout"), QoS.reliable());
    const ws = track(new WaitSet());
    ws.attachReader(r);

    const started = process.hrtime.bigint();
    expect(ws.wait(0.2)).toBe(false);
    const elapsedMs = Number(process.hrtime.bigint() - started) / 1e6;
    // Generous upper bound: this box runs several suites at once.
    expect(elapsedMs).toBeGreaterThanOrEqual(150);
    expect(elapsedMs).toBeLessThan(5000);
  });

  it("guard_condition_trigger_wakes_wait", () => {
    const ws = track(new WaitSet());
    const guard = track(new GuardCondition());
    ws.attachGuard(guard);

    expect(ws.wait(0.1)).toBe(false);
    guard.trigger();
    expect(ws.wait(2.0)).toBe(true);
    guard.reset();
    expect(ws.wait(0.1)).toBe(false);
  });
});

suite("qos", () => {
  it("qos_getters_reflect_the_setters", () => {
    const qos = track(QoS.reliable().transientLocal().historyDepth(12));
    expect(qos.isReliable()).toBe(true);
    expect(qos.isTransientLocal()).toBe(true);
    expect(qos.getHistoryDepth()).toBe(12);

    const be = track(QoS.bestEffort().historyDepth(3));
    expect(be.isReliable()).toBe(false);
    expect(be.getHistoryDepth()).toBe(3);
  });

  it("resource_limits_unlimited_reaches_the_c_abi_as_size_max", () => {
    // Regression: Number.MAX_SAFE_INTEGER was passed through as a finite
    // limit, so max_samples=500 alone failed max_samples >= per_instance.
    const p = intraParticipant("rl_unlimited");
    for (const unlimited of [Number.MAX_SAFE_INTEGER, -1]) {
      const qos = track(
        QoS.reliable().historyDepth(20).resourceLimits(500, unlimited, unlimited)
      );
      expect(qos.getMaxSamples()).toBe(500);
      expect(BigInt(qos.getMaxInstances())).toBe(0xffff_ffff_ffff_ffffn);
      expect(BigInt(qos.getMaxSamplesPerInstance())).toBe(0xffff_ffff_ffff_ffffn);
      expect(() => track(p.createWriter(`rl_unlimited_${unlimited}`, qos))).not.toThrow();
    }
  });

  it("inconsistent_history_and_limits_refuse_reader_and_writer_naming_the_rule", () => {
    // DDS 1.4 2.2.3.18: depth <= max_samples_per_instance; 2.2.3.19:
    // max_samples >= max_samples_per_instance. Both entities are refused.
    const p = intraParticipant("rl_inconsistent");
    const deep = track(QoS.reliable().historyDepth(100).resourceLimits(500, 10, 50));
    expect(deep.consistencyProblems()).toEqual([
      "history depth (100) must be <= resource_limits max_samples_per_instance (50)",
    ]);
    expect(() => track(p.createReader("rl_deep_r", deep))).toThrow(
      /reader.*history depth \(100\) must be <=/
    );
    expect(() => track(p.createWriter("rl_deep_w", deep))).toThrow(
      /writer.*history depth \(100\) must be <=/
    );
    const total = track(QoS.reliable().historyDepth(5).resourceLimits(10, -1, 20));
    expect(() => track(p.createReader("rl_total_r", total))).toThrow(
      /max_samples \(10\) must be >= max_samples_per_instance \(20\)/
    );
    const ok = track(QoS.reliable().historyDepth(20).resourceLimits(500, 10, 50));
    expect(ok.consistencyProblems()).toEqual([]);
    expect(() => track(p.createReader("rl_ok_r", ok))).not.toThrow();
  });

  it("qos_deadline_and_lifespan_round_trip_in_nanoseconds", () => {
    const qos = track(QoS.reliable().deadlineMs(250).lifespanMs(1000));
    expect(qos.getDeadlineNs()).toBe(250_000_000n);
    expect(qos.getLifespanNs()).toBe(1_000_000_000n);
  });
});

suite("data representation", () => {
  // DDS-XTypes 1.3 7.6.3.1.1: a reader requests what its decoders read.
  const CDR_LE = 0x0001;
  const CDR2_LE = 0x0007;

  it("data_representation_takes_xcdr_and_xcdr2_only", () => {
    const qos = track(QoS.reliable());
    expect(qos.getDataRepresentation()).toEqual([]);
    qos.dataRepresentation(QoS.XCDR_DATA_REPRESENTATION, QoS.XCDR2_DATA_REPRESENTATION);
    expect(qos.getDataRepresentation()).toEqual([0, 2]);
    expect(() => qos.dataRepresentation(1)).toThrow(HddsError);
    expect(qos.getDataRepresentation()).toEqual([0, 2]);
    qos.dataRepresentation();
    expect(qos.getDataRepresentation()).toEqual([]);
  });

  it("a_reader_told_an_xcdr1_codec_requests_both_and_dispatches_by_representation", () => {
    const p = intraParticipant("datarep");
    const t = topic("NativeDatarep");
    const x1 = p.createWriter(
      t,
      track(QoS.reliable().dataRepresentation(QoS.XCDR_DATA_REPRESENTATION))
    );
    const x2 = p.createWriter(t, track(QoS.reliable()));
    const r = p.createReader(t, track(QoS.reliable()), null, { HDDS_DECODES_XCDR1: true });
    expect(r.qos!.getDataRepresentation()).toEqual([0, 2]);

    x1.write(Buffer.from([1, 2, 3, 4]));
    x2.write(Buffer.from([5, 6, 7, 8]));
    const byEncapsulation = (id: number, data: Uint8Array) => [id, Array.from(data)];
    expect(r.takeTyped(byEncapsulation)).toEqual([CDR_LE, [1, 2, 3, 4]]);
    expect(r.takeTyped(byEncapsulation)).toEqual([CDR2_LE, [5, 6, 7, 8]]);
    expect(r.takeTyped(byEncapsulation)).toBeNull();

    // An XCDR2-only decoder (one parameter) is never handed XCDR1 bytes.
    const xcdr2Only = (data: Uint8Array) => Array.from(data);
    x1.write(Buffer.from([9, 9, 9, 9]));
    expect(() => r.takeTyped(xcdr2Only)).toThrow(/XCDR1/);
    x2.write(Buffer.from([7, 7, 7, 7]));
    expect(r.takeTyped(xcdr2Only)).toEqual([7, 7, 7, 7]);
  });

  it("a_reader_of_an_old_codec_requests_xcdr2_and_misses_an_xcdr1_writer", () => {
    const p = intraParticipant("datarep_old");
    const t = topic("NativeDatarepOld");
    const r = p.createReader(t, track(QoS.reliable()), null, {});
    expect(r.qos!.getDataRepresentation()).toEqual([]);
    const x1 = p.createWriter(
      t,
      track(QoS.reliable().dataRepresentation(QoS.XCDR_DATA_REPRESENTATION))
    );
    x1.write(Buffer.from([1, 0, 0, 0]));
    expect(r.takeWithEncapsulation()).toBeNull();
  });

  /**
   * Item 3 (datarep-default upgrade path): on a native library that
   * predates hdds_qos_set_data_representation/hdds_reader_take_ex, a
   * reader of a codec that decodes XCDR1 (HDDS_DECODES_XCDR1) cannot be
   * made to request XCDR2 only, and takeWithEncapsulation cannot learn a
   * taken sample's true representation either -- its fallback always
   * assumes CDR2_LE. Before this fix, createReader silently left such a
   * reader's QoS at the empty default, which this library's own
   * resolve_reader_data_representation announces as [XCDR, XCDR2]: a
   * reader that could match an XCDR1 writer and then have
   * takeWithEncapsulation mislabel its samples CDR2_LE. It must refuse
   * instead.
   */
  it("createReader_refuses_rather_than_mislabel_on_an_old_library", () => {
    const native = getNativeLib() as Record<string, unknown>;
    const real = native["hdds_qos_set_data_representation"];
    delete native["hdds_qos_set_data_representation"];
    try {
      const p = intraParticipant("datarep_no_ex");
      const t = topic("NativeDatarepNoEx");
      expect(() =>
        p.createReader(t, track(QoS.reliable()), null, { HDDS_DECODES_XCDR1: true })
      ).toThrow(/XCDR1/);
      // A codec that decodes XCDR2 only never reaches the ABI check.
      expect(() => track(p.createReader(t, track(QoS.reliable()), null, {}))).not.toThrow();
    } finally {
      native["hdds_qos_set_data_representation"] = real;
    }
  });
});

suite("writer extensibility", () => {
  /**
   * DDS-XTypes 1.3 7.6.3.1.2, Table 60: the encapsulation identifier of a
   * sample names its type's extensibility. createWriter hands the
   * `extensibility<Name>` a generated module (hdds_gen 2.0) exports to the
   * C ABI writer, which labels every sample with it (the bytes on the wire
   * are checked by scripts/test-sdk-typed.sh); without one the writer of
   * earlier releases is kept (every sample CDR2_LE); a string that is none
   * of the three is refused before any FFI call.
   */
  it("createWriter_hands_the_generated_extensibility_to_the_c_abi", () => {
    // What a generated module exports (`export const extensibility<Name>`).
    const generated = {
      extensibilityApp: "appendable" as const,
      extensibilityMut: "mutable" as const,
      extensibilityFin: "final" as const,
    };
    const native = getNativeLib() as unknown as Record<string, unknown>;
    const name = "hdds_writer_create_with_extensibility";
    const real = native[name] as (...args: unknown[]) => unknown;
    const seen: number[] = [];
    native[name] = (...args: unknown[]) => {
      seen.push(args[4] as number);
      return real(...args);
    };
    try {
      const p = intraParticipant("ts_ext");
      track(p.createWriter(topic("TsExtA"), null, null, generated.extensibilityApp));
      track(p.createWriter(topic("TsExtM"), track(QoS.reliable()), null, generated.extensibilityMut));
      track(p.createWriter(topic("TsExtF"), null, null, generated.extensibilityFin));
      track(p.createWriter(topic("TsExtNone"), track(QoS.reliable())));
      expect(() =>
        p.createWriter(topic("TsExtBad"), null, null, "extensible" as unknown as "final")
      ).toThrow(HddsError);
      expect(seen).toEqual([1, 2, 0]);
    } finally {
      native[name] = real;
    }
  });

  /**
   * The natural call: the whole generated module, read via `typeName` the
   * same way `createReader`'s `codec` is -- `createWriter(topic, qos,
   * "TsExtModApp", generatedModule)` -- instead of the caller naming
   * `extensibility<Name>` itself. An explicit literal still overrides it;
   * a `typeName` the module has no constant for falls back to FINAL
   * rather than throwing.
   */
  it("createWriter_derives_the_extensibility_from_the_generated_module_and_typeName", () => {
    // One module, several generated types -- exactly what `import * as
    // Types from "./MyTypes"` gives createWriter.
    const Types = {
      extensibilityTsExtModApp: "appendable" as const,
      extensibilityTsExtModMut: "mutable" as const,
    };
    const native = getNativeLib() as unknown as Record<string, unknown>;
    const name = "hdds_writer_create_with_extensibility";
    const real = native[name] as (...args: unknown[]) => unknown;
    const seen: number[] = [];
    native[name] = (...args: unknown[]) => {
      seen.push(args[4] as number);
      return real(...args);
    };
    try {
      const p = intraParticipant("ts_ext_mod");
      track(p.createWriter(topic("TsExtModApp"), null, "TsExtModApp", Types));
      track(
        p.createWriter(topic("TsExtModMut"), track(QoS.reliable()), "TsExtModMut", Types)
      );
      // An explicit literal still wins over the module.
      track(p.createWriter(topic("TsExtModOverride"), null, "TsExtModApp", "final"));
      expect(seen).toEqual([1, 2, 0]);
    } finally {
      native[name] = real;
    }

    // A typeName the module has no extensibility<Name> for: no FFI call
    // to hdds_writer_create_with_extensibility at all, same as passing
    // nothing -- the writer labels every sample FINAL as before.
    const p = intraParticipant("ts_ext_mod_miss");
    const spy = native[name] as (...args: unknown[]) => unknown;
    let called = false;
    native[name] = (...args: unknown[]) => {
      called = true;
      return spy(...args);
    };
    try {
      track(p.createWriter(topic("TsExtModMiss"), null, "NoSuchType", Types));
      expect(called).toBe(false);
    } finally {
      native[name] = real;
    }
  });
});
