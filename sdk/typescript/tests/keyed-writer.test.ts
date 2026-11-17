// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

import { beforeEach, describe, expect, it, vi } from "vitest";
import { Participant } from "../src/participant.js";
import { DataWriter } from "../src/writer.js";

const native = vi.hoisted(() => ({
  hdds_writer_create_keyed: vi.fn(() => 1),
  hdds_writer_create_with_extensibility: vi.fn(() => 1),
  hdds_writer_write: vi.fn(() => 0),
  hdds_writer_write_keyed: vi.fn(() => 0),
  hdds_writer_dispose_keyed: vi.fn(() => 0),
  hdds_writer_unregister_instance_keyed: vi.fn(() => 0),
  hdds_writer_register_instance_keyed: vi.fn((_w, _b, _n, key, handle) => {
    Buffer.from(key.hash).copy(handle); return 0;
  }),
}));
vi.mock("../src/native.js", () => ({ getNativeLib: () => native }));

class Cursor {
  bytes = new Uint8Array();
  constructor(_storage: Uint8Array) {}
  toBytes(): Uint8Array { return this.bytes; }
}
const normal = Buffer.from("00000001000000000000000000000000", "hex");
const protectedHash = Buffer.from("f1450306517624a57eafbbf8ed995985", "hex");
const codec = {
  Cdr2Buffer: Cursor, hasKeyRow: true, keySupportedRow: true,
  encodeRow: (_row: unknown, cursor: Cursor) => { cursor.bytes = new Uint8Array([1, 0, 0, 0, 9, 0, 0, 0]); },
  decodeRow: (_cursor: Cursor) => ({}),
  encodeKeyRow: (_row: unknown, cursor: Cursor) => { cursor.bytes = new Uint8Array([1, 0, 0, 0]); },
  computeKeyRow: (_row: unknown, protectedKey = false) => protectedKey ? protectedHash : normal,
};

describe("typed keyed writer", () => {
  beforeEach(() => vi.clearAllMocks());
  it.each(["writeTyped", "disposeInstance", "unregisterInstance", "registerInstance"] as const)(
    "%s preserves normal hash, protected digest and key payload", (operation) => {
      const writer = DataWriter._fromHandle("keys", 1 as never, null, codec, "Row", true);
      const handle = writer[operation]({});
      const fn = operation === "writeTyped" ? native.hdds_writer_write_keyed :
        operation === "disposeInstance" ? native.hdds_writer_dispose_keyed :
        operation === "unregisterInstance" ? native.hdds_writer_unregister_instance_keyed :
        native.hdds_writer_register_instance_keyed;
      expect(fn).toHaveBeenCalledOnce();
      const args = fn.mock.calls[0] as unknown[];
      expect(args[2]).toBe(operation === "writeTyped" ? 8 : 0);
      expect(args[3]).toEqual({ hash: Array.from(normal), protected_hash: Array.from(protectedHash),
        payload: Buffer.from([1, 0, 0, 0]), payload_len: 4, representation: 2 });
      if (operation === "registerInstance") expect(handle).toEqual(normal);
    }
  );
  it("refuses a key whose serialization is unsupported", () => {
    const writer = DataWriter._fromHandle("keys", 1 as never, null, { ...codec, keySupportedRow: false }, "Row", true);
    expect(() => writer.writeTyped({})).toThrow("unsupported keyed type");
    expect(native.hdds_writer_write_keyed).not.toHaveBeenCalled();
  });
  it("does not encode non-key fields for lifecycle operations", () => {
    const writer = DataWriter._fromHandle("keys", 1 as never, null,
      { ...codec, encodeRow: () => { throw new Error("non-key data read"); } }, "Row", true);
    writer.disposeInstance({});
    expect(native.hdds_writer_dispose_keyed).toHaveBeenCalledOnce();
  });
  it("keeps older codecs on the legacy writer ABI", () => {
    const older = { ...codec } as Record<string, unknown>;
    delete older.hasKeyRow;
    const writer = DataWriter._fromHandle("keys", 1 as never, null, older, "Row");
    writer.writeTyped({});
    expect(native.hdds_writer_write).toHaveBeenCalledOnce();
    expect(native.hdds_writer_write_keyed).not.toHaveBeenCalled();
  });

  it("accepts encoded bytes on a typed keyed writer", () => {
    const writer = DataWriter._fromHandle("keys", 1 as never, null, codec, "Row", true);
    const bytes = Buffer.from([1, 0, 0, 0, 9, 0, 0, 0]);
    writer.write(bytes);
    expect(native.hdds_writer_write_keyed).toHaveBeenCalledOnce();
    expect(native.hdds_writer_write_keyed.mock.calls[0][1]).toEqual(bytes);
    expect(native.hdds_writer_write).not.toHaveBeenCalled();
  });

  it("dispatches a keyed message through the writer's legacy ABI", () => {
    const writer = DataWriter._fromHandle("keys", 1 as never, null, codec, "Row");
    writer.writeTyped({});
    expect(native.hdds_writer_write).toHaveBeenCalledOnce();
    expect(native.hdds_writer_write_keyed).not.toHaveBeenCalled();
  });

  it("uses an encoding-only codec for typed writes", () => {
    const writer = DataWriter._fromHandle("keys", 1 as never, null,
      { ...codec, decodeRow: undefined }, "Row", true);
    writer.writeTyped({});
    expect(native.hdds_writer_write_keyed).toHaveBeenCalledOnce();
    expect(() => writer.write(Buffer.from([1, 0, 0, 0]))).toThrow("decoding codec");
  });

  it.each([true, false])("constructor keeps an encoding-only keyed codec (decoder=%s)", (decoder) => {
    const participant = Object.assign(Object.create(Participant.prototype), { _handle: 1, _writers: [] }) as Participant;
    const writer = participant.createWriter("keys", null, "Row",
      { ...codec, extensibilityRow: "final", decodeRow: decoder ? codec.decodeRow : undefined });
    writer.writeTyped({});
    expect(native.hdds_writer_create_keyed).toHaveBeenCalledOnce();
    expect(native.hdds_writer_create_with_extensibility).not.toHaveBeenCalled();
    expect(native.hdds_writer_write_keyed).toHaveBeenCalledOnce();
  });

});
