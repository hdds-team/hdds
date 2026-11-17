// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * HDDS TypeScript SDK - DataWriter
 *
 * Wraps hdds_writer_create / hdds_writer_write / hdds_writer_destroy.
 */

import { getNativeLib } from "./native.js";
import { type Pointer, HddsError, checkError } from "./types.js";
import type { WriterCodec } from "./participant.js";
import type { SerializedKey } from "./native.js";
import type { QoS } from "./qos.js";

/**
 * DDS DataWriter for publishing data to a topic.
 *
 * Created via `Participant.createWriter()` or `Publisher.createWriter()`.
 * Do not instantiate directly.
 *
 * @example
 * ```typescript
 * const writer = participant.createWriter<MyMessage>("my_topic");
 * writer.write(Buffer.from(JSON.stringify({ value: 42 })));
 * writer.dispose();
 * ```
 */
export class DataWriter<_T = unknown> {
  /** @internal Native writer handle */
  private _handle: Pointer;
  private readonly _topicName: string;
  private readonly _qos: QoS | null;

  /** @internal Factory method -- do not call directly */
  static _fromHandle<T>(
    topicName: string,
    handle: Pointer,
    qos: QoS | null,
    codec?: WriterCodec,
    typeName?: string | null,
    keyed = false
  ): DataWriter<T> {
    return new DataWriter<T>(topicName, handle, qos, codec, typeName, keyed);
  }

  private constructor(topicName: string, handle: Pointer, qos: QoS | null,
                      private readonly codec?: WriterCodec, private readonly typeName?: string | null,
                      private readonly keyed = false) {
    this._topicName = topicName;
    this._handle = handle;
    this._qos = qos;
  }

  /** Topic name this writer publishes to. */
  get topicName(): string {
    return this._topicName;
  }

  /** QoS configuration (may be null if default was used). */
  get qos(): QoS | null {
    return this._qos;
  }

  /**
   * Write raw bytes to the topic.
   *
   * @param data - Data buffer to publish. Can be a Buffer, Uint8Array, or ArrayBuffer.
   * @throws HddsError if the write fails
   */
  write(data: Buffer | Uint8Array | ArrayBuffer): void {
    this.ensureHandle();
    const native = getNativeLib();

    let buf: Buffer;
    if (Buffer.isBuffer(data)) {
      buf = data;
    } else if (data instanceof Uint8Array) {
      buf = Buffer.from(data.buffer, data.byteOffset, data.byteLength);
    } else if (data instanceof ArrayBuffer) {
      buf = Buffer.from(data);
    } else {
      throw new HddsError("Expected Buffer, Uint8Array, or ArrayBuffer");
    }

    if (this.keyed) {
      const codec = this.codec!;
      const Cursor = codec["Cdr2Buffer"] as new (bytes: Uint8Array) => unknown;
      const decode = codec["decode" + this.typeName] as (cursor: unknown) => _T;
      if (typeof decode !== "function" || !Cursor) throw new HddsError("pre-encoded keyed operations require a decoding codec");
      this.typedOperation("write", decode(new Cursor(buf)), buf);
      return;
    }
    const err = native.hdds_writer_write(this._handle, buf, buf.length);
    checkError(err, `write to topic "${this._topicName}"`);
  }

  /** Encode with the generated module passed to createWriter(). */
  writeTyped(data: _T): void {
    this.typedOperation("write", data);
  }

  /** Dispose a DDS instance; the writer remains usable. */
  disposeInstance(data: _T): void {
    this.typedOperation("dispose", data);
  }

  unregisterInstance(data: _T): void {
    this.typedOperation("unregister_instance", data);
  }

  registerInstance(data: _T): Buffer {
    return this.typedOperation("register_instance", data)!;
  }

  private typedOperation(operation: string, data: _T, serialized?: Buffer): Buffer | undefined {
    this.ensureHandle();
    const codec = this.codec;
    const name = this.typeName;
    if (!codec || !name) throw new HddsError("typed operations require a generated module and type name");
    const Cursor = codec["Cdr2Buffer"] as new (bytes: Uint8Array) => { toBytes(): Uint8Array };
    const encode = (prefix: string): Buffer => {
      const fn = codec[prefix + name] as (data: _T, cursor: unknown) => void;
      if (typeof fn !== "function" || !Cursor) throw new HddsError("missing generated encoder: " + prefix + name);
      for (let size = 1024; size <= 16 * 1024 * 1024; size *= 2) {
        const cursor = new Cursor(new Uint8Array(size));
        try {
          fn(data, cursor);
          return Buffer.from(cursor.toBytes());
        } catch (error) {
          if (!(error instanceof RangeError)) throw error;
        }
      }
      throw new HddsError("serialized data exceeds 16MB");
    };
    const keyed = this.keyed;
    const bytes = serialized ?? (operation === "write" || !keyed ? encode("encode") : Buffer.alloc(0));
    if (!keyed) {
      if (operation !== "write") throw new HddsError("instance operations require a keyed type");
      this.write(bytes);
      return;
    }
    if (!codec["keySupported" + name]) throw new HddsError("unsupported keyed type");
    const hash = codec["computeKey" + name] as (data: _T, protectedKey?: boolean) => Uint8Array;
    const payload = encode("encodeKey");
    const key: SerializedKey = {
      hash: Array.from(hash(data)), protected_hash: Array.from(hash(data, true)),
      payload, payload_len: payload.length, representation: 2,
    };
    const native = getNativeLib();
    const handle = Buffer.alloc(16);
    let error: number;
    if (operation === "register_instance") {
      if (!native.hdds_writer_register_instance_keyed) throw new HddsError("missing keyed writer ABI");
      error = native.hdds_writer_register_instance_keyed(this._handle, bytes, bytes.length, key, handle);
    } else {
      const fn = operation === "write" ? native.hdds_writer_write_keyed :
        operation === "dispose" ? native.hdds_writer_dispose_keyed : native.hdds_writer_unregister_instance_keyed;
      if (!fn) throw new HddsError("missing keyed writer ABI");
      error = fn(this._handle, bytes, bytes.length, key);
    }
    checkError(error, operation + " keyed instance");
    return operation === "register_instance" ? handle : undefined;
  }

  /**
   * Write a JavaScript object to the topic as JSON-encoded bytes.
   *
   * Convenience method that serializes the object to JSON and writes the
   * resulting UTF-8 bytes.
   *
   * **Warning:** JSON encoding is NOT CDR-compatible. Data written with
   * `writeJson()` will NOT interop with C/C++/Python DDS readers that
   * expect CDR2 serialization. Use this only when both sides use JSON
   * (e.g., TypeScript-to-TypeScript via HDDS, or with hdds-ws bridge).
   * For cross-language interop, use `write()` with CDR2-encoded buffers.
   *
   * @param obj - Object to serialize and publish
   * @throws HddsError if the write fails
   */
  writeJson(obj: unknown): void {
    const json = JSON.stringify(obj);
    this.write(Buffer.from(json, "utf-8"));
  }

  /**
   * Destroy the writer and release native resources.
   * After calling dispose(), this instance must not be used.
   */
  dispose(): void {
    if (this._handle) {
      const native = getNativeLib();
      native.hdds_writer_destroy(this._handle);
      this._handle = null;
    }
  }

  /** @internal Called by Participant during cleanup */
  _destroy(): void {
    this.dispose();
  }

  toString(): string {
    return `DataWriter(topic="${this._topicName}")`;
  }

  private ensureHandle(): void {
    if (!this._handle) {
      throw new HddsError("DataWriter has been disposed");
    }
  }
}
