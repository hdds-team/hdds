// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * HDDS TypeScript SDK - DataWriter
 *
 * Wraps hdds_writer_create / hdds_writer_write / hdds_writer_destroy.
 */

import { getNativeLib } from "./native.js";
import { type Pointer, HddsError, checkError } from "./types.js";
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
    qos: QoS | null
  ): DataWriter<T> {
    return new DataWriter<T>(topicName, handle, qos);
  }

  private constructor(topicName: string, handle: Pointer, qos: QoS | null) {
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

    const err = native.hdds_writer_write(this._handle, buf, buf.length);
    checkError(err, `write to topic "${this._topicName}"`);
  }

  /**
   * Write a JavaScript object to the topic as JSON-encoded bytes.
   *
   * Convenience method that serializes the object to JSON and writes the
   * resulting UTF-8 bytes.
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
