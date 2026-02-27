// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * HDDS TypeScript SDK - DataReader
 *
 * Wraps hdds_reader_create / hdds_reader_take / hdds_reader_destroy.
 */

import { getNativeLib } from "./native.js";
import { type Pointer, HddsError, HddsErrorCode } from "./types.js";
import type { QoS } from "./qos.js";

/** Default buffer size for reader take operations (64 KB). */
const DEFAULT_BUFFER_SIZE = 65536;

/**
 * DDS DataReader for subscribing to data on a topic.
 *
 * Created via `Participant.createReader()` or `Subscriber.createReader()`.
 * Do not instantiate directly.
 *
 * @example
 * ```typescript
 * const reader = participant.createReader<MyMessage>("my_topic");
 *
 * // Non-blocking take
 * const data = reader.take();
 * if (data !== null) {
 *   const msg = JSON.parse(data.toString("utf-8"));
 *   console.log(msg);
 * }
 *
 * reader.dispose();
 * ```
 */
export class DataReader<_T = unknown> {
  /** @internal Native reader handle */
  private _handle: Pointer;
  private readonly _topicName: string;
  private readonly _qos: QoS | null;
  private _statusCondition: Pointer = null;

  /** @internal Factory method -- do not call directly */
  static _fromHandle<T>(
    topicName: string,
    handle: Pointer,
    qos: QoS | null
  ): DataReader<T> {
    return new DataReader<T>(topicName, handle, qos);
  }

  private constructor(topicName: string, handle: Pointer, qos: QoS | null) {
    this._topicName = topicName;
    this._handle = handle;
    this._qos = qos;
  }

  /** Topic name this reader subscribes to. */
  get topicName(): string {
    return this._topicName;
  }

  /** QoS configuration (may be null if default was used). */
  get qos(): QoS | null {
    return this._qos;
  }

  /**
   * Take one sample from the reader (non-blocking).
   *
   * @param bufferSize - Maximum number of bytes to read (default: 64 KB)
   * @returns Buffer containing the data, or null if no data is available
   * @throws HddsError on read errors (other than NOT_FOUND)
   */
  take(bufferSize: number = DEFAULT_BUFFER_SIZE): Buffer | null {
    this.ensureHandle();
    const native = getNativeLib();

    const buf = Buffer.alloc(bufferSize);
    const lenOut = [0];

    const err = native.hdds_reader_take(
      this._handle,
      buf,
      bufferSize,
      lenOut
    );

    if (err === HddsErrorCode.NOT_FOUND) {
      return null; // No data available
    }
    if (err !== HddsErrorCode.OK) {
      const codeName =
        err === HddsErrorCode.WOULD_BLOCK ? "WOULD_BLOCK" : `code=${err}`;
      throw new HddsError(
        `take from topic "${this._topicName}": ${codeName}`,
        err
      );
    }

    const actualLen = lenOut[0];
    return buf.subarray(0, actualLen);
  }

  /**
   * Take one sample and parse it as JSON.
   *
   * Convenience method that takes raw bytes and parses them as a JSON string.
   *
   * @param bufferSize - Maximum number of bytes to read
   * @returns Parsed object, or null if no data is available
   */
  takeJson<R = _T>(bufferSize: number = DEFAULT_BUFFER_SIZE): R | null {
    const data = this.take(bufferSize);
    if (data === null) {
      return null;
    }
    return JSON.parse(data.toString("utf-8")) as R;
  }

  /**
   * Get the status condition associated with this reader.
   * Used for WaitSet integration.
   *
   * @returns Opaque status condition handle
   * @throws HddsError if reader has been disposed
   */
  getStatusCondition(): Pointer {
    this.ensureHandle();
    if (this._statusCondition === null) {
      const native = getNativeLib();
      this._statusCondition = native.hdds_reader_get_status_condition(
        this._handle
      );
    }
    return this._statusCondition;
  }

  /**
   * Destroy the reader and release native resources.
   * After calling dispose(), this instance must not be used.
   */
  dispose(): void {
    if (this._handle) {
      const native = getNativeLib();
      native.hdds_reader_destroy(this._handle);
      this._handle = null;
      this._statusCondition = null;
    }
  }

  /** @internal Called by Participant during cleanup */
  _destroy(): void {
    this.dispose();
  }

  toString(): string {
    return `DataReader(topic="${this._topicName}")`;
  }

  private ensureHandle(): void {
    if (!this._handle) {
      throw new HddsError("DataReader has been disposed");
    }
  }
}
