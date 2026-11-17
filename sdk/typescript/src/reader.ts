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

/** Encapsulation identifier of an XCDR2 sample (DDS-XTypes 1.3 Table 60). */
const CDR2_LE = 0x0007;

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
   * Take one sample and the representation it is in (non-blocking).
   *
   * `encapsulationId` is `CDR_LE` (0x0001) for XCDR1 and `CDR2_LE` (0x0007)
   * for XCDR2: what the generated `decode<Name>ByEncapsulation` takes (the
   * encoding version; the extensibility framing is not reported). With a
   * library older than `hdds_reader_take_ex`, it is always 0x0007: this
   * reader's codec does NOT decode XCDR1 (`createReader` refuses at
   * creation otherwise, rather than let this path ever report a taken
   * sample's true representation wrong), and such a reader requests
   * XCDR2 only.
   *
   * @returns The body and its identifier, or null if no data is available
   * @throws HddsError on read errors (other than NOT_FOUND)
   */
  takeWithEncapsulation(
    bufferSize: number = DEFAULT_BUFFER_SIZE
  ): { data: Buffer; encapsulationId: number } | null {
    this.ensureHandle();
    const native = getNativeLib();
    if (!native.hdds_reader_take_ex) {
      const data = this.take(bufferSize);
      return data === null ? null : { data, encapsulationId: CDR2_LE };
    }
    const buf = Buffer.alloc(bufferSize);
    const lenOut = [0];
    const idOut = [0];
    const err = native.hdds_reader_take_ex(this._handle, buf, bufferSize, lenOut, idOut);
    if (err === HddsErrorCode.NOT_FOUND) {
      return null;
    }
    if (err !== HddsErrorCode.OK) {
      throw new HddsError(`take from topic "${this._topicName}": code=${err}`, err);
    }
    return { data: buf.subarray(0, lenOut[0]), encapsulationId: idOut[0] };
  }

  /**
   * Take one sample and decode it with a generated decoder.
   *
   * `decode` is either `decode<Name>ByEncapsulation(encapsulationId, data)`
   * (two parameters; hdds_gen 2.0, reads XCDR1 and XCDR2) or an XCDR2
   * decoder of one parameter (`(data) => decode<Name>(new Cdr2Buffer(data))`),
   * which is never handed an XCDR1 sample: one is refused with an HddsError
   * rather than misread (it reaches a reader only when its QoS requested
   * XCDR).
   *
   * @returns The decoded value, or null if no data is available
   */
  takeTyped<R>(
    decode:
      | ((encapsulationId: number, data: Uint8Array) => R)
      | ((data: Uint8Array) => R),
    bufferSize: number = DEFAULT_BUFFER_SIZE
  ): R | null {
    const sample = this.takeWithEncapsulation(bufferSize);
    if (sample === null) {
      return null;
    }
    if (decode.length >= 2) {
      return (decode as (id: number, data: Uint8Array) => R)(
        sample.encapsulationId,
        sample.data
      );
    }
    if (sample.encapsulationId !== CDR2_LE) {
      throw new HddsError(
        `take from topic "${this._topicName}": an XCDR1 sample, and the decoder reads XCDR2 only`
      );
    }
    return (decode as (data: Uint8Array) => R)(sample.data);
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
