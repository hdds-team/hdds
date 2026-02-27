// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * HDDS TypeScript SDK - Participant
 *
 * Entry point for DDS communication. Wraps hdds_participant_create/destroy.
 */

import { getNativeLib } from "./native.js";
import {
  type Pointer,
  type TransportModeValue,
  TransportMode,
  HddsError,
} from "./types.js";
import { QoS } from "./qos.js";
import { DataWriter } from "./writer.js";
import { DataReader } from "./reader.js";

/**
 * Options for creating a Participant.
 */
export interface ParticipantOptions {
  /**
   * Transport mode for network communication.
   * Default: TransportMode.UDP_MULTICAST
   */
  transport?: TransportModeValue;
}

/**
 * DDS Domain Participant.
 *
 * The Participant is the entry point for all DDS operations.
 * It manages discovery, writers, readers, and topics within a DDS domain.
 *
 * @example
 * ```typescript
 * // Create a participant with default settings (UDP multicast)
 * const participant = Participant.create("my_app");
 *
 * // Create writer and reader
 * const writer = participant.createWriter("temperature");
 * const reader = participant.createReader("temperature");
 *
 * // Write data
 * writer.write(Buffer.from(JSON.stringify({ value: 23.5 })));
 *
 * // Read data
 * const data = reader.take();
 *
 * // Clean up
 * participant.dispose();
 * ```
 *
 * @example
 * ```typescript
 * // Intra-process mode (no network, fastest for same-process communication)
 * const participant = Participant.create("local_app", {
 *   transport: TransportMode.INTRA_PROCESS,
 * });
 * ```
 */
export class Participant {
  /** @internal Native participant handle */
  private _handle: Pointer;
  private readonly _name: string;
  private readonly _writers: DataWriter[] = [];
  private readonly _readers: DataReader[] = [];

  private constructor(name: string, handle: Pointer) {
    this._name = name;
    this._handle = handle;
  }

  /**
   * Create a new DDS Participant.
   *
   * @param name - Application/participant name
   * @param options - Optional configuration (transport mode, etc.)
   * @returns A new Participant instance
   * @throws HddsError if creation fails
   */
  static create(name: string, options?: ParticipantOptions): Participant {
    const native = getNativeLib();
    const transport = options?.transport ?? TransportMode.UDP_MULTICAST;

    const handle = native.hdds_participant_create_with_transport(
      name,
      transport
    );
    if (!handle) {
      throw new HddsError(`Failed to create participant "${name}"`);
    }

    return new Participant(name, handle);
  }

  // ===========================================================================
  // Properties
  // ===========================================================================

  /**
   * Get the participant name (from the native library).
   */
  get name(): string {
    if (!this._handle) return this._name;
    const native = getNativeLib();
    const result = native.hdds_participant_name(this._handle);
    return result ?? this._name;
  }

  /**
   * Get the DDS domain ID.
   */
  get domainId(): number {
    this.ensureHandle();
    const native = getNativeLib();
    return native.hdds_participant_domain_id(this._handle);
  }

  /**
   * Get the unique participant ID within the domain.
   */
  get participantId(): number {
    this.ensureHandle();
    const native = getNativeLib();
    return native.hdds_participant_id(this._handle);
  }

  // ===========================================================================
  // Writer / Reader Creation
  // ===========================================================================

  /**
   * Create a DataWriter for the given topic.
   *
   * @param topicName - Name of the DDS topic
   * @param qos - QoS configuration (null for default)
   * @returns A new DataWriter
   * @throws HddsError if creation fails
   *
   * @example
   * ```typescript
   * const writer = participant.createWriter("sensor_data",
   *   QoS.reliable().transientLocal()
   * );
   * ```
   */
  createWriter<T = unknown>(
    topicName: string,
    qos?: QoS | null
  ): DataWriter<T> {
    this.ensureHandle();
    const native = getNativeLib();

    let handle: Pointer;
    if (qos) {
      handle = native.hdds_writer_create_with_qos(
        this._handle,
        topicName,
        qos.nativeHandle
      );
    } else {
      handle = native.hdds_writer_create(this._handle, topicName);
    }

    if (!handle) {
      throw new HddsError(
        `Failed to create writer for topic "${topicName}"`
      );
    }

    const writer = DataWriter._fromHandle<T>(topicName, handle, qos ?? null);
    this._writers.push(writer as DataWriter);
    return writer;
  }

  /**
   * Create a DataReader for the given topic.
   *
   * @param topicName - Name of the DDS topic
   * @param qos - QoS configuration (null for default)
   * @returns A new DataReader
   * @throws HddsError if creation fails
   *
   * @example
   * ```typescript
   * const reader = participant.createReader("sensor_data",
   *   QoS.reliable()
   * );
   * const data = reader.take();
   * ```
   */
  createReader<T = unknown>(
    topicName: string,
    qos?: QoS | null
  ): DataReader<T> {
    this.ensureHandle();
    const native = getNativeLib();

    let handle: Pointer;
    if (qos) {
      handle = native.hdds_reader_create_with_qos(
        this._handle,
        topicName,
        qos.nativeHandle
      );
    } else {
      handle = native.hdds_reader_create(this._handle, topicName);
    }

    if (!handle) {
      throw new HddsError(
        `Failed to create reader for topic "${topicName}"`
      );
    }

    const reader = DataReader._fromHandle<T>(topicName, handle, qos ?? null);
    this._readers.push(reader as DataReader);
    return reader;
  }

  // ===========================================================================
  // Lifecycle
  // ===========================================================================

  /**
   * Destroy the participant and all associated writers/readers.
   * After calling dispose(), this instance must not be used.
   */
  dispose(): void {
    // Destroy writers first
    for (const writer of this._writers) {
      writer._destroy();
    }
    this._writers.length = 0;

    // Destroy readers
    for (const reader of this._readers) {
      reader._destroy();
    }
    this._readers.length = 0;

    // Destroy participant
    if (this._handle) {
      const native = getNativeLib();
      native.hdds_participant_destroy(this._handle);
      this._handle = null;
    }
  }

  toString(): string {
    return `Participant(name="${this._name}", domainId=${this._handle ? this.domainId : "?"})`;
  }

  private ensureHandle(): void {
    if (!this._handle) {
      throw new HddsError("Participant has been disposed");
    }
  }
}
