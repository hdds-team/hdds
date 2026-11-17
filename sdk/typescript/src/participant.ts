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
  HddsErrorCode,
} from "./types.js";
import { QoS } from "./qos.js";
import { DataWriter } from "./writer.js";
import { DataReader } from "./reader.js";

/**
 * What a reader is told about the code that decodes its samples: the
 * generated TypeScript module itself (`import * as types from
 * "./MyTypes"`), whose `HDDS_DECODES_XCDR1` (hdds_gen 2.0) says it decodes
 * XCDR1 as well as XCDR2 (`decode<Name>ByEncapsulation`).
 */
/**
 * The extensibility of an IDL type (DDS-XTypes 1.3 7.2.2.4.4). A module
 * hdds_gen 2.0 or later generated exports it for every structure and union
 * as `extensibility<Name>`.
 */
export type Extensibility = "final" | "appendable" | "mutable";

const EXTENSIBILITY_CODES: Readonly<Record<Extensibility, number>> = {
  final: 0,
  appendable: 1,
  mutable: 2,
};

export interface ReaderCodec {
  readonly HDDS_DECODES_XCDR1?: boolean;
}

/**
 * The generated TypeScript module itself (`import * as Types from
 * "./MyTypes"`), passed to `createWriter` the same way `ReaderCodec` is
 * passed to `createReader`. It exports one `extensibility<Name>` per
 * structure/union (hdds_gen 2.0); `createWriter` reads the one for
 * `typeName` (DDS-XTypes 1.3 7.2.2.4.4), so the natural call --
 * `createWriter(topic, qos, "SensorReading", Types)` -- labels every
 * sample right without the caller naming the constant itself.
 */
export interface WriterCodec {
  readonly [exported: string]: unknown;
}

/**
 * The extensibility `createWriter` resolves from its `extensibility`
 * argument: a literal (`extensibilitySensorReading`, or any of "final",
 * "appendable", "mutable") always wins; a generated module (`WriterCodec`)
 * is read via `extensibility${typeName}` when `typeName` is given, so
 * `createWriter(topic, qos, "SensorReading", Types)` derives it from the
 * module/type pair the same way `createReader`'s `codec` is read. Neither
 * given, or the module exports no such constant (an older `hdds_gen`, or a
 * `typeName` that does not match the generated name): null, which keeps
 * the writer labelling every sample FINAL (the legacy behaviour).
 */
function resolveWriterExtensibility(
  extensibility: Extensibility | WriterCodec | null | undefined,
  typeName: string | null | undefined
): Extensibility | string | null {
  if (extensibility == null) {
    return null;
  }
  if (typeof extensibility === "string") {
    return extensibility;
  }
  if (typeName) {
    const value = extensibility[`extensibility${typeName}`];
    if (typeof value === "string") {
      return value;
    }
  }
  return null;
}

/**
 * Options for creating a Participant.
 */
export interface ParticipantOptions {
  /**
   * DDS domain ID (0-232).
   * Default: HDDS_DOMAIN_ID if set and valid, else 0. A value given here always wins.
   */
  domainId?: number;
  /**
   * Transport mode for network communication.
   * Default: TransportMode.UDP_MULTICAST
   */
  transport?: TransportModeValue;
}

/**
 * The error thrown when the native library refuses a writer or a reader.
 *
 * The C constructors return NULL without a reason. The most common cause is a
 * QoS that breaks a DDS consistency rule, which `QoS.consistencyProblems`
 * can name, so the message says which rule; otherwise it points at the
 * native log, where the library writes the reason.
 */
function creationError(
  kind: "writer" | "reader",
  topicName: string,
  qos: QoS | null
): HddsError {
  let message = `Failed to create ${kind} for topic "${topicName}"`;
  const problems = qos ? qos.consistencyProblems() : [];
  if (problems.length > 0) {
    message += `: inconsistent QoS: ${problems.join("; ")}`;
  } else {
    message += " (call initLogging(LogLevel.WARN) to see the reason reported by the native library)";
  }
  return new HddsError(message);
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
    const domainId = options?.domainId;
    const transport = options?.transport ?? TransportMode.UDP_MULTICAST;

    let handle;
    if (domainId !== undefined) {
      const cfg = native.hdds_config_create(name);
      if (!cfg) {
        throw new HddsError(`Failed to create config for "${name}"`);
      }
      native.hdds_config_set_domain_id(cfg, domainId);
      native.hdds_config_set_transport_mode(cfg, transport);
      handle = native.hdds_config_build(cfg);
    } else {
      handle = native.hdds_participant_create_with_transport(name, transport);
    }
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
   * @param typeName - DDS type name announced via SEDP (default: the name the
   *   topic's other endpoints already announce, else "RawBytes")
   * @param extensibility - The extensibility of the IDL type the bodies are
   *   encoded from, either way the encapsulation identifier of every
   *   sample names it (DDS-XTypes 1.3 Table 60: D_CDR2_LE for an
   *   APPENDABLE type, the hdds_gen default, PL_CDR2_LE for a MUTABLE one):
   *   the literal `extensibility<Name>` a generated module exports
   *   (hdds_gen 2.0+), which always wins, or the generated module itself
   *   (`import * as Types from "./MyTypes"`), read via `typeName` the same
   *   way `createReader`'s `codec` argument is -- the natural call is
   *   `createWriter(topic, qos, "SensorReading", Types)`. Neither given,
   *   or a module with no matching `typeName`: every body is labelled
   *   FINAL (CDR2_LE), as before.
   * @returns A new DataWriter
   * @throws HddsError if creation fails, or on an unknown extensibility
   *
   * @example
   * ```typescript
   * import * as Types from "./types";
   * const writer = participant.createWriter("sensor_data",
   *   QoS.reliable().transientLocal(), "SensorReading", Types
   * );
   * ```
   */
  createWriter<T = unknown>(
    topicName: string,
    qos?: QoS | null,
    typeName?: string | null,
    extensibility?: Extensibility | WriterCodec | null
  ): DataWriter<T> {
    this.ensureHandle();
    const native = getNativeLib();

    // The extensibility of the IDL type the bodies are encoded from: the
    // encapsulation identifier of every sample names it (DDS-XTypes 1.3
    // Table 60, D_CDR2_LE appendable, PL_CDR2_LE mutable). Not resolved:
    // every body is labelled FINAL (CDR2_LE), as before.
    const resolved = resolveWriterExtensibility(extensibility, typeName);
    if (resolved != null) {
      // A string from untyped code, or a module's exported constant, may
      // be anything: refuse what the C ABI would refuse, with the reason.
      if (!Object.prototype.hasOwnProperty.call(EXTENSIBILITY_CODES, resolved)) {
        throw new HddsError(
          `createWriter("${topicName}"): extensibility "${String(resolved)}" ` +
            "is none of 'final', 'appendable', 'mutable'",
          HddsErrorCode.INVALID_ARGUMENT
        );
      }
      if (!native.hdds_writer_create_with_extensibility) {
        throw new HddsError("this libhdds_c cannot label a writer's extensibility");
      }
      const keyed = typeof extensibility === "object" && extensibility !== null && typeName != null &&
        extensibility["hasKey" + typeName] === true &&
        typeof extensibility["keySupported" + typeName] === "boolean" &&
        ["encodeKey", "computeKey"].every(prefix => typeof extensibility[prefix + typeName] === "function");
      const create = keyed ? native.hdds_writer_create_keyed : native.hdds_writer_create_with_extensibility;
      if (!create) throw new HddsError("missing keyed writer ABI");
      const handle = create(
        this._handle,
        topicName,
        typeName ?? null,
        qos ? qos.nativeHandle : null,
        EXTENSIBILITY_CODES[resolved as Extensibility]
      );
      if (!handle) {
        throw creationError("writer", topicName, qos ?? null);
      }
      const writer = DataWriter._fromHandle<T>(topicName, handle, qos ?? null,
        typeof extensibility === "object" ? extensibility ?? undefined : undefined, typeName, keyed);
      this._writers.push(writer as DataWriter);
      return writer;
    }

    // One FFI call either way: the type name is resolved here, at endpoint
    // creation (cold path), never per message. Omitting it keeps the C
    // library default: the name the topic's other endpoints already announce,
    // else "RawBytes", which is what the C, C++, Python and Rust
    // cross-language drivers announce, so a TypeScript endpoint matches them
    // on the wire.
    let handle: Pointer;
    if (typeName) {
      handle = native.hdds_writer_create_with_type(
        this._handle,
        topicName,
        typeName,
        qos ? qos.nativeHandle : null
      );
    } else if (qos) {
      handle = native.hdds_writer_create_with_qos(
        this._handle,
        topicName,
        qos.nativeHandle
      );
    } else {
      handle = native.hdds_writer_create(this._handle, topicName);
    }

    if (!handle) {
      throw creationError("writer", topicName, qos ?? null);
    }

    const writer = DataWriter._fromHandle<T>(topicName, handle, qos ?? null,
        typeof extensibility === "object" ? extensibility ?? undefined : undefined, typeName);
    this._writers.push(writer as DataWriter);
    return writer;
  }

  /**
   * Create a DataReader for the given topic.
   *
   * @param topicName - Name of the DDS topic
   * @param qos - QoS configuration (null for default)
   * @param typeName - DDS type name announced via SEDP (default: the name the
   *   topic's other endpoints already announce, else "RawBytes")
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
   *
   * `codec`: the generated module the samples are decoded with. One that
   * decodes XCDR1 (`HDDS_DECODES_XCDR1`, hdds_gen 2.0) makes the reader
   * request XCDR as well as XCDR2 when `qos` sets no DATA_REPRESENTATION
   * (DDS-XTypes 1.3 7.6.3.1.1), so a default writer, which offers XCDR,
   * reaches it; take with `takeTyped(decode<Name>ByEncapsulation)`.
   * Without it, or with an older module, the reader requests XCDR2 only.
   */
  createReader<T = unknown>(
    topicName: string,
    qos?: QoS | null,
    typeName?: string | null,
    codec?: ReaderCodec | null
  ): DataReader<T> {
    this.ensureHandle();
    const native = getNativeLib();

    // A reader requests what its decoders read (DDS-XTypes 1.3 7.6.3.1.1):
    // XCDR as well as XCDR2 only for a generated module that says it decodes
    // XCDR1 (hdds_gen 2.0), and only when the caller set no list.
    // The QoS built here is the reader's (`DataReader.qos`): not disposed.
    const noExplicitDataRepresentation =
      qos == null || qos.getDataRepresentation().length === 0;
    if (
      codec?.HDDS_DECODES_XCDR1 === true &&
      noExplicitDataRepresentation &&
      !native.hdds_qos_set_data_representation
    ) {
      // Old libhdds_c (predates hdds_qos_set_data_representation,
      // added together with hdds_reader_take_ex): no API to request
      // XCDR2 only here, and no way for takeWithEncapsulation to learn
      // a taken sample's true representation either -- its fallback
      // there can only ever assume CDR2_LE. The default (empty
      // DATA_REPRESENTATION) on such a library would announce
      // [XCDR, XCDR2] and risk matching a writer that offers XCDR1 (the
      // default for any writer of a type that does not refuse it), with no way to notice the mismatch. Refuse
      // rather than guess; a caller that sets an explicit
      // DATA_REPRESENTATION QoS has taken that decision itself and is
      // never refused here.
      throw new HddsError(
        `createReader("${topicName}"): this reader's codec decodes XCDR1 ` +
          "(hdds_gen 2.0+), but the loaded native library predates " +
          "hdds_qos_set_data_representation/hdds_reader_take_ex and " +
          "cannot request XCDR2 only, nor learn a taken sample's true " +
          "representation. Upgrade the native library, use a module " +
          "generated before hdds_gen 2.0 (XCDR2-only), or set an " +
          "explicit DATA_REPRESENTATION QoS yourself.",
        HddsErrorCode.INVALID_STATE
      );
    }
    if (
      codec?.HDDS_DECODES_XCDR1 === true &&
      native.hdds_qos_set_data_representation &&
      noExplicitDataRepresentation
    ) {
      const requesting = qos ? qos.clone() : QoS.createDefault();
      requesting.dataRepresentation(
        QoS.XCDR_DATA_REPRESENTATION,
        QoS.XCDR2_DATA_REPRESENTATION
      );
      qos = requesting;
    }

    // Same contract as createWriter: resolved once, here.
    let handle: Pointer;
    if (typeName) {
      handle = native.hdds_reader_create_with_type(
        this._handle,
        topicName,
        typeName,
        qos ? qos.nativeHandle : null
      );
    } else if (qos) {
      handle = native.hdds_reader_create_with_qos(
        this._handle,
        topicName,
        qos.nativeHandle
      );
    } else {
      handle = native.hdds_reader_create(this._handle, topicName);
    }

    if (!handle) {
      throw creationError("reader", topicName, qos ?? null);
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
