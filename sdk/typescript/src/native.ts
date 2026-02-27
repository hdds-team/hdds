// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * HDDS TypeScript SDK - Native FFI Bindings
 *
 * Low-level bindings to the hdds-c shared library via koffi.
 * This module handles library loading and function signature definitions.
 */

import koffi from "koffi";
import * as path from "node:path";
import * as fs from "node:fs";
import * as os from "node:os";

// ============================================================================
// Library Loading
// ============================================================================

/**
 * Resolve the platform-specific shared library name.
 */
function getLibraryName(): string {
  switch (os.platform()) {
    case "linux":
      return "libhdds_c.so";
    case "darwin":
      return "libhdds_c.dylib";
    case "win32":
      return "hdds_c.dll";
    default:
      return "libhdds_c.so";
  }
}

/**
 * Search for the hdds-c shared library in standard locations.
 * Order of precedence:
 *   1. HDDS_LIB_PATH environment variable (explicit override)
 *   2. Development build paths (target/release, target/debug)
 *   3. System library paths (/usr/local/lib, /usr/lib)
 */
function findLibraryPath(): string {
  const libName = getLibraryName();
  const searchPaths: string[] = [];

  // 1. Environment variable override
  const envPath = process.env["HDDS_LIB_PATH"];
  if (envPath) {
    searchPaths.push(envPath);
  }

  // 2. Development paths (relative to this file -> sdk/typescript/src -> project root)
  const sdkRoot = path.resolve(__dirname, "..", "..", "..");
  searchPaths.push(
    path.join(sdkRoot, "target", "release"),
    path.join(sdkRoot, "target", "debug")
  );

  // 3. System paths
  searchPaths.push("/usr/local/lib", "/usr/lib");

  for (const dir of searchPaths) {
    const fullPath = path.join(dir, libName);
    if (fs.existsSync(fullPath)) {
      return fullPath;
    }
  }

  // Fallback: let the system loader try
  return libName;
}

// ============================================================================
// Koffi Type Definitions
// ============================================================================

// Opaque pointer types for type safety in signatures
const HddsParticipantPtr = koffi.pointer("HddsParticipant", koffi.opaque());
const HddsDataWriterPtr = koffi.pointer("HddsDataWriter", koffi.opaque());
const HddsDataReaderPtr = koffi.pointer("HddsDataReader", koffi.opaque());
const HddsQoSPtr = koffi.pointer("HddsQoS", koffi.opaque());
const HddsWaitSetPtr = koffi.pointer("HddsWaitSet", koffi.opaque());
const HddsGuardConditionPtr = koffi.pointer(
  "HddsGuardCondition",
  koffi.opaque()
);
const HddsStatusConditionPtr = koffi.pointer(
  "HddsStatusCondition",
  koffi.opaque()
);
const HddsPublisherPtr = koffi.pointer("HddsPublisher", koffi.opaque());
const HddsSubscriberPtr = koffi.pointer("HddsSubscriber", koffi.opaque());
const HddsMetricsPtr = koffi.pointer("HddsMetrics", koffi.opaque());
const HddsTelemetryExporterPtr = koffi.pointer(
  "HddsTelemetryExporter",
  koffi.opaque()
);

// Metrics snapshot struct matching C layout
const HddsMetricsSnapshotStruct = koffi.struct("HddsMetricsSnapshot", {
  TIMESTAMP_NS: "uint64",
  MESSAGES_SENT: "uint64",
  MESSAGES_RECEIVED: "uint64",
  MESSAGES_DROPPED: "uint64",
  BYTES_SENT: "uint64",
  LATENCY_P50_NS: "uint64",
  LATENCY_P99_NS: "uint64",
  LATENCY_P999_NS: "uint64",
  MERGE_FULL_COUNT: "uint64",
  WOULD_BLOCK_COUNT: "uint64",
});

// ============================================================================
// Native Library Interface
// ============================================================================

/**
 * All native function bindings from the hdds-c library.
 * Function signatures match the C header hdds.h exactly.
 */
export interface NativeLib {
  // -- Version ----------------------------------------------------------------
  hdds_version(): string | null;

  // -- Logging ----------------------------------------------------------------
  hdds_logging_init(level: number): number;
  hdds_logging_init_env(defaultLevel: number): number;
  hdds_logging_init_with_filter(filter: string): number;

  // -- Participant ------------------------------------------------------------
  hdds_participant_create(name: string): unknown;
  hdds_participant_create_with_transport(
    name: string,
    transport: number
  ): unknown;
  hdds_participant_destroy(participant: unknown): void;
  hdds_participant_name(participant: unknown): string | null;
  hdds_participant_domain_id(participant: unknown): number;
  hdds_participant_id(participant: unknown): number;
  hdds_participant_graph_guard_condition(participant: unknown): unknown;

  // -- DataWriter -------------------------------------------------------------
  hdds_writer_create(participant: unknown, topicName: string): unknown;
  hdds_writer_create_with_qos(
    participant: unknown,
    topicName: string,
    qos: unknown
  ): unknown;
  hdds_writer_write(writer: unknown, data: Buffer, len: number): number;
  hdds_writer_destroy(writer: unknown): void;
  hdds_writer_topic_name(
    writer: unknown,
    buf: Buffer,
    bufLen: number,
    outLen: number[]
  ): number;

  // -- DataReader -------------------------------------------------------------
  hdds_reader_create(participant: unknown, topicName: string): unknown;
  hdds_reader_create_with_qos(
    participant: unknown,
    topicName: string,
    qos: unknown
  ): unknown;
  hdds_reader_take(
    reader: unknown,
    dataOut: Buffer,
    maxLen: number,
    lenOut: number[]
  ): number;
  hdds_reader_destroy(reader: unknown): void;
  hdds_reader_get_status_condition(reader: unknown): unknown;
  hdds_reader_topic_name(
    reader: unknown,
    buf: Buffer,
    bufLen: number,
    outLen: number[]
  ): number;

  // -- StatusCondition --------------------------------------------------------
  hdds_status_condition_release(condition: unknown): void;

  // -- GuardCondition ---------------------------------------------------------
  hdds_guard_condition_create(): unknown;
  hdds_guard_condition_release(condition: unknown): void;
  hdds_guard_condition_set_trigger(condition: unknown, active: boolean): void;

  // -- WaitSet ----------------------------------------------------------------
  hdds_waitset_create(): unknown;
  hdds_waitset_destroy(waitset: unknown): void;
  hdds_waitset_attach_status_condition(
    waitset: unknown,
    condition: unknown
  ): number;
  hdds_waitset_attach_guard_condition(
    waitset: unknown,
    condition: unknown
  ): number;
  hdds_waitset_detach_condition(waitset: unknown, condition: unknown): number;
  hdds_waitset_wait(
    waitset: unknown,
    timeoutNs: bigint,
    outConditions: unknown[],
    maxConditions: number,
    outLen: number[]
  ): number;

  // -- QoS --------------------------------------------------------------------
  hdds_qos_default(): unknown;
  hdds_qos_best_effort(): unknown;
  hdds_qos_reliable(): unknown;
  hdds_qos_rti_defaults(): unknown;
  hdds_qos_destroy(qos: unknown): void;
  hdds_qos_clone(qos: unknown): unknown;

  // QoS Setters
  hdds_qos_set_history_depth(qos: unknown, depth: number): number;
  hdds_qos_set_history_keep_all(qos: unknown): number;
  hdds_qos_set_volatile(qos: unknown): number;
  hdds_qos_set_transient_local(qos: unknown): number;
  hdds_qos_set_persistent(qos: unknown): number;
  hdds_qos_set_reliable(qos: unknown): number;
  hdds_qos_set_best_effort(qos: unknown): number;
  hdds_qos_set_deadline_ns(qos: unknown, periodNs: bigint): number;
  hdds_qos_set_lifespan_ns(qos: unknown, durationNs: bigint): number;
  hdds_qos_set_ownership_shared(qos: unknown): number;
  hdds_qos_set_ownership_exclusive(qos: unknown, strength: number): number;
  hdds_qos_add_partition(qos: unknown, partition: string): number;
  hdds_qos_set_liveliness_automatic_ns(qos: unknown, leaseNs: bigint): number;
  hdds_qos_set_liveliness_manual_participant_ns(
    qos: unknown,
    leaseNs: bigint
  ): number;
  hdds_qos_set_liveliness_manual_topic_ns(
    qos: unknown,
    leaseNs: bigint
  ): number;
  hdds_qos_set_time_based_filter_ns(
    qos: unknown,
    minSeparationNs: bigint
  ): number;
  hdds_qos_set_latency_budget_ns(qos: unknown, budgetNs: bigint): number;
  hdds_qos_set_transport_priority(qos: unknown, priority: number): number;
  hdds_qos_set_resource_limits(
    qos: unknown,
    maxSamples: number,
    maxInstances: number,
    maxSamplesPerInstance: number
  ): number;

  // QoS Getters
  hdds_qos_is_reliable(qos: unknown): boolean;
  hdds_qos_is_transient_local(qos: unknown): boolean;
  hdds_qos_get_history_depth(qos: unknown): number;
  hdds_qos_get_deadline_ns(qos: unknown): bigint;
  hdds_qos_get_lifespan_ns(qos: unknown): bigint;
  hdds_qos_is_ownership_exclusive(qos: unknown): boolean;
  hdds_qos_get_ownership_strength(qos: unknown): number;
  hdds_qos_get_liveliness_kind(qos: unknown): number;
  hdds_qos_get_liveliness_lease_ns(qos: unknown): bigint;
  hdds_qos_get_time_based_filter_ns(qos: unknown): bigint;
  hdds_qos_get_latency_budget_ns(qos: unknown): bigint;
  hdds_qos_get_transport_priority(qos: unknown): number;
  hdds_qos_get_max_samples(qos: unknown): number;
  hdds_qos_get_max_instances(qos: unknown): number;
  hdds_qos_get_max_samples_per_instance(qos: unknown): number;

  // QoS XML Loading (optional)
  hdds_qos_from_xml?(xmlPath: string): unknown;
  hdds_qos_load_fastdds_xml?(xmlPath: string): unknown;

  // -- Publisher / Subscriber -------------------------------------------------
  hdds_publisher_create(participant: unknown): unknown;
  hdds_publisher_create_with_qos(participant: unknown, qos: unknown): unknown;
  hdds_publisher_destroy(publisher: unknown): void;
  hdds_publisher_create_writer(publisher: unknown, topicName: string): unknown;
  hdds_publisher_create_writer_with_qos(
    publisher: unknown,
    topicName: string,
    qos: unknown
  ): unknown;

  hdds_subscriber_create(participant: unknown): unknown;
  hdds_subscriber_create_with_qos(participant: unknown, qos: unknown): unknown;
  hdds_subscriber_destroy(subscriber: unknown): void;
  hdds_subscriber_create_reader(subscriber: unknown, topicName: string): unknown;
  hdds_subscriber_create_reader_with_qos(
    subscriber: unknown,
    topicName: string,
    qos: unknown
  ): unknown;

  // -- Telemetry --------------------------------------------------------------
  hdds_telemetry_init(): unknown;
  hdds_telemetry_get(): unknown;
  hdds_telemetry_release(metrics: unknown): void;
  hdds_telemetry_snapshot(
    metrics: unknown,
    out: Record<string, unknown>
  ): number;
  hdds_telemetry_record_latency(
    metrics: unknown,
    startNs: bigint,
    endNs: bigint
  ): void;
  hdds_telemetry_start_exporter(bindAddr: string, port: number): unknown;
  hdds_telemetry_stop_exporter(exporter: unknown): void;
}

// ============================================================================
// Library Singleton
// ============================================================================

let _lib: NativeLib | null = null;

/**
 * Load and bind the hdds-c shared library.
 * The library is loaded once and cached for the lifetime of the process.
 *
 * @throws Error if the library cannot be found or loaded
 */
export function loadNativeLibrary(): NativeLib {
  if (_lib !== null) {
    return _lib;
  }

  const libPath = findLibraryPath();

  let lib: koffi.IKoffiLib;
  try {
    lib = koffi.load(libPath);
  } catch (err) {
    throw new Error(
      `Could not load hdds-c library from "${libPath}". ` +
        `Make sure hdds-c is built: cargo build --release -p hdds-c\n` +
        `Set HDDS_LIB_PATH to the directory containing the library.\n` +
        `Error: ${err}`
    );
  }

  const native: NativeLib = {
    // -- Version ----------------------------------------------------------------
    hdds_version: lib.func("hdds_version", "str", []),

    // -- Logging ----------------------------------------------------------------
    hdds_logging_init: lib.func("hdds_logging_init", "int", ["int"]),
    hdds_logging_init_env: lib.func("hdds_logging_init_env", "int", ["int"]),
    hdds_logging_init_with_filter: lib.func(
      "hdds_logging_init_with_filter",
      "int",
      ["str"]
    ),

    // -- Participant ------------------------------------------------------------
    hdds_participant_create: lib.func(
      "hdds_participant_create",
      HddsParticipantPtr,
      ["str"]
    ),
    hdds_participant_create_with_transport: lib.func(
      "hdds_participant_create_with_transport",
      HddsParticipantPtr,
      ["str", "int"]
    ),
    hdds_participant_destroy: lib.func("hdds_participant_destroy", "void", [
      HddsParticipantPtr,
    ]),
    hdds_participant_name: lib.func("hdds_participant_name", "str", [
      HddsParticipantPtr,
    ]),
    hdds_participant_domain_id: lib.func(
      "hdds_participant_domain_id",
      "uint32",
      [HddsParticipantPtr]
    ),
    hdds_participant_id: lib.func("hdds_participant_id", "uint8", [
      HddsParticipantPtr,
    ]),
    hdds_participant_graph_guard_condition: lib.func(
      "hdds_participant_graph_guard_condition",
      HddsGuardConditionPtr,
      [HddsParticipantPtr]
    ),

    // -- DataWriter -------------------------------------------------------------
    hdds_writer_create: lib.func("hdds_writer_create", HddsDataWriterPtr, [
      HddsParticipantPtr,
      "str",
    ]),
    hdds_writer_create_with_qos: lib.func(
      "hdds_writer_create_with_qos",
      HddsDataWriterPtr,
      [HddsParticipantPtr, "str", HddsQoSPtr]
    ),
    hdds_writer_write: lib.func("hdds_writer_write", "int", [
      HddsDataWriterPtr,
      "void *",
      "uintptr_t",
    ]),
    hdds_writer_destroy: lib.func("hdds_writer_destroy", "void", [
      HddsDataWriterPtr,
    ]),
    hdds_writer_topic_name: lib.func("hdds_writer_topic_name", "int", [
      HddsDataWriterPtr,
      "void *",
      "uintptr_t",
      koffi.out(koffi.pointer("uintptr_t")),
    ]),

    // -- DataReader -------------------------------------------------------------
    hdds_reader_create: lib.func("hdds_reader_create", HddsDataReaderPtr, [
      HddsParticipantPtr,
      "str",
    ]),
    hdds_reader_create_with_qos: lib.func(
      "hdds_reader_create_with_qos",
      HddsDataReaderPtr,
      [HddsParticipantPtr, "str", HddsQoSPtr]
    ),
    hdds_reader_take: lib.func("hdds_reader_take", "int", [
      HddsDataReaderPtr,
      "void *",
      "uintptr_t",
      koffi.out(koffi.pointer("uintptr_t")),
    ]),
    hdds_reader_destroy: lib.func("hdds_reader_destroy", "void", [
      HddsDataReaderPtr,
    ]),
    hdds_reader_get_status_condition: lib.func(
      "hdds_reader_get_status_condition",
      HddsStatusConditionPtr,
      [HddsDataReaderPtr]
    ),
    hdds_reader_topic_name: lib.func("hdds_reader_topic_name", "int", [
      HddsDataReaderPtr,
      "void *",
      "uintptr_t",
      koffi.out(koffi.pointer("uintptr_t")),
    ]),

    // -- StatusCondition --------------------------------------------------------
    hdds_status_condition_release: lib.func(
      "hdds_status_condition_release",
      "void",
      [HddsStatusConditionPtr]
    ),

    // -- GuardCondition ---------------------------------------------------------
    hdds_guard_condition_create: lib.func(
      "hdds_guard_condition_create",
      HddsGuardConditionPtr,
      []
    ),
    hdds_guard_condition_release: lib.func(
      "hdds_guard_condition_release",
      "void",
      [HddsGuardConditionPtr]
    ),
    hdds_guard_condition_set_trigger: lib.func(
      "hdds_guard_condition_set_trigger",
      "void",
      [HddsGuardConditionPtr, "bool"]
    ),

    // -- WaitSet ----------------------------------------------------------------
    hdds_waitset_create: lib.func(
      "hdds_waitset_create",
      HddsWaitSetPtr,
      []
    ),
    hdds_waitset_destroy: lib.func("hdds_waitset_destroy", "void", [
      HddsWaitSetPtr,
    ]),
    hdds_waitset_attach_status_condition: lib.func(
      "hdds_waitset_attach_status_condition",
      "int",
      [HddsWaitSetPtr, HddsStatusConditionPtr]
    ),
    hdds_waitset_attach_guard_condition: lib.func(
      "hdds_waitset_attach_guard_condition",
      "int",
      [HddsWaitSetPtr, HddsGuardConditionPtr]
    ),
    hdds_waitset_detach_condition: lib.func(
      "hdds_waitset_detach_condition",
      "int",
      [HddsWaitSetPtr, "void *"]
    ),
    hdds_waitset_wait: lib.func("hdds_waitset_wait", "int", [
      HddsWaitSetPtr,
      "int64",
      koffi.out(koffi.pointer("void *")),
      "uintptr_t",
      koffi.out(koffi.pointer("uintptr_t")),
    ]),

    // -- QoS --------------------------------------------------------------------
    hdds_qos_default: lib.func("hdds_qos_default", HddsQoSPtr, []),
    hdds_qos_best_effort: lib.func("hdds_qos_best_effort", HddsQoSPtr, []),
    hdds_qos_reliable: lib.func("hdds_qos_reliable", HddsQoSPtr, []),
    hdds_qos_rti_defaults: lib.func("hdds_qos_rti_defaults", HddsQoSPtr, []),
    hdds_qos_destroy: lib.func("hdds_qos_destroy", "void", [HddsQoSPtr]),
    hdds_qos_clone: lib.func("hdds_qos_clone", HddsQoSPtr, [HddsQoSPtr]),

    // QoS Setters
    hdds_qos_set_history_depth: lib.func("hdds_qos_set_history_depth", "int", [
      HddsQoSPtr,
      "uint32",
    ]),
    hdds_qos_set_history_keep_all: lib.func(
      "hdds_qos_set_history_keep_all",
      "int",
      [HddsQoSPtr]
    ),
    hdds_qos_set_volatile: lib.func("hdds_qos_set_volatile", "int", [
      HddsQoSPtr,
    ]),
    hdds_qos_set_transient_local: lib.func(
      "hdds_qos_set_transient_local",
      "int",
      [HddsQoSPtr]
    ),
    hdds_qos_set_persistent: lib.func("hdds_qos_set_persistent", "int", [
      HddsQoSPtr,
    ]),
    hdds_qos_set_reliable: lib.func("hdds_qos_set_reliable", "int", [
      HddsQoSPtr,
    ]),
    hdds_qos_set_best_effort: lib.func("hdds_qos_set_best_effort", "int", [
      HddsQoSPtr,
    ]),
    hdds_qos_set_deadline_ns: lib.func("hdds_qos_set_deadline_ns", "int", [
      HddsQoSPtr,
      "uint64",
    ]),
    hdds_qos_set_lifespan_ns: lib.func("hdds_qos_set_lifespan_ns", "int", [
      HddsQoSPtr,
      "uint64",
    ]),
    hdds_qos_set_ownership_shared: lib.func(
      "hdds_qos_set_ownership_shared",
      "int",
      [HddsQoSPtr]
    ),
    hdds_qos_set_ownership_exclusive: lib.func(
      "hdds_qos_set_ownership_exclusive",
      "int",
      [HddsQoSPtr, "int32"]
    ),
    hdds_qos_add_partition: lib.func("hdds_qos_add_partition", "int", [
      HddsQoSPtr,
      "str",
    ]),
    hdds_qos_set_liveliness_automatic_ns: lib.func(
      "hdds_qos_set_liveliness_automatic_ns",
      "int",
      [HddsQoSPtr, "uint64"]
    ),
    hdds_qos_set_liveliness_manual_participant_ns: lib.func(
      "hdds_qos_set_liveliness_manual_participant_ns",
      "int",
      [HddsQoSPtr, "uint64"]
    ),
    hdds_qos_set_liveliness_manual_topic_ns: lib.func(
      "hdds_qos_set_liveliness_manual_topic_ns",
      "int",
      [HddsQoSPtr, "uint64"]
    ),
    hdds_qos_set_time_based_filter_ns: lib.func(
      "hdds_qos_set_time_based_filter_ns",
      "int",
      [HddsQoSPtr, "uint64"]
    ),
    hdds_qos_set_latency_budget_ns: lib.func(
      "hdds_qos_set_latency_budget_ns",
      "int",
      [HddsQoSPtr, "uint64"]
    ),
    hdds_qos_set_transport_priority: lib.func(
      "hdds_qos_set_transport_priority",
      "int",
      [HddsQoSPtr, "int32"]
    ),
    hdds_qos_set_resource_limits: lib.func(
      "hdds_qos_set_resource_limits",
      "int",
      [HddsQoSPtr, "uintptr_t", "uintptr_t", "uintptr_t"]
    ),

    // QoS Getters
    hdds_qos_is_reliable: lib.func("hdds_qos_is_reliable", "bool", [
      HddsQoSPtr,
    ]),
    hdds_qos_is_transient_local: lib.func(
      "hdds_qos_is_transient_local",
      "bool",
      [HddsQoSPtr]
    ),
    hdds_qos_get_history_depth: lib.func(
      "hdds_qos_get_history_depth",
      "uint32",
      [HddsQoSPtr]
    ),
    hdds_qos_get_deadline_ns: lib.func(
      "hdds_qos_get_deadline_ns",
      "uint64",
      [HddsQoSPtr]
    ),
    hdds_qos_get_lifespan_ns: lib.func(
      "hdds_qos_get_lifespan_ns",
      "uint64",
      [HddsQoSPtr]
    ),
    hdds_qos_is_ownership_exclusive: lib.func(
      "hdds_qos_is_ownership_exclusive",
      "bool",
      [HddsQoSPtr]
    ),
    hdds_qos_get_ownership_strength: lib.func(
      "hdds_qos_get_ownership_strength",
      "int32",
      [HddsQoSPtr]
    ),
    hdds_qos_get_liveliness_kind: lib.func(
      "hdds_qos_get_liveliness_kind",
      "int",
      [HddsQoSPtr]
    ),
    hdds_qos_get_liveliness_lease_ns: lib.func(
      "hdds_qos_get_liveliness_lease_ns",
      "uint64",
      [HddsQoSPtr]
    ),
    hdds_qos_get_time_based_filter_ns: lib.func(
      "hdds_qos_get_time_based_filter_ns",
      "uint64",
      [HddsQoSPtr]
    ),
    hdds_qos_get_latency_budget_ns: lib.func(
      "hdds_qos_get_latency_budget_ns",
      "uint64",
      [HddsQoSPtr]
    ),
    hdds_qos_get_transport_priority: lib.func(
      "hdds_qos_get_transport_priority",
      "int32",
      [HddsQoSPtr]
    ),
    hdds_qos_get_max_samples: lib.func(
      "hdds_qos_get_max_samples",
      "uintptr_t",
      [HddsQoSPtr]
    ),
    hdds_qos_get_max_instances: lib.func(
      "hdds_qos_get_max_instances",
      "uintptr_t",
      [HddsQoSPtr]
    ),
    hdds_qos_get_max_samples_per_instance: lib.func(
      "hdds_qos_get_max_samples_per_instance",
      "uintptr_t",
      [HddsQoSPtr]
    ),

    // -- Publisher / Subscriber -------------------------------------------------
    hdds_publisher_create: lib.func(
      "hdds_publisher_create",
      HddsPublisherPtr,
      [HddsParticipantPtr]
    ),
    hdds_publisher_create_with_qos: lib.func(
      "hdds_publisher_create_with_qos",
      HddsPublisherPtr,
      [HddsParticipantPtr, HddsQoSPtr]
    ),
    hdds_publisher_destroy: lib.func("hdds_publisher_destroy", "void", [
      HddsPublisherPtr,
    ]),
    hdds_publisher_create_writer: lib.func(
      "hdds_publisher_create_writer",
      HddsDataWriterPtr,
      [HddsPublisherPtr, "str"]
    ),
    hdds_publisher_create_writer_with_qos: lib.func(
      "hdds_publisher_create_writer_with_qos",
      HddsDataWriterPtr,
      [HddsPublisherPtr, "str", HddsQoSPtr]
    ),

    hdds_subscriber_create: lib.func(
      "hdds_subscriber_create",
      HddsSubscriberPtr,
      [HddsParticipantPtr]
    ),
    hdds_subscriber_create_with_qos: lib.func(
      "hdds_subscriber_create_with_qos",
      HddsSubscriberPtr,
      [HddsParticipantPtr, HddsQoSPtr]
    ),
    hdds_subscriber_destroy: lib.func("hdds_subscriber_destroy", "void", [
      HddsSubscriberPtr,
    ]),
    hdds_subscriber_create_reader: lib.func(
      "hdds_subscriber_create_reader",
      HddsDataReaderPtr,
      [HddsSubscriberPtr, "str"]
    ),
    hdds_subscriber_create_reader_with_qos: lib.func(
      "hdds_subscriber_create_reader_with_qos",
      HddsDataReaderPtr,
      [HddsSubscriberPtr, "str", HddsQoSPtr]
    ),

    // -- Telemetry --------------------------------------------------------------
    hdds_telemetry_init: lib.func("hdds_telemetry_init", HddsMetricsPtr, []),
    hdds_telemetry_get: lib.func("hdds_telemetry_get", HddsMetricsPtr, []),
    hdds_telemetry_release: lib.func("hdds_telemetry_release", "void", [
      HddsMetricsPtr,
    ]),
    hdds_telemetry_snapshot: lib.func("hdds_telemetry_snapshot", "int", [
      HddsMetricsPtr,
      koffi.out(koffi.pointer(HddsMetricsSnapshotStruct)),
    ]),
    hdds_telemetry_record_latency: lib.func(
      "hdds_telemetry_record_latency",
      "void",
      [HddsMetricsPtr, "uint64", "uint64"]
    ),
    hdds_telemetry_start_exporter: lib.func(
      "hdds_telemetry_start_exporter",
      HddsTelemetryExporterPtr,
      ["str", "uint16"]
    ),
    hdds_telemetry_stop_exporter: lib.func(
      "hdds_telemetry_stop_exporter",
      "void",
      [HddsTelemetryExporterPtr]
    ),
  };

  // Optional functions (may not be present depending on build features)
  try {
    native.hdds_qos_from_xml = lib.func("hdds_qos_from_xml", HddsQoSPtr, [
      "str",
    ]);
  } catch {
    // qos-loaders feature not enabled
  }

  try {
    native.hdds_qos_load_fastdds_xml = lib.func(
      "hdds_qos_load_fastdds_xml",
      HddsQoSPtr,
      ["str"]
    );
  } catch {
    // qos-loaders feature not enabled
  }

  _lib = native;
  return native;
}

/**
 * Get the loaded native library (loads if not yet loaded).
 */
export function getNativeLib(): NativeLib {
  return loadNativeLibrary();
}
