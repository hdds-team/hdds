// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * HDDS TypeScript SDK - Common Types
 *
 * Error codes, enums, and shared type definitions matching hdds.h.
 */

// ============================================================================
// Opaque Pointer Type
// ============================================================================

/**
 * Opaque native pointer returned by koffi.
 * Represents a handle to a C struct (HddsParticipant, HddsDataWriter, etc.).
 */
export type Pointer = unknown;

// ============================================================================
// Error Codes
// ============================================================================

/**
 * Error codes from the HDDS C library (matches HddsError enum in hdds.h).
 *
 * Error code categories:
 *  - 0-9:   Success and generic errors
 *  - 10-19: Configuration errors
 *  - 20-29: I/O and transport errors
 *  - 30-39: Type and serialization errors
 *  - 40-49: QoS and resource errors
 *  - 50-59: Security errors
 */
export const HddsErrorCode = {
  /** Operation completed successfully */
  OK: 0,
  /** Invalid argument provided (null pointer, invalid value) */
  INVALID_ARGUMENT: 1,
  /** Requested resource not found */
  NOT_FOUND: 2,
  /** Generic operation failure */
  OPERATION_FAILED: 3,
  /** Memory allocation failed */
  OUT_OF_MEMORY: 4,
  /** Invalid configuration settings */
  CONFIG_ERROR: 10,
  /** Invalid domain ID (must be 0-232) */
  INVALID_DOMAIN_ID: 11,
  /** Invalid participant ID (must be 0-119) */
  INVALID_PARTICIPANT_ID: 12,
  /** No available participant ID (all 120 ports occupied) */
  NO_AVAILABLE_PARTICIPANT_ID: 13,
  /** Invalid entity state for requested operation */
  INVALID_STATE: 14,
  /** Generic I/O error */
  IO_ERROR: 20,
  /** UDP transport send/receive failed */
  TRANSPORT_ERROR: 21,
  /** Topic registration failed */
  REGISTRATION_FAILED: 22,
  /** Operation would block but non-blocking mode requested */
  WOULD_BLOCK: 23,
  /** Type mismatch between writer and reader */
  TYPE_MISMATCH: 30,
  /** CDR serialization failed */
  SERIALIZATION_ERROR: 31,
  /** Buffer too small for encoding */
  BUFFER_TOO_SMALL: 32,
  /** CDR endianness mismatch */
  ENDIAN_MISMATCH: 33,
  /** QoS policies are incompatible between endpoints */
  QOS_INCOMPATIBLE: 40,
  /** Requested feature or operation is not supported */
  UNSUPPORTED: 41,
  /** Permission denied by access control (DDS Security) */
  PERMISSION_DENIED: 50,
  /** Authentication failed */
  AUTHENTICATION_FAILED: 51,
} as const;

export type HddsErrorCodeValue = (typeof HddsErrorCode)[keyof typeof HddsErrorCode];

// ============================================================================
// HddsError Class
// ============================================================================

const ERROR_CODE_NAMES: Record<number, string> = {
  [HddsErrorCode.OK]: "OK",
  [HddsErrorCode.INVALID_ARGUMENT]: "INVALID_ARGUMENT",
  [HddsErrorCode.NOT_FOUND]: "NOT_FOUND",
  [HddsErrorCode.OPERATION_FAILED]: "OPERATION_FAILED",
  [HddsErrorCode.OUT_OF_MEMORY]: "OUT_OF_MEMORY",
  [HddsErrorCode.CONFIG_ERROR]: "CONFIG_ERROR",
  [HddsErrorCode.INVALID_DOMAIN_ID]: "INVALID_DOMAIN_ID",
  [HddsErrorCode.INVALID_PARTICIPANT_ID]: "INVALID_PARTICIPANT_ID",
  [HddsErrorCode.NO_AVAILABLE_PARTICIPANT_ID]: "NO_AVAILABLE_PARTICIPANT_ID",
  [HddsErrorCode.INVALID_STATE]: "INVALID_STATE",
  [HddsErrorCode.IO_ERROR]: "IO_ERROR",
  [HddsErrorCode.TRANSPORT_ERROR]: "TRANSPORT_ERROR",
  [HddsErrorCode.REGISTRATION_FAILED]: "REGISTRATION_FAILED",
  [HddsErrorCode.WOULD_BLOCK]: "WOULD_BLOCK",
  [HddsErrorCode.TYPE_MISMATCH]: "TYPE_MISMATCH",
  [HddsErrorCode.SERIALIZATION_ERROR]: "SERIALIZATION_ERROR",
  [HddsErrorCode.BUFFER_TOO_SMALL]: "BUFFER_TOO_SMALL",
  [HddsErrorCode.ENDIAN_MISMATCH]: "ENDIAN_MISMATCH",
  [HddsErrorCode.QOS_INCOMPATIBLE]: "QOS_INCOMPATIBLE",
  [HddsErrorCode.UNSUPPORTED]: "UNSUPPORTED",
  [HddsErrorCode.PERMISSION_DENIED]: "PERMISSION_DENIED",
  [HddsErrorCode.AUTHENTICATION_FAILED]: "AUTHENTICATION_FAILED",
};

/**
 * Error thrown by HDDS operations.
 */
export class HddsError extends Error {
  /** Numeric error code from the C library */
  public readonly code: number;

  constructor(message: string, code?: number) {
    const codeName = code !== undefined ? ERROR_CODE_NAMES[code] : undefined;
    const prefix = codeName ? `[${codeName}] ` : "";
    super(`${prefix}${message}`);
    this.name = "HddsError";
    this.code = code ?? HddsErrorCode.OPERATION_FAILED;
  }
}

/**
 * Check an error code returned by a native function.
 * Throws HddsError if the code is not OK.
 */
export function checkError(code: number, context?: string): void {
  if (code !== HddsErrorCode.OK) {
    const codeName = ERROR_CODE_NAMES[code] ?? `UNKNOWN(${code})`;
    const msg = context
      ? `${context}: ${codeName}`
      : `Native call failed: ${codeName}`;
    throw new HddsError(msg, code);
  }
}

// ============================================================================
// Transport Mode
// ============================================================================

/**
 * Transport mode for participant creation.
 */
export const TransportMode = {
  /** Intra-process only (no network, fastest for same-process communication) */
  INTRA_PROCESS: 0,
  /** UDP multicast for network discovery and communication (default for DDS interop) */
  UDP_MULTICAST: 1,
} as const;

export type TransportModeValue = (typeof TransportMode)[keyof typeof TransportMode];

// ============================================================================
// Log Level
// ============================================================================

/**
 * Log level for HDDS logging.
 */
export const LogLevel = {
  OFF: 0,
  ERROR: 1,
  WARN: 2,
  INFO: 3,
  DEBUG: 4,
  TRACE: 5,
} as const;

export type LogLevelValue = (typeof LogLevel)[keyof typeof LogLevel];

// ============================================================================
// Liveliness Kind
// ============================================================================

/**
 * Liveliness kind for QoS configuration.
 */
export const LivelinessKind = {
  /** DDS infrastructure automatically asserts liveliness */
  AUTOMATIC: 0,
  /** Application must assert per participant */
  MANUAL_BY_PARTICIPANT: 1,
  /** Application must assert per writer/topic */
  MANUAL_BY_TOPIC: 2,
} as const;

export type LivelinessKindValue = (typeof LivelinessKind)[keyof typeof LivelinessKind];

// ============================================================================
// Metrics Snapshot
// ============================================================================

/**
 * Telemetry metrics snapshot.
 */
export interface MetricsSnapshot {
  /** Timestamp in nanoseconds since epoch */
  timestampNs: bigint;
  /** Total messages sent */
  messagesSent: bigint;
  /** Total messages received */
  messagesReceived: bigint;
  /** Total messages dropped */
  messagesDropped: bigint;
  /** Total bytes sent */
  bytesSent: bigint;
  /** Latency p50 in nanoseconds */
  latencyP50Ns: bigint;
  /** Latency p99 in nanoseconds */
  latencyP99Ns: bigint;
  /** Latency p999 in nanoseconds */
  latencyP999Ns: bigint;
  /** Merge full count (backpressure events) */
  mergeFullCount: bigint;
  /** Would-block count (send buffer full) */
  wouldBlockCount: bigint;
}
