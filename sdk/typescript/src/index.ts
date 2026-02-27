// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * @hdds/client - HDDS TypeScript SDK
 *
 * Native FFI bindings to the HDDS DDS implementation via koffi.
 * Provides pub/sub access to DDS topics from Node.js.
 *
 * @packageDocumentation
 */

// Core classes
export { Participant } from "./participant.js";
export type { ParticipantOptions } from "./participant.js";
export { DataWriter } from "./writer.js";
export { DataReader } from "./reader.js";
export { QoS } from "./qos.js";
export { WaitSet, GuardCondition } from "./waitset.js";

// Types and enums
export {
  HddsError,
  HddsErrorCode,
  TransportMode,
  LogLevel,
  LivelinessKind,
  checkError,
} from "./types.js";

export type {
  Pointer,
  HddsErrorCodeValue,
  TransportModeValue,
  LogLevelValue,
  LivelinessKindValue,
  MetricsSnapshot,
} from "./types.js";

// Native library access (advanced use)
export { loadNativeLibrary, getNativeLib } from "./native.js";
export type { NativeLib } from "./native.js";

// ---------------------------------------------------------------------------
// Convenience functions
// ---------------------------------------------------------------------------

import { getNativeLib } from "./native.js";
import { checkError } from "./types.js";
import type { LogLevelValue } from "./types.js";

/**
 * Get the HDDS native library version string.
 *
 * @returns Version string (e.g., "1.0.5")
 */
export function version(): string {
  const native = getNativeLib();
  const v = native.hdds_version();
  return v ?? "unknown";
}

/**
 * Initialize HDDS logging with the specified level.
 *
 * @param level - Minimum log level (use LogLevel constants)
 */
export function initLogging(level: LogLevelValue): void {
  const native = getNativeLib();
  checkError(native.hdds_logging_init(level), "init logging");
}

/**
 * Initialize HDDS logging from the RUST_LOG environment variable.
 * Falls back to the provided default level if RUST_LOG is not set.
 *
 * @param defaultLevel - Default log level if RUST_LOG is not set
 */
export function initLoggingEnv(defaultLevel: LogLevelValue): void {
  const native = getNativeLib();
  checkError(native.hdds_logging_init_env(defaultLevel), "init logging env");
}

/**
 * Initialize HDDS logging with a custom filter string.
 *
 * @param filter - Log filter string (e.g., "hdds=debug,info")
 */
export function initLoggingWithFilter(filter: string): void {
  const native = getNativeLib();
  checkError(
    native.hdds_logging_init_with_filter(filter),
    "init logging with filter"
  );
}
