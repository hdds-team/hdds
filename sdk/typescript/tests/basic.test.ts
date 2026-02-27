// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * Basic unit tests for the HDDS TypeScript SDK.
 *
 * These tests verify the TypeScript-side logic (types, error handling, etc.)
 * without requiring the native hdds-c library. For integration tests that
 * exercise the full FFI path, build hdds-c first and set HDDS_LIB_PATH.
 */

import { describe, it, expect } from "vitest";
import {
  HddsError,
  HddsErrorCode,
  TransportMode,
  LogLevel,
  LivelinessKind,
  checkError,
} from "../src/types.js";

// ============================================================================
// Error Types
// ============================================================================

describe("HddsError", () => {
  it("should create error with message and code", () => {
    const err = new HddsError("test failure", HddsErrorCode.INVALID_ARGUMENT);
    expect(err.message).toContain("INVALID_ARGUMENT");
    expect(err.message).toContain("test failure");
    expect(err.code).toBe(HddsErrorCode.INVALID_ARGUMENT);
    expect(err.name).toBe("HddsError");
    expect(err instanceof Error).toBe(true);
  });

  it("should create error with message only", () => {
    const err = new HddsError("simple error");
    expect(err.message).toBe("simple error");
    expect(err.code).toBe(HddsErrorCode.OPERATION_FAILED);
  });

  it("should format unknown error codes", () => {
    const err = new HddsError("unknown", 999);
    expect(err.code).toBe(999);
    expect(err.message).toBe("unknown");
  });
});

describe("checkError", () => {
  it("should not throw on OK", () => {
    expect(() => checkError(HddsErrorCode.OK)).not.toThrow();
  });

  it("should throw on non-OK codes", () => {
    expect(() => checkError(HddsErrorCode.INVALID_ARGUMENT)).toThrow(
      HddsError
    );
    expect(() => checkError(HddsErrorCode.NOT_FOUND)).toThrow(HddsError);
    expect(() => checkError(HddsErrorCode.OPERATION_FAILED)).toThrow(
      HddsError
    );
  });

  it("should include context in error message", () => {
    try {
      checkError(HddsErrorCode.TRANSPORT_ERROR, "write operation");
      expect.unreachable("should have thrown");
    } catch (e) {
      expect(e).toBeInstanceOf(HddsError);
      const err = e as HddsError;
      expect(err.message).toContain("write operation");
      expect(err.message).toContain("TRANSPORT_ERROR");
      expect(err.code).toBe(HddsErrorCode.TRANSPORT_ERROR);
    }
  });

  it("should handle unknown error codes", () => {
    try {
      checkError(999, "unknown op");
      expect.unreachable("should have thrown");
    } catch (e) {
      expect(e).toBeInstanceOf(HddsError);
      const err = e as HddsError;
      expect(err.message).toContain("UNKNOWN(999)");
    }
  });
});

// ============================================================================
// Enum Constants
// ============================================================================

describe("HddsErrorCode", () => {
  it("should have correct values matching hdds.h", () => {
    expect(HddsErrorCode.OK).toBe(0);
    expect(HddsErrorCode.INVALID_ARGUMENT).toBe(1);
    expect(HddsErrorCode.NOT_FOUND).toBe(2);
    expect(HddsErrorCode.OPERATION_FAILED).toBe(3);
    expect(HddsErrorCode.OUT_OF_MEMORY).toBe(4);
    expect(HddsErrorCode.CONFIG_ERROR).toBe(10);
    expect(HddsErrorCode.IO_ERROR).toBe(20);
    expect(HddsErrorCode.TYPE_MISMATCH).toBe(30);
    expect(HddsErrorCode.QOS_INCOMPATIBLE).toBe(40);
    expect(HddsErrorCode.PERMISSION_DENIED).toBe(50);
    expect(HddsErrorCode.AUTHENTICATION_FAILED).toBe(51);
  });
});

describe("TransportMode", () => {
  it("should match C enum values", () => {
    expect(TransportMode.INTRA_PROCESS).toBe(0);
    expect(TransportMode.UDP_MULTICAST).toBe(1);
  });
});

describe("LogLevel", () => {
  it("should match C enum values", () => {
    expect(LogLevel.OFF).toBe(0);
    expect(LogLevel.ERROR).toBe(1);
    expect(LogLevel.WARN).toBe(2);
    expect(LogLevel.INFO).toBe(3);
    expect(LogLevel.DEBUG).toBe(4);
    expect(LogLevel.TRACE).toBe(5);
  });
});

describe("LivelinessKind", () => {
  it("should match C enum values", () => {
    expect(LivelinessKind.AUTOMATIC).toBe(0);
    expect(LivelinessKind.MANUAL_BY_PARTICIPANT).toBe(1);
    expect(LivelinessKind.MANUAL_BY_TOPIC).toBe(2);
  });
});

// ============================================================================
// Import Verification
// ============================================================================

describe("Module exports", () => {
  it("should export all core classes", async () => {
    const mod = await import("../src/index.js");

    expect(mod.Participant).toBeDefined();
    expect(mod.DataWriter).toBeDefined();
    expect(mod.DataReader).toBeDefined();
    expect(mod.QoS).toBeDefined();
    expect(mod.WaitSet).toBeDefined();
    expect(mod.GuardCondition).toBeDefined();
  });

  it("should export all enum constants", async () => {
    const mod = await import("../src/index.js");

    expect(mod.HddsErrorCode).toBeDefined();
    expect(mod.TransportMode).toBeDefined();
    expect(mod.LogLevel).toBeDefined();
    expect(mod.LivelinessKind).toBeDefined();
  });

  it("should export error class and check function", async () => {
    const mod = await import("../src/index.js");

    expect(mod.HddsError).toBeDefined();
    expect(mod.checkError).toBeDefined();
    expect(typeof mod.checkError).toBe("function");
  });

  it("should export convenience functions", async () => {
    const mod = await import("../src/index.js");

    expect(mod.version).toBeDefined();
    expect(typeof mod.version).toBe("function");
    expect(mod.initLogging).toBeDefined();
    expect(typeof mod.initLogging).toBe("function");
    expect(mod.initLoggingEnv).toBeDefined();
    expect(typeof mod.initLoggingEnv).toBe("function");
    expect(mod.initLoggingWithFilter).toBeDefined();
    expect(typeof mod.initLoggingWithFilter).toBe("function");
  });

  it("should export native library access", async () => {
    const mod = await import("../src/index.js");

    expect(mod.loadNativeLibrary).toBeDefined();
    expect(typeof mod.loadNativeLibrary).toBe("function");
    expect(mod.getNativeLib).toBeDefined();
    expect(typeof mod.getNativeLib).toBe("function");
  });
});
