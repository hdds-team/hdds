// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * HDDS TypeScript SDK - WaitSet and Conditions
 *
 * Synchronization primitives for blocking until data is available.
 */

import { getNativeLib } from "./native.js";
import {
  type Pointer,
  HddsError,
  HddsErrorCode,
  checkError,
} from "./types.js";
import type { DataReader } from "./reader.js";

/**
 * Manually triggered condition for waking a WaitSet.
 *
 * @example
 * ```typescript
 * const guard = new GuardCondition();
 * waitset.attachGuard(guard);
 *
 * // From another context:
 * guard.trigger();
 * ```
 */
export class GuardCondition {
  /** @internal Native guard condition handle */
  private _handle: Pointer;

  constructor() {
    const native = getNativeLib();
    this._handle = native.hdds_guard_condition_create();
    if (!this._handle) {
      throw new HddsError("Failed to create guard condition");
    }
  }

  /**
   * Trigger the condition, waking any WaitSet that has it attached.
   */
  trigger(): void {
    this.ensureHandle();
    const native = getNativeLib();
    native.hdds_guard_condition_set_trigger(this._handle, true);
  }

  /**
   * Reset the condition (un-trigger).
   */
  reset(): void {
    this.ensureHandle();
    const native = getNativeLib();
    native.hdds_guard_condition_set_trigger(this._handle, false);
  }

  /**
   * Release the guard condition and free native resources.
   */
  dispose(): void {
    if (this._handle) {
      const native = getNativeLib();
      native.hdds_guard_condition_release(this._handle);
      this._handle = null;
    }
  }

  /** @internal */
  get nativeHandle(): Pointer {
    return this._handle;
  }

  toString(): string {
    return "GuardCondition()";
  }

  private ensureHandle(): void {
    if (!this._handle) {
      throw new HddsError("GuardCondition has been disposed");
    }
  }
}

/**
 * Synchronization primitive for blocking on conditions.
 *
 * Attach reader status conditions or guard conditions, then call `wait()`
 * to block until any attached condition is triggered.
 *
 * @example
 * ```typescript
 * const waitset = new WaitSet();
 * waitset.attachReader(reader);
 *
 * while (true) {
 *   const triggered = waitset.wait(5.0);
 *   if (triggered) {
 *     const data = reader.take();
 *     if (data !== null) {
 *       console.log("Received:", data.toString("utf-8"));
 *     }
 *   }
 * }
 *
 * waitset.dispose();
 * ```
 */
export class WaitSet {
  /** @internal Native waitset handle */
  private _handle: Pointer;
  private readonly _attachedReaders: DataReader[] = [];
  private readonly _attachedGuards: GuardCondition[] = [];

  constructor() {
    const native = getNativeLib();
    this._handle = native.hdds_waitset_create();
    if (!this._handle) {
      throw new HddsError("Failed to create WaitSet");
    }
  }

  /**
   * Attach a reader's status condition to the WaitSet.
   * The WaitSet will wake when data is available on the reader.
   *
   * @param reader - DataReader to monitor
   */
  attachReader(reader: DataReader): void {
    this.ensureHandle();
    if (this._attachedReaders.includes(reader)) {
      return; // Already attached
    }

    const cond = reader.getStatusCondition();
    const native = getNativeLib();
    checkError(
      native.hdds_waitset_attach_status_condition(this._handle, cond),
      "attach reader to waitset"
    );
    this._attachedReaders.push(reader);
  }

  /**
   * Detach a reader from the WaitSet.
   *
   * @param reader - DataReader to stop monitoring
   */
  detachReader(reader: DataReader): void {
    this.ensureHandle();
    const idx = this._attachedReaders.indexOf(reader);
    if (idx < 0) {
      return; // Not attached
    }

    const cond = reader.getStatusCondition();
    const native = getNativeLib();
    checkError(
      native.hdds_waitset_detach_condition(this._handle, cond),
      "detach reader from waitset"
    );
    this._attachedReaders.splice(idx, 1);
  }

  /**
   * Attach a guard condition to the WaitSet.
   *
   * @param guard - GuardCondition to monitor
   */
  attachGuard(guard: GuardCondition): void {
    this.ensureHandle();
    if (this._attachedGuards.includes(guard)) {
      return; // Already attached
    }

    const native = getNativeLib();
    checkError(
      native.hdds_waitset_attach_guard_condition(
        this._handle,
        guard.nativeHandle
      ),
      "attach guard to waitset"
    );
    this._attachedGuards.push(guard);
  }

  /**
   * Detach a guard condition from the WaitSet.
   *
   * @param guard - GuardCondition to stop monitoring
   */
  detachGuard(guard: GuardCondition): void {
    this.ensureHandle();
    const idx = this._attachedGuards.indexOf(guard);
    if (idx < 0) {
      return; // Not attached
    }

    const native = getNativeLib();
    checkError(
      native.hdds_waitset_detach_condition(this._handle, guard.nativeHandle),
      "detach guard from waitset"
    );
    this._attachedGuards.splice(idx, 1);
  }

  /**
   * Wait for any attached condition to trigger.
   *
   * @param timeoutSecs - Maximum wait time in seconds.
   *   - `undefined` / no argument: block indefinitely
   *   - `0`: non-blocking poll
   *   - positive number: block up to that many seconds
   * @returns `true` if conditions triggered, `false` on timeout
   * @throws HddsError on internal errors
   */
  wait(timeoutSecs?: number): boolean {
    this.ensureHandle();
    const native = getNativeLib();

    let timeoutNs: bigint;
    if (timeoutSecs === undefined) {
      timeoutNs = -1n;
    } else {
      timeoutNs = BigInt(Math.round(timeoutSecs * 1_000_000_000));
    }

    // Allocate output buffer for triggered conditions
    const maxConditions = 64;
    const outConditions = new Array<unknown>(maxConditions).fill(null);
    const outLen = [0];

    const err = native.hdds_waitset_wait(
      this._handle,
      timeoutNs,
      outConditions,
      maxConditions,
      outLen
    );

    if (err === HddsErrorCode.OK) {
      return true;
    }
    if (err === HddsErrorCode.NOT_FOUND) {
      return false; // Timeout
    }

    throw new HddsError(`WaitSet.wait failed`, err);
  }

  /**
   * Destroy the WaitSet and release native resources.
   */
  dispose(): void {
    if (this._handle) {
      const native = getNativeLib();
      native.hdds_waitset_destroy(this._handle);
      this._handle = null;
      this._attachedReaders.length = 0;
      this._attachedGuards.length = 0;
    }
  }

  toString(): string {
    return `WaitSet(readers=${this._attachedReaders.length}, guards=${this._attachedGuards.length})`;
  }

  private ensureHandle(): void {
    if (!this._handle) {
      throw new HddsError("WaitSet has been disposed");
    }
  }
}
