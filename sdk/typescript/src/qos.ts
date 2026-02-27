// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * HDDS TypeScript SDK - QoS (Quality of Service) Configuration
 *
 * Fluent builder API for configuring DDS QoS policies.
 * Mirrors the Python SDK QoS builder pattern.
 */

import { getNativeLib } from "./native.js";
import {
  type Pointer,
  type LivelinessKindValue,
  HddsError,
  checkError,
} from "./types.js";

/**
 * DDS Quality of Service configuration.
 *
 * Use static factory methods for common profiles:
 *   - `QoS.createDefault()` -- BestEffort, Volatile
 *   - `QoS.reliable()` -- Reliable delivery
 *   - `QoS.bestEffort()` -- Fire-and-forget
 *   - `QoS.rtiDefaults()` -- RTI Connext compatible
 *
 * All setter methods return `this` for fluent chaining:
 *
 * ```typescript
 * const qos = QoS.reliable()
 *   .transientLocal()
 *   .historyDepth(10)
 *   .deadlineMs(500);
 * ```
 */
export class QoS {
  /** @internal Native QoS handle */
  private _handle: Pointer;
  /** @internal Whether this instance owns (must destroy) the handle */
  private _owned: boolean;

  /** @internal */
  private constructor(handle: Pointer, owned: boolean) {
    this._handle = handle;
    this._owned = owned;
  }

  // ===========================================================================
  // Factory Methods
  // ===========================================================================

  /**
   * Create default QoS (BestEffort, Volatile, KeepLast(100)).
   */
  static createDefault(): QoS {
    const native = getNativeLib();
    const handle = native.hdds_qos_default();
    if (!handle) {
      throw new HddsError("Failed to create default QoS");
    }
    return new QoS(handle, true);
  }

  /**
   * Create Reliable QoS with NACK-driven retransmission.
   */
  static reliable(): QoS {
    const native = getNativeLib();
    const handle = native.hdds_qos_reliable();
    if (!handle) {
      throw new HddsError("Failed to create reliable QoS");
    }
    return new QoS(handle, true);
  }

  /**
   * Create BestEffort QoS (fire-and-forget).
   */
  static bestEffort(): QoS {
    const native = getNativeLib();
    const handle = native.hdds_qos_best_effort();
    if (!handle) {
      throw new HddsError("Failed to create best-effort QoS");
    }
    return new QoS(handle, true);
  }

  /**
   * Create RTI Connext-compatible QoS defaults.
   */
  static rtiDefaults(): QoS {
    const native = getNativeLib();
    const handle = native.hdds_qos_rti_defaults();
    if (!handle) {
      throw new HddsError("Failed to create RTI QoS defaults");
    }
    return new QoS(handle, true);
  }

  /**
   * Load QoS from an XML profile file (auto-detects vendor format).
   * Requires the `qos-loaders` Cargo feature.
   *
   * @param xmlPath - Path to the XML profile file
   */
  static fromXml(xmlPath: string): QoS {
    const native = getNativeLib();
    if (!native.hdds_qos_from_xml) {
      throw new HddsError(
        "QoS.fromXml() requires the qos-loaders feature to be enabled"
      );
    }
    const handle = native.hdds_qos_from_xml(xmlPath);
    if (!handle) {
      throw new HddsError(`Failed to load QoS from "${xmlPath}"`);
    }
    return new QoS(handle, true);
  }

  /**
   * Load QoS from a FastDDS XML profile file.
   * Requires the `qos-loaders` Cargo feature.
   *
   * @param xmlPath - Path to the FastDDS XML profile file
   */
  static fromFastDdsXml(xmlPath: string): QoS {
    const native = getNativeLib();
    if (!native.hdds_qos_load_fastdds_xml) {
      throw new HddsError(
        "QoS.fromFastDdsXml() requires the qos-loaders feature to be enabled"
      );
    }
    const handle = native.hdds_qos_load_fastdds_xml(xmlPath);
    if (!handle) {
      throw new HddsError(`Failed to load FastDDS QoS from "${xmlPath}"`);
    }
    return new QoS(handle, true);
  }

  // ===========================================================================
  // Lifecycle
  // ===========================================================================

  /**
   * Create a deep copy of this QoS.
   */
  clone(): QoS {
    this.ensureHandle();
    const native = getNativeLib();
    const handle = native.hdds_qos_clone(this._handle);
    if (!handle) {
      throw new HddsError("Failed to clone QoS");
    }
    return new QoS(handle, true);
  }

  /**
   * Destroy the QoS and release native resources.
   * After calling dispose(), this instance must not be used.
   */
  dispose(): void {
    if (this._owned && this._handle) {
      const native = getNativeLib();
      native.hdds_qos_destroy(this._handle);
      this._handle = null;
    }
  }

  /** @internal Get the native handle for FFI calls */
  get nativeHandle(): Pointer {
    return this._handle;
  }

  // ===========================================================================
  // Fluent Builder - Setters
  // ===========================================================================

  /**
   * Set durability to TRANSIENT_LOCAL (late-joiner support).
   */
  transientLocal(): this {
    this.ensureHandle();
    checkError(
      getNativeLib().hdds_qos_set_transient_local(this._handle),
      "set transient_local"
    );
    return this;
  }

  /**
   * Set durability to VOLATILE (no caching).
   */
  setVolatile(): this {
    this.ensureHandle();
    checkError(
      getNativeLib().hdds_qos_set_volatile(this._handle),
      "set volatile"
    );
    return this;
  }

  /**
   * Set durability to PERSISTENT (disk storage).
   */
  persistent(): this {
    this.ensureHandle();
    checkError(
      getNativeLib().hdds_qos_set_persistent(this._handle),
      "set persistent"
    );
    return this;
  }

  /**
   * Switch to RELIABLE delivery.
   */
  setReliable(): this {
    this.ensureHandle();
    checkError(
      getNativeLib().hdds_qos_set_reliable(this._handle),
      "set reliable"
    );
    return this;
  }

  /**
   * Switch to BEST_EFFORT delivery.
   */
  setBestEffort(): this {
    this.ensureHandle();
    checkError(
      getNativeLib().hdds_qos_set_best_effort(this._handle),
      "set best_effort"
    );
    return this;
  }

  /**
   * Set history depth (KEEP_LAST).
   */
  historyDepth(depth: number): this {
    this.ensureHandle();
    checkError(
      getNativeLib().hdds_qos_set_history_depth(this._handle, depth),
      "set history_depth"
    );
    return this;
  }

  /**
   * Set history to KEEP_ALL (unbounded).
   */
  historyKeepAll(): this {
    this.ensureHandle();
    checkError(
      getNativeLib().hdds_qos_set_history_keep_all(this._handle),
      "set history_keep_all"
    );
    return this;
  }

  /**
   * Set deadline period in milliseconds.
   */
  deadlineMs(milliseconds: number): this {
    this.ensureHandle();
    checkError(
      getNativeLib().hdds_qos_set_deadline_ns(
        this._handle,
        BigInt(milliseconds) * 1_000_000n
      ),
      "set deadline"
    );
    return this;
  }

  /**
   * Set deadline period in seconds.
   */
  deadlineSecs(seconds: number): this {
    this.ensureHandle();
    checkError(
      getNativeLib().hdds_qos_set_deadline_ns(
        this._handle,
        BigInt(seconds) * 1_000_000_000n
      ),
      "set deadline"
    );
    return this;
  }

  /**
   * Set lifespan duration in milliseconds.
   */
  lifespanMs(milliseconds: number): this {
    this.ensureHandle();
    checkError(
      getNativeLib().hdds_qos_set_lifespan_ns(
        this._handle,
        BigInt(milliseconds) * 1_000_000n
      ),
      "set lifespan"
    );
    return this;
  }

  /**
   * Set lifespan duration in seconds.
   */
  lifespanSecs(seconds: number): this {
    this.ensureHandle();
    checkError(
      getNativeLib().hdds_qos_set_lifespan_ns(
        this._handle,
        BigInt(seconds) * 1_000_000_000n
      ),
      "set lifespan"
    );
    return this;
  }

  /**
   * Set ownership to SHARED (multiple writers allowed).
   */
  ownershipShared(): this {
    this.ensureHandle();
    checkError(
      getNativeLib().hdds_qos_set_ownership_shared(this._handle),
      "set ownership_shared"
    );
    return this;
  }

  /**
   * Set ownership to EXCLUSIVE with given strength.
   */
  ownershipExclusive(strength: number): this {
    this.ensureHandle();
    checkError(
      getNativeLib().hdds_qos_set_ownership_exclusive(this._handle, strength),
      "set ownership_exclusive"
    );
    return this;
  }

  /**
   * Add a partition name.
   */
  partition(name: string): this {
    this.ensureHandle();
    checkError(
      getNativeLib().hdds_qos_add_partition(this._handle, name),
      "add partition"
    );
    return this;
  }

  /**
   * Set automatic liveliness with given lease duration in seconds.
   */
  livelinessAutomatic(leaseSecs: number): this {
    this.ensureHandle();
    checkError(
      getNativeLib().hdds_qos_set_liveliness_automatic_ns(
        this._handle,
        BigInt(Math.round(leaseSecs * 1_000_000_000))
      ),
      "set liveliness_automatic"
    );
    return this;
  }

  /**
   * Set manual-by-participant liveliness with given lease duration in seconds.
   */
  livelinessManualParticipant(leaseSecs: number): this {
    this.ensureHandle();
    checkError(
      getNativeLib().hdds_qos_set_liveliness_manual_participant_ns(
        this._handle,
        BigInt(Math.round(leaseSecs * 1_000_000_000))
      ),
      "set liveliness_manual_participant"
    );
    return this;
  }

  /**
   * Set manual-by-topic liveliness with given lease duration in seconds.
   */
  livelinessManualTopic(leaseSecs: number): this {
    this.ensureHandle();
    checkError(
      getNativeLib().hdds_qos_set_liveliness_manual_topic_ns(
        this._handle,
        BigInt(Math.round(leaseSecs * 1_000_000_000))
      ),
      "set liveliness_manual_topic"
    );
    return this;
  }

  /**
   * Set minimum sample separation in milliseconds (time-based filter).
   */
  timeBasedFilterMs(milliseconds: number): this {
    this.ensureHandle();
    checkError(
      getNativeLib().hdds_qos_set_time_based_filter_ns(
        this._handle,
        BigInt(milliseconds) * 1_000_000n
      ),
      "set time_based_filter"
    );
    return this;
  }

  /**
   * Set latency budget hint in milliseconds.
   */
  latencyBudgetMs(milliseconds: number): this {
    this.ensureHandle();
    checkError(
      getNativeLib().hdds_qos_set_latency_budget_ns(
        this._handle,
        BigInt(milliseconds) * 1_000_000n
      ),
      "set latency_budget"
    );
    return this;
  }

  /**
   * Set transport priority (0-100 typical).
   */
  transportPriority(priority: number): this {
    this.ensureHandle();
    checkError(
      getNativeLib().hdds_qos_set_transport_priority(this._handle, priority),
      "set transport_priority"
    );
    return this;
  }

  /**
   * Set resource limits.
   * Pass Number.MAX_SAFE_INTEGER for any parameter to indicate unlimited.
   */
  resourceLimits(
    maxSamples: number,
    maxInstances: number,
    maxSamplesPerInstance: number
  ): this {
    this.ensureHandle();
    checkError(
      getNativeLib().hdds_qos_set_resource_limits(
        this._handle,
        maxSamples,
        maxInstances,
        maxSamplesPerInstance
      ),
      "set resource_limits"
    );
    return this;
  }

  // ===========================================================================
  // Inspection - Getters
  // ===========================================================================

  /** Check if reliability is RELIABLE. */
  isReliable(): boolean {
    this.ensureHandle();
    return getNativeLib().hdds_qos_is_reliable(this._handle);
  }

  /** Check if durability is TRANSIENT_LOCAL. */
  isTransientLocal(): boolean {
    this.ensureHandle();
    return getNativeLib().hdds_qos_is_transient_local(this._handle);
  }

  /** Get history depth. */
  getHistoryDepth(): number {
    this.ensureHandle();
    return getNativeLib().hdds_qos_get_history_depth(this._handle);
  }

  /** Get deadline in nanoseconds (u64::MAX = infinite). */
  getDeadlineNs(): bigint {
    this.ensureHandle();
    return getNativeLib().hdds_qos_get_deadline_ns(this._handle);
  }

  /** Get lifespan in nanoseconds (u64::MAX = infinite). */
  getLifespanNs(): bigint {
    this.ensureHandle();
    return getNativeLib().hdds_qos_get_lifespan_ns(this._handle);
  }

  /** Check if ownership is EXCLUSIVE. */
  isOwnershipExclusive(): boolean {
    this.ensureHandle();
    return getNativeLib().hdds_qos_is_ownership_exclusive(this._handle);
  }

  /** Get ownership strength. */
  getOwnershipStrength(): number {
    this.ensureHandle();
    return getNativeLib().hdds_qos_get_ownership_strength(this._handle);
  }

  /** Get liveliness kind. */
  getLivelinessKind(): LivelinessKindValue {
    this.ensureHandle();
    return getNativeLib().hdds_qos_get_liveliness_kind(
      this._handle
    ) as LivelinessKindValue;
  }

  /** Get liveliness lease duration in nanoseconds. */
  getLivelinessLeaseNs(): bigint {
    this.ensureHandle();
    return getNativeLib().hdds_qos_get_liveliness_lease_ns(this._handle);
  }

  /** Get time-based filter minimum separation in nanoseconds (0 = disabled). */
  getTimeBasedFilterNs(): bigint {
    this.ensureHandle();
    return getNativeLib().hdds_qos_get_time_based_filter_ns(this._handle);
  }

  /** Get latency budget in nanoseconds (0 = disabled). */
  getLatencyBudgetNs(): bigint {
    this.ensureHandle();
    return getNativeLib().hdds_qos_get_latency_budget_ns(this._handle);
  }

  /** Get transport priority. */
  getTransportPriority(): number {
    this.ensureHandle();
    return getNativeLib().hdds_qos_get_transport_priority(this._handle);
  }

  /** Get max samples resource limit. */
  getMaxSamples(): number {
    this.ensureHandle();
    return getNativeLib().hdds_qos_get_max_samples(this._handle);
  }

  /** Get max instances resource limit. */
  getMaxInstances(): number {
    this.ensureHandle();
    return getNativeLib().hdds_qos_get_max_instances(this._handle);
  }

  /** Get max samples per instance resource limit. */
  getMaxSamplesPerInstance(): number {
    this.ensureHandle();
    return getNativeLib().hdds_qos_get_max_samples_per_instance(this._handle);
  }

  /** Get a human-readable description. */
  toString(): string {
    if (!this._handle) return "QoS(disposed)";
    const rel = this.isReliable() ? "reliable" : "best_effort";
    const dur = this.isTransientLocal() ? "transient_local" : "volatile";
    const depth = this.getHistoryDepth();
    return `QoS(${rel}, ${dur}, depth=${depth})`;
  }

  // ===========================================================================
  // Internal
  // ===========================================================================

  private ensureHandle(): void {
    if (!this._handle) {
      throw new HddsError("QoS has been disposed");
    }
  }
}
