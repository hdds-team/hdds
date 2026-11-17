// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * Type declarations for domain-lease.js. Hand-written, not generated: the
 * implementation is deliberately plain CommonJS (see the header comment in
 * domain-lease.js) so it stays usable from `node domain-lease.js ...` with
 * no build step; this file exists only so a .ts test file that imports it
 * gets real types instead of `any`.
 */

export const FLEET_RESERVED_DOMAINS: readonly number[];
export const TEST_PINNED_DOMAINS: readonly number[];
export const MAX_DOMAIN_ID: number;
export const DOMAIN_POOL: readonly number[];
export const TOKEN_NAME_PREFIX: string;
export const NON_LINUX_TOKEN_PORT_BASE: number;
export const NON_LINUX_MAX_TOKEN_ID: number;

export function computePool(): number[];
export function touchesEphemeralRange(domain: number): boolean;
export function isExcluded(domain: number): boolean;
export function isLinux(): boolean;

export interface DomainLease {
  readonly domain: number;
  release(): Promise<void>;
}

export function tryBindToken(domain: number): Promise<DomainLease>;

export interface LeaseDomainOptions {
  startHint?: number;
  pool?: readonly number[];
}

export function leaseDomain(options?: LeaseDomainOptions): Promise<DomainLease>;

export class DomainTokenError extends Error {}

export class DomainPoolExhaustedError extends Error {
  readonly poolLen: number;
  constructor(poolLen: number);
}
