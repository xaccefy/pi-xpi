/**
 * Lookup-local cache helpers.
 *
 * The TTL/LRU cache and abortableSleep live in @xaccefy/pi-shared so bug fixes
 * land once across all XPI packages. This module re-exports them for backwards
 * compatibility and adds the lookup-specific HTTP status helper.
 */
export { abortableSleep, TtlLruCache } from "@xaccefy/pi-shared";

export function isTransientHttpStatus(status: number): boolean {
  return status === 408 || status === 429 || status >= 500;
}
