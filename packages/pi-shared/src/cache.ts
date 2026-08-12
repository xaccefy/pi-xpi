/**
 * Bounded TTL + LRU cache with singleflight coalescing.
 *
 * Shared across XPI packages so a bug fix lands once. Kept dependency-free
 * (no typebox, no host types) so any extension can import it.
 */
import { setTimeout as nodeDelay } from "node:timers/promises";

type CacheEntry<T> = { expires: number; value: T; gen: number };

export class TtlLruCache<T> {
  private readonly map = new Map<string, CacheEntry<T>>();
  private readonly inflight = new Map<string, Promise<T>>();

  constructor(
    private readonly ttlMs: number,
    private readonly maxSize: number,
  ) {
    if (!Number.isFinite(ttlMs) || ttlMs <= 0) {
      throw new Error("TtlLruCache: ttlMs must be a positive number");
    }
    if (!Number.isInteger(maxSize) || maxSize <= 0) {
      throw new Error("TtlLruCache: maxSize must be a positive integer");
    }
  }

  get(key: string): T | undefined {
    const hit = this.map.get(key);
    if (!hit) return undefined;
    if (hit.expires <= Date.now()) {
      this.map.delete(key);
      return undefined;
    }
    // LRU touch: re-insert at the tail so eviction order reflects recency.
    // The entry object (and its gen counter) is preserved.
    this.map.delete(key);
    this.map.set(key, hit);
    return hit.value;
  }

  set(key: string, value: T): void {
    const prev = this.map.get(key);
    // Direct set bumps the generation so an in-flight getOrLoad loader cannot
    // clobber this newer value when it resolves (stale-write race).
    const gen = (prev?.gen ?? 0) + 1;
    if (this.map.has(key)) this.map.delete(key);
    this.map.set(key, { expires: Date.now() + this.ttlMs, value, gen });
    this.evict();
  }

  async getOrLoad(key: string, loader: () => Promise<T>): Promise<T> {
    const cached = this.get(key);
    if (cached !== undefined) return cached;
    const pending = this.inflight.get(key);
    if (pending) return pending;
    const hadEntry = this.map.has(key);
    const genAtStart = this.map.get(key)?.gen ?? 0;
    const promise = (async () => {
      try {
        const value = await loader();
        // Publish the loaded value only if the entry has not been directly
        // replaced since the load started (stale-write guard). An LRU touch
        // preserves the gen, so a plain get() does not suppress the publish.
        const current = this.map.get(key);
        const staleWrite = hadEntry ? current?.gen !== genAtStart : current !== undefined;
        if (!staleWrite && value !== undefined) {
          // undefined results are not cached (get treats a miss as
          // undefined); caching them would just reload on every call.
          this.set(key, value);
        }
        return value;
      } finally {
        this.inflight.delete(key);
      }
    })();
    this.inflight.set(key, promise);
    return promise;
  }

  private evict(): void {
    const now = Date.now();
    for (const [k, v] of this.map) {
      if (v.expires <= now) this.map.delete(k);
    }
    while (this.map.size > this.maxSize) {
      const oldest = this.map.keys().next().value as string | undefined;
      if (oldest === undefined) break;
      this.map.delete(oldest);
    }
  }
}

/** Sleep that rejects when the parent signal aborts. No-op safe when undefined. */
export function abortableSleep(ms: number, parentSignal?: AbortSignal): Promise<void> {
  if (parentSignal?.aborted) {
    return Promise.reject(parentSignal.reason ?? new Error("aborted"));
  }
  if (parentSignal) {
    return nodeDelay(ms, undefined, { signal: parentSignal });
  }
  return nodeDelay(ms);
}
