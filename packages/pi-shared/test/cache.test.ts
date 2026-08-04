import assert from "node:assert";
import { describe, it } from "node:test";

import { abortableSleep, TtlLruCache } from "../src/index.ts";

describe("pi-shared: abortableSleep", () => {
  it("rejects when the signal aborts mid-sleep", async () => {
    const ac = new AbortController();
    const sleep = abortableSleep(10_000, ac.signal);
    ac.abort();
    await assert.rejects(sleep, (err: Error) => err.name === "AbortError");
  });

  it("rejects immediately on an already-aborted signal", async () => {
    const ac = new AbortController();
    ac.abort();
    await assert.rejects(abortableSleep(1, ac.signal), (err: Error) => err.name === "AbortError");
  });

  it("resolves without a signal", async () => {
    await abortableSleep(1);
  });
});

describe("pi-shared: TtlLruCache", () => {
  it("expires entries after the TTL", async () => {
    const cache = new TtlLruCache<string>(1, 10);
    cache.set("k", "v");
    await new Promise((r) => setTimeout(r, 5));
    assert.equal(cache.get("k"), undefined);
  });

  it("evicts the least-recently-used entry past maxSize", () => {
    const cache = new TtlLruCache<string>(60_000, 2);
    cache.set("a", "1");
    cache.set("b", "2");
    cache.get("a"); // touch a → b is now oldest
    cache.set("c", "3");
    assert.equal(cache.get("b"), undefined);
    assert.equal(cache.get("a"), "1");
    assert.equal(cache.get("c"), "3");
  });

  it("coalesces concurrent loads (singleflight)", async () => {
    const cache = new TtlLruCache<string>(60_000, 10);
    let loads = 0;
    const [a, b] = await Promise.all([
      cache.getOrLoad("k", async () => {
        loads++;
        return "v";
      }),
      cache.getOrLoad("k", async () => {
        loads++;
        return "v";
      }),
    ]);
    assert.equal(a, "v");
    assert.equal(b, "v");
    assert.equal(loads, 1);
  });
});
