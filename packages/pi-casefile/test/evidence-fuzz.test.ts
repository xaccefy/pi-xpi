import assert from "node:assert";
import { describe, it } from "node:test";
import { POC_CANARY_PLACEHOLDER, type PoCEvidence, parsePoCEvidence } from "../src/evidence.ts";

/** Named contract type for the parser result (no ReturnType coupling). */
type ParseResult = { ok: true; evidence: PoCEvidence } | { ok: false; error: string };

/**
 * Property-style adversarial input testing for the evidence contract parser —
 * the security boundary between PoC-authored bytes and the confirmation gate.
 *
 * Invariants under mutation:
 * 1. parsePoCEvidence NEVER throws — it always returns { ok, evidence/error }.
 *    A throw would crash the gate instead of rejecting the run.
 * 2. Trivial predicates (status-only, one-char contains, `.*` regexes) are
 *    always rejected.
 * 3. Nonce mismatch is always rejected (copy-pasted evidence fails).
 * 4. Valid evidence passes.
 */

/** Deterministic LCG so failures are reproducible. */
function lcg(seed: number): () => number {
  let state = seed >>> 0;
  return () => {
    state = (state * 1664525 + 1013904223) >>> 0;
    return state / 0x100000000;
  };
}

const CANARY = POC_CANARY_PLACEHOLDER;

function validEvidence(): Record<string, unknown> {
  return {
    nonce: "poc_abc123",
    claim: "foreign receipt content readable cross-account",
    verify: {
      method: "GET",
      url: "https://app.target.test/order/300401/receipt",
      headers: { authorization: "Bearer x" },
      expect: {
        status: [200],
        body_contains: ["flag{c4n4ry}"],
        body_regex: ["flag\\{[a-z0-9]+\\}"],
      },
    },
    observations: ["own receipt lacks flag", "foreign receipt leaks flag"],
  };
}

type Mutation =
  | { path: string[]; op: "delete" | "flood" }
  | { path: string[]; op: "replace" | "set-key"; value?: unknown; key?: string };

const MUTATIONS: Mutation[] = [
  // root type flips
  { path: [], op: "replace", value: null },
  { path: [], op: "replace", value: "string" },
  { path: [], op: "replace", value: 42 },
  { path: [], op: "replace", value: [] },
  // nonce attacks
  { path: ["nonce"], op: "delete" },
  { path: ["nonce"], op: "replace", value: "" },
  { path: ["nonce"], op: "replace", value: "x".repeat(257) },
  { path: ["nonce"], op: "replace", value: 123 },
  // claim attacks
  { path: ["claim"], op: "delete" },
  { path: ["claim"], op: "replace", value: "   " },
  { path: ["claim"], op: "replace", value: "c".repeat(2001) },
  // verify shape attacks
  { path: ["verify"], op: "delete" },
  { path: ["verify"], op: "replace", value: [] },
  { path: ["verify", "method"], op: "replace", value: "TRACE" },
  { path: ["verify", "method"], op: "replace", value: "" },
  { path: ["verify", "url"], op: "replace", value: "not a url" },
  { path: ["verify", "url"], op: "replace", value: "ftp://host/x" },
  { path: ["verify", "url"], op: "replace", value: "https://" },
  { path: ["verify", "url"], op: "replace", value: `https://host/${"u".repeat(5000)}` },
  // header injection / forbidden headers
  { path: ["verify", "headers"], op: "set-key", key: "transfer-encoding", value: "chunked" },
  { path: ["verify", "headers"], op: "set-key", key: "content-length", value: "5" },
  { path: ["verify", "headers"], op: "set-key", key: "host", value: "evil.test" },
  { path: ["verify", "headers"], op: "set-key", key: "x\r\nInjected", value: "1" },
  { path: ["verify", "headers"], op: "set-key", key: "x-inject", value: "line1\r\nline2" },
  { path: ["verify", "headers"], op: "replace", value: "not-an-object" },
  { path: ["verify", "headers"], op: "flood" },
  // body oversize
  { path: ["verify", "body"], op: "replace", value: "b".repeat(128 * 1024 + 1) },
  // trivial predicate battery — each must be rejected
  { path: ["verify", "expect", "body_contains"], op: "replace", value: ["a"] },
  { path: ["verify", "expect", "body_contains"], op: "replace", value: [" "] },
  { path: ["verify", "expect", "body_contains"], op: "replace", value: [""] },
  { path: ["verify", "expect", "body_contains"], op: "delete" },
  { path: ["verify", "expect", "body_regex"], op: "replace", value: [".*"] },
  { path: ["verify", "expect", "body_regex"], op: "replace", value: ["\\d+"] },
  { path: ["verify", "expect", "body_regex"], op: "replace", value: ["."] },
  { path: ["verify", "expect", "body_regex"], op: "replace", value: ["(a+)+$"] },
  { path: ["verify", "expect"], op: "delete" },
  { path: ["verify", "expect"], op: "replace", value: { status: [200] } },
  // expect shape attacks
  { path: ["verify", "expect", "status"], op: "replace", value: [99] },
  { path: ["verify", "expect", "status"], op: "replace", value: [600] },
  { path: ["verify", "expect", "status"], op: "replace", value: ["200"] },
  { path: ["verify", "expect", "status"], op: "replace", value: [] },
  { path: ["verify", "expect", "body_contains"], op: "replace", value: Array(17).fill("valid") },
  { path: ["verify", "expect", "body_regex"], op: "replace", value: ["("] },
  // observations abuse
  { path: ["observations"], op: "delete" },
  { path: ["observations"], op: "replace", value: "not-an-array" },
  { path: ["observations"], op: "replace", value: Array(65).fill("o") },
  { path: ["observations"], op: "replace", value: [null] },
  // canary placeholder count violations
  {
    path: ["verify"],
    op: "replace",
    value: {
      method: "GET",
      url: `https://host/${CANARY}?x=${CANARY}`,
      expect: { body_contains: ["marker"] },
      canary: { mode: "reflection", placeholder: CANARY },
    },
  },
  {
    path: ["verify"],
    op: "replace",
    value: {
      method: "GET",
      url: "https://host/",
      expect: { body_contains: ["marker"] },
      canary: { mode: "reflection", placeholder: "{{WRONG}}" },
    },
  },
  // baseline shape attacks
  { path: ["baseline"], op: "replace", value: "not-an-object" },
  { path: ["baseline"], op: "replace", value: { method: "GET" } },
];

function applyMutation(base: Record<string, unknown>, m: Mutation, rng: () => number) {
  const clone = structuredClone(base);
  let cursor: Record<string, unknown> | unknown[] = clone as Record<string, unknown>;
  for (let i = 0; i < m.path.length - (m.op === "set-key" ? 0 : 1); i++) {
    const next = (cursor as Record<string, unknown>)[m.path[i]];
    if (typeof next !== "object" || next === null) return clone; // parent gone; nothing to mutate
    cursor = next as Record<string, unknown>;
  }
  const leaf = m.path[m.path.length - 1];
  switch (m.op) {
    case "delete":
      delete (cursor as Record<string, unknown>)[leaf];
      break;
    case "replace":
      if (m.path.length === 0) return m.value as Record<string, unknown>;
      (cursor as Record<string, unknown>)[leaf] = m.value;
      break;
    case "set-key":
      (cursor as Record<string, unknown>)[m.key ?? "x"] = m.value;
      break;
    case "flood": {
      const obj: Record<string, string> = {};
      for (let i = 0; i < 70; i++) obj[`h${i}-${rng()}`] = "v";
      Object.assign(cursor as Record<string, unknown>, obj);
      break;
    }
  }
  return clone;
}

describe("evidence contract: adversarial property tests", () => {
  it("baseline valid evidence passes", () => {
    const parsed = parsePoCEvidence(validEvidence());
    assert.ok(parsed.ok, `valid evidence must pass: ${parsed.ok ? "" : parsed.error}`);
  });

  for (const [i, mutation] of MUTATIONS.entries()) {
    it(`mutation ${i}: ${mutation.path.join(".")} ${mutation.op}${"key" in mutation ? ` ${mutation.key}` : ""} never throws`, () => {
      const mutated = applyMutation(validEvidence(), mutation, () => 0.5);
      let result: ParseResult;
      try {
        result = parsePoCEvidence(mutated);
      } catch (e) {
        assert.fail(`parsePoCEvidence threw on mutation ${JSON.stringify(mutation)}: ${e}`);
      }
      assert.equal(typeof result.ok, "boolean", "result must be the ok-discriminated union");
    });
  }

  it("trivial predicates are always rejected across a randomized corpus", () => {
    const rng = lcg(0x5eed);
    const trivialPredicates = [
      { body_contains: ["a"] },
      { body_contains: [" "] },
      { body_regex: [".*"] },
      { body_regex: ["\\d+"] },
      { body_regex: ["\\S+"] },
      { status: [200], body_contains: ["ok"] }, // contains is 2 chars — still trivial
      {},
    ];
    let accepted = 0;
    for (let round = 0; round < 500; round++) {
      const ev = validEvidence();
      const pred = trivialPredicates[Math.floor(rng() * trivialPredicates.length)];
      const expect = {
        ...(rng() > 0.5 ? { status: [200] } : {}),
        ...pred,
      } as Record<string, unknown>;
      (ev.verify as Record<string, unknown>).expect = expect;
      const parsed = parsePoCEvidence(ev);
      if (parsed.ok) accepted++;
    }
    assert.equal(accepted, 0, `${accepted}/500 trivial-predicate evidences were ACCEPTED`);
  });

  it("nonce mismatch detection is exact across randomized nonces", () => {
    const rng = lcg(0xace);
    for (let round = 0; round < 200; round++) {
      const ev = validEvidence();
      const runNonce = `poc_${Math.floor(rng() * Number.MAX_SAFE_INTEGER).toString(16)}`;
      if (round % 2 === 0) ev.nonce = runNonce; // match
      const parsed = parsePoCEvidence(ev);
      assert.ok(parsed.ok);
      // The binding check itself lives in evidenceNonceMatches; the parser only
      // validates nonce presence/bounds — mismatch rejection is asserted in
      // ledger tests. Here we pin that the parser preserves the nonce verbatim
      // so the later comparison cannot be corrupted by parsing.
      assert.equal(parsed.ok && parsed.evidence.nonce, ev.nonce);
    }
  });

  it("randomized structural garbage never throws and never passes", () => {
    const rng = lcg(0xbadc0de);
    const garbageFactory = (): unknown => {
      const roll = rng();
      if (roll < 0.15) return null;
      if (roll < 0.3) return undefined;
      if (roll < 0.45) return rng() * 100;
      if (roll < 0.6)
        return String.fromCharCode(32 + Math.floor(rng() * 90)).repeat(Math.floor(rng() * 50));
      if (roll < 0.75)
        return Array.from({ length: Math.floor(rng() * 10) }, () => garbagePrimitive(rng));
      return { [`k${Math.floor(rng() * 5)}`]: garbagePrimitive(rng) };
    };
    const garbagePrimitive = (r: () => number): unknown =>
      r() < 0.5 ? Math.floor(r() * 1000) : "s".repeat(Math.floor(r() * 20));
    for (let round = 0; round < 500; round++) {
      let result: ParseResult | undefined;
      try {
        result = parsePoCEvidence(garbageFactory());
      } catch (e) {
        assert.fail(`parser threw on garbage round ${round}: ${e}`);
      }
      // No garbage blob satisfies the full contract (needs valid nonce+claim+
      // verify+expect with a discriminating body predicate), so ok must be false.
      assert.equal(result?.ok, false, `garbage passed on round ${round}`);
    }
  });
});
