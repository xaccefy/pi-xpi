import assert from "node:assert";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, it } from "node:test";
import {
  addCaseResult,
  addPrimitiveResult,
  deletePrimitiveResult,
  getPrimitiveById,
  linkCasesResult,
  linkPrimitiveResult,
  listPrimitives,
  setCasefilePath,
  suggestChains,
  unlinkPrimitiveResult,
} from "../src/ledger.ts";

let tempDir: string;
let ledgerPath: string;

beforeEach(async () => {
  tempDir = mkdtempSync(join(tmpdir(), "casefile-primitives-"));
  ledgerPath = join(tempDir, "casefile.db");
  setCasefilePath(ledgerPath);
});

afterEach(async () => {
  setCasefilePath(undefined);
  await Promise.resolve();
  rmSync(tempDir, { recursive: true, force: true });
});

function addCase(title: string, extra: Record<string, unknown> = {}) {
  const result = addCaseResult({
    title,
    status: "investigating",
    confidence: "medium",
    target: "https://api.example.com",
    evidence: "observed leak path from source to sink",
    disproveIf: ["the claim does not reproduce"],
    ...extra,
  });
  return result.record;
}

describe("pi-casefile: attack primitives", () => {
  it("adds, lists, gets, and deletes primitives with kind validation", () => {
    const prim = addPrimitiveResult({
      kind: "token",
      label: "admin API token",
      valueRef: "env:PRIM_ADMIN_TOKEN",
      capabilities: "full admin API access",
      notes: "leaked via debug endpoint case",
    });
    assert.match(prim.id, /^pr_/);
    assert.equal(prim.kind, "token");

    assert.throws(
      () => addPrimitiveResult({ kind: "banana", label: "x" }),
      /Invalid primitive kind/,
    );
    assert.throws(() => addPrimitiveResult({ kind: "token", label: "  " }), /must not be empty/);

    const got = getPrimitiveById(prim.id);
    assert.equal(got?.capabilities, "full admin API access");

    assert.equal(listPrimitives().length, 1);
    assert.equal(listPrimitives({ kind: "credential" }).length, 0);
    assert.equal(listPrimitives({ kind: "token" }).length, 1);

    assert.equal(deletePrimitiveResult(prim.id), true);
    assert.equal(getPrimitiveById(prim.id), undefined);
    assert.equal(deletePrimitiveResult(prim.id), false);
  });

  it("links primitives to cases; links are idempotent and validated", () => {
    const c1 = addCase("Debug endpoint leaks admin token");
    const c2 = addCase("Admin panel accepts leaked tokens");
    const prim = addPrimitiveResult({ kind: "token", label: "admin token", caseIds: [c1.id] });

    assert.deepEqual(getPrimitiveById(prim.id)?.caseIds, [c1.id]);

    const linked = linkPrimitiveResult(prim.id, c2.id);
    assert.deepEqual(linked.caseIds.sort(), [c1.id, c2.id].sort());

    // Idempotent
    assert.deepEqual(linkPrimitiveResult(prim.id, c2.id).caseIds.length, 2);

    assert.throws(() => linkPrimitiveResult("pr_missing", c1.id), /Primitive not found/);
    assert.throws(() => linkPrimitiveResult(prim.id, "missing-case"), /Case not found/);

    const unlinked = unlinkPrimitiveResult(prim.id, c2.id);
    assert.deepEqual(unlinked.caseIds, [c1.id]);
  });

  it("list by case filters through the junction table", () => {
    const c1 = addCase("Case one");
    const c2 = addCase("Case two");
    addPrimitiveResult({ kind: "session", label: "victim session", caseIds: [c1.id] });
    addPrimitiveResult({ kind: "endpoint", label: "/internal/debug", caseIds: [c2.id] });

    assert.equal(listPrimitives({ caseId: c1.id }).length, 1);
    assert.equal(listPrimitives({ caseId: c1.id })[0].kind, "session");
    assert.equal(listPrimitives({ caseId: c2.id })[0].kind, "endpoint");
  });

  it("ChainSuggest pairs primitive-producing cases with consumer cases on the same asset", () => {
    const producer = addCase("Debug endpoint leaks admin API token", {
      summary: "debug dump exposes api key material",
    });
    const consumer = addCase("Admin account takeover via login endpoint", {
      summary: "auth login admin account endpoint accepts anything",
    });

    const prim = addPrimitiveResult({
      kind: "token",
      label: "admin bearer token",
      capabilities: "admin API access",
      caseIds: [producer.id],
    });

    const suggestions = suggestChains();
    const hit = suggestions.find(
      (s) =>
        s.pattern === "primitive_use" && s.sourceId === producer.id && s.targetId === consumer.id,
    );
    assert.ok(hit, `expected primitive_use suggestion, got: ${JSON.stringify(suggestions)}`);
    assert.ok(hit.rationale.includes("admin bearer token"));
    assert.equal(hit.suggestedKind, "depends-on");

    // Once the pair is linked, the suggestion is no longer noise.
    linkCasesResult(producer.id, consumer.id, "depends-on");
    const after = suggestChains().filter((s) => s.pattern === "primitive_use");
    assert.equal(after.length, 0, "already-linked pairs must not be re-suggested");

    // Cleanup so later assertions in other tests are unaffected (fresh db per test anyway).
    assert.ok(prim);
  });

  it("primitive_use suggestions respect same-asset scoping", () => {
    const producer = addCase("Token leak on api.example.com", {
      target: "https://api.example.com",
    });
    const foreign = addCase("Unrelated auth surface elsewhere", { target: "https://other.org" });
    addPrimitiveResult({ kind: "credential", label: "creds", caseIds: [producer.id] });

    const hits = suggestChains().filter((s) => s.pattern === "primitive_use");
    assert.equal(hits.length, 0, "primitives must not chain across unrelated assets");
    assert.ok(foreign);
  });
});
