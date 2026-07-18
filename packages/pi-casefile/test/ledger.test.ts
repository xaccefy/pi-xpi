import assert from "node:assert";
import { mkdtempSync } from "node:fs";
import { rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, it } from "node:test";

import {
  addCaseResult,
  assertPromotable,
  linkCasesResult,
  promoteFindingResult,
  readCasefile,
  searchCases,
  setCasefilePath,
  unlinkCasesResult,
  updateCaseResult,
  writeCaseReport,
} from "../src/ledger.ts";

const addCase = (input: Parameters<typeof addCaseResult>[0]) => {
  const res = addCaseResult(input);
  return res.record;
};

let tempDir: string;
let ledgerPath: string;

beforeEach(async () => {
  tempDir = mkdtempSync(join(tmpdir(), "casefile-test-"));
  ledgerPath = join(tempDir, "casefile.db");
  setCasefilePath(ledgerPath);
});

afterEach(async () => {
  setCasefilePath(undefined);
  await rm(tempDir, { recursive: true, force: true });
});

describe("casefile sqlite ledger", () => {
  it("adds cases with defaults and persists them in sqlite", () => {
    const record = addCase({
      title: " SSRF candidate ",
      target: "api.example.test",
      summary: "Server fetches attacker-controlled URLs",
      tags: [" ssrf ", "ssrf", ""],
    });

    assert.match(record.id, /^case_[a-f0-9]{10}$/);
    assert.strictEqual(record.title, "SSRF candidate");
    assert.strictEqual(record.status, "hypothesis");
    assert.strictEqual(record.confidence, "low");
    assert.deepStrictEqual(record.tags, ["ssrf"]);

    const records = readCasefile();
    assert.strictEqual(records.length, 1);
    assert.strictEqual(records[0].id, record.id);
    assert.strictEqual(records[0].title, "SSRF candidate");
    assert.strictEqual(records[0].target, "api.example.test");
    assert.strictEqual(records[0].summary, "Server fetches attacker-controlled URLs");
  });

  it("deduplicates active cases with the same title and scope", () => {
    const first = addCaseResult({
      title: " SSRF candidate ",
      target: "api.example.test",
      bugClass: "SSRF",
      evidence: "Observed URL fetch",
    });
    assert.strictEqual(first.created, true);

    const duplicate = addCaseResult({
      title: "ssrf   candidate",
      target: "api.example.test",
      bugClass: "ssrf",
      evidence: "Repeated audit note",
    });
    assert.strictEqual(duplicate.created, false);
    assert.strictEqual(duplicate.record.id, first.record.id);

    assert.strictEqual(readCasefile().length, 1);
  });

  it("assertPromotable gates cheaply before any PoC run", () => {
    const record = addCase({
      title: "XSS candidate",
      status: "hypothesis",
      evidence: "Reflected input",
    });

    // Wrong status
    assert.throws(() => assertPromotable(record.id), /requires an investigating case/);
    // Missing case
    assert.throws(() => assertPromotable("case_missing00"), /Case not found/);

    // Investigating but missing severity/impact
    updateCaseResult(record.id, { status: "investigating" });
    assert.throws(() => assertPromotable(record.id), /CONFIRMED requires/);

    // Fully gated
    updateCaseResult(record.id, {
      severity: "medium",
      impact: "Session theft",
      poc: "alert(1) in search box",
    });
    const ok = assertPromotable(record.id);
    assert.strictEqual(ok.id, record.id);
  });

  it("updates by replacing in sqlite and returns unchanged status", () => {
    const record = addCase({
      title: "IDOR in export",
      status: "investigating",
      evidence: "Observed sequential IDs",
      confidence: "medium",
    });

    const updated = updateCaseResult(record.id, {
      confidence: "high",
      severity: "high",
      poc: "Request /exports/123 as another user",
      impact: "Unauthorized file disclosure",
      evidence: "Observed sequential IDs",
    });
    assert.strictEqual(updated.changed, true);

    const promoted = promoteFindingResult(record.id, {
      path: "/workspace/idor-poc.py",
      exitCode: 0,
      ranAt: "2024-01-01T00:00:00Z",
      sandbox: true,
    });
    assert.strictEqual(promoted.record.status, "confirmed");
    assert.strictEqual(promoted.record.confidence, "high");
    assert.strictEqual(promoted.record.severity, "high");

    const noOp = updateCaseResult(record.id, { status: "confirmed" });
    assert.strictEqual(noOp.changed, false);

    assert.strictEqual(readCasefile().length, 1);
  });

  it("links cases bidirectionally using case_links table", () => {
    const caseA = addCase({ title: "Case A" });
    const caseB = addCase({ title: "Case B" });

    const linked = linkCasesResult(caseA.id, caseB.id);
    assert.strictEqual(linked.changed, true);
    assert.ok(linked.source.linkedCaseIds.includes(caseB.id));
    assert.ok(linked.target.linkedCaseIds.includes(caseA.id));

    const unlinked = unlinkCasesResult(caseA.id, caseB.id);
    assert.strictEqual(unlinked.changed, true);
    assert.ok(!unlinked.source.linkedCaseIds.includes(caseB.id));
  });

  it("preserves exploit-chain links across CaseUpdate (no REPLACE cascade)", () => {
    const a = addCase({ title: "Link source" });
    const b = addCase({ title: "Link target" });
    linkCasesResult(a.id, b.id);

    const updated = updateCaseResult(a.id, { summary: "material field change" });
    assert.strictEqual(updated.changed, true);
    assert.ok(
      updated.record.linkedCaseIds.includes(b.id),
      "update must not wipe case_links via INSERT OR REPLACE cascade",
    );

    const reloaded = readCasefile().find((c) => c.id === a.id);
    assert.ok(reloaded?.linkedCaseIds.includes(b.id));
  });

  it("records and surfaces a typed relationship kind on links", () => {
    const a = addCase({ title: "Root cause A" });
    const b = addCase({ title: "Symptom B" });

    // Default kind is "related" when omitted (back-compat with pre-kind links).
    const plain = linkCasesResult(a.id, b.id);
    assert.strictEqual(plain.changed, true);
    assert.strictEqual(plain.kind, "related");
    const reloadedA = readCasefile().find((c) => c.id === a.id)!;
    assert.ok(reloadedA.linkedCases.some((l) => l.id === b.id && l.kind === "related"));
    assert.ok(reloadedA.linkedCaseIds.includes(b.id));
    unlinkCasesResult(a.id, b.id);

    // Directional kind: source→target keeps the stated kind; the reverse row
    // stores the inverse so each case lists the edge from its own perspective.
    const typed = linkCasesResult(a.id, b.id, "caused-by");
    assert.strictEqual(typed.changed, true);
    assert.strictEqual(typed.kind, "caused-by");
    const afterA = readCasefile().find((c) => c.id === a.id)!;
    const afterB = readCasefile().find((c) => c.id === b.id)!;
    assert.ok(afterA.linkedCases.some((l) => l.id === b.id && l.kind === "caused-by"));
    assert.ok(afterB.linkedCases.some((l) => l.id === a.id && l.kind === "causes"));

    // Symmetric kind maps to itself on both sides.
    unlinkCasesResult(a.id, b.id);
    linkCasesResult(a.id, b.id, "duplicate");
    const dupA = readCasefile().find((c) => c.id === a.id)!;
    const dupB = readCasefile().find((c) => c.id === b.id)!;
    assert.ok(dupA.linkedCases.some((l) => l.id === b.id && l.kind === "duplicate"));
    assert.ok(dupB.linkedCases.some((l) => l.id === a.id && l.kind === "duplicate"));

    // Unknown kind falls back to the default rather than throwing.
    unlinkCasesResult(a.id, b.id);
    const fallback = linkCasesResult(a.id, b.id, "nonsense" as unknown as string);
    assert.strictEqual(fallback.kind, "related");
  });

  it("promotes hypothesis → investigating using evidence already on the case", () => {
    const record = addCase({
      title: "IDOR with prior evidence",
      status: "hypothesis",
      evidence: "source→sink already recorded",
      confidence: "medium",
    });

    // Status-only update must succeed when fields already exist on the record.
    const updated = updateCaseResult(record.id, { status: "investigating" });
    assert.strictEqual(updated.changed, true);
    assert.strictEqual(updated.record.status, "investigating");
  });

  it("rejects field mutations on killed and reported cases", () => {
    const killed = addCase({
      title: "Dead lead",
      evidence: "not a vuln",
    });
    updateCaseResult(killed.id, {
      status: "killed",
      assumptions: ["matches documented behavior"],
    });
    assert.throws(
      () => updateCaseResult(killed.id, { summary: "should not stick" }),
      /Cannot mutate a killed case/,
    );

    const live = addCase({
      title: "Confirmed then reported",
      status: "investigating",
      evidence: "repro steps",
      confidence: "high",
      impact: "data leak",
      severity: "high",
      poc: "/tmp/poc.sh",
    });
    promoteFindingResult(live.id, {
      path: "/tmp/poc.sh",
      exitCode: 0,
      ranAt: "2024-01-01T00:00:00Z",
      sandbox: true,
    });
    // CaseReport writes reportPath before status can advance to reported.
    writeCaseReport(live.id);
    updateCaseResult(live.id, { status: "reported" });
    assert.throws(
      () => updateCaseResult(live.id, { summary: "should not stick" }),
      /Cannot mutate a reported case/,
    );
  });

  it("searchCases pushes filters into SQL (tag, severity, minSeverity, since, field, pagination)", () => {
    addCase({
      title: "SQL injection in login",
      target: "app.test",
      bugClass: "sqli",
      severity: "high",
      tags: ["inj", "auth"],
      summary: "UNION-based extraction",
    });
    addCase({
      title: "Reflected XSS in search",
      target: "app.test",
      bugClass: "xss",
      severity: "low",
      tags: ["inj"],
      summary: "reflects query in HTML",
    });
    addCase({
      title: "Open redirect",
      target: "other.test",
      bugClass: "redirect",
      severity: "info",
      tags: ["web"],
    });

    // tag filter via json_each
    const byTag = searchCases({ tag: "inj" });
    assert.strictEqual(byTag.total, 2);

    // exact severity
    const bySev = searchCases({ severity: "high" });
    assert.strictEqual(bySev.total, 1);
    assert.strictEqual(bySev.cases[0].bugClass, "sqli");

    // minSeverity threshold (low+ => high & low, not info)
    const byMin = searchCases({ minSeverity: "low" });
    assert.strictEqual(byMin.total, 2);

    // field-scoped free-text
    const byField = searchCases({ field: "summary", query: "union" });
    assert.strictEqual(byField.total, 1);
    assert.strictEqual(byField.cases[0].bugClass, "sqli");

    // since/until date range
    const before = searchCases({ until: "2000-01-01T00:00:00Z" });
    assert.strictEqual(before.total, 0);
    const after = searchCases({ since: "2000-01-01T00:00:00Z" });
    assert.strictEqual(after.total, 3);

    // pagination
    const page = searchCases({ limit: 1, offset: 0 });
    assert.strictEqual(page.total, 3);
    assert.strictEqual(page.cases.length, 1);
  });
});
