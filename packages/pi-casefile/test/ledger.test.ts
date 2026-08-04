import assert from "node:assert";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, it } from "node:test";
import {
  addEvidenceItemResult,
  assertPromotable,
  coverageSummary,
  getCaseById,
  getCasefilePath,
  addCaseResult as ledgerAddCaseResult,
  linkCasesResult,
  listEvidenceItems,
  type PocVerification,
  promoteFindingResult,
  readCasefile,
  recordCoverageResult,
  searchCases,
  setCasefilePath,
  suggestChains,
  unlinkCasesResult,
  updateCaseResult,
  writeCaseContext,
} from "../src/ledger.ts";
import {
  scratchpad_checkpoint,
  scratchpad_init,
  scratchpad_write,
  setScratchpadRoot,
} from "../src/scratchpad.ts";
import { DatabaseSync } from "../src/sqlite-compat/index.ts";

const addCase = (input: Parameters<typeof ledgerAddCaseResult>[0]) => {
  const res = ledgerAddCaseResult({
    // New cases require falsification conditions; tests inject a default.
    disproveIf: ["test: finding is actually intended behavior"],
    ...input,
  });
  // Promotion requires the observation evidence item (evidence-chain closure);
  // tests inject one so fixtures focus on the behavior they exercise.
  addEvidenceItemResult(res.record.id, {
    role: "observation",
    summary: "test fixture: initial observed signal",
  });
  return res.record;
};

// Direct addCaseResult call sites in older tests predate the disproveIf
// requirement; route them through the same default injection.
const addCaseResult = (input: Parameters<typeof ledgerAddCaseResult>[0]) => {
  const res = ledgerAddCaseResult({
    disproveIf: ["test: finding is actually intended behavior"],
    ...input,
  });
  addEvidenceItemResult(res.record.id, {
    role: "observation",
    summary: "test fixture: initial observed signal",
  });
  return res;
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
  setScratchpadRoot(undefined);
  await rm(tempDir, { recursive: true, force: true });
});

describe("casefile sqlite ledger", () => {
  it("whitespace-only PI_CASEFILE_PATH falls through to the default ledger path", () => {
    // Regression: truthiness was checked on the raw env value, so "   " passed
    // and resolve("") returned the process cwd (a directory) — every tool call
    // then failed with "unable to open database file".
    setCasefilePath(undefined);
    const previous = process.env.PI_CASEFILE_PATH;
    try {
      process.env.PI_CASEFILE_PATH = "   ";
      const p = getCasefilePath();
      assert.ok(
        p.endsWith(join(".pi", "casefile.db")),
        `whitespace env must fall back to the workspace default, got: ${p}`,
      );
      assert.notEqual(p, process.cwd());
    } finally {
      if (previous === undefined) delete process.env.PI_CASEFILE_PATH;
      else process.env.PI_CASEFILE_PATH = previous;
      setCasefilePath(ledgerPath);
    }
  });

  it("PI_CASEFILE_PATH is honored after trimming", () => {
    setCasefilePath(undefined);
    const previous = process.env.PI_CASEFILE_PATH;
    try {
      process.env.PI_CASEFILE_PATH = ` ${ledgerPath} `;
      assert.strictEqual(getCasefilePath(), ledgerPath);
    } finally {
      if (previous === undefined) delete process.env.PI_CASEFILE_PATH;
      else process.env.PI_CASEFILE_PATH = previous;
      setCasefilePath(ledgerPath);
    }
  });

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

  it("deduplicates when the STORED title has irregular whitespace or non-ASCII case", () => {
    // Regression: the old SQL LIKE pre-filter compared the JS-normalized
    // candidate against the raw DB title, so rows with extra whitespace or
    // non-ASCII casing never reached the JS comparator and duplicates were
    // created.
    const first = addCaseResult({
      title: "SQL  Éxploitation in Login",
      target: "shop.example.test",
      evidence: "probe",
    });
    assert.strictEqual(first.created, true);

    const dupe = addCaseResult({
      title: "SQL ÉXPLOITATION IN LOGIN",
      target: "shop.example.test",
      evidence: "probe again",
    });
    assert.strictEqual(dupe.created, false);
    assert.strictEqual(dupe.record.id, first.record.id);
    assert.strictEqual(readCasefile().length, 1);
  });

  it("catches near-duplicates from parallel subagent phrasings (same target, overlapping title)", () => {
    // Regression: parallel subagents phrase the same finding differently, so a
    // 30-case run produced several re-writes of one bug. Calibrated against the
    // real js-iam run: these share 4-6 significant tokens, distinct findings 1-2.
    const first = addCaseResult({
      title:
        "IAM middleware: global userCache keyed only by email:service — cross-environment/tenant permission reuse",
      target: "kiwicom/js-iam-middleware",
      evidence: "probe",
    });
    assert.strictEqual(first.created, true);

    const rephrased = addCaseResult({
      title:
        "userCache key omits iamURL/iamToken/tenant — cross-environment permission cache collision",
      target: "kiwicom/js-iam-middleware",
      evidence: "probe",
    });
    assert.strictEqual(rephrased.created, false);
    assert.strictEqual(rephrased.record.id, first.record.id);
    assert.match(rephrased.reason ?? "", /near-duplicate/i);

    // A different bug (directive config) must pair against its OWN group, not
    // the usercache case — only "cross" is shared between the two groups.
    const directive = addCaseResult({
      title:
        "AuthorizationDirective static config contamination — last authorizationDirective() call wins for ALL schemas",
      target: "kiwicom/js-iam-middleware",
      evidence: "probe",
    });
    assert.strictEqual(directive.created, true);

    const directiveRephrased = addCaseResult({
      title:
        "IAM middleware: AuthorizationDirective static config — second directive registration overwrites first (cross-schema authz contamination)",
      target: "kiwicom/js-iam-middleware",
      evidence: "probe",
    });
    assert.strictEqual(directiveRephrased.created, false);
    assert.strictEqual(directiveRephrased.record.id, directive.record.id);
    assert.match(directiveRephrased.reason ?? "", /near-duplicate/i);
  });

  it("does not near-merge distinct findings or different targets", () => {
    const a = addCaseResult({
      title: "Reflected XSS in search endpoint via q parameter",
      target: "shop.example.test",
      evidence: "probe",
    });
    assert.strictEqual(a.created, true);

    // Same target, distinct bug: only 1-2 shared tokens — must be allowed.
    const b = addCaseResult({
      title: "CSRF on password change endpoint",
      target: "shop.example.test",
      evidence: "probe",
    });
    assert.strictEqual(b.created, true);

    // Same bug + shared words, but different target: must be allowed.
    const c = addCaseResult({
      title:
        "IAM middleware: global userCache keyed only by email:service — cross-environment/tenant permission reuse",
      target: "another-target",
      evidence: "probe",
    });
    assert.strictEqual(c.created, true);
  });

  it("update blocked when it would near-duplicate an existing case", () => {
    addCaseResult({
      title: "OAuth dev callback CSRF: no state param, no origin check",
      target: "api.example.test",
      evidence: "probe",
    });
    const second = addCaseResult({
      title: "Rate limit missing on login endpoint",
      target: "api.example.test",
      evidence: "probe",
    });
    assert.strictEqual(second.created, true);

    const res = updateCaseResult(second.record.id, {
      title: "OAuth callback CSRF/race in generate-iap-token: missing state + first-callback-wins",
      target: "api.example.test",
    });
    assert.strictEqual(res.changed, false);
    assert.match(res.reason ?? "", /near-duplicate/i);
  });

  it("near-dup boundary: 2 shared tokens or stopword-only overlap does NOT fire; 3 fires", () => {
    // Distinctive tokens only (stopwords are suppressed): alpha/bravo/… are
    // made-up 5+ char words so the counts are exact.
    const base = addCaseResult({
      title: "alpha bravo charlie delta",
      target: "boundary.test",
      evidence: "probe",
    });
    assert.strictEqual(base.created, true);

    // Exactly 2 shared distinctive tokens (alpha, bravo) → distinct finding.
    const two = addCaseResult({
      title: "alpha bravo echo foxtrot",
      target: "boundary.test",
      evidence: "probe",
    });
    assert.strictEqual(two.created, true);

    // Exactly 3 shared (alpha, bravo, charlie) → near-duplicate.
    const three = addCaseResult({
      title: "alpha bravo charlie foxtrot",
      target: "boundary.test",
      evidence: "probe",
    });
    assert.strictEqual(three.created, false);
    assert.match(three.reason ?? "", /near-duplicate/i);
  });

  it("near-dup does not fire on stopword-only overlap or empty targets", () => {
    const first = addCaseResult({
      title: "Remote code execution in image processing",
      target: "app.test",
      evidence: "probe",
    });
    assert.strictEqual(first.created, true);

    // All shared words are suppressed stopwords (remote/code/execution/processing).
    const stopwordOnly = addCaseResult({
      title: "Remote code execution in PDF processing",
      target: "app.test",
      evidence: "probe",
    });
    assert.strictEqual(stopwordOnly.created, true);

    // Same class words, but no target on either side → must not near-merge.
    const noTarget = addCaseResult({
      title: "Remote code execution in video processing",
      target: "",
      evidence: "probe",
    });
    assert.strictEqual(noTarget.created, true);
  });

  it("reported cases are excluded from the duplicate scan (follow-up case allowed)", () => {
    const original = addCase({
      title: "Stored XSS in chat",
      status: "investigating",
      evidence: "payload renders",
      confidence: "high",
      impact: "script execution",
      severity: "high",
      target: "chat.test",
      poc: "repro",
      disconfirmation: "tried, held",
    });
    promoteFindingResult(original.id, {
      path: "/tmp/poc.sh",
      exitCode: 0,
      ranAt: "2024-01-01T00:00:00Z",
      sandbox: true,
    });
    const { path } = writeCaseContext(original.id);
    writeFileSync(path, "# Report\n", "utf8");
    updateCaseResult(original.id, { status: "reported" });

    // An exact duplicate of a REPORTED case is a new follow-up case, not a merge.
    const followUp = addCaseResult({
      title: "Stored XSS in chat",
      target: "chat.test",
      evidence: "recurred after patch",
    });
    assert.strictEqual(followUp.created, true);
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
      target: "example-app",
      disconfirmation: "Tried to reproduce without search input; could not.",
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
      target: "example-app",
      disconfirmation:
        "Attempted to access own export without authentication; blocked. Only IDOR through authenticated session.",
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
    assert.ok(linked.source.linkedCases.map((l) => l.id).includes(caseB.id));
    assert.ok(linked.target.linkedCases.map((l) => l.id).includes(caseA.id));

    const unlinked = unlinkCasesResult(caseA.id, caseB.id);
    assert.strictEqual(unlinked.changed, true);
    assert.ok(!unlinked.source.linkedCases.map((l) => l.id).includes(caseB.id));
  });

  it("preserves exploit-chain links across CaseUpdate (no REPLACE cascade)", () => {
    const a = addCase({ title: "Link source" });
    const b = addCase({ title: "Link target" });
    linkCasesResult(a.id, b.id);

    const updated = updateCaseResult(a.id, { summary: "material field change" });
    assert.strictEqual(updated.changed, true);
    assert.ok(
      updated.record.linkedCases.map((l) => l.id).includes(b.id),
      "update must not wipe case_links via INSERT OR REPLACE cascade",
    );

    const reloaded = readCasefile().find((c) => c.id === a.id);
    assert.ok(reloaded?.linkedCases.map((l) => l.id).includes(b.id));
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
    assert.ok(reloadedA.linkedCases.map((l) => l.id).includes(b.id));
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

  it("requires disproveIf (falsification conditions) on new cases", () => {
    assert.throws(
      () => ledgerAddCaseResult({ title: "No falsification", evidence: "x" }),
      /disproveIf/,
    );
    assert.throws(
      () => ledgerAddCaseResult({ title: "Empty falsification", disproveIf: ["   "] }),
      /disproveIf/,
    );
  });

  it("rejects a kill without refutation evidence or a kill-reason token", () => {
    const noReason = addCase({ title: "Kill without reason" });
    assert.throws(
      () => updateCaseResult(noReason.id, { status: "killed" }),
      /Cannot kill without justification/,
    );
    // Reason token in assumptions passes.
    const token = addCase({ title: "Kill with token" });
    const killed = updateCaseResult(token.id, {
      status: "killed",
      assumptions: ["intended_behavior: documented in README"],
    });
    assert.strictEqual(killed.record.status, "killed");
    // Refutation evidence item also passes.
    const refuted = addCase({ title: "Kill with refutation evidence" });
    addEvidenceItemResult(refuted.id, {
      role: "refutation",
      summary: "Re-probe returned 403 with the same payload; path is WAF-blocked.",
    });
    const killed2 = updateCaseResult(refuted.id, {
      status: "killed",
      nextStep: "killed: refutation evidence — WAF-blocked re-probe",
    });
    assert.strictEqual(killed2.record.status, "killed");
  });

  it("adds role-typed, hashed evidence items and lists them on the case", () => {
    // Bare case (no helper observation item) so the count below is exact.
    const c = ledgerAddCaseResult({
      title: "Evidence item case",
      disproveIf: ["test: finding is actually intended behavior"],
    }).record;
    const artifact = join(tempDir, "probe-response.txt");
    writeFileSync(artifact, "HTTP/1.1 200 OK\nsecret-data", "utf8");

    const item = addEvidenceItemResult(c.id, {
      role: "observation",
      summary: "Probe response shows reflected input",
      artifactPath: artifact,
    });
    assert.ok(item.id.startsWith("ev_"));
    assert.strictEqual(item.role, "observation");
    assert.strictEqual(item.artifactPath, "probe-response.txt"); // basename only
    // The digest must be the REAL sha256 of the artifact bytes, not a stub.
    const expected = createHash("sha256").update("HTTP/1.1 200 OK\nsecret-data").digest("hex");
    assert.strictEqual(item.sha256, expected);
    assert.throws(
      () => addEvidenceItemResult(c.id, { role: "nonsense" as any, summary: "x" }),
      /Invalid evidence role/,
    );
    assert.throws(
      () =>
        addEvidenceItemResult(c.id, {
          role: "observation",
          summary: "x",
          artifactPath: join(tempDir, "missing.txt"),
        }),
      /Evidence artifact not found/,
    );

    const items = listEvidenceItems(c.id);
    assert.strictEqual(items.length, 1);
    assert.strictEqual(items[0].sha256, item.sha256);

    // Terminal cases reject new evidence.
    updateCaseResult(c.id, {
      status: "killed",
      assumptions: ["duplicate"],
    });
    assert.throws(
      () => addEvidenceItemResult(c.id, { role: "impact", summary: "too late" }),
      /terminal case/,
    );
  });

  it("rejects promotion of a live finding (sandbox:false) without control verification", () => {
    const live = addCase({
      title: "Live IDOR",
      status: "investigating",
      evidence: "Observed other user's export",
      confidence: "high",
      impact: "data leak",
      severity: "high",
      poc: "/tmp/poc.sh",
      target: "example-app",
      disconfirmation: "Tried to disprove; could not.",
    });
    assert.throws(
      () =>
        promoteFindingResult(live.id, {
          path: "/tmp/poc.sh",
          exitCode: 0,
          ranAt: "2024-01-01T00:00:00Z",
          sandbox: false,
        }),
      /require.*controlVerification/,
    );
    // Content, not just presence: a crashed control (completed:false) is invalid.
    assert.throws(
      () =>
        promoteFindingResult(
          live.id,
          { path: "/tmp/poc.sh", exitCode: 0, ranAt: "2024-01-01T00:00:00Z", sandbox: false },
          undefined,
          {
            path: "/tmp/ctrl.sh",
            exitCode: 127,
            ranAt: "2024-01-01T00:00:00Z",
            sandbox: false,
            completed: false,
            output: "",
          },
          "VULN_MARKER",
        ),
      /require.*controlVerification/,
    );
    // …and so is a control whose output contains the marker (unconditional-marker PoC).
    assert.throws(
      () =>
        promoteFindingResult(
          live.id,
          { path: "/tmp/poc.sh", exitCode: 0, ranAt: "2024-01-01T00:00:00Z", sandbox: false },
          undefined,
          {
            path: "/tmp/ctrl.sh",
            exitCode: 1,
            ranAt: "2024-01-01T00:00:00Z",
            sandbox: false,
            completed: true,
            output: "VULN_MARKER leaked",
          },
          "VULN_MARKER",
        ),
      /require.*controlVerification/,
    );
    // sandbox: undefined (JS caller omitting the field) must ALSO fail closed.
    // TS requires the field, so the omission is simulated via a runtime cast.
    const noSandboxField = {
      path: "/tmp/poc.sh",
      exitCode: 0,
      ranAt: "2024-01-01T00:00:00Z",
      // sandbox deliberately absent
    } as unknown as PocVerification;
    assert.throws(
      () => promoteFindingResult(live.id, noSandboxField),
      /require.*controlVerification/,
    );
    // A control that RAN, exited non-zero (vuln absent — expected) and printed
    // no marker is valid: the live finding promotes.
    const ok = promoteFindingResult(
      live.id,
      { path: "/tmp/poc.sh", exitCode: 0, ranAt: "2024-01-01T00:00:00Z", sandbox: false },
      undefined,
      {
        path: "/tmp/ctrl.sh",
        exitCode: 1,
        ranAt: "2024-01-01T00:00:00Z",
        sandbox: false,
        completed: true,
        output: "control target clean",
      },
      "VULN_MARKER",
    );
    assert.strictEqual(ok.record.status, "confirmed");
    // Sandboxed (source-audit) findings do not need a control run.
    const source = addCase({
      title: "Source XSS",
      status: "investigating",
      evidence: "Payload renders",
      confidence: "high",
      impact: "script execution",
      severity: "high",
      poc: "/tmp/poc.sh",
      target: "packages/ui",
      disconfirmation: "Tried; held.",
    });
    const promoted = promoteFindingResult(source.id, {
      path: "/tmp/poc.sh",
      exitCode: 0,
      ranAt: "2024-01-01T00:00:00Z",
      sandbox: true,
    });
    assert.strictEqual(promoted.record.status, "confirmed");
  });

  it("rejects promotion without an observation evidence item (chain closure)", () => {
    // Built WITHOUT the helper's observation item.
    const bare = ledgerAddCaseResult({
      title: "No observation",
      status: "investigating",
      evidence: "reflected input",
      confidence: "high",
      impact: "script execution",
      severity: "high",
      poc: "/tmp/poc.sh",
      target: "example-app",
      disconfirmation: "Tried; could not disprove.",
      disproveIf: ["test: finding is actually intended behavior"],
    });
    assert.throws(
      () =>
        promoteFindingResult(bare.record.id, {
          path: "/tmp/poc.sh",
          exitCode: 0,
          ranAt: "2024-01-01T00:00:00Z",
          sandbox: true,
        }),
      /Evidence chain incomplete/,
    );
    // No phantom reproduction item may exist on the still-investigating case.
    assert.strictEqual(listEvidenceItems(bare.record.id).length, 0);
    // Retry after adding the observation item succeeds — no PK conflict on the
    // deterministic reproduction id.
    addEvidenceItemResult(bare.record.id, { role: "observation", summary: "obs" });
    const ok = promoteFindingResult(bare.record.id, {
      path: "/tmp/poc.sh",
      exitCode: 0,
      ranAt: "2024-01-02T00:00:00Z",
      sandbox: true,
    });
    assert.strictEqual(ok.record.status, "confirmed");
    assert.strictEqual(listEvidenceItems(bare.record.id).length, 2); // obs + reproduction
  });

  it("migrates a pre-evidence/pre-coverage ledger schema on reopen", () => {
    const seed = addCase({ title: "Legacy case" });

    // Simulate a DB created before evidence_items / coverage_items existed:
    // strip the new feature surface, then reopen through the ledger.
    const raw = new DatabaseSync(ledgerPath);
    raw.exec("DROP TABLE coverage_items");
    raw.exec("DROP TABLE evidence_items");
    raw.exec("ALTER TABLE cases DROP COLUMN disprove_if_json");
    raw.exec("ALTER TABLE cases DROP COLUMN control_verified_json");
    raw.close();

    // Force the ledger to re-run schema init against the stripped file.
    setCasefilePath(ledgerPath);

    const reopened = getCaseById(seed.id);
    assert.ok(reopened, "legacy row readable after migration");
    const item = addEvidenceItemResult(seed.id, {
      role: "observation",
      summary: "post-migration",
    });
    assert.ok(item.id.startsWith("ev_"));
    assert.strictEqual(listEvidenceItems(seed.id).length, 1);
    // The restored schema accepts a fresh write end to end.
    const next = addCase({ title: "After migration" });
    assert.ok(next.id);
  });

  it("records coverage cells with wide/local scope and propagates wide verdicts", () => {
    const c = addCase({ title: "Coverage case" });
    const wide = recordCoverageResult(c.id, {
      asset: "example-app",
      class: "sql-injection",
      scope: "wide",
      note: "ffuf + manual payloads on all params; no injection",
    });
    assert.ok(wide.id.startsWith("cov_"));
    assert.strictEqual(wide.scope, "wide");

    // Local cell for a second asset — the wide verdict must cover it.
    recordCoverageResult(c.id, {
      asset: "api.example-app",
      class: "sql-injection",
      scope: "local",
      note: "api param reflects payload; no DB error",
    });
    recordCoverageResult(c.id, {
      asset: "admin.example-app",
      class: "xss",
      scope: "local",
      note: "no reflection",
    });

    assert.throws(
      () =>
        recordCoverageResult(c.id, { asset: "x", class: "y", scope: "bogus" as never, note: "z" }),
      /Invalid coverage scope/,
    );

    const summary = coverageSummary(c.id);
    assert.deepStrictEqual(summary.classes.sort(), ["sql-injection", "xss"]);
    // admin asset gets the wide sql-injection verdict applied (no local cell for it).
    const adminCells = summary.byAsset["admin.example-app"]!;
    assert.ok(adminCells.some((cell) => cell.class === "sql-injection" && cell.scope === "wide"));
    assert.ok(adminCells.some((cell) => cell.class === "xss" && cell.scope === "local"));
  });

  it("hydrates coverage/evidence rows to camelCase (testedBy, createdAt) on every read path", () => {
    const c = addCase({ title: "Hydration case" });
    recordCoverageResult(c.id, {
      asset: "a1",
      class: "sqli",
      scope: "wide",
      note: "first verdict",
      testedBy: "agent-1",
    });
    // A newer wide verdict for the same class must supersede the older one
    // when propagated (createdAt comparison needs the mapped field).
    recordCoverageResult(c.id, {
      asset: "a2",
      class: "sqli",
      scope: "wide",
      note: "NEWER verdict",
      testedBy: "agent-2",
    });
    recordCoverageResult(c.id, { asset: "a3", class: "xss", scope: "local", note: "none" });
    addEvidenceItemResult(c.id, { role: "observation", summary: "obs" });

    const summary = coverageSummary(c.id);
    const wide = summary.byAsset["a1"]![0];
    assert.strictEqual(wide.testedBy, "agent-1");
    assert.ok(wide.createdAt, "coverage cell createdAt hydrated");
    // Latest wide verdict wins (not the first recorded one).
    const a3sqli = summary.byAsset["a3"]!.find((cell) => cell.class === "sqli")!;
    assert.match(a3sqli.note, /NEWER verdict/);

    // Batch reads attach items to their case (fetchItemMap keyed on caseId).
    const viaBatch = readCasefile().find((r) => r.id === c.id)!;
    assert.strictEqual(viaBatch.coverageItems.length, 3);
    // addCase helper injects an observation fixture + the one we added.
    assert.strictEqual(viaBatch.evidenceItems.length, 2);
    const ev = viaBatch.evidenceItems.find((e) => e.summary === "obs")!;
    assert.strictEqual(ev.caseId, c.id);
    assert.ok(ev.createdAt);

    // Single-case read hydrates too.
    const viaSingle = getCaseById(c.id)!;
    assert.strictEqual(viaSingle.coverageItems[0].testedBy, "agent-1");
    assert.ok(viaSingle.evidenceItems[0].artifactPath === undefined);
  });

  it("suggests exploit chains from cases", () => {
    const cred = addCase({
      title: "Leaked API key in repo",
      status: "investigating",
      evidence: "Key in public repo",
      confidence: "high",
      impact: "credential exposure",
      severity: "high",
      target: "example-app",
    });
    const endpoint = addCase({
      title: "Admin login endpoint",
      status: "investigating",
      evidence: "Login accepts credentials",
      confidence: "high",
      impact: "auth",
      severity: "medium",
      target: "example-app",
    });

    const suggestions = suggestChains();
    const ato = suggestions.find((s) => s.pattern === "credential_endpoint");
    assert.ok(ato, "credential_endpoint chain suggested");
    assert.strictEqual(ato!.sourceId, cred.id);
    assert.strictEqual(ato!.targetId, endpoint.id);
    assert.strictEqual(ato!.confidence, 55); // neither confirmed

    // Only pairs on the same asset chain.
    const other = addCase({
      title: "XSS in unrelated-app",
      evidence: "reflected",
      target: "other-app",
    });
    const xssSuggestions = suggestChains(other.id).filter((s) => s.pattern === "xss_csrf");
    assert.strictEqual(xssSuggestions.length, 0);
  });

  it("does not pair unrelated targets whose names overlap as substrings", () => {
    // Regression: sameAssetOrRelated used a bare substring check, so
    // "myshop.io".includes("shop.io") paired two unrelated targets as one
    // asset and suggested a credential+endpoint chain between them.
    const cred = addCase({
      title: "Leaked API key in repo",
      status: "investigating",
      evidence: "Key in public repo",
      confidence: "high",
      impact: "credential exposure",
      severity: "high",
      target: "shop.io",
    });
    const endpoint = addCase({
      title: "Admin login endpoint",
      status: "investigating",
      evidence: "Login accepts credentials",
      confidence: "high",
      impact: "auth",
      severity: "medium",
      target: "myshop.io",
    });
    assert.strictEqual(suggestChains().length, 0, "no chain across unrelated targets");

    // Subdomain relation still pairs (label-boundary aware).
    const subCred = addCase({
      title: "Leaked token",
      status: "investigating",
      evidence: "Token in docs",
      confidence: "high",
      target: "api.example-app.com",
    });
    const subEndpoint = addCase({
      title: "Admin panel",
      status: "investigating",
      evidence: "Login accepts credentials",
      confidence: "high",
      target: "example-app.com",
    });
    const pair = suggestChains().filter((s) => s.sourceId === subCred.id);
    assert.ok(
      pair.some((s) => s.targetId === subEndpoint.id),
      "subdomain targets still pair",
    );
    assert.strictEqual(
      pair.some((s) => s.targetId === cred.id || s.targetId === endpoint.id),
      false,
    );
  });

  it("rejects field mutations on killed and reported cases", () => {
    const killed = addCase({
      title: "Dead lead",
      evidence: "not a vuln",
    });
    updateCaseResult(killed.id, {
      status: "killed",
      assumptions: ["intended_behavior: matches documented behavior"],
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
      target: "example-app",
      disconfirmation: "Checked if data is public by default; it is not.",
    });
    promoteFindingResult(live.id, {
      path: "/tmp/poc.sh",
      exitCode: 0,
      ranAt: "2024-01-01T00:00:00Z",
      sandbox: true,
    });
    // CaseContext records reportPath; the report writer then creates the file
    // (the confirmed→reported gate requires it on disk).
    const { path } = writeCaseContext(live.id);
    writeFileSync(path, "# Report\n", "utf8");
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

  it("writeCaseContext includes the disconfirmation attempt and verification log", () => {
    const record = addCase({
      title: "IDOR with disconfirmation",
      status: "investigating",
      evidence: "Observed sequential IDs",
      confidence: "medium",
      tags: ["pipeline-2026"],
      nextStep: "Chain with the export endpoint",
    });
    updateCaseResult(record.id, {
      confidence: "high",
      severity: "high",
      poc: "Request /exports/123 as another user",
      impact: "Unauthorized file disclosure",
      evidence: "Observed sequential IDs",
      target: "example-app",
      disconfirmation:
        "Attempted to access own export without auth; blocked. Only IDOR via session works.",
    });
    promoteFindingResult(record.id, {
      path: "/workspace/idor-poc.py",
      exitCode: 0,
      ranAt: "2024-01-01T00:00:00Z",
      sandbox: true,
    });

    // A chain step, linked in, so the context records the chain relationship.
    const chainStep = addCaseResult({
      title: "Chain: export endpoint leaks session token",
      status: "investigating",
      evidence: "Observed token in export response",
      confidence: "medium",
    });
    linkCasesResult(record.id, chainStep.record.id, "depends-on");
    linkCasesResult(chainStep.record.id, record.id, "related");

    // A scratchpad run that produced this case: recon map + trace output.
    setScratchpadRoot(tempDir);
    scratchpad_init("run-idor-2026", tempDir);
    scratchpad_checkpoint(
      "run-idor-2026",
      "recon",
      { ids: [record.id], summary: "surface mapped" },
      tempDir,
    );
    scratchpad_write(
      "run-idor-2026",
      "recon",
      "entry-points.md",
      "# Entry points\n- GET /exports/{id} (unauth probe observed)",
      tempDir,
    );
    // A SECOND run belonging to a different case must be excluded from the
    // bundle, plus a corrupt-state run dir that must be skipped, not crash.
    scratchpad_init("run-other-2026", tempDir);
    scratchpad_checkpoint(
      "run-other-2026",
      "recon",
      { ids: [chainStep.record.id], summary: "other surface" },
      tempDir,
    );
    scratchpad_write(
      "run-other-2026",
      "recon",
      "entry-points.md",
      "# OTHER run — must NOT appear in this context",
      tempDir,
    );
    const runDir = join(tempDir, ".scratchpad", "run-corrupt-2026");
    mkdirSync(runDir, { recursive: true });
    writeFileSync(join(runDir, "state.json"), "{ not json", "utf8");

    const { path, contextPath } = writeCaseContext(record.id);
    const context = readFileSync(contextPath, "utf8");
    // The context bundle carries the full audit trail…
    assert.ok(
      context.includes("## Disconfirmation Attempt"),
      "context must include the disconfirmation text section",
    );
    assert.ok(
      context.includes("Attempted to access own export without auth"),
      "context must include the disconfirmation body",
    );
    // …the complete record (every field, incl. tags/nextStep/timestamps)…
    assert.ok(context.includes("## Complete Case Record (all fields)"), "complete record section");
    assert.ok(context.includes("pipeline-2026"), "tags in complete record");
    assert.ok(context.includes("Chain with the export endpoint"), "nextStep in complete record");
    // …linked cases in both directions…
    assert.ok(context.includes("## Linked Cases"), "linked cases section");
    assert.ok(context.includes(chainStep.record.id), "chain-step case id in links");
    assert.ok(context.includes("depends-on"), "link kind in links");
    // …and the pipeline artifacts from the scratchpad run…
    assert.ok(context.includes("## Pipeline Artifacts"), "pipeline artifacts section");
    assert.ok(context.includes("run-idor-2026"), "scratchpad run id in context");
    assert.ok(context.includes("entry-points.md"), "recon artifact listed");
    assert.ok(context.includes("GET /exports/{id}"), "recon artifact content included");
    assert.ok(
      !context.includes("run-other-2026"),
      "other run's artifacts excluded (belongs to a different case)",
    );
    assert.ok(!context.includes("OTHER run"), "other run's artifact content excluded");
    // Path-leak guard: only the PoC basename, never the absolute path.
    assert.ok(context.includes("idor-poc.py"), "context must include the PoC script basename");
    assert.ok(
      !context.includes("/workspace/idor-poc.py"),
      "context must NOT leak the absolute PoC path",
    );
    // The report path is reserved for the reporter agent; the report file does
    // not exist until the reporter writes it.
    assert.ok(!existsSync(path), "report file not yet written (reporter writes it)");
  });

  it("writeCaseContext surfaces a run whose artifacts name the case even when phase_ids are empty", () => {
    const record = addCase({
      title: "Gate-by-filename",
      status: "investigating",
      evidence: "Observed leak",
      confidence: "medium",
    });
    updateCaseResult(record.id, {
      confidence: "high",
      severity: "medium",
      poc: "/tmp/gate-poc.sh",
      impact: "Token leak",
      evidence: "Observed leak",
      target: "example-app",
      disconfirmation: "Tried to disprove; could not.",
    });
    promoteFindingResult(record.id, {
      path: "/tmp/gate-poc.sh",
      exitCode: 0,
      ranAt: "2024-01-01T00:00:00Z",
      sandbox: true,
    });

    // Run checkpointed with NO ids (recon/hunt often record none), but the
    // artifact filename itself carries the case id — must still surface.
    setScratchpadRoot(tempDir);
    scratchpad_init("run-gate-2026", tempDir);
    scratchpad_checkpoint(
      "run-gate-2026",
      "skeptic",
      { ids: [], summary: "no ids recorded" },
      tempDir,
    );
    scratchpad_write(
      "run-gate-2026",
      "skeptic",
      `skeptic_${record.id}.json`,
      JSON.stringify({ finding_id: record.id, verdict: "CONFIRMED" }),
      tempDir,
    );

    const { contextPath } = writeCaseContext(record.id);
    const context = readFileSync(contextPath, "utf8");
    assert.ok(context.includes("## Pipeline Artifacts"), "pipeline artifacts section");
    assert.ok(context.includes("run-gate-2026"), "run included despite empty phase_ids");
    assert.ok(
      context.includes(`skeptic_${record.id}.json`),
      "artifact named after the case is surfaced",
    );
  });

  it("writeCaseContext rejects non-confirmed cases", () => {
    const hyp = addCase({ title: "Lead", status: "hypothesis", evidence: "x" });
    const inv = addCase({
      title: "Active",
      status: "investigating",
      evidence: "x",
      confidence: "low",
    });
    assert.throws(() => writeCaseContext(hyp.id), /confirmed or reported/i);
    assert.throws(() => writeCaseContext(inv.id), /confirmed or reported/i);

    const killed = addCaseResult({ title: "Dead", status: "hypothesis", evidence: "x" });
    updateCaseResult(killed.record.id, { status: "killed", assumptions: ["intended_behavior"] });
    assert.throws(() => writeCaseContext(killed.record.id), /confirmed or reported/i);
  });

  it("demoting confirmed → investigating clears both pocVerified and disconfirmationVerified", () => {
    const record = addCase({
      title: "Confirmed then demoted",
      status: "investigating",
      evidence: "repro steps",
      confidence: "high",
      impact: "data leak",
      severity: "high",
      poc: "/tmp/poc.sh",
      target: "example-app",
      disconfirmation: "Tried to disprove; could not.",
    });
    promoteFindingResult(
      record.id,
      { path: "/tmp/poc.sh", exitCode: 0, ranAt: "2024-01-01T00:00:00Z", sandbox: true },
      { path: "/tmp/disconfirm.sh", exitCode: 1, ranAt: "2024-01-01T00:00:00Z", sandbox: true },
      { path: "/tmp/control.sh", exitCode: 1, ranAt: "2024-01-01T00:00:00Z", sandbox: true },
    );
    const confirmed = readCasefile().find((c) => c.id === record.id)!;
    assert.ok(confirmed.pocVerified, "pocVerified set after promotion");
    assert.ok(confirmed.disconfirmationVerified, "disconfirmationVerified set after promotion");
    assert.ok(confirmed.controlVerified, "controlVerified set after promotion");

    // Demote back to investigating — both verification artifacts must be cleared.
    updateCaseResult(record.id, { status: "investigating" });
    const demoted = readCasefile().find((c) => c.id === record.id)!;
    assert.strictEqual(demoted.pocVerified, undefined, "pocVerified cleared on demotion");
    assert.strictEqual(
      demoted.disconfirmationVerified,
      undefined,
      "disconfirmationVerified cleared on demotion",
    );
    assert.strictEqual(demoted.controlVerified, undefined, "controlVerified cleared on demotion");
  });
});
