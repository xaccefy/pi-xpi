import assert from "node:assert";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, it } from "node:test";
import {
  addCaseResult,
  assertPromotable,
  getCasefilePath,
  linkCasesResult,
  promoteFindingResult,
  readCasefile,
  searchCases,
  setCasefilePath,
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
    );
    const confirmed = readCasefile().find((c) => c.id === record.id)!;
    assert.ok(confirmed.pocVerified, "pocVerified set after promotion");
    assert.ok(confirmed.disconfirmationVerified, "disconfirmationVerified set after promotion");

    // Demote back to investigating — both verification artifacts must be cleared.
    updateCaseResult(record.id, { status: "investigating" });
    const demoted = readCasefile().find((c) => c.id === record.id)!;
    assert.strictEqual(demoted.pocVerified, undefined, "pocVerified cleared on demotion");
    assert.strictEqual(
      demoted.disconfirmationVerified,
      undefined,
      "disconfirmationVerified cleared on demotion",
    );
  });
});
