import assert from "node:assert";
import { createHash } from "node:crypto";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  symlinkSync,
  utimesSync,
  writeFileSync,
} from "node:fs";
import { rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, it } from "node:test";
import type { ConfirmerVerdict, PoCEvidence } from "../src/evidence.ts";
import type { HarnessVerifyResult } from "../src/harness-verify.ts";
import {
  addEvidenceItemResult,
  applyConfirmationResult,
  assertPromotable,
  coverageSummary,
  getCaseById,
  getCasefilePath,
  addCaseResult as ledgerAddCaseResult,
  linkCasesResult,
  listEvidenceItems,
  type MainAgentVerification,
  type PendingConfirmation,
  POC_EVIDENCE_GC_GRACE_MS,
  type PocEvidenceRun,
  readCasefile,
  recordCoverageResult,
  searchCases,
  setCasefilePath,
  storePendingConfirmation,
  suggestChains,
  unlinkCasesResult,
  updateCaseResult,
  writeCaseContext,
} from "../src/ledger.ts";
import { suggestChainsAsync, writeCaseContextAsync } from "../src/ledger-worker.ts";
import {
  scratchpad_checkpoint,
  scratchpad_init,
  scratchpad_write,
  setScratchpadRoot,
} from "../src/scratchpad.ts";
import { DatabaseSync } from "../src/sqlite-compat/index.ts";

/** Writes the artifact file backing the helper observation evidence item. */
function observationArtifactPath(): string {
  const p = join(tempDir, "observation.txt");
  writeFileSync(p, "observed signal (fixture)", "utf8");
  return p;
}

const addCase = (input: Parameters<typeof ledgerAddCaseResult>[0]) => {
  const res = ledgerAddCaseResult({
    // New cases require falsification conditions; tests inject a default.
    disproveIf: ["test: finding is actually intended behavior"],
    ...input,
  });
  // Promotion requires an ARTIFACT-BACKED observation evidence item
  // (evidence-chain closure); tests inject one so fixtures focus on the
  // behavior they exercise.
  addEvidenceItemResult(res.record.id, {
    role: "observation",
    summary: "test fixture: initial observed signal",
    artifactPath: observationArtifactPath(),
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
    artifactPath: observationArtifactPath(),
  });
  return res;
};

/** Writes a REAL script file (same-file contract) and returns its path. */
function pocScriptPath(name = "poc.sh"): string {
  const safe = name.replace(/[^a-zA-Z0-9._-]/g, "_") || "poc.sh";
  const p = join(tempDir, safe);
  writeFileSync(p, "#!/bin/sh\necho ok\n", "utf8");
  return p;
}

/**
 * Seed the title corpus with heavy generic web-finding vocabulary on DISTINCT
 * targets. The near-dup IDF weights are computed over ALL live titles, so a
 * small test corpus (2-4 cases) cannot distinguish distinctive tokens from
 * corpus-wide ones — every shared token scores "rare" and the weighted half
 * of the hybrid gate degenerates back to raw count. Seeding mirrors the real
 * 30-case calibration: the generic core (xss / search / parameter / panel /
 * login / endpoint …) repeats across many titles → weight ≈ 0, and only
 * genuinely distinctive tokens keep a high weight.
 */
function seedCommonVocabulary(): void {
  const common = [
    "Reflected XSS in search parameter of admin panel",
    "Stored XSS in search parameter of user panel",
    "DOM XSS via search parameter in settings panel",
    "Reflected XSS in search parameter of login panel",
    "Blind XSS via search parameter in report panel",
    "Reflected XSS in search endpoint of admin page",
    "XSS in search parameter of export panel",
    "Stored XSS via search parameter in admin panel",
    "Reflected XSS in search parameter of profile panel",
    "XSS through search parameter in billing panel",
    "Rate limit missing on login endpoint",
    "Directory traversal in file download endpoint",
  ];
  for (let i = 0; i < common.length; i++) {
    ledgerAddCaseResult({
      title: common[i],
      target: `filler-${i}.test`,
      evidence: "probe",
      disproveIf: ["test: finding is actually intended behavior"],
    });
  }
}

/** Writes a report file that passes the content gate (size + sections + no internal identifiers). */
function writeGoodReport(reportPath: string): void {
  writeFileSync(
    reportPath,
    `# Stored XSS in chat\n\n## Summary\nReflected input is rendered without encoding, allowing script execution.\n\n## Vulnerability Details\nThe search endpoint reflects the query parameter into the page.\n\n## Steps to Reproduce\n1. Submit a payload.\n2. Observe execution.\n\n## Impact\nAn attacker can execute script in a victim's session and steal tokens.\n\n## Remediation\nEncode output at the sink; add a CSP.\n`,
    "utf8",
  );
}

/** Default disconfirmation prose is gone — the main agent's attempt becomes it. */
const sha256hex = (s: string) => createHash("sha256").update(s).digest("hex");

function makeEvidence(
  nonce: string,
  contains: string[] = ["root:"],
  claim = "read /etc/passwd of target",
  target = "target.test",
): PoCEvidence {
  const origin = /^https?:\/\//i.test(target) ? new URL(target).origin : `http://${target}`;
  return {
    nonce,
    claim,
    verify: {
      method: "GET",
      url: `${origin}/read?file=/etc/passwd`,
      expect: { status: [200], body_contains: contains },
    },
    observations: ["response body contains the claimed entry"],
  };
}

function evidenceRun(
  mode: "poc" | "control",
  target: string,
  nonce: string,
  evidence: PoCEvidence,
  overrides: Partial<PocEvidenceRun> = {},
): PocEvidenceRun {
  return {
    mode,
    target,
    nonce,
    ranAt: new Date().toISOString(),
    exitCode: 0,
    sandbox: true,
    completed: true,
    outputComplete: true,
    output: `${mode} output`,
    evidence,
    evidenceSha256: sha256hex(JSON.stringify(evidence)),
    ...overrides,
  };
}

/**
 * Standard confirmation fixture: a pending bundle with two deterministic
 * target runs and a DIFFERING control run (target-only differential), plus a
 * complete CONFIRMED verdict. The control is the SAME file as the PoC by
 * default (same-file contract).
 */
function pendingBundle(
  id: string,
  opts: {
    pocPath?: string;
    controlPath?: string;
    targetEvidence?: PoCEvidence;
    secondTargetEvidence?: PoCEvidence;
    controlEvidence?: PoCEvidence;
    controlTarget?: string;
    bundleRanAt?: string;
    pocSha256?: string;
  } = {},
): PendingConfirmation & { controlRun: PocEvidenceRun } {
  const target = getCaseById(id)?.target ?? "target";
  const pocPath = opts.pocPath ?? pocScriptPath("poc.sh");
  const controlPath = opts.controlPath ?? pocPath; // same file by default
  const controlTarget = opts.controlTarget ?? "control.test";
  const n1 = "nonce-target-1";
  const n2 = "nonce-target-2";
  const nc = "nonce-control";
  const tEv =
    opts.targetEvidence ?? makeEvidence(n1, ["root:"], "read /etc/passwd of target", target);
  const cEv =
    opts.controlEvidence ??
    makeEvidence(nc, ["no-such-entry"], "control lacks the vuln", controlTarget);
  const targetRuns: [PocEvidenceRun, PocEvidenceRun] = [
    evidenceRun("poc", target, n1, tEv),
    evidenceRun(
      "poc",
      target,
      n2,
      opts.secondTargetEvidence ??
        makeEvidence(n2, ["root:"], "read /etc/passwd of target", target),
    ),
  ];
  const controlRun = evidenceRun("control", controlTarget, nc, cEv);
  const durableDir = join(tempDir, ".pi", "poc-evidence");
  mkdirSync(durableDir, { recursive: true });
  for (const run of [...targetRuns, controlRun]) {
    const evidencePath = join(durableDir, `${run.nonce}.evidence.json`);
    writeFileSync(evidencePath, JSON.stringify(run.evidence), "utf8");
    run.evidencePath = evidencePath;
  }
  return {
    caseId: id,
    ranAt: opts.bundleRanAt ?? new Date().toISOString(),
    pocPath,
    pocSha256: opts.pocSha256 ?? sha256hex(readFileSync(pocPath, "utf8")),
    controlPath,
    controlTarget,
    targetRuns,
    controlRun,
    harnessVerified: {
      attempted: true,
      pass: true,
      status: 200,
      differential: "target_only",
      target: {
        attempted: true,
        matched: true,
        status: 200,
        url: tEv.verify.url,
        note: "fixture target matched",
      },
      control: {
        attempted: true,
        matched: false,
        status: 404,
        url: cEv.verify.url,
        note: "fixture control did not match",
      },
      note: "fixture harness differential target_only",
    },
  };
}

function makeVerdict(overrides: Partial<ConfirmerVerdict> = {}): ConfirmerVerdict {
  return {
    verdict: "CONFIRMED",
    reasoning: "re-sent the verify request: target returned the claimed entry, control did not",
    evidence_reviewed: ["evidence.json (target run 1)", "evidence.json (control run)"],
    re_execution_note: "GET /read?file=/etc/passwd → 200 with root: on target; 403 on control",
    differential: "target_only",
    severity_match: "ok",
    disconfirmation_attempt:
      "tried /read?file=/etc/shadow and a patched replica → no entry; the effect is target-dependent",
    canary_assessment: "not_applicable",
    canary_reason: "file-read output is fixed target state and has no attacker-reflected field",
    model: "test-model",
    ...overrides,
  };
}

function freshMainAgentVerification(id: string): MainAgentVerification {
  const bundle = getCaseById(id)?.pendingConfirmation;
  assert.ok(bundle, "pending confirmation fixture exists");
  assert.ok(bundle.harnessVerified, "phase-1 harness fixture exists");
  return {
    at: new Date().toISOString(),
    result: bundle.harnessVerified,
  };
}

/** Phase 1 + phase 2 in one call for happy-path fixtures. */
function promote(
  id: string,
  opts: { verdict?: ConfirmerVerdict; bundle?: PendingConfirmation } = {},
): ReturnType<typeof applyConfirmationResult> {
  storePendingConfirmation(id, opts.bundle ?? pendingBundle(id));
  return applyConfirmationResult(id, opts.verdict ?? makeVerdict(), freshMainAgentVerification(id));
}

let tempDir: string;
let ledgerPath: string;

beforeEach(async () => {
  tempDir = mkdtempSync(join(tmpdir(), "casefile-test-"));
  ledgerPath = join(tempDir, "casefile.db");
  process.env.CASEFILE_WORKSPACE_ROOT = tempDir;
  setCasefilePath(ledgerPath);
});

afterEach(async () => {
  setCasefilePath(undefined);
  setScratchpadRoot(undefined);
  delete process.env.CASEFILE_WORKSPACE_ROOT;
  await rm(tempDir, { recursive: true, force: true });
});

describe("casefile sqlite ledger", () => {
  it("garbage-collects only old, unreferenced harness evidence", () => {
    const record = addCase({ title: "Evidence GC fixture" });
    const evidenceDir = join(tempDir, ".pi", "poc-evidence");
    mkdirSync(evidenceDir, { recursive: true });
    const referenced = join(evidenceDir, "referenced.evidence.json");
    const pending = join(evidenceDir, "pending.evidence.json");
    const orphan = join(evidenceDir, "orphan.evidence.json");
    const young = join(evidenceDir, "young.evidence.json");
    for (const path of [referenced, pending, orphan, young]) {
      writeFileSync(path, JSON.stringify({ fixture: path }), "utf8");
    }
    addEvidenceItemResult(record.id, {
      role: "cleanup",
      summary: "protect referenced durable evidence",
      artifactPath: referenced,
    });

    // Seed a pending-bundle reference directly: this test exercises GC's
    // conservative path discovery, not confirmation-bundle validation.
    setCasefilePath(undefined);
    const raw = new DatabaseSync(ledgerPath);
    raw
      .prepare("UPDATE cases SET pending_confirmation_json = ? WHERE id = ?")
      .run(JSON.stringify({ targetRuns: [{ evidencePath: pending }], controlRun: {} }), record.id);
    raw.close();

    const old = new Date(Date.now() - POC_EVIDENCE_GC_GRACE_MS - 60_000);
    for (const path of [referenced, pending, orphan]) utimesSync(path, old, old);

    // Reopening runs the best-effort sweep.
    setCasefilePath(ledgerPath);
    readCasefile();
    assert.ok(existsSync(referenced), "ledger evidence item remains protected");
    assert.ok(existsSync(pending), "pending confirmation evidence remains protected");
    assert.ok(!existsSync(orphan), "old orphan is removed");
    assert.ok(existsSync(young), "recent orphan remains inside the grace window");
  });

  it("rejects a symlinked casefile database", () => {
    const outside = mkdtempSync(join(tmpdir(), "casefile-db-outside-"));
    try {
      const victim = join(outside, "victim.db");
      writeFileSync(victim, "operator data", "utf8");
      symlinkSync(victim, ledgerPath);

      assert.throws(() => readCasefile(), /regular, non-symlink file/);
      assert.strictEqual(readFileSync(victim, "utf8"), "operator data");
    } finally {
      rmSync(outside, { recursive: true, force: true });
    }
  });

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
    // Seed generic vocabulary first so the distinctive tokens are corpus-rare
    // (the IDF weights would otherwise see every shared token as "rare" in a
    // 2-case corpus and the weighted gate degenerates to raw count).
    seedCommonVocabulary();
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
    seedCommonVocabulary();
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

  it("near-dup boundary: 2 shared tokens or common-vocabulary overlap does NOT fire; 3 distinctive fires", () => {
    // Distinctive tokens only (stopwords are suppressed): alpha/bravo/… are
    // made-up 5+ char words so the counts are exact. Seed the corpus so the
    // made-up tokens are corpus-rare — otherwise the IDF-weighted half of the
    // hybrid gate cannot down-weight anything.
    seedCommonVocabulary();
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

    // Exactly 3 shared distinctive tokens (alpha, bravo, charlie) → near-duplicate.
    const three = addCaseResult({
      title: "alpha bravo charlie foxtrot",
      target: "boundary.test",
      evidence: "probe",
    });
    assert.strictEqual(three.created, false);
    assert.match(three.reason ?? "", /near-duplicate/i);

    // The weighted half of the gate must NOT be vacuous: 3+ shared tokens that
    // are corpus-COMMON (the seeded generic vocabulary) must NOT merge. This
    // is the false-merge the IDF weighting exists to prevent.
    const panelA = addCaseResult({
      title: "Reflected XSS via search parameter in admin panel",
      target: "boundary.test",
      evidence: "probe",
    });
    assert.strictEqual(panelA.created, true);
    const panelB = addCaseResult({
      title: "Reflected XSS via search parameter in user panel",
      target: "boundary.test",
      evidence: "probe",
    });
    assert.strictEqual(panelB.created, true);
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
    promote(original.id);
    const { path } = writeCaseContext(original.id);
    writeGoodReport(path);
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

    const promoted = promote(record.id);
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
    // Refutation evidence item also passes (must be artifact-backed now —
    // prose-only refutation cannot justify a kill).
    const refuted = addCase({ title: "Kill with refutation evidence" });
    addEvidenceItemResult(refuted.id, {
      role: "refutation",
      summary: "Re-probe returned 403 with the same payload; path is WAF-blocked.",
      artifactPath: observationArtifactPath(),
    });
    const killed2 = updateCaseResult(refuted.id, {
      status: "killed",
      nextStep: "killed: refutation evidence — WAF-blocked re-probe",
    });
    assert.strictEqual(killed2.record.status, "killed");
  });

  it("requires refutation evidence to kill a case that reached investigating/confirmed", () => {
    const investigating = addCase({
      title: "Advanced case",
      status: "investigating",
      evidence: "Reflected input observed",
      confidence: "medium",
    });
    // A keyword in free text is NOT enough once the case left hypothesis.
    assert.throws(
      () =>
        updateCaseResult(investigating.id, {
          status: "killed",
          assumptions: ["out_of_scope: not in program scope"],
        }),
      /refutation evidence/,
    );
    // A refutation evidence item (artifact-backed) makes the kill valid.
    addEvidenceItemResult(investigating.id, {
      role: "refutation",
      summary: "Re-probe: the sink is WAF-blocked; payload never reaches it.",
      artifactPath: observationArtifactPath(),
    });
    const killed = updateCaseResult(investigating.id, { status: "killed" });
    assert.strictEqual(killed.record.status, "killed");

    // A CONFIRMED case is the same: refutation evidence required, keyword alone
    // insufficient.
    const confirmed = addCase({
      title: "Confirmed case",
      status: "investigating",
      evidence: "Observed leak",
      confidence: "high",
      impact: "data leak",
      severity: "high",
      poc: "/tmp/poc.sh",
      target: "example-app",
      disconfirmation: "Tried; could not disprove.",
    });
    promote(confirmed.id);
    assert.strictEqual(readCasefile().find((c) => c.id === confirmed.id)?.status, "confirmed");
    assert.throws(
      () => updateCaseResult(confirmed.id, { status: "killed", nextStep: "not_applicable" }),
      /refutation evidence/,
    );
    addEvidenceItemResult(confirmed.id, {
      role: "refutation",
      summary: "Re-test after patch: path no longer reachable.",
      artifactPath: observationArtifactPath(),
    });
    const killedConfirmed = updateCaseResult(confirmed.id, { status: "killed" });
    assert.strictEqual(killedConfirmed.record.status, "killed");
  });

  it("confirmation requires a pending bundle and a complete verdict", () => {
    const rec = addCase({
      title: "High severity IDOR",
      status: "investigating",
      evidence: "Observed other user's data",
      confidence: "high",
      impact: "data leak",
      severity: "high",
      poc: "/tmp/poc.sh",
      target: "example-app",
    });
    // No pending bundle yet -> the verdict cannot be applied at all.
    assert.throws(() => applyConfirmationResult(rec.id, makeVerdict()), /No pending confirmation/);

    // Phase 1 first: the verdict only ever applies to a stored bundle.
    storePendingConfirmation(rec.id, pendingBundle(rec.id));

    // NOT_CONFIRMED works without the CONFIRMED-only fields (they are only
    // validated on a CONFIRMED verdict) — a refusal needs no disconfirmation.
    const refused = applyConfirmationResult(
      rec.id,
      makeVerdict({
        verdict: "NOT_CONFIRMED",
        differential: "unclear",
        disconfirmation_attempt: undefined,
      }),
    );
    assert.strictEqual(refused.record.status, "investigating");

    // CONFIRMED requires a disconfirmation attempt, a target-only differential,
    // a concrete review note, and a fresh harness replay. A verdict missing
    // any of these is rejected. A
    // NOT_CONFIRMED attempt above already recorded a verdict; re-store a fresh
    // bundle so the CONFIRMED path has one to commit against.
    storePendingConfirmation(rec.id, pendingBundle(rec.id));
    assert.throws(
      () => applyConfirmationResult(rec.id, makeVerdict({ disconfirmation_attempt: undefined })),
      /disconfirmation_attempt/,
    );
    assert.throws(
      () => applyConfirmationResult(rec.id, makeVerdict({ differential: "both" })),
      /target_only/,
    );
    assert.throws(
      () => applyConfirmationResult(rec.id, makeVerdict({ differential: "control_only" })),
      /target_only/,
    );
    assert.throws(
      () => applyConfirmationResult(rec.id, makeVerdict({ re_execution_note: undefined })),
      /re_execution_note/,
    );
    assert.throws(
      () => applyConfirmationResult(rec.id, makeVerdict()),
      /MAIN-AGENT REPLAY REQUIRED/,
    );
    const misboundReplay = freshMainAgentVerification(rec.id);
    if (misboundReplay.result.target) {
      misboundReplay.result = {
        ...misboundReplay.result,
        target: { ...misboundReplay.result.target, url: "https://unrelated.test/proof" },
      };
    }
    assert.throws(
      () => applyConfirmationResult(rec.id, makeVerdict(), misboundReplay),
      /target transcript is not bound/,
    );
    // A complete CONFIRMED verdict promotes.
    const ok = applyConfirmationResult(rec.id, makeVerdict(), freshMainAgentVerification(rec.id));
    assert.strictEqual(ok.record.status, "confirmed");
  });

  it("kill gate cannot be bypassed by demoting to hypothesis first (round-trip)", () => {
    const rec = addCase({
      title: "Round-trip kill",
      status: "investigating",
      evidence: "observed leak",
      confidence: "high",
    });
    // Demotion is legal, but the case has EVER reached investigating — the
    // refutation gate must fire on the kill even from hypothesis.
    updateCaseResult(rec.id, { status: "hypothesis" });
    assert.throws(
      () => updateCaseResult(rec.id, { status: "killed", nextStep: "out_of_scope" }),
      /refutation evidence/,
    );
    // Artifact-backed refutation evidence unblocks the kill.
    addEvidenceItemResult(rec.id, {
      role: "refutation",
      summary: "Re-test after patch: path no longer reachable.",
      artifactPath: observationArtifactPath(),
    });
    const killed = updateCaseResult(rec.id, { status: "killed", nextStep: "out_of_scope" });
    assert.strictEqual(killed.record.status, "killed");
  });

  it("hypothesis-stage kills accept natural-language reasons (spaced forms)", () => {
    // The kill vocabulary is machine tokens (out_of_scope); free text must not
    // be rejected just because it reads naturally.
    const rec = addCase({ title: "Plain hypothesis", status: "hypothesis" });
    const killed = updateCaseResult(rec.id, {
      status: "killed",
      nextStep: "out of scope per the program scope table",
    });
    assert.strictEqual(killed.record.status, "killed");
  });

  it("confirm-time rejects a case whose target changed since the PoC runs", () => {
    const rec = addCase({
      title: "Target drift",
      status: "investigating",
      evidence: "observed leak",
      confidence: "high",
      impact: "data leak",
      severity: "high",
      poc: "/tmp/poc.sh",
      target: "host-a",
    });
    storePendingConfirmation(rec.id, pendingBundle(rec.id)); // bundle ran against host-a
    // Swap the target between phase 1 and phase 2 — the evidence proves
    // nothing about the new target.
    updateCaseResult(rec.id, { target: "host-b" });
    assert.throws(
      () => applyConfirmationResult(rec.id, makeVerdict()),
      /changed since the PoC runs/,
    );
  });

  it("store rejects a bundle whose control run targeted the wrong host", () => {
    const rec = addCase({
      title: "Control binding",
      status: "investigating",
      evidence: "observed leak",
      confidence: "high",
      target: "host-a",
    });
    const bundle = pendingBundle(rec.id);
    bundle.controlRun.target = "somewhere-else"; // ≠ controlTarget
    assert.throws(() => storePendingConfirmation(rec.id, bundle), /CONTROL BINDING FAILED/);
    // Control run against the SAME host as the target runs is equally dead.
    const same = pendingBundle(rec.id);
    same.controlRun.target = same.targetRuns[0].target;
    assert.throws(() => storePendingConfirmation(rec.id, same), /CONTROL BINDING FAILED/);
    // control_target equal to the case target proves nothing.
    const equalsCase = pendingBundle(rec.id, { controlTarget: "host-a" });
    assert.throws(() => storePendingConfirmation(rec.id, equalsCase), /CONTROL BINDING FAILED/);
  });

  it("store rejects a bundle whose harness verify replay failed", () => {
    const rec = addCase({
      title: "Harness replay gate",
      status: "investigating",
      evidence: "observed leak",
      confidence: "high",
      impact: "data leak",
      severity: "high",
      poc: "/tmp/poc.sh",
      target: "host-a",
    });
    const bundle = pendingBundle(rec.id);
    bundle.harnessVerified = {
      attempted: true,
      pass: false,
      status: 200,
      note: "harness replayed the verify request — body_contains missing: root:",
    };
    assert.throws(() => storePendingConfirmation(rec.id, bundle), /HARNESS DIFFERENTIAL FAILED/);
  });

  it("store rejects a skipped harness replay (private targets fail closed)", () => {
    const rec = addCase({
      title: "Private target replay skip",
      status: "investigating",
      evidence: "observed leak",
      confidence: "high",
      impact: "data leak",
      severity: "high",
      poc: "/tmp/poc.sh",
      target: "10.0.0.5",
    });
    const bundle = pendingBundle(rec.id);
    bundle.harnessVerified = {
      attempted: false,
      note: "skipped: 127.0.0.1 is a private/internal host — main-agent review cannot bypass the machine gate",
    };
    assert.throws(() => storePendingConfirmation(rec.id, bundle), /HARNESS DIFFERENTIAL FAILED/);
  });

  it("store rejects an OOB-verified bundle with zero target-token hits", () => {
    const rec = addCase({
      title: "OOB silent target",
      status: "investigating",
      evidence: "observed SSRF",
      confidence: "high",
      impact: "internal fetch",
      severity: "high",
      poc: "/tmp/poc.sh",
      target: "host-a",
    });
    const bundle = pendingBundle(rec.id);
    bundle.callbackVerified = {
      attempted: true,
      targetHits: 0,
      controlHits: 0,
      note: "listener logged 0 interactions",
    };
    assert.throws(() => storePendingConfirmation(rec.id, bundle), /OOB VERIFY FAILED/);
  });

  it("store rejects an OOB-verified bundle whose control token was hit", () => {
    const rec = addCase({
      title: "OOB self-caller",
      status: "investigating",
      evidence: "observed SSRF",
      confidence: "high",
      impact: "internal fetch",
      severity: "high",
      poc: "/tmp/poc.sh",
      target: "host-a",
    });
    const bundle = pendingBundle(rec.id);
    bundle.callbackVerified = {
      attempted: true,
      targetHits: 1,
      controlHits: 1,
      note: "listener logged 2 interactions",
    };
    assert.throws(() => storePendingConfirmation(rec.id, bundle), /OOB VERIFY FAILED/);
  });

  it("store rejects loopback OOB telemetry without source separation", () => {
    const rec = addCase({
      title: "OOB self-call boundary",
      status: "investigating",
      evidence: "observed SSRF",
      confidence: "high",
      impact: "internal fetch",
      severity: "high",
      poc: "/tmp/poc.sh",
      target: "host-a",
    });
    const bundle = pendingBundle(rec.id);
    bundle.callbackVerified = {
      attempted: true,
      targetHits: 1,
      controlHits: 0,
      sourceSeparated: false,
      note: "loopback listener logged one target-token interaction",
    };
    assert.throws(() => storePendingConfirmation(rec.id, bundle), /source separation/i);
  });

  it("reproduction evidence item is backed by the preserved evidence file", () => {
    const rec = addCase({
      title: "Preserved evidence",
      status: "investigating",
      evidence: "observed leak",
      confidence: "high",
      impact: "data leak",
      severity: "high",
      poc: "/tmp/poc.sh",
      target: "host-a",
    });
    const bundle = pendingBundle(rec.id);
    // The runner preserves each evidence.json into .pi/poc-evidence/; the
    // reproduction item must reference that surviving copy, not a temp file.
    storePendingConfirmation(rec.id, bundle);
    const confirmed = applyConfirmationResult(
      rec.id,
      makeVerdict(),
      freshMainAgentVerification(rec.id),
    );
    assert.strictEqual(confirmed.record.status, "confirmed");
    const repro = listEvidenceItems(rec.id).find((e) => e.role === "reproduction");
    assert.ok(repro, "reproduction item recorded");
    assert.match(repro!.artifactPath ?? "", /\.evidence\.json$/);
    assert.strictEqual(repro!.sha256, bundle.targetRuns[0].evidenceSha256);
  });

  it("rejects missing or tampered durable PoC evidence", () => {
    const rec = addCase({
      title: "Durable PoC evidence binding",
      status: "investigating",
      evidence: "observed leak",
      confidence: "high",
      impact: "data leak",
      severity: "high",
      poc: "/tmp/poc.sh",
      target: "host-a",
    });
    const missing = pendingBundle(rec.id);
    missing.targetRuns[0].evidencePath = undefined;
    assert.throws(
      () => storePendingConfirmation(rec.id, missing),
      /ephemeral evidence cannot confirm/,
    );

    const tampered = pendingBundle(rec.id);
    const evidencePath = tampered.targetRuns[0].evidencePath;
    assert.ok(evidencePath);
    writeFileSync(evidencePath, '{"tampered":true}', "utf8");
    assert.throws(() => storePendingConfirmation(rec.id, tampered), /hash does not match/);
  });

  it("expires stale pending confirmations (1h TTL)", () => {
    const rec = addCase({
      title: "Stale bundle",
      status: "investigating",
      evidence: "observed",
      confidence: "high",
      impact: "leak",
      severity: "medium",
      poc: "/tmp/poc.sh",
      target: "example-app",
    });
    const stale = pendingBundle(rec.id, {
      bundleRanAt: new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString(),
    });
    storePendingConfirmation(rec.id, stale);
    assert.throws(() => applyConfirmationResult(rec.id, makeVerdict()), /expired/);
  });

  it("rejects a phase-2 ledger commit from a worker process", () => {
    const rec = addCase({
      title: "Worker cannot commit",
      status: "investigating",
      evidence: "observed",
      confidence: "high",
      impact: "leak",
      severity: "medium",
      poc: "/tmp/poc.sh",
      target: "example-app",
    });
    storePendingConfirmation(rec.id, pendingBundle(rec.id));
    process.env.PI_SUBAGENT_CHILD = "1";
    const startupAuthority = { startedAsSubagent: true };
    delete process.env.PI_SUBAGENT_CHILD;
    try {
      assert.throws(
        () => applyConfirmationResult(rec.id, makeVerdict(), undefined, startupAuthority),
        /reserved for the main\/coordinator agent/,
      );
    } finally {
      delete process.env.PI_SUBAGENT_CHILD;
    }
    assert.strictEqual(getCaseById(rec.id)?.status, "investigating");
  });

  it("NOT_CONFIRMED records the verdict, keeps investigating, and allows a fresh attempt", () => {
    const rec = addCase({
      title: "Refused then confirmed",
      status: "investigating",
      evidence: "observed",
      confidence: "high",
      impact: "leak",
      severity: "medium",
      poc: "/tmp/poc.sh",
      target: "example-app",
    });
    storePendingConfirmation(rec.id, pendingBundle(rec.id));
    const refused = applyConfirmationResult(
      rec.id,
      makeVerdict({
        verdict: "NOT_CONFIRMED",
        differential: "unclear",
        disconfirmation_attempt: undefined,
      }),
    );
    assert.strictEqual(refused.record.status, "investigating");
    assert.strictEqual(refused.record.confirmerVerdict?.verdict, "NOT_CONFIRMED");
    assert.strictEqual(refused.record.confirmerVerdict?.reviewer, "main_agent");
    assert.strictEqual(refused.record.pendingConfirmation, undefined);
    assert.ok(refused.record.assumptions?.some((a) => a.includes("NOT_CONFIRMED")));
    assert.strictEqual(refused.record.pocVerified, undefined);
    // A second, successful attempt after a fresh phase 1.
    storePendingConfirmation(rec.id, pendingBundle(rec.id));
    const ok = applyConfirmationResult(rec.id, makeVerdict(), freshMainAgentVerification(rec.id));
    assert.strictEqual(ok.record.status, "confirmed");
  });

  it("promotion records evidence, verdict, and reproduction item; clears the pending bundle", () => {
    const rec = addCase({
      title: "Happy path records",
      status: "investigating",
      evidence: "observed",
      confidence: "high",
      impact: "leak",
      severity: "medium",
      poc: "/tmp/poc.sh",
      target: "example-app",
    });
    const bundle = pendingBundle(rec.id);
    storePendingConfirmation(rec.id, bundle);
    const ok = applyConfirmationResult(rec.id, makeVerdict(), freshMainAgentVerification(rec.id));
    assert.strictEqual(ok.record.status, "confirmed");
    const confirmed = getCaseById(rec.id)!;
    assert.strictEqual(confirmed.pendingConfirmation, undefined, "pending bundle cleared");
    assert.strictEqual(confirmed.disconfirmation, makeVerdict().disconfirmation_attempt);
    assert.strictEqual(confirmed.pocVerified?.mode, "poc");
    assert.strictEqual(confirmed.pocVerified?.target, "example-app");
    assert.strictEqual(confirmed.controlVerified?.mode, "control");
    assert.strictEqual(confirmed.confirmerVerdict?.verdict, "CONFIRMED");
    assert.strictEqual(confirmed.confirmerVerdict?.model, "test-model");
    assert.strictEqual(confirmed.confirmerVerdict?.reviewer, "main_agent");
    assert.strictEqual(
      confirmed.confirmerVerdict?.phase2Verification?.result.differential,
      "target_only",
    );
    const repro = listEvidenceItems(rec.id).find((e) => e.role === "reproduction");
    assert.ok(repro, "reproduction item recorded");
    assert.strictEqual(repro!.sha256, bundle.targetRuns[0].evidenceSha256);
    assert.match(repro!.artifactPath ?? "", /\.evidence\.json$/);
  });

  it("records canary-differential strength only for a machine-observed target-only canary", () => {
    const rec = addCase({
      title: "Reflected canary proof",
      status: "investigating",
      evidence: "target reflected attacker-controlled marker",
      confidence: "high",
      severity: "medium",
      poc: "send marker and compare target/control",
      impact: "attacker-controlled reflection",
      target: "target.test",
    });
    const bundle = pendingBundle(rec.id);
    for (const run of [...bundle.targetRuns, bundle.controlRun]) {
      run.evidence.verify.url += "&marker={{PI_POC_CANARY}}";
      run.evidence.verify.canary = {
        mode: "reflection",
        placeholder: "{{PI_POC_CANARY}}",
      };
      run.evidenceSha256 = sha256hex(JSON.stringify(run.evidence));
      assert.ok(run.evidencePath);
      writeFileSync(run.evidencePath, JSON.stringify(run.evidence), "utf8");
    }
    bundle.harnessVerified = {
      ...(bundle.harnessVerified as HarnessVerifyResult),
      canary: {
        mode: "reflection",
        attempted: true,
        pass: true,
        tokenSha256: "a".repeat(64),
        targetObserved: true,
        controlObserved: false,
        note: "fixture target-only canary",
      },
      proofStrength: "canary_differential",
    };
    storePendingConfirmation(rec.id, bundle);
    const confirmed = applyConfirmationResult(
      rec.id,
      makeVerdict({
        canary_assessment: "verified",
        canary_reason: undefined,
      }),
      freshMainAgentVerification(rec.id),
    ).record;
    assert.strictEqual(confirmed.confirmerVerdict?.proofStrength, "canary_differential");
    assert.strictEqual(confirmed.confirmerVerdict?.phase2Verification?.result.canary?.pass, true);
  });

  it("links coverage cells to artifact-backed evidence items and rejects bogus links", () => {
    const c = addCase({ title: "Coverage backing" });
    const ev = addEvidenceItemResult(c.id, {
      role: "observation",
      summary: "probe log",
      artifactPath: observationArtifactPath(),
    });
    const backed = recordCoverageResult(c.id, {
      asset: "example-app",
      class: "sqli",
      scope: "local",
      note: "payloads on all params; no injection",
      evidenceItemId: ev.id,
    });
    assert.strictEqual(backed.evidenceItemId, ev.id);
    // The linkage survives persistence (re-read from the ledger).
    assert.strictEqual(coverageSummary(c.id).items[0].evidenceItemId, ev.id);

    // A summary-only evidence item cannot back a cell (no sha256).
    const prose = addEvidenceItemResult(c.id, { role: "observation", summary: "prose only" });
    assert.throws(
      () =>
        recordCoverageResult(c.id, {
          asset: "a",
          class: "xss",
          scope: "local",
          note: "no reflection",
          evidenceItemId: prose.id,
        }),
      /artifact-backed/,
    );
    // An item from ANOTHER case cannot back this cell.
    const other = addCase({ title: "Other case" });
    const otherEv = addEvidenceItemResult(other.id, {
      role: "observation",
      summary: "other",
      artifactPath: observationArtifactPath(),
    });
    assert.throws(
      () =>
        recordCoverageResult(c.id, {
          asset: "a",
          class: "xss",
          scope: "local",
          note: "no reflection",
          evidenceItemId: otherEv.id,
        }),
      /not found on this case/,
    );
    // Unbacked cells are allowed but flagged (no evidenceItemId) — CoverageReport
    // renders them distinctly as unbacked.
    const unbacked = recordCoverageResult(c.id, {
      asset: "a",
      class: "ssti",
      scope: "local",
      note: "no reflection",
    });
    assert.strictEqual(unbacked.evidenceItemId, undefined);
  });

  it("near-dup redirect surfaces the existing case title (no silent drop)", () => {
    seedCommonVocabulary();
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
    assert.strictEqual(rephrased.nearDuplicate, true);
    assert.match(rephrased.reason ?? "", /Near-duplicate of existing case/);
    // The drop is NOT silent: the existing case's title is surfaced so the
    // agent can decide whether the merge is right.
    assert.ok((rephrased.reason ?? "").includes(first.record.title));
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
    // Durable copy: the artifact bytes survive in <ledger-dir>/evidence-items/
    // keyed by the sha256 (artifact_path itself stays a basename — path-leak
    // guard). The hash must stay re-verifiable after the source file is gone.
    const durable = join(tempDir, "evidence-items", `${item.sha256}.bin`);
    assert.ok(existsSync(durable), `durable copy missing at ${durable}`);
    assert.strictEqual(readFileSync(durable, "utf8"), "HTTP/1.1 200 OK\nsecret-data");
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

  it("keeps evidence artifact reads inside the workspace and rejects symlinks", () => {
    const c = ledgerAddCaseResult({
      title: "Evidence containment",
      disproveIf: ["test: finding is actually intended behavior"],
    }).record;
    const outsideDir = mkdtempSync(join(tmpdir(), "casefile-outside-"));
    try {
      const outside = join(outsideDir, "secret.txt");
      writeFileSync(outside, "must not be imported", "utf8");
      assert.throws(
        () =>
          addEvidenceItemResult(c.id, {
            role: "observation",
            summary: "outside file",
            artifactPath: outside,
          }),
        /must stay inside the workspace/,
      );

      const linked = join(tempDir, "linked-secret.txt");
      symlinkSync(outside, linked);
      assert.throws(
        () =>
          addEvidenceItemResult(c.id, {
            role: "observation",
            summary: "symlink file",
            artifactPath: linked,
          }),
        /must not be a symbolic link/,
      );
      assert.strictEqual(listEvidenceItems(c.id).length, 0);
    } finally {
      rmSync(outsideDir, { recursive: true, force: true });
    }
  });

  it("rejects a symlinked durable evidence store", () => {
    const c = ledgerAddCaseResult({
      title: "Durable evidence containment",
      disproveIf: ["test: finding is actually intended behavior"],
    }).record;
    const artifact = join(tempDir, "probe.txt");
    writeFileSync(artifact, "verified bytes", "utf8");
    const outside = mkdtempSync(join(tmpdir(), "casefile-evidence-outside-"));
    try {
      symlinkSync(outside, join(tempDir, "evidence-items"), "dir");
      assert.throws(
        () =>
          addEvidenceItemResult(c.id, {
            role: "observation",
            summary: "must not escape",
            artifactPath: artifact,
          }),
        /real directory, not a symlink/,
      );
      assert.deepStrictEqual(readFileSync(artifact, "utf8"), "verified bytes");
      assert.deepStrictEqual(listEvidenceItems(c.id), []);
      assert.deepStrictEqual(readdirSync(outside), []);
    } finally {
      rmSync(outside, { recursive: true, force: true });
    }
  });

  it("control evidence must exist and differ from the target (differential gate)", () => {
    const rec = addCase({
      title: "Live IDOR",
      status: "investigating",
      evidence: "Observed other user's export",
      confidence: "high",
      impact: "data leak",
      severity: "high",
      poc: "/tmp/poc.sh",
      target: "example-app",
    });
    // No control evidence at all -> the bundle is rejected at store time.
    const noControl = pendingBundle(rec.id);
    noControl.controlRun = {
      ...noControl.controlRun,
      evidence: undefined as unknown as PoCEvidence,
      evidenceSha256: "",
    };
    assert.throws(() => storePendingConfirmation(rec.id, noControl), /no evidence/);
    // A crashed control run (completed:false) is not evidence.
    const crashed = pendingBundle(rec.id);
    crashed.controlRun = { ...crashed.controlRun, completed: false };
    assert.throws(() => storePendingConfirmation(rec.id, crashed), /did not complete/);
    // Control evidence IDENTICAL to the target (normalized, nonce stripped)
    // means the claimed impact is not target-dependent — the unconditional-
    // success cheat, now judged on structured evidence instead of markers.
    const same = pendingBundle(rec.id, {
      controlEvidence: makeEvidence(
        "nonce-control",
        ["root:"],
        "read /etc/passwd of target",
        "example-app",
      ),
    });
    assert.throws(() => storePendingConfirmation(rec.id, same), /not target-dependent/);
    // A clean differential (control lacks the claimed entry) promotes.
    const ok = promote(rec.id);
    assert.strictEqual(ok.record.status, "confirmed");
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
      disproveIf: ["test: finding is actually intended behavior"],
    });
    assert.throws(() => assertPromotable(bare.record.id), /Evidence chain incomplete/);
    // No phantom reproduction item may exist on the still-investigating case.
    assert.strictEqual(listEvidenceItems(bare.record.id).length, 0);
    // A SUMMARY-ONLY observation is still rejected — the observation must be
    // artifact-backed (SHA-256), not agent prose.
    addEvidenceItemResult(bare.record.id, { role: "observation", summary: "obs" });
    assert.throws(() => assertPromotable(bare.record.id), /Evidence chain incomplete/);
    // Retry after adding an ARTIFACT-BACKED observation item succeeds — no PK
    // conflict on the deterministic reproduction id.
    addEvidenceItemResult(bare.record.id, {
      role: "observation",
      summary: "obs (artifact-backed)",
      artifactPath: observationArtifactPath(),
    });
    const ok = promote(bare.record.id);
    assert.strictEqual(ok.record.status, "confirmed");
    assert.strictEqual(listEvidenceItems(bare.record.id).length, 3); // obs + obs + reproduction
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

    // Single-case read hydrates too. The helper's observation is
    // artifact-backed: artifact_path/sha256 must map to camelCase.
    const viaSingle = getCaseById(c.id)!;
    assert.strictEqual(viaSingle.coverageItems[0].testedBy, "agent-1");
    assert.strictEqual(viaSingle.evidenceItems[0].artifactPath, "observation.txt");
    assert.match(viaSingle.evidenceItems[0].sha256 ?? "", /^[0-9a-f]{64}$/);
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
    assert.strictEqual(ato!.confidence, 60); // investigating pair (neither confirmed)

    // Only pairs on the same asset chain.
    const other = addCase({
      title: "XSS in unrelated-app",
      evidence: "reflected",
      target: "other-app",
    });
    const xssSuggestions = suggestChains(other.id).filter((s) => s.pattern === "xss_csrf");
    assert.strictEqual(xssSuggestions.length, 0);
  });

  it("does not suggest chains from ruled-out evidence sentences", () => {
    const cred = addCase({
      title: "Leaked API key in repo",
      status: "investigating",
      evidence: "Key in public repo",
      confidence: "high",
      impact: "credential exposure",
      severity: "high",
      target: "negation-app",
    });
    // The credential keyword appears only in a ruled-out sentence.
    const endpoint = addCase({
      title: "Admin login endpoint",
      status: "investigating",
      evidence: "Login accepts credentials. SSRF ruled out on all hosts.",
      confidence: "high",
      impact: "auth",
      severity: "medium",
      target: "negation-app",
    });
    const suggestions = suggestChains();
    assert.ok(
      suggestions.some((s) => s.pattern === "credential_endpoint"),
      "the positive credential sentence still chains",
    );
    assert.ok(
      !suggestions.some((s) => s.pattern === "info_disclosure_ssrf" && s.sourceId === endpoint.id),
      "the ruled-out SSRF sentence must not produce an SSRF chain",
    );
    void cred;
  });

  it("does not re-suggest pairs that are already linked", () => {
    const cred = addCase({
      title: "Leaked API key in repo",
      status: "investigating",
      evidence: "Key in public repo",
      confidence: "high",
      impact: "credential exposure",
      severity: "high",
      target: "linked-app",
    });
    const endpoint = addCase({
      title: "Admin login endpoint",
      status: "investigating",
      evidence: "Login accepts credentials",
      confidence: "high",
      impact: "auth",
      severity: "medium",
      target: "linked-app",
    });
    linkCasesResult(cred.id, endpoint.id, "depends-on");
    const suggestions = suggestChains();
    assert.ok(
      !suggestions.some((s) => s.pattern === "credential_endpoint" && s.sourceId === cred.id),
      "an already-linked pair is existing knowledge, not a suggestion",
    );
  });

  it("async offload (worker thread) matches the inline implementation", async () => {
    addCase({
      title: "Leaked API key in repo",
      status: "investigating",
      evidence: "Key in public repo",
      confidence: "high",
      impact: "credential exposure",
      severity: "high",
      target: "worker-app",
    });
    addCase({
      title: "Admin login endpoint",
      status: "investigating",
      evidence: "Login accepts credentials",
      confidence: "high",
      impact: "auth",
      severity: "medium",
      target: "worker-app",
    });
    const inline = suggestChains();
    const offloaded = await suggestChainsAsync();
    assert.deepStrictEqual(offloaded, inline);
    assert.ok(offloaded.length > 0);
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
    promote(live.id);
    // CaseContext records reportPath; the main agent then creates the file
    // (the confirmed→reported gate requires it on disk AND passing the content
    // gate: non-trivial size, required sections, no internal identifiers).
    const { path } = writeCaseContext(live.id);
    writeGoodReport(path);
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

  it("searchCases treats LIKE wildcards in the query literally", () => {
    addCase({ title: "Coverage 100% verified", target: "app.test" });
    addCase({ title: "Coverage 1000 rows", target: "app.test" });
    addCase({ title: "Coverage complete", target: "app.test" });

    // "%" must not act as a wildcard: "100%" matches only the literal string.
    const literal = searchCases({ query: "100%" });
    assert.strictEqual(literal.total, 1);
    assert.strictEqual(literal.cases[0].title, "Coverage 100% verified");

    // "_" must match a literal underscore, not any single character.
    const underscore = searchCases({ query: "coverage_1000" });
    assert.strictEqual(underscore.total, 0, "underscore in the query is literal");

    // NaN limit falls back to the default instead of disabling the cap.
    const nanLimit = searchCases({ limit: NaN as unknown as number });
    assert.ok(Array.isArray(nanLimit.cases), "NaN limit does not throw");
    assert.strictEqual(nanLimit.total, 3);
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
    promote(record.id);

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
      context.includes("tried /read?file=/etc/shadow"),
      "context must include the disconfirmation body (the main agent's attempt becomes the case's disconfirmation)",
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
    // Path-leak guard: only the PoC basename (poc.sh from the fixture bundle),
    // never its absolute path (the scratchpad section legitimately names the
    // project root, so scope the check to the PoC path itself).
    assert.ok(context.includes("poc.sh"), "context must include the PoC script basename");
    assert.ok(
      !context.includes(join(tempDir, "poc.sh")),
      "context must NOT leak the absolute PoC path",
    );
    // The report path is reserved for the main agent's final report; the report file
    // does not exist until the writer creates it.
    assert.ok(!existsSync(path), "report file not yet written");
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
    promote(record.id);

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

  it("worker-thread CaseContext reads artifacts from the configured scratchpad root", async () => {
    const record = addCase({
      title: "Worker context artifact",
      status: "investigating",
      evidence: "Observed a target-only response",
      confidence: "high",
      severity: "high",
      impact: "Sensitive data disclosure",
      poc: "GET /worker-proof",
      target: "worker-app",
    });
    promote(record.id);

    setScratchpadRoot(tempDir);
    scratchpad_init("run-worker-context", tempDir);
    scratchpad_checkpoint(
      "run-worker-context",
      "recon",
      { ids: [record.id], summary: "worker context fixture" },
      tempDir,
    );
    scratchpad_write(
      "run-worker-context",
      "recon",
      "worker-proof.md",
      "worker-thread-visible-artifact",
      tempDir,
    );

    const { contextPath } = await writeCaseContextAsync(record.id);
    const context = readFileSync(contextPath, "utf8");
    assert.ok(context.includes("run-worker-context"));
    assert.ok(context.includes("worker-thread-visible-artifact"));
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

  it("demoting confirmed → investigating clears all verification records", () => {
    const record = addCase({
      title: "Confirmed then demoted",
      status: "investigating",
      evidence: "repro steps",
      confidence: "high",
      impact: "data leak",
      severity: "high",
      poc: "/tmp/poc.sh",
      target: "example-app",
    });
    promote(record.id);
    const confirmed = readCasefile().find((c) => c.id === record.id)!;
    assert.ok(confirmed.pocVerified, "pocVerified set after promotion");
    assert.ok(confirmed.controlVerified, "controlVerified set after promotion");
    assert.ok(confirmed.confirmerVerdict, "confirmerVerdict set after promotion");
    assert.throws(
      () => updateCaseResult(record.id, { impact: "different impact" }),
      /proof-bound field/,
    );

    // Demote back to investigating — every verification artifact must clear.
    updateCaseResult(record.id, { status: "investigating" });
    const demoted = readCasefile().find((c) => c.id === record.id)!;
    assert.strictEqual(demoted.pocVerified, undefined, "pocVerified cleared on demotion");
    assert.strictEqual(demoted.controlVerified, undefined, "controlVerified cleared on demotion");
    assert.strictEqual(demoted.confirmerVerdict, undefined, "confirmerVerdict cleared on demotion");
    assert.strictEqual(
      demoted.pendingConfirmation,
      undefined,
      "pendingConfirmation cleared on demotion",
    );
  });

  it("enforces the same-file control contract and script immutability at the ledger", () => {
    const rec = addCase({
      title: "Same-file control",
      status: "investigating",
      evidence: "observed",
      confidence: "high",
      impact: "leak",
      severity: "medium",
      poc: "/tmp/poc.sh",
      target: "example-app",
    });
    const pocPath = join(tempDir, "poc.sh");
    const otherPath = join(tempDir, "other.sh");
    writeFileSync(pocPath, "#!/bin/sh\necho target", "utf8");
    writeFileSync(otherPath, "#!/bin/sh\necho control", "utf8");
    // A DIFFERENT real file as the control — the two-file cheat.
    assert.throws(
      () =>
        storePendingConfirmation(
          rec.id,
          pendingBundle(rec.id, { pocPath, controlPath: otherPath }),
        ),
      /SAME script/,
    );
    // pocSha256 mismatch (bundle claims different bytes than the file) fails.
    assert.throws(
      () => storePendingConfirmation(rec.id, pendingBundle(rec.id, { pocSha256: "deadbeef" })),
      /pocSha256 does not match/,
    );
    // Script edited BETWEEN phase 1 and phase 2 → the main agent would review
    // different bytes than ran; blocked at apply time.
    const edited = pendingBundle(rec.id, { pocPath });
    storePendingConfirmation(rec.id, edited);
    writeFileSync(pocPath, "#!/bin/sh\necho EDITED", "utf8");
    assert.throws(() => applyConfirmationResult(rec.id, makeVerdict()), /changed since the runs/);

    // Same file for both, untouched → promotes.
    const ok = promote(rec.id, { bundle: pendingBundle(rec.id, { pocPath }) });
    assert.strictEqual(ok.record.status, "confirmed");
  });

  it("binds evidence to its run via the nonce (copy-pasted evidence fails)", () => {
    const rec = addCase({
      title: "Nonce binding",
      status: "investigating",
      evidence: "observed",
      confidence: "high",
      impact: "leak",
      severity: "medium",
      poc: "/tmp/poc.sh",
      target: "example-app",
    });
    // Evidence whose nonce does not match its run's nonce — a file copied from
    // another run — is rejected at store time.
    const wrong = pendingBundle(rec.id);
    wrong.targetRuns[0].evidence = {
      ...wrong.targetRuns[0].evidence,
      nonce: "some-other-runs-nonce",
    };
    assert.throws(() => storePendingConfirmation(rec.id, wrong), /nonce mismatch/);
  });

  it("requires deterministic evidence across the two target runs", () => {
    const rec = addCase({
      title: "Determinism",
      status: "investigating",
      evidence: "observed",
      confidence: "high",
      impact: "leak",
      severity: "medium",
      poc: "/tmp/poc.sh",
      target: "example-app",
    });
    // The two target runs claim DIFFERENT impacts — flaky/one-shot evidence.
    const flaky = pendingBundle(rec.id, {
      secondTargetEvidence: makeEvidence("nonce-target-2", ["different-data"], "a different claim"),
    });
    assert.throws(
      () => storePendingConfirmation(rec.id, flaky),
      /did not reproduce deterministically/,
    );
  });

  it("blocks observation items that postdate the repro", () => {
    // Built WITHOUT the helper's default observation so the timestamp is real.
    const res = ledgerAddCaseResult({
      title: "Observation provenance",
      status: "investigating",
      evidence: "observed",
      confidence: "high",
      impact: "leak",
      severity: "medium",
      poc: "/tmp/poc.sh",
      target: "example-app",
      disproveIf: ["test: finding is actually intended behavior"],
    });
    const rec = res.record;
    const obsPath = join(tempDir, "obs.txt");
    writeFileSync(obsPath, "observed signal", "utf8");
    addEvidenceItemResult(rec.id, {
      role: "observation",
      summary: "initial signal",
      artifactPath: obsPath,
    });
    // Runs dated in the past -> the (real-time) observation postdates the repro.
    const bundle = pendingBundle(rec.id);
    bundle.targetRuns[0].ranAt = "2020-01-01T00:00:00Z";
    bundle.targetRuns[1].ranAt = "2020-01-01T00:00:00Z";
    bundle.controlRun.ranAt = "2020-01-01T00:00:00Z";
    storePendingConfirmation(rec.id, bundle);
    assert.throws(() => applyConfirmationResult(rec.id, makeVerdict()), /after the PoC ran/);
  });

  it("report content gate: blocks undersized / section-less / identifier-leaking reports", () => {
    const rec = addCase({
      title: "Report gate",
      status: "investigating",
      evidence: "observed",
      confidence: "high",
      impact: "leak",
      severity: "medium",
      poc: "/tmp/poc.sh",
      target: "example-app",
      disconfirmation: "Tried; held.",
    });
    promote(rec.id);
    const { path } = writeCaseContext(rec.id);

    // Empty/undersized file → blocked.
    writeFileSync(path, "# Report\n", "utf8");
    assert.throws(
      () => updateCaseResult(rec.id, { status: "reported" }),
      /too small|missing required section/,
    );
    // Real sections but leaking the case id → blocked (padded past the size floor).
    writeFileSync(
      path,
      `# Report for ${rec.id}\n\n## Summary\nStored XSS in chat; payload renders without encoding.\n\n## Impact\nScript execution in victim browser; token theft.\n\n## Remediation\nEncode output at the sink; add a strict CSP.\n`,
      "utf8",
    );
    assert.throws(
      () => updateCaseResult(rec.id, { status: "reported" }),
      /forbidden internal identifier/,
    );
    // A clean report → transition commits AND reportedAt is stamped at commit time.
    writeGoodReport(path);
    const done = updateCaseResult(rec.id, { status: "reported" });
    assert.strictEqual(done.record.status, "reported");
    assert.ok(done.record.reportedAt, "reportedAt stamped on the transition");
    // CaseContext does NOT stamp reportedAt while still confirmed.
    const fresh = addCase({
      title: "No premature stamp",
      status: "investigating",
      evidence: "observed",
      confidence: "high",
      impact: "leak",
      severity: "medium",
      poc: "/tmp/poc.sh",
      target: "example-app",
      disconfirmation: "Tried; held.",
    });
    promote(fresh.id);
    writeCaseContext(fresh.id);
    const afterCtx = readCasefile().find((c) => c.id === fresh.id)!;
    assert.strictEqual(afterCtx.reportedAt, undefined, "reportedAt NOT stamped by CaseContext");
  });
});

describe("intra-target confirmation (same-host attack-vs-baseline differential)", () => {
  /** IDOR-style evidence: attack reads a victim object, baseline reads own. */
  function makeIntraEvidence(
    nonce: string,
    target = "target.test",
    opts: { baseline?: "own" | "identical" | "none" } = {},
  ): PoCEvidence {
    const origin = `http://${target}`;
    const verify: PoCEvidence["verify"] = {
      method: "GET",
      url: `${origin}/api/orders/1001`,
      headers: { authorization: "Bearer attacker" },
      expect: { status: [200], body_contains: ["victim-ssn:111-22-3333"] },
      mode: "intra_target",
    };
    const baseline =
      opts.baseline === "none"
        ? undefined
        : opts.baseline === "identical"
          ? { method: "GET", url: verify.url, headers: verify.headers }
          : { method: "GET", url: `${origin}/api/orders/2002`, headers: verify.headers };
    return {
      nonce,
      claim: "IDOR: cross-tenant order read",
      verify,
      observations: ["victim ssn present on attack response"],
      ...(baseline ? { baseline } : {}),
    };
  }

  function intraBundle(
    id: string,
    opts: { baseline?: "own" | "identical" | "none"; harnessVerified?: HarnessVerifyResult } = {},
  ): PendingConfirmation {
    const target = getCaseById(id)?.target ?? "target.test";
    const e1 = makeIntraEvidence("intra-nonce-1", target, opts);
    const e2 = makeIntraEvidence("intra-nonce-2", target, opts);
    const targetRuns: [PocEvidenceRun, PocEvidenceRun] = [
      evidenceRun("poc", target, "intra-nonce-1", e1),
      evidenceRun("poc", target, "intra-nonce-2", e2),
    ];
    const durableDir = join(tempDir, ".pi", "poc-evidence");
    mkdirSync(durableDir, { recursive: true });
    for (const run of targetRuns) {
      const p = join(durableDir, `${run.nonce}.evidence.json`);
      writeFileSync(p, JSON.stringify(run.evidence), "utf8");
      run.evidencePath = p;
    }
    const pocPath = pocScriptPath("poc.sh");
    return {
      caseId: id,
      ranAt: new Date().toISOString(),
      pocPath,
      pocSha256: sha256hex(readFileSync(pocPath, "utf8")),
      mode: "intra_target",
      targetRuns,
      harnessVerified: opts.harnessVerified ?? {
        attempted: true,
        pass: true,
        status: 200,
        differential: "target_only",
        target: {
          attempted: true,
          matched: true,
          status: 200,
          url: e1.verify.url,
          note: "attack matched",
        },
        control: {
          attempted: true,
          matched: false,
          status: 200,
          url: e1.baseline?.url ?? e1.verify.url,
          note: "baseline did not match",
        },
        note: "intra-target differential target_only",
      },
    };
  }

  function intraCase() {
    return addCase({
      title: "IDOR order read",
      status: "investigating",
      evidence: "attacker token returned victim order",
      confidence: "high",
      impact: "cross-tenant PII read",
      severity: "high",
      poc: "/tmp/poc.sh",
      target: "target.test",
    });
  }

  it("stores and confirms an intra-target bundle with a same-host baseline", () => {
    const rec = intraCase();
    const stored = storePendingConfirmation(rec.id, intraBundle(rec.id));
    assert.ok(stored.pendingConfirmation, "bundle recorded");
    assert.strictEqual(stored.pendingConfirmation?.mode, "intra_target");
    const result = applyConfirmationResult(
      rec.id,
      makeVerdict(),
      freshMainAgentVerification(rec.id),
    );
    assert.strictEqual(result.record.status, "confirmed");
    assert.ok(
      result.record.evidenceItems.some((e) => e.role === "reproduction"),
      "reproduction evidence recorded",
    );
  });

  it("rejects an intra-target bundle that smuggles in a control run", () => {
    const rec = intraCase();
    const bundle = intraBundle(rec.id);
    bundle.controlRun = evidenceRun(
      "control",
      "control.test",
      "c-nonce",
      makeIntraEvidence("c-nonce"),
    );
    bundle.controlTarget = "control.test";
    assert.throws(() => storePendingConfirmation(rec.id, bundle), /must not carry a control run/i);
  });

  it("rejects intra-target evidence without a baseline request", () => {
    const rec = intraCase();
    assert.throws(
      () => storePendingConfirmation(rec.id, intraBundle(rec.id, { baseline: "none" })),
      /baseline/i,
    );
  });

  it("rejects intra-target evidence whose attack and baseline are identical", () => {
    const rec = intraCase();
    assert.throws(
      () => storePendingConfirmation(rec.id, intraBundle(rec.id, { baseline: "identical" })),
      /identical/i,
    );
  });

  it("rejects an intra-target bundle whose harness differential is not target_only", () => {
    const rec = intraCase();
    const bundle = intraBundle(rec.id, {
      harnessVerified: {
        attempted: true,
        pass: false,
        status: 200,
        differential: "both",
        target: { attempted: true, matched: true, status: 200, url: "x", note: "attack matched" },
        control: {
          attempted: true,
          matched: true,
          status: 200,
          url: "y",
          note: "baseline ALSO matched",
        },
        note: "intra-target differential both",
      },
    });
    assert.throws(() => storePendingConfirmation(rec.id, bundle), /HARNESS DIFFERENTIAL FAILED/);
  });
});
