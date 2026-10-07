/**
 * Two-phase PoC confirmation gate (phase 1: PromoteFinding evidence bundle;
 * phase 2: main-agent ConfirmFinding commit).
 *
 * Extracted verbatim from ledger.ts so the trust-critical machinery lives in
 * one readable module. ledger.ts re-exports every public symbol here, so
 * callers and tests are unchanged.
 *
 * The gate's contract (docs/confirmation-design.md):
 * - Zero exit + complete output capture = run integrity, never proof.
 * - Evidence must be nonce-bound, schema-valid, carry a discriminating
 *   response-body predicate, and survive durable-hash re-verification.
 * - Target-dependence requires a machine differential: inter-host control run,
 *   intra-target same-host baseline, or a source-separated OOB token delta.
 * - Phase 2 requires a fresh harness-owned replay bound to the verdict; only
 *   the ledger can transition a case to confirmed.
 */

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

import { basename } from "node:path";

import {
  evidenceNonceMatches,
  type MainAgentVerdict,
  normalizeEvidence,
  parsePoCEvidence,
  validateMainAgentVerdict,
} from "./evidence.ts";
import { type HarnessVerifyResult, sameRequest, verifyUrlBindingError } from "./harness-verify.ts";
import type {
  CaseRecord,
  CaseUpdateResult,
  EvidenceItem,
  MainAgentVerdictRecord,
  MainAgentVerification,
  NormalizedCaseInput,
  PendingConfirmation,
  PocEvidenceRun,
} from "./ledger.ts";
import { getCaseById, readWorkspaceArtifact } from "./ledger.ts";
import {
  buildRecord,
  getDb,
  insertEvidenceItem,
  upsertCase,
  validateCase,
  withImmediateTransaction,
} from "./ledger-internal.ts";

/** PoC evidence has a tighter runner-side cap and must remain equally bounded on re-read. */
const POC_EVIDENCE_MAX_BYTES = 256 * 1024;

/** Immutable module-start role; child shells cannot upgrade this process by unsetting an env var. */
const PROCESS_STARTED_AS_SUBAGENT = process.env.PI_SUBAGENT_CHILD === "1";

/** Pending confirmation expires after 1h — re-run PromoteFinding for a fresh bundle. */
export const PENDING_CONFIRM_TTL_MS = 60 * 60 * 1000;

// Re-declared here as narrow internal helpers; ledger.ts keeps the shared copies.
function stableShortId(input: string): string {
  return createHash("sha1").update(input).digest("hex").slice(0, 10);
}
function validateRunEvidence(run: PocEvidenceRun, label: string): void {
  if (!run.completed) {
    throw new Error(`${label} did not complete; a crash is not evidence`);
  }
  if (!run.outputComplete) {
    throw new Error(`${label} output capture was incomplete; evidence checks are unsafe`);
  }
  if (run.exitCode !== 0) {
    throw new Error(
      `${label} exited with ${run.exitCode}; exit 0 is required for a complete run but is never sufficient proof`,
    );
  }
  if (!run.evidence || !run.evidenceSha256) {
    throw new Error(
      `${label} has no evidence.json — the PoC must write evidence to $PI_POC_EVIDENCE_DIR`,
    );
  }
  if (!evidenceNonceMatches(run.evidence, run.nonce)) {
    throw new Error(`${label} evidence nonce mismatch — evidence not bound to this run`);
  }
  const parsed = parsePoCEvidence(run.evidence);
  if (!parsed.ok) {
    throw new Error(`${label} evidence contract invalid: ${parsed.error}`);
  }
  if (!run.evidencePath) {
    throw new Error(`${label} has no durable evidencePath; ephemeral evidence cannot confirm`);
  }
  const artifact = readWorkspaceArtifact(run.evidencePath);
  if (artifact.bytes.byteLength > POC_EVIDENCE_MAX_BYTES) {
    throw new Error(
      `${label} durable evidence exceeds ${POC_EVIDENCE_MAX_BYTES} bytes; evidence cannot be revalidated safely`,
    );
  }
  const durableHash = createHash("sha256").update(artifact.bytes).digest("hex");
  if (durableHash !== run.evidenceSha256) {
    throw new Error(`${label} durable evidence hash does not match evidenceSha256`);
  }
  let durableRaw: unknown;
  try {
    durableRaw = JSON.parse(artifact.bytes.toString("utf8"));
  } catch (error) {
    throw new Error(`${label} durable evidence is not valid JSON: ${(error as Error).message}`);
  }
  const durable = parsePoCEvidence(durableRaw);
  if (!durable.ok) {
    throw new Error(`${label} durable evidence contract invalid: ${durable.error}`);
  }
  if (
    normalizeEvidence(durable.evidence) !== normalizeEvidence(run.evidence) ||
    JSON.stringify(durable.evidence.observations) !== JSON.stringify(run.evidence.observations)
  ) {
    throw new Error(`${label} durable evidence bytes do not match the stored evidence object`);
  }
}

/** Determinism + differential on normalized evidence (nonce/observations stripped). */
function assertEvidenceDifferential(bundle: PendingConfirmation, isIntra = false): void {
  const [r1, r2] = bundle.targetRuns;
  if (normalizeEvidence(r1.evidence) !== normalizeEvidence(r2.evidence)) {
    throw new Error(
      "Target runs produced inconsistent evidence — the exploit did not reproduce deterministically",
    );
  }
  // Intra-target target-dependence is proven by the harness attack-vs-baseline
  // replay (same host), not by comparing a target run to a separate control run.
  if (isIntra) return;
  // OOB-only bundles prove target-dependence via the oracle token differential
  // (assertMachineConfirmation judges callbackVerified); no control run exists.
  if (!bundle.controlRun && bundle.callbackVerified?.attempted) return;
  if (!bundle.controlRun) {
    throw new Error("inter-host confirmation requires a control run");
  }
  if (normalizeEvidence(r1.evidence) === normalizeEvidence(bundle.controlRun.evidence)) {
    throw new Error(
      "Control run produced identical evidence to the target — the claimed impact is not target-dependent",
    );
  }
}

function assertMachineConfirmation(bundle: PendingConfirmation): void {
  const oob = bundle.callbackVerified;
  if (oob?.attempted) {
    if (oob.targetHits === 0) {
      throw new Error(
        `OOB VERIFY FAILED: no interaction with the target-run callback token. ${oob.note}`,
      );
    }
    if (oob.controlHits > 0) {
      throw new Error(
        `OOB VERIFY FAILED: the control-run callback token received ${oob.controlHits} interaction(s) — the callback is not target-dependent. ${oob.note}`,
      );
    }
    if (oob.sourceSeparated !== true) {
      throw new Error(
        "OOB VERIFY FAILED: callback source separation was not established. " +
          "A loopback listener reachable by the PoC is diagnostic telemetry, not proof that the target caused the interaction.",
      );
    }
    return;
  }

  assertHarnessTargetOnly(
    bundle.harnessVerified,
    "HARNESS DIFFERENTIAL FAILED",
    "no machine-owned target/control replay was recorded",
  );
}

function assertHarnessTargetOnly(
  harness: HarnessVerifyResult | undefined,
  label: string,
  missingNote: string,
): asserts harness is HarnessVerifyResult {
  if (
    !harness?.attempted ||
    harness.pass !== true ||
    harness.differential !== "target_only" ||
    harness.target?.matched !== true ||
    harness.control?.matched !== false
  ) {
    throw new Error(`${label}: ${harness?.note ?? missingNote}`);
  }
}

function assertHarnessCanary(
  harness: HarnessVerifyResult | undefined,
  required: boolean,
  label: string,
): void {
  if (!required) return;
  if (
    harness?.canary?.attempted !== true ||
    harness.canary.pass !== true ||
    harness.canary.targetObserved !== true ||
    harness.canary.controlObserved !== false ||
    harness.proofStrength !== "canary_differential"
  ) {
    throw new Error(`${label}: ${harness?.canary?.note ?? "required canary transcript missing"}`);
  }
}

function assertMainAgentVerification(
  bundle: PendingConfirmation,
  verification: MainAgentVerification | undefined,
  isIntra = false,
): asserts verification is MainAgentVerification {
  if (!verification) {
    throw new Error(
      "MAIN-AGENT REPLAY REQUIRED: ConfirmFinding must produce a fresh harness-owned target/control transcript",
    );
  }
  const at = Date.parse(verification.at);
  const bundleAt = Date.parse(bundle.ranAt);
  const now = Date.now();
  if (
    !Number.isFinite(at) ||
    !Number.isFinite(bundleAt) ||
    at < bundleAt ||
    at > now + 30_000 ||
    now - at > 5 * 60 * 1000
  ) {
    throw new Error(
      "MAIN-AGENT REPLAY FAILED: transcript timestamp must be valid, newer than phase 1, and no more than 5 minutes old",
    );
  }
  assertHarnessTargetOnly(
    verification.result,
    "MAIN-AGENT REPLAY FAILED",
    "no fresh phase-2 target/control replay was recorded",
  );
  assertHarnessCanary(
    verification.result,
    bundle.targetRuns[0].evidence.verify.canary !== undefined,
    "MAIN-AGENT CANARY FAILED",
  );
  // OOB-only bundles bind by TOKEN identity (enforced at store time on
  // evidence.verify.url); there is no control host to bind a transcript to.
  if (bundle.callbackVerified?.attempted && bundle.oobTokens) return;
  const targetUrl = verification.result.target?.url;
  const controlUrl = verification.result.control?.url;
  const targetIdentity = bundle.targetRuns[0].target;
  if (!targetUrl || verifyUrlBindingError(targetUrl, targetIdentity)) {
    throw new Error("MAIN-AGENT REPLAY FAILED: target transcript is not bound to the case target");
  }
  // Intra-target: the "control" transcript is the legitimate baseline request,
  // which is bound to the SAME case target. Inter-host: it is bound to the
  // distinct control target.
  const controlBindTarget = isIntra ? targetIdentity : bundle.controlTarget;
  if (!controlUrl || !controlBindTarget || verifyUrlBindingError(controlUrl, controlBindTarget)) {
    throw new Error(
      isIntra
        ? "MAIN-AGENT REPLAY FAILED: baseline transcript is not bound to the case target"
        : "MAIN-AGENT REPLAY FAILED: control transcript is not bound to control_target",
    );
  }
}

/**
 * Gate for phase 1 of promotion: case must exist, be investigating, and have
 * poc/evidence/impact/severity/target. The disconfirmation is provided by the
 * main agent at confirm time, so it is NOT a precondition here. Returns the
 * record when promotable, throws otherwise. Exported so PromoteFinding can
 * validate BEFORE paying for (potentially slow) sandboxed PoC runs.
 */
export function assertPromotable(id: string): CaseRecord {
  const current = getCaseById(id);
  if (!current) {
    throw new Error(`Case not found: ${id}`);
  }
  if (current.status !== "investigating") {
    throw new Error(`PromoteFinding requires an investigating case (current: ${current.status})`);
  }
  if (!current.poc) {
    throw new Error("CONFIRMED requires poc; set poc on the case first");
  }
  if (!current.evidence) {
    throw new Error("CONFIRMED requires evidence; set evidence on the case first");
  }
  if (!current.impact) {
    throw new Error("CONFIRMED requires impact; set impact on the case first");
  }
  if (!current.severity) {
    throw new Error("CONFIRMED requires severity; set severity on the case first");
  }
  if (!current.target) {
    throw new Error(
      "CONFIRMED requires target (what host/repo/scope this affects); set target on the case first",
    );
  }
  // Evidence-chain closure: the observation item must be ARTIFACT-BACKED. A
  // summary-only observation is agent prose about itself — promotion requires
  // a real file with its SHA-256 as the initial signal. (The reproduction item
  // is always artifact-backed: the gate writes it from the evidence hash.)
  if (!current.evidenceItems?.some((e: EvidenceItem) => e.role === "observation" && e.sha256)) {
    throw new Error(
      "Evidence chain incomplete: CONFIRMED requires an artifact-backed observation evidence item " +
        "(EvidenceAdd role=observation with artifact_path — the initial signal, stored as basename + SHA-256) " +
        "in addition to the auto-recorded reproduction item. Add the artifact-backed observation item and retry promotion.",
    );
  }
  return current;
}

/**
 * Phase 1 (intra-target): validate a same-host attack-vs-baseline bundle. The
 * differential is proven by the harness replay (attack matched, baseline did
 * not, both against the case target), not by a separate control run — the
 * discriminating variable is the request's identity or a parameter, not the host.
 */
function validateIntraTargetBundle(
  current: CaseRecord,
  id: string,
  bundle: PendingConfirmation,
): CaseRecord {
  if (bundle.targetRuns.length !== 2) {
    throw new Error("Intra-target confirmation requires two target runs");
  }
  if (bundle.controlRun || bundle.controlTarget) {
    throw new Error(
      "Intra-target confirmation must not carry a control run or control target — the baseline is a same-host request inside the evidence",
    );
  }
  const targetRunTarget = bundle.targetRuns[0]?.target;
  if (!targetRunTarget || bundle.targetRuns.some((r) => r.target !== targetRunTarget)) {
    throw new Error("Intra-target confirmation requires both runs against the same case target");
  }
  let pocHash: string | undefined;
  try {
    pocHash = createHash("sha256").update(readFileSync(bundle.pocPath)).digest("hex");
  } catch {
    pocHash = undefined;
  }
  if (!pocHash || (bundle.pocSha256 && bundle.pocSha256 !== pocHash)) {
    throw new Error("pocSha256 does not match the PoC file on disk");
  }
  for (const run of bundle.targetRuns) {
    validateRunEvidence(run, `${run.mode} run`);
    const ev = run.evidence;
    if (ev.verify.mode !== "intra_target") {
      throw new Error(
        "INTRA-TARGET FAILED: each run's evidence.verify.mode must be 'intra_target'",
      );
    }
    if (!ev.baseline) {
      throw new Error(
        "INTRA-TARGET FAILED: evidence.baseline (a legitimate same-host request) is required",
      );
    }
    const attackBinding = verifyUrlBindingError(ev.verify.url, targetRunTarget);
    if (attackBinding) throw new Error(`ATTACK BINDING FAILED: ${attackBinding}`);
    const baselineBinding = verifyUrlBindingError(ev.baseline.url, targetRunTarget);
    if (baselineBinding) throw new Error(`BASELINE BINDING FAILED: ${baselineBinding}`);
    if (ev.baseline && sameRequest(ev.verify, ev.baseline)) {
      throw new Error(
        "INTRA-TARGET FAILED: attack and baseline requests are identical — vary identity or a parameter",
      );
    }
  }
  if (bundle.caseId !== id) throw new Error("Pending confirmation caseId mismatch");
  assertEvidenceDifferential(bundle, true);
  // Machine floor: attack matched, baseline did not, both against the case target.
  assertMachineConfirmation(bundle);
  assertHarnessCanary(
    bundle.harnessVerified,
    bundle.targetRuns[0].evidence.verify.canary !== undefined,
    "PHASE-1 CANARY FAILED",
  );
  const next = buildRecord({ pendingConfirmation: bundle }, current);
  validateCase(next);
  return next;
}

/**
 * Phase 1: record the harness-observed evidence bundle on the case. The whole
 * contract is validated here — same-file control, nonce binding, run
 * completion, determinism across the two target runs, and the target/control
 * differential — so a bundle that cannot promote is rejected before the
 * main agent performs phase-2 review.
 */
export function storePendingConfirmation(id: string, bundle: PendingConfirmation): CaseRecord {
  const db = getDb();
  return withImmediateTransaction(db, () => {
    const current = getCaseById(id);
    if (!current) throw new Error(`Case not found: ${id}`);
    if (current.status !== "investigating") {
      throw new Error(
        `Pending confirmation requires an investigating case (current: ${current.status})`,
      );
    }
    if (bundle.caseId !== id) throw new Error("Pending confirmation caseId mismatch");
    if (bundle.mode === "intra_target") {
      const next = validateIntraTargetBundle(current, id, bundle);
      upsertCase(db, next);
      return next;
    }
    // Control-run requirements key off controlRun PRESENCE, not the OOB flag:
    // an OOB-only bundle has no control run (token differential instead), but
    // an OOB+control bundle still carries one and gets the full checks.
    if (!bundle.controlRun && !bundle.callbackVerified) {
      throw new Error("Pending confirmation requires two target runs and one control run");
    }
    if (bundle.controlRun && (!bundle.pocPath || !bundle.controlPath || !bundle.controlTarget)) {
      throw new Error("Pending confirmation requires pocPath, controlPath, and controlTarget");
    }
    // Control-target binding (machine-verified here, not just in the tool
    // layer): the control run must actually have targeted the declared
    // control_target, that target must differ from the target runs' target,
    // and the control target must differ from the case's target — otherwise
    // "the control demonstrated nothing on the vulnerable target" passes.
    const targetRunTarget = bundle.targetRuns[0]?.target;
    if (!targetRunTarget || bundle.targetRuns.some((r) => r.target !== targetRunTarget)) {
      throw new Error(
        "Pending confirmation requires both target runs against the same case target",
      );
    }
    if (bundle.controlRun) {
      if (!bundle.controlRun.target || bundle.controlRun.target !== bundle.controlTarget) {
        throw new Error(
          "CONTROL BINDING FAILED: controlRun.target must equal control_target — a control run " +
            "against a different host than the one declared proves nothing.",
        );
      }
      if (bundle.controlRun.target === targetRunTarget) {
        throw new Error(
          "CONTROL BINDING FAILED: the control run targeted the same host as the target runs — " +
            "the claimed impact is not target-dependent.",
        );
      }
    }
    if (bundle.controlTarget && bundle.controlTarget === current.target) {
      throw new Error(
        "CONTROL BINDING FAILED: control_target must differ from the case target; a control run " +
          "against the vulnerable target proves nothing.",
      );
    }
    // Same-file contract re-checked at store time (the tool already checked).
    // OOB-only bundles carry no separate control script — the PoC hash alone
    // is re-verified against the file on disk.
    let pocHash: string | undefined;
    let controlHash: string | undefined;
    try {
      pocHash = createHash("sha256").update(readFileSync(bundle.pocPath)).digest("hex");
      controlHash = bundle.controlPath
        ? createHash("sha256").update(readFileSync(bundle.controlPath)).digest("hex")
        : pocHash;
    } catch {
      pocHash = undefined;
      controlHash = undefined;
    }
    if (!pocHash || !controlHash || pocHash !== controlHash) {
      throw new Error(
        "CONTROL CHECK FAILED: control_path must be the SAME script as poc_path " +
          "(sha256 mismatch). A separately written control file proves nothing.",
      );
    }
    if (bundle.pocSha256 && bundle.pocSha256 !== pocHash) {
      throw new Error("pocSha256 does not match the PoC file on disk");
    }
    // Validate every run that exists — OOB-only bundles have no control run;
    // OOB+control bundles validate all three.
    const runsToValidate = bundle.controlRun
      ? [...bundle.targetRuns, bundle.controlRun]
      : [...bundle.targetRuns];
    for (const run of runsToValidate) {
      validateRunEvidence(run, `${run.mode} run`);
    }
    assertEvidenceDifferential(bundle);
    // Target binding applies to EVERY mode — an OOB bundle's verify.url must
    // still belong to the case target, or the PoC could anchor its evidence on
    // an unrelated host while the callback alone carries the proof.
    for (const run of bundle.targetRuns) {
      const bindingError = verifyUrlBindingError(run.evidence.verify.url, targetRunTarget);
      if (bindingError) throw new Error(`TARGET BINDING FAILED: ${bindingError}`);
    }
    if (bundle.controlRun) {
      const controlBindingError = verifyUrlBindingError(
        bundle.controlRun.evidence.verify.url,
        bundle.controlTarget!,
      );
      if (controlBindingError) {
        throw new Error(`CONTROL BINDING FAILED: ${controlBindingError}`);
      }
    }
    // A clean exit and model-authored evidence are necessary inputs, never the
    // proof. Promotion requires a harness-observed target/control differential
    // or a harness-owned OOB interaction differential.
    assertMachineConfirmation(bundle);

    const next = buildRecord({ pendingConfirmation: bundle }, current);
    validateCase(next);
    upsertCase(db, next);
    return next;
  });
}

/**
 * Phase 2: commit (or refuse) the promotion on the main agent's verdict.
 *
 * CONFIRMED requires the full bundle to still hold (completion, nonce,
 * determinism, differential), the PoC script to be unchanged since the runs
 * (pocSha256 — otherwise the main agent reviewed different bytes), and a
 * verdict accompanied by a fresh harness-owned target-only replay, a concrete
 * review note, and a disconfirmation attempt. NOT_CONFIRMED records the
 * verdict and keeps the case investigating — no tie-breaker.
 */
export function applyConfirmationResult(
  id: string,
  verdictInput: MainAgentVerdict,
  phase2Verification?: MainAgentVerification,
  authority: { startedAsSubagent: boolean } = {
    startedAsSubagent: PROCESS_STARTED_AS_SUBAGENT || process.env.PI_SUBAGENT_CHILD === "1",
  },
): CaseUpdateResult {
  if (authority.startedAsSubagent) {
    throw new Error(
      "ConfirmFinding is reserved for the main/coordinator agent; worker processes cannot commit confirmation",
    );
  }
  const db = getDb();
  return withImmediateTransaction(db, () => {
    const current = getCaseById(id);
    if (!current) throw new Error(`Case not found: ${id}`);
    if (current.status !== "investigating") {
      throw new Error(`ConfirmFinding requires an investigating case (current: ${current.status})`);
    }
    const bundle = current.pendingConfirmation;
    if (!bundle) {
      throw new Error("No pending confirmation on this case — run PromoteFinding first");
    }
    // Fail closed on an unparseable ranAt: Date.parse(garbage) is NaN, and
    // NaN > TTL is false — a malformed timestamp must NOT make the bundle
    // immortal. Treat it as expired (re-run PromoteFinding for a fresh one).
    const ranAtMs = Date.parse(bundle.ranAt);
    if (!Number.isFinite(ranAtMs) || Date.now() - ranAtMs > PENDING_CONFIRM_TTL_MS) {
      throw new Error(
        "Pending confirmation expired or has an invalid timestamp (1h TTL) — re-run PromoteFinding for a fresh bundle",
      );
    }
    const parsed = validateMainAgentVerdict(verdictInput);
    if (!parsed.ok) throw new Error(`Invalid main-agent confirmation verdict: ${parsed.error}`);
    const verdict = parsed.verdict;
    const canaryRequested = bundle.targetRuns[0].evidence.verify.canary !== undefined;
    if (verdict.verdict === "CONFIRMED") {
      if (canaryRequested && verdict.canary_assessment !== "verified") {
        throw new Error(
          "CONFIRMED canary mismatch: evidence requested a harness canary, so canary_assessment must be verified",
        );
      }
      if (!canaryRequested && verdict.canary_assessment !== "not_applicable") {
        throw new Error(
          "CONFIRMED canary mismatch: this evidence has no canary template; record canary_assessment=not_applicable and explain why",
        );
      }
    }
    const recorded: MainAgentVerdictRecord = {
      ...verdict,
      at: new Date().toISOString(),
      reviewer: "main_agent",
      phase2Verification: verdict.verdict === "CONFIRMED" ? phase2Verification : undefined,
      proofStrength:
        verdict.verdict === "CONFIRMED"
          ? canaryRequested
            ? "canary_differential"
            : "predicate_differential"
          : undefined,
    };

    if (verdict.verdict === "NOT_CONFIRMED") {
      const note = `main agent NOT_CONFIRMED${verdict.model ? ` (${verdict.model})` : ""}: ${verdict.reasoning}`;
      const next = buildRecord(
        {
          confirmerVerdict: recorded,
          pendingConfirmation: undefined,
          assumptions: [...(current.assumptions ?? []), note],
        },
        current,
      );
      // buildRecord's nullish fallback preserves the old value; consume the
      // rejected attempt explicitly so a retry must produce fresh evidence.
      next.pendingConfirmation = undefined;
      validateCase(next);
      upsertCase(db, next);
      return { record: next, changed: true };
    }

    // CONFIRMED — re-validate the whole bundle (defense in depth; the case may
    // have been touched between phase 1 and the verdict).
    const isIntra = bundle.mode === "intra_target";
    const allRuns = isIntra
      ? [...bundle.targetRuns]
      : [...bundle.targetRuns, ...(bundle.controlRun ? [bundle.controlRun] : [])];
    for (const run of allRuns) {
      validateRunEvidence(run, `${run.mode} run`);
    }
    assertEvidenceDifferential(bundle, isIntra);
    assertMachineConfirmation(bundle);
    assertHarnessCanary(bundle.harnessVerified, canaryRequested, "PHASE-1 CANARY FAILED");
    let pocHash: string | undefined;
    try {
      pocHash = createHash("sha256").update(readFileSync(bundle.pocPath)).digest("hex");
    } catch {
      pocHash = undefined;
    }
    if (!pocHash || pocHash !== bundle.pocSha256) {
      throw new Error(
        "PoC script changed since the runs — re-run PromoteFinding (the main agent must review the exact bytes that ran)",
      );
    }
    // The case target must still be the host the PoC ran against, and still
    // differ from the control target. The evidence proves nothing about a
    // target the case adopted after the runs.
    const targetRun = bundle.targetRuns[0];
    if (!current.target || current.target !== targetRun.target) {
      throw new Error(
        "Case target changed since the PoC runs — re-run PromoteFinding against the current target " +
          `(bundle target: ${targetRun.target}, case target: ${current.target ?? "(none)"}).`,
      );
    }
    if (!isIntra && current.target === bundle.controlTarget) {
      throw new Error(
        "Case target now equals the control target — the claimed impact is not target-dependent; " +
          "re-run PromoteFinding with a distinct control_target.",
      );
    }

    // The observation must predate the repro (provenance guard).
    const observation = current.evidenceItems?.find(
      (e: EvidenceItem) => e.role === "observation" && e.sha256,
    );
    if (observation && observation.createdAt > bundle.targetRuns[0].ranAt) {
      throw new Error(
        "Evidence chain invalid: the observation item was recorded after the PoC ran " +
          `(${observation.createdAt} > ${bundle.targetRuns[0].ranAt}). The observation must predate the repro.`,
      );
    }

    // Phase 1 proves the evidence floor. Phase 2 must freshly replay that same
    // request inside the main agent's ConfirmFinding call; a caller-provided
    // boolean is not accepted as proof of re-execution.
    assertMainAgentVerification(bundle, phase2Verification, isIntra);

    const reproductionItem: EvidenceItem = {
      id: `ev_${stableShortId(`${id}\nreproduction\n${targetRun.ranAt}`)}`,
      caseId: id,
      role: "reproduction",
      // The runner preserves each run's evidence.json in a durable dir
      // (.pi/poc-evidence/) — the artifact the hash was computed over still
      // exists, so the item stays artifact-backed and re-verifiable.
      artifactPath: targetRun.evidencePath ? basename(targetRun.evidencePath) : "evidence.json",
      sha256: targetRun.evidenceSha256,
      summary: `PoC evidence accepted (2 target runs + ${isIntra ? "same-host baseline" : "control"}; ${recorded.proofStrength}) — main agent semantic confirmation${verdict.model ? ` (${verdict.model})` : ""}`,
      createdAt: targetRun.ranAt,
    };

    const newEvidence =
      (current.evidence ? `${current.evidence}\n\n` : "") +
      `### PoC Execution Capture (${targetRun.ranAt})\n` +
      `- **Evidence sha256:** ${targetRun.evidenceSha256}\n` +
      `- **Target:** ${targetRun.target}\n` +
      `- **Machine evidence:** ${recorded.proofStrength} (a differential is not by itself proof of exploitation)\n` +
      `- **Main-agent reviewer:** ${verdict.model ?? "unknown model"} — semantic confirmation\n` +
      `#### Target Run Output\n\`\`\`\n${targetRun.output ?? ""}\n\`\`\``;

    const update: NormalizedCaseInput = {
      status: "confirmed",
      pocVerified: {
        path: bundle.pocPath,
        exitCode: targetRun.exitCode,
        ranAt: targetRun.ranAt,
        output: targetRun.output,
        sandbox: targetRun.sandbox,
        completed: true,
        outputComplete: true,
        mode: "poc",
        target: targetRun.target,
      },
      controlVerified:
        isIntra || !bundle.controlRun
          ? {
              path: bundle.pocPath,
              exitCode: targetRun.exitCode,
              ranAt: targetRun.ranAt,
              output: `intra-target baseline (same host): ${bundle.harnessVerified?.control?.note ?? "baseline did not satisfy the attack predicate"}`,
              sandbox: targetRun.sandbox,
              completed: true,
              outputComplete: true,
              mode: "baseline",
              target: targetRun.target,
            }
          : {
              path: bundle.controlPath ?? bundle.pocPath,
              exitCode: bundle.controlRun.exitCode,
              ranAt: bundle.controlRun.ranAt,
              output: bundle.controlRun.output,
              sandbox: bundle.controlRun.sandbox,
              completed: true,
              outputComplete: true,
              mode: "control",
              target: bundle.controlRun.target,
            },
      disconfirmation: verdict.disconfirmation_attempt,
      confirmerVerdict: recorded,
      pendingConfirmation: undefined,
      evidence: newEvidence,
    };

    const next = buildRecord(update, current);
    next.pendingConfirmation = undefined; // buildRecord's ?? existing keeps it; clear explicitly
    validateCase(next);
    insertEvidenceItem(db, reproductionItem);
    upsertCase(db, next);
    next.evidenceItems = [...(next.evidenceItems ?? []), reproductionItem];
    return { record: next, changed: true };
  });
}
