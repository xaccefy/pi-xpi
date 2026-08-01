/**
 * PipelineSubmit — the stage-output gate.
 *
 * The coordinator (model) dispatches stage subagents and submits their output
 * here. This module is where the pipeline stops trusting prose: it validates
 * stage output against the field specs mirrored from schemas/*.json, applies
 * the deterministic pre-filter (test paths, hallucinated files, trivial dedup),
 * and counts repair attempts. A stage cannot advance on an invalid output —
 * the answer is REPAIR (with field-level errors) or REJECTED, in code.
 *
 * KEEP IN SYNC with schemas/*.json at the repo root. The JSON schemas are the
 * canonical data contract for documentation; the SPECS table here is the
 * executable gate (a focused validator for exactly these six shapes — no
 * general JSON Schema engine).
 *
 * Persistence: .scratchpad/{run_id}/pipeline-submit.json
 *   { repairs: { "<stage>:<key>": n }, accepted_findings: FindingRef[] }
 */

import { createHash } from "node:crypto";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, isAbsolute, join, relative, resolve } from "node:path";
import {
  getRunDir,
  getScratchpadRoot,
  type ScratchpadPhase,
  scratchpad_write,
} from "./scratchpad.ts";

// ── Types ────────────────────────────────────────────────────────────

export const SUBMIT_STAGES = ["hunt", "trace", "skeptic", "validate", "chain", "report"] as const;
export type SubmitStage = (typeof SUBMIT_STAGES)[number];

export type SubmitVerdict = "accepted" | "repair" | "rejected";

export type SubmitResult = {
  verdict: SubmitVerdict;
  stage: SubmitStage;
  /** Field-level validation errors (repair) or rejection reason (rejected). */
  errors: string[];
  /** Repair attempt number (1-based) when verdict is repair. */
  repair_attempt?: number;
  /** Stable key identifying this finding's repair bucket. */
  key?: string;
  /** Set when hunt-stage dedup matched an accepted finding. */
  duplicate_of?: string;
  /** Scratchpad path the accepted output was written to. */
  artifact?: string;
};

type StageSpec = {
  /** Fields that must be present and non-empty. */
  required: {
    name: string;
    type: "string" | "integer" | "array" | "object";
    enum?: readonly string[];
    minItems?: number;
  }[];
  /** Exactly one of these locator field-sets must be fully present. */
  locatorXor?: [string[], string[]];
  /** Conditional requirements: when field equals value, these must be non-empty. */
  conditional?: { when: { field: string; equals: string }; require: string[] }[];
};

// ── Stage specs (mirror of schemas/*.json semantics) ─────────────────

const VULN_CLASSES = [
  "injection",
  "xss",
  "idor",
  "bola",
  "path-traversal",
  "ssrf",
  "command-injection",
  "deserialization",
  "auth-bypass",
  "privilege-escalation",
  "business-logic",
  "race-condition",
  "xxe",
  "ssti",
  "open-redirect",
  "information-disclosure",
  "crypto-weakness",
  "other",
] as const;

const SPECS: Record<SubmitStage, StageSpec> = {
  // schemas/stage-finding.json
  hunt: {
    required: [
      { name: "vuln_class", type: "string", enum: VULN_CLASSES },
      { name: "sink", type: "string" },
      { name: "entry_point", type: "string" },
      { name: "confidence", type: "string", enum: ["low", "medium", "high"] },
      { name: "evidence", type: "string" },
    ],
    // Source targets: file + line. Live targets: endpoint.
    locatorXor: [["file", "line"], ["endpoint"]],
  },
  // schemas/stage-trace.json
  trace: {
    required: [
      { name: "trace_result", type: "string", enum: ["REACHABLE", "UNREACHABLE"] },
      { name: "entry_point", type: "string" },
      { name: "call_chain", type: "array", minItems: 1 },
      { name: "defenses_checked", type: "array" },
      { name: "attacker_model", type: "string" },
    ],
    conditional: [
      { when: { field: "trace_result", equals: "REACHABLE" }, require: ["impact_if_reachable"] },
      { when: { field: "trace_result", equals: "UNREACHABLE" }, require: ["unreachable_reason"] },
    ],
  },
  // schemas/stage-skeptic.json
  skeptic: {
    required: [
      { name: "finding_id", type: "string" },
      { name: "verdict", type: "string", enum: ["CONFIRMED", "DISPROVEN"] },
      { name: "reasoning", type: "string" },
      { name: "evidence_reviewed", type: "array", minItems: 1 },
    ],
    conditional: [
      { when: { field: "verdict", equals: "DISPROVEN" }, require: ["disproval_reason"] },
    ],
  },
  // schemas/stage-validation.json
  validate: {
    required: [
      { name: "finding_id", type: "string" },
      { name: "status", type: "string", enum: ["confirmed", "killed", "reported"] },
      { name: "technique_used", type: "string" },
      { name: "detection_method", type: "string" },
    ],
    conditional: [
      {
        when: { field: "status", equals: "confirmed" },
        require: ["poc_path", "run_log", "evidence_extracted"],
      },
      { when: { field: "status", equals: "killed" }, require: ["kill_reason"] },
    ],
  },
  // schemas/stage-chain.json
  chain: {
    required: [
      { name: "chains", type: "array" },
      { name: "summary", type: "string" },
    ],
  },
  // schemas/stage-report.json
  report: {
    required: [
      { name: "target", type: "string" },
      { name: "pipeline_status", type: "string", enum: ["complete", "partial", "aborted"] },
      { name: "findings", type: "array" },
      { name: "coverage", type: "object" }, // patternProperties object, not array
      { name: "summary", type: "string" },
    ],
  },
};

const MAX_REPAIR_ATTEMPTS = 2;

// Segment-based test-path detection: matches "test", "__tests__", "specs",
// "e2e", "test-utils", "fixtures", ... anchored per path segment so
// "latest"/"contest"/"attest" do NOT match. A regex-only version missed
// leading underscores ("__tests__").
const TEST_SEGMENT_RE =
  /^[._-]*(tests?|specs?|e2e|fixtures?|mocks?|stubs?|examples?|samples?|test[-_]?data|test[-_]?utils)[._-]*$/i;
const TEST_FILE_RE =
  /([._-](test|spec|mock|fixture|stub|example|sample)\.[a-z0-9]+$|^test[-_]utils\.[a-z0-9]+$)/i;

/** Chain items: each must have title, severity, steps (≥2), narrative. */
const CHAIN_SEVERITIES = ["low", "medium", "high", "critical"] as const;

// ── Pre-filter constants (hunt stage only) ───────────────────────────

/**
 * Test/mock/example paths carry no real findings (mirrors VVAH S5). Exception
 * from VVAH deliberately not copied: hardcoded-creds-in-test-files — the
 * auditor can submit those under vuln_class "other"+bugClass documentation;
 * the gate errs on filtering noise.
 */

/** Trivial dedup: same file + vuln_class + line within this tolerance. */
const DEDUP_LINE_TOLERANCE = 10;

// ── Persistence ─────────────────────────────────────────────────────

type FindingRef = {
  key: string;
  file: string;
  line?: number;
  vuln_class: string;
};

type SubmitState = {
  repairs: Record<string, number>;
  accepted_findings: FindingRef[];
};

function statePath(runId: string): string {
  return join(getRunDir(runId), "pipeline-submit.json");
}

function readState(runId: string): SubmitState {
  const p = statePath(runId);
  if (!existsSync(p)) return { repairs: {}, accepted_findings: [] };
  try {
    const raw = JSON.parse(readFileSync(p, "utf8")) as Partial<SubmitState>;
    return {
      repairs: raw.repairs ?? {},
      accepted_findings: raw.accepted_findings ?? [],
    };
  } catch {
    return { repairs: {}, accepted_findings: [] };
  }
}

function writeState(runId: string, state: SubmitState): void {
  writeFileSync(statePath(runId), JSON.stringify(state, null, 2), "utf8");
}

/** Project root containing the scratchpad (file-existence checks resolve here). */
function projectRoot(): string {
  return dirname(getScratchpadRoot());
}

// ── Parsing ──────────────────────────────────────────────────────────

function parseOutput(output: unknown): { obj?: Record<string, unknown>; error?: string } {
  if (typeof output === "object" && output !== null && !Array.isArray(output)) {
    return { obj: output as Record<string, unknown> };
  }
  if (typeof output !== "string") {
    return { error: "output must be a JSON object or a JSON string" };
  }
  let text = output.trim();
  // Tolerate markdown code fences around the payload.
  text = text.replace(/^```(?:json)?\s*\n?/i, "").replace(/\n?```\s*$/i, "");
  try {
    const parsed = JSON.parse(text);
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
      return { error: "output must parse to a JSON object" };
    }
    return { obj: parsed as Record<string, unknown> };
  } catch (e) {
    return { error: `output is not valid JSON: ${(e as Error).message.slice(0, 120)}` };
  }
}

/** Stable repair-bucket key for a submission. */
/** Placeholder-y ids that carry no identity (observed in the wild: every
 * submission in a run keyed "false"). Trusting them makes distinct findings
 * share one key — one artifact name, one repair-budget bucket — so the last
 * write clobbers the rest. Fall back to the content hash instead. */
const JUNK_ID_RE =
  /^(false|true|null|none|undefined|n\/?a|na|unknown|missing|empty|todo|tbd|pending|not-set)$/i;

function submissionKey(stage: SubmitStage, obj: Record<string, unknown>): string {
  const candidate =
    (typeof obj.finding_id === "string" && obj.finding_id.trim()) ||
    (typeof obj.title === "string" && obj.title.trim()) ||
    (typeof obj.id === "string" && obj.id.trim());
  const id =
    candidate && candidate.length >= 3 && !JUNK_ID_RE.test(candidate) ? candidate : undefined;
  const tail = id ?? createHash("sha1").update(JSON.stringify(obj)).digest("hex").slice(0, 8);
  return `${stage}:${tail}`;
}

// ── Validation ──────────────────────────────────────────────────────

function isNonEmptyString(v: unknown): v is string {
  return typeof v === "string" && v.trim().length > 0;
}

function validateStage(stage: SubmitStage, obj: Record<string, unknown>): string[] {
  const spec = SPECS[stage];
  const errors: string[] = [];

  for (const field of spec.required) {
    const v = obj[field.name];
    if (field.type === "string") {
      if (!isNonEmptyString(v)) {
        errors.push(`${field.name}: missing or empty string`);
        continue;
      }
    } else if (field.type === "object") {
      if (typeof v !== "object" || v === null || Array.isArray(v)) {
        errors.push(`${field.name}: missing or not an object`);
        continue;
      }
    } else if (field.type === "integer") {
      if (typeof v !== "number" || !Number.isInteger(v)) {
        errors.push(`${field.name}: missing or not an integer`);
        continue;
      }
    } else {
      if (!Array.isArray(v)) {
        errors.push(`${field.name}: missing or not an array`);
        continue;
      }
      if (field.minItems !== undefined && v.length < field.minItems) {
        errors.push(`${field.name}: needs at least ${field.minItems} item(s), got ${v.length}`);
        continue;
      }
    }
    if (field.enum && !field.enum.includes(v as never)) {
      errors.push(`${field.name}: "${String(v)}" not in { ${field.enum.join(" | ")} }`);
    }
  }

  if (spec.locatorXor) {
    const [a, b] = spec.locatorXor;
    const hasSet = (set: string[]) =>
      set.every((f) => (f === "line" ? Number.isInteger(obj[f]) : isNonEmptyString(obj[f])));
    const hasA = hasSet(a);
    const hasB = hasSet(b);
    if (hasA === hasB) {
      errors.push(
        `locator: provide exactly one of { ${a.join("+")} } (source) or { ${b.join("+")} } (live)`,
      );
    }
    if (hasA && typeof obj.line === "number" && obj.line < 1) {
      errors.push("line: must be >= 1");
    }
  }

  for (const cond of spec.conditional ?? []) {
    if (obj[cond.when.field] === cond.when.equals) {
      for (const name of cond.require) {
        if (!isNonEmptyString(obj[name])) {
          errors.push(`${name}: required when ${cond.when.field} = ${cond.when.equals}`);
        }
      }
    }
  }

  // Chain items have their own inner contract (≥2 steps, severity enum).
  if (stage === "chain" && Array.isArray(obj.chains)) {
    obj.chains.forEach((c, i) => {
      const chain = c as Record<string, unknown>;
      if (!isNonEmptyString(chain.title)) errors.push(`chains[${i}].title: missing or empty`);
      if (
        !isNonEmptyString(chain.severity) ||
        !(CHAIN_SEVERITIES as readonly string[]).includes(chain.severity)
      ) {
        errors.push(`chains[${i}].severity: must be one of { ${CHAIN_SEVERITIES.join(" | ")} }`);
      }
      if (!Array.isArray(chain.steps) || chain.steps.length < 2) {
        errors.push(`chains[${i}].steps: needs at least 2 case IDs`);
      }
      if (!isNonEmptyString(chain.narrative))
        errors.push(`chains[${i}].narrative: missing or empty`);
    });
  }

  return errors;
}

// ── Pre-filter + dedup (hunt only) ──────────────────────────────────

function prefilterHunt(obj: Record<string, unknown>): string | null {
  const file = typeof obj.file === "string" ? obj.file : undefined;
  if (!file) return null; // live target: endpoint locator, nothing to filter
  const normalized = file.replace(/^\.?\//, "");
  const segments = normalized.split("/");
  if (segments.some((s) => TEST_SEGMENT_RE.test(s)) || TEST_FILE_RE.test(normalized)) {
    return (
      `test-path filter: "${file}" matches test/fixture/mock paths — findings in ` +
      `test code are noise. If this is a deliberately-shipped test credential, ` +
      `re-submit documenting why it ships to production.`
    );
  }
  const root = projectRoot();
  const abs = isAbsolute(normalized) ? resolve(normalized) : resolve(root, normalized);
  // Containment: resolved path must stay inside the project, otherwise a
  // "finding" can point at ../ or absolute files outside the target repo.
  const rel = relative(root, abs);
  if (rel.startsWith("..") || isAbsolute(rel)) {
    return (
      `containment filter: "${file}" resolves outside the project root (${root}). ` +
      `Findings must reference files inside the target repository.`
    );
  }
  if (!existsSync(abs)) {
    return (
      `file-existence filter: "${file}" does not exist under the project root ` +
      `(${root}). Hallucinated paths are rejected outright.`
    );
  }
  return null;
}

function dedupHunt(state: SubmitState, obj: Record<string, unknown>): { duplicateOf?: string } {
  const file = typeof obj.file === "string" ? obj.file.replace(/^\.?\//, "") : undefined;
  const vulnClass = typeof obj.vuln_class === "string" ? obj.vuln_class : undefined;
  const line = typeof obj.line === "number" ? obj.line : undefined;
  if (!file || !vulnClass) return {};
  for (const accepted of state.accepted_findings) {
    if (accepted.vuln_class !== vulnClass) continue;
    if (accepted.file !== file) continue;
    if (
      line !== undefined &&
      accepted.line !== undefined &&
      Math.abs(line - accepted.line) > DEDUP_LINE_TOLERANCE
    ) {
      continue;
    }
    return { duplicateOf: accepted.key };
  }
  return {};
}

// ── Public API ───────────────────────────────────────────────────────

const STAGE_TO_PHASE: Record<SubmitStage, ScratchpadPhase> = {
  hunt: "hunt",
  trace: "trace",
  skeptic: "skeptic",
  validate: "validate",
  chain: "chain",
  report: "report",
};

export function pipeline_submit(runId: string, stage: SubmitStage, output: unknown): SubmitResult {
  const parsed = parseOutput(output);
  if (parsed.error || !parsed.obj) {
    const state = readState(runId);
    const key = `${stage}:unparseable`;
    state.repairs[key] = (state.repairs[key] ?? 0) + 1;
    const attempt = state.repairs[key];
    // Persist before BOTH returns — otherwise unparseable output bypasses the
    // repair budget forever (counter never hits disk on the rejected path).
    writeState(runId, state);
    if (attempt > MAX_REPAIR_ATTEMPTS) {
      return { verdict: "rejected", stage, errors: [parsed.error ?? "unparseable"], key };
    }
    return {
      verdict: "repair",
      stage,
      errors: [parsed.error ?? "unparseable"],
      repair_attempt: attempt,
      key,
    };
  }

  const obj = parsed.obj;
  const key = submissionKey(stage, obj);

  const errors = validateStage(stage, obj);
  if (errors.length > 0) {
    const state = readState(runId);
    state.repairs[key] = (state.repairs[key] ?? 0) + 1;
    const attempt = state.repairs[key];
    if (attempt > MAX_REPAIR_ATTEMPTS) {
      writeState(runId, state);
      return {
        verdict: "rejected",
        stage,
        errors: [...errors, `repair budget exhausted (${MAX_REPAIR_ATTEMPTS} attempts)`],
        key,
      };
    }
    writeState(runId, state);
    return { verdict: "repair", stage, errors, repair_attempt: attempt, key };
  }

  // Hunt stage: deterministic noise gates before acceptance.
  if (stage === "hunt") {
    const filtered = prefilterHunt(obj);
    if (filtered) {
      return { verdict: "rejected", stage, errors: [filtered], key };
    }
    const state = readState(runId);
    const { duplicateOf } = dedupHunt(state, obj);
    if (duplicateOf) {
      return {
        verdict: "rejected",
        stage,
        errors: [
          `trivial dedup: same file + vuln_class within ${DEDUP_LINE_TOLERANCE} lines of accepted finding ${duplicateOf}`,
        ],
        key,
        duplicate_of: duplicateOf,
      };
    }
    if (typeof obj.file === "string" && typeof obj.vuln_class === "string") {
      state.accepted_findings.push({
        key,
        file: obj.file.replace(/^\.?\//, ""),
        line: typeof obj.line === "number" ? obj.line : undefined,
        vuln_class: obj.vuln_class,
      });
      writeState(runId, state);
    }
  }

  const artifact = scratchpad_write(
    runId,
    STAGE_TO_PHASE[stage],
    `${key.replace(/[^a-zA-Z0-9._:-]/g, "_")}.json`,
    JSON.stringify(obj, null, 2),
  );
  return { verdict: "accepted", stage, errors: [], key, artifact };
}
