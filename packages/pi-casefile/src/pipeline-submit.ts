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
import { existsSync, realpathSync } from "node:fs";
import { basename, dirname, isAbsolute, join, relative, resolve } from "node:path";
import { KILL_REASON_VALUES } from "./ledger.ts";
import {
  assertSafeRegularFile,
  assertSafeStateDirectory,
  readSafeFile,
  writeSafeFileAtomic,
} from "./safe-state.ts";
import { getRunDir, getScratchpadRoot, scratchpad_write } from "./scratchpad.ts";

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
  /** Exact top-level field allowlist; mirrors additionalProperties:false. */
  allowed: readonly string[];
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

// Exported for test/pipeline-submit-schema-parity.test.ts (drift guard
// against schemas/*.json — the two are kept as mirrors of each other).
export const SPECS: Record<SubmitStage, StageSpec> = {
  // schemas/stage-finding.json
  hunt: {
    allowed: [
      "vuln_class",
      "file",
      "line",
      "endpoint",
      "sink",
      "entry_point",
      "confidence",
      "evidence",
      "attacker_model",
      "subsystem",
    ],
    required: [
      { name: "vuln_class", type: "string" },
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
    allowed: [
      "trace_result",
      "entry_point",
      "call_chain",
      "defenses_checked",
      "attacker_model",
      "impact_if_reachable",
      "unreachable_reason",
      "uncertainty_reason",
    ],
    required: [
      { name: "trace_result", type: "string", enum: ["REACHABLE", "UNREACHABLE", "UNDETERMINED"] },
      { name: "entry_point", type: "string" },
      { name: "call_chain", type: "array", minItems: 1 },
      { name: "defenses_checked", type: "array" },
      { name: "attacker_model", type: "string" },
    ],
    conditional: [
      { when: { field: "trace_result", equals: "REACHABLE" }, require: ["impact_if_reachable"] },
      { when: { field: "trace_result", equals: "UNREACHABLE" }, require: ["unreachable_reason"] },
      { when: { field: "trace_result", equals: "UNDETERMINED" }, require: ["uncertainty_reason"] },
    ],
  },
  // schemas/stage-skeptic.json
  skeptic: {
    allowed: [
      "finding_id",
      "verdict",
      "reasoning",
      "evidence_reviewed",
      "disconfirmation_attempt",
      "disproval_reason",
      "uncertainty_reason",
    ],
    required: [
      { name: "finding_id", type: "string" },
      { name: "verdict", type: "string", enum: ["CONFIRMED", "DISPROVEN", "UNDETERMINED"] },
      { name: "reasoning", type: "string" },
      { name: "evidence_reviewed", type: "array", minItems: 1 },
    ],
    conditional: [
      { when: { field: "verdict", equals: "DISPROVEN" }, require: ["disproval_reason"] },
      {
        // A CONFIRMED verdict must carry the skeptic's own failed disproof —
        // the workflow makes it the case's disconfirmation. "Could not
        // disprove" alone is not an attempt.
        when: { field: "verdict", equals: "CONFIRMED" },
        require: ["disconfirmation_attempt"],
      },
      { when: { field: "verdict", equals: "UNDETERMINED" }, require: ["uncertainty_reason"] },
    ],
  },
  // schemas/stage-validation.json
  validate: {
    allowed: [
      "finding_id",
      "status",
      "technique_used",
      "detection_method",
      "poc_path",
      "run_log",
      "evidence_extracted",
      "kill_reason",
      "refinement_attempts",
    ],
    required: [
      { name: "finding_id", type: "string" },
      {
        name: "status",
        type: "string",
        enum: ["pending_confirmation", "killed", "reported"],
      },
      { name: "technique_used", type: "string" },
      { name: "detection_method", type: "string" },
    ],
    conditional: [
      {
        when: { field: "status", equals: "pending_confirmation" },
        require: ["poc_path", "run_log", "evidence_extracted"],
      },
      { when: { field: "status", equals: "killed" }, require: ["kill_reason"] },
    ],
  },
  // schemas/stage-chain.json
  chain: {
    allowed: ["chains", "summary", "tokens_input", "tokens_output"],
    required: [
      { name: "chains", type: "array" },
      { name: "summary", type: "string" },
    ],
  },
  // schemas/stage-report.json
  report: {
    allowed: [
      "target",
      "pipeline_status",
      "total_tokens",
      "findings",
      "chains",
      "coverage",
      "summary",
      "patches_applied",
    ],
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
 * auditor can submit those under the precise class it decides fits the issue;
 * the gate errs on filtering noise.
 */

/** Trivial dedup: same file + vuln_class + line within this tolerance. */
const DEDUP_LINE_TOLERANCE = 10;

// ── Persistence ─────────────────────────────────────────────────────

type FindingRef = {
  key: string;
  file: string;
  line?: number;
  endpoint?: string;
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
  assertSafeStateDirectory(projectRoot(), [".scratchpad", basename(dirname(p))]);
  assertSafeRegularFile(p, "Pipeline state");
  const raw = JSON.parse(
    readSafeFile(p, "Pipeline state").toString("utf8"),
  ) as Partial<SubmitState>;
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    throw new Error(`Corrupt pipeline-submit state for ${runId}: root must be an object`);
  }
  const repairs = raw.repairs ?? {};
  if (typeof repairs !== "object" || repairs === null || Array.isArray(repairs)) {
    throw new Error(`Corrupt pipeline-submit state for ${runId}: repairs must be an object`);
  }
  for (const [k, v] of Object.entries(repairs)) {
    if (typeof k !== "string" || typeof v !== "number" || !Number.isInteger(v) || v < 0) {
      throw new Error(`Corrupt pipeline-submit state for ${runId}: invalid repair counter`);
    }
  }
  const accepted = raw.accepted_findings ?? [];
  if (!Array.isArray(accepted)) {
    throw new Error(
      `Corrupt pipeline-submit state for ${runId}: accepted_findings must be an array`,
    );
  }
  for (const [i, item] of accepted.entries()) {
    if (typeof item !== "object" || item === null || Array.isArray(item)) {
      throw new Error(
        `Corrupt pipeline-submit state for ${runId}: accepted_findings[${i}] invalid`,
      );
    }
  }
  return {
    repairs: repairs as Record<string, number>,
    accepted_findings: accepted as FindingRef[],
  };
}

function writeState(runId: string, state: SubmitState): void {
  const p = statePath(runId);
  assertSafeStateDirectory(projectRoot(), [".scratchpad", basename(dirname(p))]);
  writeSafeFileAtomic(p, JSON.stringify(state, null, 2));
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

function requireStringArray(errors: string[], path: string, value: unknown, minItems = 0): void {
  if (!Array.isArray(value)) {
    errors.push(`${path}: missing or not an array`);
    return;
  }
  if (value.length < minItems) errors.push(`${path}: needs at least ${minItems} item(s)`);
  value.forEach((item, i) => {
    if (!isNonEmptyString(item)) errors.push(`${path}[${i}]: missing or empty string`);
  });
}

function asObject(value: unknown): Record<string, unknown> | undefined {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;
}

function validateReport(errors: string[], obj: Record<string, unknown>): void {
  const findingSeverities = ["info", "low", "medium", "high", "critical"];
  if (Array.isArray(obj.findings)) {
    obj.findings.forEach((item, i) => {
      const finding = asObject(item);
      if (!finding) {
        errors.push(`findings[${i}]: not an object`);
        return;
      }
      for (const field of ["id", "vuln_class", "severity", "status"] as const) {
        if (!isNonEmptyString(finding[field]))
          errors.push(`findings[${i}].${field}: missing or empty`);
      }
      if (!isNonEmptyString(finding.file) && !isNonEmptyString(finding.endpoint)) {
        errors.push(`findings[${i}]: provide file or endpoint`);
      }
      if (isNonEmptyString(finding.severity) && !findingSeverities.includes(finding.severity)) {
        errors.push(`findings[${i}].severity: invalid value`);
      }
      if (isNonEmptyString(finding.status) && !["confirmed", "reported"].includes(finding.status)) {
        errors.push(`findings[${i}].status: invalid value`);
      }
      if (finding.chain_with !== undefined)
        requireStringArray(errors, `findings[${i}].chain_with`, finding.chain_with);
    });
  }

  const coverage = asObject(obj.coverage);
  if (coverage) {
    const allowed = ["COVERED", "SKIPPED", "NOT_FOUND", "INCOMPLETE"];
    for (const [key, value] of Object.entries(coverage)) {
      if (!key.trim() || /[\r\n]/.test(key)) errors.push(`coverage.${key}: invalid class key`);
      if (typeof value !== "string" || !allowed.includes(value)) {
        errors.push(`coverage.${key}: must be one of { ${allowed.join(" | ")} }`);
      }
    }
  }

  if (obj.chains !== undefined) {
    if (!Array.isArray(obj.chains)) {
      errors.push("chains: not an array");
    } else {
      obj.chains.forEach((item, i) => {
        const chain = asObject(item);
        if (!chain) {
          errors.push(`chains[${i}]: not an object`);
          return;
        }
        if (chain.title !== undefined && !isNonEmptyString(chain.title))
          errors.push(`chains[${i}].title: missing or empty`);
        if (chain.steps !== undefined)
          requireStringArray(errors, `chains[${i}].steps`, chain.steps);
        if (
          chain.severity !== undefined &&
          (!isNonEmptyString(chain.severity) ||
            !(CHAIN_SEVERITIES as readonly string[]).includes(chain.severity))
        ) {
          errors.push(`chains[${i}].severity: invalid value`);
        }
        if (chain.blocked_by_controls !== undefined) {
          requireStringArray(errors, `chains[${i}].blocked_by_controls`, chain.blocked_by_controls);
        }
      });
    }
  }

  if (obj.patches_applied !== undefined) {
    if (!Array.isArray(obj.patches_applied)) {
      errors.push("patches_applied: not an array");
    } else {
      obj.patches_applied.forEach((item, i) => {
        const patch = asObject(item);
        if (!patch) {
          errors.push(`patches_applied[${i}]: not an object`);
          return;
        }
        for (const field of ["finding_id", "diff_summary", "re_attack_result"] as const) {
          if (patch[field] !== undefined && !isNonEmptyString(patch[field])) {
            errors.push(`patches_applied[${i}].${field}: missing or empty`);
          }
        }
      });
    }
  }
}

function resolveProjectPath(input: string): { abs: string; rel: string } {
  const root = projectRoot();
  const trimmed = input.trim();
  const relativeInput = trimmed.replace(/^\.\//, "");
  const abs = isAbsolute(trimmed) ? resolve(trimmed) : resolve(root, relativeInput);
  return { abs, rel: relative(root, abs) };
}

function validateStage(stage: SubmitStage, obj: Record<string, unknown>): string[] {
  const spec = SPECS[stage];
  const errors: string[] = [];

  const allowedFields = new Set(spec.allowed);
  for (const name of Object.keys(obj)) {
    if (!allowedFields.has(name)) errors.push(`${name}: unknown top-level field`);
  }

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

  if (stage === "trace") {
    requireStringArray(errors, "call_chain", obj.call_chain, 1);
    if (Array.isArray(obj.defenses_checked)) {
      obj.defenses_checked.forEach((item, i) => {
        const defense = asObject(item);
        if (!defense) {
          errors.push(`defenses_checked[${i}]: not an object`);
          return;
        }
        if (!isNonEmptyString(defense.defense))
          errors.push(`defenses_checked[${i}].defense: missing or empty`);
        if (!isNonEmptyString(defense.location))
          errors.push(`defenses_checked[${i}].location: missing or empty`);
        if (
          !isNonEmptyString(defense.verdict) ||
          !["bypassed", "blocked", "not-present"].includes(defense.verdict)
        ) {
          errors.push(`defenses_checked[${i}].verdict: must be bypassed, blocked, or not-present`);
        }
      });
    }
  }

  if (stage === "skeptic") {
    requireStringArray(errors, "evidence_reviewed", obj.evidence_reviewed, 1);
    if (obj.verdict === "DISPROVEN" && isNonEmptyString(obj.disproval_reason)) {
      if (!(KILL_REASON_VALUES as readonly string[]).includes(obj.disproval_reason)) {
        errors.push("disproval_reason: invalid value");
      }
    }
  }

  if (stage === "validate") {
    if (obj.status === "killed" && isNonEmptyString(obj.kill_reason)) {
      if (!(KILL_REASON_VALUES as readonly string[]).includes(obj.kill_reason)) {
        errors.push("kill_reason: invalid value");
      }
    }
    if (obj.status === "pending_confirmation" && isNonEmptyString(obj.poc_path)) {
      // A phase-1 validation submission must point at a PoC file
      // that actually exists in the project — same file-existence filter hunt
      // findings get. Otherwise fabricated run logs pass the stage gate.
      const raw = obj.poc_path as string;
      const { abs, rel } = resolveProjectPath(raw);
      if (rel.startsWith("..") || isAbsolute(rel)) {
        errors.push("poc_path: must resolve inside the project root");
      } else if (!existsSync(abs)) {
        errors.push(`poc_path: "${raw}" does not exist under the project root`);
      }
    }
    if (
      obj.refinement_attempts !== undefined &&
      (!Number.isInteger(obj.refinement_attempts) ||
        (obj.refinement_attempts as number) < 1 ||
        (obj.refinement_attempts as number) > 3)
    ) {
      errors.push("refinement_attempts: must be an integer from 1 to 3");
    }
  }

  if (stage === "chain" && Array.isArray(obj.chains)) {
    obj.chains.forEach((c, i) => {
      const chain = asObject(c);
      if (!chain) {
        errors.push(`chains[${i}]: not an object`);
        return;
      }
      if (!isNonEmptyString(chain.title)) errors.push(`chains[${i}].title: missing or empty`);
      if (
        !isNonEmptyString(chain.severity) ||
        !(CHAIN_SEVERITIES as readonly string[]).includes(chain.severity)
      ) {
        errors.push(`chains[${i}].severity: must be one of { ${CHAIN_SEVERITIES.join(" | ")} }`);
      }
      requireStringArray(errors, `chains[${i}].steps`, chain.steps, 2);
      if (chain.blocked_by_controls !== undefined) {
        requireStringArray(errors, `chains[${i}].blocked_by_controls`, chain.blocked_by_controls);
      }
      if (!isNonEmptyString(chain.narrative))
        errors.push(`chains[${i}].narrative: missing or empty`);
    });
  }

  if (stage === "report") validateReport(errors, obj);

  return errors;
}

// ── Pre-filter + dedup (hunt only) ──────────────────────────────────

function prefilterHunt(obj: Record<string, unknown>): string | null {
  const file = typeof obj.file === "string" ? obj.file : undefined;
  if (!file) return null; // live target: endpoint locator, nothing to filter
  const root = projectRoot();
  const { abs, rel } = resolveProjectPath(file);
  // Containment: resolved path must stay inside the project, otherwise a
  // "finding" can point at ../ or absolute files outside the target repo.
  if (rel.startsWith("..") || isAbsolute(rel)) {
    return (
      `containment filter: "${file}" resolves outside the project root (${root}). ` +
      `Findings must reference files inside the target repository.`
    );
  }
  const segments = rel.split("/");
  if (segments.some((s) => TEST_SEGMENT_RE.test(s)) || TEST_FILE_RE.test(rel)) {
    return (
      `test-path filter: "${file}" matches test/fixture/mock paths — findings in ` +
      `test code are noise. If this is a deliberately-shipped test credential, ` +
      `re-submit documenting why it ships to production.`
    );
  }
  // Symlink containment (same defense as the PoC runner): resolve() is
  // lexical, and existsSync() dereferences symlinks — a workspace symlink to
  // /etc (ln -s /etc etc-link) would otherwise pass both checks and let a
  // "finding" point at host paths outside the project.
  let real: string;
  try {
    real = realpathSync(abs);
  } catch {
    return `file-existence filter: "${file}" cannot be resolved under the project root (${root}).`;
  }
  const realRel = relative(root, real);
  if (realRel.startsWith("..") || isAbsolute(realRel)) {
    return (
      `containment filter: "${file}" resolves through a symlink to outside the project root ` +
      `(${real}). Symlinked files outside ${root} are rejected.`
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
  const file =
    typeof obj.file === "string"
      ? resolveProjectPath(obj.file).rel.replace(/^\.\//, "")
      : undefined;
  const endpoint = typeof obj.endpoint === "string" ? obj.endpoint.trim() : undefined;
  const vulnClass = typeof obj.vuln_class === "string" ? obj.vuln_class : undefined;
  const line = typeof obj.line === "number" ? obj.line : undefined;
  if (!vulnClass) return {};
  for (const accepted of state.accepted_findings) {
    if (accepted.vuln_class !== vulnClass) continue;
    // Live locator: same endpoint + class is the same finding (re-submissions
    // after a repair must not be accepted repeatedly).
    if (!file && endpoint !== undefined) {
      if (accepted.endpoint === endpoint) return { duplicateOf: accepted.key };
      continue;
    }
    if (!file || accepted.file !== file) continue;
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
    if (typeof obj.vuln_class === "string") {
      const isFileFinding = typeof obj.file === "string";
      const isEndpointFinding = !isFileFinding && typeof obj.endpoint === "string";
      if (isFileFinding || isEndpointFinding) {
        state.accepted_findings.push({
          key,
          file: isFileFinding
            ? resolveProjectPath(obj.file as string).rel.replace(/^\.\//, "")
            : "",
          line: typeof obj.line === "number" ? obj.line : undefined,
          endpoint: isEndpointFinding ? (obj.endpoint as string).trim() : undefined,
          vuln_class: obj.vuln_class,
        });
      }
      writeState(runId, state);
    }
  }

  // Submit stages are a subset of scratchpad phases, so the stage name IS
  // the phase directory. The filename gets a content hash: distinct findings
  // sharing one plausible id (the stable repair-bucket key) must not clobber
  // each other's accepted artifact.
  const json = JSON.stringify(obj, null, 2);
  const contentHash = createHash("sha1").update(json).digest("hex").slice(0, 8);
  const artifact = scratchpad_write(
    runId,
    stage,
    `${key.replace(/[^a-zA-Z0-9._:-]/g, "_")}-${contentHash}.json`,
    json,
  );
  return { verdict: "accepted", stage, errors: [], key, artifact };
}
