/**
 * Evidence contract for PoC confirmation.
 *
 * A PoC must write `evidence.json` into $PI_POC_EVIDENCE_DIR: a nonce-bound,
 * schema-validated record of what it claims and the request spec the
 * confirmer re-executes. The harness validates the file and binds it to the
 * run via $PI_POC_NONCE (per-run random — copy-pasted evidence fails the
 * nonce check). The confirmer agent judges semantics; the ledger commits
 * only on a CONFIRMED verdict with a target-only differential.
 *
 * Exit codes and verification markers are DIAGNOSTICS, not gates.
 */

// ── PoC evidence (written by the PoC script) ────────────────────────

export type VerifyExpect = {
  /** Acceptable HTTP statuses for the verify request (empty = any). */
  status?: number[];
  /** Substrings the verify response must contain. */
  body_contains?: string[];
  /** Regexes the verify response must match. */
  body_regex?: string[];
};

export type PoCEvidence = {
  /** Must equal the run's PI_POC_NONCE (harness-verified). */
  nonce: string;
  /** What the exploit asserts, e.g. "read /etc/passwd of target". */
  claim: string;
  /** Request spec the confirmer re-executes with its own HTTP client. */
  verify: {
    method: string;
    url: string;
    headers?: Record<string, string>;
    body?: string;
    expect: VerifyExpect;
  };
  /** What the script itself saw — corroboration only, never proof. */
  observations: string[];
  /** Optional baseline request for the confirmer's differential replay. */
  baseline?: {
    method: string;
    url: string;
    headers?: Record<string, string>;
    body?: string;
    body_contains?: string[];
  };
};

const HTTP_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function nonEmptyString(v: unknown): v is string {
  return typeof v === "string" && v.trim().length > 0;
}

function stringArray(v: unknown): v is string[] {
  return Array.isArray(v) && v.every((x) => nonEmptyString(x));
}

/** Header map: string keys, string values, no CR/LF (header injection guard). */
function headerRecord(v: unknown): v is Record<string, string> {
  if (!isRecord(v)) return false;
  return Object.entries(v).every(
    ([k, value]) => typeof k === "string" && typeof value === "string" && !/[\r\n]/.test(value),
  );
}

/** http(s) URL with a non-empty host — prefix-only matches would accept garbage. */
function httpUrl(v: unknown): v is string {
  if (!nonEmptyString(v)) return false;
  let parsed: URL;
  try {
    parsed = new URL(v);
  } catch {
    return false;
  }
  return (
    (parsed.protocol === "http:" || parsed.protocol === "https:") && parsed.hostname.length > 0
  );
}

/** body_regex entries must compile — an invalid regex would poison the confirmer's replay. */
function validRegexArray(v: unknown): v is string[] {
  return (
    stringArray(v) &&
    v.every((re) => {
      try {
        new RegExp(re);
        return true;
      } catch {
        return false;
      }
    })
  );
}

/**
 * Parse + validate a PoC's evidence.json. Returns the validated object or a
 * field-level error. Deliberately strict: an invalid evidence file means the
 * run failed the contract, which blocks promotion.
 */
export function parsePoCEvidence(
  raw: unknown,
): { ok: true; evidence: PoCEvidence } | { ok: false; error: string } {
  if (!isRecord(raw)) return { ok: false, error: "evidence.json must be a JSON object" };
  if (!nonEmptyString(raw.nonce)) return { ok: false, error: "evidence.json missing nonce" };
  if (!nonEmptyString(raw.claim)) return { ok: false, error: "evidence.json missing claim" };
  const verify = raw.verify;
  if (!isRecord(verify)) return { ok: false, error: "evidence.json verify must be an object" };
  if (!nonEmptyString(verify.method) || !HTTP_METHODS.includes(verify.method.toUpperCase())) {
    return {
      ok: false,
      error: `evidence.json verify.method must be one of ${HTTP_METHODS.join("|")}`,
    };
  }
  if (!httpUrl(verify.url)) {
    return { ok: false, error: "evidence.json verify.url must be an http(s) URL with a host" };
  }
  if (verify.headers !== undefined && !headerRecord(verify.headers)) {
    return {
      ok: false,
      error: "evidence.json verify.headers must be an object of string values without CR/LF",
    };
  }
  if (verify.body !== undefined && typeof verify.body !== "string") {
    return { ok: false, error: "evidence.json verify.body must be a string" };
  }
  const expect = verify.expect;
  if (!isRecord(expect))
    return { ok: false, error: "evidence.json verify.expect must be an object" };
  if (
    expect.status !== undefined &&
    (!Array.isArray(expect.status) || !expect.status.every((s) => Number.isInteger(s)))
  ) {
    return { ok: false, error: "evidence.json verify.expect.status must be an integer array" };
  }
  if (expect.body_contains !== undefined && !stringArray(expect.body_contains)) {
    return { ok: false, error: "evidence.json verify.expect.body_contains must be a string array" };
  }
  if (expect.body_regex !== undefined && !validRegexArray(expect.body_regex)) {
    return {
      ok: false,
      error: "evidence.json verify.expect.body_regex must be an array of compilable regexes",
    };
  }
  if (!Array.isArray(raw.observations) || !raw.observations.every((o) => typeof o === "string")) {
    return { ok: false, error: "evidence.json observations must be a string array" };
  }
  if (raw.baseline !== undefined) {
    const b = raw.baseline;
    if (!isRecord(b)) return { ok: false, error: "evidence.json baseline must be an object" };
    if (
      !nonEmptyString(b.method) ||
      !HTTP_METHODS.includes(b.method.toUpperCase()) ||
      !httpUrl(b.url)
    ) {
      return {
        ok: false,
        error: "evidence.json baseline needs an http(s) url and a valid HTTP method",
      };
    }
    if (b.headers !== undefined && !headerRecord(b.headers)) {
      return {
        ok: false,
        error: "evidence.json baseline.headers must be an object of string values without CR/LF",
      };
    }
    if (b.body !== undefined && typeof b.body !== "string") {
      return { ok: false, error: "evidence.json baseline.body must be a string" };
    }
    if (b.body_contains !== undefined && !stringArray(b.body_contains)) {
      return { ok: false, error: "evidence.json baseline.body_contains must be a string array" };
    }
  }
  return { ok: true, evidence: raw as unknown as PoCEvidence };
}

/** Bind evidence to its run: the nonce must equal the harness-generated one. */
export function evidenceNonceMatches(evidence: PoCEvidence, nonce: string): boolean {
  return evidence.nonce === nonce;
}

/**
 * The comparator for determinism + differential checks. Strips the nonce
 * (per-run by design) and observations (free-form, run-dependent) — the
 * load-bearing shape is claim + verify + baseline.
 */
export function normalizeEvidence(e: PoCEvidence): string {
  return JSON.stringify({ claim: e.claim, verify: e.verify, baseline: e.baseline });
}

// ── Confirmer verdict (written by the confirmer subagent) ───────────

export const CONFIRM_VERDICT_VALUES = ["CONFIRMED", "NOT_CONFIRMED"] as const;
export type ConfirmVerdict = (typeof CONFIRM_VERDICT_VALUES)[number];

export const CONFIRM_DIFFERENTIAL_VALUES = [
  "target_only",
  "both",
  "control_only",
  "unclear",
] as const;
export type ConfirmDifferential = (typeof CONFIRM_DIFFERENTIAL_VALUES)[number];

export const SEVERITY_MATCH_VALUES = ["under", "over", "ok"] as const;

export type ConfirmerVerdict = {
  verdict: ConfirmVerdict;
  reasoning: string;
  /** Files/evidence the confirmer actually reviewed. */
  evidence_reviewed: string[];
  /** True iff the confirmer re-sent the verify request itself. Mandatory for CONFIRMED. */
  re_executed: boolean;
  /** What the confirmer observed when re-executing. */
  re_execution_note?: string;
  /** Target vs control evidence comparison. CONFIRMED requires target_only. */
  differential: ConfirmDifferential;
  /** Claimed severity vs what the evidence shows. */
  severity_match?: (typeof SEVERITY_MATCH_VALUES)[number];
  /** The confirmer's own failed attempt to disprove — becomes the case's disconfirmation. */
  disconfirmation_attempt?: string;
  /** Which model judged (recorded for the accuracy ledger). */
  model?: string;
};

/**
 * Validate a confirmer verdict. CONFIRMED additionally requires a target-only
 * differential, a re-execution, and a disconfirmation attempt — a verdict
 * that skips any of those cannot promote.
 */
export function validateConfirmerVerdict(
  raw: unknown,
): { ok: true; verdict: ConfirmerVerdict } | { ok: false; error: string } {
  if (!isRecord(raw)) return { ok: false, error: "verdict must be a JSON object" };
  if (!nonEmptyString(raw.verdict) || !CONFIRM_VERDICT_VALUES.includes(raw.verdict as never)) {
    return {
      ok: false,
      error: `verdict must be one of ${CONFIRM_VERDICT_VALUES.join(" | ")}`,
    };
  }
  if (!nonEmptyString(raw.reasoning)) return { ok: false, error: "verdict reasoning required" };
  if (!Array.isArray(raw.evidence_reviewed) || raw.evidence_reviewed.length === 0) {
    return { ok: false, error: "verdict evidence_reviewed must be a non-empty array" };
  }
  if (!raw.evidence_reviewed.every((e) => typeof e === "string")) {
    return { ok: false, error: "verdict evidence_reviewed entries must be strings" };
  }
  if (typeof raw.re_executed !== "boolean") {
    return { ok: false, error: "verdict re_executed must be a boolean" };
  }
  if (
    !nonEmptyString(raw.differential) ||
    !CONFIRM_DIFFERENTIAL_VALUES.includes(raw.differential as never)
  ) {
    return {
      ok: false,
      error: `verdict differential must be one of ${CONFIRM_DIFFERENTIAL_VALUES.join(" | ")}`,
    };
  }
  if (
    raw.severity_match !== undefined &&
    !SEVERITY_MATCH_VALUES.includes(raw.severity_match as never)
  ) {
    return {
      ok: false,
      error: `verdict severity_match must be one of ${SEVERITY_MATCH_VALUES.join(" | ")}`,
    };
  }
  if (raw.verdict === "CONFIRMED") {
    if (raw.differential !== "target_only") {
      return {
        ok: false,
        error:
          'CONFIRMED requires differential "target_only" — the control run must not demonstrate the claimed impact',
      };
    }
    if (raw.re_executed !== true) {
      return {
        ok: false,
        error:
          "CONFIRMED requires re_executed: true — the confirmer must re-send the verify request itself",
      };
    }
    if (!nonEmptyString(raw.disconfirmation_attempt)) {
      return {
        ok: false,
        error:
          "CONFIRMED requires disconfirmation_attempt — the confirmer's own failed attempt to disprove",
      };
    }
  }
  return { ok: true, verdict: raw as unknown as ConfirmerVerdict };
}
