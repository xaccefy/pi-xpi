/**
 * Evidence contract for PoC confirmation.
 *
 * A PoC must write `evidence.json` into $PI_POC_EVIDENCE_DIR: a nonce-bound,
 * schema-validated record of what it claims and the request spec the harness
 * executes against both target and control. The harness validates the file,
 * binds it to the run via $PI_POC_NONCE, and acquires the responses itself.
 * The main/coordinator agent remains the semantic reviewer after the machine differential.
 *
 * Exit zero is required run integrity, but never vulnerability proof.
 */

// ── PoC evidence (written by the PoC script) ────────────────────────

export type VerifyExpect = {
  /** Acceptable HTTP statuses for the verify request. */
  status?: number[];
  /** Substrings the verify response must contain. */
  body_contains?: string[];
  /** Regexes the verify response must match. */
  body_regex?: string[];
};

/** Replaced only inside the harness replay, after the PoC process has exited. */
export const POC_CANARY_PLACEHOLDER = "{{PI_POC_CANARY}}";

export type VerifyCanary = {
  /** Reflection is machine-checked: target must return the fresh token and control must not. */
  mode: "reflection";
  /** Fixed literal; callers cannot choose or predict the harness-generated token. */
  placeholder: typeof POC_CANARY_PLACEHOLDER;
};

export type PoCEvidence = {
  /** Must equal the run's PI_POC_NONCE (harness-verified). */
  nonce: string;
  /** What the exploit asserts, e.g. "read /etc/passwd of target". */
  claim: string;
  /** Request spec the harness executes in phase 1 and again from the main-agent phase-2 call. */
  verify: {
    method: string;
    url: string;
    headers?: Record<string, string>;
    body?: string;
    expect: VerifyExpect;
    /** Optional stronger causality dimension, independent of the authored predicate. */
    canary?: VerifyCanary;
    /**
     * Differential shape. "inter_host" (default) = same request to target vs a
     * distinct patched control host (body-carried proof). "intra_target" = attack
     * request vs a legitimate same-host `baseline` request (access-control /
     * business-logic classes, where the discriminating variable is identity or a
     * parameter, not the host) — requires `baseline`.
     */
    mode?: "inter_host" | "intra_target";
  };
  /** What the script itself saw — corroboration only, never proof. */
  observations: string[];
  /** Optional baseline request for the main agent's differential review. */
  baseline?: {
    method: string;
    url: string;
    headers?: Record<string, string>;
    body?: string;
    body_contains?: string[];
  };
};

const HTTP_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];
const MAX_CLAIM_CHARS = 2_000;
const MAX_URL_CHARS = 4_096;
const MAX_REQUEST_BODY_CHARS = 128 * 1024;
const MAX_HEADERS = 64;
const MAX_HEADER_CHARS = 8 * 1024;
const MAX_EXPECT_VALUES = 16;
const MAX_EXPECT_CHARS = 1_024;
const MAX_REGEX_VALUES = 8;
const MAX_REGEX_CHARS = 512;
const MAX_OBSERVATIONS = 64;
const MAX_OBSERVATION_CHARS = 4_096;
const FORBIDDEN_REQUEST_HEADERS = new Set([
  "connection",
  "content-length",
  "host",
  "keep-alive",
  "proxy-authorization",
  "proxy-connection",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
]);

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function nonEmptyString(v: unknown): v is string {
  return typeof v === "string" && v.trim().length > 0;
}

function boundedStringArray(v: unknown, maxItems: number, maxChars: number): v is string[] {
  return (
    Array.isArray(v) &&
    v.length <= maxItems &&
    v.every((x) => nonEmptyString(x) && x.length <= maxChars)
  );
}

/** Bounded RFC-token header map with no CR/LF (injection/resource guard). */
function headerRecord(v: unknown): v is Record<string, string> {
  if (!isRecord(v)) return false;
  const entries = Object.entries(v);
  return (
    entries.length <= MAX_HEADERS &&
    entries.every(
      ([key, value]) =>
        /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(key) &&
        !FORBIDDEN_REQUEST_HEADERS.has(key.toLowerCase()) &&
        key.length <= 256 &&
        typeof value === "string" &&
        value.length <= MAX_HEADER_CHARS &&
        !/[\r\n]/.test(value),
    )
  );
}

/** http(s) URL with a non-empty host — prefix-only matches would accept garbage. */
function httpUrl(v: unknown): v is string {
  if (!nonEmptyString(v) || v.length > MAX_URL_CHARS) return false;
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

/** body_regex entries must compile — evaluation is isolated and time-bounded by the harness. */
function validRegexArray(v: unknown): v is string[] {
  return (
    boundedStringArray(v, MAX_REGEX_VALUES, MAX_REGEX_CHARS) &&
    v.every((re) => {
      try {
        // nosemgrep: javascript.lang.security.audit.detect-non-literal-regexp.detect-non-literal-regexp -- compile-only validation; evaluation runs in a worker with a hard timeout.
        new RegExp(re);
        return true;
      } catch {
        return false;
      }
    })
  );
}

function hasMeaningfulExpectation(expect: Record<string, unknown>): boolean {
  return [expect.status, expect.body_contains, expect.body_regex].some(
    (value) => Array.isArray(value) && value.length > 0,
  );
}

function hasBodyExpectation(expect: Record<string, unknown>): boolean {
  return [expect.body_contains, expect.body_regex].some(
    (value) => Array.isArray(value) && value.length > 0,
  );
}

/** Reject predicates that are structurally incapable of carrying useful proof. */
function hasDiscriminatingBodyExpectation(expect: Record<string, unknown>): boolean {
  const contains = Array.isArray(expect.body_contains) ? expect.body_contains : [];
  if (contains.some((value) => typeof value === "string" && value.trim().length >= 4)) {
    return true;
  }
  const regexes = Array.isArray(expect.body_regex) ? expect.body_regex : [];
  return regexes.some(
    (pattern) =>
      typeof pattern === "string" &&
      // Require a literal alphabetic anchor, e.g. `root:\\S+` or `is_admin`.
      // Patterns such as `.`, `.*`, or `\\d+` match broad response classes and
      // cannot independently identify the claimed vulnerability effect.
      /[A-Za-z]{4,}/.test(pattern.replace(/\\[dDsSwWbB]/g, "")),
  );
}

function countOccurrences(value: string, needle: string): number {
  return value.split(needle).length - 1;
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
  if (raw.nonce.length > 256) return { ok: false, error: "evidence.json nonce is too long" };
  if (!nonEmptyString(raw.claim)) return { ok: false, error: "evidence.json missing claim" };
  if (raw.claim.length > MAX_CLAIM_CHARS) {
    return { ok: false, error: `evidence.json claim exceeds ${MAX_CLAIM_CHARS} characters` };
  }
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
      error:
        "evidence.json verify.headers must be bounded valid end-to-end HTTP headers; authority, framing, proxy, and hop-by-hop headers are forbidden",
    };
  }
  if (
    verify.body !== undefined &&
    (typeof verify.body !== "string" || verify.body.length > MAX_REQUEST_BODY_CHARS)
  ) {
    return {
      ok: false,
      error: `evidence.json verify.body must be a string no longer than ${MAX_REQUEST_BODY_CHARS} characters`,
    };
  }
  if (verify.canary !== undefined) {
    if (
      !isRecord(verify.canary) ||
      verify.canary.mode !== "reflection" ||
      verify.canary.placeholder !== POC_CANARY_PLACEHOLDER
    ) {
      return {
        ok: false,
        error: `evidence.json verify.canary must be {"mode":"reflection","placeholder":"${POC_CANARY_PLACEHOLDER}"}`,
      };
    }
    const canaryLocations = [
      verify.url,
      typeof verify.body === "string" ? verify.body : "",
      ...(isRecord(verify.headers)
        ? Object.values(verify.headers).filter(
            (value): value is string => typeof value === "string",
          )
        : []),
    ];
    const count = canaryLocations.reduce(
      (total, value) => total + countOccurrences(value, POC_CANARY_PLACEHOLDER),
      0,
    );
    if (count !== 1) {
      return {
        ok: false,
        error: `evidence.json verify.canary requires exactly one ${POC_CANARY_PLACEHOLDER} placeholder across url, body, or header values (got ${count})`,
      };
    }
  }
  if (verify.mode !== undefined && verify.mode !== "inter_host" && verify.mode !== "intra_target") {
    return {
      ok: false,
      error: 'evidence.json verify.mode must be "inter_host" or "intra_target"',
    };
  }
  if (verify.mode === "intra_target" && !isRecord(raw.baseline)) {
    return {
      ok: false,
      error:
        "evidence.json verify.mode intra_target requires baseline — a legitimate same-host request whose response must NOT satisfy the attack predicate",
    };
  }
  const expect = verify.expect;
  if (!isRecord(expect))
    return { ok: false, error: "evidence.json verify.expect must be an object" };
  if (
    expect.status !== undefined &&
    (!Array.isArray(expect.status) ||
      expect.status.length === 0 ||
      expect.status.length > MAX_EXPECT_VALUES ||
      !expect.status.every((s) => Number.isInteger(s) && s >= 100 && s <= 599))
  ) {
    return {
      ok: false,
      error: "evidence.json verify.expect.status must be a non-empty array of HTTP status codes",
    };
  }
  if (
    expect.body_contains !== undefined &&
    !boundedStringArray(expect.body_contains, MAX_EXPECT_VALUES, MAX_EXPECT_CHARS)
  ) {
    return {
      ok: false,
      error: `evidence.json verify.expect.body_contains must have at most ${MAX_EXPECT_VALUES} non-empty strings of at most ${MAX_EXPECT_CHARS} characters`,
    };
  }
  if (expect.body_regex !== undefined && !validRegexArray(expect.body_regex)) {
    return {
      ok: false,
      error: `evidence.json verify.expect.body_regex must have at most ${MAX_REGEX_VALUES} compilable patterns of at most ${MAX_REGEX_CHARS} characters`,
    };
  }
  if (!hasMeaningfulExpectation(expect)) {
    return {
      ok: false,
      error:
        "evidence.json verify.expect must contain at least one non-empty status, body_contains, or body_regex assertion",
    };
  }
  if (!hasBodyExpectation(expect)) {
    return {
      ok: false,
      error:
        "evidence.json verify.expect needs a non-empty body_contains or body_regex assertion; status-only differences are not vulnerability proof",
    };
  }
  if (!hasDiscriminatingBodyExpectation(expect)) {
    return {
      ok: false,
      error:
        "evidence.json verify.expect needs a discriminating body predicate: body_contains must include at least 4 characters or body_regex must include a literal alphabetic anchor; trivial matchers are not vulnerability proof",
    };
  }
  if (
    !Array.isArray(raw.observations) ||
    raw.observations.length > MAX_OBSERVATIONS ||
    !raw.observations.every((o) => typeof o === "string" && o.length <= MAX_OBSERVATION_CHARS)
  ) {
    return { ok: false, error: "evidence.json observations exceed the bounded string-array limit" };
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
        error:
          "evidence.json baseline.headers must be bounded valid end-to-end HTTP headers; authority, framing, proxy, and hop-by-hop headers are forbidden",
      };
    }
    if (
      b.body !== undefined &&
      (typeof b.body !== "string" || b.body.length > MAX_REQUEST_BODY_CHARS)
    ) {
      return {
        ok: false,
        error: `evidence.json baseline.body must be no longer than ${MAX_REQUEST_BODY_CHARS} characters`,
      };
    }
    if (
      b.body_contains !== undefined &&
      !boundedStringArray(b.body_contains, MAX_EXPECT_VALUES, MAX_EXPECT_CHARS)
    ) {
      return { ok: false, error: "evidence.json baseline.body_contains exceeds limits" };
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

// ── Main-agent confirmation verdict ─────────────────────────────────

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
export const CANARY_ASSESSMENT_VALUES = ["verified", "not_applicable"] as const;

export type MainAgentVerdict = {
  verdict: ConfirmVerdict;
  reasoning: string;
  /** Files/evidence the main agent actually reviewed. */
  evidence_reviewed: string[];
  /** What the main agent observed during its review and fresh harness replay. */
  re_execution_note?: string;
  /** Target vs control evidence comparison. CONFIRMED requires target_only. */
  differential: ConfirmDifferential;
  /** Claimed severity vs what the evidence shows. */
  severity_match?: (typeof SEVERITY_MATCH_VALUES)[number];
  /** The main agent's own failed attempt to disprove — becomes the case's disconfirmation. */
  disconfirmation_attempt?: string;
  /** Whether the machine replay carried a harness-generated causal canary. */
  canary_assessment?: (typeof CANARY_ASSESSMENT_VALUES)[number];
  /** Why no meaningful canary oracle exists for this exploit class. */
  canary_reason?: string;
  /** Which model judged (recorded for the accuracy ledger). */
  model?: string;
};

/**
 * Validate the main-agent verdict. CONFIRMED additionally requires a target-only
 * differential, a concrete review note, and a disconfirmation attempt. The
 * ledger separately requires a fresh harness-owned phase-2 replay; there is no
 * caller-supplied `re_executed` checkbox.
 */
export function validateMainAgentVerdict(
  raw: unknown,
): { ok: true; verdict: MainAgentVerdict } | { ok: false; error: string } {
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
  if (raw.re_execution_note !== undefined && !nonEmptyString(raw.re_execution_note)) {
    return { ok: false, error: "verdict re_execution_note must be a non-empty string" };
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
    raw.canary_assessment !== undefined &&
    !CANARY_ASSESSMENT_VALUES.includes(raw.canary_assessment as never)
  ) {
    return {
      ok: false,
      error: `verdict canary_assessment must be one of ${CANARY_ASSESSMENT_VALUES.join(" | ")}`,
    };
  }
  if (raw.canary_reason !== undefined && !nonEmptyString(raw.canary_reason)) {
    return { ok: false, error: "verdict canary_reason must be a non-empty string" };
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
    if (!nonEmptyString(raw.re_execution_note)) {
      return {
        ok: false,
        error:
          "CONFIRMED requires re_execution_note — record what the main agent observed during review and the fresh harness replay",
      };
    }
    if (!nonEmptyString(raw.disconfirmation_attempt)) {
      return {
        ok: false,
        error:
          "CONFIRMED requires disconfirmation_attempt — the main agent's own failed attempt to disprove",
      };
    }
    if (!CANARY_ASSESSMENT_VALUES.includes(raw.canary_assessment as never)) {
      return {
        ok: false,
        error: `CONFIRMED requires canary_assessment (${CANARY_ASSESSMENT_VALUES.join(" | ")})`,
      };
    }
    if (raw.canary_assessment === "not_applicable" && !nonEmptyString(raw.canary_reason)) {
      return {
        ok: false,
        error: "CONFIRMED with canary_assessment not_applicable requires canary_reason",
      };
    }
  }
  return { ok: true, verdict: raw as unknown as MainAgentVerdict };
}

/** @deprecated Compatibility alias for integrations built before phase 2 became main-agent-only. */
export type ConfirmerVerdict = MainAgentVerdict;

/** @deprecated Use validateMainAgentVerdict. */
export const validateConfirmerVerdict = validateMainAgentVerdict;
