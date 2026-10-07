/**
 * Exploit-chain suggestions and attack primitives.
 *
 * Extracted from ledger.ts (verbatim bodies). ledger.ts re-exports the public
 * API so callers are unchanged.
 */

import { randomUUID } from "node:crypto";
import type { CaseLinkKind, CaseRecord, PrimitiveKind, PrimitiveRecord } from "./ledger.ts";
import { getCaseById, PRIMITIVE_KIND_VALUES } from "./ledger.ts";
import {
  getDb,
  normalizeText,
  stableShortId,
  withImmediateTransaction,
} from "./ledger-internal.ts";
import type { DatabaseSync } from "./sqlite-compat/index.ts";

// ── Chain suggestions ───────────────────────────────────────────────

/** Automated exploit-chain patterns (ported shape from CyberStrike chain.ts + XBOW 104 expansion). */
const CHAIN_PATTERN_VALUES = [
  "credential_endpoint",
  "info_disclosure_ssrf",
  "redirect_oauth",
  "idor_data_leak",
  "xss_csrf",
  "ssti_rce",
  "race_condition_business",
  "primitive_use",
  // ── XBOW expansion — chaining-heavy benchmarks (XBEN-020..104) ───────────
  "sqli_credential_dump",
  "lfi_rce_chain",
  "ssrf_internal_pivot",
  "jwt_privilege_escalation",
  "graphql_chain",
  "deserialization_rce",
  "xxe_file_read",
  "business_logic_privilege",
  "upload_rce",
  "crypto_auth_bypass",
] as const;
export type ChainPattern = (typeof CHAIN_PATTERN_VALUES)[number];

export type ChainSuggestion = {
  pattern: ChainPattern;
  sourceId: string;
  targetId?: string;
  sourceTitle: string;
  targetTitle?: string;
  rationale: string;
  confidence: number;
  /** Suggested CaseLink kind when the agent links the pair. */
  suggestedKind?: CaseLinkKind;
};

// Word-boundary anchored so "admin" does not match "administration" and
// "update" does not match "updated" — substring matching over-mines pairs.
export const CHAIN_CLASS_RE = {
  credential: /\b(credential|password|api[ _-]?key|token|secret|leak|dump|exposure)\b/i,
  authEndpoint: /\b(auth|login|sso|signup|account|admin|endpoint|api|ssh)\b/i,
  redirect: /\b(open[ _-]?redirect|redirect)\b/i,
  oauth: /\b(oauth|callback|redirect_uri|sso|saml|openid|authorize)\b/i,
  xss: /\b(xss|cross-?site.?script)\b/i,
  stateChange:
    /\b(POST|PUT|DELETE|PATCH|create|update|delete|transfer|payment|invite|admin|state.?chang)\b/i,
  idor: /\b(idor|bola|object[ _-]?reference|broken[ _-]?access)\b/i,
  userData:
    /\b(user|users|profile|account|accounts|email|phone|address|personal|private|settings|data)\b/i,
  ssti: /\b(ssti|template[ _-]?injection|template[ _-]?render)\b/i,
  race: /\b(race|toctou|concurrent|race[ _-]?condition)\b/i,
  payment: /\b(payment|transfer|order|checkout|cart|purchase|balance|credit|withdraw|deposit)\b/i,
  infoDisclosure: /\b(info[ _-]?disclosure|information[ _-]?disclosure|leak|exposure|debug)\b/i,
  ssrf: /\b(ssrf|server[ _-]?side[ _-]?request)\b/i,
  // ── XBOW expansion — new classifiers for chaining-heavy classes ──────
  sqli: /\b(sqli|sql[ _-]?injection|blind[ _-]?sqli|nosqli|nosql[ _-]?injection|union[ _-]?select|sql[ _-]?map)\b/i,
  lfi: /\b(lfi|local[ _-]?file[ _-]?inclusion|path[ _-]?traversal|directory[ _-]?traversal|file[ _-]?inclusion|arbitrary[ _-]?file[ _-]?read)\b/i,
  fileUpload:
    /\b(arbitrary[ _-]?file[ _-]?upload|file[ _-]?upload|unrestricted[ _-]?upload|upload[ _-]?bypass)\b/i,
  commandInjection:
    /\b(command[ _-]?injection|rce|remote[ _-]?code|code[ _-]?execution|os[ _-]?command)\b/i,
  deserialization:
    /\b(insecure[ _-]?deserialization|deserialization|unserialize|pickle|yaml[ _-]?deserialization)\b/i,
  jwt: /\b(jwt|json[ _-]?web[ _-]?token|jwk|kid[ _-]?injection|alg[ _-]?none|token[ _-]?tamper)\b/i,
  graphql: /\b(graphql|graph[ _-]?ql)\b/i,
  businessLogic:
    /\b(business[ _-]?logic|privilege[ _-]?escalation|auth[ _-]?bypass|authorization[ _-]?bypass|authz[ _-]?bypass)\b/i,
  xxe: /\b(xxe|xml[ _-]?external[ _-]?entity)\b/i,
  crypto:
    /\b(crypto|encryption|hash[ _-]?collision|brute[ _-]?force|weak[ _-]?crypto|cryptographic)\b/i,
} satisfies Record<string, RegExp>;

/** Multi-label second-level suffixes — *.co.uk must not false-pair via last-2 labels. */
const SECOND_LEVEL_SUFFIXES = new Set([
  "co",
  "com",
  "org",
  "net",
  "gov",
  "ac",
  "edu",
  "mil",
  "ltd",
  "me",
  "tv",
  "info",
  "biz",
]);

function eTLDPlus1(host: string): string {
  const parts = host.split(".");
  if (parts.length >= 3 && SECOND_LEVEL_SUFFIXES.has(parts[parts.length - 2] ?? "")) {
    return parts.slice(-3).join(".");
  }
  return parts.slice(-2).join(".");
}

/**
 * Ruled-out phrasings that must not contribute to chain matching. Sentence
 * granularity keeps the positive signals intact: "no CSRF token on /transfer"
 * (a reason XSS→state-change chains) is NOT dropped — only explicit
 * "this class is not a finding" sentences are.
 */
const CHAIN_NEGATION_RE =
  /\b(not vulnerable|not susceptible|not exploitable|not present|not found|not affected|ruled out|no vulnerability|no vuln|no evidence of|absence of|false positive|not a finding|no issue found|dismissed|non-?vulnerable|not reachable)\b/i;

export function chainText(c: CaseRecord): string {
  const raw = [
    c.title,
    c.bugClass ?? "",
    c.evidence ?? "",
    (c.tags ?? []).join(" "),
    c.summary ?? "",
    c.impact ?? "",
  ].join(" ");
  return raw
    .split(/[.;\n]+/)
    .filter((s) => !CHAIN_NEGATION_RE.test(s))
    .join(" ");
}

export function hasChainClass(c: CaseRecord, re: RegExp): boolean {
  return re.test(chainText(c));
}

/** Reduce a target string to a bare hostname (strip scheme, port, path). */
export function normalizeTargetHost(target: string): string {
  let h = target
    .toLowerCase()
    .trim()
    .replace(/^[a-z][a-z0-9+.-]*:\/\//, "");
  h = h.split("?")[0].split("/")[0].split(":")[0];
  return h.trim();
}

/** Same asset or related (same eTLD+1) — chains only pair cases on one target. */
export function sameAssetOrRelated(a: CaseRecord, b: CaseRecord): boolean {
  const ta = normalizeTargetHost(a.target ?? "");
  const tb = normalizeTargetHost(b.target ?? "");
  if (!ta || !tb) return false;
  if (ta === tb) return true;
  // Subdomain relation requires a label boundary: "api.example.com" vs
  // "example.com" pair, but "myshop.io" vs "shop.io" do NOT — a bare
  // substring check pairs unrelated targets whose names merely overlap.
  if (ta.endsWith(`.${tb}`) || tb.endsWith(`.${ta}`)) return true;
  return eTLDPlus1(ta) === eTLDPlus1(tb);
}

// ── Attack primitives ─────────────────────────────────────────────

function mapPrimitiveRow(row: any, caseIds: string[]): PrimitiveRecord {
  return {
    id: row.id,
    kind: row.kind,
    label: row.label,
    valueRef: row.value_ref ?? undefined,
    capabilities: row.capabilities ?? undefined,
    notes: row.notes ?? undefined,
    caseIds,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function loadPrimitiveCaseIds(db: DatabaseSync, primitiveId: string): string[] {
  return (
    db
      .prepare("SELECT case_id FROM primitive_links WHERE primitive_id = ? ORDER BY case_id")
      .all(primitiveId) as {
      case_id: string;
    }[]
  ).map((r) => r.case_id);
}

function assertPrimitiveKind(kind: string): asserts kind is PrimitiveKind {
  if (!(PRIMITIVE_KIND_VALUES as readonly string[]).includes(kind)) {
    throw new Error(`Invalid primitive kind: ${kind}. Kinds: ${PRIMITIVE_KIND_VALUES.join(", ")}`);
  }
}

export function addPrimitiveResult(input: {
  kind: string;
  label: string;
  valueRef?: string;
  capabilities?: string;
  notes?: string;
  caseIds?: string[];
}): PrimitiveRecord {
  assertPrimitiveKind(input.kind);
  const kind: PrimitiveKind = input.kind;
  const label = normalizeText(input.label);
  if (!label) throw new Error("Primitive label must not be empty");
  const valueRef = normalizeText(input.valueRef);
  const capabilities = normalizeText(input.capabilities);
  const notes = normalizeText(input.notes);

  const db = getDb();
  // Transactional: the insert and every case link commit together, so a bad
  // case id mid-list cannot leave a partially-linked primitive behind.
  return withImmediateTransaction(db, () => {
    const now = new Date().toISOString();
    const primitive: PrimitiveRecord = {
      id: `pr_${stableShortId(`${kind}\n${label}\n${randomUUID()}`)}`,
      kind,
      label,
      valueRef,
      capabilities,
      notes,
      caseIds: [],
      createdAt: now,
      updatedAt: now,
    };
    db.prepare(
      `INSERT INTO primitives (id, kind, label, value_ref, capabilities, notes, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    ).run(
      primitive.id,
      primitive.kind,
      label,
      valueRef ?? null,
      capabilities ?? null,
      notes ?? null,
      now,
      now,
    );

    for (const caseId of input.caseIds ?? []) {
      linkPrimitiveResult(primitive.id, caseId);
    }
    return { ...primitive, caseIds: loadPrimitiveCaseIds(db, primitive.id) };
  });
}

export function getPrimitiveById(id: string): PrimitiveRecord | undefined {
  const db = getDb();
  const row = db.prepare("SELECT * FROM primitives WHERE id = ?").get(id) as any;
  if (!row) return;
  return mapPrimitiveRow(row, loadPrimitiveCaseIds(db, id));
}

export function listPrimitives(filter: { kind?: string; caseId?: string } = {}): PrimitiveRecord[] {
  const db = getDb();
  if (filter.kind) assertPrimitiveKind(filter.kind);
  let rows: any[];
  if (filter.caseId) {
    rows = db
      .prepare(
        `SELECT p.* FROM primitives p
         JOIN primitive_links l ON l.primitive_id = p.id
         WHERE l.case_id = ? ORDER BY p.created_at`,
      )
      .all(filter.caseId) as any[];
  } else {
    rows = db.prepare("SELECT * FROM primitives ORDER BY created_at").all() as any[];
  }
  return rows
    .map((row) => mapPrimitiveRow(row, loadPrimitiveCaseIds(db, row.id)))
    .filter((p) => !filter.kind || p.kind === filter.kind);
}

/** Attach a primitive to a case (both must exist; idempotent). */
export function linkPrimitiveResult(primitiveId: string, caseId: string): PrimitiveRecord {
  const db = getDb();
  const primitive = getPrimitiveById(primitiveId);
  if (!primitive) throw new Error(`Primitive not found: ${primitiveId}`);
  const current = getCaseById(caseId);
  if (!current) throw new Error(`Case not found: ${caseId}`);
  db.prepare("INSERT OR IGNORE INTO primitive_links (primitive_id, case_id) VALUES (?, ?)").run(
    primitiveId,
    caseId,
  );
  return getPrimitiveById(primitiveId)!;
}

export function unlinkPrimitiveResult(primitiveId: string, caseId: string): PrimitiveRecord {
  const db = getDb();
  const primitive = getPrimitiveById(primitiveId);
  if (!primitive) throw new Error(`Primitive not found: ${primitiveId}`);
  db.prepare("DELETE FROM primitive_links WHERE primitive_id = ? AND case_id = ?").run(
    primitiveId,
    caseId,
  );
  return getPrimitiveById(primitiveId)!;
}

export function deletePrimitiveResult(id: string): boolean {
  const db = getDb();
  const result = db.prepare("DELETE FROM primitives WHERE id = ?").run(id);
  return result.changes > 0;
}
