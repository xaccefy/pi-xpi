/**
 * Casefile SQLite Ledger — SQLite-backed storage engine for offensive security cases.
 *
 * Uses Node.js built-in `node:sqlite` (DatabaseSync) for synchronous,
 * fast, zero-dependency SQLite interactions, perfectly matching Pi Agent's runtime.
 *
 * - Unified schema with structured JSON arrays for tags, blockers, references, assumptions.
 * - Exploit chains stored in a junction table (`case_links`) instead of JSON string arrays.
 * - Simple transaction boundaries for updates, links, promotions.
 * - Auto-indexing on target, status, priority, severity.
 */

import { createHash, randomUUID } from "node:crypto";
import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { DatabaseSync } from "./sqlite-compat/index.ts";

// ── Types ────────────────────────────────────────────────────────────

export const STATUS_VALUES = [
  "hypothesis",
  "investigating",
  "confirmed",
  "blocked",
  "killed",
  "reported",
] as const;
export type CaseStatus = (typeof STATUS_VALUES)[number];

export const CONFIDENCE_VALUES = ["low", "medium", "high"] as const;
export type CaseConfidence = (typeof CONFIDENCE_VALUES)[number];

export const SEVERITY_VALUES = ["info", "low", "medium", "high", "critical"] as const;
export type CaseSeverity = (typeof SEVERITY_VALUES)[number];

export const PRIORITY_VALUES = ["P0", "P1", "P2", "P3", "P4"] as const;
export type CasePriority = (typeof PRIORITY_VALUES)[number];

/** Typed relationship kinds for CaseLink. Input values accepted by the tool. */
export const LINK_KIND_VALUES = [
  "duplicate",
  "related",
  "blocks",
  "depends-on",
  "caused-by",
  "supersedes",
  "mitigates",
  "same-root-cause",
] as const;
export type CaseLinkKind = (typeof LINK_KIND_VALUES)[number];

/** Default kind when none is specified (preserves pre-kind behavior). */
export const DEFAULT_LINK_KIND: CaseLinkKind = "related";

/**
 * Inverse of each kind, written to the reverse row so a case lists the
 * relationship from its own perspective. Symmetric kinds map to themselves;
 * directional kinds produce a display-only converse (never accepted as input).
 */
export const LINK_KIND_INVERSE: Record<CaseLinkKind, string> = {
  duplicate: "duplicate",
  related: "related",
  blocks: "blocked-by",
  "depends-on": "dependency-of",
  "caused-by": "causes",
  supersedes: "superseded-by",
  mitigates: "mitigated-by",
  "same-root-cause": "same-root-cause",
};

export const SEARCH_FIELD_VALUES = [
  "title",
  "summary",
  "evidence",
  "impact",
  "target",
  "endpoint",
  "bugClass",
  "poc",
] as const;
export type CaseSearchField = (typeof SEARCH_FIELD_VALUES)[number];

export type CaseRecord = {
  id: string;
  title: string;
  status: CaseStatus;
  confidence: CaseConfidence;
  severity?: CaseSeverity;
  priority?: CasePriority;
  target?: string;
  endpoint?: string;
  bugClass?: string;
  summary?: string;
  evidence?: string;
  impact?: string;
  nextStep?: string;
  poc?: string;
  remediation?: string;
  references?: string[];
  blockers?: string[];
  tags?: string[];
  /** Explicit assumptions or unknowns to avoid overstating exploitability. */
  assumptions?: string[];
  /** Verification of an on-disk PoC run (set only by promoteFindingResult). */
  pocVerified?: {
    path: string;
    exitCode: number;
    ranAt: string;
    output?: string;
    sandbox: boolean;
  };
  /** ISO timestamp when CaseReport first wrote the markdown report. */
  reportedAt?: string;
  /** Path to the generated markdown report (set only by writeCaseReport). */
  reportPath?: string;
  /** Flat list of linked case IDs (back-compat; derived from linkedCases). */
  linkedCaseIds: string[];
  /** Linked cases with their relationship kind, from this case's perspective. */
  linkedCases: { id: string; kind: string }[];
  createdAt: string;
  updatedAt: string;
};

export type CaseInput = {
  title: string;
  status?: CaseStatus;
  confidence?: CaseConfidence;
  severity?: CaseSeverity;
  priority?: CasePriority;
  target?: string;
  endpoint?: string;
  bugClass?: string;
  summary?: string;
  evidence?: string;
  impact?: string;
  nextStep?: string;
  poc?: string;
  remediation?: string;
  references?: string[];
  blockers?: string[];
  tags?: string[];
  assumptions?: string[];
};

type NormalizedCaseInput = Partial<CaseInput> & {
  linkedCaseIds?: string[];
  pocVerified?: CaseRecord["pocVerified"];
  reportedAt?: string;
  reportPath?: string;
};

export type CaseUpdate = Partial<CaseInput>;

export type CaseUpdateResult = {
  record: CaseRecord;
  changed: boolean;
  reason?: string;
};

export type CaseAddResult = {
  record: CaseRecord;
  created: boolean;
  reason?: string;
};

export type CaseLinkResult = {
  source: CaseRecord;
  target: CaseRecord;
  changed: boolean;
  reason?: string;
  /** Relationship kind as stated by the caller (source → target). */
  kind: string;
};

export type CaseSearchOptions = {
  query?: string;
  field?: CaseSearchField;
  status?: CaseStatus;
  confidence?: CaseConfidence;
  severity?: CaseSeverity;
  /** Return only cases at or above this severity (info < low < medium < high < critical). */
  minSeverity?: CaseSeverity;
  priority?: CasePriority;
  tag?: string;
  /** ISO timestamp; only cases created at/after this time. */
  since?: string;
  /** ISO timestamp; only cases created at/before this time. */
  until?: string;
  limit?: number;
  offset?: number;
};

// ── Globals & Environment ─────────────────────────────────────────────

let ledgerPathOverride: string | undefined;
let dbInstance: DatabaseSync | undefined;

function normalizeList(values: string[] | undefined): string[] {
  return Array.from(new Set((values ?? []).map((v) => v.trim()).filter(Boolean)));
}

function normalizeText(value: string | undefined): string | undefined {
  const trimmed = value?.trim();
  return trimmed || undefined;
}

function normalizeMatchText(value: string | undefined): string {
  return normalizeText(value)?.toLowerCase().replace(/\s+/g, " ") ?? "";
}

function stableShortId(input: string): string {
  return createHash("sha1").update(input).digest("hex").slice(0, 10);
}

function detectWorkspaceRoot(): string {
  const envs = ["CASEFILE_WORKSPACE_ROOT", "PI_WORKSPACE_ROOT", "GITHUB_WORKSPACE", "PWD"];
  for (const e of envs) if (process.env[e]) return resolve(process.env[e]!);

  let curr = resolve(process.cwd());
  for (let i = 0; i < 20; i++) {
    if (existsSync(join(curr, ".git"))) return curr;
    const parent = dirname(curr);
    if (parent === curr) break;
    curr = parent;
  }
  return resolve(process.cwd());
}

export function getCasefilePath(): string {
  if (ledgerPathOverride) return ledgerPathOverride;
  if (process.env.PI_CASEFILE_PATH) return resolve(process.env.PI_CASEFILE_PATH.trim());
  return join(detectWorkspaceRoot(), ".pi", "casefile.db");
}

export function setCasefilePath(path: string | undefined): void {
  if (dbInstance) {
    try {
      dbInstance.close();
    } catch {
      // Best-effort close.
    }
  }
  ledgerPathOverride = path;
  dbInstance = undefined; // Force reconnection on next getDb
}

// ── SQLite Schema Init ────────────────────────────────────────────────

function getDb(): DatabaseSync {
  if (dbInstance) return dbInstance;

  const dbPath = getCasefilePath();
  const dbDir = dirname(dbPath);
  if (!existsSync(dbDir)) {
    try {
      mkdirSync(dbDir, { recursive: true });
    } catch {}
  }

  const db = new DatabaseSync(dbPath);
  // Enable foreign-key enforcement so ON DELETE CASCADE actually fires
  // (SQLite keeps FK off by default; bun:sqlite in particular defaults it off).
  db.exec("PRAGMA foreign_keys = ON");

  // Create tables
  db.exec(`
    CREATE TABLE IF NOT EXISTS cases (
      id TEXT PRIMARY KEY,
      title TEXT NOT NULL,
      status TEXT NOT NULL,
      confidence TEXT NOT NULL,
      severity TEXT,
      priority TEXT,
      target TEXT,
      endpoint TEXT,
      bugClass TEXT,
      summary TEXT,
      evidence TEXT,
      impact TEXT,
      nextStep TEXT,
      poc TEXT,
      remediation TEXT,
      references_json TEXT, -- JSON string array
      blockers_json TEXT, -- JSON string array
      tags_json TEXT, -- JSON string array
      assumptions_json TEXT, -- JSON string array
      poc_verified_json TEXT, -- JSON object
      reported_at TEXT,
      report_path TEXT,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    )
  `);

  db.exec(`
    CREATE TABLE IF NOT EXISTS case_links (
      source_id TEXT,
      target_id TEXT,
      kind TEXT NOT NULL DEFAULT 'related',
      PRIMARY KEY (source_id, target_id),
      FOREIGN KEY (source_id) REFERENCES cases(id) ON DELETE CASCADE,
      FOREIGN KEY (target_id) REFERENCES cases(id) ON DELETE CASCADE
    )
  `);
  // Pre-kind ledgers lack the column; add it idempotently. SQLite has no
  // ADD COLUMN IF NOT EXISTS, so guard via pragma table_info.
  const linkCols = db.prepare("PRAGMA table_info(case_links)").all() as { name: string }[];
  if (!linkCols.some((c) => c.name === "kind")) {
    db.exec("ALTER TABLE case_links ADD COLUMN kind TEXT NOT NULL DEFAULT 'related'");
  }

  // Indexes
  db.exec(`CREATE INDEX IF NOT EXISTS idx_cases_status ON cases(status)`);
  db.exec(`CREATE INDEX IF NOT EXISTS idx_cases_target ON cases(target)`);
  db.exec(`CREATE INDEX IF NOT EXISTS idx_cases_severity ON cases(severity)`);
  db.exec(`CREATE INDEX IF NOT EXISTS idx_cases_priority ON cases(priority)`);

  dbInstance = db;
  return db;
}

// Helper to map DB row to CaseRecord
function mapRow(row: any, linkedCases: { id: string; kind: string }[] = []): CaseRecord {
  /** Safely parse a JSON column; returns [] for arrays, undefined for objects. */
  const safeParseArray = (raw: unknown): string[] => {
    if (!raw) return [];
    try {
      const parsed = JSON.parse(raw as string);
      return Array.isArray(parsed) ? parsed : [];
    } catch {
      // Corrupted JSON — return empty rather than crashing the entire read
      return [];
    }
  };
  const safeParseObject = <T>(raw: unknown): T | undefined => {
    if (!raw) return undefined;
    try {
      return JSON.parse(raw as string) as T;
    } catch {
      return undefined;
    }
  };

  return {
    id: row.id,
    title: row.title,
    status: row.status as CaseStatus,
    confidence: row.confidence as CaseConfidence,
    severity: row.severity as CaseSeverity | undefined,
    priority: row.priority as CasePriority | undefined,
    target: row.target || undefined,
    endpoint: row.endpoint || undefined,
    bugClass: row.bugClass || undefined,
    summary: row.summary || undefined,
    evidence: row.evidence || undefined,
    impact: row.impact || undefined,
    nextStep: row.nextStep || undefined,
    poc: row.poc || undefined,
    remediation: row.remediation || undefined,
    references: safeParseArray(row.references_json),
    blockers: safeParseArray(row.blockers_json),
    tags: safeParseArray(row.tags_json),
    assumptions: safeParseArray(row.assumptions_json),
    pocVerified: safeParseObject(row.poc_verified_json),
    reportedAt: row.reported_at || undefined,
    reportPath: row.report_path || undefined,
    linkedCases,
    linkedCaseIds: linkedCases.map((l) => l.id),
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

// ── Read operations ──────────────────────────────────────────────────

export function readCasefile(): CaseRecord[] {
  const db = getDb();

  // Read all cases
  const stmt = db.prepare("SELECT * FROM cases");
  const rows = stmt.all();

  // Read all links to construct linkedCases map
  const linkStmt = db.prepare("SELECT source_id, target_id, kind FROM case_links");
  const links = linkStmt.all() as { source_id: string; target_id: string; kind: string }[];

  const linkMap = new Map<string, { id: string; kind: string }[]>();
  for (const link of links) {
    if (!linkMap.has(link.source_id)) linkMap.set(link.source_id, []);
    linkMap.get(link.source_id)?.push({ id: link.target_id, kind: link.kind });
  }

  return rows.map((row: any) => mapRow(row, linkMap.get(row.id) ?? []));
}

export function getCaseById(id: string): CaseRecord | undefined {
  const db = getDb();
  const stmt = db.prepare("SELECT * FROM cases WHERE id = ?");
  const row = stmt.get(id);
  if (!row) return undefined;

  const linkStmt = db.prepare("SELECT target_id, kind FROM case_links WHERE source_id = ?");
  const links = linkStmt.all(id) as { target_id: string; kind: string }[];

  return mapRow(
    row,
    links.map((l) => ({ id: l.target_id, kind: l.kind })),
  );
}

// ── Validation ────────────────────────────────────────────────────────

function validateCase(record: CaseRecord): void {
  if (!record.title.trim()) throw new Error("Case title cannot be empty");
  // Keep this gate in lockstep with promoteFindingResult: a case may only be
  // CONFIRMED when it has evidence, a PoC, demonstrated impact, and a severity.
  if (
    record.status === "confirmed" &&
    (!record.evidence || !record.poc || !record.impact || !record.severity)
  ) {
    throw new Error("Confirmed cases require evidence, poc, impact, and severity");
  }
  if (record.status === "blocked" && (record.blockers ?? []).length === 0) {
    throw new Error("Blocked cases require at least one blocker");
  }
  if (
    record.status === "killed" &&
    !record.evidence &&
    !record.nextStep &&
    (record.blockers ?? []).length === 0 &&
    (record.assumptions ?? []).length === 0
  ) {
    throw new Error(
      "Killed cases require evidence, next step, blockers, or assumptions explaining why",
    );
  }
  // A case becomes REPORTED only via CaseReport, which records reportPath. Require it
  // here so validation stays consistent with the confirmed→reported transition gate.
  if (record.status === "reported" && !record.reportPath) {
    throw new Error("Reported cases require a generated report (run CaseReport first)");
  }
}

function validateTransition(
  from: CaseStatus,
  to: CaseStatus,
  update: CaseUpdate,
  current?: CaseRecord,
): void {
  if (from === to) return;

  if (from === "killed") {
    throw new Error(
      `Cannot revive a killed case; open a new case if the lead is revived (was ${from} → ${to})`,
    );
  }
  if (from === "reported") {
    throw new Error(
      `Cannot mutate a reported case; file a follow-up case instead (was ${from} → ${to})`,
    );
  }

  if (to === "killed") return;
  if (to === "blocked") return;

  type Rule = (u: CaseUpdate, current?: CaseRecord) => string | null;

  // Transition rules must consult both the update payload AND the current record.
  // Agents often promote status alone after evidence was already written in a prior update.
  const requireInvestigatingFields: Rule = (u, cur) => {
    // Normalize so whitespace-only evidence cannot satisfy the gate.
    const evidence = normalizeText(u.evidence ?? cur?.evidence);
    const confidence = u.confidence ?? cur?.confidence;
    if (!evidence) return "INVESTIGATING requires evidence (source→sink trace)";
    if (!confidence) return "INVESTIGATING requires confidence level";
    return null;
  };

  const transitions: Partial<Record<CaseStatus, Partial<Record<CaseStatus, Rule>>>> = {
    hypothesis: {
      investigating: requireInvestigatingFields,
      confirmed: () => "Cannot jump hypothesis → confirmed; promote to investigating first",
      reported: () => "Cannot jump hypothesis → reported; confirm first",
    },
    investigating: {
      confirmed: () =>
        "investigating → confirmed requires a verified PoC run; use the promote_finding tool",
      hypothesis: () => null,
    },
    confirmed: {
      reported: (_, current) =>
        !current?.reportPath
          ? "confirmed → reported requires a report; run CaseReport first"
          : null,
      investigating: () => null,
    },
    blocked: {
      investigating: requireInvestigatingFields,
      hypothesis: () => null,
    },
  };

  const rule = transitions[from]?.[to];
  if (rule === undefined) {
    throw new Error(`Invalid transition: ${from} → ${to}`);
  }
  const reason = rule(update, current);
  if (reason) {
    throw new Error(`Cannot transition ${from} → ${to}: ${reason}`);
  }
}

function validateNewCaseInput(input: CaseInput): void {
  if (input.status && input.status !== "hypothesis" && input.status !== "investigating") {
    throw new Error(
      "New cases must start as hypothesis or investigating; promote with CaseUpdate after validation",
    );
  }
  if (input.status === "investigating") {
    if (!input.evidence) {
      throw new Error("New investigating cases require evidence (source→sink trace)");
    }
    if (!input.confidence) {
      throw new Error("New investigating cases require a confidence level");
    }
  }
}

function buildRecord(input: NormalizedCaseInput, existing?: CaseRecord): CaseRecord {
  const timestamp = new Date().toISOString();
  const title = ("title" in input ? input.title : existing?.title)?.trim() ?? "";
  const id = existing?.id ?? `case_${stableShortId(`${title}\n${timestamp}\n${randomUUID()}`)}`;

  return {
    id,
    title,
    status: input.status ?? existing?.status ?? "hypothesis",
    confidence: input.confidence ?? existing?.confidence ?? "low",
    severity: input.severity ?? existing?.severity,
    priority: input.priority ?? existing?.priority,
    target: input.target !== undefined ? normalizeText(input.target) : existing?.target,
    endpoint: input.endpoint !== undefined ? normalizeText(input.endpoint) : existing?.endpoint,
    bugClass: input.bugClass !== undefined ? normalizeText(input.bugClass) : existing?.bugClass,
    summary: input.summary !== undefined ? normalizeText(input.summary) : existing?.summary,
    evidence: input.evidence !== undefined ? normalizeText(input.evidence) : existing?.evidence,
    impact: input.impact !== undefined ? normalizeText(input.impact) : existing?.impact,
    nextStep: input.nextStep !== undefined ? normalizeText(input.nextStep) : existing?.nextStep,
    poc: input.poc !== undefined ? normalizeText(input.poc) : existing?.poc,
    remediation:
      input.remediation !== undefined ? normalizeText(input.remediation) : existing?.remediation,
    references: normalizeList(input.references ?? existing?.references),
    blockers: normalizeList(input.blockers ?? existing?.blockers),
    tags: normalizeList(input.tags ?? existing?.tags),
    assumptions: normalizeList(input.assumptions ?? existing?.assumptions),
    pocVerified: input.pocVerified ?? existing?.pocVerified,
    reportedAt: input.reportedAt ?? existing?.reportedAt,
    reportPath: input.reportPath ?? existing?.reportPath,
    linkedCases: existing?.linkedCases ?? [],
    linkedCaseIds: existing?.linkedCaseIds ?? [],
    createdAt: existing?.createdAt ?? timestamp,
    updatedAt: timestamp,
  };
}

function findDuplicateCaseInDb(
  db: DatabaseSync,
  candidate: Pick<CaseRecord, "title" | "target" | "endpoint" | "bugClass">,
  excludeId?: string,
): CaseRecord | undefined {
  const title = normalizeMatchText(candidate.title);
  if (!title) return undefined;

  const target = normalizeMatchText(candidate.target);
  const endpoint = normalizeMatchText(candidate.endpoint);
  const bugClass = normalizeMatchText(candidate.bugClass);

  // Query non-killed cases, then match normalized title/scope in JS.
  const rows = excludeId
    ? (db
        .prepare("SELECT * FROM cases WHERE status != 'killed' AND id != ?")
        .all(excludeId) as any[])
    : (db.prepare("SELECT * FROM cases WHERE status != 'killed'").all() as any[]);

  for (const row of rows) {
    if (
      normalizeMatchText(row.title as string) === title &&
      normalizeMatchText(row.target as string) === target &&
      normalizeMatchText(row.endpoint as string) === endpoint &&
      normalizeMatchText(row.bugClass as string) === bugClass
    ) {
      const links = db
        .prepare("SELECT target_id, kind FROM case_links WHERE source_id = ?")
        .all(row.id) as { target_id: string; kind: string }[];
      return mapRow(
        row,
        links.map((l) => ({ id: l.target_id, kind: l.kind })),
      );
    }
  }
  return undefined;
}

// ── SQLite Mutation Actions ───────────────────────────────────────────

function upsertCase(db: DatabaseSync, record: CaseRecord) {
  // Use ON CONFLICT DO UPDATE (not INSERT OR REPLACE) so FK CASCADE does not
  // wipe case_links when updating an existing primary key.
  const stmt = db.prepare(`
    INSERT INTO cases (
      id, title, status, confidence, severity, priority, target, endpoint, bugClass,
      summary, evidence, impact, nextStep, poc, remediation,
      references_json, blockers_json, tags_json, assumptions_json, poc_verified_json,
      reported_at, report_path, created_at, updated_at
    ) VALUES (
      ?, ?, ?, ?, ?, ?, ?, ?, ?,
      ?, ?, ?, ?, ?, ?,
      ?, ?, ?, ?, ?,
      ?, ?, ?, ?
    )
    ON CONFLICT(id) DO UPDATE SET
      title = excluded.title,
      status = excluded.status,
      confidence = excluded.confidence,
      severity = excluded.severity,
      priority = excluded.priority,
      target = excluded.target,
      endpoint = excluded.endpoint,
      bugClass = excluded.bugClass,
      summary = excluded.summary,
      evidence = excluded.evidence,
      impact = excluded.impact,
      nextStep = excluded.nextStep,
      poc = excluded.poc,
      remediation = excluded.remediation,
      references_json = excluded.references_json,
      blockers_json = excluded.blockers_json,
      tags_json = excluded.tags_json,
      assumptions_json = excluded.assumptions_json,
      poc_verified_json = excluded.poc_verified_json,
      reported_at = excluded.reported_at,
      report_path = excluded.report_path,
      created_at = excluded.created_at,
      updated_at = excluded.updated_at
  `);

  stmt.run(
    record.id,
    record.title,
    record.status,
    record.confidence,
    record.severity || null,
    record.priority || null,
    record.target || null,
    record.endpoint || null,
    record.bugClass || null,
    record.summary || null,
    record.evidence || null,
    record.impact || null,
    record.nextStep || null,
    record.poc || null,
    record.remediation || null,
    JSON.stringify(record.references),
    JSON.stringify(record.blockers),
    JSON.stringify(record.tags),
    JSON.stringify(record.assumptions),
    record.pocVerified ? JSON.stringify(record.pocVerified) : null,
    record.reportedAt || null,
    record.reportPath || null,
    record.createdAt,
    record.updatedAt,
  );
}

export function addCaseResult(input: CaseInput): CaseAddResult {
  const db = getDb();
  validateNewCaseInput(input);
  const record = buildRecord(input, undefined);
  validateCase(record);

  // Check duplicates
  const duplicate = findDuplicateCaseInDb(db, record);
  if (duplicate) {
    return {
      record: duplicate,
      created: false,
      reason: `Duplicate case exists: ${duplicate.id}`,
    };
  }

  upsertCase(db, record);
  return { record, created: true };
}

export function updateCaseResult(id: string, update: CaseUpdate): CaseUpdateResult {
  const db = getDb();
  const current = getCaseById(id);
  if (!current) {
    throw new Error(`Case not found: ${id}`);
  }

  // Terminal states: block all mutations (status and field edits). The transition
  // gate only runs on status changes, so without this reported/killed cases could
  // still be rewritten via field-only updates.
  if (current.status === "killed") {
    throw new Error("Cannot mutate a killed case; open a new case if the lead is revived");
  }
  if (current.status === "reported") {
    throw new Error("Cannot mutate a reported case; file a follow-up case instead");
  }

  const optionalFields = [
    "title",
    "target",
    "endpoint",
    "bugClass",
    "summary",
    "evidence",
    "impact",
    "nextStep",
    "poc",
    "remediation",
  ] as const;
  const optionalPatch: Record<string, unknown> = {};
  for (const field of optionalFields) {
    if (field in update && update[field] !== undefined) {
      optionalPatch[field] = update[field];
    }
  }

  let next = buildRecord(
    {
      ...optionalPatch,
      status: update.status ?? current.status,
      confidence: update.confidence ?? current.confidence,
      severity: update.severity ?? current.severity,
      priority: update.priority ?? current.priority,
      references: update.references ?? current.references,
      blockers: update.blockers ?? current.blockers,
      tags: update.tags ?? current.tags,
      assumptions: update.assumptions ?? current.assumptions,
    },
    current,
  );

  if (update.status && update.status !== current.status) {
    validateTransition(current.status, next.status, update, current);
  }

  // Demoting off confirmed invalidates prior PoC verification — re-promote required.
  if (current.status === "confirmed" && next.status === "investigating") {
    next = { ...next, pocVerified: undefined };
  }

  validateCase(next);

  // Check material equality (we ignore links since links are mutated via CaseLink)
  const norm = (r: CaseRecord) =>
    JSON.stringify({ ...r, updatedAt: "", createdAt: "", linkedCaseIds: [], linkedCases: [] });
  if (norm(current) === norm(next)) {
    const reason =
      update.status && update.status === current.status
        ? `Case is already ${current.status}; no material fields changed.`
        : "No material fields changed.";
    return { record: current, changed: false, reason };
  }

  const duplicate = findDuplicateCaseInDb(db, next, id);
  if (duplicate) {
    return {
      record: current,
      changed: false,
      reason: `Update would create a duplicate of case ${duplicate.id}`,
    };
  }

  upsertCase(db, next);
  return { record: next, changed: true };
}

type PocVerification = {
  path: string;
  exitCode: number;
  ranAt: string;
  output?: string;
  sandbox: boolean;
};

export function promoteFindingResult(id: string, verification: PocVerification): CaseUpdateResult {
  const db = getDb();
  const current = getCaseById(id);
  if (!current) {
    throw new Error(`Case not found: ${id}`);
  }
  if (current.status !== "investigating") {
    throw new Error(`promote_finding requires an investigating case (current: ${current.status})`);
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
  if (verification.exitCode !== 0) {
    throw new Error(
      `PoC verification failed (exit ${verification.exitCode}); cannot promote to confirmed`,
    );
  }

  const newEvidence =
    (current.evidence ? current.evidence + "\n\n" : "") +
    `### PoC Execution Capture (${verification.ranAt})\n` +
    `- **Exit Code:** ${verification.exitCode}\n` +
    `- **Sandbox:** ${verification.sandbox ? "yes" : "no"}\n` +
    `#### Execution Output\n\`\`\`\n${verification.output ?? ""}\n\`\`\``;

  const next = buildRecord(
    {
      status: "confirmed",
      pocVerified: verification,
      evidence: newEvidence,
    },
    current,
  );
  validateCase(next);

  upsertCase(db, next);
  return { record: next, changed: true };
}

// ── Link operations ──────────────────────────────────────────────────

export function linkCasesResult(sourceId: string, targetId: string, kind?: string): CaseLinkResult {
  const db = getDb();
  if (sourceId === targetId) {
    throw new Error("Cannot link a case to itself");
  }
  const resolvedKind: CaseLinkKind =
    kind && (LINK_KIND_VALUES as readonly string[]).includes(kind)
      ? (kind as CaseLinkKind)
      : DEFAULT_LINK_KIND;
  const source = getCaseById(sourceId);
  const target = getCaseById(targetId);
  if (!source) throw new Error(`Case not found: ${sourceId}`);
  if (!target) throw new Error(`Case not found: ${targetId}`);
  if (source.status === "killed" || source.status === "reported") {
    throw new Error(`Cannot link terminal case ${sourceId} (${source.status})`);
  }
  if (target.status === "killed" || target.status === "reported") {
    throw new Error(`Cannot link terminal case ${targetId} (${target.status})`);
  }

  const checkStmt = db.prepare("SELECT kind FROM case_links WHERE source_id = ? AND target_id = ?");
  const existing = checkStmt.get(sourceId, targetId) as { kind: string } | undefined;

  if (existing) {
    return {
      source,
      target,
      changed: false,
      reason: "Cases are already linked",
      kind: existing.kind,
    };
  }

  // Atomic insert both directions: source→target keeps the stated kind, the
  // reverse row stores the inverse so each case lists the edge from its own
  // perspective.
  const inverseKind = LINK_KIND_INVERSE[resolvedKind];
  db.exec("BEGIN");
  try {
    const linkStmt = db.prepare(
      "INSERT INTO case_links (source_id, target_id, kind) VALUES (?, ?, ?)",
    );
    linkStmt.run(sourceId, targetId, resolvedKind);
    linkStmt.run(targetId, sourceId, inverseKind);

    const now = new Date().toISOString();
    const updateTimeStmt = db.prepare("UPDATE cases SET updated_at = ? WHERE id = ?");
    updateTimeStmt.run(now, sourceId);
    updateTimeStmt.run(now, targetId);
    db.exec("COMMIT");
  } catch (err) {
    try {
      db.exec("ROLLBACK");
    } catch {
      // ignore
    }
    throw err;
  }

  const finalSource = getCaseById(sourceId)!;
  const finalTarget = getCaseById(targetId)!;
  return { source: finalSource, target: finalTarget, changed: true, kind: resolvedKind };
}

export function unlinkCasesResult(sourceId: string, targetId: string): CaseLinkResult {
  const db = getDb();
  const source = getCaseById(sourceId);
  const target = getCaseById(targetId);
  if (!source) throw new Error(`Case not found: ${sourceId}`);
  if (!target) throw new Error(`Case not found: ${targetId}`);
  if (source.status === "killed" || source.status === "reported") {
    throw new Error(`Cannot unlink terminal case ${sourceId} (${source.status})`);
  }
  if (target.status === "killed" || target.status === "reported") {
    throw new Error(`Cannot unlink terminal case ${targetId} (${target.status})`);
  }

  const checkStmt = db.prepare("SELECT kind FROM case_links WHERE source_id = ? AND target_id = ?");
  const existing = checkStmt.get(sourceId, targetId) as { kind: string } | undefined;

  if (!existing) {
    return { source, target, changed: false, reason: "Cases are not linked", kind: "related" };
  }

  db.exec("BEGIN");
  try {
    const unlinkStmt = db.prepare(
      "DELETE FROM case_links WHERE (source_id = ? AND target_id = ?) OR (source_id = ? AND target_id = ?)",
    );
    unlinkStmt.run(sourceId, targetId, targetId, sourceId);

    const now = new Date().toISOString();
    const updateTimeStmt = db.prepare("UPDATE cases SET updated_at = ? WHERE id = ?");
    updateTimeStmt.run(now, sourceId);
    updateTimeStmt.run(now, targetId);
    db.exec("COMMIT");
  } catch (err) {
    try {
      db.exec("ROLLBACK");
    } catch {
      // ignore
    }
    throw err;
  }

  const finalSource = getCaseById(sourceId)!;
  const finalTarget = getCaseById(targetId)!;
  return { source: finalSource, target: finalTarget, changed: true, kind: existing.kind };
}

// ── Search & Queries ─────────────────────────────────────────────────

// Searchable text columns (excludes ids/timestamps/JSON arrays for performance + signal).
const SEARCH_COLUMNS = [
  "title",
  "summary",
  "evidence",
  "impact",
  "target",
  "endpoint",
  "bugClass",
  "poc",
] as const;

const FIELD_COLUMN: Record<CaseSearchField, string> = {
  title: "title",
  summary: "summary",
  evidence: "evidence",
  impact: "impact",
  target: "target",
  endpoint: "endpoint",
  bugClass: "bugClass",
  poc: "poc",
};

function severityRank(s: CaseSeverity): number {
  return SEVERITY_VALUES.indexOf(s);
}

/**
 * Build a parameterized WHERE clause + params for case queries. Pushes all
 * structured filters (and free-text) into SQL so we never load the whole ledger
 * into memory just to filter it in JS. Also returns a stable ORDER BY that keeps
 * the original status precedence (hypothesis first) with updated_at as tiebreak.
 */
function buildCaseWhere(options: CaseSearchOptions): {
  whereSql: string;
  orderSql: string;
  params: unknown[];
} {
  const where: string[] = [];
  const params: unknown[] = [];

  if (options.status) {
    where.push("status = ?");
    params.push(options.status);
  }
  if (options.confidence) {
    where.push("confidence = ?");
    params.push(options.confidence);
  }
  if (options.severity) {
    where.push("severity = ?");
    params.push(options.severity);
  }
  if (options.minSeverity) {
    where.push(
      "severity IS NOT NULL AND (CASE severity WHEN 'info' THEN 0 WHEN 'low' THEN 1 WHEN 'medium' THEN 2 WHEN 'high' THEN 3 WHEN 'critical' THEN 4 ELSE -1 END) >= ?",
    );
    params.push(severityRank(options.minSeverity));
  }
  if (options.priority) {
    where.push("priority = ?");
    params.push(options.priority);
  }
  if (options.tag) {
    where.push("EXISTS (SELECT 1 FROM json_each(tags_json) WHERE lower(value) = ?)");
    params.push(options.tag.trim().toLowerCase());
  }
  if (options.since) {
    where.push("created_at >= ?");
    params.push(options.since);
  }
  if (options.until) {
    where.push("created_at <= ?");
    params.push(options.until);
  }

  const query = options.query?.trim().toLowerCase();
  if (query) {
    const likeParam = `%${query}%`;
    if (options.field) {
      where.push(`lower(${FIELD_COLUMN[options.field]}) LIKE ?`);
      params.push(likeParam);
    } else {
      const ors = SEARCH_COLUMNS.map((c) => `lower(${c}) LIKE ?`).join(" OR ");
      where.push(`(${ors})`);
      for (let i = 0; i < SEARCH_COLUMNS.length; i++) params.push(likeParam);
    }
  }

  const orderSql =
    "CASE status WHEN 'hypothesis' THEN 0 WHEN 'investigating' THEN 1 WHEN 'confirmed' THEN 2 " +
    "WHEN 'blocked' THEN 3 WHEN 'killed' THEN 4 WHEN 'reported' THEN 5 ELSE 6 END, updated_at DESC";

  return {
    whereSql: where.length ? `WHERE ${where.join(" AND ")}` : "",
    orderSql,
    params,
  };
}

/** Map DB rows to CaseRecords, attaching linkedCases fetched in a single batch. */
function mapRowsWithLinks(db: DatabaseSync, rows: any[]): CaseRecord[] {
  if (rows.length === 0) return [];
  const ids = rows.map((r) => r.id);
  const placeholders = ids.map(() => "?").join(",");
  const links = db
    .prepare(
      `SELECT source_id, target_id, kind FROM case_links WHERE source_id IN (${placeholders})`,
    )
    .all(...ids) as { source_id: string; target_id: string; kind: string }[];
  const linkMap = new Map<string, { id: string; kind: string }[]>();
  for (const l of links) {
    if (!linkMap.has(l.source_id)) linkMap.set(l.source_id, []);
    linkMap.get(l.source_id)!.push({ id: l.target_id, kind: l.kind });
  }
  return rows.map((row) => mapRow(row, linkMap.get(row.id) ?? []));
}

export function searchCases(options: CaseSearchOptions = {}): {
  cases: CaseRecord[];
  total: number;
} {
  const db = getDb();
  const limit = Math.max(1, Math.min(options.limit ?? 50, 200));
  const offset = Math.max(0, options.offset ?? 0);

  const { whereSql, orderSql, params } = buildCaseWhere(options);

  const total = (db.prepare(`SELECT COUNT(*) as c FROM cases ${whereSql}`).get(...params) as any).c;
  const rows = db
    .prepare(`SELECT * FROM cases ${whereSql} ORDER BY ${orderSql} LIMIT ? OFFSET ?`)
    .all(...params, limit, offset) as any[];

  return { total, cases: mapRowsWithLinks(db, rows) };
}

export function countCases(): {
  total: number;
  byStatus: Record<string, number>;
  bySeverity: Record<string, number>;
} {
  const db = getDb();
  const total = (db.prepare("SELECT COUNT(*) as c FROM cases").get() as any).c;
  const statusRows = db
    .prepare("SELECT status, COUNT(*) as n FROM cases GROUP BY status")
    .all() as { status: string; n: number }[];
  const severityRows = db
    .prepare(
      "SELECT severity, COUNT(*) as n FROM cases WHERE severity IS NOT NULL GROUP BY severity",
    )
    .all() as { severity: string; n: number }[];

  const byStatus: Record<string, number> = {};
  const bySeverity: Record<string, number> = {};
  for (const r of statusRows) byStatus[r.status] = r.n;
  for (const r of severityRows) bySeverity[r.severity] = r.n;
  return { total, byStatus, bySeverity };
}

// ── Format helpers ───────────────────────────────────────────────────

export function formatCase(record: CaseRecord): string {
  const linkBits = record.linkedCases.map((l) =>
    l.kind && l.kind !== DEFAULT_LINK_KIND ? `${l.id}:${l.kind}` : l.id,
  );
  const bits = [
    `${record.id} [${record.status}/${record.confidence}] ${record.title}`,
    record.priority ? `priority=${record.priority}` : undefined,
    record.severity ? `severity=${record.severity}` : undefined,
    record.bugClass ? `class=${record.bugClass}` : undefined,
    record.summary ? `summary=${record.summary}` : undefined,
    record.endpoint ? `endpoint=${record.endpoint}` : undefined,
    record.target ? `target=${record.target}` : undefined,
    record.tags?.length ? `tags=${record.tags.join(",")}` : undefined,
    linkBits.length ? `links=${linkBits.join(",")}` : undefined,
    record.nextStep ? `next=${record.nextStep}` : undefined,
  ].filter(Boolean);
  return bits.join(" | ");
}

export function formatCases(records: CaseRecord[]): string {
  if (records.length === 0) return "No cases recorded.";
  return records.map(formatCase).join("\n");
}

export function formatCaseDetail(record: CaseRecord): string {
  const lines = [`═══ ${record.id} ═══`];
  for (const [key, val] of Object.entries(record)) {
    if (
      !val ||
      (Array.isArray(val) && !val.length) ||
      ["id", "createdAt", "updatedAt", "linkedCaseIds"].includes(key)
    )
      continue;
    const label = key.charAt(0).toUpperCase() + key.slice(1).replace(/([A-Z])/g, " $1");
    let display: string;
    if (key === "linkedCases") {
      display = (val as { id: string; kind: string }[])
        .map((l) => `${l.id} (${l.kind})`)
        .join(", ");
    } else if (Array.isArray(val)) {
      display = val.join(", ");
    } else if (typeof val === "object") {
      display = JSON.stringify(val);
    } else {
      display = String(val);
    }
    lines.push(`${label.padEnd(12)} ${display}`);
  }
  return lines
    .concat([`Created:     ${record.createdAt}`, `Updated:     ${record.updatedAt}`])
    .join("\n");
}

function mdSection(title: string, body?: string): string {
  return `## ${title}\n\n${body?.trim() || "Not recorded."}\n`;
}

export function writeCaseReport(id: string): { path: string; record: CaseRecord } {
  const current = getCaseById(id);
  if (!current) throw new Error(`Case not found: ${id}`);
  if (current.status !== "confirmed" && current.status !== "reported") {
    throw new Error("Case reports require a confirmed or reported case");
  }

  // Reported cases are terminal artifacts — return the existing report path if present.
  if (current.status === "reported" && current.reportPath && existsSync(current.reportPath)) {
    return { path: current.reportPath, record: current };
  }

  const db = getDb();
  const dbPath = getCasefilePath();

  const reportDir = join(dirname(dbPath), "report");
  mkdirSync(reportDir, { recursive: true });

  const slug =
    current.title
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-+|-+$/g, "")
      .slice(0, 70) || "case";
  const reportPath = join(reportDir, `${slug}-${current.id}.md`);
  const references = current.references?.length
    ? current.references.map((r) => `- ${r}`).join("\n")
    : undefined;
  const assumptions = current.assumptions?.length
    ? current.assumptions.map((a) => `- ${a}`).join("\n")
    : undefined;
  const body = [
    `# ${current.title}`,
    `**Severity:** ${current.severity ?? "Not assessed"}`,
    `**Status:** ${current.status}`,
    `**Confidence:** ${current.confidence}`,
    current.priority ? `**Priority:** ${current.priority}` : undefined,
    current.target ? `**Target:** ${current.target}` : undefined,
    current.endpoint ? `**Endpoint:** ${current.endpoint}` : undefined,
    current.bugClass ? `**Bug class:** ${current.bugClass}` : undefined,
    "",
    mdSection("Summary", current.summary),
    mdSection("Steps to Reproduce / Evidence", current.evidence),
    mdSection("Proof of Concept", current.poc),
    current.pocVerified
      ? mdSection(
          "PoC Verification Log",
          `### PoC Run Verification\n- **Timestamp:** ${current.pocVerified.ranAt}\n- **Path:** \`${current.pocVerified.path}\`\n- **Sandbox:** ${current.pocVerified.sandbox ? "yes" : "no"}\n- **Exit Code:** ${current.pocVerified.exitCode}\n\n#### Output\n\`\`\`\n${current.pocVerified.output ?? ""}\n\`\`\``,
        )
      : undefined,
    mdSection("Impact", current.impact),
    mdSection("Remediation", current.remediation),
    mdSection("Assumptions and Uncertainty", assumptions),
    mdSection("References", references),
  ]
    .filter(Boolean)
    .join("\n");

  writeFileSync(reportPath, body, "utf8");

  const next: CaseRecord = {
    ...current,
    reportPath,
    reportedAt: current.reportedAt ?? new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };

  upsertCase(db, next);
  return { path: reportPath, record: next };
}
