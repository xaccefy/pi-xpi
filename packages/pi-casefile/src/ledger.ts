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
import { DatabaseSync } from "@xaccefy/pi-sqlite-compat";

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
  linkedCaseIds: string[];
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
};

export type CaseSearchOptions = {
  query?: string;
  field?: CaseSearchField;
  status?: CaseStatus;
  confidence?: CaseConfidence;
  severity?: CaseSeverity;
  priority?: CasePriority;
  tag?: string;
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
  ledgerPathOverride = path;
  if (dbInstance) {
    dbInstance = undefined; // Force reconnection on next getDb
  }
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
      PRIMARY KEY (source_id, target_id),
      FOREIGN KEY (source_id) REFERENCES cases(id) ON DELETE CASCADE,
      FOREIGN KEY (target_id) REFERENCES cases(id) ON DELETE CASCADE
    )
  `);

  // Indexes
  db.exec(`CREATE INDEX IF NOT EXISTS idx_cases_status ON cases(status)`);
  db.exec(`CREATE INDEX IF NOT EXISTS idx_cases_target ON cases(target)`);
  db.exec(`CREATE INDEX IF NOT EXISTS idx_cases_severity ON cases(severity)`);
  db.exec(`CREATE INDEX IF NOT EXISTS idx_cases_priority ON cases(priority)`);

  dbInstance = db;
  return db;
}

// Helper to map DB row to CaseRecord
function mapRow(row: any, linkedCaseIds: string[] = []): CaseRecord {
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
    linkedCaseIds,
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

  // Read all links to construct linkedCaseIds map
  const linkStmt = db.prepare("SELECT source_id, target_id FROM case_links");
  const links = linkStmt.all() as { source_id: string; target_id: string }[];

  const linkMap = new Map<string, string[]>();
  for (const link of links) {
    if (!linkMap.has(link.source_id)) linkMap.set(link.source_id, []);
    linkMap.get(link.source_id)?.push(link.target_id);
  }

  return rows.map((row: any) => mapRow(row, linkMap.get(row.id) ?? []));
}

export function getCaseById(id: string): CaseRecord | undefined {
  const db = getDb();
  const stmt = db.prepare("SELECT * FROM cases WHERE id = ?");
  const row = stmt.get(id);
  if (!row) return undefined;

  const linkStmt = db.prepare("SELECT target_id FROM case_links WHERE source_id = ?");
  const links = linkStmt.all(id) as { target_id: string }[];

  return mapRow(
    row,
    links.map((l) => l.target_id),
  );
}

// ── Validation ────────────────────────────────────────────────────────

function validateCase(record: CaseRecord): void {
  if (!record.title.trim()) throw new Error("Case title cannot be empty");
  if (record.status === "confirmed" && (!record.evidence || !record.poc)) {
    throw new Error("Confirmed cases require both evidence and poc");
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
  if (
    record.status === "reported" &&
    !record.poc &&
    !record.remediation &&
    (record.references ?? []).length === 0
  ) {
    throw new Error("Reported cases require poc, remediation, or references");
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
  const transitions: Partial<Record<CaseStatus, Partial<Record<CaseStatus, Rule>>>> = {
    hypothesis: {
      investigating: (u) =>
        !u.evidence
          ? "INVESTIGATING requires evidence (source→sink trace)"
          : !u.confidence
            ? "INVESTIGATING requires confidence level"
            : null,
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
      investigating: (u) =>
        !u.evidence
          ? "INVESTIGATING requires evidence (source→sink trace)"
          : !u.confidence
            ? "INVESTIGATING requires confidence level"
            : null,
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
    linkedCaseIds: existing?.linkedCaseIds ?? [],
    createdAt: existing?.createdAt ?? timestamp,
    updatedAt: timestamp,
  };
}

function findDuplicateCaseInDb(db: DatabaseSync, candidate: CaseRecord): CaseRecord | undefined {
  const title = normalizeMatchText(candidate.title);
  if (!title) return undefined;

  const target = normalizeMatchText(candidate.target);
  const endpoint = normalizeMatchText(candidate.endpoint);
  const bugClass = normalizeMatchText(candidate.bugClass);

  // We query all cases where status is not killed, then match in JS for normalized forms
  const stmt = db.prepare("SELECT * FROM cases WHERE status != 'killed'");
  const rows = stmt.all();

  for (const row of rows) {
    if (
      normalizeMatchText(row.title as string) === title &&
      normalizeMatchText(row.target as string) === target &&
      normalizeMatchText(row.endpoint as string) === endpoint &&
      normalizeMatchText(row.bugClass as string) === bugClass
    ) {
      // Find links
      const linkStmt = db.prepare("SELECT target_id FROM case_links WHERE source_id = ?");
      const links = linkStmt.all(row.id) as { target_id: string }[];
      return mapRow(
        row,
        links.map((l) => l.target_id),
      );
    }
  }
  return undefined;
}

// ── SQLite Mutation Actions ───────────────────────────────────────────

function insertOrReplaceCase(db: DatabaseSync, record: CaseRecord) {
  const stmt = db.prepare(`
    INSERT OR REPLACE INTO cases (
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

  insertOrReplaceCase(db, record);
  return { record, created: true };
}

export function updateCaseResult(id: string, update: CaseUpdate): CaseUpdateResult {
  const db = getDb();
  const current = getCaseById(id);
  if (!current) {
    throw new Error(`Case not found: ${id}`);
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

  const next = buildRecord(
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
  validateCase(next);

  // Check material equality (we ignore links since links are mutated via CaseLink)
  const norm = (r: CaseRecord) =>
    JSON.stringify({ ...r, updatedAt: "", createdAt: "", linkedCaseIds: [] });
  if (norm(current) === norm(next)) {
    const reason =
      update.status && update.status === current.status
        ? `Case is already ${current.status}; no material fields changed.`
        : "No material fields changed.";
    return { record: current, changed: false, reason };
  }

  // Duplicate checks excluding current
  const title = normalizeMatchText(next.title);
  const target = normalizeMatchText(next.target);
  const endpoint = normalizeMatchText(next.endpoint);
  const bugClass = normalizeMatchText(next.bugClass);

  const stmt = db.prepare("SELECT * FROM cases WHERE status != 'killed' AND id != ?");
  const rows = stmt.all(id);
  let duplicate: CaseRecord | undefined;
  for (const row of rows) {
    if (
      normalizeMatchText(row.title as string) === title &&
      normalizeMatchText(row.target as string) === target &&
      normalizeMatchText(row.endpoint as string) === endpoint &&
      normalizeMatchText(row.bugClass as string) === bugClass
    ) {
      const linkStmt = db.prepare("SELECT target_id FROM case_links WHERE source_id = ?");
      const links = linkStmt.all(row.id) as { target_id: string }[];
      duplicate = mapRow(
        row,
        links.map((l) => l.target_id),
      );
      break;
    }
  }

  if (duplicate) {
    return {
      record: current,
      changed: false,
      reason: `Update would create a duplicate of case ${duplicate.id}`,
    };
  }

  insertOrReplaceCase(db, next);
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

  const next = buildRecord(
    {
      status: "confirmed",
      pocVerified: verification,
    },
    current,
  );
  validateCase(next);

  insertOrReplaceCase(db, next);
  return { record: next, changed: true };
}

// ── Link operations ──────────────────────────────────────────────────

export function linkCasesResult(sourceId: string, targetId: string): CaseLinkResult {
  const db = getDb();
  if (sourceId === targetId) {
    throw new Error("Cannot link a case to itself");
  }
  const source = getCaseById(sourceId);
  const target = getCaseById(targetId);
  if (!source) throw new Error(`Case not found: ${sourceId}`);
  if (!target) throw new Error(`Case not found: ${targetId}`);

  const checkStmt = db.prepare("SELECT 1 FROM case_links WHERE source_id = ? AND target_id = ?");
  const exists = checkStmt.get(sourceId, targetId);

  if (exists) {
    return { source, target, changed: false, reason: "Cases are already linked" };
  }

  // Atomic insert both directions into junction table
  const linkStmt = db.prepare("INSERT INTO case_links (source_id, target_id) VALUES (?, ?)");
  linkStmt.run(sourceId, targetId);
  linkStmt.run(targetId, sourceId);

  const now = new Date().toISOString();
  const updateTimeStmt = db.prepare("UPDATE cases SET updated_at = ? WHERE id = ?");
  updateTimeStmt.run(now, sourceId);
  updateTimeStmt.run(now, targetId);

  const finalSource = getCaseById(sourceId)!;
  const finalTarget = getCaseById(targetId)!;
  return { source: finalSource, target: finalTarget, changed: true };
}

export function unlinkCasesResult(sourceId: string, targetId: string): CaseLinkResult {
  const db = getDb();
  const source = getCaseById(sourceId);
  const target = getCaseById(targetId);
  if (!source) throw new Error(`Case not found: ${sourceId}`);
  if (!target) throw new Error(`Case not found: ${targetId}`);

  const checkStmt = db.prepare("SELECT 1 FROM case_links WHERE source_id = ? AND target_id = ?");
  const exists = checkStmt.get(sourceId, targetId);

  if (!exists) {
    return { source, target, changed: false, reason: "Cases are not linked" };
  }

  const unlinkStmt = db.prepare(
    "DELETE FROM case_links WHERE (source_id = ? AND target_id = ?) OR (source_id = ? AND target_id = ?)",
  );
  unlinkStmt.run(sourceId, targetId, targetId, sourceId);

  const now = new Date().toISOString();
  const updateTimeStmt = db.prepare("UPDATE cases SET updated_at = ? WHERE id = ?");
  updateTimeStmt.run(now, sourceId);
  updateTimeStmt.run(now, targetId);

  const finalSource = getCaseById(sourceId)!;
  const finalTarget = getCaseById(targetId)!;
  return { source: finalSource, target: finalTarget, changed: true };
}

// ── Search & Queries ─────────────────────────────────────────────────

function caseHaystack(record: CaseRecord, field?: CaseSearchField): string {
  if (field) {
    const val = record[field];
    if (Array.isArray(val)) return val.join(" ").toLowerCase();
    return (typeof val === "string" ? val : String(val ?? "")).toLowerCase();
  }
  return Object.entries(record)
    .filter(([k]) => !["id", "createdAt", "updatedAt", "reportedAt", "reportPath"].includes(k))
    .map(([, v]) => (Array.isArray(v) ? v.join(" ") : String(v ?? "")))
    .filter(Boolean)
    .join("\n")
    .toLowerCase();
}

export function searchCases(options: CaseSearchOptions = {}): {
  cases: CaseRecord[];
  total: number;
} {
  const query = options.query?.trim().toLowerCase();
  const field = options.field;
  const tag = options.tag?.trim().toLowerCase();
  const limit = Math.max(1, Math.min(options.limit ?? 50, 200));
  const offset = Math.max(0, options.offset ?? 0);

  const STATUS_ORDER: CaseStatus[] = [
    "hypothesis",
    "investigating",
    "confirmed",
    "blocked",
    "killed",
    "reported",
  ];

  const filtered = readCasefile()
    .filter((r) => !options.status || r.status === options.status)
    .filter((r) => !options.confidence || r.confidence === options.confidence)
    .filter((r) => !options.severity || r.severity === options.severity)
    .filter((r) => !options.priority || r.priority === options.priority)
    .filter((r) => !tag || r.tags?.some((t) => t.toLowerCase() === tag))
    .filter((r) => !query || caseHaystack(r, field).includes(query))
    .sort((a, b) => {
      const aStatus = STATUS_ORDER.indexOf(a.status);
      const bStatus = STATUS_ORDER.indexOf(b.status);
      if (aStatus !== bStatus) return aStatus - bStatus;
      return b.updatedAt.localeCompare(a.updatedAt);
    });

  return {
    total: filtered.length,
    cases: filtered.slice(offset, offset + limit),
  };
}

export function countCases(): {
  total: number;
  byStatus: Record<string, number>;
  bySeverity: Record<string, number>;
} {
  const records = readCasefile();
  const byStatus: Record<string, number> = {};
  const bySeverity: Record<string, number> = {};
  for (const r of records) {
    byStatus[r.status] = (byStatus[r.status] ?? 0) + 1;
    if (r.severity) bySeverity[r.severity] = (bySeverity[r.severity] ?? 0) + 1;
  }
  return { total: records.length, byStatus, bySeverity };
}

// ── Format helpers ───────────────────────────────────────────────────

export function formatCase(record: CaseRecord): string {
  const bits = [
    `${record.id} [${record.status}/${record.confidence}] ${record.title}`,
    record.priority ? `priority=${record.priority}` : undefined,
    record.severity ? `severity=${record.severity}` : undefined,
    record.bugClass ? `class=${record.bugClass}` : undefined,
    record.summary ? `summary=${record.summary}` : undefined,
    record.endpoint ? `endpoint=${record.endpoint}` : undefined,
    record.target ? `target=${record.target}` : undefined,
    record.tags?.length ? `tags=${record.tags.join(",")}` : undefined,
    record.linkedCaseIds.length ? `links=${record.linkedCaseIds.join(",")}` : undefined,
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
      ["id", "createdAt", "updatedAt"].includes(key)
    )
      continue;
    const label = key.charAt(0).toUpperCase() + key.slice(1).replace(/([A-Z])/g, " $1");
    const display = Array.isArray(val)
      ? val.join(", ")
      : typeof val === "object"
        ? JSON.stringify(val)
        : val;
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

  insertOrReplaceCase(db, next);
  return { path: reportPath, record: next };
}
