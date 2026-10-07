/**
 * Kill-chain engagement objectives (OPPLAN-lite) and exploit-chain suggestion
 * engine.
 *
 * Extracted from ledger.ts (verbatim bodies). ledger.ts re-exports the public
 * API so callers are unchanged.
 */

import { randomUUID } from "node:crypto";

import {
  CHAIN_CLASS_RE,
  type ChainPattern,
  type ChainSuggestion,
  chainText,
  hasChainClass,
  listPrimitives,
  sameAssetOrRelated,
} from "./chains.ts";
import type {
  CaseLinkKind,
  CaseRecord,
  ObjectivePhase,
  ObjectiveRecord,
  ObjectiveStatus,
} from "./ledger.ts";
import {
  getCaseById,
  OBJECTIVE_PHASE_VALUES,
  OBJECTIVE_STATUS_VALUES,
  OBJECTIVE_TRANSITIONS,
  readCasefile,
} from "./ledger.ts";
import {
  getDb,
  normalizeText,
  stableShortId,
  withImmediateTransaction,
} from "./ledger-internal.ts";
import type { DatabaseSync } from "./sqlite-compat/index.ts";

// ── Engagement objectives (OPPLAN-lite) ────────────────────────────

function mapObjectiveRow(row: any, caseIds: string[]): ObjectiveRecord {
  return {
    id: row.id,
    title: row.title,
    phase: row.phase,
    status: row.status,
    dependsOn: JSON.parse(row.depends_on_json ?? "[]") as string[],
    acceptance: row.acceptance ?? undefined,
    blockedReason: row.blocked_reason ?? undefined,
    caseIds,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function loadObjectiveCaseIds(db: DatabaseSync, objectiveId: string): string[] {
  return (
    db
      .prepare("SELECT case_id FROM objective_cases WHERE objective_id = ? ORDER BY case_id")
      .all(objectiveId) as {
      case_id: string;
    }[]
  ).map((r) => r.case_id);
}

function getObjectiveRow(db: DatabaseSync, id: string): ObjectiveRecord | undefined {
  const row = db.prepare("SELECT * FROM objectives WHERE id = ?").get(id) as any;
  if (!row) return;
  return mapObjectiveRow(row, loadObjectiveCaseIds(db, id));
}

export function addObjectiveResult(input: {
  title: string;
  phase: string;
  acceptance?: string;
  dependsOn?: string[];
}): ObjectiveRecord {
  if (!(OBJECTIVE_PHASE_VALUES as readonly string[]).includes(input.phase)) {
    throw new Error(
      `Invalid objective phase: ${input.phase}. Phases: ${OBJECTIVE_PHASE_VALUES.join(", ")}`,
    );
  }
  const title = normalizeText(input.title);
  if (!title) throw new Error("Objective title must not be empty");

  const db = getDb();
  const dependsOn = input.dependsOn ?? [];
  for (const depId of dependsOn) {
    if (!getObjectiveRow(db, depId)) throw new Error(`Dependency objective not found: ${depId}`);
  }

  const now = new Date().toISOString();
  const objective: ObjectiveRecord = {
    id: `obj_${stableShortId(`${input.phase}\n${title}\n${randomUUID()}`)}`,
    title,
    phase: input.phase as ObjectivePhase,
    status: "pending",
    dependsOn,
    acceptance: normalizeText(input.acceptance),
    caseIds: [],
    createdAt: now,
    updatedAt: now,
  };
  db.prepare(
    `INSERT INTO objectives (id, title, phase, status, depends_on_json, acceptance, created_at, updated_at)
     VALUES (?, ?, ?, 'pending', ?, ?, ?, ?)`,
  ).run(
    objective.id,
    title,
    objective.phase,
    JSON.stringify(dependsOn),
    objective.acceptance ?? null,
    now,
    now,
  );
  return objective;
}

export function getObjectiveById(id: string): ObjectiveRecord | undefined {
  return getObjectiveRow(getDb(), id);
}

export function listObjectives(
  filter: { phase?: string; status?: string } = {},
): ObjectiveRecord[] {
  const db = getDb();
  if (filter.phase && !(OBJECTIVE_PHASE_VALUES as readonly string[]).includes(filter.phase)) {
    throw new Error(`Invalid objective phase: ${filter.phase}`);
  }
  if (filter.status && !(OBJECTIVE_STATUS_VALUES as readonly string[]).includes(filter.status)) {
    throw new Error(`Invalid objective status: ${filter.status}`);
  }
  const rows = db.prepare("SELECT * FROM objectives ORDER BY created_at").all() as any[];
  return rows
    .map((row) => mapObjectiveRow(row, loadObjectiveCaseIds(db, row.id)))
    .filter(
      (o) =>
        (!filter.phase || o.phase === filter.phase) &&
        (!filter.status || o.status === filter.status),
    );
}

/**
 * Transition an objective's status through the state machine. Starting work
 * (`in-progress`) requires every dependency to be `completed` — the OPPLAN
 * ordering is enforced in code, not prose.
 */
export function updateObjectiveStatusResult(
  id: string,
  status: string,
  blockedReason?: string,
): ObjectiveRecord {
  if (!(OBJECTIVE_STATUS_VALUES as readonly string[]).includes(status)) {
    throw new Error(
      `Invalid objective status: ${status}. Statuses: ${OBJECTIVE_STATUS_VALUES.join(", ")}`,
    );
  }
  const db = getDb();
  const current = getObjectiveRow(db, id);
  if (!current) throw new Error(`Objective not found: ${id}`);
  const allowed = OBJECTIVE_TRANSITIONS[current.status];
  if (!allowed.includes(status as ObjectiveStatus)) {
    throw new Error(
      `Invalid transition ${current.status} -> ${status}. Allowed from ${current.status}: ${allowed.join(", ") || "none (terminal)"}`,
    );
  }
  if (status === "in-progress") {
    const deps = current.dependsOn
      .map((d) => getObjectiveRow(db, d))
      .filter((d) => d !== undefined);
    const unmet = deps.filter((d) => d!.status !== "completed");
    if (unmet.length > 0) {
      throw new Error(
        `Dependencies not met for ${id}: ${unmet.map((d) => `${d!.id} (${d!.status})`).join(", ")}`,
      );
    }
  }
  const reason = status === "blocked" ? normalizeText(blockedReason) : undefined;
  if (status === "blocked" && !reason) {
    throw new Error("Blocking an objective requires blocked_reason");
  }
  db.prepare(
    "UPDATE objectives SET status = ?, blocked_reason = ?, updated_at = ? WHERE id = ?",
  ).run(status, reason ?? null, new Date().toISOString(), id);
  return getObjectiveRow(db, id)!;
}

export function linkObjectiveCase(objectiveId: string, caseId: string): ObjectiveRecord {
  const db = getDb();
  const objective = getObjectiveRow(db, objectiveId);
  if (!objective) throw new Error(`Objective not found: ${objectiveId}`);
  const current = getCaseById(caseId);
  if (!current) throw new Error(`Case not found: ${caseId}`);
  db.prepare("INSERT OR IGNORE INTO objective_cases (objective_id, case_id) VALUES (?, ?)").run(
    objectiveId,
    caseId,
  );
  return getObjectiveRow(db, objectiveId)!;
}

export function unlinkObjectiveCase(objectiveId: string, caseId: string): ObjectiveRecord {
  const db = getDb();
  const objective = getObjectiveRow(db, objectiveId);
  if (!objective) throw new Error(`Objective not found: ${objectiveId}`);
  db.prepare("DELETE FROM objective_cases WHERE objective_id = ? AND case_id = ?").run(
    objectiveId,
    caseId,
  );
  return getObjectiveRow(db, objectiveId)!;
}

export function deleteObjectiveResult(id: string): boolean {
  const db = getDb();
  return withImmediateTransaction(db, () => {
    // Refuse deletion while other objectives depend on this one — a dangling
    // depends_on entry would let dependents start once their remaining deps
    // completed, silently skipping the deleted objective's ordering.
    const dependents = (
      db.prepare("SELECT id, depends_on_json FROM objectives").all() as {
        id: string;
        depends_on_json: string;
      }[]
    ).filter(
      (row) => row.id !== id && (JSON.parse(row.depends_on_json ?? "[]") as string[]).includes(id),
    );
    if (dependents.length > 0) {
      throw new Error(
        `Cannot delete ${id}: objectives ${dependents.map((d) => d.id).join(", ")} depend on it. ` +
          "Remove the dependency first.",
      );
    }
    const result = db.prepare("DELETE FROM objectives WHERE id = ?").run(id);
    return result.changes > 0;
  });
}

export function suggestChains(caseId?: string): ChainSuggestion[] {
  // Pair over ALL non-terminal cases; the caseId filter narrows the RESULTS
  // to suggestions involving that case (filtering the inputs first would drop
  // unlinked partner cases and kill cross-case pairing).
  const cases = readCasefile().filter((c) => c.status !== "killed" && c.status !== "reported");
  // Already-linked pairs are existing knowledge, not a missed combination —
  // suggesting them again is noise. One query for every link row.
  const linkedPairs = new Set<string>();
  const linkRows = getDb().prepare("SELECT source_id, target_id FROM case_links").all() as {
    source_id: string;
    target_id: string;
  }[];
  for (const row of linkRows) linkedPairs.add([row.source_id, row.target_id].sort().join("+"));
  const suggestions: ChainSuggestion[] = [];
  const seen = new Set<string>();
  const confirmed = (c: CaseRecord) => c.status === "confirmed";
  const confidenceFor = (a: CaseRecord, b?: CaseRecord) => {
    const both = confirmed(a) && (!b || confirmed(b));
    const one = confirmed(a) || (b ? confirmed(b) : false);
    const anyHypothesis = a.status === "hypothesis" || (b ? b.status === "hypothesis" : false);
    if (both) return 90;
    if (anyHypothesis) return 40; // unproven primitives chain weakly
    return one ? 75 : 60;
  };
  const add = (
    pattern: ChainPattern,
    a: CaseRecord,
    b: CaseRecord | undefined,
    rationale: string,
    kind?: CaseLinkKind,
  ) => {
    if (b && linkedPairs.has([a.id, b.id].sort().join("+"))) return; // already known
    const key = b ? `${pattern}:${[a.id, b.id].sort().join("+")}` : `${pattern}:${a.id}`;
    if (seen.has(key)) return;
    seen.add(key);
    suggestions.push({
      pattern,
      sourceId: a.id,
      targetId: b?.id,
      sourceTitle: a.title,
      targetTitle: b?.title,
      rationale,
      confidence: confidenceFor(a, b),
      suggestedKind: kind,
    });
  };

  // Pair rules as data: (classifier A, classifier B, rationale, link kind).
  // One loop replaces seven copy-pasted pair loops — XBOW expansion adds
  // chaining-heavy pairs observed in the 104-benchmark full corpus.
  const PAIR_RULES: Array<{
    pattern: Exclude<ChainPattern, "ssti_rce" | "deserialization_rce" | "xxe_file_read">;
    a: RegExp;
    b: RegExp;
    rationale: (a: CaseRecord, b: CaseRecord) => string;
    kind?: CaseLinkKind;
  }> = [
    {
      pattern: "credential_endpoint",
      a: CHAIN_CLASS_RE.credential,
      b: CHAIN_CLASS_RE.authEndpoint,
      kind: "depends-on",
      rationale: (a, b) =>
        `Use leaked credential "${a.title}" to authenticate against "${b.title}" → account takeover`,
    },
    {
      pattern: "redirect_oauth",
      a: CHAIN_CLASS_RE.redirect,
      b: CHAIN_CLASS_RE.oauth,
      rationale: (a, b) =>
        `Chain open redirect "${a.title}" into OAuth flow "${b.title}" to steal access tokens`,
    },
    {
      pattern: "xss_csrf",
      a: CHAIN_CLASS_RE.xss,
      b: CHAIN_CLASS_RE.stateChange,
      rationale: (a, b) =>
        `Use XSS "${a.title}" to drive state-changing "${b.title}" (CSRF bypass / victim-action)`,
    },
    {
      pattern: "idor_data_leak",
      a: CHAIN_CLASS_RE.idor,
      b: CHAIN_CLASS_RE.userData,
      rationale: (a, b) => `Use IDOR "${a.title}" to enumerate user data via "${b.title}"`,
    },
    {
      pattern: "race_condition_business",
      a: CHAIN_CLASS_RE.race,
      b: CHAIN_CLASS_RE.payment,
      rationale: (a, b) =>
        `Use race condition "${a.title}" on financial endpoint "${b.title}" (double-spend / bypass)`,
    },
    {
      pattern: "info_disclosure_ssrf",
      a: CHAIN_CLASS_RE.infoDisclosure,
      b: CHAIN_CLASS_RE.ssrf,
      rationale: (a, b) =>
        `Use internal URL/config from "${a.title}" as SSRF target via "${b.title}"`,
    },
    // ── XBOW expansion ─────────────────────────────────────────────
    {
      pattern: "sqli_credential_dump",
      a: CHAIN_CLASS_RE.sqli,
      b: CHAIN_CLASS_RE.credential,
      kind: "depends-on",
      rationale: (a, b) =>
        `Use SQLi "${a.title}" to dump credentials via "${b.title}" → authenticated takeover`,
    },
    {
      pattern: "sqli_credential_dump",
      a: CHAIN_CLASS_RE.sqli,
      b: CHAIN_CLASS_RE.fileUpload,
      kind: "depends-on",
      rationale: (a, b) =>
        `Use SQLi "${a.title}" to pivot into file-upload surface "${b.title}" → RCE`,
    },
    {
      pattern: "lfi_rce_chain",
      a: CHAIN_CLASS_RE.lfi,
      b: CHAIN_CLASS_RE.fileUpload,
      kind: "depends-on",
      rationale: (a, b) =>
        `Chain LFI/path traversal "${a.title}" with file upload "${b.title}" → RCE via poison inclusion`,
    },
    {
      pattern: "ssrf_internal_pivot",
      a: CHAIN_CLASS_RE.ssrf,
      b: CHAIN_CLASS_RE.commandInjection,
      kind: "depends-on",
      rationale: (a, b) => `Pivot SSRF "${a.title}" into internal command surface "${b.title}"`,
    },
    {
      pattern: "jwt_privilege_escalation",
      a: CHAIN_CLASS_RE.jwt,
      b: CHAIN_CLASS_RE.businessLogic,
      kind: "depends-on",
      rationale: (a, b) => `Use JWT tampering "${a.title}" to bypass authorization in "${b.title}"`,
    },
    {
      pattern: "graphql_chain",
      a: CHAIN_CLASS_RE.graphql,
      b: CHAIN_CLASS_RE.sqli,
      kind: "depends-on",
      rationale: (a, b) => `Drive GraphQL endpoint "${a.title}" into SQLi sink "${b.title}"`,
    },
    {
      pattern: "graphql_chain",
      a: CHAIN_CLASS_RE.graphql,
      b: CHAIN_CLASS_RE.idor,
      kind: "depends-on",
      rationale: (a, b) =>
        `Drive GraphQL endpoint "${a.title}" into IDOR sink "${b.title}" → broken-access via GraphQL`,
    },
    {
      pattern: "lfi_rce_chain",
      a: CHAIN_CLASS_RE.lfi,
      b: CHAIN_CLASS_RE.commandInjection,
      kind: "depends-on",
      rationale: (a, b) => `Use LFI "${a.title}" to pivot into command execution "${b.title}"`,
    },
    {
      pattern: "business_logic_privilege",
      a: CHAIN_CLASS_RE.businessLogic,
      b: CHAIN_CLASS_RE.authEndpoint,
      kind: "depends-on",
      rationale: (a, b) =>
        `Exploit business-logic flaw "${a.title}" to escalate privilege via "${b.title}"`,
    },
    {
      pattern: "upload_rce",
      a: CHAIN_CLASS_RE.fileUpload,
      b: CHAIN_CLASS_RE.commandInjection,
      kind: "depends-on",
      rationale: (a, b) => `Use file upload "${a.title}" to achieve RCE via "${b.title}"`,
    },
    {
      pattern: "crypto_auth_bypass",
      a: CHAIN_CLASS_RE.crypto,
      b: CHAIN_CLASS_RE.authEndpoint,
      kind: "depends-on",
      rationale: (a, b) =>
        `Use crypto weakness "${a.title}" to bypass authentication on "${b.title}"`,
    },
  ];

  for (const rule of PAIR_RULES) {
    const aCases = cases.filter((c) => rule.a.test(chainText(c)));
    const bCases = cases.filter((c) => rule.b.test(chainText(c)));
    for (const a of aCases) {
      for (const b of bCases) {
        if (a.id === b.id || !sameAssetOrRelated(a, b)) continue;
        add(rule.pattern, a, b, rule.rationale(a, b), rule.kind);
      }
    }
  }

  // SSTI → RCE (single-case escalation)
  for (const s of cases.filter((c) => hasChainClass(c, CHAIN_CLASS_RE.ssti))) {
    add("ssti_rce", s, undefined, `Escalate SSTI "${s.title}" to RCE via template-engine gadgets`);
  }
  // XBOW expansion — single-case escalations for isolated primitives that chain internally
  for (const c of cases.filter((c) => hasChainClass(c, CHAIN_CLASS_RE.deserialization))) {
    add(
      "deserialization_rce",
      c,
      undefined,
      `Escalate insecure deserialization "${c.title}" to RCE via gadget chain`,
    );
  }
  for (const c of cases.filter((c) => hasChainClass(c, CHAIN_CLASS_RE.xxe))) {
    add(
      "xxe_file_read",
      c,
      undefined,
      `Use XXE "${c.title}" to read arbitrary files → credential/flag exfiltration`,
    );
  }
  // GraphQL → IDOR is also a pair, but GraphQL alone often indicates IDOR/broken-access surface
  for (const c of cases.filter(
    (c) => hasChainClass(c, CHAIN_CLASS_RE.graphql) && hasChainClass(c, CHAIN_CLASS_RE.idor),
  )) {
    // avoid duplicate with pair-rule graphql_chain; this is the single-case where GraphQL endpoint itself is IDOR
    add(
      "graphql_chain",
      c,
      undefined,
      `GraphQL endpoint "${c.title}" exposes IDOR/broken-access → enumerate via introspection`,
    );
  }

  // Primitive-based suggestions: material found on one case (a leaked token,
  // a victim session) applied to another case's attack surface.
  const primitiveRows = listPrimitives();
  const usableKinds = new Set(["credential", "token", "session", "account"]);
  for (const prim of primitiveRows) {
    if (!usableKinds.has(prim.kind)) continue;
    for (const producerId of prim.caseIds) {
      const producer = cases.find((c) => c.id === producerId);
      if (!producer) continue;
      for (const consumer of cases) {
        if (consumer.id === producer.id || !sameAssetOrRelated(producer, consumer)) continue;
        if (!CHAIN_CLASS_RE.authEndpoint.test(chainText(consumer))) continue;
        add(
          "primitive_use",
          producer,
          consumer,
          `Use ${prim.kind} "${prim.label}"${prim.capabilities ? ` (${prim.capabilities})` : ""} from "${producer.title}" against "${consumer.title}"`,
          "depends-on",
        );
      }
    }
  }

  const scoped = caseId
    ? suggestions.filter((s) => s.sourceId === caseId || s.targetId === caseId)
    : suggestions;
  return scoped.sort((a, b) => b.confidence - a.confidence);
}
