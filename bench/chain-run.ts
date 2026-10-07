/**
 * Chain-suggestion benchmark runner — XBOW 104 style.
 *
 * Creates synthetic cases for each CHAIN_CORPUS expectation and drives the
 * REAL suggestChains engine to measure recall on same-asset chains vs
 * rejection of cross-asset/negated pairs.
 *
 * Run: bun bench/chain-run.ts            (scoreboard + writes bench/results/chain-latest.json)
 *      bun bench/chain-run.ts --json     (JSON only)
 */

import {
  mkdirSync,
  mkdtempSync,
  rmSync,
  writeFileSync as writeArtifact,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  addEvidenceItemResult,
  addCaseResult as ledgerAddCaseResult,
  setCasefilePath as setPath,
} from "../packages/pi-casefile/src/ledger.ts";
import { suggestChains } from "../packages/pi-casefile/src/objectives.ts";
import { CHAIN_CORPUS, type ChainExpectation } from "./chain-corpus.ts";
import { CHAIN_HOLDOUT } from "./chain-holdout.ts";

const here = dirname(fileURLToPath(import.meta.url));
const outDir = join(here, "results");

function artifactFor(dir: string): string {
  const p = join(dir, `obs-${Date.now()}-${Math.random().toString(36).slice(2)}.txt`);
  writeArtifact(p, "observed signal", "utf8");
  return p;
}

/** One ledger case may belong to exactly one corpus entry — collisions are a corpus bug. */
function claimCaseOwner(ownerByCaseId: Map<string, string>, caseId: string, owner: string): void {
  const existing = ownerByCaseId.get(caseId);
  if (existing && existing !== owner) {
    throw new Error(
      `chain-bench corpus collision: ${owner} and ${existing} resolved to the same ledger case ${caseId} — make titles lexically distinct`,
    );
  }
  ownerByCaseId.set(caseId, owner);
}

export type ChainBenchResult = {
  total: number;
  shouldSuggest: number;
  correctlySuggested: number;
  correctlyRejected: number;
  shouldNotSuggest: number;
  score: number;
  cGain: number; // recall on shouldSuggest
  details: Array<{
    id: string;
    pattern: string;
    expected: boolean;
    suggested: boolean;
    pass: boolean;
    note: string;
  }>;
};

export function runChainBench(): ChainBenchResult {
  const dir = mkdtempSync(join(tmpdir(), "chain-bench-"));
  const dbPath = join(dir, "casefile.db");
  const prevWorkspace = process.env.CASEFILE_WORKSPACE_ROOT;
  process.env.CASEFILE_WORKSPACE_ROOT = dir;
  setPath(dbPath);
  const artifact = artifactFor(dir);

  // Map expectation id -> case ids (a, b)
  const caseMap = new Map<string, { aId: string; bId?: string }>();
  const ownerByCaseId = new Map<string, string>();

  // The ledger's near-duplicate gate merges same-target cases sharing ≥3
  // significant title tokens — without a unique marker, corpus entries with
  // overlapping vocabulary silently collapse onto ONE case id and cross-entry
  // suggestions poison pair-scoped scoring. The bracketed ref is a single
  // unique ≥5-char token: inert for classifiers, decisive for dedup.
  const refFor = (expId: string, side: "a" | "b") => `${expId.replace(/[^a-z0-9]/gi, "")}${side}`;

  // Per-entry isolation host. The near-duplicate gate only merges cases with
  // the SAME normalized target, so giving each entry its own <id>.bench.test
  // host makes merges structurally impossible without rewriting titles.
  // Chain pairing is unaffected: entries remain related via the shared
  // bench.test registrable domain, so realistic cross-entry suggestions still
  // occur — pair-scoped scoring ignores them.
  const hostFor = (expId: string) => `${expId.replace(/[^a-z0-9]/gi, "").slice(0, 32)}.bench.test`;

  for (const exp of CHAIN_CORPUS) {
    // Cross-asset expectations keep their distinct targets; same-target
    // entries get the isolation host.
    const sameTarget = exp.targetA.toLowerCase() === exp.targetB.toLowerCase();
    const targetForA = sameTarget ? hostFor(exp.id) : exp.targetA;
    const targetForB = sameTarget ? hostFor(exp.id) : exp.targetB;
    const aRes = ledgerAddCaseResult({
      title: `${exp.a.title} [${refFor(exp.id, "a")}]`,
      target: targetForA,
      bugClass: exp.a.bugClass,
      evidence: `${exp.a.title} evidence — ${exp.a.bugClass}`,
      tags: exp.a.tags,
      disproveIf: ["test negated"],
    } as any);
    if (aRes.record.title !== `${exp.a.title} [${refFor(exp.id, "a")}]`) {
      throw new Error(
        `chain-bench corpus collision: entry ${exp.id}-A was merged into existing case ${aRes.record.id} "${aRes.record.title}" by the near-duplicate gate — make its title lexically distinct`,
      );
    }
    claimCaseOwner(ownerByCaseId, aRes.record.id, `${exp.id}-A`);
    addEvidenceItemResult(aRes.record.id, {
      role: "observation",
      summary: "chain bench observation",
      artifactPath: artifact,
    });
    let bId: string | undefined;
    if (exp.b) {
      const bRes = ledgerAddCaseResult({
        title: `${exp.b.title} [${refFor(exp.id, "b")}]`,
        target: targetForB,
        bugClass: exp.b.bugClass,
        evidence: `${exp.b.title} evidence — ${exp.b.bugClass}`,
        tags: exp.b.tags,
        disproveIf: ["test negated"],
      } as any);
      if (bRes.record.title !== `${exp.b.title} [${refFor(exp.id, "b")}]`) {
        throw new Error(
          `chain-bench corpus collision: entry ${exp.id}-B was merged into existing case ${bRes.record.id} "${bRes.record.title}" by the near-duplicate gate — make its title lexically distinct`,
        );
      }
      claimCaseOwner(ownerByCaseId, bRes.record.id, `${exp.id}-B`);
      addEvidenceItemResult(bRes.record.id, {
        role: "observation",
        summary: "chain bench observation",
        artifactPath: artifact,
      });
      bId = bRes.record.id;
    }
    caseMap.set(exp.id, { aId: aRes.record.id, bId });
  }

  const suggestions = suggestChains();
  // Pattern-scoped index: `pattern:id+id`. Positives require the EXPECTED
  // pattern to fire between the pair — any-pattern firing is not a match.
  const suggestionKeys = new Set(
    suggestions.map((s) => `${s.pattern}:${[s.sourceId, s.targetId ?? ""].sort().join("+")}`),
  );
  // Any-pattern pair index: negatives must produce NO suggestion at all
  // between their two cases — an accidental co-fire of the wrong rule still
  // means this pair reads as chainable to the engine.
  const pairKeys = new Set(
    suggestions.filter((s) => s.targetId).map((s) => [s.sourceId, s.targetId!].sort().join("+")),
  );

  const details: ChainBenchResult["details"] = [];
  let correctlySuggested = 0;
  let correctlyRejected = 0;
  const shouldSuggest = CHAIN_CORPUS.filter((c) => c.shouldSuggest).length;
  const shouldNotSuggest = CHAIN_CORPUS.filter((c) => !c.shouldSuggest).length;

  const soloSuggested = (exp: ChainExpectation, aId: string) =>
    suggestions.some(
      (s) => s.pattern === exp.pattern && (s.sourceId === aId || s.targetId === aId),
    );

  for (const exp of CHAIN_CORPUS) {
    const ids = caseMap.get(exp.id)!;
    let suggested: boolean;
    if (ids.bId) {
      const pair = [ids.aId, ids.bId].sort().join("+");
      // `suggested` uniformly means "the engine surfaced a chain here":
      // positives require the EXPECTED pattern between the pair; negatives
      // fail when ANY rule fires between them.
      suggested = exp.shouldSuggest
        ? suggestionKeys.has(`${exp.pattern}:${pair}`)
        : pairKeys.has(pair);
      // Single-case expectations may also be satisfied by a solo escalation.
      if (!suggested && exp.shouldSuggest && !exp.b) {
        suggested = soloSuggested(exp, ids.aId);
      }
    } else {
      suggested = soloSuggested(exp, ids.aId);
    }
    const pass = suggested === exp.shouldSuggest;
    if (exp.shouldSuggest && pass) correctlySuggested++;
    if (!exp.shouldSuggest && pass) correctlyRejected++;
    details.push({
      id: exp.id,
      pattern: exp.pattern,
      expected: exp.shouldSuggest,
      suggested,
      pass,
      note: pass
        ? exp.shouldSuggest
          ? "suggested"
          : "correctly rejected"
        : exp.shouldSuggest
          ? "missed — chain not suggested"
          : "false positive — chain incorrectly suggested",
    });
  }

  const score = (correctlySuggested + correctlyRejected) / CHAIN_CORPUS.length;
  const cGain = correctlySuggested / shouldSuggest;

  // cleanup
  setPath(undefined as any);
  if (prevWorkspace === undefined) delete process.env.CASEFILE_WORKSPACE_ROOT;
  else process.env.CASEFILE_WORKSPACE_ROOT = prevWorkspace;
  try {
    rmSync(dir, { recursive: true, force: true });
  } catch {}

  return {
    total: CHAIN_CORPUS.length,
    shouldSuggest,
    correctlySuggested,
    correctlyRejected,
    shouldNotSuggest,
    score,
    cGain,
    details,
  };
}

export type HoldoutReport = {
  total: number;
  suggested: number;
  recall: number;
  misses: Array<{ id: string; pattern: string; difficulty: string }>;
};

/**
 * Generalization probe on paraphrased findings. NOT a gate: in-vocabulary
 * entries are expected to pass, "paraphrase" difficulty entries document
 * vocabulary the classifiers do not cover yet.
 */
export function runHoldoutProbe(): HoldoutReport {
  const dir = mkdtempSync(join(tmpdir(), "chain-holdout-"));
  const dbPath = join(dir, "casefile.db");
  const prevWorkspace = process.env.CASEFILE_WORKSPACE_ROOT;
  process.env.CASEFILE_WORKSPACE_ROOT = dir;
  setPath(dbPath);
  const artifact = artifactFor(dir);
  try {
    const caseIds = new Map<string, { aId: string; bId?: string }>();
    for (const entry of CHAIN_HOLDOUT) {
      const ref = entry.id.replace(/[^a-z0-9]/gi, "");
      const host = `${ref}.bench.test`;
      const aRes = ledgerAddCaseResult({
        title: `${entry.a.title} [${ref}a]`,
        target: host,
        bugClass: entry.a.bugClass,
        evidence: `${entry.a.title} evidence`,
        tags: entry.a.tags,
        disproveIf: ["test negated"],
      } as any);
      addEvidenceItemResult(aRes.record.id, {
        role: "observation",
        summary: "holdout observation",
        artifactPath: artifact,
      });
      let bId: string | undefined;
      if (entry.b) {
        const bRes = ledgerAddCaseResult({
          title: `${entry.b.title} [${ref}b]`,
          target: host,
          bugClass: entry.b.bugClass,
          evidence: `${entry.b.title} evidence`,
          tags: entry.b.tags,
          disproveIf: ["test negated"],
        } as any);
        addEvidenceItemResult(bRes.record.id, {
          role: "observation",
          summary: "holdout observation",
          artifactPath: artifact,
        });
        bId = bRes.record.id;
      }
      caseIds.set(entry.id, { aId: aRes.record.id, bId });
    }
    const suggestions = suggestChains();
    const details: HoldoutReport["misses"] = [];
    let suggested = 0;
    for (const entry of CHAIN_HOLDOUT) {
      const ids = caseIds.get(entry.id)!;
      const pair = ids.bId ? [ids.aId, ids.bId].sort().join("+") : undefined;
      const hit = pair
        ? suggestions.some(
            (s) =>
              s.pattern === (entry.pattern as ChainExpectation["pattern"]) &&
              [s.sourceId, s.targetId ?? ""].sort().join("+") === pair,
          )
        : suggestions.some(
            (s) =>
              s.pattern === (entry.pattern as ChainExpectation["pattern"]) &&
              (s.sourceId === ids.aId || s.targetId === ids.aId),
          );
      if (hit) suggested++;
      else details.push({ id: entry.id, pattern: entry.pattern, difficulty: entry.difficulty });
    }
    return {
      total: CHAIN_HOLDOUT.length,
      suggested,
      recall: suggested / CHAIN_HOLDOUT.length,
      misses: details,
    };
  } finally {
    setPath(undefined as any);
    if (prevWorkspace === undefined) delete process.env.CASEFILE_WORKSPACE_ROOT;
    else process.env.CASEFILE_WORKSPACE_ROOT = prevWorkspace;
    try {
      rmSync(dir, { recursive: true, force: true });
    } catch {}
  }
}

function scoreboard(r: ChainBenchResult): string {
  const lines: string[] = [];
  lines.push("XPI chain-suggestion benchmark — XBOW 104 style (cGain = recall on chaining pairs)");
  lines.push("=".repeat(80));
  for (const d of r.details) {
    const mark = d.pass ? "PASS" : "FAIL";
    lines.push(
      `[${mark}] ${d.id.padEnd(22)} ${d.pattern.padEnd(26)} exp=${String(d.expected).padEnd(5)} got=${String(d.suggested).padEnd(5)} — ${d.note}`,
    );
  }
  lines.push("-".repeat(80));
  lines.push(
    `SCORE ${r.correctlySuggested + r.correctlyRejected}/${r.total} = ${(r.score * 100).toFixed(1)}%  |  cGain (chain recall) ${r.correctlySuggested}/${r.shouldSuggest} = ${(r.cGain * 100).toFixed(1)}%  |  correctly rejected ${r.correctlyRejected}/${r.shouldNotSuggest}`,
  );
  lines.push(
    `Baseline (pre-expansion 8 patterns) would score ~ ${((8 / 18) * 100).toFixed(1)}% cGain (8/18 pairs) → current ${(r.cGain * 100).toFixed(1)}% (+${((r.cGain - 8 / 18) * 100).toFixed(1)}pp)`,
  );
  return lines.join("\n");
}

if (import.meta.main) {
  const report = runChainBench();
  const holdout = runHoldoutProbe();
  mkdirSync(outDir, { recursive: true });
  writeFileSync(
    join(outDir, "chain-latest.json"),
    `${JSON.stringify({ ...report, holdout }, null, 2)}\n`,
  );
  const out = (s: string) => console.log(s);
  if (process.argv.includes("--json")) {
    out(JSON.stringify({ ...report, holdout }, null, 2));
  } else {
    out(scoreboard(report));
    out("");
    out(
      `HOLDOUT (paraphrase probe, non-gating): ${holdout.suggested}/${holdout.total} recalled` +
        ` (${(holdout.recall * 100).toFixed(0)}%)` +
        (holdout.misses.length
          ? ` — misses: ${holdout.misses.map((m) => `${m.id}[${m.difficulty}]`).join(", ")}`
          : ""),
    );
    out(`\nwrote ${join(outDir, "chain-latest.json")}`);
  }
  if (report.cGain < 0.85) {
    console.error(`\nchain cGain ${(report.cGain * 100).toFixed(1)}% below 85% threshold`);
    process.exit(1);
  }
}
