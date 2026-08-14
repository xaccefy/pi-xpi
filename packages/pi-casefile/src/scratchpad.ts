/**
 * Scratchpad — intermediate artifact store for pipeline runs.
 *
 * The casefile owns state transitions; the scratchpad owns artifacts.
 * Agents write their outputs here (recon maps, trace outputs, verification
 * logs) instead of stuffing everything into casefile text fields or relying
 * on each other's output streams (which creates an echo chamber).
 *
 * Directory layout per pipeline run (one subdir per phase — see PHASE_DIRS):
 *   {project_root}/.scratchpad/{run_id}/
 *     recon/      — fingerprints, tech detection, surface maps
 *     hunt/       — per-class findings
 *     gapfil/     — gap-fill audit notes
 *     trace/      — per-finding reachability traces
 *     skeptic/    — adversarial disproof attempts
 *     verify/     — PoC logs, run outputs (validate phase)
 *     chain/      — exploit-chain analysis
 *     patch/      — remediation work
 *     report/     — final report context
 *     state.json  — checkpoint file with phase completion + key IDs
 *
 * Resume re-reads scratchpad artifacts; it does not re-run completed phases
 * (idempotent). The `.scratchpad/` directory is preserved between runs;
 * `--fresh` clears it via scratchpad_clear().
 */

import { createHash } from "node:crypto";
import { existsSync, readdirSync, rmSync } from "node:fs";
import { basename, dirname, join, resolve } from "node:path";
import {
  assertSafeRegularFile,
  assertSafeStateDirectory,
  ensureSafeStateDirectory,
  readSafeFile,
  writeSafeFileAtomic,
} from "./safe-state.ts";

// ── Types ────────────────────────────────────────────────────────────

export type ScratchpadPhase =
  | "recon"
  | "hunt"
  | "gapfil"
  | "trace"
  | "skeptic"
  | "validate"
  | "chain"
  | "patch"
  | "report";

export interface ScratchpadCheckpoint {
  run_id: string;
  project_root: string;
  created_at: string;
  last_updated: string;
  /** Ordered list of phases that have completed (in pipeline order). */
  completed_phases: ScratchpadPhase[];
  /** ISO timestamp of the last phase completion. */
  last_phase_at: string | null;
  /** Key IDs produced by each phase — case IDs, finding IDs, etc. */
  phase_ids: Record<ScratchpadPhase, string[]>;
  /** Free-form summary per phase, set by checkpoint(). */
  phase_summaries: Record<ScratchpadPhase, string>;
}

export interface ScratchpadResume {
  checkpoint: ScratchpadCheckpoint;
  /** The next phase to run (or null if the run is done). */
  next_phase: ScratchpadPhase | null;
  /** Artifact references per phase: { trace: ["finding-abc.json", ...], ... } */
  artifacts: Record<string, string[]>;
}

// ── Constants ────────────────────────────────────────────────────────

// All accepted artifact buckets. Some are legacy/manual-only and should not be
// scheduled by ScratchpadResume for new swarm runs.
export const SCRATCHPAD_PHASES: ScratchpadPhase[] = [
  "recon",
  "hunt",
  "gapfil",
  "trace",
  "skeptic",
  "validate",
  "chain",
  "patch",
  "report",
];

// Active pipeline order for new/resumed runs.
export const PHASE_ORDER: ScratchpadPhase[] = [
  "recon",
  "hunt",
  "trace",
  "skeptic",
  "validate",
  "chain",
  "report",
];

const PHASE_DIRS: Record<ScratchpadPhase, string> = {
  recon: "recon",
  hunt: "hunt",
  gapfil: "gapfil",
  trace: "trace",
  skeptic: "skeptic",
  validate: "verify",
  chain: "chain",
  patch: "patch",
  report: "report",
};

const SCRATCHPAD_DIR = ".scratchpad";

// ── Helpers ──────────────────────────────────────────────────────────

let scratchpadRootOverride: string | undefined;

/**
 * Walk up from cwd to the first directory containing any of `markers`.
 * PWD is deliberately excluded (shell-set, can be stale/forged); explicit
 * env overrides win, then the real cwd walk. Shared by ledger, scratchpad,
 * and the PoC runner so the heuristic lives in one place.
 */
export function findWorkspaceRoot(envNames: string[], markers: string[]): string {
  for (const e of envNames) {
    const v = process.env[e]?.trim();
    if (v) return resolve(v);
  }

  let curr = resolve(process.cwd());
  for (let i = 0; i < 20; i++) {
    if (markers.some((m) => existsSync(join(curr, m)))) return curr;
    const parent = dirname(curr);
    if (parent === curr) break;
    curr = parent;
  }
  return resolve(process.cwd());
}

/** Detect the scratchpad workspace root (override, env, then walk up). */
export function detectWorkspaceRoot(): string {
  if (scratchpadRootOverride) return scratchpadRootOverride;
  return findWorkspaceRoot(
    ["XPI_SCRATCHPAD_ROOT", "PI_WORKSPACE_ROOT", "GITHUB_WORKSPACE"],
    [".git", "package.json"],
  );
}

/** Override the scratchpad root (for testing). Pass undefined to reset. */
export function setScratchpadRoot(path: string | undefined): void {
  scratchpadRootOverride = path ? resolve(path) : undefined;
}

/** The top-level scratchpad directory for a given project root. */
export function getScratchpadRoot(projectRoot?: string): string {
  const root = projectRoot ?? detectWorkspaceRoot();
  return join(root, SCRATCHPAD_DIR);
}

/**
 * Sanitize an agent-supplied name into a single safe path component. `..`/`/`
 * would let join() escape its base directory (ScratchpadClear("..") would
 * recursively delete the project root; an artifact named ".." points at the
 * phase dir itself), so anything outside the allowlist becomes `_`, and a
 * dot-only or empty result is rejected.
 */
function sanitizeName(name: string, label: string): string {
  const safe = name.replace(/[^a-zA-Z0-9._-]/g, "_");
  if (!safe || /^\.+$/.test(safe)) {
    throw new Error(`Invalid ${label}: "${name}" — nothing left after sanitization`);
  }
  return safe;
}

function runDirName(runId: string): string {
  const safe = sanitizeName(runId, "run_id");
  if (safe === runId) return safe;
  const suffix = createHash("sha256").update(runId).digest("hex").slice(0, 12);
  return `${safe.slice(0, 80)}-${suffix}`;
}

/**
 * Artifact names get the same disambiguation as run dirs: sanitization is
 * lossy ("a/b" and "a_b" both become "a_b"), so a changed name gets a content
 * hash suffix — distinct inputs can no longer silently overwrite each other's
 * file. Reads use the same mapping, so round-trips stay consistent.
 */
function artifactFileName(name: string): string {
  const safe = sanitizeName(name, "artifact name");
  if (safe === name) return safe;
  const suffix = createHash("sha256").update(name).digest("hex").slice(0, 12);
  return `${safe.slice(0, 80)}-${suffix}`;
}

/** Cap on a single scratchpad artifact (2 MiB) — a hallucinating or hostile
 * subagent must not be able to fill the disk with unbounded writes. */
const MAX_ARTIFACT_BYTES = 2 * 1024 * 1024;

/** Pre-hash-suffix naming used by older scratchpad versions (sanitize only). */
function legacyRunDirName(runId: string): string {
  return sanitizeName(runId, "run_id");
}

/** The directory for a specific run. */
export function getRunDir(runId: string, projectRoot?: string): string {
  return join(getScratchpadRoot(projectRoot), runDirName(runId));
}

/** The state.json path for a run. */
export function getStatePath(runId: string, projectRoot?: string): string {
  return join(getRunDir(runId, projectRoot), "state.json");
}

function emptyCheckpoint(runId: string, projectRoot: string): ScratchpadCheckpoint {
  const now = new Date().toISOString();
  return {
    run_id: runId,
    project_root: projectRoot,
    created_at: now,
    last_updated: now,
    last_phase_at: null,
    completed_phases: [],
    phase_ids: {} as Record<ScratchpadPhase, string[]>,
    phase_summaries: {} as Record<ScratchpadPhase, string>,
  };
}

function ensureRunDirs(runDir: string): void {
  const scratchpadRoot = dirname(runDir);
  const projectRoot = dirname(scratchpadRoot);
  const runName = basename(runDir);
  ensureSafeStateDirectory(projectRoot, [SCRATCHPAD_DIR, runName]);
  for (const phase of SCRATCHPAD_PHASES) {
    ensureSafeStateDirectory(projectRoot, [SCRATCHPAD_DIR, runName, PHASE_DIRS[phase]]);
  }
}

function readCheckpointRaw(runId: string, projectRoot?: string): ScratchpadCheckpoint | null {
  const root = projectRoot ?? detectWorkspaceRoot();
  const statePath = getStatePath(runId, projectRoot);
  if (existsSync(statePath)) {
    assertSafeStateDirectory(root, [SCRATCHPAD_DIR, runDirName(runId)]);
  }
  if (!assertSafeRegularFile(statePath, "Scratchpad checkpoint")) return null;
  const raw = readSafeFile(statePath, "Scratchpad checkpoint").toString("utf8");
  const cp = JSON.parse(raw) as ScratchpadCheckpoint;
  if (typeof cp !== "object" || cp === null || Array.isArray(cp)) {
    throw new Error(`Corrupt scratchpad state for ${runId}: root must be an object`);
  }
  if (cp.run_id !== runId) {
    throw new Error(`Corrupt scratchpad state for ${runId}: state belongs to ${cp.run_id}`);
  }
  if (!Array.isArray(cp.completed_phases)) {
    throw new Error(`Corrupt scratchpad state for ${runId}: completed_phases must be an array`);
  }
  for (const phase of cp.completed_phases) {
    if (!SCRATCHPAD_PHASES.includes(phase)) {
      throw new Error(`Corrupt scratchpad state for ${runId}: invalid phase ${phase}`);
    }
  }
  if (!cp.phase_ids || typeof cp.phase_ids !== "object" || Array.isArray(cp.phase_ids)) {
    cp.phase_ids = {} as Record<ScratchpadPhase, string[]>;
  }
  if (
    !cp.phase_summaries ||
    typeof cp.phase_summaries !== "object" ||
    Array.isArray(cp.phase_summaries)
  ) {
    cp.phase_summaries = {} as Record<ScratchpadPhase, string>;
  }
  return cp;
}

function writeCheckpointRaw(cp: ScratchpadCheckpoint, projectRoot?: string): void {
  cp.last_updated = new Date().toISOString();
  const statePath = getStatePath(cp.run_id, projectRoot);
  ensureRunDirs(getRunDir(cp.run_id, projectRoot));
  writeSafeFileAtomic(statePath, JSON.stringify(cp, null, 2));
}

// ── Public API ───────────────────────────────────────────────────────

/**
 * Initialize a new scratchpad run. Creates the directory structure and writes
 * an initial state.json. If the run already exists, returns the existing
 * checkpoint (idempotent — safe to call on resume without --fresh).
 */
export function scratchpad_init(runId: string, projectRoot?: string): ScratchpadCheckpoint {
  const root = projectRoot ?? detectWorkspaceRoot();
  const runDir = getRunDir(runId, root);
  ensureRunDirs(runDir);

  const existing = readCheckpointRaw(runId, root);
  if (existing) return existing;

  const cp = emptyCheckpoint(runId, root);
  writeCheckpointRaw(cp, root);
  return cp;
}

/**
 * Write an artifact to a phase's subdirectory. Overwrites if the name exists.
 * Returns the full path to the written artifact.
 */
export function scratchpad_write(
  runId: string,
  phase: ScratchpadPhase,
  artifactName: string,
  content: string,
  projectRoot?: string,
): string {
  const root = projectRoot ?? detectWorkspaceRoot();
  const runDir = getRunDir(runId, root);
  ensureRunDirs(runDir);

  if (Buffer.byteLength(content, "utf8") > MAX_ARTIFACT_BYTES) {
    throw new Error(
      `Artifact too large (${Buffer.byteLength(content, "utf8")} bytes; max ${MAX_ARTIFACT_BYTES}): ${artifactName}`,
    );
  }

  // Sanitize + disambiguate artifact name: no path traversal, no dot-only
  // escape, and lossy sanitization cannot collide two distinct names.
  const safeName = artifactFileName(artifactName);
  const dir = join(runDir, PHASE_DIRS[phase]);
  const filePath = join(dir, safeName);
  writeSafeFileAtomic(filePath, content);
  return filePath;
}

/**
 * Read an artifact. Returns null if missing.
 */
export function scratchpad_read(
  runId: string,
  phase: ScratchpadPhase,
  artifactName: string,
  projectRoot?: string,
): string | null {
  const root = projectRoot ?? detectWorkspaceRoot();
  const safeName = artifactFileName(artifactName);
  const filePath = join(getRunDir(runId, root), PHASE_DIRS[phase], safeName);
  if (existsSync(filePath)) {
    assertSafeStateDirectory(root, [SCRATCHPAD_DIR, runDirName(runId), PHASE_DIRS[phase]]);
  }
  if (!assertSafeRegularFile(filePath, "Scratchpad artifact")) return null;
  return readSafeFile(filePath, "Scratchpad artifact").toString("utf8");
}

/**
 * List all artifacts written for a phase.
 */
export function scratchpad_runs(projectRoot?: string): string[] {
  const root = getScratchpadRoot(projectRoot);
  if (!existsSync(root)) return [];
  assertSafeStateDirectory(dirname(root), [SCRATCHPAD_DIR]);
  const out: string[] = [];
  for (const entry of readdirSync(root, { withFileTypes: true })) {
    if (!entry.isDirectory()) continue;
    const state = join(root, entry.name, "state.json");
    if (!assertSafeRegularFile(state, "Scratchpad checkpoint")) continue;
    try {
      const cp = JSON.parse(readSafeFile(state, "Scratchpad checkpoint").toString("utf8")) as {
        run_id?: unknown;
      };
      if (typeof cp.run_id !== "string") continue;
      if (getRunDir(cp.run_id, projectRoot) === join(root, entry.name)) {
        out.push(cp.run_id);
      } else if (join(root, legacyRunDirName(cp.run_id)) === join(root, entry.name)) {
        // Runs created before the hash-suffix naming used sanitizeName(runId)
        // as the directory; keep surfacing them in bundle discovery. Safe ids
        // were never suffixed, so only legacy unsafe ids can land here.
        out.push(cp.run_id);
      }
    } catch {
      // Corrupt runs are ignored during report bundle discovery; direct resume still fails closed.
    }
  }
  return out;
}

export function scratchpad_list(
  runId: string,
  phase: ScratchpadPhase,
  projectRoot?: string,
): string[] {
  const root = projectRoot ?? detectWorkspaceRoot();
  const dir = join(getRunDir(runId, root), PHASE_DIRS[phase]);
  if (!existsSync(dir)) return [];
  assertSafeStateDirectory(root, [SCRATCHPAD_DIR, runDirName(runId), PHASE_DIRS[phase]]);
  return readdirSync(dir).filter(
    (f) => f !== "state.json" && assertSafeRegularFile(join(dir, f), "Scratchpad artifact"),
  );
}

/**
 * Mark a phase as complete. Records the completion timestamp, key IDs, and an
 * optional summary in state.json. Idempotent: re-checkpointing a phase
 * overwrites its previous summary/IDs but does not duplicate the entry in
 * completed_phases.
 */
export function scratchpad_checkpoint(
  runId: string,
  phase: ScratchpadPhase,
  data: { ids?: string[]; summary?: string },
  projectRoot?: string,
): ScratchpadCheckpoint {
  const root = projectRoot ?? detectWorkspaceRoot();
  const cp = readCheckpointRaw(runId, root) ?? scratchpad_init(runId, root);

  if (!cp.completed_phases.includes(phase)) {
    cp.completed_phases.push(phase);
    // Keep completed_phases in pipeline order for predictable resume.
    cp.completed_phases.sort((a, b) => SCRATCHPAD_PHASES.indexOf(a) - SCRATCHPAD_PHASES.indexOf(b));
  }
  cp.last_phase_at = new Date().toISOString();
  if (data.ids) cp.phase_ids[phase] = data.ids;
  if (data.summary) cp.phase_summaries[phase] = data.summary;

  writeCheckpointRaw(cp, root);
  return cp;
}

/**
 * Read the checkpoint + all artifact references for resume.
 * Returns null if the run doesn't exist.
 */
export function scratchpad_resume(runId: string, projectRoot?: string): ScratchpadResume | null {
  const root = projectRoot ?? detectWorkspaceRoot();
  const cp = readCheckpointRaw(runId, root);
  if (!cp) return null;

  // Find the next phase: the first phase in order not in completed_phases.
  const next = PHASE_ORDER.find((p) => !cp.completed_phases.includes(p)) ?? null;

  // Gather artifact listing per completed phase.
  const artifacts: Record<string, string[]> = {};
  for (const phase of cp.completed_phases) {
    artifacts[phase] = scratchpad_list(runId, phase, root);
  }

  return { checkpoint: cp, next_phase: next, artifacts };
}

/**
 * Check whether a phase has already been checkpointed (for idempotent re-run).
 */
export function scratchpad_phase_done(
  runId: string,
  phase: ScratchpadPhase,
  projectRoot?: string,
): boolean {
  const cp = readCheckpointRaw(runId, projectRoot);
  return cp?.completed_phases.includes(phase) ?? false;
}

/**
 * Clear a specific run's scratchpad directory. Used by `--fresh` for a single
 * run. Does not touch other runs.
 */
export function scratchpad_clear(runId: string, projectRoot?: string): void {
  const root = projectRoot ?? detectWorkspaceRoot();
  const runDir = getRunDir(runId, root);
  if (existsSync(runDir)) {
    assertSafeStateDirectory(root, [SCRATCHPAD_DIR, runDirName(runId)]);
    rmSync(runDir, { recursive: true, force: true });
  }
}
