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
 *     report/     — report-writer context
 *     state.json  — checkpoint file with phase completion + key IDs
 *
 * Resume re-reads scratchpad artifacts; it does not re-run completed phases
 * (idempotent). The `.scratchpad/` directory is preserved between runs;
 * `--fresh` clears it via scratchpad_clear().
 */

import { existsSync, mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";

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

export const PHASE_ORDER: ScratchpadPhase[] = [
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
function detectWorkspaceRoot(): string {
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

/** The directory for a specific run. */
export function getRunDir(runId: string, projectRoot?: string): string {
  return join(getScratchpadRoot(projectRoot), sanitizeName(runId, "run_id"));
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
  if (!existsSync(runDir)) mkdirSync(runDir, { recursive: true });
  for (const phase of PHASE_ORDER) {
    const dir = join(runDir, PHASE_DIRS[phase]);
    if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
  }
}

function readCheckpointRaw(runId: string, projectRoot?: string): ScratchpadCheckpoint | null {
  const statePath = getStatePath(runId, projectRoot);
  if (!existsSync(statePath)) return null;
  try {
    const raw = readFileSync(statePath, "utf8");
    const cp = JSON.parse(raw) as ScratchpadCheckpoint;
    // Backfill maps for phases not yet checkpointed (defensive).
    if (!cp.phase_ids) cp.phase_ids = {} as Record<ScratchpadPhase, string[]>;
    if (!cp.phase_summaries) cp.phase_summaries = {} as Record<ScratchpadPhase, string>;
    return cp;
  } catch {
    return null;
  }
}

function writeCheckpointRaw(cp: ScratchpadCheckpoint, projectRoot?: string): void {
  cp.last_updated = new Date().toISOString();
  const statePath = getStatePath(cp.run_id, projectRoot);
  ensureRunDirs(getRunDir(cp.run_id, projectRoot));
  writeFileSync(statePath, JSON.stringify(cp, null, 2), "utf8");
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

  // Sanitize artifact name: no path traversal, no dot-only escape.
  const safeName = sanitizeName(artifactName, "artifact name");
  const dir = join(runDir, PHASE_DIRS[phase]);
  const filePath = join(dir, safeName);
  writeFileSync(filePath, content, "utf8");
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
  const safeName = sanitizeName(artifactName, "artifact name");
  const filePath = join(getRunDir(runId, root), PHASE_DIRS[phase], safeName);
  if (!existsSync(filePath)) return null;
  return readFileSync(filePath, "utf8");
}

/**
 * List all artifacts written for a phase.
 */
export function scratchpad_list(
  runId: string,
  phase: ScratchpadPhase,
  projectRoot?: string,
): string[] {
  const root = projectRoot ?? detectWorkspaceRoot();
  const dir = join(getRunDir(runId, root), PHASE_DIRS[phase]);
  if (!existsSync(dir)) return [];
  return readdirSync(dir).filter((f) => f !== "state.json");
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
    cp.completed_phases.sort((a, b) => PHASE_ORDER.indexOf(a) - PHASE_ORDER.indexOf(b));
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
  if (existsSync(runDir)) rmSync(runDir, { recursive: true, force: true });
}
