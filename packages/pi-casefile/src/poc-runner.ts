import { spawnSync } from "node:child_process";
import { copyFileSync, existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, extname, isAbsolute, join, relative, resolve } from "node:path";

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
};

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
  return `__PI_POC_DONE_${Math.random().toString(36).slice(2, 12)}__`;
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
  // Use path.relative so prefix-sibling escapes like /tmp/proj vs /tmp/proj-evil are rejected.
  // startsWith(`${root}/`) would accept /tmp/proj-evil when root is /tmp/proj.
  const rel = relative(root, normalized);
  const outsideWorkspace = rel === "" ? false : rel.startsWith("..") || isAbsolute(rel);
  if (outsideWorkspace) {
    const allowAbsolute = process.env.PI_POC_ALLOW_ABSOLUTE === "1";
    if (!allowAbsolute) {
      throw new Error(
        `PoC path must be under the project workspace (${root}). ` +
          `Set PI_POC_ALLOW_ABSOLUTE=1 to allow arbitrary absolute paths.`,
      );
    }
  }

  if (!existsSync(normalized)) {
    throw new Error(`PoC not found on disk: ${pocPath}`);
  }

  return normalized;
}

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
    .replace(ctrl, "")
    .slice(0, OUTPUT_MAX_CHARS);
}

function buildDockerArgs(
  image: string,
  command: string,
  workspaceDir: string,
  containerName: string,
): string[] {
  return [
    "run",
    "--rm",
    "--name",
    containerName,
    "--network",
    "none",
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

function runSandboxed(pocPath: string, language: PocLanguage): PocRun {
  const ranAt = new Date().toISOString();
  const sourceName = basename(pocPath);
  const workspaceDir = mkdtempSync(resolve(tmpdir(), "poc-runner-"));
  // Named container so a timed-out / killed client can still be cleaned up —
  // `--rm` alone leaks the container when the CLI dies before the child exits.
  const containerName = `poc-runner-${process.pid}-${Math.random().toString(36).slice(2, 10)}`;

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
      };
    }
    copyFileSync(pocPath, `${workspaceDir}/${sourceName}`);

    const command = renderCommand(language.run, pocPath, true);

    // Completion sentinel: wrap the command so the shell echoes a unique token
    // AFTER the PoC exits, preserving its exit code. If the container is
    // killed, times out, or the run never starts, the sentinel is absent —
    // callers can then tell "script ran and failed" from "script crashed".
    const sentinel = makeSentinel();
    const wrapped = `${command}; rc=$?; echo '${sentinel}'; exit $rc`;

    const result = spawnSync(
      "docker",
      buildDockerArgs(language.image, wrapped, workspaceDir, containerName),
      {
        encoding: "utf8",
        timeout: TIMEOUT_MS,
        maxBuffer: MAX_BUFFER,
      },
    );

    const spawnErr = result.error ? `\n[spawn error] ${result.error.message}` : "";
    const raw = (result.stdout ?? "") + (result.stderr ?? "") + spawnErr;
    const completed = raw.includes(sentinel);
    const output = sanitizeOutput(raw.replace(sentinel, ""));
    return {
      path: pocPath,
      exitCode: spawnExitCode(result),
      output,
      ranAt,
      sandbox: true,
      completed,
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

function runLocal(pocPath: string, language: PocLanguage): PocRun {
  const ranAt = new Date().toISOString();

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
  });

  // Local runs stay shell-free (space-containing paths stay single args), so
  // there is no sentinel echo: "completed" is derived from the spawn result.
  // A spawn error (interpreter missing) or a signal kill (timeout, SIGKILL)
  // means the script never ran to completion — fail closed on those.
  const spawnErr = result.error ? `\n[spawn error] ${result.error.message}` : "";
  const completed = !result.error && result.signal === null;
  const output = sanitizeOutput((result.stdout ?? "") + (result.stderr ?? "") + spawnErr);
  return {
    path: pocPath,
    exitCode: spawnExitCode(result),
    output,
    ranAt,
    sandbox: false,
    completed,
  };
}

/**
 * Run a PoC script in an adaptive, language-aware sandbox or locally.
 *
 * Language detection (in order):
 * 1. Shebang line in the PoC file.
 * 2. File extension (a .py PoC in a Node repo still runs under python).
 * 3. Project type markers in the workspace root (e.g., package.json, requirements.txt).
 * 4. PI_POC_DEFAULT_LANGUAGE environment variable (a built-in language key).
 *
 * Security:
 * - PoC paths must be absolute and under the project workspace by default.
 * - Docker sandbox runs with no network, read-only root FS, dropped caps,
 *   no new privileges, and an unprivileged user.
 * - Local execution is restricted to interpreted languages.
 */
export function runPoc(pocPath: string, useSandbox = true): PocRun {
  const normalized = validatePocPath(pocPath);
  const { language } = resolveLanguage(normalized);

  if (useSandbox) {
    return runSandboxed(normalized, language);
  }

  return runLocal(normalized, language);
}
