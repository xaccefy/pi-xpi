import { spawnSync } from "node:child_process";
import { copyFileSync, existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, extname, isAbsolute, join, resolve } from "node:path";

export type PocRun = {
  path: string;
  exitCode: number;
  output: string;
  ranAt: string;
  sandbox: boolean;
};

export type PocLanguage = {
  /** Docker image used when running inside the sandbox. */
  image: string;
  /** Shell command to run an interpreted PoC. {{file}} is replaced with the source path. */
  run?: string;
  /** Shell command to build and run a compiled PoC. {{file}}, {{bin}}, {{class}} replaced. */
  buildRun?: string;
  /** Files that, when present in the project root, identify this project type. */
  projectMarkers?: string[];
};

/** Minimal built-in defaults. Users can override/extend via env. */
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

/** Extension to language key. Unknown extensions can be supplied by the user. */
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
const MAX_BUFFER = 8 * 1024 * 1024;

function getProjectRoot(): string {
  const envRoot = process.env.PI_POC_ROOT?.trim();
  if (envRoot) return resolve(envRoot);

  let curr = resolve(process.cwd());
  for (let i = 0; i < 20; i++) {
    if (existsSync(join(curr, ".git"))) return curr;
    const parent = dirname(curr);
    if (parent === curr) break;
    curr = parent;
  }
  return resolve(process.cwd());
}

function loadLanguages(): Record<string, PocLanguage> {
  const languages = { ...BUILTIN_LANGUAGES };

  const envOverride = process.env.PI_POC_LANGUAGES?.trim();
  if (envOverride) {
    try {
      const extra = JSON.parse(envOverride) as Record<string, PocLanguage>;
      for (const [key, lang] of Object.entries(extra)) {
        if (lang?.image) languages[key] = lang;
      }
    } catch {
      // Malformed env JSON is ignored.
    }
  }

  return languages;
}

function detectProjectType(languages: Record<string, PocLanguage>): string | undefined {
  const root = getProjectRoot();
  for (const [key, lang] of Object.entries(languages)) {
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

function interpreterToLanguage(
  interpreter: string,
  languages: Record<string, PocLanguage>,
): string | undefined {
  const bin = basename(interpreter).toLowerCase();
  for (const [key, lang] of Object.entries(languages)) {
    if (lang.run) {
      const runBin = lang.run.split(" ")[0].toLowerCase();
      if (runBin === bin) return key;
    }
    if (lang.buildRun) {
      const buildBin = lang.buildRun.split(" ")[0].toLowerCase();
      if (buildBin === bin) return key;
    }
  }
  return undefined;
}

function resolveLanguage(pocPath: string): { key: string; language: PocLanguage } {
  const languages = loadLanguages();
  const ext = extname(pocPath).toLowerCase();
  const extKey = EXTENSION_MAP[ext];

  // 1. Shebang overrides everything.
  const shebang = parseShebang(pocPath);
  if (shebang) {
    const shebangKey = interpreterToLanguage(shebang, languages);
    if (shebangKey) return { key: shebangKey, language: languages[shebangKey] };
  }

  // 2. Project type detection.
  const projectType = detectProjectType(languages);
  if (projectType && languages[projectType]) {
    // If the file extension matches the project type or type has no extension restrictions, use it.
    return { key: projectType, language: languages[projectType] };
  }

  // 3. Extension-based fallback.
  if (extKey && languages[extKey]) {
    return { key: extKey, language: languages[extKey] };
  }

  // 4. Unknown extension: allow env override specifying a single language key.
  const envDefault = process.env.PI_POC_DEFAULT_LANGUAGE?.trim();
  if (envDefault && languages[envDefault]) {
    return { key: envDefault, language: languages[envDefault] };
  }

  const supported = Object.keys(languages).sort().join(", ");
  throw new Error(
    `Cannot determine PoC language for "${pocPath}". ` +
      `Detected extension: "${ext || "none"}". ` +
      `Supported/adapted languages: ${supported}. ` +
      `Add a shebang, use a known extension, or set PI_POC_DEFAULT_LANGUAGE or PI_POC_LANGUAGES.`,
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

  const parts = normalized.split(/[\\/]/);
  if (parts.includes("..")) {
    throw new Error(`PoC path contains traversal segments: ${pocPath}`);
  }

  const root = getProjectRoot();
  if (!normalized.startsWith(`${root}/`) && normalized !== root) {
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

function buildDockerArgs(image: string, command: string, workspaceDir: string): string[] {
  return [
    "run",
    "--rm",
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

function renderCommand(template: string, pocPath: string, inSandbox: boolean): string {
  const sourceName = basename(pocPath);
  const className = sourceName.replace(/\.[^.]+$/i, "");
  const targetPath = inSandbox ? `/workspace/${sourceName}` : pocPath;
  const binPath = inSandbox ? "/workspace/poc" : join(dirname(pocPath), "poc");

  return template
    .replace(/{{file}}/g, targetPath)
    .replace(/{{bin}}/g, binPath)
    .replace(/{{class}}/g, className);
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

function runSandboxed(pocPath: string, language: PocLanguage): PocRun {
  const ranAt = new Date().toISOString();
  const sourceName = basename(pocPath);
  const workspaceDir = mkdtempSync(resolve(tmpdir(), "poc-runner-"));

  try {
    copyFileSync(pocPath, `${workspaceDir}/${sourceName}`);

    let command: string;
    if (language.buildRun) {
      command = renderCommand(language.buildRun, pocPath, true);
    } else if (language.run) {
      command = renderCommand(language.run, pocPath, true);
    } else {
      throw new Error("Language config has no run or buildRun command");
    }

    const result = spawnSync("docker", buildDockerArgs(language.image, command, workspaceDir), {
      encoding: "utf8",
      timeout: TIMEOUT_MS,
      maxBuffer: MAX_BUFFER,
    });

    const spawnErr = result.error ? `\n[spawn error] ${result.error.message}` : "";
    const output = sanitizeOutput((result.stdout ?? "") + (result.stderr ?? "") + spawnErr);
    return {
      path: pocPath,
      exitCode: spawnExitCode(result),
      output,
      ranAt,
      sandbox: true,
    };
  } finally {
    try {
      rmSync(workspaceDir, { recursive: true, force: true });
    } catch {
      // Best-effort cleanup.
    }
  }
}

function runLocal(pocPath: string, language: PocLanguage): PocRun {
  const ranAt = new Date().toISOString();

  if (language.buildRun) {
    throw new Error(
      "Compiled PoC languages require the Docker sandbox. " +
        "Run PromoteFinding with local:false or use an interpreted PoC.",
    );
  }

  if (!language.run) {
    throw new Error("Language config has no run command");
  }

  // The run template is `<interpreter> <file>`. Preserve multi-arg run commands for
  // normal paths, but keep a space-containing PoC path as a single argument (no shell
  // is used, so args are passed verbatim).
  const command = renderCommand(language.run, pocPath, false);
  const trimmed = command.trim();
  const firstSpace = trimmed.indexOf(" ");
  const interpreter = firstSpace === -1 ? trimmed : trimmed.slice(0, firstSpace);
  const rest = firstSpace === -1 ? "" : trimmed.slice(firstSpace + 1);
  const args = pocPath.includes(" ") ? (rest ? [rest] : []) : rest ? rest.split(" ") : [];

  const result = spawnSync(interpreter, args, {
    encoding: "utf8",
    timeout: TIMEOUT_MS,
    maxBuffer: MAX_BUFFER,
  });

  const spawnErr = result.error ? `\n[spawn error] ${result.error.message}` : "";
  const output = sanitizeOutput((result.stdout ?? "") + (result.stderr ?? "") + spawnErr);
  return {
    path: pocPath,
    exitCode: spawnExitCode(result),
    output,
    ranAt,
    sandbox: false,
  };
}

/**
 * Run a PoC script in an adaptive, language-aware sandbox or locally.
 *
 * Language detection (in order):
 * 1. Shebang line in the PoC file.
 * 2. Project type markers in the workspace root (e.g., package.json, go.mod, Cargo.toml).
 * 3. File extension.
 * 4. PI_POC_DEFAULT_LANGUAGE environment variable.
 *
 * Users can extend or override language definitions via:
 * - `.pi/poc-languages.json` in the project root.
 * - `PI_POC_LANGUAGES` environment variable (JSON object).
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
