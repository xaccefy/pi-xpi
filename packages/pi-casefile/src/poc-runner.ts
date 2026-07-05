import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { extname } from "node:path";

export type PocRun = {
  path: string;
  exitCode: number;
  output: string;
  ranAt: string;
  sandbox: boolean;
};

/**
 * Run a PoC script. Supports docker sandbox (default) or local execution.
 *
 * Python (.py), JavaScript (.js/.mjs/.cjs), and shell (.sh) scripts are supported.
 * Unsupported extensions are rejected with a clear error.
 */
export function runPoc(pocPath: string, useSandbox = true): PocRun {
  if (!existsSync(pocPath)) {
    throw new Error(`PoC not found on disk: ${pocPath}`);
  }

  const ext = extname(pocPath).toLowerCase();
  const isPython = ext === ".py";
  const isJavaScript = ext === ".js" || ext === ".mjs" || ext === ".cjs";

  if (!isPython && !isJavaScript && ext !== ".sh") {
    throw new Error(
      `Unsupported PoC extension "${ext}". Supported: .py (Python), .js/.mjs/.cjs (Node), .sh (shell)`,
    );
  }

  const ranAt = new Date().toISOString();

  // Resolve the runner command and container image for the file type
  const runner = isPython ? "python3" : isJavaScript ? "node" : "sh";
  const image = isPython ? "python:3.12-slim" : isJavaScript ? "node:22-slim" : "alpine";

  if (useSandbox) {
    const containerPath = `/workspace/poc${ext}`;

    const args = [
      "run",
      "--rm",
      "--network",
      "none",
      "-v",
      `${pocPath}:${containerPath}:ro`,
      image,
      runner,
      containerPath,
    ];

    const result = spawnSync("docker", args, {
      encoding: "utf8",
      timeout: 30000,
      maxBuffer: 8 * 1024 * 1024,
    });

    const output = (result.stdout ?? "") + (result.stderr ?? "");
    return {
      path: pocPath,
      exitCode: result.status ?? (result.signal ? 1 : 0),
      output: output.slice(0, 4000),
      ranAt,
      sandbox: true,
    };
  }

  // Local execution
  const result = spawnSync(runner, [pocPath], {
    encoding: "utf8",
    timeout: 30000,
    maxBuffer: 8 * 1024 * 1024,
  });

  const output = (result.stdout ?? "") + (result.stderr ?? "");
  return {
    path: pocPath,
    exitCode: result.status ?? (result.signal ? 1 : 0),
    output: output.slice(0, 4000),
    ranAt,
    sandbox: false,
  };
}
