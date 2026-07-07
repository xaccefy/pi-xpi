import { afterEach, beforeEach, describe, expect, it } from "bun:test";
import { spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { runPoc } from "../src/poc-runner.ts";

let tempDir: string;

beforeEach(() => {
  tempDir = mkdtempSync(join(tmpdir(), "poc-runner-test-"));
  // Set PI_POC_ROOT to our temp dir so path validation passes
  process.env.PI_POC_ROOT = tempDir;
});

afterEach(async () => {
  delete process.env.PI_POC_ROOT;
  delete process.env.PI_POC_ALLOW_ABSOLUTE;
  delete process.env.PI_POC_DEFAULT_LANGUAGE;
  delete process.env.PI_POC_LANGUAGES;
  await rm(tempDir, { recursive: true, force: true });
});

describe("poc-runner", () => {
  it("validates paths to prevent traversal", () => {
    const invalidPath = join(tempDir, "../../../etc/passwd");
    expect(() => runPoc(invalidPath, false)).toThrow(
      /traversal segments|under the project workspace/,
    );
  });

  it("fails on unknown extensions", () => {
    const badPoc = join(tempDir, "poc.unknown");
    writeFileSync(badPoc, "echo 1", "utf8");
    expect(() => runPoc(badPoc, false)).toThrow(/Cannot determine PoC language for/);
  });

  it("runs a shell script locally", () => {
    const shPoc = join(tempDir, "poc.sh");
    writeFileSync(shPoc, "#!/bin/sh\necho 'hello world'", "utf8");

    const result = runPoc(shPoc, false);

    expect(result.exitCode).toBe(0);
    expect(result.output).toContain("hello world");
    expect(result.sandbox).toBe(false);
  });

  it("sanitizes control characters from output", () => {
    const shPoc = join(tempDir, "poc.sh");
    // Print ANSI color escape and a null byte
    writeFileSync(shPoc, '#!/bin/sh\nprintf "\\033[31mhello\\033[0m \\000world\\n"', "utf8");

    const result = runPoc(shPoc, false);

    // ANSI codes and null byte should be stripped
    expect(result.output).not.toContain("\x1b[31m");
    expect(result.output).not.toContain("\x00");
    expect(result.output).toContain("hello world");
  });

  it("fails closed when the interpreter is missing (no false exit 0)", () => {
    // Define a language whose interpreter does not exist, and force it via the
    // default-language env. This reproduces the spawn ENOENT path: previously the
    // PoC would report exitCode 0 and get promoted to CONFIRMED without running.
    process.env.PI_POC_DEFAULT_LANGUAGE = "ghost";
    process.env.PI_POC_LANGUAGES = JSON.stringify({
      ghost: { image: "alpine", run: "definitely_missing_interpreter_xyz {{file}}" },
    });

    const poc = join(tempDir, "poc.txt");
    writeFileSync(poc, "echo hi", "utf8");

    const result = runPoc(poc, false);
    expect(result.exitCode).not.toBe(0);
    expect(result.output).toContain("[spawn error]");
  });

  it("fails closed when docker is missing (sandbox path)", () => {
    // Only meaningful when docker is NOT installed; if it is, the sandbox would
    // actually run and we can't deterministically assert fail-closed.
    let hasDocker = false;
    try {
      hasDocker = spawnSync("docker", ["--version"]).status === 0;
    } catch {
      hasDocker = false;
    }
    if (hasDocker) return;

    const shPoc = join(tempDir, "poc.sh");
    writeFileSync(shPoc, "#!/bin/sh\necho hi", "utf8");

    const result = runPoc(shPoc, true);
    expect(result.exitCode).not.toBe(0);
  });
});
