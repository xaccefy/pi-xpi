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
      hasDocker = spawnSync("docker", ["--version"], { timeout: 5_000 }).status === 0;
    } catch {
      hasDocker = false;
    }
    if (hasDocker) return;

    const shPoc = join(tempDir, "poc.sh");
    writeFileSync(shPoc, "#!/bin/sh\necho hi", "utf8");

    const result = runPoc(shPoc, true);
    expect(result.exitCode).not.toBe(0);
  });

  it("passes extra template flags as separate args and keeps a space-containing path intact", () => {
    // A custom language with a multi-arg run template (interpreter + flag + file).
    // Previously the space-in-path branch collapsed everything after the interpreter
    // into one arg, breaking the flag. The fix splits the static template first.
    process.env.PI_POC_DEFAULT_LANGUAGE = "nodeflag";
    process.env.PI_POC_LANGUAGES = JSON.stringify({
      // --no-warnings is a valueless flag; the path is the file to run.
      nodeflag: { image: "node:22-slim", run: "node --no-warnings {{file}}" },
    });

    // PoC path with a space — must stay a single arg.
    const dir = mkdtempSync(join(tempDir, "with space-"));
    const poc = join(dir, "poc.txt");
    writeFileSync(poc, "process.stdout.write(process.argv.join('|'))", "utf8");

    const result = runPoc(poc, false);
    expect(result.exitCode).toBe(0);
    // The path must arrive intact as a single arg (not split on its space).
    // Node strips --no-warnings from argv, so we assert on the path itself:
    // if the fix regressed, the path would be truncated at the space.
    expect(result.output).toContain(poc);
    expect(result.output).not.toContain("Cannot find module");
  });
});
