import { afterEach, beforeEach, describe, expect, it } from "bun:test";
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
});
