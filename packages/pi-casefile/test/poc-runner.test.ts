import { afterEach, beforeEach, describe, expect, it } from "bun:test";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readdirSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { runPoc } from "../src/poc-runner.ts";

let tempDir: string;

beforeEach(() => {
  tempDir = mkdtempSync(join(tmpdir(), "poc-runner-test-"));
  // Set PI_POC_ROOT to our temp dir so path validation passes
  process.env.PI_POC_ROOT = tempDir;
  // Local (host) execution is operator-gated; the test harness acts as the
  // operator and FORCE_LOCAL so local-run tests stay hermetic (no Docker)
  // even when Docker is installed — production still prefers the sandbox.
  process.env.PI_POC_ALLOW_LOCAL = "1";
  process.env.PI_POC_FORCE_LOCAL = "1";
});

afterEach(async () => {
  delete process.env.PI_POC_ROOT;
  delete process.env.PI_POC_ALLOW_ABSOLUTE;
  delete process.env.PI_POC_DEFAULT_LANGUAGE;
  delete process.env.PI_POC_ALLOW_LOCAL;
  delete process.env.PI_POC_FORCE_LOCAL;
  await rm(tempDir, { recursive: true, force: true });
});

describe("poc-runner", () => {
  it("validates paths to prevent traversal", () => {
    const invalidPath = join(tempDir, "../../../etc/passwd");
    expect(() => runPoc(invalidPath, { local: true })).toThrow(
      /traversal segments|under the project workspace/,
    );
  });

  it("fails on unknown extensions", () => {
    const badPoc = join(tempDir, "poc.unknown");
    writeFileSync(badPoc, "echo 1", "utf8");
    expect(() => runPoc(badPoc, { local: true })).toThrow(/Cannot determine PoC language for/);
  });

  it("runs a shell script locally", () => {
    const shPoc = join(tempDir, "poc.sh");
    writeFileSync(shPoc, "#!/bin/sh\necho 'hello world'", "utf8");

    const result = runPoc(shPoc, { local: true });

    expect(result.exitCode).toBe(0);
    expect(result.output).toContain("hello world");
    expect(result.sandbox).toBe(false);
  });

  it("local mode WITHOUT the operator opt-in never runs on the host", () => {
    // Host execution is never agent-selectable. Without the operator's env
    // opt-in, local:true must NOT spawn on the host: with Docker available it
    // degrades to a host-network SANDBOX; without Docker it fails closed with
    // the opt-in error.
    const previousAllow = process.env.PI_POC_ALLOW_LOCAL;
    const previousForce = process.env.PI_POC_FORCE_LOCAL;
    delete process.env.PI_POC_ALLOW_LOCAL;
    delete process.env.PI_POC_FORCE_LOCAL;
    const shPoc = join(tempDir, "poc.sh");
    writeFileSync(shPoc, "#!/bin/sh\necho 'must not run on host'", "utf8");

    let result: ReturnType<typeof runPoc>;
    try {
      result = runPoc(shPoc, { local: true });
    } finally {
      if (previousAllow === undefined) delete process.env.PI_POC_ALLOW_LOCAL;
      else process.env.PI_POC_ALLOW_LOCAL = previousAllow;
      if (previousForce === undefined) delete process.env.PI_POC_FORCE_LOCAL;
      else process.env.PI_POC_FORCE_LOCAL = previousForce;
    }

    if (result.sandbox && !result.infraError) {
      // Docker path: the script ran inside the sandbox (isolation kept), never
      // on the host. The opt-in error must not appear.
      expect(result.completed).toBe(true);
      expect(result.output).not.toContain("PI_POC_ALLOW_LOCAL");
    } else {
      // Docker-less or Docker-unavailable path: fail closed — nothing ran on the host.
      expect(result.exitCode).not.toBe(0);
      expect(result.completed).toBe(false);
      expect(result.output).toContain("PI_POC_ALLOW_LOCAL");
      expect(result.output).not.toContain("must not run on host");
    }
  });

  it("passes the harness env contract (PI_POC_MODE / PI_POC_TARGET) to local runs", () => {
    const shPoc = join(tempDir, "poc-env.sh");
    writeFileSync(shPoc, '#!/bin/sh\nprintf \'%s|%s\' "$PI_POC_MODE" "$PI_POC_TARGET"', "utf8");

    const result = runPoc(shPoc, {
      local: true,
      env: { PI_POC_MODE: "control", PI_POC_TARGET: "http://example.test" },
    });

    expect(result.exitCode).toBe(0);
    expect(result.output).toContain("control|http://example.test");
  });

  it("uses a fresh CSPRNG-shaped evidence nonce for every run", () => {
    const shPoc = join(tempDir, "nonce-evidence.sh");
    writeFileSync(
      shPoc,
      `#!/bin/sh
printf '{"nonce":"%s","claim":"target signal","verify":{"method":"GET","url":"http://example.test/proof","expect":{"body_contains":["target signal"]}},"observations":[]}' "$PI_POC_NONCE" > "$PI_POC_EVIDENCE_DIR/evidence.json"`,
      "utf8",
    );

    const first = runPoc(shPoc, { local: true });
    const second = runPoc(shPoc, { local: true });
    expect(first.nonce).toMatch(/^poc_[a-f0-9]{48}$/);
    expect(second.nonce).toMatch(/^poc_[a-f0-9]{48}$/);
    expect(first.nonce).not.toBe(second.nonce);
    expect(first.evidence?.nonce).toBe(first.nonce);
    expect(second.evidence?.nonce).toBe(second.nonce);
  });

  it("rejects oversized evidence.json before parsing or preserving it", () => {
    const shPoc = join(tempDir, "oversized-evidence.sh");
    writeFileSync(
      shPoc,
      '#!/bin/sh\nhead -c 300000 /dev/zero | tr "\\0" x > "$PI_POC_EVIDENCE_DIR/evidence.json"',
      "utf8",
    );

    const result = runPoc(shPoc, { local: true });
    expect(result.exitCode).toBe(0);
    expect(result.evidence).toBeUndefined();
    expect(result.evidencePath).toBeUndefined();
    expect(result.evidenceError).toContain("too large");
  });

  it("rejects a symlinked evidence.json", () => {
    const shPoc = join(tempDir, "symlink-evidence.sh");
    writeFileSync(
      shPoc,
      '#!/bin/sh\nln -s /etc/passwd "$PI_POC_EVIDENCE_DIR/evidence.json"',
      "utf8",
    );

    const result = runPoc(shPoc, { local: true });
    expect(result.exitCode).toBe(0);
    expect(result.evidence).toBeUndefined();
    expect(result.evidencePath).toBeUndefined();
    expect(result.evidenceError).toContain("non-symlink");
  });

  it("rejects a symlinked durable PoC evidence store", () => {
    const shPoc = join(tempDir, "valid-evidence.sh");
    writeFileSync(
      shPoc,
      `#!/bin/sh
printf '{"nonce":"%s","claim":"target signal","verify":{"method":"GET","url":"http://example.test/proof","expect":{"status":[200],"body_contains":["target signal"]}},"observations":[]}' "$PI_POC_NONCE" > "$PI_POC_EVIDENCE_DIR/evidence.json"`,
      "utf8",
    );
    const outside = mkdtempSync(join(tmpdir(), "poc-evidence-outside-"));
    try {
      mkdirSync(join(tempDir, ".pi"), { mode: 0o700 });
      symlinkSync(outside, join(tempDir, ".pi", "poc-evidence"), "dir");

      const result = runPoc(shPoc, { local: true });
      expect(result.exitCode).toBe(0);
      expect(result.evidence).toBeUndefined();
      expect(result.evidencePath).toBeUndefined();
      expect(result.evidenceError).toContain("could not be preserved");
      expect(readdirSync(outside)).toEqual([]);
    } finally {
      rmSync(outside, { recursive: true, force: true });
    }
  });

  it("sanitizes control characters from output", () => {
    const shPoc = join(tempDir, "poc.sh");
    // Print ANSI color escape and a null byte
    writeFileSync(shPoc, '#!/bin/sh\nprintf "\\033[31mhello\\033[0m \\000world\\n"', "utf8");

    const result = runPoc(shPoc, { local: true });

    // ANSI codes and null byte should be stripped
    expect(result.output).not.toContain("\x1b[31m");
    expect(result.output).not.toContain("\x00");
    expect(result.output).toContain("hello world");
  });

  it("keeps the FULL sanitized output in rawOutput while output is a display slice", () => {
    const shPoc = join(tempDir, "poc.sh");
    // 5000 lines of filler, then the marker at the end — past the 4000-char
    // display window. Marker checks MUST run on rawOutput, never on output.
    const body = Array.from({ length: 500 }, () => "x".repeat(20)).join("\n");
    writeFileSync(shPoc, `#!/bin/sh\necho "${body}"\necho MARKER_AT_THE_END`, "utf8");

    const result = runPoc(shPoc, { local: true });

    expect(result.exitCode).toBe(0);
    expect(result.output).not.toContain("MARKER_AT_THE_END");
    expect(result.truncated).toBe(true);
    expect(result.rawOutput).toContain("MARKER_AT_THE_END");
  });

  it("rejects an unknown PI_POC_DEFAULT_LANGUAGE", () => {
    // Only built-in languages are allowed as the default; a typo must error,
    // not silently fall through. Language override config was removed on
    // purpose (its templates were trusted shells inside the sandbox).
    process.env.PI_POC_DEFAULT_LANGUAGE = "ghost";

    const poc = join(tempDir, "poc.txt");
    writeFileSync(poc, "echo hi", "utf8");

    expect(() => runPoc(poc, { local: true })).toThrow(/Cannot determine PoC language/);
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

    const result = runPoc(shPoc, { network: "none" });
    expect(result.exitCode).not.toBe(0);
  });

  it("keeps a space-containing PoC path intact (local run, no shell)", () => {
    // Local runs spawn with NO shell so a space in the path stays one arg.
    const dir = mkdtempSync(join(tempDir, "with space-"));
    const poc = join(dir, "poc.sh");
    writeFileSync(poc, "#!/bin/sh\necho 'ok from spaced path'", "utf8");

    const result = runPoc(poc, { local: true });
    expect(result.sandbox).toBe(false);
    expect(result.exitCode).toBe(0);
    expect(result.output).toContain("ok from spaced path");
    expect(result.output).not.toContain("Cannot find module");
  });
});
