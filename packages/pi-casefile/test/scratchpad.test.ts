import assert from "node:assert";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, it } from "node:test";

import {
  getRunDir,
  getScratchpadRoot,
  scratchpad_checkpoint,
  scratchpad_clear,
  scratchpad_init,
  scratchpad_list,
  scratchpad_phase_done,
  scratchpad_read,
  scratchpad_resume,
  scratchpad_runs,
  scratchpad_write,
  setScratchpadRoot,
} from "../src/scratchpad.ts";

let tempDir: string;

beforeEach(() => {
  tempDir = mkdtempSync(join(tmpdir(), "scratchpad-test-"));
  setScratchpadRoot(tempDir);
});

afterEach(async () => {
  setScratchpadRoot(undefined);
  await rm(tempDir, { recursive: true, force: true });
});

describe("scratchpad", () => {
  it("init creates the directory structure and state.json", () => {
    const cp = scratchpad_init("run-1");
    assert.strictEqual(cp.run_id, "run-1");
    assert.deepStrictEqual(cp.completed_phases, []);

    const runDir = getRunDir("run-1", tempDir);
    assert.ok(existsSync(join(runDir, "state.json")));
    assert.ok(existsSync(join(runDir, "recon")));
    assert.ok(existsSync(join(runDir, "trace")));
    assert.ok(existsSync(join(runDir, "verify")));
  });

  it("init is idempotent — returns existing checkpoint on re-init", () => {
    scratchpad_init("run-1");
    scratchpad_checkpoint("run-1", "recon", { ids: ["case_a"], summary: "done" });

    const second = scratchpad_init("run-1");
    assert.strictEqual(second.run_id, "run-1");
    // Re-init must not wipe the checkpoint.
    assert.ok(second.completed_phases.includes("recon"));
  });

  it("write + read round-trips an artifact", () => {
    scratchpad_init("run-1");
    const path = scratchpad_write("run-1", "trace", "finding-abc.json", '{"reachable": true}');
    assert.ok(path.endsWith("finding-abc.json"));

    const content = scratchpad_read("run-1", "trace", "finding-abc.json");
    assert.strictEqual(content, '{"reachable": true}');
  });

  it("rejects a pre-planted scratchpad-directory symlink", () => {
    const outside = mkdtempSync(join(tmpdir(), "scratchpad-outside-"));
    try {
      symlinkSync(outside, join(tempDir, ".scratchpad"), "dir");
      assert.throws(() => scratchpad_init("run-1"), /real directory, not a symlink/);
      assert.deepStrictEqual(readdirSync(outside), []);
    } finally {
      rmSync(outside, { recursive: true, force: true });
    }
  });

  it("rejects an artifact symlink without overwriting its target", () => {
    const outside = mkdtempSync(join(tmpdir(), "scratchpad-outside-"));
    try {
      scratchpad_init("run-1");
      const victim = join(outside, "victim.txt");
      writeFileSync(victim, "operator data", "utf8");
      const artifact = join(getRunDir("run-1"), "trace", "finding.json");
      symlinkSync(victim, artifact);

      assert.throws(
        () => scratchpad_write("run-1", "trace", "finding.json", "attacker data"),
        /regular, non-symlink file/,
      );
      assert.strictEqual(readFileSync(victim, "utf8"), "operator data");
    } finally {
      rmSync(outside, { recursive: true, force: true });
    }
  });

  it("read returns null for missing artifact", () => {
    scratchpad_init("run-1");
    assert.strictEqual(scratchpad_read("run-1", "trace", "nope.json"), null);
  });

  it("write sanitizes artifact names to prevent path traversal", () => {
    scratchpad_init("run-1");
    const path = scratchpad_write("run-1", "recon", "../../etc/passwd", "evil");
    // The file must land inside the recon dir — no escape.
    const reconDir = join(getRunDir("run-1", tempDir), "recon");
    assert.ok(path.startsWith(reconDir), `path ${path} escaped recon dir`);
    // Verify the content was actually written to the sanitized path.
    assert.strictEqual(scratchpad_read("run-1", "recon", "../../etc/passwd"), "evil");
  });

  it("run_id cannot traverse out of the scratchpad root (clear/write)", () => {
    // Regression: sanitizeRunId — ScratchpadClear("..") previously deleted the
    // project root; "../../x" wrote outside .scratchpad.
    scratchpad_init("run-1");
    assert.throws(() => scratchpad_clear(".."), /Invalid run_id/); // dot-only: rejected
    assert.ok(
      existsSync(join(tempDir, ".scratchpad", "run-1")),
      "../ clear must not touch the run dir",
    );

    const path = scratchpad_write("../../evil", "recon", "x.json", "payload");
    assert.ok(path.startsWith(tempDir), `write with traversal run_id escaped scratchpad: ${path}`);
    assert.ok(!existsSync(join(tempDir, "..", "evil")), "no dir created outside root");
  });

  it("rejects run_ids that sanitize to dot-only", () => {
    for (const id of [".", "..", "..."]) {
      assert.throws(() => scratchpad_init(id), /Invalid run_id/);
    }
    // But separators elsewhere sanitize into a unique safe dir name.
    scratchpad_init("https://target.example.com/api");
    const dirs = readdirSync(join(tempDir, ".scratchpad"));
    assert.ok(dirs.some((d) => d.startsWith("https___target.example.com_api-")));
  });

  it("rejects dot-only artifact names on write and read (no EISDIR escape)", () => {
    scratchpad_init("run-1");
    assert.throws(() => scratchpad_write("run-1", "recon", "..", "x"), /Invalid artifact name/);
    assert.throws(() => scratchpad_write("run-1", "recon", ".", "x"), /Invalid artifact name/);
    assert.throws(() => scratchpad_read("run-1", "recon", ".."), /Invalid artifact name/);
    // Sanitized-to-dot-only also rejected; nothing written.
    assert.throws(() => scratchpad_write("run-1", "recon", "...", "x"), /Invalid artifact name/);
    assert.strictEqual(
      readdirSync(join(getRunDir("run-1"), "recon")).length,
      0,
      "no artifact written",
    );
  });

  it("list returns artifacts for a phase", () => {
    scratchpad_init("run-1");
    scratchpad_write("run-1", "trace", "a.json", "a");
    scratchpad_write("run-1", "trace", "b.json", "b");
    const list = scratchpad_list("run-1", "trace");
    assert.deepStrictEqual(list.sort(), ["a.json", "b.json"]);
  });

  it("list returns empty for a phase with no artifacts", () => {
    scratchpad_init("run-1");
    assert.deepStrictEqual(scratchpad_list("run-1", "trace"), []);
  });

  it("checkpoint records phase completion, ids, and summary", () => {
    scratchpad_init("run-1");
    const cp = scratchpad_checkpoint("run-1", "hunt", {
      ids: ["case_1", "case_2"],
      summary: "found 2 hypotheses",
    });
    assert.deepStrictEqual(cp.completed_phases, ["hunt"]);
    assert.deepStrictEqual(cp.phase_ids.hunt, ["case_1", "case_2"]);
    assert.strictEqual(cp.phase_summaries.hunt, "found 2 hypotheses");
    assert.ok(cp.last_phase_at);
  });

  it("checkpoint is idempotent — does not duplicate phase in completed_phases", () => {
    scratchpad_init("run-1");
    scratchpad_checkpoint("run-1", "hunt", { summary: "first" });
    scratchpad_checkpoint("run-1", "hunt", { summary: "second" });
    const cp = scratchpad_resume("run-1")!;
    assert.strictEqual(cp.checkpoint.completed_phases.filter((p) => p === "hunt").length, 1);
    assert.strictEqual(cp.checkpoint.phase_summaries.hunt, "second");
  });

  it("checkpoint keeps completed_phases in pipeline order", () => {
    scratchpad_init("run-1");
    // Checkpoint out of order.
    scratchpad_checkpoint("run-1", "validate", { summary: "v" });
    scratchpad_checkpoint("run-1", "recon", { summary: "r" });
    scratchpad_checkpoint("run-1", "trace", { summary: "t" });
    const cp = scratchpad_resume("run-1")!;
    assert.deepStrictEqual(cp.checkpoint.completed_phases, ["recon", "trace", "validate"]);
  });

  it("phase_done reports completion status", () => {
    scratchpad_init("run-1");
    assert.strictEqual(scratchpad_phase_done("run-1", "recon"), false);
    scratchpad_checkpoint("run-1", "recon", { summary: "done" });
    assert.strictEqual(scratchpad_phase_done("run-1", "recon"), true);
  });

  it("resume returns null for a non-existent run", () => {
    assert.strictEqual(scratchpad_resume("nope"), null);
  });

  it("resume returns next_phase and artifacts for a partial run", () => {
    scratchpad_init("run-1");
    scratchpad_write("run-1", "recon", "fingerprint.json", "tech: express");
    scratchpad_checkpoint("run-1", "recon", { ids: ["case_r"], summary: "recon done" });

    const resume = scratchpad_resume("run-1")!;
    assert.strictEqual(resume.checkpoint.run_id, "run-1");
    assert.strictEqual(resume.next_phase, "hunt");
    assert.deepStrictEqual(resume.artifacts.recon, ["fingerprint.json"]);
  });

  it("does not schedule legacy gapfil as a new next phase", () => {
    scratchpad_init("run-1");
    scratchpad_checkpoint("run-1", "recon", { summary: "recon done" });
    scratchpad_checkpoint("run-1", "hunt", { summary: "hunt done" });

    const resume = scratchpad_resume("run-1")!;
    assert.strictEqual(resume.next_phase, "trace");
  });

  it("does not schedule legacy patch as a new next phase", () => {
    scratchpad_init("run-1");
    for (const phase of ["recon", "hunt", "trace", "skeptic", "validate", "chain"] as const) {
      scratchpad_checkpoint("run-1", phase, { summary: `${phase} done` });
    }

    const resume = scratchpad_resume("run-1")!;
    assert.strictEqual(resume.next_phase, "report");
  });

  it("resume returns null next_phase when all phases complete", () => {
    scratchpad_init("run-1");
    for (const phase of [
      "recon",
      "hunt",
      "gapfil",
      "trace",
      "skeptic",
      "validate",
      "chain",
      "patch",
      "report",
    ] as const) {
      scratchpad_checkpoint("run-1", phase, { summary: `${phase} done` });
    }
    const resume = scratchpad_resume("run-1")!;
    assert.strictEqual(resume.next_phase, null);
  });

  it("scratchpad_runs surfaces pre-hash-suffix (legacy) run directories", () => {
    // Runs created before the hash-suffix naming used sanitizeName(runId) as
    // the directory (e.g. "a/b" → "a_b"). They must still be discoverable
    // even though getRunDir now returns "a_b-<hash>".
    scratchpad_init("run-1");
    const legacyDir = join(getScratchpadRoot(tempDir), "a_b");
    mkdirSync(legacyDir, { recursive: true });
    writeFileSync(
      join(legacyDir, "state.json"),
      JSON.stringify({
        run_id: "a/b",
        project_root: tempDir,
        created_at: "2025-01-01T00:00:00.000Z",
        last_updated: "2025-01-01T00:00:00.000Z",
        last_phase_at: null,
        completed_phases: ["recon"],
        phase_ids: {},
        phase_summaries: {},
      }),
      "utf8",
    );
    const runs = scratchpad_runs(tempDir);
    assert.ok(runs.includes("a/b"), `legacy run missing from discovery: ${runs}`);
    assert.ok(runs.includes("run-1"), "new-style run still discovered");
  });

  it("clear removes a single run without touching others", () => {
    scratchpad_init("run-1");
    scratchpad_init("run-2");
    scratchpad_clear("run-1");
    const runs = readdirSync(getScratchpadRoot(tempDir));
    assert.deepStrictEqual(runs, ["run-2"]);
  });

  it("state.json is valid JSON with the expected shape", () => {
    scratchpad_init("run-1");
    scratchpad_checkpoint("run-1", "recon", { ids: ["x"], summary: "s" });
    const raw = readFileSync(join(getRunDir("run-1", tempDir), "state.json"), "utf8");
    const parsed = JSON.parse(raw);
    assert.strictEqual(parsed.run_id, "run-1");
    assert.ok(Array.isArray(parsed.completed_phases));
  });
});
