import assert from "node:assert";
import { existsSync, mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, it } from "node:test";

import { pipeline_submit } from "../src/pipeline-submit.ts";
import { scratchpad_init, scratchpad_read, setScratchpadRoot } from "../src/scratchpad.ts";

let tempDir: string;

beforeEach(() => {
  tempDir = mkdtempSync(join(tmpdir(), "pipeline-submit-test-"));
  setScratchpadRoot(tempDir);
  scratchpad_init("run-1");
});

afterEach(async () => {
  setScratchpadRoot(undefined);
  await rm(tempDir, { recursive: true, force: true });
});

const VALID_HUNT = {
  file: "src/api/users.ts",
  line: 42,
  vuln_class: "sqli" as string,
  sink: "db.query()",
  entry_point: "GET /api/users",
  confidence: "high",
  evidence: "param flows unescaped into query",
};

function withRealFile(obj: Record<string, unknown>): Record<string, unknown> {
  const filePath = join(tempDir, "src/api/users.ts");
  mkdirSync(join(tempDir, "src/api"), { recursive: true });
  writeFileSync(filePath, "// source\n");
  return obj;
}

describe("pipeline_submit", () => {
  it("accepts a valid hunt finding and writes an artifact", () => {
    withRealFile({});
    const res = pipeline_submit("run-1", "hunt", { ...VALID_HUNT, vuln_class: "injection" });
    assert.strictEqual(res.verdict, "accepted");
    assert.ok(res.artifact && existsSync(res.artifact));
  });

  it("tolerates JSON-string output with code fences", () => {
    withRealFile({});
    const res = pipeline_submit(
      "run-1",
      "hunt",
      `\`\`\`json\n${JSON.stringify({ ...VALID_HUNT, vuln_class: "xss" })}\n\`\`\``,
    );
    assert.strictEqual(res.verdict, "accepted");
  });

  it("returns repair with field-level errors for a missing required field", () => {
    const res = pipeline_submit("run-1", "hunt", {
      ...VALID_HUNT,
      vuln_class: "xss",
      evidence: "",
    });
    assert.strictEqual(res.verdict, "repair");
    assert.ok(res.errors.some((e) => e.startsWith("evidence:")));
    assert.strictEqual(res.repair_attempt, 1);
  });

  it("returns repair for a bad enum value", () => {
    const res = pipeline_submit("run-1", "hunt", { ...VALID_HUNT, confidence: "certain" });
    assert.strictEqual(res.verdict, "repair");
    assert.ok(res.errors.some((e) => e.includes("confidence")));
  });

  it("enforces the locator XOR: file+line OR endpoint, not both/neither", () => {
    const both = { ...VALID_HUNT, vuln_class: "xss", endpoint: "GET /api/users" };
    const resBoth = pipeline_submit("run-1", "hunt", both);
    assert.strictEqual(resBoth.verdict, "repair");
    assert.ok(resBoth.errors.some((e) => e.startsWith("locator:")));

    const neither = { ...VALID_HUNT, vuln_class: "xss" };
    delete (neither as Record<string, unknown>).file;
    delete (neither as Record<string, unknown>).line;
    const resNeither = pipeline_submit("run-1", "hunt", neither);
    assert.strictEqual(resNeither.verdict, "repair");
    assert.ok(resNeither.errors.some((e) => e.startsWith("locator:")));
  });

  it("endpoint-only (live target) findings skip the file gates", () => {
    const res = pipeline_submit("run-1", "hunt", {
      vuln_class: "ssrf",
      sink: "fetch(url)",
      endpoint: "GET /api/proxy?url=",
      entry_point: "url param",
      confidence: "medium",
      evidence: "url flows to fetch without allowlist",
    });
    assert.strictEqual(res.verdict, "accepted");
  });

  it("repair budget: third invalid submission of the same finding is rejected", () => {
    const bad = { ...VALID_HUNT, vuln_class: "xss", evidence: "" };
    assert.strictEqual(pipeline_submit("run-1", "hunt", bad).verdict, "repair");
    assert.strictEqual(pipeline_submit("run-1", "hunt", bad).verdict, "repair");
    const third = pipeline_submit("run-1", "hunt", bad);
    assert.strictEqual(third.verdict, "rejected");
    assert.ok(third.errors.some((e) => e.includes("repair budget exhausted")));
  });

  it("skeptic DISPROVEN without disproval_reason is repair", () => {
    const res = pipeline_submit("run-1", "skeptic", {
      finding_id: "case_1",
      verdict: "DISPROVEN",
      reasoning: "defense in depth blocks it",
      evidence_reviewed: ["src/auth.ts"],
    });
    assert.strictEqual(res.verdict, "repair");
    assert.ok(res.errors.some((e) => e.includes("disproval_reason")));
  });

  it("trace UNREACHABLE without unreachable_reason is repair", () => {
    const res = pipeline_submit("run-1", "trace", {
      trace_result: "UNREACHABLE",
      entry_point: "GET /x",
      call_chain: ["a → b"],
      defenses_checked: [],
      attacker_model: "unauth",
    });
    assert.strictEqual(res.verdict, "repair");
    assert.ok(res.errors.some((e) => e.includes("unreachable_reason")));
  });

  it("validate confirmed requires poc_path + run_log + evidence_extracted", () => {
    const res = pipeline_submit("run-1", "validate", {
      finding_id: "case_1",
      status: "confirmed",
      technique_used: "error-based",
      detection_method: "response diff",
    });
    assert.strictEqual(res.verdict, "repair");
    assert.ok(res.errors.some((e) => e.includes("poc_path")));
    assert.ok(res.errors.some((e) => e.includes("run_log")));
    assert.ok(res.errors.some((e) => e.includes("evidence_extracted")));
  });

  it("prefilter rejects test-path findings (not repairable)", () => {
    const res = pipeline_submit("run-1", "hunt", {
      ...VALID_HUNT,
      vuln_class: "injection",
      file: "test/helpers/login.test.ts",
    });
    assert.strictEqual(res.verdict, "rejected");
    assert.ok(res.errors.some((e) => e.includes("test-path filter")));
  });

  it("prefilter rejects hallucinated files (not repairable)", () => {
    const res = pipeline_submit("run-1", "hunt", {
      ...VALID_HUNT,
      vuln_class: "injection",
      file: "src/does/not/exist.ts",
    });
    assert.strictEqual(res.verdict, "rejected");
    assert.ok(res.errors.some((e) => e.includes("file-existence filter")));
  });

  it("trivial dedup: same file + class within 10 lines is rejected as duplicate", () => {
    withRealFile({});
    const first = pipeline_submit("run-1", "hunt", { ...VALID_HUNT, vuln_class: "xss", line: 40 });
    assert.strictEqual(first.verdict, "accepted");
    const second = pipeline_submit("run-1", "hunt", { ...VALID_HUNT, vuln_class: "xss", line: 45 });
    assert.strictEqual(second.verdict, "rejected");
    assert.strictEqual(second.duplicate_of, first.key);
  });

  it("dedup does not fire across classes or distant lines", () => {
    withRealFile({});
    pipeline_submit("run-1", "hunt", { ...VALID_HUNT, vuln_class: "xss", line: 40 });
    const otherClass = pipeline_submit("run-1", "hunt", {
      ...VALID_HUNT,
      vuln_class: "injection",
      line: 40,
    });
    assert.strictEqual(otherClass.verdict, "accepted");
    const distant = pipeline_submit("run-1", "hunt", {
      ...VALID_HUNT,
      vuln_class: "ssti",
      line: 80,
    });
    assert.strictEqual(distant.verdict, "accepted");
  });

  it("dedup state persists across submissions via the run state file", () => {
    withRealFile({});
    pipeline_submit("run-1", "hunt", { ...VALID_HUNT, vuln_class: "idor", line: 10 });
    const res = pipeline_submit("run-1", "hunt", { ...VALID_HUNT, vuln_class: "idor", line: 12 });
    assert.strictEqual(res.verdict, "rejected");
    assert.ok(res.duplicate_of);
  });

  it("chain items enforce steps >= 2 and severity enum", () => {
    const res = pipeline_submit("run-1", "chain", {
      chains: [{ title: "c", severity: "extreme", steps: ["a"], narrative: "n" }],
      summary: "one chain",
    });
    assert.strictEqual(res.verdict, "repair");
    assert.ok(res.errors.some((e) => e.includes("severity")));
    assert.ok(res.errors.some((e) => e.includes("steps")));
  });

  it("prefilter catches __tests__ and e2e directories (segment-anchored)", () => {
    for (const dir of ["__tests__", "e2e", "test-utils"]) {
      const res = pipeline_submit("run-1", "hunt", {
        ...VALID_HUNT,
        vuln_class: "crypto-weakness",
        file: `src/${dir}/widget.ts`,
      });
      assert.strictEqual(res.verdict, "rejected", `${dir} should be filtered`);
    }
  });

  it("prefilter does NOT false-positive on segments like latest/attest", () => {
    mkdirSync(join(tempDir, "src/latest"), { recursive: true });
    writeFileSync(join(tempDir, "src/latest/widget.ts"), "// source\n");
    const res = pipeline_submit("run-1", "hunt", {
      ...VALID_HUNT,
      vuln_class: "open-redirect",
      file: "src/latest/widget.ts",
    });
    assert.strictEqual(res.verdict, "accepted");
  });

  it("containment filter rejects files resolving outside the project root", () => {
    const res = pipeline_submit("run-1", "hunt", {
      ...VALID_HUNT,
      vuln_class: "information-disclosure",
      file: "../outside/secret.ts",
    });
    assert.strictEqual(res.verdict, "rejected");
    assert.ok(res.errors.some((e) => e.includes("containment filter")));
  });

  it("report stage requires coverage as an OBJECT (not array)", () => {
    const asArray = pipeline_submit("run-1", "report", {
      target: "t",
      pipeline_status: "complete",
      findings: [],
      coverage: [],
      summary: "s",
    });
    assert.strictEqual(asArray.verdict, "repair");
    assert.ok(asArray.errors.some((e) => e.includes("coverage")));

    const asObject = pipeline_submit("run-1", "report", {
      target: "t",
      pipeline_status: "complete",
      findings: [],
      coverage: { sqli: "NOT_FOUND" },
      summary: "s",
    });
    assert.strictEqual(asObject.verdict, "accepted");
  });

  it("unparseable output also exhausts the repair budget", () => {
    assert.strictEqual(pipeline_submit("run-1", "hunt", "not json{").verdict, "repair");
    assert.strictEqual(pipeline_submit("run-1", "hunt", "not json{").verdict, "repair");
    const third = pipeline_submit("run-1", "hunt", "not json{");
    assert.strictEqual(third.verdict, "rejected");
  });

  it("accepted outputs land in the scratchpad phase dir (resume-safe)", () => {
    const res = pipeline_submit("run-1", "skeptic", {
      finding_id: "case_9",
      verdict: "CONFIRMED",
      reasoning: "read src/auth.ts:88 — no defense on this path",
      evidence_reviewed: ["src/auth.ts"],
    });
    assert.strictEqual(res.verdict, "accepted");
    const back = scratchpad_read("run-1", "skeptic", "skeptic_case_9.json");
    assert.ok(back?.includes("CONFIRMED"));
  });
});
