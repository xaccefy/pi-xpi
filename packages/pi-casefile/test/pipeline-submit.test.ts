import assert from "node:assert";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, it } from "node:test";

import { pipeline_submit } from "../src/pipeline-submit.ts";
import { scratchpad_init, setScratchpadRoot } from "../src/scratchpad.ts";

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
    const res = pipeline_submit("run-1", "hunt", VALID_HUNT);
    assert.strictEqual(res.verdict, "accepted");
    assert.ok(res.artifact && existsSync(res.artifact));
  });

  it("accepts an agent-chosen vuln_class outside the old fixed taxonomy", () => {
    withRealFile({});
    const res = pipeline_submit("run-1", "hunt", {
      ...VALID_HUNT,
      vuln_class: "oauth-callback-open-redirect",
    });
    assert.strictEqual(res.verdict, "accepted");
  });

  it("accepts an absolute in-project hunt file path", () => {
    withRealFile({});
    const res = pipeline_submit("run-1", "hunt", {
      ...VALID_HUNT,
      file: join(tempDir, "src/api/users.ts"),
      vuln_class: "graphql-bola",
    });
    assert.strictEqual(res.verdict, "accepted");
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

  it("returns repair for a bad confidence enum value", () => {
    const res = pipeline_submit("run-1", "hunt", { ...VALID_HUNT, confidence: "certain" });
    assert.strictEqual(res.verdict, "repair");
    assert.ok(res.errors.some((e) => e.includes("confidence")));
  });

  it("returns repair for an unknown top-level field", () => {
    const res = pipeline_submit("run-1", "hunt", {
      ...VALID_HUNT,
      confidence: "high",
      invented_by_agent: true,
    });
    assert.strictEqual(res.verdict, "repair");
    assert.ok(res.errors.includes("invented_by_agent: unknown top-level field"));
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

  it("skeptic UNDETERMINED requires uncertainty_reason", () => {
    const missing = pipeline_submit("run-1", "skeptic", {
      finding_id: "case_1",
      verdict: "UNDETERMINED",
      reasoning: "the endpoint requires credentials the reviewer does not have",
      evidence_reviewed: ["GET /admin/export"],
    });
    assert.strictEqual(missing.verdict, "repair");
    assert.ok(missing.errors.some((e) => e.includes("uncertainty_reason")));

    const accepted = pipeline_submit("run-1", "skeptic", {
      finding_id: "case_1",
      verdict: "UNDETERMINED",
      reasoning: "the endpoint requires credentials the reviewer does not have",
      evidence_reviewed: ["GET /admin/export"],
      uncertainty_reason: "missing low-privileged account needed to verify reachability",
    });
    assert.strictEqual(accepted.verdict, "accepted");
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

  it("trace UNDETERMINED requires uncertainty_reason", () => {
    const missing = pipeline_submit("run-1", "trace", {
      trace_result: "UNDETERMINED",
      entry_point: "GET /admin/export",
      call_chain: ["GET /admin/export → blocked before sink visibility"],
      defenses_checked: [{ defense: "auth gateway", location: "live probe", verdict: "blocked" }],
      attacker_model: "low-privilege user",
    });
    assert.strictEqual(missing.verdict, "repair");
    assert.ok(missing.errors.some((e) => e.includes("uncertainty_reason")));

    const accepted = pipeline_submit("run-1", "trace", {
      trace_result: "UNDETERMINED",
      entry_point: "GET /admin/export",
      call_chain: ["GET /admin/export → blocked before sink visibility"],
      defenses_checked: [{ defense: "auth gateway", location: "live probe", verdict: "blocked" }],
      attacker_model: "low-privilege user",
      uncertainty_reason:
        "probe requires a low-privileged test account to distinguish auth block from WAF block",
    });
    assert.strictEqual(accepted.verdict, "accepted");
  });

  it("validate pending_confirmation requires poc_path + run_log + evidence_extracted", () => {
    const res = pipeline_submit("run-1", "validate", {
      finding_id: "case_1",
      status: "pending_confirmation",
      technique_used: "error-based",
      detection_method: "response diff",
    });
    assert.strictEqual(res.verdict, "repair");
    assert.ok(res.errors.some((e) => e.includes("poc_path")));
    assert.ok(res.errors.some((e) => e.includes("run_log")));
    assert.ok(res.errors.some((e) => e.includes("evidence_extracted")));
  });

  it("accepts an absolute in-project validation poc_path", () => {
    const pocPath = join(tempDir, "pocs/prove.sh");
    mkdirSync(join(tempDir, "pocs"), { recursive: true });
    writeFileSync(pocPath, "#!/bin/sh\nexit 0\n", "utf8");

    const res = pipeline_submit("run-1", "validate", {
      finding_id: "case_1",
      status: "pending_confirmation",
      technique_used: "differential request",
      detection_method: "response diff",
      poc_path: pocPath,
      run_log: "PromoteFinding bundle recorded",
      evidence_extracted: "target-only body predicate matched",
    });
    assert.strictEqual(res.verdict, "accepted");
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
      coverage: { "OAuth callback open redirect": "NOT_FOUND" },
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
      disconfirmation_attempt:
        "tried the same request unauthenticated and with a second account — no leak; effect is account-bound",
    });
    assert.strictEqual(res.verdict, "accepted");
    // Artifact filenames carry a content hash (distinct findings sharing an
    // id must not clobber each other) — read back through the returned path.
    assert.ok(res.artifact, "accepted submission records its artifact path");
    assert.ok(readFileSync(res.artifact, "utf8").includes("CONFIRMED"));
  });

  it('junk ids ("false") are rejected without merging distinct repair buckets', () => {
    withRealFile({});
    // Hunt does not allow finding_id, and the value "false" carries no useful
    // identity anyway. Distinct invalid submissions still need independent
    // content-hash repair buckets so one cannot exhaust the other's budget.
    const a = pipeline_submit("run-1", "hunt", {
      ...VALID_HUNT,
      vuln_class: "injection",
      sink: "db.query(a)",
      finding_id: "false",
    });
    const b = pipeline_submit("run-1", "hunt", {
      ...VALID_HUNT,
      vuln_class: "xss",
      sink: "innerHTML(b)",
      finding_id: "false",
    });
    assert.strictEqual(a.verdict, "repair");
    assert.strictEqual(b.verdict, "repair");
    assert.strictEqual(a.repair_attempt, 1);
    assert.strictEqual(b.repair_attempt, 1);
    assert.ok(a.errors.some((e) => e.startsWith("finding_id: unknown")));
    assert.ok(b.errors.some((e) => e.startsWith("finding_id: unknown")));
    assert.notStrictEqual(a.key, b.key, "distinct findings must not share a key");

    // Unparseable output has its own fixed bucket as well.
    const bad = pipeline_submit("run-1", "hunt", "not json{");
    assert.strictEqual(bad.repair_attempt, 1);
    assert.strictEqual(bad.key, "hunt:unparseable");
  });
});
