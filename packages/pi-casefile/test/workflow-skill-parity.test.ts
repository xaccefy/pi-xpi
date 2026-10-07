import assert from "node:assert";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { KILL_REASON_VALUES } from "../src/ledger.ts";
import { STATIC_CYBER_WORKFLOW, STATIC_CYBER_WORKFLOW_LITE } from "../src/workflow.ts";

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "../../..");
const skillText = readFileSync(join(repoRoot, "skills/cyberwf/SKILL.md"), "utf8");
describe("workflow ↔ skill drift guard", () => {
  it("kill-reason vocabulary stays in sync with workflow text", () => {
    const wLower = STATIC_CYBER_WORKFLOW.toLowerCase();
    const sLower = skillText.toLowerCase();
    for (const reason of KILL_REASON_VALUES) {
      assert.ok(wLower.includes(reason.toLowerCase()), `workflow missing kill reason: ${reason}`);
    }
    const skillMustHave = ["intended_behavior", "out_of_scope"];
    for (const reason of skillMustHave) {
      assert.ok(sLower.includes(reason.toLowerCase()), `skill missing kill reason: ${reason}`);
    }
  });

  it("differential-mode definitions appear in both workflow and skill", () => {
    for (const invariant of ["inter_host", "intra_target"]) {
      assert.ok(
        STATIC_CYBER_WORKFLOW.includes(invariant),
        `workflow missing invariant: ${invariant}`,
      );
      assert.ok(skillText.includes(invariant), `skill missing invariant: ${invariant}`);
    }
  });
  it("exit-zero-never-proof gate sentence appears in both", () => {
    const w = STATIC_CYBER_WORKFLOW.toLowerCase();
    const s = skillText.toLowerCase();
    // Workflow says "exit zero", skill says "zero exit" — both signal the same gate.
    assert.ok(w.includes("zero") && w.includes("never"), "workflow missing exit-zero gate wording");
    assert.ok(s.includes("zero"), "skill missing zero-exit gate wording");
  });
  it("ConfirmFinding main-agent-only wording appears in both", () => {
    const w = STATIC_CYBER_WORKFLOW.toLowerCase();
    const s = skillText.toLowerCase();
    assert.ok(w.includes("confirmfinding"), "workflow missing ConfirmFinding");
    assert.ok(s.includes("confirmfinding"), "skill missing ConfirmFinding");
    assert.ok(
      w.includes("main") && w.includes("confirm"),
      "workflow missing main-agent confirm wording",
    );
    assert.ok(
      s.includes("main") && s.includes("confirm"),
      "skill missing main-agent confirm wording",
    );
  });

  it("LITE workflow retains the same invariants as full workflow", () => {
    for (const reason of KILL_REASON_VALUES.slice(0, 3)) {
      assert.ok(
        STATIC_CYBER_WORKFLOW_LITE.includes(reason),
        `LITE workflow missing kill reason: ${reason}`,
      );
    }
    assert.ok(STATIC_CYBER_WORKFLOW_LITE.includes("intra_target"));
  });
});
