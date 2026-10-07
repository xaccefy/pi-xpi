import assert from "node:assert";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, it } from "node:test";
import {
  addCaseResult,
  addObjectiveResult,
  deleteObjectiveResult,
  getObjectiveById,
  linkObjectiveCase,
  listObjectives,
  setCasefilePath,
  unlinkObjectiveCase,
  updateObjectiveStatusResult,
} from "../src/ledger.ts";

let tempDir: string;
let ledgerPath: string;

beforeEach(async () => {
  tempDir = mkdtempSync(join(tmpdir(), "casefile-objectives-"));
  ledgerPath = join(tempDir, "casefile.db");
  setCasefilePath(ledgerPath);
});

afterEach(async () => {
  setCasefilePath(undefined);
  await Promise.resolve();
  rmSync(tempDir, { recursive: true, force: true });
});

function addCase(title: string) {
  const result = addCaseResult({
    title,
    status: "investigating",
    confidence: "medium",
    target: "https://api.example.com",
    evidence: "observed path",
    disproveIf: ["does not reproduce"],
  });
  return result.record;
}

describe("pi-casefile: engagement objectives", () => {
  it("adds and validates objectives", () => {
    const obj = addObjectiveResult({
      title: "Obtain admin session",
      phase: "initial-access",
      acceptance: "admin cookie captured in attacker jar",
    });
    assert.match(obj.id, /^obj_/);
    assert.equal(obj.status, "pending");

    assert.throws(
      () => addObjectiveResult({ title: "x", phase: "lateral-movement" }),
      /Invalid objective phase/,
    );
    assert.throws(() => addObjectiveResult({ title: "", phase: "recon" }), /must not be empty/);
    assert.throws(
      () => addObjectiveResult({ title: "y", phase: "recon", dependsOn: ["obj_missing"] }),
      /Dependency objective not found/,
    );
  });

  it("enforces the status state machine", () => {
    const obj = addObjectiveResult({ title: "Enumerate surface", phase: "recon" });

    // pending -> completed is not allowed; must pass through in-progress.
    assert.throws(
      () => updateObjectiveStatusResult(obj.id, "completed"),
      /Invalid transition pending -> completed/,
    );

    updateObjectiveStatusResult(obj.id, "in-progress");
    assert.equal(getObjectiveById(obj.id)?.status, "in-progress");

    updateObjectiveStatusResult(obj.id, "completed");
    assert.equal(getObjectiveById(obj.id)?.status, "completed");

    // Terminal states accept nothing.
    assert.throws(() => updateObjectiveStatusResult(obj.id, "in-progress"), /none \(terminal\)/);
  });

  it("blocking requires a reason; blocked objectives can resume", () => {
    const obj = addObjectiveResult({ title: "Exploit race", phase: "post-exploit" });
    updateObjectiveStatusResult(obj.id, "in-progress");

    assert.throws(() => updateObjectiveStatusResult(obj.id, "blocked"), /requires blocked_reason/);
    updateObjectiveStatusResult(obj.id, "blocked", "WAF rate-limits the burst endpoint");
    assert.equal(getObjectiveById(obj.id)?.blockedReason, "WAF rate-limits the burst endpoint");

    updateObjectiveStatusResult(obj.id, "in-progress");
    assert.equal(getObjectiveById(obj.id)?.status, "in-progress");
  });

  it("dependencies are enforced before an objective can start", () => {
    const recon = addObjectiveResult({ title: "Recon the target", phase: "recon" });
    const access = addObjectiveResult({
      title: "Obtain admin session",
      phase: "initial-access",
      dependsOn: [recon.id],
    });

    assert.throws(
      () => updateObjectiveStatusResult(access.id, "in-progress"),
      new RegExp(`Dependencies not met.*${recon.id} \\(pending\\)`),
    );

    updateObjectiveStatusResult(recon.id, "in-progress");
    updateObjectiveStatusResult(recon.id, "completed");
    updateObjectiveStatusResult(access.id, "in-progress");
    assert.equal(getObjectiveById(access.id)?.status, "in-progress");
  });

  it("links cases to objectives; link/unlink validated both ways", () => {
    const obj = addObjectiveResult({ title: "Read cross-tenant data", phase: "exfiltration" });
    const c1 = addCase("IDOR on invoices");
    const c2 = addCase("Unrelated case");

    const linked = linkObjectiveCase(obj.id, c1.id);
    assert.deepEqual(linked.caseIds, [c1.id]);

    assert.throws(() => linkObjectiveCase("obj_missing", c1.id), /Objective not found/);
    assert.throws(() => linkObjectiveCase(obj.id, "missing-case"), /Case not found/);

    assert.deepEqual(unlinkObjectiveCase(obj.id, c1.id).caseIds, []);
    assert.ok(c2);
  });

  it("lists with filters and deletes", () => {
    addObjectiveResult({ title: "Recon A", phase: "recon" });
    const b = addObjectiveResult({ title: "Access B", phase: "initial-access" });
    updateObjectiveStatusResult(b.id, "in-progress");

    assert.equal(listObjectives().length, 2);
    assert.equal(listObjectives({ phase: "recon" }).length, 1);
    assert.equal(listObjectives({ status: "in-progress" })[0].title, "Access B");

    assert.equal(deleteObjectiveResult(b.id), true);
    assert.equal(getObjectiveById(b.id), undefined);
    assert.equal(deleteObjectiveResult(b.id), false);
  });

  it("refuses to delete an objective that others depend on (no dangling depends_on)", () => {
    const recon = addObjectiveResult({ title: "Recon first", phase: "recon" });
    addObjectiveResult({ title: "Then access", phase: "initial-access", dependsOn: [recon.id] });

    assert.throws(() => deleteObjectiveResult(recon.id), /objectives .* depend on it/);
    // The dependency ordering still holds after the failed delete.
    assert.ok(getObjectiveById(recon.id));
  });
});
