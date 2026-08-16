/**
 * Regression gate for the machine-confirmation benchmark.
 *
 * Baseline (pre intra-target differential, captured in bench/results/baseline.json
 * from unmodified harness code): 6/12 = 0.50 — only body-carried classes
 * (file read, injection exfil, info leak, reflection) had a sound differential;
 * access-control and business-logic classes were unconfirmable.
 *
 * This test runs the corpus against the CURRENT harness and asserts the score
 * is at least 50% above that baseline, and that every access-control / logic
 * class now has a sound same-host differential.
 */

import assert from "node:assert";
import { describe, it } from "node:test";
import { runBench } from "./run.ts";

const BASELINE_SCORE = 0.5; // bench/results/baseline.json, unmodified harness

describe("machine-confirmation benchmark", () => {
  it("scores at least +50% over the pre-intra-target baseline", async () => {
    const report = await runBench();
    assert.ok(
      report.score >= BASELINE_SCORE * 1.5,
      `score ${(report.score * 100).toFixed(1)}% is not >= +50% over baseline ${(BASELINE_SCORE * 100).toFixed(1)}%`,
    );
  });

  it("soundly confirms every corpus class (confirms vulnerable, rejects patched)", async () => {
    const report = await runBench();
    const unsound = report.results.filter((r) => !r.sound).map((r) => `${r.id}: ${r.note}`);
    assert.deepStrictEqual(unsound, [], `unsound classes:\n${unsound.join("\n")}`);
  });

  it("keeps every intra-target class sound (guards the new capability)", async () => {
    const report = await runBench();
    const intra = report.results.filter((r) => r.method === "intra_target");
    assert.ok(intra.length >= 6, "expected at least 6 intra-target classes");
    for (const r of intra) {
      assert.ok(r.sound, `${r.id} regressed: ${r.note}`);
    }
  });
});
