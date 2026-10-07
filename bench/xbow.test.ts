import assert from "node:assert";
import { describe, it } from "node:test";
import { runAdversarial } from "./adversarial.ts";
import { runChainBench, runHoldoutProbe } from "./chain-run.ts";
import { runOobSuite } from "./oob-run.ts";
import { runBench } from "./run.ts";
import { runTransportSuite } from "./transport-run.ts";
import { runXbow } from "./xbow-run.ts";

// The gate suites exercise loopback transports (127.0.0.1 fixtures); the
// tests are the operator, so the private-host gate opens for this process.
process.env.PI_WEBXP_ALLOW_PRIVATE_HOSTS = "1";

describe("gate soundness suites", () => {
  it("differential stays 12/12 (confirms vulnerable AND rejects patched)", async () => {
    const r = await runBench();
    assert.strictEqual(r.sound, 12, `differential regressed: ${r.sound}/12`);
    assert.strictEqual(r.score, 1);
    const intra = r.results.filter((x) => x.method === "intra_target");
    assert.ok(intra.length >= 6, "intra-target classes must remain covered");
    for (const x of intra) assert.ok(x.sound, `${x.id} regressed: ${x.note}`);
  });

  it("adversarial cheats are ALL rejected (no false confirms)", async () => {
    const r = await runAdversarial();
    assert.strictEqual(
      r.rejected,
      r.total,
      `false confirms: ${r.results
        .filter((x) => !x.rejected)
        .map((x) => x.id)
        .join(", ")}`,
    );
    assert.strictEqual(r.score, 1);
  });

  it("chain: pattern-exact positives AND strict near-miss rejections", () => {
    const c = runChainBench();
    assert.strictEqual(c.total, 33);
    assert.strictEqual(
      c.correctlySuggested,
      c.shouldSuggest,
      `missed chains: ${c.details
        .filter((d) => !d.pass && d.expected)
        .map((d) => d.id)
        .join(", ")}`,
    );
    assert.strictEqual(
      c.correctlyRejected,
      c.shouldNotSuggest,
      `near-misses accepted: ${c.details
        .filter((d) => !d.pass && !d.expected)
        .map((d) => d.id)
        .join(", ")}`,
    );
    assert.strictEqual(c.score, 1);
    // The near-miss negative set must stay meaningful — not shrink back to 2.
    assert.ok(c.shouldNotSuggest >= 15, `negative coverage shrank: ${c.shouldNotSuggest}`);
  });

  it("chain holdout: in-vocabulary paraphrases recalled; probe reports honestly", () => {
    const h = runHoldoutProbe();
    const invocabMisses = h.misses.filter((m) => m.difficulty === "in-vocabulary");
    assert.deepStrictEqual(
      invocabMisses,
      [],
      `in-vocabulary holdout missed: ${invocabMisses.map((m) => m.id).join(", ")}`,
    );
  });

  it("oob oracle decisions are correct end-to-end", async () => {
    const r = await runOobSuite();
    assert.strictEqual(
      r.passed,
      r.total,
      `oob failures: ${r.results
        .filter((x) => !x.pass)
        .map((x) => x.id)
        .join(", ")}`,
    );
  });

  it("transport: verbatim bytes and race burst delivery over real sockets", async () => {
    const r = await runTransportSuite();
    assert.strictEqual(
      r.passed,
      r.total,
      `transport failures: ${r.results
        .filter((x) => !x.pass)
        .map((x) => x.id)
        .join(", ")}`,
    );
  });

  it("overall gated suite 63/63", async () => {
    const x = await runXbow();
    assert.strictEqual(x.overall.total, 63);
    assert.strictEqual(x.overall.passed, 63);
    assert.strictEqual(x.overall.score, 1);
    assert.strictEqual(x.differential.sound, 12);
    assert.strictEqual(x.adversarial.rejected, 10);
    assert.strictEqual(x.chain.correctlySuggested, 16);
    assert.strictEqual(x.oob.passed, 6);
    assert.strictEqual(x.transport.passed, 2);
  });
});
