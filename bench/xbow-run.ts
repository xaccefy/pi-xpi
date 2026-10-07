/**
 * XPI gate-evaluation suite — soundness gates + chain recall.
 *
 * Naming honesty: what most of this repo calls a "bench" is a SOUNDNESS
 * suite — deterministic checks that the confirmation machinery behaves
 * correctly offline. It measures the judge, not the hunter. The only
 * agent-in-the-loop evaluation is scripts/xbow/run-one.sh against real
 * XBEN docker challenges; its per-challenge verdicts are the benchmark.
 *
 * Gated suites (CI must stay at 100%):
 *   differential — vulnerable/patched pairs through harness-verify.ts
 *   adversarial  — cheats and noise the gate must REJECT
 *   chain        — ChainSuggest recall + strict near-miss rejection
 *   oob          — Tier-1 oracle client end-to-end decisions
 *   transport    — raw_request byte-exactness, race_send burst delivery
 * Reported but NOT gated:
 *   holdout      — paraphrased-chain generalization probe
 *
 * Run: bun bench/xbow-run.ts [--json]
 */

import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { runAdversarial } from "./adversarial.ts";
import { runChainBench, runHoldoutProbe } from "./chain-run.ts";
import { runOobSuite } from "./oob-run.ts";
import { runBench } from "./run.ts";
import { runTransportSuite } from "./transport-run.ts";

export type SuiteReport = {
  differential: Awaited<ReturnType<typeof runBench>>;
  adversarial: Awaited<ReturnType<typeof runAdversarial>>;
  chain: ReturnType<typeof runChainBench>;
  holdout: ReturnType<typeof runHoldoutProbe>;
  oob: Awaited<ReturnType<typeof runOobSuite>>;
  transport: Awaited<ReturnType<typeof runTransportSuite>>;
  overall: {
    /** Gated units: every suite contributes its pass count. */
    total: number;
    passed: number;
    score: number;
  };
};

export async function runXbow(): Promise<SuiteReport> {
  const differential = await runBench();
  const adversarial = await runAdversarial();
  const chain = runChainBench();
  const holdout = runHoldoutProbe();
  const oob = await runOobSuite();
  const transport = await runTransportSuite();

  const total = differential.total + adversarial.total + chain.total + oob.total + transport.total;
  const passed =
    differential.sound +
    adversarial.rejected +
    chain.correctlySuggested +
    chain.correctlyRejected +
    oob.passed +
    transport.passed;
  return {
    differential,
    adversarial,
    chain,
    holdout,
    oob,
    transport,
    overall: { total, passed, score: passed / total },
  };
}

function scoreboard(r: SuiteReport): string {
  const lines: string[] = [];
  lines.push("XPI gate soundness suites — judge correctness, offline and deterministic");
  lines.push("=".repeat(80));
  lines.push("");
  lines.push("DIFFERENTIAL (vulnerable confirmed AND patched rejected — harness-verify.ts)");
  lines.push("-".repeat(80));
  for (const res of r.differential.results) {
    const mark = res.sound ? "PASS" : "FAIL";
    lines.push(
      `[${mark}] ${res.id.padEnd(24)} ${res.method.padEnd(13)} ${res.sound ? "" : `— ${res.note}`}`,
    );
  }
  lines.push(
    `SCORE ${r.differential.sound}/${r.differential.total} = ${(r.differential.score * 100).toFixed(1)}%`,
  );
  lines.push("");
  lines.push("ADVERSARIAL (cheats and noise — every case must be REJECTED)");
  lines.push("-".repeat(80));
  for (const res of r.adversarial.results) {
    lines.push(
      `[${res.rejected ? "PASS" : "FAIL"}] ${res.id.padEnd(28)} ${res.rejected ? "rejected" : `FALSE CONFIRM — ${res.note}`}`,
    );
  }
  lines.push(
    `SCORE ${r.adversarial.rejected}/${r.adversarial.total} = ${(r.adversarial.score * 100).toFixed(1)}%`,
  );
  lines.push("");
  lines.push("CHAIN (ChainSuggest: pattern-exact positives + strict near-miss rejection)");
  lines.push("-".repeat(80));
  for (const d of r.chain.details) {
    if (d.pass) continue; // failures are the news; keep the scoreboard short
    lines.push(
      `[FAIL] ${d.id.padEnd(22)} ${d.pattern.padEnd(26)} exp=${String(d.expected).padEnd(5)} got=${String(d.suggested).padEnd(5)} — ${d.note}`,
    );
  }
  lines.push(
    `SCORE ${r.chain.correctlySuggested + r.chain.correctlyRejected}/${r.chain.total} = ${(r.chain.score * 100).toFixed(1)}%` +
      `  |  cGain ${r.chain.correctlySuggested}/${r.chain.shouldSuggest} = ${(r.chain.cGain * 100).toFixed(1)}%` +
      `  |  rejections ${r.chain.correctlyRejected}/${r.chain.shouldNotSuggest}`,
  );
  lines.push("");
  lines.push("OOB ORACLE (Tier-1 client decisions against a contract-faithful mock oracle)");
  lines.push("-".repeat(80));
  for (const res of r.oob.results) {
    lines.push(
      `[${res.pass ? "PASS" : "FAIL"}] ${res.id.padEnd(28)} ${res.pass ? res.note : `— ${res.note}`}`,
    );
  }
  lines.push(`SCORE ${r.oob.passed}/${r.oob.total} = ${(r.oob.score * 100).toFixed(1)}%`);
  lines.push("");
  lines.push("TRANSPORT (real sockets: raw_request verbatim bytes, race_send burst delivery)");
  lines.push("-".repeat(80));
  for (const res of r.transport.results) {
    lines.push(
      `[${res.pass ? "PASS" : "FAIL"}] ${res.id.padEnd(24)} ${res.pass ? res.note : `— ${res.note}`}`,
    );
  }
  lines.push(
    `SCORE ${r.transport.passed}/${r.transport.total} = ${(r.transport.score * 100).toFixed(1)}%`,
  );
  lines.push("");
  lines.push("HOLDOUT (paraphrase generalization probe — reported, NOT gated)");
  lines.push("-".repeat(80));
  lines.push(
    `${r.holdout.suggested}/${r.holdout.total} recalled (${(r.holdout.recall * 100).toFixed(0)}%)` +
      (r.holdout.misses.length
        ? ` — misses: ${r.holdout.misses.map((m) => `${m.id}[${m.difficulty}]`).join(", ")}`
        : ""),
  );
  lines.push("");
  lines.push("=".repeat(80));
  lines.push(
    `OVERALL ${r.overall.passed}/${r.overall.total} = ${(r.overall.score * 100).toFixed(1)}%` +
      ` (differential ${r.differential.sound}/${r.differential.total}` +
      ` + adversarial ${r.adversarial.rejected}/${r.adversarial.total}` +
      ` + chain ${r.chain.correctlySuggested + r.chain.correctlyRejected}/${r.chain.total}` +
      ` + oob ${r.oob.passed}/${r.oob.total}` +
      ` + transport ${r.transport.passed}/${r.transport.total})`,
  );
  lines.push("");
  lines.push("Agent-in-the-loop results live in scripts/xbow/run-one.sh verdicts, not here.");
  return lines.join("\n");
}

if (import.meta.main) {
  const report = await runXbow();
  const here = dirname(fileURLToPath(import.meta.url));
  const outDir = join(here, "results");
  mkdirSync(outDir, { recursive: true });
  writeFileSync(join(outDir, "xbow-latest.json"), `${JSON.stringify(report, null, 2)}\n`);
  const out = (s: string) => console.log(s);
  if (process.argv.includes("--json")) {
    out(JSON.stringify(report, null, 2));
  } else {
    out(scoreboard(report));
    out(`\nwrote ${join(outDir, "xbow-latest.json")}`);
  }
  // Gates: both differential directions stay perfect, every cheat is
  // rejected, chain keeps >=90% with cGain >=85%, OOB and transport stay
  // perfect, and the combined gated score stays >=95%.
  if (
    report.differential.score < 1 ||
    report.adversarial.score < 1 ||
    report.chain.score < 0.9 ||
    report.chain.cGain < 0.85 ||
    report.oob.score < 1 ||
    report.transport.score < 1 ||
    report.overall.score < 0.95
  ) {
    console.error(
      "\nGate thresholds not met (need differential 100%, adversarial 100%, chain ≥90%/cGain ≥85%, oob 100%, transport 100%, overall ≥95%)",
    );
    process.exit(1);
  }
}
