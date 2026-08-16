/**
 * Machine-confirmation benchmark runner.
 *
 * Drives the REAL harness gate (harness-verify.ts) against every corpus
 * scenario's vulnerable and patched instance through a deterministic mock
 * fetch. A class scores iff the gate confirms the vulnerable target AND
 * rejects the patched one (sound differential). The pre-intra-target baseline
 * (6/12, inter-host + canary only) is recorded in bench/results/baseline.json.
 *
 * Run:  bun bench/run.ts            (human scoreboard + writes bench/results/latest.json)
 *       bun bench/run.ts --json     (JSON only)
 */

import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import * as harness from "../packages/pi-casefile/src/harness-verify.ts";
import {
  CONTROL_HOST,
  CORPUS,
  type ReqCtx,
  type Resp,
  type Scenario,
  TARGET_HOST,
} from "./corpus.ts";

const TOKEN_RE = /poc_canary_[a-f0-9]{48}/;

type ScenarioResult = {
  id: string;
  title: string;
  method: Scenario["method"];
  confirmedVulnerable: boolean;
  rejectedPatched: boolean;
  sound: boolean;
  note: string;
};

export type BenchReport = {
  total: number;
  sound: number;
  score: number; // 0..1
  results: ScenarioResult[];
};

function headersToRecord(init?: RequestInit): Record<string, string> {
  const out: Record<string, string> = {};
  const h = init?.headers;
  if (h instanceof Headers) for (const [k, v] of h.entries()) out[k.toLowerCase()] = v;
  else if (Array.isArray(h)) for (const [k, v] of h) out[k.toLowerCase()] = String(v);
  else if (h) for (const [k, v] of Object.entries(h)) out[k.toLowerCase()] = String(v);
  return out;
}

function detectToken(
  url: string,
  body: string | undefined,
  headers: Record<string, string>,
): string | undefined {
  for (const hay of [url, body ?? "", ...Object.values(headers)]) {
    const m = hay.match(TOKEN_RE);
    if (m) return m[0];
  }
  return undefined;
}

/** Build a mock fetch that answers from the scenario's response model. */
function mockFetch(scenario: Scenario, patched: boolean) {
  return async (input: string | URL, init?: RequestInit): Promise<Response> => {
    const url = new URL(String(input));
    const headers = headersToRecord(init);
    const body = typeof init?.body === "string" ? init.body : undefined;
    const ctx: ReqCtx = {
      host: url.hostname.toLowerCase(),
      pathAndQuery: url.pathname + url.search,
      method: (init?.method ?? "GET").toUpperCase(),
      headers,
      body,
      token: detectToken(url.toString(), body, headers),
      patched,
    };
    const r: Resp = scenario.respond(ctx);
    return new Response(r.body, { status: r.status });
  };
}

/** Confirm one instance (vulnerable or patched) via the class's sound method. */
async function confirm(
  scenario: Scenario,
  patched: boolean,
): Promise<{ pass: boolean; note: string }> {
  const fetchImpl = mockFetch(scenario, patched);
  const res =
    scenario.method === "intra_target"
      ? await harness.replayIntraTarget(scenario.evidence, TARGET_HOST, {
          allowPrivate: true,
          fetchImpl,
        })
      : await harness.replayDifferential(scenario.evidence, TARGET_HOST, CONTROL_HOST, {
          allowPrivate: true,
          fetchImpl,
        });
  return { pass: res.pass === true, note: res.note };
}

export async function runBench(): Promise<BenchReport> {
  const results: ScenarioResult[] = [];
  for (const scenario of CORPUS) {
    const tp = await confirm(scenario, false);
    const fp = await confirm(scenario, true);
    const confirmedVulnerable = tp.pass;
    const rejectedPatched = !fp.pass;
    const sound = confirmedVulnerable && rejectedPatched;
    results.push({
      id: scenario.id,
      title: scenario.title,
      method: scenario.method,
      confirmedVulnerable,
      rejectedPatched,
      sound,
      note: sound
        ? "sound: confirmed vulnerable, rejected patched"
        : !confirmedVulnerable
          ? `missed vulnerable: ${tp.note}`
          : `false-confirmed patched: ${fp.note}`,
    });
  }
  const sound = results.filter((r) => r.sound).length;
  return { total: results.length, sound, score: sound / results.length, results };
}

function scoreboard(report: BenchReport): string {
  const lines: string[] = [];
  lines.push("XPI machine-confirmation benchmark — sound-confirm recall by vuln class");
  lines.push("=".repeat(72));
  for (const r of report.results) {
    const mark = r.sound ? "PASS" : "FAIL";
    lines.push(
      `[${mark}] ${r.id.padEnd(24)} ${r.method.padEnd(13)} ${r.sound ? "" : `— ${r.note}`}`,
    );
  }
  lines.push("-".repeat(72));
  lines.push(`SCORE ${report.sound}/${report.total} = ${(report.score * 100).toFixed(1)}%`);
  return lines.join("\n");
}

if (import.meta.main) {
  const report = await runBench();
  const here = dirname(fileURLToPath(import.meta.url));
  const outDir = join(here, "results");
  mkdirSync(outDir, { recursive: true });
  writeFileSync(join(outDir, "latest.json"), `${JSON.stringify(report, null, 2)}\n`);
  // biome-ignore lint/suspicious/noConsole: CLI scoreboard output is the point
  const out = (s: string) => console.log(s);
  if (process.argv.includes("--json")) {
    out(JSON.stringify(report, null, 2));
  } else {
    out(scoreboard(report));
    out(`\nwrote ${join(outDir, "latest.json")}`);
  }
}
