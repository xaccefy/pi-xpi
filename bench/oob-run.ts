/**
 * OOB oracle soundness suite — Tier 1 of docs/poc-trust-model.md.
 *
 * Drives the REAL oracle client (oob-oracle.ts): harness-generated per-run
 * tokens, provision-domain binding, interaction polling with settle window,
 * self-IP filtering, unattributed-source rejection, and fail-closed behavior.
 * The operator-run oracle service is simulated with a faithful in-memory
 * implementation of its documented HTTP contract (POST /provision {token} ->
 * {domain}; GET /interactions?token= -> {interactions}).
 *
 * Every scenario asserts the gate's DECISION: target-only hits with attested
 * source separation may confirm; anything else must reject.
 *
 * Run: bun bench/oob-run.ts [--json]
 */

import {
  provisionCallback,
  setOobOracleFetchForTest,
  verifyOobDifferential,
} from "../packages/pi-casefile/src/oob-oracle.ts";

type OobInteraction = { protocol?: string; src_ip?: string; ts?: string; raw?: string };

/** In-memory oracle implementing the documented contract. */
function makeOracle() {
  const registry = new Map<string, OobInteraction[]>();
  let requestLog: Array<{ path: string; token?: string }> = [];
  return {
    registry,
    requestLog,
    reset() {
      registry.clear();
      requestLog = [];
    },
    hit(token: string, interaction: OobInteraction) {
      const list = registry.get(token) ?? [];
      list.push(interaction);
      registry.set(token, list);
    },
    /** Fetch handler speaking the documented JSON API. */
    fetch: async (url: string, init?: RequestInit): Promise<Response> => {
      const u = new URL(url);
      requestLog.push({ path: u.pathname, token: u.searchParams.get("token") ?? undefined });
      if (u.pathname === "/provision" && init?.method === "POST") {
        const body = JSON.parse(String(init.body)) as { token: string };
        return Response.json({ domain: `${body.token}.oob.oracle.test` });
      }
      if (u.pathname === "/interactions") {
        const token = u.searchParams.get("token");
        return Response.json({ interactions: registry.get(token ?? "") ?? [] });
      }
      return new Response("not found", { status: 404 });
    },
  };
}

const BASE_ENV = {
  // In-memory oracle: fetch is intercepted before any connection, but the
// URL must still satisfy the transport rule (https, or loopback http).
  PI_OOB_ORACLE_URL: "http://localhost",
  PI_OOB_SOURCE_SEPARATED: "1",
};

const TARGET_IP = "203.0.113.7"; // the (simulated) target's egress
const SELF_IP = "198.18.0.5"; // the sandbox's own egress

type ScenarioResult = { id: string; threat: string; pass: boolean; note: string };

const scenarios: Array<{ id: string; threat: string; run: () => Promise<string> }> = [
  {
    id: "oob-target-only-separated",
    threat: "target-token hit only, source separation attested — the one confirmable shape",
    run: async () => {
      const oracle = makeOracle();
      setOobOracleFetchForTest(oracle.fetch);
      const t = await provisionCallback({
        baseUrl: "http://localhost",
        sourceSeparated: true,
        selfIps: [SELF_IP],
      });
      const c = await provisionCallback({
        baseUrl: "http://localhost",
        sourceSeparated: true,
        selfIps: [SELF_IP],
      });
      oracle.hit(t.token, { src_ip: TARGET_IP });
      const { verification } = await verifyOobDifferential(
        {
          targetToken: t.token,
          controlToken: c.token,
          pollMs: 1500,
          intervalMs: 100,
          settleMs: 300,
        },
        BASE_ENV,
      );
      if (!verification.attempted) throw new Error("verification not attempted");
      if (!(verification.targetHits === 1 && verification.controlHits === 0))
        throw new Error(`hits ${verification.targetHits}/${verification.controlHits}`);
      if (!verification.sourceSeparated) throw new Error("separation lost");
      return `target=${verification.targetHits} control=${verification.controlHits}`;
    },
  },
  {
    id: "oob-delayed-control-hit",
    threat: "control-token hit lands AFTER the first target hit — settle window must catch it",
    run: async () => {
      const oracle = makeOracle();
      setOobOracleFetchForTest(oracle.fetch);
      const t = await provisionCallback({
        baseUrl: "http://localhost",
        sourceSeparated: true,
        selfIps: [],
      });
      const c = await provisionCallback({
        baseUrl: "http://localhost",
        sourceSeparated: true,
        selfIps: [],
      });
      // Control hit appears only after a delay that outlasts an early exit
      // but lands INSIDE the settle window once the target fires.
      setTimeout(() => oracle.hit(c.token, { src_ip: TARGET_IP }), 450);
      oracle.hit(t.token, { src_ip: TARGET_IP });
      const { verification } = await verifyOobDifferential(
        {
          targetToken: t.token,
          controlToken: c.token,
          pollMs: 4000,
          intervalMs: 80,
          settleMs: 900,
        },
        BASE_ENV,
      );
      if (verification.targetHits < 1) throw new Error("target miss");
      if (verification.controlHits !== 1)
        throw new Error(`delayed control hit missed (control=${verification.controlHits})`);
      return `settle window caught trailing control hit`;
    },
  },
  {
    id: "oob-self-ip-only",
    threat: "interactions originate from PI_OOB_SELF_IPS — self-caused, never counted",
    run: async () => {
      const oracle = makeOracle();
      setOobOracleFetchForTest(oracle.fetch);
      oracle.hit("selftokentoken123", { src_ip: SELF_IP });
      oracle.hit("selftokentoken123", { src_ip: SELF_IP });
      const { verification } = await verifyOobDifferential(
        {
          targetToken: "selftokentoken123",
          controlToken: "unusedtoken000001",
          pollMs: 800,
          intervalMs: 100,
          settleMs: 200,
        },
        { ...BASE_ENV, PI_OOB_SELF_IPS: SELF_IP },
      );
      if (verification.targetHits !== 0)
        throw new Error(`self hits counted: ${verification.targetHits}`);
      if (!/unattributed-or-self-source/.test(verification.note))
        throw new Error("note lacks rejection detail");
      return "self interactions rejected";
    },
  },
  {
    id: "oob-unattributed-source",
    threat: "interaction without src_ip cannot be attributed to the target — never counted",
    run: async () => {
      const oracle = makeOracle();
      setOobOracleFetchForTest(oracle.fetch);
      oracle.hit("faketokentoken01", { raw: "fabricated" }); // no src_ip
      const { verification } = await verifyOobDifferential(
        {
          targetToken: "faketokentoken01",
          controlToken: "unusedtoken000002",
          pollMs: 800,
          intervalMs: 100,
          settleMs: 200,
        },
        BASE_ENV,
      );
      if (verification.targetHits !== 0)
        throw new Error(`unattributed counted: ${verification.targetHits}`);
      return "unattributed interaction rejected";
    },
  },
  {
    id: "oob-no-oracle-fail-closed",
    threat: "no oracle configured — promotion must be impossible, not skipped",
    run: async () => {
      setOobOracleFetchForTest(undefined);
      let threw = "";
      try {
        await verifyOobDifferential({ targetToken: "t", controlToken: "c", pollMs: 500 }, {});
      } catch (e) {
        threw = (e as Error).message;
      }
      if (!/no OOB oracle configured/.test(threw))
        throw new Error(`wrong failure: ${threw || "none"}`);
      return "fails closed with explanatory error";
    },
  },
  {
    id: "oob-refuse-invented-domain",
    threat: "oracle returns a domain NOT embedding the harness token (invented secret)",
    run: async () => {
      setOobOracleFetchForTest(async () => Response.json({ domain: "fixed.oob.oracle.test" }));
      let threw = "";
      try {
        await provisionCallback({
          baseUrl: "http://localhost",
          sourceSeparated: true,
          selfIps: [],
        });
      } catch (e) {
        threw = (e as Error).message;
      }
      if (!/does not embed the harness token/.test(threw))
        throw new Error(`wrong failure: ${threw || "none"}`);
      return "oracle-invented secret refused";
    },
  },
];

export type OobReport = {
  total: number;
  passed: number;
  score: number;
  results: ScenarioResult[];
};

export async function runOobSuite(): Promise<OobReport> {
  const results: ScenarioResult[] = [];
  for (const scenario of scenarios) {
    try {
      const note = await scenario.run();
      results.push({ id: scenario.id, threat: scenario.threat, pass: true, note });
    } catch (e) {
      results.push({
        id: scenario.id,
        threat: scenario.threat,
        pass: false,
        note: (e as Error).message,
      });
    }
  }
  setOobOracleFetchForTest(undefined);
  const passed = results.filter((r) => r.pass).length;
  return { total: results.length, passed, score: passed / results.length, results };
}

if (import.meta.main) {
  const report = await runOobSuite();
  const out = (s: string) => console.log(s);
  for (const r of report.results) {
    out(`[${r.pass ? "PASS" : "FAIL"}] ${r.id.padEnd(28)} ${r.pass ? r.note : `— ${r.note}`}`);
  }
  out(`SCORE ${report.passed}/${report.total} = ${(report.score * 100).toFixed(1)}%`);
  if (report.passed !== report.total) process.exit(1);
}
