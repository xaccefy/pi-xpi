/**
 * Adversarial soundness suite — cheat and noise shapes the gate MUST reject.
 *
 * Unlike corpus.ts (vulnerable/patched pairs proving the gate can CONFIRM),
 * every scenario here models an attempt to make the harness confirm something
 * unsound: decoy reflections, mirrored secrets, trivially-true predicates,
 * flaky targets, missing/identical baselines, and binding violations.
 * The only passing outcome is REJECTION — a false confirm scores zero.
 *
 * Drives the real harness-verify.ts through the same deterministic mock fetch
 * seam as run.ts. Run: bun bench/adversarial.ts [--json]
 */

import { POC_CANARY_PLACEHOLDER, type PoCEvidence } from "../packages/pi-casefile/src/evidence.ts";
import * as harness from "../packages/pi-casefile/src/harness-verify.ts";
import { CONTROL_HOST, type ReqCtx, type Resp, TARGET_HOST } from "./corpus.ts";

const NOT_FOUND: Resp = { status: 404, body: "not found" };

type RespondFn = (ctx: ReqCtx) => Resp;

type AdversarialScenario = {
  id: string;
  /** The cheat/noise shape being exercised. */
  threat: string;
  /** Which harness entry point the cheat targets. */
  method: "inter_host" | "canary" | "intra_target" | "binding";
  evidence?: PoCEvidence;
  /** Override the control origin (used by the same-identity cheat). */
  controlTarget?: string;
  respond: RespondFn;
};

function ev(verify: PoCEvidence["verify"], baseline?: PoCEvidence["baseline"]): PoCEvidence {
  return {
    nonce: "adv",
    claim: "adversarial scenario",
    verify,
    observations: ["adversarial observation"],
    ...(baseline ? { baseline } : {}),
  };
}

/** 1 — canary echoed by the CONTROL host: reflection alone proves nothing. */
const canaryControlEcho: AdversarialScenario = {
  id: "adv-canary-control-echo",
  threat: "control host reflects the harness canary (shared template/echo server)",
  method: "canary",
  evidence: ev({
    method: "GET",
    url: `http://${TARGET_HOST}/search?q=${POC_CANARY_PLACEHOLDER}`,
    expect: { status: [200], body_contains: ["reflected:"] },
    canary: { mode: "reflection", placeholder: POC_CANARY_PLACEHOLDER },
  }),
  respond: ({ host, token }) =>
    host === TARGET_HOST
      ? { status: 200, body: `reflected:${token ?? ""}` }
      : { status: 200, body: `reflected:${token ?? ""}` },
};

/** 2 — control serves the SAME secret (misconfigured mirror / decoy twin). */
const decoySecretControl: AdversarialScenario = {
  id: "adv-decoy-secret-control",
  threat: "control host returns the same matching body (decoy twin)",
  method: "inter_host",
  evidence: ev({
    method: "GET",
    url: `http://${TARGET_HOST}/actuator/env`,
    expect: { status: [200], body_contains: ["DB_PASSWORD="] },
  }),
  respond: () => ({
    status: 200,
    body: "APP_ENV=prod\nDB_PASSWORD=Sup3rS3cr3t!\n",
  }),
};

/** 3 — status-code-only predicate: generic 200s everywhere are not proof. */
const genericStatusPredicate: AdversarialScenario = {
  id: "adv-generic-status-predicate",
  threat: "predicate checks only the status code (matches both hosts)",
  method: "inter_host",
  evidence: ev({
    method: "GET",
    url: `http://${TARGET_HOST}/`,
    expect: { status: [200] },
  }),
  respond: ({ host }) =>
    host === TARGET_HOST
      ? { status: 200, body: "welcome to the app" }
      : { status: 200, body: "generic landing page" },
};

/** 4 — always-match regex: `.*` is satisfied by any response pair. */
const alwaysMatchRegex: AdversarialScenario = {
  id: "adv-always-match-regex",
  threat: "body_regex .* matches every body (trivial predicate)",
  method: "inter_host",
  evidence: ev({
    method: "GET",
    url: `http://${TARGET_HOST}/download?file=../../../../etc/passwd`,
    expect: { status: [200], body_regex: [".*"] },
  }),
  respond: ({ host }) =>
    host === TARGET_HOST
      ? { status: 200, body: "root:x:0:0:root:/root:/bin/bash" }
      : { status: 200, body: "harmless index" },
};

/** 5 — flaky target: first probe 500s; a crash is not evidence. */
const flakyTarget: AdversarialScenario = {
  id: "adv-flaky-target",
  threat: "target errors transiently (single-shot gate must not confirm)",
  method: "inter_host",
  evidence: ev({
    method: "GET",
    url: `http://${TARGET_HOST}/item?id=1 UNION SELECT secret FROM users`,
    expect: { status: [200], body_regex: ["FLAG\\{[a-f0-9]{8}\\}"] },
  }),
  respond: ({ host }) => {
    if (host !== TARGET_HOST) return NOT_FOUND;
    const n = (flakyCalls.get(flakyTarget) ?? 0) + 1;
    flakyCalls.set(flakyTarget, n);
    if (n === 1) return { status: 500, body: "internal error" };
    return { status: 200, body: "secret=FLAG{deadbeef}" };
  },
};

/** Per-run probe counters — reset by runAdversarial so repeated invocations
 * (test file calling both runAdversarial and runXbow) see identical behavior
 * instead of leaking state into the second run. */
const flakyCalls = new WeakMap<AdversarialScenario, number>();

/** 6 — intra-target without a baseline: no discriminator, no proof. */
const intraMissingBaseline: AdversarialScenario = {
  id: "adv-intra-missing-baseline",
  threat: "intra_target evidence omits baseline",
  method: "intra_target",
  evidence: ev({
    method: "GET",
    url: `http://${TARGET_HOST}/api/orders/1001`,
    headers: { authorization: "Bearer attacker-token" },
    expect: { status: [200], body_contains: ["ssn:111-22-3333"] },
  }),
  respond: ({ host }) =>
    host === TARGET_HOST
      ? { status: 200, body: "order 1001 owner:victim ssn:111-22-3333" }
      : NOT_FOUND,
};

/** 7 — attack and baseline identical: the variable must actually differ. */
const intraIdenticalBaseline: AdversarialScenario = {
  id: "adv-intra-identical-baseline",
  threat: "baseline request equals the attack request",
  method: "intra_target",
  evidence: ev(
    {
      method: "GET",
      url: `http://${TARGET_HOST}/admin/users`,
      headers: { "x-original-url": "/admin/users" },
      expect: { status: [200], body_contains: ["role:admin"] },
    },
    {
      method: "GET",
      url: `http://${TARGET_HOST}/admin/users`,
      headers: { "x-original-url": "/admin/users" },
    },
  ),
  respond: ({ host, headers }) =>
    host === TARGET_HOST && headers["x-original-url"] !== undefined
      ? { status: 200, body: "user:root role:admin" }
      : { status: 401, body: "unauthorized" },
};

/** 8 — verify.url points at a different host than the case target. */
const bindingHostMismatch: AdversarialScenario = {
  id: "adv-binding-host-mismatch",
  threat: "verify.url bound to a host other than the case target",
  method: "binding",
  evidence: ev({
    method: "GET",
    url: `http://other.target.test/download?file=../../../../etc/passwd`,
    expect: { status: [200], body_regex: ["root:.*:0:0:"] },
  }),
  respond: ({ host }) =>
    host === TARGET_HOST ? { status: 200, body: "root:x:0:0:root:/root:/bin/bash" } : NOT_FOUND,
};

/** 9 — control resolves to the same identity as the target. */
const controlSameIdentity: AdversarialScenario = {
  id: "adv-control-same-identity",
  threat: "control target is the case target (self-controlled differential)",
  method: "binding",
  evidence: ev({
    method: "GET",
    url: `http://${TARGET_HOST}/actuator/env`,
    expect: { status: [200], body_contains: ["DB_PASSWORD="] },
  }),
  controlTarget: TARGET_HOST,
  respond: () => ({ status: 200, body: "APP_ENV=prod\nDB_PASSWORD=Sup3rS3cr3t!\n" }),
};

/** 10 — target redirects off-host: the redirect guard voids the probe. */
const redirectOffHost: AdversarialScenario = {
  id: "adv-redirect-off-host",
  threat: "302 redirects the probe to an external host mid-replay",
  method: "inter_host",
  evidence: ev({
    method: "GET",
    url: `http://${TARGET_HOST}/jump?to=/etc/passwd`,
    expect: { status: [200], body_regex: ["root:.*:0:0:"] },
  }),
  respond: ({ host }) => (host === TARGET_HOST ? { status: 302, body: "" } : NOT_FOUND),
};

export const ADVERSARIAL_CORPUS: AdversarialScenario[] = [
  canaryControlEcho,
  decoySecretControl,
  genericStatusPredicate,
  alwaysMatchRegex,
  flakyTarget,
  intraMissingBaseline,
  intraIdenticalBaseline,
  bindingHostMismatch,
  controlSameIdentity,
  redirectOffHost,
];

function headersToRecord(init?: RequestInit): Record<string, string> {
  const out: Record<string, string> = {};
  const h = init?.headers;
  if (h instanceof Headers) for (const [k, v] of h.entries()) out[k.toLowerCase()] = v;
  else if (Array.isArray(h)) for (const [k, v] of h) out[k.toLowerCase()] = String(v);
  else if (h) for (const [k, v] of Object.entries(h)) out[k.toLowerCase()] = String(v);
  return out;
}

const TOKEN_RE = /poc_canary_[a-f0-9]{48}/;

function mockFetch(scenario: AdversarialScenario) {
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
      token: [url.toString(), body ?? "", ...Object.values(headers)]
        .map((hay) => hay.match(TOKEN_RE)?.[0])
        .find(Boolean),
      patched: false,
    };
    const r = scenario.respond(ctx);
    const res = new Response(r.body, { status: r.status });
    if (r.status === 302) {
      // Redirect target for the off-host hop scenario.
      res.headers.set("location", "http://evil.test/steal");
    }
    return res;
  };
}

export type AdversarialResult = {
  id: string;
  title: string;
  threat: string;
  rejected: boolean;
  note: string;
};

export type AdversarialReport = {
  total: number;
  rejected: number;
  score: number;
  results: AdversarialResult[];
};

async function judgeOne(scenario: AdversarialScenario): Promise<{ pass: boolean; note: string }> {
  const opts = { allowPrivate: true, fetchImpl: mockFetch(scenario) };
  let res: harness.HarnessVerifyResult;
  if (scenario.method === "intra_target") {
    res = await harness.replayIntraTarget(scenario.evidence!, TARGET_HOST, opts);
  } else {
    res = await harness.replayDifferential(
      scenario.evidence!,
      TARGET_HOST,
      scenario.controlTarget ?? CONTROL_HOST,
      opts,
    );
  }
  return { pass: res.pass === true, note: res.note };
}

/** Every scenario must be REJECTED. A pass is an integrity failure. */
export async function runAdversarial(): Promise<AdversarialReport> {
  flakyCalls.delete(flakyTarget);
  const results: AdversarialResult[] = [];
  for (const scenario of ADVERSARIAL_CORPUS) {
    const outcome = await judgeOne(scenario);
    results.push({
      id: scenario.id,
      title: scenario.threat,
      threat: scenario.threat,
      rejected: !outcome.pass,
      note: outcome.note,
    });
  }
  const rejected = results.filter((r) => r.rejected).length;
  return { total: results.length, rejected, score: rejected / results.length, results };
}

function scoreboard(report: AdversarialReport): string {
  const lines: string[] = [];
  lines.push("XPI adversarial soundness suite — cheats and noise the gate must reject");
  lines.push("=".repeat(72));
  for (const r of report.results) {
    const mark = r.rejected ? "PASS" : "FAIL";
    lines.push(
      `[${mark}] ${r.id.padEnd(28)} ${r.rejected ? "rejected" : `FALSE CONFIRM — ${r.note}`}`,
    );
  }
  lines.push("-".repeat(72));
  lines.push(
    `SCORE ${report.rejected}/${report.total} rejected = ${(report.score * 100).toFixed(1)}%`,
  );
  return lines.join("\n");
}

if (import.meta.main) {
  const report = await runAdversarial();
  const out = (s: string) => console.log(s);
  if (process.argv.includes("--json")) {
    out(JSON.stringify(report, null, 2));
  } else {
    out(scoreboard(report));
  }
  if (report.rejected !== report.total) process.exit(1);
}
