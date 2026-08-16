/**
 * Machine-confirmation benchmark corpus.
 *
 * Each scenario models one vulnerability class as a pair of live targets the
 * XPI harness gate must judge: a VULNERABLE instance and a PATCHED instance.
 * A class only scores when the gate SOUNDLY confirms — it must pass the
 * vulnerable target AND reject the patched one. Confirming both (or neither)
 * is a fail: a differential that cannot separate vulnerable from fixed is not
 * proof.
 *
 * `method` is the only sound machine-differential available to that class:
 *  - inter_host  — same request to target vs a distinct patched control host
 *                  (works when the proof travels in the response body and is
 *                  host-independent: file read, injection exfil, info leak).
 *  - canary      — inter_host plus a harness-injected reflection token.
 *  - intra_target — attack request vs a legitimate BASELINE request against the
 *                  SAME host (the only sound shape for access-control / logic
 *                  classes, where the discriminating variable is identity or a
 *                  parameter, not the host). Requires evidence.baseline.
 *
 * The response model is deterministic and offline; the runner turns it into a
 * mock fetch and drives the real harness (harness-verify.ts).
 */

import { POC_CANARY_PLACEHOLDER, type PoCEvidence } from "../packages/pi-casefile/src/evidence.ts";

export const TARGET_HOST = "app.target.test";
export const CONTROL_HOST = "app.control.test";

export type ReqCtx = {
  /** Lower-cased request host. */
  host: string;
  /** URL path + query. */
  pathAndQuery: string;
  method: string;
  headers: Record<string, string>;
  body?: string;
  /** The harness-injected canary token if this request carried one. */
  token?: string;
  /** True when modelling the PATCHED instance of the class. */
  patched: boolean;
};

export type Resp = { status: number; body: string };

export type Scenario = {
  id: string;
  /** Human label for the attack family. */
  title: string;
  method: "inter_host" | "canary" | "intra_target";
  evidence: PoCEvidence;
  /** Deterministic response model for both vulnerable and patched instances. */
  respond: (ctx: ReqCtx) => Resp;
};

const NOT_FOUND: Resp = { status: 404, body: "not found" };

/** Convenience: evidence skeleton with the load-bearing fields. */
function ev(verify: PoCEvidence["verify"], baseline?: PoCEvidence["baseline"]): PoCEvidence {
  return {
    nonce: "bench",
    claim: "benchmark scenario",
    verify,
    observations: ["benchmark observation"],
    ...(baseline ? { baseline } : {}),
  };
}

// ── Inter-host / canary classes: proof travels in the response body ──────────
// Sound under the current harness (same request, target vs patched control).

const reflectedXss: Scenario = {
  id: "reflected-xss",
  title: "Reflected XSS (canary reflection)",
  method: "canary",
  evidence: ev({
    method: "GET",
    url: `http://${TARGET_HOST}/search?q=${POC_CANARY_PLACEHOLDER}`,
    expect: { status: [200], body_contains: ["reflected:"] },
    canary: { mode: "reflection", placeholder: POC_CANARY_PLACEHOLDER },
  }),
  respond: ({ host, token, patched }) => {
    if (host !== TARGET_HOST) return { status: 200, body: "search page" };
    if (patched) return { status: 200, body: "sanitized input" };
    return { status: 200, body: `reflected:${token ?? ""}` };
  },
};

const pathTraversal: Scenario = {
  id: "path-traversal",
  title: "Path traversal → arbitrary file read",
  method: "inter_host",
  evidence: ev({
    method: "GET",
    url: `http://${TARGET_HOST}/download?file=../../../../etc/passwd`,
    expect: { status: [200], body_regex: ["root:.*:0:0:"] },
  }),
  respond: ({ host, patched }) => {
    if (host !== TARGET_HOST) return NOT_FOUND;
    if (patched) return { status: 403, body: "forbidden: path outside root" };
    return { status: 200, body: "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:" };
  },
};

const sqliExfil: Scenario = {
  id: "sqli-union-exfil",
  title: "SQL injection (UNION exfiltration)",
  method: "inter_host",
  evidence: ev({
    method: "GET",
    url: `http://${TARGET_HOST}/item?id=1%20UNION%20SELECT%20secret%20FROM%20users`,
    expect: { status: [200], body_regex: ["FLAG\\{[a-f0-9]{8}\\}"] },
  }),
  respond: ({ host, patched }) => {
    if (host !== TARGET_HOST) return NOT_FOUND;
    if (patched) return { status: 200, body: "item: Widget (no such id merged)" };
    return { status: 200, body: "item: Widget | secret=FLAG{deadbeef}" };
  },
};

const infoDisclosure: Scenario = {
  id: "info-disclosure-debug",
  title: "Debug endpoint leaks secrets",
  method: "inter_host",
  evidence: ev({
    method: "GET",
    url: `http://${TARGET_HOST}/actuator/env`,
    expect: { status: [200], body_contains: ["DB_PASSWORD="] },
  }),
  respond: ({ host, patched }) => {
    if (host !== TARGET_HOST) return NOT_FOUND;
    if (patched) return { status: 404, body: "not found" };
    return { status: 200, body: "APP_ENV=prod\nDB_PASSWORD=Sup3rS3cr3t!\n" };
  },
};

const xxe: Scenario = {
  id: "xxe-file-read",
  title: "XXE → local file read",
  method: "inter_host",
  evidence: ev({
    method: "POST",
    url: `http://${TARGET_HOST}/api/import`,
    headers: { "content-type": "application/xml" },
    body: '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>',
    expect: { status: [200], body_regex: ["root:.*:0:0:"] },
  }),
  respond: ({ host, patched }) => {
    if (host !== TARGET_HOST) return NOT_FOUND;
    if (patched) return { status: 400, body: "DOCTYPE is disallowed" };
    return { status: 200, body: "imported: root:x:0:0:root:/root:/bin/bash" };
  },
};

const ssti: Scenario = {
  id: "ssti-secret-leak",
  title: "SSTI leaks application secret",
  method: "inter_host",
  evidence: ev({
    method: "GET",
    url: `http://${TARGET_HOST}/greet?name=%7B%7Bconfig.SECRET_KEY%7D%7D`,
    expect: { status: [200], body_contains: ["SECRETKEY_"] },
  }),
  respond: ({ host, patched }) => {
    if (host !== TARGET_HOST) return NOT_FOUND;
    if (patched) return { status: 200, body: "Hello, {{config.SECRET_KEY}}" };
    return { status: 200, body: "Hello, SECRETKEY_9f83ab21" };
  },
};

// ── Intra-target classes: the discriminating variable is identity/parameter ──
// UNSOUND under inter-host (a different host lacks the victim's object/state);
// sound only with a same-host attack-vs-baseline differential (evidence.baseline).

const idor: Scenario = {
  id: "idor-bola",
  title: "IDOR / BOLA (cross-tenant object read)",
  method: "intra_target",
  evidence: ev(
    {
      method: "GET",
      url: `http://${TARGET_HOST}/api/orders/1001`,
      headers: { authorization: "Bearer attacker-token" },
      expect: { status: [200], body_contains: ["ssn:111-22-3333"] },
    },
    {
      method: "GET",
      url: `http://${TARGET_HOST}/api/orders/2002`,
      headers: { authorization: "Bearer attacker-token" },
    },
  ),
  respond: ({ host, pathAndQuery, patched }) => {
    if (host !== TARGET_HOST) return NOT_FOUND;
    const victim = pathAndQuery.includes("/orders/1001");
    if (victim) {
      if (patched) return { status: 403, body: "forbidden: not your order" };
      return { status: 200, body: "order 1001 owner:victim ssn:111-22-3333" };
    }
    return { status: 200, body: "order 2002 owner:attacker ssn:999-99-9999" };
  },
};

const authBypass: Scenario = {
  id: "broken-auth-bypass",
  title: "Missing authorization on admin endpoint",
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
    },
  ),
  respond: ({ host, headers, patched }) => {
    if (host !== TARGET_HOST) return NOT_FOUND;
    const bypass = headers["x-original-url"] !== undefined;
    if (bypass && !patched) return { status: 200, body: "user:root role:admin" };
    return { status: 401, body: "unauthorized" };
  },
};

const massAssignment: Scenario = {
  id: "mass-assignment-privesc",
  title: "Mass assignment → privilege escalation",
  method: "intra_target",
  evidence: ev(
    {
      method: "PUT",
      url: `http://${TARGET_HOST}/api/profile`,
      headers: { "content-type": "application/json" },
      body: '{"name":"eve","role":"admin"}',
      expect: { status: [200], body_contains: ['"role":"admin"'] },
    },
    {
      method: "PUT",
      url: `http://${TARGET_HOST}/api/profile`,
      headers: { "content-type": "application/json" },
      body: '{"name":"eve"}',
    },
  ),
  respond: ({ host, body, patched }) => {
    if (host !== TARGET_HOST) return NOT_FOUND;
    const wantsAdmin = (body ?? "").includes('"role":"admin"');
    if (wantsAdmin && !patched) return { status: 200, body: '{"name":"eve","role":"admin"}' };
    return { status: 200, body: '{"name":"eve","role":"user"}' };
  },
};

const jwtNone: Scenario = {
  id: "jwt-alg-none",
  title: "JWT alg=none authentication bypass",
  method: "intra_target",
  evidence: ev(
    {
      method: "GET",
      url: `http://${TARGET_HOST}/api/me`,
      headers: { authorization: "Bearer eyJhbGciOiJub25lIn0.eyJhZG1pbiI6dHJ1ZX0." },
      expect: { status: [200], body_contains: ['"admin":true'] },
    },
    {
      method: "GET",
      url: `http://${TARGET_HOST}/api/me`,
      headers: { authorization: "Bearer eyJhbGciOiJIUzI1NiJ9.eyJhZG1pbiI6ZmFsc2V9.sig" },
    },
  ),
  respond: ({ host, headers, patched }) => {
    if (host !== TARGET_HOST) return NOT_FOUND;
    const auth = headers.authorization ?? "";
    const algNone = auth.includes("eyJhbGciOiJub25lIn0");
    if (algNone) {
      if (patched) return { status: 401, body: "unsigned token rejected" };
      return { status: 200, body: '{"user":"eve","admin":true}' };
    }
    return { status: 200, body: '{"user":"eve","admin":false}' };
  },
};

const priceTampering: Scenario = {
  id: "price-tampering-logic",
  title: "Business logic: client-controlled price",
  method: "intra_target",
  evidence: ev(
    {
      method: "POST",
      url: `http://${TARGET_HOST}/checkout`,
      headers: { "content-type": "application/json" },
      body: '{"item":"tv","price":1}',
      expect: { status: [200], body_regex: ['"charged":1[^0-9]'] },
    },
    {
      method: "POST",
      url: `http://${TARGET_HOST}/checkout`,
      headers: { "content-type": "application/json" },
      body: '{"item":"tv"}',
    },
  ),
  respond: ({ host, body, patched }) => {
    if (host !== TARGET_HOST) return NOT_FOUND;
    const clientPrice = (body ?? "").includes('"price":1');
    if (clientPrice && !patched) return { status: 200, body: '{"item":"tv","charged":1}' };
    return { status: 200, body: '{"item":"tv","charged":19999}' };
  },
};

const pathAuthzBypass: Scenario = {
  id: "path-authz-bypass",
  title: "Path-normalization authorization bypass",
  method: "intra_target",
  evidence: ev(
    {
      method: "GET",
      url: `http://${TARGET_HOST}/public/..%2fadmin%2fconfig`,
      expect: { status: [200], body_contains: ["ADMIN_CONFIG_SECRET"] },
    },
    {
      method: "GET",
      url: `http://${TARGET_HOST}/admin/config`,
    },
  ),
  respond: ({ host, pathAndQuery, patched }) => {
    if (host !== TARGET_HOST) return NOT_FOUND;
    const bypass =
      pathAndQuery.includes("%2fadmin%2fconfig") || pathAndQuery.includes("/public/..");
    if (bypass && !patched) return { status: 200, body: "ADMIN_CONFIG_SECRET=root//admin" };
    return { status: 403, body: "forbidden" };
  },
};

export const CORPUS: Scenario[] = [
  // inter-host / canary (6)
  reflectedXss,
  pathTraversal,
  sqliExfil,
  infoDisclosure,
  xxe,
  ssti,
  // intra-target (6)
  idor,
  authBypass,
  massAssignment,
  jwtNone,
  priceTampering,
  pathAuthzBypass,
];
