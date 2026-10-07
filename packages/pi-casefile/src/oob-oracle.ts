/**
 * Operator-owned OOB oracle client — Tier 1 of docs/poc-trust-model.md.
 *
 * Blind/OOB classes (SSRF, blind XSS, XXE, DNS exfil) cannot be confirmed by
 * response differentials: the effect lands on a callback channel. The trust
 * model requires the judge to own the evidence channel and the secret:
 *
 * - The HARNESS generates a per-run random token and provisions a callback
 *   domain embedding it via the operator-run oracle service. The value does
 *   not exist when the PoC script is written, so it cannot be pre-printed.
 * - The PoC causes the TARGET to interact with that domain; the oracle's own
 *   interaction log — read back by the harness, never by the PoC — is the
 *   evidence.
 * - Differential shape: the target run gets one token, the control run a
 *   DIFFERENT token. Proof requires target-token interactions AND zero
 *   control-token interactions.
 *
 * Source separation (the PoC must not be able to fake the interaction):
 * - Hard guarantee (three-box model): only when the operator attests the
 *   network topology separates PoC egress from oracle reachability via
 *   PI_OOB_SOURCE_SEPARATED=1. Without it, verification stays diagnostic
 *   and the ledger gate refuses promotion.
 * - Self-interaction filtering: interactions originating from PI_OOB_SELF_IPS
 *   (the sandbox/host egress addresses) are rejected as self-caused and never
 *   counted as target hits.
 *
 * Everything fails closed: no oracle configured -> OOB promotion impossible.
 */

import { randomBytes } from "node:crypto";

export type OobInteraction = {
  protocol?: string;
  src_ip?: string;
  ts?: string;
  raw?: string;
};

export type OobOracleConfig = {
  baseUrl: string;
  bearer?: string;
  sourceSeparated: boolean;
  selfIps: string[];
};

/** Read the operator's oracle configuration; error text explains what's missing. */
export function readOobOracleConfig(env: NodeJS.ProcessEnv = process.env): {
  config?: OobOracleConfig;
  error?: string;
} {
  const raw = (env.PI_OOB_ORACLE_URL ?? "").trim();
  if (!raw) {
    return {
      error:
        "no OOB oracle configured. Set PI_OOB_ORACLE_URL to an operator-run oracle service " +
        "(POST /provision {token} -> {domain}; GET /interactions?token= -> {interactions}). " +
        "Declare PI_OOB_SOURCE_SEPARATED=1 only when the network topology truly prevents the " +
        "PoC sandbox from reaching the oracle directly.",
    };
  }
  let baseUrl: URL;
  try {
    baseUrl = new URL(raw);
  } catch {
    return { error: `PI_OOB_ORACLE_URL is not a valid URL: ${raw}` };
  }
  if (baseUrl.protocol !== "http:" && baseUrl.protocol !== "https:") {
    return { error: `PI_OOB_ORACLE_URL must be http(s), got ${baseUrl.protocol}` };
  }
  const selfIps = (env.PI_OOB_SELF_IPS ?? "")
    .split(",")
    .map((v) => v.trim())
    .filter(Boolean);
  return {
    config: {
      baseUrl: raw.replace(/\/+$/, ""),
      bearer: env.PI_OOB_ORACLE_TOKEN?.trim() || undefined,
      sourceSeparated: env.PI_OOB_SOURCE_SEPARATED === "1",
      selfIps,
    },
  };
}

type FetchLike = (url: string, init?: RequestInit) => Promise<Response>;

let oracleFetchForTest: FetchLike | undefined;

/** Test seam; production uses global fetch. */
export function setOobOracleFetchForTest(impl: FetchLike | undefined): void {
  oracleFetchForTest = impl;
}

function makeToken(): string {
  return randomBytes(16).toString("hex");
}

async function oracleFetch(
  config: OobOracleConfig,
  path: string,
  init?: RequestInit,
): Promise<Response> {
  const headers: Record<string, string> = {
    accept: "application/json",
    ...((init?.headers as Record<string, string>) ?? {}),
  };
  if (config.bearer) headers.authorization = `Bearer ${config.bearer}`;
  const fetchImpl = oracleFetchForTest ?? fetch;
  // Bounded: an unresponsive oracle must fail the run, not hang the tool.
  return fetchImpl(`${config.baseUrl}${path}`, {
    ...init,
    headers,
    signal: AbortSignal.timeout(30_000),
  });
}

export type ProvisionedCallback = {
  /** Harness-generated secret embedded in the provisioned domain. */
  token: string;
  /** Domain the payload must make the target interact with. */
  domain: string;
};

/**
 * Provision one callback identity. The token is generated HERE (harness owns
 * the secret); the oracle returns a domain that embeds it.
 */
export async function provisionCallback(config: OobOracleConfig): Promise<ProvisionedCallback> {
  const token = makeToken();
  let res: Response;
  try {
    res = await oracleFetch(config, "/provision", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ token }),
    });
  } catch (e) {
    throw new Error(`OOB oracle unreachable (${config.baseUrl}): ${(e as Error).message}`);
  }
  if (!res.ok) {
    throw new Error(`OOB oracle /provision failed: HTTP ${res.status}`);
  }
  let body: { domain?: unknown };
  try {
    body = (await res.json()) as { domain?: unknown };
  } catch {
    throw new Error("OOB oracle /provision returned a non-JSON body");
  }
  if (typeof body.domain !== "string" || !body.domain.includes(token)) {
    throw new Error(
      "OOB oracle /provision returned a domain that does not embed the harness token — refusing an oracle that invents its own secrets",
    );
  }
  return { token, domain: body.domain };
}

export type OobPollResult = {
  interactions: OobInteraction[];
  /** Interactions NOT counted (self-IP matches) — recorded honestly. */
  selfInteractions: OobInteraction[];
};

/** Fetch (not wait-and-retry — callers own the polling loop) current interactions for a token. */
export async function fetchInteractions(
  config: OobOracleConfig,
  token: string,
): Promise<OobPollResult> {
  let res: Response;
  try {
    res = await oracleFetch(config, `/interactions?token=${encodeURIComponent(token)}`);
  } catch (e) {
    throw new Error(`OOB oracle unreachable (${config.baseUrl}): ${(e as Error).message}`);
  }
  if (!res.ok) {
    throw new Error(`OOB oracle /interactions failed: HTTP ${res.status}`);
  }
  let body: { interactions?: unknown };
  try {
    body = (await res.json()) as { interactions?: unknown };
  } catch {
    throw new Error("OOB oracle /interactions returned a non-JSON body");
  }
  if (!Array.isArray(body.interactions)) {
    throw new Error("OOB oracle /interactions response missing interactions array");
  }
  const all = body.interactions.filter(
    (i): i is OobInteraction => typeof i === "object" && i !== null,
  );
  const self = config.selfIps;
  // Fail closed on provenance: an interaction WITHOUT a source IP cannot be
  // attributed to the target (a PoC could fabricate one on any channel it
  // reaches), so it is never counted as a hit — surfaced separately instead.
  const interactions = all.filter(
    (i) => typeof i.src_ip === "string" && i.src_ip.length > 0 && !self.includes(i.src_ip),
  );
  const selfInteractions = all.filter(
    (i) => !i.src_ip || (typeof i.src_ip === "string" && self.includes(i.src_ip)),
  );
  return { interactions, selfInteractions };
}

/**
 * Poll for interactions on both run tokens. Once ANY token observes an
 * interaction, polling continues for a full settle window so a DELAYED
 * control-token hit (the false-positive shape: target fires at t=1s, a
 * cheating/self-caused control hit lands at t=3s after an early exit)
 * cannot be missed. Evaluation happens after settle or at deadline.
 */
export async function verifyOobDifferential(
  opts: {
    targetToken: string;
    controlToken: string;
    pollMs?: number;
    intervalMs?: number;
    /** Keep polling this long after the first observed interaction. */
    settleMs?: number;
  },
  env: NodeJS.ProcessEnv = process.env,
): Promise<{ verification: import("./ledger.ts").OobVerification }> {
  const { config, error } = readOobOracleConfig(env);
  if (!config) throw new Error(error ?? "OOB oracle not configured");
  // Env overrides are operator tuning: clamp to sane minimums so a typo like
  // PI_OOB_POLL_MS=-5 cannot produce an inverted deadline or a zero window.
  const pollMs = opts.pollMs ?? Math.max(Number(env.PI_OOB_POLL_MS) || 30_000, 1_000);
  const intervalMs = opts.intervalMs ?? Math.max(Number(env.PI_OOB_INTERVAL_MS) || 2_000, 100);
  const settleMs =
    opts.settleMs ?? Math.max(Number(env.PI_OOB_SETTLE_MS) || Math.max(intervalMs, 5_000), 250);
  const deadline = Date.now() + pollMs;

  let target: OobPollResult = { interactions: [], selfInteractions: [] };
  let control: OobPollResult = { interactions: [], selfInteractions: [] };
  let firstHitAt: number | undefined;
  for (;;) {
    target = await fetchInteractions(config, opts.targetToken);
    control = await fetchInteractions(config, opts.controlToken);
    if (target.interactions.length > 0 || control.interactions.length > 0) {
      firstHitAt ??= Date.now();
      // Settled: kept watching past the first hit long enough to catch
      // trailing control hits.
      if (Date.now() - firstHitAt >= settleMs) break;
    }
    const now = Date.now();
    if (now >= deadline) break;
    await new Promise((r) => setTimeout(r, Math.min(intervalMs, deadline - now)));
  }

  const notes: string[] = [];
  if (target.selfInteractions.length + control.selfInteractions.length > 0) {
    notes.push(
      `${target.selfInteractions.length} target-run / ${control.selfInteractions.length} ` +
        "control-run unattributed-or-self-source interaction(s) rejected (missing src_ip or PI_OOB_SELF_IPS)",
    );
  }
  notes.push(
    config.sourceSeparated
      ? "operator attests source separation (PI_OOB_SOURCE_SEPARATED=1)"
      : "source separation NOT attested — diagnostic only",
  );
  // Tokens are stored raw in the ledger (see PendingConfirmation.oobTokens);
  // an oracle reachable without a bearer token makes those tokens pollable by
  // anyone with ledger read access. Surface it where the operator's attention
  // already is — the verification note.
  if (!config.bearer) {
    notes.push(
      "oracle has no PI_OOB_ORACLE_TOKEN — stored run tokens are pollable by anyone with oracle network access; set a bearer token or restrict the oracle endpoint",
    );
  }

  return {
    verification: {
      attempted: true,
      targetHits: target.interactions.length,
      controlHits: control.interactions.length,
      sourceSeparated: config.sourceSeparated,
      note:
        `target-token ${target.interactions.length} interaction(s), control-token ${control.interactions.length}` +
        (notes.length ? `; ${notes.join("; ")}` : ""),
    },
  };
}
