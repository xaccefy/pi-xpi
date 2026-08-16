/**
 * Harness-side target/control replay — Tier 2 of docs/poc-trust-model.md.
 *
 * The machine floor cannot trust a caller's self-reported `re_executed`
 * boolean. This module makes the HARNESS re-send the evidence's `verify`
 * request with its own HTTP client and apply the same `expect` predicates
 * (status / body_contains / body_regex) to target and control responses. The
 * main agent supplies the predicate; the harness owns both evidence acquisition
 * and predicate execution before the later semantic review.
 *
 * Policy:
 * - Private/internal hosts require explicit operator authorization; otherwise
 *   replay fails closed.
 * - Redirects are manual and every hop is checked before it is fetched.
 * - Target must match while the identical control request must not.
 *
 * Undici's custom dispatcher pins the approved DNS result through connect;
 * node:dns and node:net provide resolution and address classification.
 */

import { createHash, randomBytes } from "node:crypto";
import { lookup as dnsLookup } from "node:dns/promises";
import { isIP } from "node:net";
import { Worker } from "node:worker_threads";
import { isPublicIpAddress } from "@xaccefy/pi-shared";
import { Agent, fetch as undiciFetch } from "undici";
import { POC_CANARY_PLACEHOLDER, type PoCEvidence, type VerifyExpect } from "./evidence.ts";

// Public re-export makes the single-source classifier identity testable across
// the web tool and confirmation replay paths.
export { isPublicIpAddress } from "@xaccefy/pi-shared";

export type HarnessVerifyResult = {
  /** true = the harness sent both target and control requests and judged them. */
  attempted: boolean;
  /** Present when attempted: target matched and control did not. */
  pass?: boolean;
  /** Backward-compatible target status summary. */
  status?: number;
  /** Machine-observed target/control response summaries. */
  target?: HarnessResponseObservation;
  control?: HarnessResponseObservation;
  differential?: "target_only" | "both" | "control_only" | "neither";
  /** Independent harness-generated reflection signal, when the template supports one. */
  canary?: HarnessCanaryResult;
  /** Honest machine claim: predicates alone, or predicates plus a causal canary. */
  proofStrength?: "predicate_differential" | "canary_differential";
  note: string;
};

export type HarnessCanaryResult = {
  mode: "reflection";
  attempted: boolean;
  pass?: boolean;
  tokenSha256: string;
  targetObserved?: boolean;
  controlObserved?: boolean;
  note: string;
};

export type HarnessResponseObservation = {
  attempted: boolean;
  matched?: boolean;
  status?: number;
  url: string;
  bodySha256?: string;
  bodyBytes?: number;
  canaryObserved?: boolean;
  note: string;
};

const MAX_BODY_BYTES = 2 * 1024 * 1024;
const TIMEOUT_MS = 30_000;
const MAX_REDIRECTS = 5;
const REGEX_TIMEOUT_MS = 250;

type ResolvedAddress = { address: string; family: 4 | 6 };

async function resolveHost(hostname: string): Promise<ResolvedAddress[]> {
  const host = hostname.toLowerCase().replace(/^\[|\]$/g, "");
  const literalFamily = isIP(host);
  if (literalFamily) return [{ address: host, family: literalFamily as 4 | 6 }];
  const lookup = dnsLookup(host, { all: true, verbatim: true }) as Promise<ResolvedAddress[]>;
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      lookup,
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new Error("DNS lookup timed out")), 5_000);
      }),
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

function parseNetworkTarget(target: string): { url: URL; explicitProtocol: boolean } | undefined {
  const value = target.trim();
  if (!value || /\s/.test(value)) return;
  const explicitProtocol = /^https?:\/\//i.test(value);
  try {
    const url = new URL(explicitProtocol ? value : `http://${value}`);
    if (!(url.protocol === "http:" || url.protocol === "https:") || !url.hostname) return;
    if (url.username || url.password) return;
    return { url, explicitProtocol };
  } catch {
    return;
  }
}

function effectivePort(url: URL): string {
  return url.port || (url.protocol === "https:" ? "443" : "80");
}

function sameTargetIdentity(left: string, right: string): boolean {
  const a = parseNetworkTarget(left);
  const b = parseNetworkTarget(right);
  if (!a || !b) return false;
  if (
    a.url.hostname.toLowerCase().replace(/\.$/, "") !==
    b.url.hostname.toLowerCase().replace(/\.$/, "")
  ) {
    return false;
  }
  if ((a.url.port || b.url.port) && effectivePort(a.url) !== effectivePort(b.url)) return false;
  return !(a.explicitProtocol && b.explicitProtocol && a.url.protocol !== b.url.protocol);
}

/**
 * A control is a trust anchor, not an agent invention. The operator supplies
 * an allowlist of approved control origins/hosts through the process env.
 */
export function controlTargetAuthorizationError(
  controlTarget: string,
  allowedRaw: string | undefined = process.env.PI_POC_CONTROL_TARGETS,
): string | undefined {
  const allowed = (allowedRaw ?? "")
    .split(/[,\n]/)
    .map((value) => value.trim())
    .filter(Boolean);
  if (allowed.length === 0) {
    return "no operator-approved controls are configured in PI_POC_CONTROL_TARGETS";
  }
  if (!allowed.some((candidate) => sameTargetIdentity(candidate, controlTarget))) {
    return `control target ${controlTarget} is not present in the operator-approved PI_POC_CONTROL_TARGETS allowlist`;
  }
  return;
}

/**
 * Bind a model-authored verify URL to the target the harness actually ran.
 * A bare target permits either HTTP scheme; an explicit target URL binds the
 * scheme as well as hostname and effective port.
 */
export function verifyUrlBindingError(verifyUrl: string, target: string): string | undefined {
  const declared = parseNetworkTarget(target);
  let observed: URL;
  try {
    observed = new URL(verifyUrl);
  } catch {
    return `verify.url is not parseable: ${verifyUrl}`;
  }
  if (!declared) return `target is not an HTTP network target: ${target}`;
  const declaredHost = declared.url.hostname.toLowerCase().replace(/\.$/, "");
  const observedHost = observed.hostname.toLowerCase().replace(/\.$/, "");
  if (declaredHost !== observedHost) {
    return `verify.url host ${observedHost} does not match run target ${declaredHost}`;
  }
  if (
    (declared.url.port || observed.port) &&
    effectivePort(declared.url) !== effectivePort(observed)
  ) {
    return `verify.url port ${effectivePort(observed)} does not match run target port ${effectivePort(declared.url)}`;
  }
  if (declared.explicitProtocol && declared.url.protocol !== observed.protocol) {
    return `verify.url protocol ${observed.protocol} does not match run target protocol ${declared.url.protocol}`;
  }
  return;
}

function controlUrlFor(targetVerifyUrl: string, controlTarget: string): URL | undefined {
  const control = parseNetworkTarget(controlTarget);
  if (!control) return;
  const target = new URL(targetVerifyUrl);
  const url = new URL(control.url.origin);
  url.pathname = target.pathname;
  url.search = target.search;
  return url;
}

// ── Predicate evaluation ──────────────────────────────────────────────

const REGEX_WORKER_SOURCE = `
  const { parentPort, workerData } = require("node:worker_threads");
  try {
    const matches = workerData.patterns.map((pattern) => new RegExp(pattern).test(workerData.body));
    parentPort.postMessage({ matches });
  } catch (error) {
    parentPort.postMessage({ error: error instanceof Error ? error.message : String(error) });
  }
`;

async function evaluateRegexes(
  patterns: string[],
  body: string,
): Promise<{ matches?: boolean[]; error?: string }> {
  if (patterns.length === 0) return { matches: [] };
  return new Promise((resolve) => {
    const worker = new Worker(REGEX_WORKER_SOURCE, {
      eval: true,
      workerData: { patterns, body },
    });
    let settled = false;
    const finish = (result: { matches?: boolean[]; error?: string }) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      void worker.terminate();
      resolve(result);
    };
    const timer = setTimeout(
      () => finish({ error: `evaluation exceeded ${REGEX_TIMEOUT_MS}ms` }),
      REGEX_TIMEOUT_MS,
    );
    worker.once("message", (message) => finish(message));
    worker.once("error", (error) =>
      finish({ error: error instanceof Error ? error.message : String(error) }),
    );
    worker.once("exit", (code) => {
      if (code !== 0) finish({ error: `worker exited with code ${code}` });
    });
  });
}

/** Apply an evidence expect spec to a harness-observed response. */
export async function evaluateExpect(
  expect: VerifyExpect,
  status: number,
  body: string,
): Promise<string[]> {
  const failures: string[] = [];
  if (expect.status && !expect.status.includes(status)) {
    failures.push(`status ${status} not in [${expect.status.join(", ")}]`);
  }
  for (const needle of expect.body_contains ?? []) {
    if (!body.includes(needle)) failures.push(`body_contains missing: ${needle}`);
  }
  const patterns = expect.body_regex ?? [];
  const regex = await evaluateRegexes(patterns, body);
  if (regex.error) {
    failures.push(`body_regex evaluation failed: ${regex.error}`);
  } else {
    for (const [index, re] of patterns.entries()) {
      if (regex.matches?.[index] !== true) failures.push(`body_regex failed: ${re}`);
    }
  }
  return failures;
}

/** Read a response body with a hard byte cap (bounded memory, honest note). */
async function readBodyCapped(
  res: Response,
): Promise<{ text: string; truncated: boolean; bytes: number; sha256: string }> {
  const reader = res.body?.getReader();
  if (!reader) {
    return {
      text: "",
      truncated: false,
      bytes: 0,
      sha256: createHash("sha256").update("").digest("hex"),
    };
  }
  const chunks: Uint8Array[] = [];
  let bytes = 0;
  let truncated = false;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    if (!value) continue;
    const remaining = MAX_BODY_BYTES - bytes;
    if (remaining > 0) {
      const kept = value.byteLength > remaining ? value.subarray(0, remaining) : value;
      chunks.push(kept);
      bytes += kept.byteLength;
    }
    if (value.byteLength > remaining || bytes >= MAX_BODY_BYTES) {
      truncated = true;
      await reader.cancel().catch(() => undefined);
      break;
    }
  }
  const body = Buffer.concat(chunks).subarray(0, MAX_BODY_BYTES);
  return {
    text: new TextDecoder().decode(body),
    truncated,
    bytes: body.byteLength,
    sha256: createHash("sha256").update(body).digest("hex"),
  };
}

// ── Replay ────────────────────────────────────────────────────────────

type FetchLike = (input: string | URL, init?: RequestInit) => Promise<Response>;
let harnessFetchForTest: FetchLike | undefined;

/** Test seam; production callers leave this undefined and use DNS-pinned undici. */
export function setHarnessFetchForTest(fetchImpl: FetchLike | undefined): void {
  harnessFetchForTest = fetchImpl;
}

type ReplayOptions = {
  timeoutMs?: number;
  allowPrivate?: boolean;
  /** Test-only injection; production always uses the DNS-pinned undici path. */
  fetchImpl?: FetchLike;
};

async function fetchPinned(
  url: URL,
  init: RequestInit,
  addresses: ResolvedAddress[],
): Promise<{ response: Response; close: () => Promise<void> }> {
  const first = addresses[0];
  const pinnedLookup = (
    _hostname: string,
    options: { all?: boolean },
    callback: (
      error: NodeJS.ErrnoException | null,
      address: string | ResolvedAddress[],
      family?: 4 | 6,
    ) => void,
  ) => {
    if (options?.all) callback(null, addresses);
    else callback(null, first.address, first.family);
  };
  const agent = new Agent({
    connect: { lookup: pinnedLookup as never },
  });
  try {
    const response = (await undiciFetch(url, {
      ...(init as object),
      dispatcher: agent,
    } as never)) as unknown as Response;
    return { response, close: () => agent.close() };
  } catch (error) {
    await agent.close().catch(() => undefined);
    throw error;
  }
}

async function replayRequest(
  verify: PoCEvidence["verify"],
  expect: VerifyExpect,
  canaryToken?: string,
  opts?: ReplayOptions,
): Promise<HarnessResponseObservation> {
  let url: URL;
  try {
    url = new URL(verify.url);
  } catch {
    return {
      attempted: false,
      url: verify.url,
      note: `verify.url unparseable (${verify.url})`,
    };
  }
  const observedUrl = () =>
    canaryToken ? url.toString().replaceAll(canaryToken, POC_CANARY_PLACEHOLDER) : url.toString();
  if (!(url.protocol === "http:" || url.protocol === "https:")) {
    return { attempted: false, url: verify.url, note: `verify.url protocol ${url.protocol}` };
  }

  let method = verify.method.toUpperCase();
  let body = method === "GET" || method === "HEAD" ? undefined : verify.body;
  let headers: Headers;
  try {
    headers = new Headers(verify.headers);
  } catch (error) {
    return {
      attempted: false,
      url: observedUrl(),
      note: `verify.headers invalid: ${(error as Error).message}`,
    };
  }
  const signal = AbortSignal.timeout(opts?.timeoutMs ?? TIMEOUT_MS);
  const lockedHostname = url.hostname.toLowerCase().replace(/\.$/, "");
  const fetchImpl = opts?.fetchImpl ?? harnessFetchForTest;

  for (let redirects = 0; redirects <= MAX_REDIRECTS; redirects++) {
    const localName =
      url.hostname.toLowerCase() === "localhost" ||
      url.hostname.toLowerCase().endsWith(".localhost");
    if (!opts?.allowPrivate && localName) {
      return {
        attempted: false,
        url: observedUrl(),
        note: `${url.hostname} is a private/internal host; operator authorization is required for harness replay`,
      };
    }
    let addresses: ResolvedAddress[] = [];
    if (!fetchImpl) {
      try {
        addresses = await resolveHost(url.hostname);
      } catch (error) {
        return {
          attempted: true,
          url: observedUrl(),
          note: `request errored (DNS): ${(error as Error).message}`,
        };
      }
      if (addresses.length === 0) {
        return {
          attempted: true,
          url: observedUrl(),
          note: `request errored (DNS): ${url.hostname} resolved to no addresses`,
        };
      }
    } else if (isIP(url.hostname.replace(/^\[|\]$/g, ""))) {
      addresses = [
        {
          address: url.hostname.replace(/^\[|\]$/g, ""),
          family: isIP(url.hostname.replace(/^\[|\]$/g, "")) as 4 | 6,
        },
      ];
    }
    if (!opts?.allowPrivate && addresses.some((address) => !isPublicIpAddress(address.address))) {
      return {
        attempted: false,
        url: observedUrl(),
        note: `${url.hostname} is a private/internal host; operator authorization is required for harness replay`,
      };
    }

    let closeFetched: (() => Promise<void>) | undefined;
    try {
      const requestInit: RequestInit = {
        method,
        headers,
        body,
        redirect: "manual",
        signal,
      };
      const fetched = fetchImpl
        ? { response: await fetchImpl(url, requestInit), close: async () => undefined }
        : await fetchPinned(url, requestInit, addresses);
      closeFetched = fetched.close;
      const res = fetched.response;
      const location = res.headers.get("location");
      if (location && [301, 302, 303, 307, 308].includes(res.status)) {
        if (redirects === MAX_REDIRECTS) {
          await res.body?.cancel().catch(() => undefined);
          await fetched.close().catch(() => undefined);
          closeFetched = undefined;
          return {
            attempted: true,
            status: res.status,
            url: observedUrl(),
            note: `redirect limit exceeded (${MAX_REDIRECTS})`,
          };
        }
        const next = new URL(location, url);
        if (!(next.protocol === "http:" || next.protocol === "https:")) {
          await res.body?.cancel().catch(() => undefined);
          await fetched.close().catch(() => undefined);
          closeFetched = undefined;
          return {
            attempted: true,
            status: res.status,
            url: observedUrl(),
            note: `redirected to disallowed protocol ${next.protocol}`,
          };
        }
        if (next.hostname.toLowerCase().replace(/\.$/, "") !== lockedHostname) {
          await res.body?.cancel().catch(() => undefined);
          await fetched.close().catch(() => undefined);
          closeFetched = undefined;
          return {
            attempted: true,
            status: res.status,
            url: observedUrl(),
            note: `redirect left the bound host (${url.hostname} -> ${next.hostname})`,
          };
        }
        if (next.origin !== url.origin) {
          for (const name of ["authorization", "cookie", "proxy-authorization"]) {
            headers.delete(name);
          }
        }
        if (
          res.status === 303 ||
          ((res.status === 301 || res.status === 302) && method === "POST")
        ) {
          method = "GET";
          body = undefined;
          headers.delete("content-length");
          headers.delete("content-type");
        }
        await res.body?.cancel().catch(() => undefined);
        await fetched.close().catch(() => undefined);
        closeFetched = undefined;
        url = next;
        continue;
      }

      const observed = await readBodyCapped(res);
      await fetched.close().catch(() => undefined);
      closeFetched = undefined;
      if (observed.truncated) {
        return {
          attempted: true,
          status: res.status,
          url: observedUrl(),
          bodySha256: observed.sha256,
          bodyBytes: observed.bytes,
          note: "response body exceeded the 2 MiB capture limit; matcher result is inconclusive",
        };
      }
      const failures = await evaluateExpect(expect, res.status, observed.text);
      const canaryObserved = canaryToken ? observed.text.includes(canaryToken) : undefined;
      return {
        attempted: true,
        matched: failures.length === 0,
        status: res.status,
        url: observedUrl(),
        bodySha256: observed.sha256,
        bodyBytes: observed.bytes,
        canaryObserved,
        note:
          failures.length === 0
            ? `status ${res.status}, all predicates matched`
            : failures.join("; "),
      };
    } catch (e) {
      await closeFetched?.().catch(() => undefined);
      return {
        attempted: true,
        url: observedUrl(),
        note: `request errored (DNS/TLS/timeout): ${(e as Error).message}`,
      };
    }
  }

  return { attempted: true, url: observedUrl(), note: "unreachable redirect state" };
}

/**
 * Two requests are "the same" when method, URL, header set, and body all match.
 * An intra-target differential whose attack and baseline are identical proves
 * nothing — the discriminating variable must actually differ.
 */
export function sameRequest(
  a: { method: string; url: string; headers?: Record<string, string>; body?: string },
  b: { method: string; url: string; headers?: Record<string, string>; body?: string },
): boolean {
  const norm = (h?: Record<string, string>) =>
    JSON.stringify(
      Object.entries(h ?? {})
        .map(([k, v]) => [k.toLowerCase(), v] as const)
        .sort(([x], [y]) => (x < y ? -1 : x > y ? 1 : 0)),
    );
  return (
    a.method.toUpperCase() === b.method.toUpperCase() &&
    a.url === b.url &&
    (a.body ?? "") === (b.body ?? "") &&
    norm(a.headers) === norm(b.headers)
  );
}

function injectCanary(
  verify: PoCEvidence["verify"],
  token: string | undefined,
): PoCEvidence["verify"] {
  if (!token) return verify;
  const replace = (value: string) => value.replace(POC_CANARY_PLACEHOLDER, token);
  return {
    ...verify,
    url: replace(verify.url),
    body: verify.body === undefined ? undefined : replace(verify.body),
    headers:
      verify.headers === undefined
        ? undefined
        : Object.fromEntries(
            Object.entries(verify.headers).map(([key, value]) => [key, replace(value)]),
          ),
  };
}

function canaryResult(
  token: string | undefined,
  target: HarnessResponseObservation,
  control?: HarnessResponseObservation,
): HarnessCanaryResult | undefined {
  if (!token) return;
  const attempted =
    target.canaryObserved !== undefined && (control ? control.canaryObserved !== undefined : true);
  const pass = control
    ? attempted && target.canaryObserved === true && control.canaryObserved === false
    : attempted && target.canaryObserved === true;
  return {
    mode: "reflection",
    attempted,
    pass,
    tokenSha256: createHash("sha256").update(token).digest("hex"),
    targetObserved: target.canaryObserved,
    controlObserved: control?.canaryObserved,
    note: control
      ? `canary ${pass ? "target-only" : "failed"}: target=${String(target.canaryObserved)}, control=${String(control.canaryObserved)}`
      : `canary ${pass ? "observed" : "not observed"} on target`,
  };
}

/**
 * Re-send the evidence's verify request with the harness's own client and
 * judge the response against verify.expect. Never throws — the outcome is a
 * structured result the ledger gate interprets.
 */
export async function replayVerify(
  evidence: PoCEvidence,
  opts?: ReplayOptions,
): Promise<HarnessVerifyResult> {
  const token = evidence.verify.canary
    ? `poc_canary_${randomBytes(24).toString("hex")}`
    : undefined;
  const verify = injectCanary(evidence.verify, token);
  const target = await replayRequest(verify, verify.expect, token, opts);
  const canary = canaryResult(token, target);
  return {
    attempted: target.attempted,
    pass: target.matched === true,
    status: target.status,
    target,
    canary,
    proofStrength: canary?.pass ? "canary_differential" : "predicate_differential",
    note: `harness replay: ${target.note}${canary ? `; ${canary.note}` : ""}`,
  };
}

/**
 * Combine the two observations into the differential verdict. Shared by the
 * inter-host (target vs control host) and intra-target (attack vs same-host
 * baseline) replays — only the note labels differ.
 */
function judgeDifferential(
  target: HarnessResponseObservation,
  control: HarnessResponseObservation,
  token: string | undefined,
  label: { kind: string; a: string; b: string },
): HarnessVerifyResult {
  const attempted = target.attempted && control.attempted;
  const conclusive = target.matched !== undefined && control.matched !== undefined;
  const differential = conclusive
    ? target.matched === true
      ? control.matched === true
        ? "both"
        : "target_only"
      : control.matched === true
        ? "control_only"
        : "neither"
    : undefined;
  const canary = canaryResult(token, target, control);
  const pass =
    attempted &&
    conclusive &&
    differential === "target_only" &&
    (canary === undefined || canary.pass === true);
  return {
    attempted,
    pass,
    status: target.status,
    target,
    control,
    differential,
    canary,
    proofStrength: canary?.pass ? "canary_differential" : "predicate_differential",
    note:
      `harness ${label.kind} ${differential ?? "inconclusive"}: ${label.a} (${target.note}); ` +
      `${label.b} (${control.note})${canary ? `; ${canary.note}` : ""}`,
  };
}

/**
 * Execute one harness-owned request template against both the case target and
 * a distinct control origin. The PoC cannot weaken the control request: the
 * harness preserves method, path, query, headers, body, and target predicates,
 * changing only the origin to the declared control target.
 */
export async function replayDifferential(
  evidence: PoCEvidence,
  caseTarget: string,
  controlTarget: string,
  opts?: ReplayOptions,
): Promise<HarnessVerifyResult> {
  const bindingError = verifyUrlBindingError(evidence.verify.url, caseTarget);
  if (bindingError) {
    return { attempted: false, pass: false, note: `target binding failed: ${bindingError}` };
  }
  if (sameTargetIdentity(caseTarget, controlTarget)) {
    return {
      attempted: false,
      pass: false,
      note: "control target resolves to the same network identity as the case target",
    };
  }
  const controlUrl = controlUrlFor(evidence.verify.url, controlTarget);
  if (!controlUrl) {
    return {
      attempted: false,
      pass: false,
      note: `control target is not an HTTP network target: ${controlTarget}`,
    };
  }

  const token = evidence.verify.canary
    ? `poc_canary_${randomBytes(24).toString("hex")}`
    : undefined;
  const targetVerify = injectCanary(evidence.verify, token);
  const target = await replayRequest(targetVerify, targetVerify.expect, token, opts);
  const control = await replayRequest(
    {
      ...targetVerify,
      url: injectCanary({ ...evidence.verify, url: controlUrl.toString() }, token).url,
    },
    targetVerify.expect,
    token,
    opts,
  );
  return judgeDifferential(target, control, token, {
    kind: "differential",
    a: "target",
    b: "control",
  });
}

/**
 * Same-host differential (Tier 2, intra-target). For access-control and
 * business-logic classes the discriminating variable is the attacker's
 * identity or a request parameter, NOT the host — so the sound baseline is a
 * legitimate request to the SAME target, not the same request to another host.
 * The harness sends the attack request and the model-declared `evidence.baseline`
 * request to the case target, applies the attack's `verify.expect` predicates to
 * BOTH responses, and passes only when the proof appears on the attack response
 * and is absent from the baseline (`target_only`, where "target" = attack and
 * "control" = baseline). The baseline is bound to the case target so it cannot
 * be redirected to a weaker origin, and it must differ from the attack request.
 */
export async function replayIntraTarget(
  evidence: PoCEvidence,
  caseTarget: string,
  opts?: ReplayOptions,
): Promise<HarnessVerifyResult> {
  const baseline = evidence.baseline;
  if (!baseline) {
    return {
      attempted: false,
      pass: false,
      note: "intra-target differential requires evidence.baseline (a legitimate same-host request)",
    };
  }
  const attackBinding = verifyUrlBindingError(evidence.verify.url, caseTarget);
  if (attackBinding) {
    return { attempted: false, pass: false, note: `attack binding failed: ${attackBinding}` };
  }
  const baselineBinding = verifyUrlBindingError(baseline.url, caseTarget);
  if (baselineBinding) {
    return { attempted: false, pass: false, note: `baseline binding failed: ${baselineBinding}` };
  }
  if (sameRequest(evidence.verify, baseline)) {
    return {
      attempted: false,
      pass: false,
      note: "attack and baseline requests are identical — an intra-target differential must vary identity or a parameter",
    };
  }

  const token = evidence.verify.canary
    ? `poc_canary_${randomBytes(24).toString("hex")}`
    : undefined;
  const attackVerify = injectCanary(evidence.verify, token);
  const attack = await replayRequest(attackVerify, attackVerify.expect, token, opts);
  // The baseline carries the attack's predicates: the proof must be ABSENT here.
  const baselineVerify = injectCanary(
    {
      ...evidence.verify,
      method: baseline.method,
      url: baseline.url,
      headers: baseline.headers,
      body: baseline.body,
    },
    token,
  );
  const base = await replayRequest(baselineVerify, attackVerify.expect, token, opts);

  return judgeDifferential(attack, base, token, {
    kind: "intra-target",
    a: "attack",
    b: "baseline",
  });
}
