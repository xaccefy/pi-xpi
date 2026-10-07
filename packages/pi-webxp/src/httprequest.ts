/**
 * Stateful raw HTTP request tool for offensive security testing.
 *
 * SSRF guard: private/internal hosts are blocked by default. The guard checks
 * IP literals and every redirect hop. Node pins policy in socket lookup; Bun
 * pins plain HTTP to the approved address and pre-flights HTTPS DNS.
 */

import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { Text } from "@earendil-works/pi-tui";
import { CookieJar } from "tough-cookie";
import { Type } from "typebox";
import {
  assertPrivateHostsAllowed,
  assertPublicDns,
  assertPublicHttpUrl,
  createSafeDispatcher,
  pinPublicHostForPlainHttp,
} from "./network-safety.ts";

const DEFAULT_TIMEOUT_MS = 30000;
// Response capture caps shared with rawhttp.ts (same package, same concept:
// max bytes held in memory per response).
export const DEFAULT_MAX_BODY = 262_144;
export const MAX_BODY_HARD = 2_000_000;
const MAX_REDIRECTS = 10;

const METHOD_LIST = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];
const REDIRECT_LIST = ["follow", "manual"];

// Bun's fetch ignores undici's `dispatcher` (verified: 0 lookup calls) but
// honors the non-standard `tls` init option; Node's fetch (undici-based)
// honors the dispatcher but ignores the `tls` key. Both must be set for
// verifyTls:false to work on both runtimes.
const isBun = typeof (globalThis as { Bun?: unknown }).Bun !== "undefined";

const HttpMethod = Type.String({ enum: METHOD_LIST });
const RedirectMode = Type.String({ enum: REDIRECT_LIST });

function findHeaderKey(headers: Record<string, string>, name: string): string | undefined {
  const lower = name.toLowerCase();
  return Object.keys(headers).find((k) => k.toLowerCase() === lower);
}

function hasHeader(headers: Record<string, string>, name: string): boolean {
  return findHeaderKey(headers, name) !== undefined;
}

function deleteHeader(headers: Record<string, string>, name: string): void {
  const key = findHeaderKey(headers, name);
  if (key) delete headers[key];
}

function setHeader(headers: Record<string, string>, name: string, value: string): void {
  const key = findHeaderKey(headers, name);
  headers[key ?? name] = value;
}

function responseSetCookies(res: Response): string[] {
  const raw = (res.headers as unknown as { getSetCookie?: () => string[] }).getSetCookie?.();
  if (raw?.length) return raw;
  const single = res.headers.get("set-cookie");
  return single ? [single] : [];
}

function storeCookies(jar: CookieJar, url: string, res: Response): string[] {
  const cookies = responseSetCookies(res);
  for (const cookie of cookies) jar.setCookieSync(cookie, url, { ignoreError: true });
  return cookies;
}

function withCookies(
  jar: CookieJar,
  url: URL,
  headers: Record<string, string>,
  explicitCookie: string | undefined,
): Record<string, string> {
  const out = { ...headers };
  deleteHeader(out, "cookie");
  const cookie = explicitCookie ?? jar.getCookieStringSync(url.toString());
  if (cookie) setHeader(out, "Cookie", cookie);
  return out;
}

async function readBody(
  res: Response,
  maxBytes: number,
): Promise<{ text: string; truncated: boolean }> {
  const reader = res.body?.getReader();
  if (!reader) {
    const text = await res.text();
    if (text.length <= maxBytes) return { text, truncated: false };
    const buf = Buffer.from(text);
    let out = buf.subarray(0, maxBytes).toString("utf8");
    if (out.endsWith("\uFFFD")) out = out.slice(0, -1);
    return { text: out, truncated: true };
  }

  const chunks: Uint8Array[] = [];
  let received = 0;
  let truncated = false;

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    if (received + value.byteLength > maxBytes) {
      chunks.push(value.subarray(0, maxBytes - received));
      received = maxBytes;
      truncated = true;
      break;
    }
    chunks.push(value);
    received += value.byteLength;
  }

  try {
    await reader.cancel();
  } catch {}
  let text = Buffer.concat(chunks.map((c) => Buffer.from(c))).toString("utf8");
  if (truncated && text.endsWith("\uFFFD")) text = text.slice(0, -1);
  return { text, truncated };
}

function redirectTarget(current: URL, location: string | null): URL | undefined {
  if (!location) return;
  return new URL(location, current);
}

function redirectMethod(status: number, method: string): string {
  if (status === 303) return method === "HEAD" ? "HEAD" : "GET";
  if ((status === 301 || status === 302) && method === "POST") return "GET";
  return method;
}

function origin(url: URL): string {
  return `${url.protocol}//${url.host}`;
}


const DEFAULT_SESSION = "default";
const MAX_SESSION_NAME_CHARS = 64;
const MAX_SESSIONS = 32;
const SESSION_NAME_RE = /^[A-Za-z0-9._-]+$/;

/**
 * Validate and normalize a session name. Named jars let the agent hold
 * several authenticated identities at once (attacker vs victim for IDOR /
 * privilege-escalation differentials) without one login destroying the
 * other's state.
 */
function normalizeSessionName(name: unknown): string {
  if (name === undefined || name === null || name === "") return DEFAULT_SESSION;
  if (typeof name !== "string") throw new Error("session must be a string");
  const trimmed = name.trim();
  if (!trimmed) return DEFAULT_SESSION;
  if (trimmed.length > MAX_SESSION_NAME_CHARS) {
    throw new Error(`session name too long (max ${MAX_SESSION_NAME_CHARS} characters)`);
  }
  if (!SESSION_NAME_RE.test(trimmed)) {
    throw new Error(
      `invalid session name "${trimmed}": use letters, digits, dot, underscore, or dash`,
    );
  }
  return trimmed;
}

export default function httpRequestExtension(pi: ExtensionAPI) {
  // One jar per named identity. The default jar keeps the historical single-
  // session behavior exactly: process-lifetime, cleared on session_shutdown.
  const jars = new Map<string, CookieJar>();

  function jarFor(name: string): CookieJar {
    let jar = jars.get(name);
    if (!jar) {
      if (jars.size >= MAX_SESSIONS) {
        throw new Error(`too many named sessions (max ${MAX_SESSIONS})`);
      }
      jar = new CookieJar();
      jars.set(name, jar);
    }
    return jar;
  }

  pi.registerTool({
    name: "http_request",
    label: "HTTP Request",
    description:
      "Send a raw HTTP request with a persistent cookie jar, custom headers, and body control. Use for authenticated web-app testing (login → probe), API vulnerability probing, and verifying HTTP behavior. Unlike web_fetch (stateless, read-only), http_request persists cookies across calls within a session, supports all methods, and surfaces raw responses. Runtime note: on Bun + HTTPS, DNS is validated pre-flight only — a rebinding resolver could still reach a private address at connect time (Node pins at connect time; see network-safety.ts).",
    promptSnippet: "Send HTTP requests with cookies, headers, and body control",
    promptGuidelines: [
      "Use http_request for authenticated web-app testing: POST to login, then GET protected resources — the cookie jar persists across calls automatically.",
      "Default redirect mode is 'manual' — you'll see 302/301 as-is (critical for redirect-chain analysis). Use 'follow' to auto-follow redirects.",
      "Pass json for JSON bodies (Content-Type set automatically); pass body for raw/form payloads.",
      "Private/internal hosts (127.0.0.1, 10.x, 192.168.x, fc00::/7) are blocked by default. allowPrivateHosts=true additionally requires the operator's PI_WEBXP_ALLOW_PRIVATE_HOSTS=1 — internal-lab access is operator-gated, not agent-selectable.",
      "Use verifyTls=false for self-signed cert targets (e.g., internal staging apps). TLS verification is enabled by default.",
      "Set-Cookie is stored with RFC cookie scope. Explicit Cookie applies only to the first request; redirects use jar cookies for the new URL.",
      "Use session:'attacker' and session:'victim' to hold two authenticated identities at once — replay a victim object URL under the attacker session to prove IDOR/access-control bugs without losing either login.",
      "Pass an Authorization header (e.g. headers: { Authorization: 'Basic <base64>' }) for Basic auth — the http_request tool does not store credentials itself, keeping auth explicit and visible in the transcript.",
      "Prefer http_request over web_fetch when you need custom methods, auth headers, cookie-dependent auth flows, or raw response headers. Use web_fetch for read-only page content when you don't need session state.",
    ],
    parameters: Type.Object(
      {
        url: Type.String({ description: "Target URL (http:// or https://)" }),
        session: Type.Optional(
          Type.String({
            description:
              "Named cookie-jar session, e.g. 'attacker' or 'victim'. Jars persist independently per name within this agent session; omit for the default jar.",
          }),
        ),
        method: Type.Optional(HttpMethod),
        headers: Type.Optional(
          Type.Record(Type.String(), Type.String(), {
            description:
              "Request headers. An explicit Cookie header overrides the jar for the first request.",
          }),
        ),
        body: Type.Optional(
          Type.String({
            description:
              "Raw request body string (for POST/PUT/PATCH). Use json for structured payloads.",
          }),
        ),
        json: Type.Optional(
          Type.Any({
            description:
              "JSON body (stringified automatically; sets Content-Type: application/json). Overrides body.",
          }),
        ),
        contentType: Type.Optional(
          Type.String({ description: "Shorthand Content-Type (e.g. application/json, text/xml)" }),
        ),
        redirect: Type.Optional(RedirectMode),
        timeoutMs: Type.Optional(
          Type.Integer({
            minimum: 500,
            maximum: 120000,
            description: "Request timeout in ms (default 30000)",
          }),
        ),
        verifyTls: Type.Optional(
          Type.Boolean({
            description:
              "Verify TLS certificate (default true). Set false for self-signed or internal certs.",
          }),
        ),
        allowPrivateHosts: Type.Optional(
          Type.Boolean({
            description:
              "Request private/internal hostname access (default false, SSRF-safe). Takes effect only when the operator set PI_WEBXP_ALLOW_PRIVATE_HOSTS=1; otherwise the call fails closed.",
          }),
        ),
        maxBody: Type.Optional(
          Type.Integer({
            minimum: 1024,
            maximum: MAX_BODY_HARD,
            description: `Max response body bytes to capture (default ${DEFAULT_MAX_BODY})`,
          }),
        ),
      },
      { additionalProperties: false },
    ),

    async execute(_id, params, signal, _onUpdate, _ctx) {
      const parsed = new URL(params.url as string);
      const sessionName = normalizeSessionName(params.session);
      const jar = jarFor(sessionName);
      const allowPrivateHosts = params.allowPrivateHosts === true;
      const verifyTls = params.verifyTls !== false;
      assertPrivateHostsAllowed(allowPrivateHosts);
      assertPublicHttpUrl(parsed, allowPrivateHosts);
      // Bun's fetch ignores the undici dispatcher, so the DNS guard must run
      // pre-flight to stay effective there (fail closed on private answers).
      await assertPublicDns(parsed.hostname, allowPrivateHosts);

      let method = ((params.method as string | undefined) || "GET").toUpperCase();
      const redirectMode = ((params.redirect as string | undefined) || "manual") as
        | "manual"
        | "follow";
      const timeoutMs = params.timeoutMs ?? DEFAULT_TIMEOUT_MS;
      const maxBody = Math.min(params.maxBody ?? DEFAULT_MAX_BODY, MAX_BODY_HARD);

      const baseHeaders: Record<string, string> = {
        ...((params.headers as Record<string, string> | undefined) ?? {}),
      };
      const explicitCookieKey = findHeaderKey(baseHeaders, "cookie");
      const explicitCookie = explicitCookieKey ? baseHeaders[explicitCookieKey] : undefined;
      deleteHeader(baseHeaders, "cookie");

      if (params.contentType && !hasHeader(baseHeaders, "content-type"))
        setHeader(baseHeaders, "Content-Type", params.contentType);

      let body: string | undefined;
      let droppedBodyNote: string | undefined;
      if (params.json !== undefined) {
        if (method === "GET" || method === "HEAD") {
          droppedBodyNote = `json ignored: ${method} requests cannot carry a body (JSON payload dropped)`;
        } else {
          body = JSON.stringify(params.json);
          if (!hasHeader(baseHeaders, "content-type"))
            setHeader(baseHeaders, "Content-Type", "application/json");
        }
      } else if (params.body !== undefined && method !== "GET" && method !== "HEAD") {
        body = params.body as string;
      } else if (params.body !== undefined) {
        droppedBodyNote = `body ignored: ${method} requests cannot carry one`;
      }
      if (droppedBodyNote) baseHeaders["X-PI-Note"] = droppedBodyNote;

      const dispatcher = createSafeDispatcher({ allowPrivateHosts, verifyTls });
      try {
        const started = Date.now();
        let current = parsed;
        const headers = baseHeaders;
        let currentBody = body;
        const redirectChain: string[] = [];
        let res: Response;
        let requestHeaders: Record<string, string> = {};
        let cookiesInResponse: string[] = [];

        for (let hop = 0; ; hop++) {
          assertPublicHttpUrl(current, allowPrivateHosts);
          await assertPublicDns(current.hostname, allowPrivateHosts);
          const cookie = hop === 0 ? explicitCookie : undefined;
          requestHeaders = withCookies(jar, current, headers, cookie);
          // Bun + plain HTTP: pin the connection to the validated IP (the
          // dispatcher's connect-time lookup never runs under Bun). Cookies
          // and result URLs keep the ORIGINAL host — only the dial target
          // changes, with the original host carried in the Host header.
          let connectTarget = current;
          if (isBun) {
            const pinned = await pinPublicHostForPlainHttp(current);
            if (pinned) {
              if (!hasHeader(requestHeaders, "host")) {
                setHeader(requestHeaders, "Host", current.host);
              }
              connectTarget = pinned;
            }
          }
          const init: RequestInit & { dispatcher?: unknown } = {
            method,
            headers: requestHeaders,
            body: currentBody,
            redirect: "manual",
            signal: AbortSignal.any([...(signal ? [signal] : []), AbortSignal.timeout(timeoutMs)]),
            dispatcher,
          };
          if (method === "GET" || method === "HEAD") delete init.body;
          // TLS bypass on Bun: the dispatcher (with rejectUnauthorized:false for
          // Node) is ignored there, so the `tls` init option is the only path.
          if (!verifyTls && isBun) {
            // nosemgrep: problem-based-packs.insecure-transport.js-node.bypass-tls-verification.bypass-tls-verification -- explicit verifyTls=false tool option for self-signed/internal test targets; default is verifyTls=true.
            (init as RequestInit & { tls?: unknown }).tls = { rejectUnauthorized: false };
          }

          res = await fetch(connectTarget, init as never);
          cookiesInResponse = storeCookies(jar, current.toString(), res);

          const next =
            redirectMode === "follow"
              ? redirectTarget(current, res.headers.get("location"))
              : undefined;
          if (!next || res.status < 300 || res.status > 399) break;
          if (hop >= MAX_REDIRECTS) throw new Error(`Redirect limit exceeded (${MAX_REDIRECTS})`);
          assertPublicHttpUrl(next, allowPrivateHosts);
          redirectChain.push(`${res.status} ${current.toString()} -> ${next.toString()}`);
          try {
            await res.body?.cancel();
          } catch {}

          const oldMethod = method;
          method = redirectMethod(res.status, method);
          if (method !== oldMethod) {
            currentBody = undefined;
            deleteHeader(headers, "content-type");
            deleteHeader(headers, "content-length");
          }
          if (origin(current) !== origin(next)) {
            deleteHeader(headers, "authorization");
            deleteHeader(headers, "proxy-authorization");
          }
          current = next;
        }

        const timingMs = Date.now() - started;
        const { text: responseBody, truncated } = await readBody(res, maxBody);

        const responseHeaders: Record<string, string> = {};
        for (const [k, v] of res.headers.entries()) {
          if (k !== "set-cookie") responseHeaders[k] = v;
        }

        const pathAndQuery = current.pathname + (current.search || "");
        let text = `> ${method} ${pathAndQuery} HTTP/1.1\n`;
        text += `> Host: ${current.hostname}\n`;
        for (const [k, v] of Object.entries(requestHeaders)) text += `> ${k}: ${v}\n`;
        if (currentBody && method !== "GET" && method !== "HEAD") {
          text += `> ${currentBody.length > 200 ? `${currentBody.slice(0, 200)}...` : currentBody}\n`;
        }
        text += `\n< HTTP/1.1 ${res.status} ${res.statusText || ""}\n`;
        for (const [k, v] of Object.entries(responseHeaders)) text += `< ${k}: ${v}\n`;
        for (const c of cookiesInResponse) text += `< Set-Cookie: ${c}\n`;
        text += `\n${responseBody}`;
        if (truncated) text += `\n\n[body truncated at ${maxBody} bytes]`;

        const cookiesOnHost = jar.getCookieStringSync(current.toString());
        return {
          content: [{ type: "text" as const, text }],
          details: {
            status: res.status,
            statusText: res.statusText,
            method,
            url: parsed.toString(),
            finalUrl: current.toString(),
            redirected: redirectChain.length > 0,
            redirectChain,
            requestHeaders,
            responseHeaders,
            responseHeadersRaw: Object.fromEntries(res.headers.entries()),
            body: responseBody,
            bodyTruncated: truncated,
            bodySize: responseBody.length,
            timingMs,
            cookiesOnHost,
            cookiesInResponse,
            session: sessionName,
          },
        };
      } catch (err) {
        throw new Error(`HTTP request failed: ${(err as Error).message}`, { cause: err });
      } finally {
        const close = (dispatcher as unknown as { close?: () => Promise<void> }).close;
        if (close) await close.call(dispatcher).catch(() => {});
      }
    },

    renderCall(args, theme) {
      const method = (args.method as string) || "GET";
      const url = (args.url as string) || "";
      return new Text(
        theme.fg("toolTitle", theme.bold("HTTP req ")) +
          theme.fg("dim", method) +
          " " +
          theme.fg("dim", url),
        0,
        0,
      );
    },

    renderResult(result, { expanded }: { expanded: boolean }, theme, context) {
      if (context.isError) return new Text(theme.fg("error", "✗ HTTP failed"), 0, 0);
      const details = result.details as {
        status?: number;
        method?: string;
        finalUrl?: string;
        url?: string;
        timingMs?: number;
        bodyTruncated?: boolean;
      };
      const status = details?.status ?? 0;
      const method = details?.method || "GET";
      const url = details?.finalUrl || details?.url || "";
      const timing = details?.timingMs ?? 0;
      const statusColor =
        status >= 200 && status < 300 ? "success" : status >= 400 ? "error" : "warning";
      let baseText =
        theme.fg(statusColor, String(status)) + theme.fg("dim", ` ${method} ${url} (${timing}ms)`);
      if (details?.bodyTruncated) baseText += theme.fg("muted", " (truncated)");
      if (expanded)
        return new Text(
          `${baseText}\n${(result.content[0] as { text?: string })?.text || ""}`,
          0,
          0,
        );
      return new Text(baseText, 0, 0);
    },
  });

  pi.on("session_shutdown", () => {
    for (const jar of jars.values()) jar.removeAllCookiesSync();
    jars.clear();
  });
}
