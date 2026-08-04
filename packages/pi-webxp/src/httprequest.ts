/**
 * pi-http — stateful HTTP request tool for offensive security testing.
 *
 * Tool: http_request
 *
 * Unlike web_fetch (stateless read-only, daemon-mediated, markdown-ized),
 * http_request maintains a per-session cookie jar, supports all HTTP methods,
 * custom headers, raw and JSON bodies, manual redirect observability, and
 * optional TLS bypass for self-signed targets — the primitives needed for
 * authenticated web-app testing (login flows, API probing, vuln verification).
 *
 * SSRF: private/internal hosts are blocked by default (allowPrivateHosts
 * opts in). DNS rebinding is unmitigated — see web-pentest skill §8.
 */

import { createRequire } from "node:module";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { Text } from "@earendil-works/pi-tui";
import { Type } from "@sinclair/typebox";
import { isPublicHttpHost } from "./websearch.ts";

const _require = createRequire(import.meta.url);

// ── Constants ────────────────────────────────────────────

const DEFAULT_TIMEOUT_MS = 30000;
const DEFAULT_MAX_BODY = 262144; // 256 KiB
const MAX_BODY_HARD = 2_000_000; // hard cap — read never exceeds this

// Provider-safe string enums — do NOT use Type.Union(Type.Literal…):
// providers drop anyOf/const fields for optional enum params, so status-only
// or method-only updates arrive empty and silently no-op. Use Type.String
// with an explicit enum array.
const METHOD_LIST = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];
const REDIRECT_LIST = ["follow", "manual"];

// ── Session / cookie jar ─────────────────────────────────

// Module-level cookie jar (hostname → "k1=v1; k2=v2") persists across
// http_request calls within a Pi session (extension is loaded once per
// session). Cleared on session_shutdown.
const cookieJar = new Map<string, string>();

// ── Cookie helpers ───────────────────────────────────────

// Header names are case-insensitive; callers may pass "Cookie" while we
// write "cookie". Find the caller's actual key so we merge into it instead
// of creating a duplicate case-variant header.
function findHeaderKey(headers: Record<string, string>, name: string): string | undefined {
  const lower = name.toLowerCase();
  return Object.keys(headers).find((k) => k.toLowerCase() === lower);
}

function hasHeader(headers: Record<string, string>, name: string): boolean {
  return findHeaderKey(headers, name) !== undefined;
}

function injectCookieHeader(
  hostname: string,
  existing: Record<string, string>,
): Record<string, string> {
  const sessionCookies = cookieJar.get(hostname);

  if (!sessionCookies) return { ...existing };
  const cookieKey = findHeaderKey(existing, "cookie");
  if (!cookieKey) return { ...existing, cookie: sessionCookies };

  // Merge: caller wins for duplicate keys; jar fills the rest.
  const merged = new Map<string, string>();
  for (const pair of existing[cookieKey].split(";")) {
    const eq = pair.indexOf("=");
    if (eq > 0) merged.set(pair.slice(0, eq).trim(), pair.slice(eq + 1).trim());
  }
  for (const pair of sessionCookies.split(";")) {
    const eq = pair.indexOf("=");
    if (eq > 0) merged.set(pair.slice(0, eq).trim(), pair.slice(eq + 1).trim());
  }
  return { ...existing, [cookieKey]: [...merged].map(([k, v]) => `${k}=${v}`).join("; ") };
}

function storeResponseCookies(hostname: string, res: Response): void {
  const raw = (res.headers as any).getSetCookie?.() as string[] | undefined;
  if (!raw) return;
  // Parse the existing jar into a name→value map so a rotated Set-Cookie
  // (same name, new value) replaces rather than appends — servers expect
  // the latest value to win, and duplicate Cookie pairs are ambiguous.
  const current = new Map<string, string>();
  for (const pair of (cookieJar.get(hostname) || "").split(";")) {
    const eq = pair.indexOf("=");
    if (eq > 0) current.set(pair.slice(0, eq).trim(), pair.slice(eq + 1).trim());
  }
  for (const cookie of raw) {
    const segment = cookie.split(";")[0].trim();
    const eq = segment.indexOf("=");
    if (eq <= 0) continue;
    current.set(segment.slice(0, eq).trim(), segment.slice(eq + 1).trim());
  }
  cookieJar.set(hostname, [...current].map(([k, v]) => `${k}=${v}`).join("; "));
}

// ── TLS bypass ────────────────────────────────

// Bun: native fetch honors the non-standard `tls` option directly.
// Node: global fetch is undici's, so pass an undici Agent with
// rejectUnauthorized:false as the `dispatcher` option.
const isBun = typeof (globalThis as { Bun?: unknown }).Bun !== "undefined";

let cachedDispatcher: unknown = null;

function getInsecureDispatcher(): unknown {
  if (cachedDispatcher !== null) return cachedDispatcher;
  try {
    const { Agent } = _require("undici");
    cachedDispatcher = new Agent({ connect: { rejectUnauthorized: false } });
  } catch {
    cachedDispatcher = undefined;
  }
  return cachedDispatcher;
}

// ── Body reader (streaming, capped) ─────────────────────

async function readBody(
  res: Response,
  maxBytes: number,
): Promise<{ text: string; truncated: boolean }> {
  const reader = res.body?.getReader();
  if (!reader) {
    const text = await res.text();
    const truncated = text.length > maxBytes;
    return { text: truncated ? text.slice(0, maxBytes) : text, truncated };
  }

  const decoder = new TextDecoder();
  let result = "";
  let received = 0;
  let truncated = false;

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    received += value.byteLength;
    result += decoder.decode(value, { stream: true });
    if (received >= maxBytes) {
      truncated = true;
      break;
    }
  }
  result += decoder.decode(); // flush

  if (result.length > maxBytes) {
    result = result.slice(0, maxBytes);
    truncated = true;
  }
  try {
    reader.cancel();
  } catch {
    /* ignore */
  }
  return { text: result, truncated };
}

// ── Tool ─────────────────────────────────────────────────

const HttpMethod = Type.String({ enum: METHOD_LIST });
const RedirectMode = Type.String({ enum: REDIRECT_LIST });

export default function httpRequestExtension(pi: ExtensionAPI) {
  pi.registerTool({
    name: "http_request",
    label: "HTTP Request",
    description:
      "Send a raw HTTP request with a persistent cookie jar, custom headers, and body control. Use for authenticated web-app testing (login → probe), API vulnerability probing, and verifying HTTP behavior. Unlike web_fetch (stateless, read-only), http_request persists cookies across calls within a session, supports all methods, and surfaces raw responses.",
    promptSnippet: "Send HTTP requests with cookies, headers, and body control",
    promptGuidelines: [
      "Use http_request for authenticated web-app testing: POST to login, then GET protected resources — the cookie jar persists across calls automatically.",
      "Default redirect mode is 'manual' — you'll see 302/301 as-is (critical for redirect-chain analysis). Use 'follow' to auto-follow redirects.",
      "Pass json for JSON bodies (Content-Type set automatically); pass body for raw/form payloads.",
      "Private/internal hosts (127.0.0.1, 10.x, 192.168.x, fc00::/7) are blocked by default. Set allowPrivateHosts=true for internal pentests.",
      "Use verifyTls=false for self-signed cert targets (e.g., internal staging apps). TLS verification is enabled by default.",
      "The Set-Cookie response header is automatically stored in the session cookie jar and injected into subsequent requests to the same host.",
      "Pass an Authorization header (e.g. headers: { Authorization: 'Basic <base64>' }) for Basic auth — the http_request tool does not store credentials itself, keeping auth explicit and visible in the transcript.",
      "Prefer http_request over web_fetch when you need custom methods, auth headers, cookie-dependent auth flows, or raw response headers. Use web_fetch for read-only page content when you don't need session state.",
    ],
    parameters: Type.Object(
      {
        url: Type.String({ description: "Target URL (http:// or https://)" }),
        method: Type.Optional(HttpMethod),
        headers: Type.Optional(
          Type.Record(Type.String(), Type.String(), {
            description: "Request headers. An explicit Cookie header merges with the session jar.",
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
          Type.String({
            description: "Shorthand Content-Type (e.g. application/json, text/xml)",
          }),
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
              "Allow private/internal hostnames (default false, SSRF-safe). Set true for internal pentest targets.",
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
      try {
        // ── URL parse + protocol gate ────────────────────────
        if (!params.url) {
          return errorResult("Missing required parameter 'url'");
        }
        let parsed: URL;
        try {
          parsed = new URL(params.url);
        } catch (err) {
          const msg = err instanceof Error ? err.message : String(err);
          return errorResult(`Invalid URL: ${msg}`);
        }
        if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
          return errorResult(`Protocol "${parsed.protocol}" not allowed. Use http:// or https://.`);
        }

        // ── SSRF guard ───────────────────────────────────────
        if (!params.allowPrivateHosts && !isPublicHttpHost(parsed)) {
          return {
            content: [
              {
                type: "text" as const,
                text: `Blocked: ${parsed.hostname} is a private/internal host (127.0.0.1, 10.x, 192.168.x, fc00::/7, link-local, etc.). Set allowPrivateHosts=true to test internal targets.`,
              },
            ],
            isError: true,
            details: {
              error: "ssrf_blocked",
              hostname: parsed.hostname,
            },
          };
        }

        // ── Resolve method / redirect / timeout / body cap ──
        const method = (params.method || "GET").toUpperCase();
        const redirectMode = (params.redirect || "manual") as RequestRedirect;
        const timeoutMs = params.timeoutMs ?? DEFAULT_TIMEOUT_MS;
        // Clamp maxBody to the hard cap — the schema maximum is advisory only;
        // the harness passes params straight through without runtime validation,
        // so a provider could bypass it and force an unbounded body read.
        const maxBody = Math.min(params.maxBody ?? DEFAULT_MAX_BODY, MAX_BODY_HARD);
        const verifyTls = params.verifyTls !== false;

        // ── Build headers ────────────────────────────────────
        const mergedHeaders = injectCookieHeader(
          parsed.hostname.toLowerCase(),
          params.headers || {},
        );

        if (params.contentType && !hasHeader(mergedHeaders, "content-type")) {
          mergedHeaders["content-type"] = params.contentType;
        }

        // ── Build body ───────────────────────────────────────
        let body: string | undefined;
        if (params.json !== undefined) {
          body = JSON.stringify(params.json);
          if (!hasHeader(mergedHeaders, "content-type")) {
            mergedHeaders["content-type"] = "application/json";
          }
        } else if (params.body !== undefined && method !== "GET" && method !== "HEAD") {
          body = params.body;
        }

        // ── Build fetch options ──────────────────────────────
        const fetchOptions: RequestInit & { dispatcher?: unknown } = {
          method,
          headers: mergedHeaders,
          redirect: redirectMode,
          signal: AbortSignal.any([...(signal ? [signal] : []), AbortSignal.timeout(timeoutMs)]),
        };
        if (body !== undefined && method !== "GET" && method !== "HEAD") {
          fetchOptions.body = body;
        }
        if (!verifyTls) {
          if (isBun) {
            (fetchOptions as RequestInit & { tls?: unknown }).tls = {
              rejectUnauthorized: false,
            };
          } else {
            const dispatcher = getInsecureDispatcher();
            if (!dispatcher) {
              // Fail loudly — silently re-verifying TLS on a request where the
              // caller explicitly asked for a bypass is a dangerous surprise.
              return errorResult(
                "verifyTls=false requested but TLS bypass is unavailable: the 'undici' " +
                  "package is not installed and this runtime can't disable verification " +
                  "otherwise. No request was sent. Install undici or run under Bun.",
              );
            }
            fetchOptions.dispatcher = dispatcher;
          }
        }

        // ── Execute request ──────────────────────────────────
        const start = Date.now();
        const res = await fetch(parsed.toString(), fetchOptions);
        const timingMs = Date.now() - start;

        // ── Store response cookies ──────────────────────────
        storeResponseCookies(parsed.hostname.toLowerCase(), res);

        // ── Read body ────────────────────────────────────────
        const { text: responseBody, truncated } = await readBody(res, maxBody);

        // ── Collect response headers ────────────────────────
        const responseHeaders: Record<string, string> = {};
        const cookiesInResponse: string[] = [];
        for (const [k, v] of res.headers.entries()) {
          if (k === "set-cookie") {
            cookiesInResponse.push(v);
          } else {
            responseHeaders[k] = v;
          }
        }

        // ── Current cookies stored for this host ────────────
        const cookiesOnHost = cookieJar.get(parsed.hostname.toLowerCase()) || "";

        // ── Build curl-style transcript for content ─────────
        const pathAndQuery = parsed.pathname + (parsed.search || "");
        let text = `> ${method} ${pathAndQuery} HTTP/1.1\n`;
        text += `> Host: ${parsed.hostname}\n`;
        for (const [k, v] of Object.entries(mergedHeaders)) {
          text += `> ${k}: ${v}\n`;
        }
        if (body && method !== "GET" && method !== "HEAD") {
          const bodyPreview = body.length > 200 ? `${body.slice(0, 200)}...` : body;
          text += `> ${bodyPreview}\n`;
        }
        text += `\n< HTTP/1.1 ${res.status} ${res.statusText || ""}\n`;
        for (const [k, v] of Object.entries(responseHeaders)) {
          text += `< ${k}: ${v}\n`;
        }
        for (const c of cookiesInResponse) {
          text += `< Set-Cookie: ${c}\n`;
        }
        text += `\n`;
        text += responseBody;
        if (truncated) {
          text += `\n\n[body truncated at ${maxBody} bytes]`;
        }

        return {
          content: [{ type: "text" as const, text }],
          isError: false,
          details: {
            status: res.status,
            statusText: res.statusText,
            method,
            url: parsed.toString(),
            finalUrl: res.url || parsed.toString(),
            redirected: res.url !== parsed.toString(),
            requestHeaders: mergedHeaders,
            responseHeaders,
            responseHeadersRaw: Object.fromEntries(res.headers.entries()),
            body: responseBody,
            bodyTruncated: truncated,
            bodySize: responseBody.length,
            timingMs,
            cookiesOnHost,
            cookiesInResponse,
            session: "default",
          },
        };
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        return errorResult(message);
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

    renderResult(result, { expanded }: { expanded: boolean }, theme) {
      const details = result.details as {
        error?: string;
        status?: number;
        statusText?: string;
        method?: string;
        url?: string;
        timingMs?: number;
        bodyTruncated?: boolean;
      };
      if (details?.error) {
        return new Text(theme.fg("error", `✗ HTTP failed: ${details.error}`), 0, 0);
      }
      const status = details?.status ?? 0;
      const method = details?.method || "GET";
      const url = details?.url || "";
      const timing = details?.timingMs ?? 0;
      const truncated = details?.bodyTruncated;

      const statusColor =
        status >= 200 && status < 300 ? "success" : status >= 400 ? "error" : "warning";

      let baseText =
        theme.fg(statusColor, String(status)) + theme.fg("dim", ` ${method} ${url} (${timing}ms)`);
      if (truncated) {
        baseText += theme.fg("muted", " (truncated)");
      }
      if (expanded) {
        const text = (result.content[0] as { text?: string })?.text || "";
        return new Text(`${baseText}\n${text}`, 0, 0);
      }
      return new Text(baseText, 0, 0);
    },
  });

  // Clear cookie jar on session shutdown so sessions don't leak state
  // between separate Pi runs or after extension reload.
  pi.on("session_shutdown", () => {
    cookieJar.clear();
  });
}

function errorResult(message: string) {
  return {
    content: [{ type: "text" as const, text: `HTTP request failed: ${message}` }],
    isError: true,
    details: { error: message },
  };
}
