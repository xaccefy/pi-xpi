/**
 * pi-websearch — keyless web search and page fetch adapter powered by open-websearch daemon.
 *
 * Exposes:
 * - Tool: web_search — query the internet using open-websearch engines.
 * - Tool: web_fetch — retrieve clean page markdown or article content.
 */

import { type ChildProcess, spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { createRequire } from "node:module";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { Text } from "@earendil-works/pi-tui";
import { Type } from "@sinclair/typebox";
import { abortableSleep, isTransientHttpStatus } from "./cache.ts";

// ── Constants & Environment ──────────────────────────────────────────

function resolveDaemonPort(): string {
  const raw = (process.env.PI_WEBSEARCH_PORT || "3210").trim();
  const n = Number(raw);
  if (!Number.isInteger(n) || n < 1 || n > 65535) return "3210";
  return String(n);
}
const DAEMON_PORT = resolveDaemonPort();
const DAEMON_URL = `http://127.0.0.1:${DAEMON_PORT}`;
let shuttingDown = false;

const POLL_INTERVAL_MS = 350;
const STARTUP_RETRIES = 15;
const REQUEST_TIMEOUT_MS = 30000;

let daemonProcess: ChildProcess | null = null;
let startupPromise: Promise<boolean> | null = null;

// Domain mapping for fetch endpoints
const DOMAIN_ENDPOINT_MAP = [
  { match: "github.com", endpoint: "/fetch-github-readme" },
  { match: "csdn.net", endpoint: "/fetch-csdn" },
  { match: "juejin.cn", endpoint: "/fetch-juejin" },
  { match: "linux.do", endpoint: "/fetch-linuxdo" },
];

// ── Helpers ──────────────────────────────────────────────────────────

function getDaemonScriptPath(): string {
  try {
    const _require = createRequire(import.meta.url);
    return _require.resolve("open-websearch/build/index.js");
  } catch {
    return "";
  }
}

async function checkDaemonRunning(): Promise<boolean> {
  try {
    const res = await fetch(`${DAEMON_URL}/health`, { signal: AbortSignal.timeout(500) });
    if (res.ok) {
      const body = (await res.json()) as any;
      return body?.status === "ok" || body?.data?.daemon === "running";
    }
  } catch {}
  return false;
}

function startDaemon(): void {
  if (shuttingDown) return;
  const scriptPath = getDaemonScriptPath();
  if (!scriptPath) {
    throw new Error(
      "open-websearch package not found. Run npm/bun install so open-websearch is available.",
    );
  }

  daemonProcess = spawn("node", [scriptPath, "serve", "--port", DAEMON_PORT], {
    stdio: "ignore",
    env: { ...process.env, PORT: DAEMON_PORT },
    windowsHide: true,
    detached: false,
  });
  // Don't pin the event loop solely because the child is alive.
  daemonProcess.unref?.();

  daemonProcess.on("exit", () => {
    daemonProcess = null;
  });
}

process.on("exit", () => {
  if (daemonProcess) {
    try {
      daemonProcess.kill();
    } catch {}
  }
});

async function ensureDaemonRunning(): Promise<boolean> {
  if (shuttingDown) return false;
  // Assign the shared promise BEFORE any await so concurrent callers coalesce
  // onto one spawn instead of each forking a daemon and orphaning children.
  if (startupPromise) return startupPromise;

  startupPromise = (async () => {
    if (await checkDaemonRunning()) return true;
    if (shuttingDown) return false;
    if (!daemonProcess) startDaemon();
    for (let i = 0; i < STARTUP_RETRIES; i++) {
      if (shuttingDown) return false;
      await new Promise((resolve) => setTimeout(resolve, POLL_INTERVAL_MS));
      if (await checkDaemonRunning()) return true;
    }
    return false;
  })();

  try {
    return await startupPromise;
  } finally {
    startupPromise = null;
  }
}

async function stopDaemon(): Promise<void> {
  shuttingDown = true;
  // Wait for any in-flight startup so we don't kill then re-spawn.
  if (startupPromise) {
    try {
      await startupPromise;
    } catch {
      // ignore
    }
  }
  if (daemonProcess) {
    try {
      daemonProcess.kill();
    } catch {}
    daemonProcess = null;
  }
}

async function fetchWithRetry(
  url: string,
  options: RequestInit,
  parentSignal?: AbortSignal,
): Promise<Response> {
  const doFetch = (): Promise<Response> =>
    fetch(url, {
      ...options,
      signal: AbortSignal.any([
        ...(parentSignal ? [parentSignal] : []),
        AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      ]),
    });

  const first = await doFetch();
  if (first.ok) return first;

  const status = first.status;
  try {
    first.body?.cancel();
  } catch {
    // ignore
  }

  // Only retry transient failures; permanent 4xx should fail fast.
  if (!isTransientHttpStatus(status)) {
    throw new Error(`HTTP ${status}`);
  }
  if (parentSignal?.aborted) throw new Error(`HTTP ${status}`);

  await abortableSleep(150, parentSignal);
  const retry = await doFetch();
  if (!retry.ok) {
    try {
      retry.body?.cancel();
    } catch {
      // ignore
    }
    throw new Error(`HTTP ${retry.status} after retry`);
  }
  return retry;
}

function validateAndParseUrl(input: string): URL {
  try {
    const parsed = new URL(input);
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      throw new Error("Protocol must be http: or https:");
    }
    return parsed;
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    throw new Error(`Invalid URL "${input}": ${msg}`);
  }
}

// ── SPA / client-rendered page fallback ──────────────────────────────
// Static HTML fetch returns the loading shell for SPAs. When the daemon
// only got a thin shell, re-render with system chromium --dump-dom.
// Daemon already SSRF-checked the URL; we only block private host literals.
// Exported for unit tests (pure helpers + injectable chromium resolver).

let cachedChromiumPath: string | null | undefined;
/** Test-only: reset cached chromium path between cases. */
export function __resetChromiumPathCacheForTests(): void {
  cachedChromiumPath = undefined;
}

export function resolveChromiumPath(
  exists: (p: string) => boolean = existsSync,
  envPath: string | undefined = process.env.PI_CHROMIUM_PATH,
): string | null {
  if (cachedChromiumPath !== undefined) return cachedChromiumPath;
  const candidates = [
    envPath,
    "/usr/bin/chromium",
    "/usr/sbin/chromium",
    "/usr/bin/chromium-browser",
    "/usr/bin/google-chrome",
    "/usr/bin/google-chrome-stable",
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
  ].filter(Boolean) as string[];
  for (const candidate of candidates) {
    if (exists(candidate)) {
      cachedChromiumPath = candidate;
      return candidate;
    }
  }
  cachedChromiumPath = null;
  return null;
}

const SPA_SHELL_MARKERS = [
  /enable javascript/i,
  /please (wait|enable)/i,
  /your browser does not support/i,
];

/** True when static extraction looks like an empty SPA shell. */
export function looksLikeSpaShell(
  data: { retrievalMethod?: string; contentType?: string } | null | undefined,
  text: string,
): boolean {
  if (data?.retrievalMethod === "browser-html") return false;
  const contentType = String(data?.contentType || "").toLowerCase();
  if (!contentType.includes("text/html")) return false;
  const trimmed = (text || "").trim();
  // Only force a browser pass for truly thin shells or explicit JS-required markers.
  if (trimmed.length < 120) return true;
  return SPA_SHELL_MARKERS.some((re) => re.test(trimmed));
}

/** Block private/local host literals (daemon already did public DNS for the URL). */
export function isPublicHttpHost(parsed: URL): boolean {
  // Normalize: some runtimes keep brackets on IPv6 hostnames ("[::1]").
  let host = parsed.hostname.toLowerCase();
  if (host.startsWith("[") && host.endsWith("]")) host = host.slice(1, -1);
  if (host === "localhost" || host.endsWith(".localhost")) return false;
  if (host === "0.0.0.0" || host === "::1" || host === "::") return false;
  // IPv6 ULA (fc00::/7) and link-local (fe80::/10)
  if (/^f[cd][0-9a-f]{0,2}:/i.test(host) || host.startsWith("fe80:")) return false;
  if (
    /^127\./.test(host) ||
    /^10\./.test(host) ||
    /^192\.168\./.test(host) ||
    /^169\.254\./.test(host) ||
    /^172\.(1[6-9]|2\d|3[01])\./.test(host)
  ) {
    return false;
  }
  return true;
}

export async function renderSpaDom(
  url: string,
  chromiumPath: string,
  parentSignal?: AbortSignal,
  timeoutMs: number = REQUEST_TIMEOUT_MS,
): Promise<string> {
  const args = [
    "--headless",
    "--no-sandbox",
    "--disable-gpu",
    "--disable-dev-shm-usage",
    "--virtual-time-budget=8000",
    "--dump-dom",
    url,
  ];
  return new Promise<string>((resolve, reject) => {
    const proc = spawn(chromiumPath, args, { stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    let settled = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const finish = (fn: () => void) => {
      if (settled) return;
      settled = true;
      if (timer !== undefined) clearTimeout(timer);
      if (parentSignal) parentSignal.removeEventListener("abort", onAbort);
      fn();
    };
    const onAbort = () => {
      try {
        proc.kill("SIGKILL");
      } catch {
        // ignore
      }
      finish(() => reject(new Error("chromium render aborted")));
    };
    timer = setTimeout(onAbort, timeoutMs);
    if (parentSignal) {
      if (parentSignal.aborted) {
        onAbort();
        return;
      }
      parentSignal.addEventListener("abort", onAbort);
    }
    proc.stdout.on("data", (chunk) => (stdout += chunk.toString()));
    proc.stderr.on("data", (chunk) => (stderr += chunk.toString()));
    proc.on("error", (err) => finish(() => reject(err)));
    proc.on("close", (code) => {
      if (code === 0 && stdout.trim()) finish(() => resolve(stdout));
      else finish(() => reject(new Error(`chromium exited ${code}: ${stderr.slice(0, 300)}`)));
    });
  });
}

export function htmlToText(html: string): string {
  let s = html
    .replace(/<script[\s\S]*?<\/script>/gi, " ")
    .replace(/<style[\s\S]*?<\/style>/gi, " ")
    .replace(/<noscript[\s\S]*?<\/noscript>/gi, " ");
  s = s.replace(/<\/(p|div|li|h[1-6]|tr|section|article|main|header|footer)>/gi, "\n");
  s = s.replace(/<br\s*\/?>/gi, "\n");
  s = s.replace(/<[^>]+>/g, " ");
  s = s
    .replace(/&nbsp;/g, " ")
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&apos;/g, "'");
  return s.replace(/[ \t]+/g, " ").replace(/\n{3,}/g, "\n\n").trim();
}

/** Prefer browser text only when it is meaningfully richer than the static shell. */
export function preferRenderedText(staticText: string, renderedText: string): boolean {
  const a = staticText.trim().length;
  const b = renderedText.trim().length;
  if (b <= a) return false;
  // Thin SPA shells: any clearly longer render wins (e.g. "Loading..." → real body).
  if (a < 120) return b >= Math.max(a + 20, 40);
  // Longer static pages: require 2x and +80 so chrome/nav noise alone doesn't win.
  return b > a * 2 && b >= a + 80;
}


// ── Diagnostic Error Handler ──────────────────────────────────────────

function handleWebsearchError(err: unknown, toolName: string) {
  const message = err instanceof Error ? err.message : String(err);
  let hint = "";
  if (
    message.includes("establish connection") ||
    message.includes("fetch failed") ||
    message.includes("ECONNREFUSED") ||
    message.includes("HTTP 502") ||
    message.includes("HTTP 504") ||
    message.includes("daemon")
  ) {
    hint = `\n\nHint: The 'open-websearch' daemon on port ${DAEMON_PORT} could not be reached or failed to start.\nTo troubleshoot:\n  1. Run 'npm install' in the project root to link all dependencies.\n  2. Verify if another server is already bound to port ${DAEMON_PORT}.\n  3. You can manually launch the daemon by running:\n     npx open-websearch serve --port ${DAEMON_PORT}`;
  }
  return {
    content: [{ type: "text" as const, text: `${toolName} failed: ${message}${hint}` }],
    isError: true,
    details: { error: message },
  };
}

// ── Pi Extension ──────────────────────────────────────────────────────

export default function websearchExtension(pi: ExtensionAPI) {
  // ── Tool: web_search ──
  pi.registerTool({
    name: "web_search",
    label: "Web Search",
    description:
      "Search the web for real-world exploits, write-ups, or documentation using search engines (no API keys required).",
    promptSnippet: "Search the web for exploits, docs, or general info",
    promptGuidelines: [
      "Use web_search to find CVEs, advisories, documentation, write-ups, or any live web results (no API key needed).",
      "Prefer web_search for general web lookups; use ExploitSearch for offense-specific technique grounding, and context7/deepwiki for library/repo docs.",
    ],
    parameters: Type.Object({
      query: Type.String({ description: "Search query string" }),
      limit: Type.Optional(
        Type.Integer({
          description: "Max search results (1-50, default: 10)",
          minimum: 1,
          maximum: 50,
        }),
      ),
      engines: Type.Optional(
        Type.Array(Type.String(), {
          description: "Engines to query (e.g. bing, duckduckgo, brave, exa)",
        }),
      ),
    }),

    async execute(_id, params, signal, _onUpdate, _ctx) {
      try {
        const running = await ensureDaemonRunning();
        if (!running) {
          throw new Error("Unable to establish connection with local open-websearch daemon.");
        }

        const res = await fetchWithRetry(
          `${DAEMON_URL}/search`,
          {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              query: params.query,
              limit: params.limit ?? 10,
              engines: params.engines || ["duckduckgo", "startpage"],
            }),
          },
          signal,
        );

        const body = (await res.json()) as any;
        if (body?.status !== "ok" || !body?.data) {
          throw new Error(body?.error?.message || "Invalid response format from daemon");
        }

        const results = body.data.results || [];
        if (results.length === 0) {
          return {
            content: [
              { type: "text" as const, text: `No results found for query: "${params.query}"` },
            ],
            details: { results: [] },
          };
        }

        let markdown = `Web Search Results for: "${params.query}"\n\n`;
        results.forEach((item: any, idx: number) => {
          markdown += `${idx + 1}. **${item.title || "Untitled"}**\n`;
          markdown += `   URL: ${item.url}\n`;
          if (item.content || item.description) {
            markdown += `   Snippet: ${item.content || item.description}\n`;
          }
          markdown += `\n`;
        });

        return {
          content: [{ type: "text" as const, text: markdown.trim() }],
          details: { results, query: params.query },
        };
      } catch (err) {
        return handleWebsearchError(err, "Web search");
      }
    },

    renderResult(result, { expanded }, theme) {
      const details = result.details as any;
      if (details?.error) {
        return new Text(theme.fg("error", `✗ Web Search failed: ${details.error}`), 0, 0);
      }
      const results = details?.results || [];
      const query = details?.query || "";
      const baseText =
        theme.fg("success", "✓") +
        theme.fg("toolTitle", " Web Search: ") +
        theme.fg("dim", `${results.length} results found for "${query}"`);
      if (expanded) {
        const text = (result.content[0] as any)?.text || "";
        return new Text(`${baseText}\n${text}`, 0, 0);
      }
      return new Text(baseText, 0, 0);
    },
  });

  // ── Tool: web_fetch ──
  pi.registerTool({
    name: "web_fetch",
    label: "Web Fetch",
    description:
      "Read full text, markdown article content, or GitHub README files from an HTTP/HTTPS URL.",
    promptSnippet: "Fetch the full text/markdown content of a URL",
    promptGuidelines: [
      "Use web_fetch to read the full text, article markdown, or README from a specific HTTP(S) URL when the user gives a link or you need page content rather than search results.",
      "SPAs and JS-rendered pages are re-rendered headlessly, so the real content is returned; just pass the URL.",
      "Prefer web_fetch over web_search when you already have a target URL.",
    ],
    parameters: Type.Object({
      url: Type.String({ description: "Valid HTTP or HTTPS URL to fetch" }),
    }),

    async execute(_id, params, signal, _onUpdate, _ctx) {
      try {
        const running = await ensureDaemonRunning();
        if (!running) {
          throw new Error("Unable to establish connection with local open-websearch daemon.");
        }

        if (!params.url) {
          throw new Error("Missing required 'url' parameter");
        }
        const parsedUrl = validateAndParseUrl(params.url);
        const targetUrl = parsedUrl.toString();

        // Match on hostname only — never substring-match the full URL, which would
        // route e.g. https://evil.example/?q=github.com to the GitHub README fetcher.
        let endpoint = "/fetch-web";
        const host = parsedUrl.hostname.toLowerCase();
        for (const entry of DOMAIN_ENDPOINT_MAP) {
          if (host === entry.match || host.endsWith(`.${entry.match}`)) {
            endpoint = entry.endpoint;
            break;
          }
        }

        const res = await fetchWithRetry(
          `${DAEMON_URL}${endpoint}`,
          {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url: targetUrl }),
          },
          signal,
        );

        const body = (await res.json()) as any;
        if (body?.status !== "ok" || !body?.data) {
          throw new Error(body?.error?.message || "Invalid response from daemon");
        }

        const data = body.data;
        let textContent =
          typeof data === "string"
            ? data
            : data.markdown || data.content || data.text || JSON.stringify(data);

        // SPA / client-rendered fallback. The daemon's static extraction
        // cannot see DOM injected by JavaScript; re-render the already
        // validated public URL with system chromium when we detect a shell.
        let renderedBy: string | undefined;
        if (endpoint === "/fetch-web" && looksLikeSpaShell(data, textContent) && isPublicHttpHost(parsedUrl)) {
          const chromiumPath = resolveChromiumPath();
          if (chromiumPath) {
            try {
              const renderedHtml = await renderSpaDom(targetUrl, chromiumPath, signal);
              const renderedText = htmlToText(renderedHtml);
              if (preferRenderedText(textContent, renderedText)) {
                textContent = renderedText;
                renderedBy = "chromium";
              }
            } catch {
              // Chromium render failed; keep the static extraction result.
            }
          }
        }

        return {
          content: [{ type: "text" as const, text: textContent }],
          details: { metadata: data, url: targetUrl, ...(renderedBy ? { renderedBy } : {}) },
        };
      } catch (err) {
        return handleWebsearchError(err, "Web fetch");
      }
    },

    renderResult(result, { expanded }, theme) {
      const details = result.details as any;
      if (details?.error) {
        return new Text(theme.fg("error", `✗ Web Fetch failed: ${details.error}`), 0, 0);
      }
      const url = details?.url || "";
      const text = (result.content[0] as any)?.text || "";
      const textLength = text.length;
      const renderedNote = details?.renderedBy ? " (browser-rendered)" : "";
      const baseText =
        theme.fg("success", "✓") +
        theme.fg("toolTitle", " Web Fetch: ") +
        theme.fg("dim", `Fetched ${textLength} characters from "${url}"${renderedNote}`);
      if (expanded) {
        return new Text(`${baseText}\n${text}`, 0, 0);
      }
      return new Text(baseText, 0, 0);
    },
  });

  // ── Session Event Bindings ──────────────────────────────────────────

  pi.on("session_start", async () => {
    // Fresh session can spawn again even if a prior shutdown ran in-process.
    shuttingDown = false;
    // Don't block session start on daemon startup; the tools await it when they need it.
    void ensureDaemonRunning().catch(() => {
      // Best-effort warm-up; tools will surface a clear error on demand.
    });
  });

  pi.on("session_shutdown", async () => {
    await stopDaemon();
  });
}
