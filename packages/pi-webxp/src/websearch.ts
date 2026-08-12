/**
 * pi-websearch — keyless web search and page fetch adapter powered by open-websearch daemon.
 *
 * Exposes:
 * - Tool: web_search — query the internet using open-websearch engines.
 * - Tool: web_fetch — retrieve clean page markdown or article content.
 */

import { type ChildProcess, spawn, spawnSync } from "node:child_process";
import { createRequire } from "node:module";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { Text } from "@earendil-works/pi-tui";
import { abortableSleep } from "@xaccefy/pi-shared";
import { Type } from "typebox";
import { isPublicHttpHost } from "./network-safety.ts";

/** Retriable HTTP statuses for daemon calls (408/429/5xx). */
function isTransientHttpStatus(status: number): boolean {
  return status === 408 || status === 429 || status >= 500;
}

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
let daemonSpawnError: Error | null = null;
let startupPromise: Promise<boolean> | null = null;

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

let resolvedDaemonBin: string | null = null;

/**
 * Pick the binary that runs the open-websearch daemon. open-websearch targets
 * Node; when pi runs under Bun, process.execPath is the bun binary, which may
 * not run a Node-oriented package. Prefer a real node binary: execPath when it
 * IS node, else a PATH lookup (probed once with --version), else execPath as a
 * last resort — the error handling in startDaemon surfaces the failure cleanly.
 */
function getDaemonBin(): string {
  if (resolvedDaemonBin) return resolvedDaemonBin;
  const execName = process.execPath.split(/[\\/]/).pop() ?? "";
  if (execName.startsWith("node")) {
    resolvedDaemonBin = process.execPath;
  } else {
    const probe = spawnSync("node", ["--version"], { stdio: "ignore" });
    resolvedDaemonBin = probe.status === 0 ? "node" : process.execPath;
  }
  return resolvedDaemonBin;
}

function startDaemon(): void {
  if (shuttingDown) return;
  const scriptPath = getDaemonScriptPath();
  if (!scriptPath) {
    throw new Error(
      "open-websearch package not found. Run npm/bun install so open-websearch is available.",
    );
  }

  daemonSpawnError = null;
  daemonProcess = spawn(getDaemonBin(), [scriptPath, "serve", "--port", DAEMON_PORT], {
    stdio: "ignore",
    env: { ...process.env, PORT: DAEMON_PORT },
    windowsHide: true,
    detached: false,
  });
  // Don't pin the event loop solely because the child is alive.
  daemonProcess.unref?.();

  // Without this, a spawn failure (e.g. missing binary) throws an unhandled
  // 'error' event and can take the whole host process down.
  daemonProcess.on("error", (err) => {
    daemonSpawnError = err;
    daemonProcess = null;
  });

  daemonProcess.on("exit", () => {
    daemonProcess = null;
  });
}

async function ensureDaemonRunning(): Promise<boolean> {
  if (shuttingDown) return false;
  // Assign the shared promise BEFORE any await so concurrent callers coalesce
  // onto one spawn instead of each forking a daemon and orphaning children.
  if (startupPromise) return startupPromise;

  startupPromise = (async () => {
    if (await checkDaemonRunning()) return true;
    // Re-check after the async health probe: a concurrent session_shutdown may
    // have flipped shuttingDown while we were awaiting. Don't spawn a daemon
    // the shutdown just killed.
    if (shuttingDown) return false;
    // startDaemon resets daemonSpawnError, so a call after a failed spawn
    // retries cleanly; the error only blocks when the fresh spawn also failed.
    if (!daemonProcess) startDaemon();
    if (daemonSpawnError) return false;
    for (let i = 0; i < STARTUP_RETRIES; i++) {
      if (shuttingDown) return false;
      if (daemonSpawnError) return false;
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
  // Do NOT await an in-flight startup: the startup loop can run up to
  // STARTUP_RETRIES × POLL_INTERVAL (~5s) against a slow/booting daemon, and
  // session_shutdown must not block that long. No kill-then-respawn race
  // exists: startDaemon() runs exactly once, synchronously, before the poll
  // loop, and the loop checks shuttingDown at every await boundary — it
  // self-terminates on the next wake-up.
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

// ── Diagnostic Error Handler ──────────────────────────────────────────

function handleWebsearchError(err: unknown, toolName: string): never {
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
  throw new Error(`${toolName} failed: ${message}${hint}`, { cause: err });
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
      "Prefer web_search for general web lookups; use exploit_search for offense-specific technique grounding, and context7/deepwiki for library/repo docs.",
    ],
    parameters: Type.Object(
      {
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
      },
      { additionalProperties: false },
    ),

    async execute(_id, params, signal, _onUpdate, _ctx) {
      try {
        const running = await ensureDaemonRunning();
        if (!running) {
          throw new Error(
            daemonSpawnError
              ? `Unable to start open-websearch daemon: ${daemonSpawnError.message}`
              : "Unable to establish connection with local open-websearch daemon.",
          );
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

    renderResult(result, { expanded }, theme, context) {
      const details = result.details as any;
      if (context.isError) {
        return new Text(theme.fg("error", "✗ Web Search failed"), 0, 0);
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
      "Prefer web_fetch over web_search when you already have a target URL.",
    ],
    parameters: Type.Object(
      {
        url: Type.String({ description: "Valid HTTP or HTTPS URL to fetch" }),
      },
      { additionalProperties: false },
    ),

    async execute(_id, params, signal, _onUpdate, _ctx) {
      try {
        const running = await ensureDaemonRunning();
        if (!running) {
          throw new Error(
            daemonSpawnError
              ? `Unable to start open-websearch daemon: ${daemonSpawnError.message}`
              : "Unable to establish connection with local open-websearch daemon.",
          );
        }

        if (!params.url) {
          throw new Error("Missing required 'url' parameter");
        }
        const parsedUrl = validateAndParseUrl(params.url);
        if (!isPublicHttpHost(parsedUrl)) {
          throw new Error(
            `Blocked: ${parsedUrl.hostname} is a private/internal host. Use http_request with allowPrivateHosts=true for internal targets.`,
          );
        }
        const targetUrl = parsedUrl.toString();

        // Match on hostname only — never substring-match the full URL, which would
        // route e.g. https://evil.example/?q=github.com to the GitHub README fetcher.
        const host = parsedUrl.hostname.toLowerCase();
        const endpoint =
          host === "github.com" || host.endsWith(".github.com")
            ? "/fetch-github-readme"
            : "/fetch-web";

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
        const textContent =
          typeof data === "string"
            ? data
            : data.markdown || data.content || data.text || JSON.stringify(data);

        return {
          content: [{ type: "text" as const, text: textContent }],
          details: { metadata: data, url: targetUrl },
        };
      } catch (err) {
        return handleWebsearchError(err, "Web fetch");
      }
    },

    renderResult(result, { expanded }, theme, context) {
      const details = result.details as any;
      if (context.isError) {
        return new Text(theme.fg("error", "✗ Web Fetch failed"), 0, 0);
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
