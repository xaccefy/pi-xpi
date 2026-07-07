/**
 * pi-websearch — keyless web search and page fetch adapter powered by open-websearch daemon.
 *
 * Exposes:
 * - Tool: web_search — query the internet using open-websearch engines.
 * - Tool: web_fetch — retrieve clean page markdown or article content.
 */

import { type ChildProcess, spawn } from "node:child_process";
import { createRequire } from "node:module";
import { dirname } from "node:path";
import { fileURLToPath } from "node:url";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { Text } from "@earendil-works/pi-tui";
import { Type } from "@sinclair/typebox";

// ── Constants & Environment ──────────────────────────────────────────

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const DAEMON_PORT = process.env.PI_WEBSEARCH_PORT || "3210";
const DAEMON_URL = `http://127.0.0.1:${DAEMON_PORT}`;

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
  const scriptPath = getDaemonScriptPath();
  if (!scriptPath) {
    return;
  }

  daemonProcess = spawn("node", [scriptPath, "serve", "--port", DAEMON_PORT], {
    stdio: "ignore",
    env: { ...process.env, PORT: DAEMON_PORT },
    windowsHide: true,
    detached: false,
  });

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
  if (await checkDaemonRunning()) {
    return true;
  }

  if (startupPromise) {
    return startupPromise;
  }

  startupPromise = (async () => {
    startDaemon();
    for (let i = 0; i < STARTUP_RETRIES; i++) {
      await new Promise((resolve) => setTimeout(resolve, POLL_INTERVAL_MS));
      if (await checkDaemonRunning()) {
        return true;
      }
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

  try {
    const res = await doFetch();
    if (res.ok) return res;
    throw new Error(`HTTP ${res.status}`);
  } catch (err) {
    // Don't retry if the parent signal aborted — that's an intentional cancel, not a transient error
    if (parentSignal?.aborted) throw err;

    await new Promise((r) => setTimeout(r, 150));
    const retry = await doFetch();
    // On retry, fail loudly instead of returning a non-ok response that callers would
    // try to parse as JSON and surface a confusing downstream error.
    if (!retry.ok) {
      throw new Error(`HTTP ${retry.status} after retry`);
    }
    return retry;
  }
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
        const targetUrl = validateAndParseUrl(params.url).toString();

        let endpoint = "/fetch-web";
        for (const entry of DOMAIN_ENDPOINT_MAP) {
          if (targetUrl.includes(entry.match)) {
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

    renderResult(result, { expanded }, theme) {
      const details = result.details as any;
      if (details?.error) {
        return new Text(theme.fg("error", `✗ Web Fetch failed: ${details.error}`), 0, 0);
      }
      const url = details?.url || "";
      const text = (result.content[0] as any)?.text || "";
      const textLength = text.length;
      const baseText =
        theme.fg("success", "✓") +
        theme.fg("toolTitle", " Web Fetch: ") +
        theme.fg("dim", `Fetched ${textLength} characters from "${url}"`);
      if (expanded) {
        return new Text(`${baseText}\n${text}`, 0, 0);
      }
      return new Text(baseText, 0, 0);
    },
  });

  // ── Session Event Bindings ──────────────────────────────────────────

  pi.on("session_start", async () => {
    // Don't block session start on daemon startup; the tools await it when they need it.
    void ensureDaemonRunning();
  });

  pi.on("session_shutdown", async () => {
    await stopDaemon();
  });
}
