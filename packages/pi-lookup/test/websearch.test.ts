import assert from "node:assert";
import { afterEach, beforeEach, describe, it } from "node:test";
import { MockExtensionAPI } from "../../../test-utils.ts";
import piLookup from "../src/index.ts";

// Save original global fetch
const originalFetch = globalThis.fetch;

describe("pi-lookup tool tests", () => {
  beforeEach(() => {
    globalThis.fetch = (async (url: string | URL | Request, init?: RequestInit) => {
      const urlStr = url.toString();

      if (urlStr.endsWith("/health")) {
        return {
          ok: true,
          json: async () => ({ status: "ok", data: { daemon: "running" } }),
        } as Response;
      }

      if (urlStr.endsWith("/search")) {
        const body = JSON.parse((init?.body as string) || "{}");
        return {
          ok: true,
          json: async () => ({
            status: "ok",
            data: {
              query: body.query,
              results: [
                {
                  title: "CVE-2024-1234 Detail",
                  url: "https://nvd.nist.gov/vuln/detail/CVE-2024-1234",
                  content: "A buffer overflow vulnerability in target...",
                },
              ],
            },
          }),
        } as Response;
      }

      if (urlStr.endsWith("/fetch-web") || urlStr.endsWith("/fetch-github-readme")) {
        return {
          ok: true,
          json: async () => ({
            status: "ok",
            data: {
              url: "https://awiki.ai",
              markdown: "# Mocked Markdown Content",
            },
          }),
        } as Response;
      }

      return {
        ok: false,
        status: 404,
      } as Response;
    }) as any;
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it("registers web_search and web_fetch tools and calls mock daemon endpoints", async () => {
    const pi = new MockExtensionAPI();
    piLookup(pi as any);

    // Assert tools are registered
    const searchTool = pi.tools.find((t) => t.name === "web_search");
    const fetchTool = pi.tools.find((t) => t.name === "web_fetch");
    assert.ok(searchTool);
    assert.ok(fetchTool);

    // Call web_search
    const searchResult = await searchTool.execute(
      "call-1",
      { query: "CVE-2024-1234" },
      null,
      null,
      null,
    );
    assert.ok(searchResult.details.results.length > 0);
    assert.strictEqual(searchResult.details.results[0].title, "CVE-2024-1234 Detail");
    assert.ok(searchResult.content[0].text.includes("CVE-2024-1234 Detail"));

    // Call web_fetch
    const fetchResult = await fetchTool.execute(
      "call-2",
      { url: "https://github.com/Aas-ee/open-webSearch" },
      null,
      null,
      null,
    );
    assert.strictEqual(fetchResult.details.metadata.markdown, "# Mocked Markdown Content");
    assert.strictEqual(fetchResult.content[0].text, "# Mocked Markdown Content");
  });

  it("retries fetchWithRetry once on a transient 500 then succeeds", async () => {
    const pi = new MockExtensionAPI();
    piLookup(pi as any);
    const searchTool = pi.tools.find((t) => t.name === "web_search");

    let searchCalls = 0;
    globalThis.fetch = (async (url: string | URL | Request, init?: RequestInit) => {
      const urlStr = url.toString();
      if (urlStr.endsWith("/health")) {
        return {
          ok: true,
          json: async () => ({ status: "ok", data: { daemon: "running" } }),
        } as Response;
      }
      if (urlStr.endsWith("/search")) {
        searchCalls++;
        if (searchCalls === 1) {
          return { ok: false, status: 500, json: async () => ({}) } as Response;
        }
        const body = JSON.parse((init?.body as string) || "{}");
        return {
          ok: true,
          status: 200,
          json: async () => ({
            status: "ok",
            data: {
              query: body.query,
              results: [{ title: "Retry OK", url: "https://e/r", content: "x" }],
            },
          }),
        } as Response;
      }
      return { ok: false, status: 404 } as Response;
    }) as any;

    const result = await searchTool.execute("call-1", { query: "retryme" }, null, null, null);
    assert.strictEqual(searchCalls, 2); // initial 500 + one retry
    assert.strictEqual(result.details.results[0].title, "Retry OK");
  });

  it("session_start does not block on daemon startup", async () => {
    const pi = new MockExtensionAPI();
    piLookup(pi as any);

    // Make the daemon health check hang forever; any `await ensureDaemonRunning()`
    // would block. The handler uses `void ensureDaemonRunning()`, so session_start
    // must resolve quickly regardless.
    globalThis.fetch = (async (url: string | URL | Request) => {
      const urlStr = url.toString();
      if (urlStr.endsWith("/health")) {
        return new Promise<Response>(() => {}); // never resolves
      }
      return { ok: true, json: async () => ({ status: "ok", data: {} }) } as Response;
    }) as any;

    const start = Date.now();
    await Promise.race([
      pi.emit("session_start", {}, {}),
      new Promise((_, reject) =>
        setTimeout(() => reject(new Error("session_start blocked on daemon")), 1000),
      ),
    ]);
    assert.ok(Date.now() - start < 1000, "session_start should not await daemon startup");
  });
});
