import assert from "node:assert";
import { afterEach, beforeEach, describe, it } from "node:test";
import { MockExtensionAPI } from "../../../test-utils.ts";
import piWebxp from "../src/index.ts";

// Save original global fetch
const originalFetch = globalThis.fetch;

describe("pi-webxp: web_search/web_fetch", () => {
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
    piWebxp(pi as any);

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

  it("routes github.com hosts to /fetch-github-readme, everything else to /fetch-web", async () => {
    const pi = new MockExtensionAPI();
    piWebxp(pi as any);
    const fetchTool = pi.tools.find((t) => t.name === "web_fetch");
    assert.ok(fetchTool);

    const hitEndpoints: string[] = [];
    globalThis.fetch = (async (url: string | URL | Request) => {
      const urlStr = url.toString();
      const path = urlStr.slice(urlStr.indexOf("/", "http://x".length)); // everything after host
      if (urlStr.endsWith("/health")) {
        return { ok: true, json: async () => ({ status: "ok", data: {} }) } as Response;
      }
      if (urlStr.endsWith("/fetch-github-readme") || urlStr.endsWith("/fetch-web")) {
        hitEndpoints.push(path);
        return {
          ok: true,
          json: async () => ({ status: "ok", data: { url: "", markdown: "x" } }),
        } as Response;
      }
      throw new Error(`unexpected endpoint: ${urlStr}`);
    }) as any;

    await fetchTool.execute("c1", { url: "https://github.com/owner/repo" }, null, null, null);
    await fetchTool.execute("c2", { url: "https://gist.github.com/user/id" }, null, null, null);
    await fetchTool.execute("c3", { url: "https://example.com/page" }, null, null, null);
    // Substring in the query string must NOT trigger the GitHub route.
    await fetchTool.execute("c4", { url: "https://evil.example/?q=github.com" }, null, null, null);

    assert.deepStrictEqual(hitEndpoints, [
      "/fetch-github-readme",
      "/fetch-github-readme",
      "/fetch-web",
      "/fetch-web",
    ]);
  });

  it("retries fetchWithRetry once on a transient 500 then succeeds", async () => {
    const pi = new MockExtensionAPI();
    piWebxp(pi as any);
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

  it("web_fetch blocks private/internal hosts (SSRF guard)", async () => {
    const pi = new MockExtensionAPI();
    piWebxp(pi as any);
    const fetchTool = pi.tools.find((t) => t.name === "web_fetch");
    await assert.rejects(
      () => fetchTool.execute("c1", { url: "http://127.0.0.1:8080/admin" }, null, null, null),
      /private\/internal host/,
    );
    await assert.rejects(
      () => fetchTool.execute("c2", { url: "http://[::ffff:10.0.0.1]/x" }, null, null, null),
      /private\/internal host/,
    );
  });

  it("web_fetch keeps thin SPA shells inside the daemon result", async () => {
    globalThis.fetch = (async (url: string | URL | Request) => {
      const urlStr = url.toString();
      if (urlStr.endsWith("/health")) {
        return {
          ok: true,
          json: async () => ({ status: "ok", data: { daemon: "running" } }),
        } as Response;
      }
      if (urlStr.endsWith("/fetch-web")) {
        return {
          ok: true,
          json: async () => ({
            status: "ok",
            data: {
              contentType: "text/html; charset=utf-8",
              retrievalMethod: "request",
              content: "Loading...",
            },
          }),
        } as Response;
      }
      return { ok: false, status: 404 } as Response;
    }) as any;

    const pi = new MockExtensionAPI();
    piWebxp(pi as any);
    const fetchTool = pi.tools.find((t) => t.name === "web_fetch");
    assert.ok(fetchTool);

    const result = await fetchTool.execute(
      "call-spa",
      { url: "https://example.com/app" },
      null,
      null,
      null,
    );
    assert.strictEqual(result.content[0].text, "Loading...");
    assert.strictEqual(result.details.renderedBy, undefined);
  });

  it("session_start does not start or probe the daemon", async () => {
    const pi = new MockExtensionAPI();
    piWebxp(pi as any);

    let healthChecks = 0;
    globalThis.fetch = (async (url: string | URL | Request) => {
      const urlStr = url.toString();
      if (urlStr.endsWith("/health")) {
        healthChecks++;
        throw new Error("session_start should not touch daemon health");
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
    assert.strictEqual(healthChecks, 0);
  });
});
