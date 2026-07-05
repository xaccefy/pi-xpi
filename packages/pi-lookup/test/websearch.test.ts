import { afterEach, beforeEach, describe, it } from "node:test";
import assert from "node:assert";

import piLookup from "../src/index.ts";

// Dummy Mock of Pi Extension API
class MockExtensionAPI {
  tools: any[] = [];
  events: Record<string, Function[]> = {};

  registerTool(spec: any) {
    this.tools.push(spec);
  }

  on(event: string, handler: Function) {
    if (!this.events[event]) this.events[event] = [];
    this.events[event].push(handler);
  }

  async emit(event: string, ...args: any[]) {
    const handlers = this.events[event] || [];
    for (const h of handlers) {
      await h(...args);
    }
  }
}

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
      null
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
      null
    );
    assert.strictEqual(fetchResult.details.metadata.markdown, "# Mocked Markdown Content");
    assert.strictEqual(fetchResult.content[0].text, "# Mocked Markdown Content");
  });
});
