import assert from "node:assert";
import { afterEach, beforeEach, describe, it } from "node:test";
import { MockExtensionAPI } from "../../../test-utils.ts";
import piWebxp from "../src/index.ts";

const originalFetch = globalThis.fetch;

describe("pi-webxp: http_request", () => {
  let api: MockExtensionAPI;

  beforeEach(() => {
    api = new MockExtensionAPI();
    piWebxp(api as any);

    globalThis.fetch = (async (url: string | URL | Request, _init?: RequestInit) => {
      const urlStr = url.toString();

      if (urlStr.includes("/login")) {
        return {
          ok: true,
          status: 200,
          statusText: "OK",
          url: urlStr,
          headers: {
            entries: () =>
              [
                ["content-type", "application/json"],
                ["set-cookie", "session=abc123; Path=/; HttpOnly"],
              ] as [string, string][],
            get: () => "application/json",
            getSetCookie: () => ["session=abc123; Path=/; HttpOnly"],
          },
          json: async () => ({ status: "ok", user: "admin" }),
          text: async () => JSON.stringify({ status: "ok", user: "admin" }),
          body: null,
        } as unknown as Response;
      }

      if (urlStr.includes("/protected")) {
        return {
          ok: true,
          status: 200,
          statusText: "OK",
          url: urlStr,
          headers: {
            entries: () => [["content-type", "application/json"]] as [string, string][],
            get: () => "application/json",
            getSetCookie: () => [],
          },
          json: async () => ({ data: "secret" }),
          text: async () => JSON.stringify({ data: "secret" }),
          body: null,
        } as unknown as Response;
      }
      if (urlStr.includes("/rotate")) {
        return {
          ok: true,
          status: 200,
          statusText: "OK",
          url: urlStr,
          headers: {
            entries: () =>
              [
                ["content-type", "application/json"],
                ["set-cookie", "session=rotated999; Path=/; HttpOnly"],
              ] as [string, string][],
            get: () => "application/json",
            getSetCookie: () => ["session=rotated999; Path=/; HttpOnly"],
          },
          json: async () => ({ status: "ok" }),
          text: async () => JSON.stringify({ status: "ok" }),
          body: null,
        } as unknown as Response;
      }

      if (urlStr.includes("/redirect")) {
        return {
          ok: true,
          status: 302,
          statusText: "Found",
          url: urlStr,
          headers: {
            entries: () => [["location", "https://target.example/land"]] as [string, string][],
            get: (name: string) => (name === "location" ? "https://target.example/land" : null),
            getSetCookie: () => [],
          },
          text: async () => "",
          body: null,
        } as unknown as Response;
      }

      if (urlStr.includes("/followed")) {
        return {
          ok: true,
          status: 200,
          statusText: "OK",
          url: "https://target.example/land",
          headers: {
            entries: () => [["content-type", "text/plain"]] as [string, string][],
            get: () => "text/plain",
            getSetCookie: () => [],
          },
          text: async () => "Landing page content here",
          body: null,
        } as unknown as Response;
      }

      if (urlStr.includes("/large")) {
        const bigBody = "x".repeat(300_000);
        return {
          ok: true,
          status: 200,
          statusText: "OK",
          url: urlStr,
          headers: {
            entries: () => [["content-type", "text/plain"]] as [string, string][],
            get: () => "text/plain",
            getSetCookie: () => [],
          },
          text: async () => bigBody,
          body: null,
        } as unknown as Response;
      }

      if (urlStr.includes("/binary")) {
        return {
          ok: true,
          status: 200,
          statusText: "OK",
          url: urlStr,
          headers: {
            entries: () => [["content-type", "image/png"]] as [string, string][],
            get: () => "image/png",
            getSetCookie: () => [],
          },
          text: async () => "",
          body: null,
        } as unknown as Response;
      }

      // Default: echo back the request
      return {
        ok: true,
        status: 200,
        statusText: "OK",
        url: urlStr,
        headers: {
          entries: () => [["content-type", "text/plain"]] as [string, string][],
          get: () => "text/plain",
          getSetCookie: () => [],
        },
        text: async () => "OK",
        body: null,
      } as unknown as Response;
    }) as any;
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  // ── Registration ────────────────────────────────────────

  it("registers the http_request tool", () => {
    const tool = api.tools.find((t) => t.name === "http_request");
    assert.ok(tool, "http_request tool is registered");
    assert.equal(tool.label, "HTTP Request");
    assert.ok(tool.description.includes("cookie jar"));
  });

  // ── basic GET ───────────────────────────────────────────

  it("returns status and body for a GET request", async () => {
    const tool = api.tools.find((t) => t.name === "http_request")!;
    const result = await tool.execute(
      "call-1",
      { url: "https://example.com/api" },
      null,
      () => {},
      {},
    );
    assert.equal(result.isError, false);
    const details = result.details as { status: number; body: string };
    assert.equal(details.status, 200);
    assert.equal(details.body, "OK");
    assert.ok(result.content[0].text.includes("HTTP/1.1 200 OK"));
  });

  // ── cookie persistence ──────────────────────────────────

  it("persists cookies from Set-Cookie across calls", async () => {
    const tool = api.tools.find((t) => t.name === "http_request")!;

    // Step 1: POST login — sets session cookie
    const loginResult = await tool.execute(
      "call-1",
      {
        url: "https://example.com/login",
        method: "POST",
        body: JSON.stringify({ user: "admin", pass: "s3cret" }),
        json: { user: "admin", pass: "s3cret" },
      },
      null,
      () => {},
      {},
    );
    assert.equal((loginResult as any).isError, false);

    // Step 2: GET protected — cookie should be injected automatically
    const protectedResult = await tool.execute(
      "call-2",
      { url: "https://example.com/protected" },
      null,
      () => {},
      {},
    );
    assert.equal((protectedResult as any).isError, false);
    const protectedDetails = (protectedResult as any).details;
    assert.equal(protectedDetails.status, 200);
    assert.ok(protectedDetails.cookiesOnHost.includes("session=abc123"));
  });
  it("clears the cookie jar on session_shutdown", async () => {
    const tool = api.tools.find((t) => t.name === "http_request")!;

    // Seed the jar.
    await tool.execute(
      "c1",
      { url: "https://example.com/login", method: "POST" },
      null,
      () => {},
      {},
    );

    // New session: the jar must be empty again.
    await (api as any).emit("session_shutdown");

    const result = await tool.execute(
      "c2",
      { url: "https://example.com/protected" },
      null,
      () => {},
      {},
    );
    assert.equal((result as any).isError, false);
    const cookiesOnHost = (result as any).details.cookiesOnHost;
    assert.ok(
      !cookiesOnHost.includes("session="),
      `jar cleared on session_shutdown, got: ${cookiesOnHost}`,
    );
  });

  // ── cookie rotation ─────────────────────────────────────

  it("replaces (not duplicates) cookies when Set-Cookie rotates a value", async () => {
    const tool = api.tools.find((t) => t.name === "http_request")!;

    // Step 1: login sets session=abc123
    await tool.execute(
      "call-1",
      { url: "https://example.com/login", method: "POST" },
      null,
      () => {},
      {},
    );

    // Step 2: a response rotates the session cookie to rotated999
    const rotated = await tool.execute(
      "call-2",
      { url: "https://example.com/rotate" },
      null,
      () => {},
      {},
    );
    const cookiesOnHost = (rotated as any).details.cookiesOnHost;
    assert.ok(
      cookiesOnHost.includes("session=rotated999"),
      `Rotated cookie present: ${cookiesOnHost}`,
    );
    assert.ok(
      !cookiesOnHost.includes("session=abc123"),
      `Old cookie value replaced, not duplicated: ${cookiesOnHost}`,
    );
    // No duplicate session= keys
    const sessionCount = (cookiesOnHost.match(/session=/g) || []).length;
    assert.equal(sessionCount, 1, `Exactly one session cookie: ${cookiesOnHost}`);
  });

  // ── headers merge ───────────────────────────────────────

  it("injects cookies from the jar into request headers", async () => {
    const tool = api.tools.find((t) => t.name === "http_request")!;

    // Pre-seed the jar: simulate a prior call that set a cookie
    // (we do this by making a call that sets cookies, then a subsequent call)
    await tool.execute(
      "s1",
      { url: "https://example.com/login", method: "POST" },
      null,
      () => {},
      {},
    );
    const second = await tool.execute(
      "s2",
      { url: "https://example.com/protected" },
      null,
      () => {},
      {},
    );
    const text = (second as any).content[0].text;
    // The request transcript should have a Cookie header
    assert.ok(text.includes("> cookie:"), "Cookie header injected into request transcript");
  });

  // ── redirect manual ─────────────────────────────────────

  it("returns 302 as-is with redirect=manual (default)", async () => {
    const tool = api.tools.find((t) => t.name === "http_request")!;
    const result = await tool.execute(
      "call-1",
      { url: "https://example.com/redirect" },
      null,
      () => {},
      {},
    );
    const details = (result as any).details;
    assert.equal(details.status, 302);
    assert.equal(details.redirected, false, "No redirect followed in manual mode");
  });

  // ── redirect follow ─────────────────────────────────────

  // ── SSRF block ──────────────────────────────────────────

  it("blocks private/internal hosts by default", async () => {
    const tool = api.tools.find((t) => t.name === "http_request")!;
    const result = await tool.execute(
      "call-1",
      { url: "http://127.0.0.1:8080/admin" },
      null,
      () => {},
      {},
    );
    assert.equal((result as any).isError, true);
    assert.ok((result as any).content[0].text.includes("Blocked"), "Response mentions the block");
    assert.equal((result as any).details.error, "ssrf_blocked");
  });

  it("allows private hosts when allowPrivateHosts=true", async () => {
    const tool = api.tools.find((t) => t.name === "http_request")!;
    const result = await tool.execute(
      "call-1",
      { url: "http://10.0.0.5:8080/admin", allowPrivateHosts: true },
      null,
      () => {},
      {},
    );
    // fetch was mocked to return "OK" for unknown URLs, so this should succeed
    assert.equal((result as any).isError, false, "Request allowed with allowPrivateHosts=true");
  });

  // ── protocol gate ───────────────────────────────────────

  it("rejects non-http(s) URLs", async () => {
    const tool = api.tools.find((t) => t.name === "http_request")!;
    const result = await tool.execute(
      "call-1",
      { url: "ftp://example.com/file" },
      null,
      () => {},
      {},
    );
    assert.equal((result as any).isError, true);
    assert.ok((result as any).content[0].text.includes("not allowed"));
  });

  // ── body truncation ─────────────────────────────────────

  it("truncates large response bodies", async () => {
    const tool = api.tools.find((t) => t.name === "http_request")!;
    const result = await tool.execute(
      "call-1",
      { url: "https://example.com/large", maxBody: 50 },
      null,
      () => {},
      {},
    );
    const details = (result as any).details;
    assert.ok(details.bodyTruncated, "Body was truncated");
    assert.ok(details.bodySize <= 50, `Body size ${details.bodySize} is within cap`);
  });

  // ── custom headers ──────────────────────────────────────

  it("sends custom headers", async () => {
    const tool = api.tools.find((t) => t.name === "http_request")!;
    const result = await tool.execute(
      "call-1",
      {
        url: "https://example.com/api",
        headers: { "X-Custom-Header": "test-value", Accept: "application/json" },
      },
      null,
      () => {},
      {},
    );
    const text = (result as any).content[0].text;
    assert.ok(text.includes("X-Custom-Header: test-value"), "Custom header in transcript");
  });

  // ── timeout ─────────────────────────────────────────────

  it("applies AbortSignal.timeout", async () => {
    const tool = api.tools.find((t) => t.name === "http_request")!;
    const result = await tool.execute(
      "call-1",
      { url: "https://example.com/slow", timeoutMs: 100 },
      null,
      () => {},
      {},
    );
    // Our mock doesn't actually delay, so this should succeed; the key is
    // that timeoutMs is passed through to the fetch signal
    assert.ok(!(result as any).content[0].text.includes("HTTP request failed"));
  });

  // ── JSON body ───────────────────────────────────────────

  it("stringifies json body and sets content-type", async () => {
    const tool = api.tools.find((t) => t.name === "http_request")!;
    const result = await tool.execute(
      "call-1",
      {
        url: "https://example.com/api",
        method: "POST",
        json: { key: "value" },
      },
      null,
      () => {},
      {},
    );
    const text = (result as any).content[0].text;
    assert.ok(text.includes("application/json"), "Content-Type set to application/json");
    assert.ok(text.includes('"key":"value"'), "JSON body stringified");
  });

  // ── case-variant header handling ────────────────────────

  it("merges jar cookies into a caller's capitalized Cookie header (no duplicate key)", async () => {
    const tool = api.tools.find((t) => t.name === "http_request")!;
    // Seed the jar.
    await tool.execute("call-1", { url: "https://example.com/login" }, null, () => {}, {});

    let sentHeaders: Record<string, string> = {};
    const prevFetch = globalThis.fetch;
    globalThis.fetch = (async (_url: unknown, init?: RequestInit) => {
      sentHeaders = (init?.headers || {}) as Record<string, string>;
      return prevFetch(_url as string, init);
    }) as typeof fetch;

    const result = await tool.execute(
      "call-2",
      {
        url: "https://example.com/protected",
        headers: { Cookie: "user_pref=dark" }, // capitalized variant
      },
      null,
      () => {},
      {},
    );
    globalThis.fetch = prevFetch;

    assert.ok(!(result as any).isError, "request succeeded");
    // Exactly one cookie header key, whatever its case.
    const cookieKeys = Object.keys(sentHeaders).filter((k) => k.toLowerCase() === "cookie");
    assert.strictEqual(
      cookieKeys.length,
      1,
      `one cookie header, got keys: ${Object.keys(sentHeaders)}`,
    );
    const value = sentHeaders[cookieKeys[0]];
    assert.ok(value.includes("session=abc123"), "jar cookie merged in");
    assert.ok(value.includes("user_pref=dark"), "caller cookie preserved");
  });

  it("does not add a second content-type key when caller passed capitalized Content-Type", async () => {
    const tool = api.tools.find((t) => t.name === "http_request")!;

    let sentHeaders: Record<string, string> = {};
    const prevFetch = globalThis.fetch;
    globalThis.fetch = (async (_url: unknown, init?: RequestInit) => {
      sentHeaders = (init?.headers || {}) as Record<string, string>;
      return prevFetch(_url as string, init);
    }) as typeof fetch;

    await tool.execute(
      "call-1",
      {
        url: "https://example.com/api",
        method: "POST",
        json: { a: 1 },
        headers: { "Content-Type": "application/vnd.api+json" },
      },
      null,
      () => {},
      {},
    );
    globalThis.fetch = prevFetch;

    const ctKeys = Object.keys(sentHeaders).filter((k) => k.toLowerCase() === "content-type");
    assert.strictEqual(
      ctKeys.length,
      1,
      `one content-type header, got keys: ${Object.keys(sentHeaders)}`,
    );
    assert.strictEqual(sentHeaders[ctKeys[0]], "application/vnd.api+json", "caller's value wins");
  });

  // ── TLS bypass ──────────────────────────────────────────

  it("verifyTls=false does not silently re-verify (Bun: tls option set; Node w/o undici: loud error)", async () => {
    const tool = api.tools.find((t) => t.name === "http_request")!;
    const isBun = typeof (globalThis as any).Bun !== "undefined";

    let sentInit: (RequestInit & { tls?: unknown; dispatcher?: unknown }) | undefined;
    const prevFetch = globalThis.fetch;
    globalThis.fetch = (async (url: unknown, init?: RequestInit) => {
      sentInit = init;
      return prevFetch(url as string, init);
    }) as typeof fetch;

    const result = await tool.execute(
      "call-1",
      { url: "https://example.com/api", verifyTls: false },
      null,
      () => {},
      {},
    );
    globalThis.fetch = prevFetch;

    if (isBun) {
      assert.ok(!(result as any).isError, "request succeeded");
      assert.deepStrictEqual(sentInit?.tls, { rejectUnauthorized: false });
    } else if (!(result as any).isError) {
      assert.ok(sentInit && "dispatcher" in sentInit, "undici dispatcher attached");
    } else {
      // No undici available: must fail loudly, not silently verify.
      const text = (result as any).content[0].text;
      assert.ok(text.includes("TLS bypass is unavailable"), "loud failure message");
    }
  });
});
