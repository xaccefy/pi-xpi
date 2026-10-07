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

      if (urlStr.includes("/redirect-private")) {
        return {
          ok: true,
          status: 302,
          statusText: "Found",
          url: urlStr,
          headers: {
            entries: () => [["location", "http://127.0.0.1/admin"]] as [string, string][],
            get: (name: string) => (name === "location" ? "http://127.0.0.1/admin" : null),
            getSetCookie: () => [],
          },
          text: async () => "",
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
    assert.ok(!("isError" in result));
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
    assert.ok(!("isError" in (loginResult as any)));

    // Step 2: GET protected — cookie should be injected automatically
    const protectedResult = await tool.execute(
      "call-2",
      { url: "https://example.com/protected" },
      null,
      () => {},
      {},
    );
    assert.ok(!("isError" in (protectedResult as any)));
    const protectedDetails = (protectedResult as any).details;
    assert.equal(protectedDetails.status, 200);
    assert.ok(protectedDetails.cookiesOnHost.includes("session=abc123"));
  });
  // ── named sessions (multi-identity) ─────────────────────

  it("keeps named session jars isolated from each other and from the default jar", async () => {
    const tool = api.tools.find((t) => t.name === "http_request")!;

    // Login as attacker (named jar) — sets session cookie in 'attacker' only.
    await tool.execute(
      "s1",
      { url: "https://example.com/login", method: "POST", session: "attacker" },
      null,
      () => {},
      {},
    );

    // Default jar must NOT have the attacker cookie.
    const defaultResult = await tool.execute(
      "s2",
      { url: "https://example.com/protected" },
      null,
      () => {},
      {},
    );
    assert.equal((defaultResult as any).details.session, "default");
    assert.ok(
      !((defaultResult as any).details.cookiesOnHost as string).includes("session=abc123"),
      "default jar must not see attacker cookies",
    );

    // Victim jar must NOT have the attacker cookie either.
    const victimResult = await tool.execute(
      "s3",
      { url: "https://example.com/protected", session: "victim" },
      null,
      () => {},
      {},
    );
    assert.equal((victimResult as any).details.session, "victim");
    assert.ok(
      !((victimResult as any).details.cookiesOnHost as string).includes("session=abc123"),
      "victim jar must not see attacker cookies",
    );

    // Attacker jar still holds its own cookie.
    const attackerResult = await tool.execute(
      "s4",
      { url: "https://example.com/protected", session: "attacker" },
      null,
      () => {},
      {},
    );
    assert.ok(
      ((attackerResult as any).details.cookiesOnHost as string).includes("session=abc123"),
      "attacker jar must persist its own cookie",
    );
  });

  it("clears ALL named session jars on session_shutdown", async () => {
    const tool = api.tools.find((t) => t.name === "http_request")!;

    // Seed default jar
    await tool.execute(
      "c0",
      { url: "https://example.com/login", method: "POST" },
      null,
      () => {},
      {},
    );
    // Seed two named jars
    await tool.execute(
      "c1",
      { url: "https://example.com/login", method: "POST", session: "attacker" },
      null,
      () => {},
      {},
    );
    await tool.execute(
      "c1b",
      { url: "https://example.com/login", method: "POST", session: "victim" },
      null,
      () => {},
      {},
    );
    await (api as any).emit("session_shutdown");

    for (const sess of [undefined, "attacker", "victim"] as const) {
      const result = await tool.execute(
        "c2",
        { url: "https://example.com/protected", ...(sess ? { session: sess } : {}) },
        null,
        () => {},
        {},
      );
      assert.ok(
        !((result as any).details.cookiesOnHost as string).includes("session="),
        `jar ${sess ?? "default"} cleared on session_shutdown`,
      );
    }
  });

  it("rejects invalid session names and falls back to default for empty ones", async () => {
    const tool = api.tools.find((t) => t.name === "http_request")!;

    for (const bad of ["bad name", "a/b", "x".repeat(65)]) {
      await assert.rejects(
        tool.execute(
          "b1",
          { url: "https://example.com/protected", session: bad },
          null,
          () => {},
          {},
        ),
        /invalid session name|too long/,
      );
    }

    // Empty/whitespace names fall back to the default jar.
    const r = await tool.execute(
      "b2",
      { url: "https://example.com/login", method: "POST", session: "   " },
      null,
      () => {},
      {},
    );
    assert.equal((r as any).details.session, "default");
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
    assert.ok(!("isError" in (result as any)));
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
    assert.ok(text.includes("> Cookie:"), "Cookie header injected into request transcript");
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

  it("blocks private/internal redirect hops by default", async () => {
    const tool = api.tools.find((t) => t.name === "http_request")!;
    await assert.rejects(
      () =>
        tool.execute(
          "call-1",
          { url: "https://example.com/redirect-private", redirect: "follow" },
          null,
          () => {},
          {},
        ),
      /private\/internal host/,
    );
  });

  it("follows a public redirect and applies safe cross-origin method/header rules", async () => {
    const tool = api.tools.find((t) => t.name === "http_request")!;
    const calls: {
      url: string;
      method?: string;
      body?: BodyInit | null;
      headers: Record<string, string>;
    }[] = [];
    const prevFetch = globalThis.fetch;
    globalThis.fetch = (async (url: string | URL | Request, init?: RequestInit) => {
      calls.push({
        url: url.toString(),
        method: init?.method,
        body: init?.body,
        headers: { ...((init?.headers as Record<string, string> | undefined) ?? {}) },
      });
      return prevFetch(url, init);
    }) as typeof fetch;

    const result = await tool.execute(
      "call-follow",
      {
        url: "https://example.com/redirect",
        method: "POST",
        body: "sensitive=request-body",
        headers: {
          Authorization: "Bearer must-not-cross-origin",
          "Content-Type": "application/x-www-form-urlencoded",
        },
        redirect: "follow",
      },
      null,
      () => {},
      {},
    );
    globalThis.fetch = prevFetch;

    const details = (result as any).details;
    assert.equal(details.status, 200);
    assert.equal(details.finalUrl, "https://target.example/land");
    assert.equal(details.redirected, true);
    assert.equal(details.redirectChain.length, 1);
    assert.equal(calls.length, 2);
    assert.equal(calls[1].method, "GET", "POST + 302 becomes GET");
    assert.equal(calls[1].body, undefined, "redirected GET does not retain the request body");
    assert.ok(
      !Object.keys(calls[1].headers).some((name) => name.toLowerCase() === "authorization"),
      "cross-origin redirect strips Authorization",
    );
    assert.ok(
      !Object.keys(calls[1].headers).some((name) => name.toLowerCase() === "content-type"),
      "GET redirect strips the stale entity content type",
    );
  });

  // ── SSRF block ──────────────────────────────────────────

  it("blocks private/internal hosts by default", async () => {
    const tool = api.tools.find((t) => t.name === "http_request")!;
    await assert.rejects(
      () => tool.execute("call-1", { url: "http://127.0.0.1:8080/admin" }, null, () => {}, {}),
      /private\/internal host/,
    );
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
    assert.ok(!("isError" in (result as any)), "Request allowed with allowPrivateHosts=true");
  });

  // ── protocol gate ───────────────────────────────────────

  it("rejects non-http(s) URLs", async () => {
    const tool = api.tools.find((t) => t.name === "http_request")!;
    await assert.rejects(
      () => tool.execute("call-1", { url: "ftp://example.com/file" }, null, () => {}, {}),
      /not allowed/,
    );
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

  it("treats a caller's capitalized Cookie header as authoritative", async () => {
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

    assert.ok(!("isError" in (result as any)), "request succeeded");
    // Exactly one cookie header key, whatever its case.
    const cookieKeys = Object.keys(sentHeaders).filter((k) => k.toLowerCase() === "cookie");
    assert.strictEqual(
      cookieKeys.length,
      1,
      `one cookie header, got keys: ${Object.keys(sentHeaders)}`,
    );
    const value = sentHeaders[cookieKeys[0]];
    assert.ok(
      !value.includes("session=abc123"),
      "caller Cookie overrides jar on the first request",
    );
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

  it("verifyTls=false wires the TLS bypass on the real request path", async () => {
    const tool = api.tools.find((t) => t.name === "http_request")!;

    let sentInit: (RequestInit & { tls?: unknown; dispatcher?: unknown }) | undefined;
    const prevFetch = globalThis.fetch;
    globalThis.fetch = (async (url: unknown, init?: RequestInit) => {
      sentInit = init;
      return prevFetch(url as string, init);
    }) as typeof fetch;

    await tool.execute(
      "call-1",
      { url: "https://example.com/api", verifyTls: false },
      null,
      () => {},
      {},
    );
    globalThis.fetch = prevFetch;

    // Bun's fetch ignores the dispatcher, so the bypass must ride the `tls`
    // init option — assert it is actually set when verifyTls:false.
    const bunTls = (sentInit as any)?.tls;
    assert.ok(
      bunTls && bunTls.rejectUnauthorized === false,
      `tls bypass missing on request init: ${JSON.stringify(sentInit)}`,
    );
    // Node path: the guarded dispatcher must ALSO carry rejectUnauthorized:false.
    assert.ok(sentInit && "dispatcher" in sentInit, "guarded dispatcher attached (Node path)");

    // Default (verifyTls unset) must NOT set the tls bypass.
    sentInit = undefined;
    globalThis.fetch = (async (url: unknown, init?: RequestInit) => {
      sentInit = init;
      return prevFetch(url as string, init);
    }) as typeof fetch;
    await tool.execute("call-2", { url: "https://example.com/api" }, null, () => {}, {});
    globalThis.fetch = prevFetch;
    assert.strictEqual((sentInit as any)?.tls, undefined, "no TLS bypass by default");
  });
});
