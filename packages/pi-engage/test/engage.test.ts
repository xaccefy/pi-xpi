import assert from "node:assert";
import { mkdtempSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, it } from "node:test";
import { MockExtensionAPI } from "../../../test-utils.ts";
import { buildToolArgs, Engage, headersToFlags } from "../src/engage.ts";
import { DisposableInbox } from "../src/inbox.ts";
import registerEngage from "../src/index.ts";
import type { AuthSession } from "../src/store.ts";
import { clearSessions, getSession, listSessions, saveSession } from "../src/store.ts";
import type { FetchImpl } from "../src/types.ts";

// Hermetic persistence: never touch the real ~/.pi/xpi-engage from tests —
// clearSessions() would delete actual stored sessions.
const TEST_ENGAGE_DIR = mkdtempSync(join(tmpdir(), "pi-engage-test-"));
process.env.PI_ENGAGE_DIR = TEST_ENGAGE_DIR;
process.on("exit", () => rmSync(TEST_ENGAGE_DIR, { recursive: true, force: true }));

function fakeFetch(
  status = 200,
  body = '<html><body><a href="/a">a</a><a href="/b">b</a><a href="https://evil.example.com/x">x</a></body></html>',
) {
  return async (_url: string | URL) =>
    ({
      status,
      headers: new Headers({ "content-type": "text/html" }),
      text: async () => body,
    }) as unknown as Response;
}

function fakeExec() {
  return async (_tool: string, _args: string[]) => ({ code: 0, stdout: "ok", stderr: "" });
}

function cookieSession(over: Partial<AuthSession> = {}): AuthSession {
  return {
    id: "s1",
    label: "shop",
    mode: "cookie",
    cookie: "session=abc123",
    target: "shop.example.com",
    createdAt: 0,
    updatedAt: 0,
    ...over,
  };
}

describe("pi-engage", () => {
  let pi: MockExtensionAPI;

  beforeEach(() => {
    pi = new MockExtensionAPI();
    registerEngage(pi as never);
    clearSessions();
  });

  afterEach(() => clearSessions());

  it("registers the engage tool and /engage command", () => {
    assert.strictEqual(pi.tools.length, 1);
    assert.strictEqual(pi.tools[0].name, "engage");
    assert.ok((pi.commands as Record<string, unknown>).engage, "/engage command registered");
  });

  it("adds a cookie session and resolves it via token", async () => {
    const tool = pi.tools[0];
    const add = await tool.execute("c1", {
      action: "add",
      id: "s1",
      label: "shop",
      target: "shop.example.com",
      mode: "cookie",
      cookie: "session=abc123",
    });
    assert.strictEqual((add as { isError?: boolean }).isError, undefined);

    const token = await tool.execute("c3", { action: "token", id: "s1" });
    assert.strictEqual((token as { isError?: boolean }).isError, undefined);
    const details = (token as { details: { headers: Record<string, string>; curlExample: string } })
      .details;
    assert.strictEqual(details.headers.Cookie, "session=abc123");
    assert.match(details.curlExample, /--cookie/);
  });

  it("rejects adding a session without a mode", async () => {
    const tool = pi.tools[0];
    const res = await tool.execute("c1", { action: "add", id: "s1", label: "shop" });
    assert.strictEqual((res as { isError: boolean }).isError, true);
  });

  it("rejects cookie session without cookie value", async () => {
    const tool = pi.tools[0];
    const res = await tool.execute("c1", {
      action: "add",
      id: "s1",
      mode: "cookie",
      target: "shop.example.com",
    });
    assert.strictEqual((res as { isError: boolean }).isError, true);
    assert.match(
      (res as { content: { text: string }[] }).content[0].text,
      /cookie mode requires a cookie/,
    );
  });

  it("rejects oauth session without tokenUrl", async () => {
    const tool = pi.tools[0];
    const res = await tool.execute("c1", {
      action: "add",
      id: "s2",
      mode: "oauth-client-credentials",
      clientId: "cid",
      clientSecret: "sec",
    });
    assert.strictEqual((res as { isError: boolean }).isError, true);
    assert.match((res as { content: { text: string }[] }).content[0].text, /requires tokenUrl/);
  });

  it("rejects mtls session without certPath", async () => {
    const tool = pi.tools[0];
    const res = await tool.execute("c1", {
      action: "add",
      id: "s3",
      mode: "mtls",
    });
    assert.strictEqual((res as { isError: boolean }).isError, true);
    assert.match((res as { content: { text: string }[] }).content[0].text, /requires certPath/);
  });
});

describe("Engage class (pdtm bridge)", () => {
  afterEach(() => clearSessions());

  it("run injects auth into httpx", async () => {
    const e = new Engage({ execImpl: fakeExec(), fetchImpl: fakeFetch() });
    e.addSession(cookieSession());
    const r = await e.run({ tool: "httpx", url: "https://shop.example.com", sessionId: "s1" });
    assert.strictEqual(r.isError, undefined);
    const d = r.details as { command: string; exitCode: number };
    assert.match(d.command, /-H 'Cookie: session=abc123'/);
    assert.match(d.command, /-u https:\/\/shop.example.com/);
  });

  it("run uses a positional URL for curl", async () => {
    const e = new Engage({ execImpl: fakeExec(), fetchImpl: fakeFetch() });
    e.addSession(cookieSession());
    const r = await e.run({ tool: "curl", url: "https://shop.example.com/a", sessionId: "s1" });
    const d = r.details as { command: string };
    assert.match(d.command, /curl/);
    assert.match(d.command, /-H 'Cookie: session=abc123'/);
    assert.match(d.command, /https:\/\/shop.example.com\/a/);
  });

  it("send issues an authenticated request and returns a curl command", async () => {
    const e = new Engage({ fetchImpl: fakeFetch(200, "hello") });
    e.addSession(cookieSession());
    const r = await e.send({ url: "https://shop.example.com/a", sessionId: "s1" });
    assert.strictEqual(r.isError, undefined);
    const d = r.details as { status: number; curl: string };
    assert.strictEqual(d.status, 200);
    assert.match(d.curl, /curl -X GET/);
    assert.match(d.curl, /-H 'Cookie: session=abc123'/);
  });

  it("send curl command includes body", async () => {
    const e = new Engage({ fetchImpl: fakeFetch(200, "ok") });
    e.addSession(cookieSession());
    const r = await e.send({
      url: "https://shop.example.com/api",
      sessionId: "s1",
      method: "POST",
      body: '{"hello":"world"}',
    });
    const d = r.details as { curl: string };
    assert.match(d.curl, /-d '{"hello":"world"}'/);
  });

  it("send curl escapes single quotes in header values", async () => {
    const e = new Engage({ fetchImpl: fakeFetch(200, "ok") });
    e.addSession(cookieSession());
    const r = await e.send({
      url: "https://shop.example.com/a",
      sessionId: "s1",
      headers: { "X-Custom": "val'with'quote" },
    });
    const d = r.details as { curl: string };
    // POSIX single-quote escaping: '...' -> '...'\''...'
    assert.match(d.curl, /val'\\''with'\\''quote/);
  });

  it("spider stays in scope", async () => {
    const e = new Engage({ fetchImpl: fakeFetch() });
    e.addSession(cookieSession({ cookie: "x=1" }));
    const r = await e.spider({
      url: "https://shop.example.com/",
      sessionId: "s1",
      inScope: ["shop.example.com"],
      depth: 1,
    });
    assert.strictEqual(r.isError, undefined);
    const visited = (r.details as { visited: string[] }).visited;
    assert.ok(
      visited.some((u) => u.includes("/a")),
      "should crawl /a",
    );
    assert.ok(
      !visited.some((u) => u.includes("evil.example.com")),
      "should skip out-of-scope host",
    );
  });

  it("spider respects depth limit", async () => {
    const e = new Engage({ fetchImpl: fakeFetch() });
    e.addSession(cookieSession({ cookie: "x=1" }));
    const r = await e.spider({
      url: "https://shop.example.com/",
      sessionId: "s1",
      inScope: ["shop.example.com"],
      depth: 0,
    });
    const visited = (r.details as { visited: string[] }).visited;
    // depth: 0 means only the seed URL is fetched, no links followed.
    assert.strictEqual(visited.length, 1);
    assert.ok(visited[0].includes("shop.example.com"));
  });

  it("spider resolves relative links against the page they appear on", async () => {
    // Regression: links were resolved against the SEED url, so "page" found on
    // /dir/ became /page instead of /dir/page.
    const pages: Record<string, string> = {
      "https://shop.example.com/": '<a href="/dir/">dir</a>',
      "https://shop.example.com/dir/": '<a href="page">page</a>',
      "https://shop.example.com/dir/page": "leaf",
    };
    const fetchImpl = (async (url: string | URL) => {
      const u = String(url);
      return {
        status: pages[u] === undefined ? 404 : 200,
        headers: new Headers({ "content-type": "text/html" }),
        text: async () => pages[u] ?? "not found",
      } as unknown as Response;
    }) as FetchImpl;
    const e = new Engage({ fetchImpl });
    e.addSession(cookieSession({ cookie: "x=1" }));
    const r = await e.spider({ url: "https://shop.example.com/", sessionId: "s1", depth: 2 });
    assert.strictEqual(r.isError, undefined);
    const visited = (r.details as { visited: string[] }).visited;
    assert.ok(
      visited.includes("https://shop.example.com/dir/page"),
      `expected /dir/page in ${JSON.stringify(visited)}`,
    );
    assert.ok(
      !visited.includes("https://shop.example.com/page"),
      "must not resolve against the seed URL",
    );
  });

  it("scan errors when the named session does not exist", async () => {
    const e = new Engage({ fetchImpl: fakeFetch() });
    const r = await e.scan({ url: "https://shop.example.com/", sessionId: "ghost" });
    assert.strictEqual(r.isError, true);
  });

  it("scan runs a passive header check", async () => {
    const e = new Engage({ execImpl: fakeExec(), fetchImpl: fakeFetch(200, "<html></html>") });
    e.addSession(cookieSession({ cookie: "x=1" }));
    const r = await e.scan({ url: "https://shop.example.com/", sessionId: "s1" });
    assert.strictEqual(r.isError, undefined);
    const d = r.details as { missing: string[] };
    assert.deepStrictEqual(d.missing, [
      "content-security-policy",
      "strict-transport-security",
      "x-frame-options",
      "x-content-type-options",
    ]);
  });
});

describe("store persistence", () => {
  afterEach(() => clearSessions());

  it("writes session files with 0600 perms (credentials are not world-readable)", () => {
    saveSession(cookieSession({ id: "perm-test" }));
    const mode = statSync(join(TEST_ENGAGE_DIR, "perm-test.json")).mode & 0o777;
    assert.strictEqual(mode, 0o600);
  });

  it("signup combines ALL Set-Cookie pairs into one Cookie header", async () => {
    // Regression: only the first Set-Cookie was captured, losing the real
    // session cookie when a tracking cookie came first.
    const fetchImpl = (async () =>
      ({
        ok: true,
        status: 200,
        headers: {
          getSetCookie: () => ["track=1; Path=/", "sess=abc; Path=/; HttpOnly"],
          get: (_k: string) => null,
        },
        text: async () => "{}",
      }) as unknown as Response) as FetchImpl;
    const e = new Engage({ fetchImpl });
    const r = await e.signup({
      signupUrl: "https://shop.example.com/register",
      verifyStrategy: "none",
      target: "shop.example.com",
    });
    assert.strictEqual(r.isError, undefined);
    const sessionId = (r.details as { sessionId: string }).sessionId;
    const s = getSession(sessionId);
    assert.strictEqual(s?.cookie, "track=1; sess=abc");
  });
});

describe("auth flag helpers", () => {
  it("headersToFlags emits -H for cookie and --cert for mtls", () => {
    const cookieFlags = headersToFlags({ Cookie: "session=abc" }, "cookie");
    assert.deepStrictEqual(cookieFlags, ["-H", "Cookie: session=abc"]);

    const mtls = cookieSession({
      mode: "mtls",
      certPath: "/c/agent.pem",
      keyPath: "/c/agent.key",
      caPath: "/c/ca.pem",
    });
    const mtlsFlags = headersToFlags({}, "mtls", mtls);
    assert.ok(mtlsFlags.includes("--cert"));
    assert.ok(mtlsFlags.includes("/c/agent.pem"));
    assert.ok(mtlsFlags.includes("--key"));
    assert.ok(mtlsFlags.includes("--cacert"));
  });

  it("buildToolArgs puts curl's target positional, others use -u", () => {
    assert.deepStrictEqual(buildToolArgs("curl", "https://t", ["-H", "A: B"], []), [
      "-H",
      "A: B",
      "https://t",
    ]);
    assert.deepStrictEqual(buildToolArgs("httpx", "https://t", ["-H", "A: B"], ["-silent"]), [
      "-H",
      "A: B",
      "-u",
      "https://t",
      "-silent",
    ]);
  });
});

describe("DisposableInbox + signup", () => {
  function fakeFetchRouter(opts: { leak?: boolean; cookie?: boolean } = {}) {
    const fetchImpl: FetchImpl = async (input: string | URL, init?: RequestInit) => {
      const url = String(input);
      const method = init?.method ?? "GET";
      if (url.endsWith("/domains")) {
        return jsonResp({ "hydra:member": [{ domain: "mail.tm" }] });
      }
      if (url.endsWith("/accounts")) {
        return jsonResp({ id: "a1", address: "x@mail.tm" });
      }
      if (url.endsWith("/token")) {
        return jsonResp({ token: "TOK" });
      }
      if (url.endsWith("/messages") && method === "GET") {
        return jsonResp({
          "hydra:member": [
            {
              id: "m1",
              subject: "Verify",
              text: "confirm https://target.test/verify?t=abc",
              html: "",
            },
          ],
        });
      }
      if (/\/messages\/m1$/.test(url)) {
        return jsonResp({
          id: "m1",
          subject: "Verify",
          text: "confirm https://target.test/verify?t=abc",
          html: "",
        });
      }
      if (url.endsWith("/register")) {
        if (opts.cookie) {
          return withCookieResp(
            "session=auto123",
            opts.leak ? "see https://target.test/verify?t=leak" : "",
          );
        }
        return textResp(200, opts.leak ? "verify at https://target.test/verify?t=leak" : "welcome");
      }
      if (url.includes("/verify")) {
        return textResp(200, "verified");
      }
      return textResp(200, "ok");
    };
    return { fetchImpl };
  }

  function jsonResp(body: unknown): Response {
    return {
      status: 200,
      ok: true,
      headers: new Headers({ "content-type": "application/json" }),
      json: async () => body,
      text: async () => JSON.stringify(body),
    } as unknown as Response;
  }
  function textResp(status: number, body: string): Response {
    return {
      status,
      ok: status >= 200 && status < 300,
      headers: new Headers({ "content-type": "text/plain" }),
      text: async () => body,
      json: async () => ({}),
    } as unknown as Response;
  }
  function withCookieResp(cookie: string, body: string): Response {
    return {
      status: 200,
      ok: true,
      headers: { get: () => null, getSetCookie: () => [cookie] } as unknown as Headers,
      text: async () => body,
      json: async () => ({}),
    } as unknown as Response;
  }

  it("DisposableInbox creates an inbox and extracts a verification link", async () => {
    const { fetchImpl } = fakeFetchRouter();
    const inbox = await DisposableInbox.create(fetchImpl);
    assert.match(inbox.address, /@mail\.tm$/);
    const msg = await inbox.waitForMessage(() => true);
    assert.ok(msg, "message received");
    const link = DisposableInbox.extractVerificationLink(msg!);
    assert.strictEqual(link, "https://target.test/verify?t=abc");
  });

  it("signup verifies via disposable inbox and stores a cookie session", async () => {
    const { fetchImpl } = fakeFetchRouter({ cookie: true });
    const e = new Engage({ fetchImpl, now: () => 0 });
    const r = await e.signup({
      signupUrl: "https://target.test/register",
      target: "target.test",
      verifyStrategy: "inbox",
    });
    assert.strictEqual(r.isError, undefined);
    const d = r.details as { verified: boolean; mode: string; sessionId: string };
    assert.strictEqual(d.verified, true);
    assert.strictEqual(d.mode, "cookie");
    const stored = getSession(d.sessionId);
    assert.ok(stored, "session persisted");
    assert.strictEqual(stored!.cookie, "session=auto123");
  });

  it("signup verifies from a token leaked in the signup response", async () => {
    const { fetchImpl } = fakeFetchRouter({ leak: true });
    const e = new Engage({ fetchImpl, now: () => 0 });
    const r = await e.signup({
      signupUrl: "https://target.test/register",
      target: "target.test",
      verifyStrategy: "response",
    });
    assert.strictEqual(r.isError, undefined);
    const d = r.details as { verified: boolean };
    assert.strictEqual(d.verified, true);
  });

  it("signup with strategy none skips verification and still creates a session", async () => {
    const { fetchImpl } = fakeFetchRouter({ cookie: true });
    const e = new Engage({ fetchImpl, now: () => 0 });
    const r = await e.signup({
      signupUrl: "https://target.test/register",
      target: "target.test",
      verifyStrategy: "none",
    });
    const d = r.details as { verified: boolean; sessionId: string };
    assert.strictEqual(d.verified, false);
    assert.ok(getSession(d.sessionId));
  });

  it("rejects signup without a signupUrl", async () => {
    const e = new Engage({});
    const r = await e.signup({ target: "target.test" });
    assert.strictEqual(r.isError, true);
  });

  it("reports a false positive as rejected when the target returns an app-level error", async () => {
    const fetchImpl: FetchImpl = async (input: string | URL) => {
      if (String(input).endsWith("/register")) {
        return textResp(
          200,
          JSON.stringify({
            ResponseStatus: { Ack: "Failure", Errors: [{ Message: "captcha required" }] },
          }),
        );
      }
      return textResp(200, "ok");
    };
    const e = new Engage({ fetchImpl, now: () => 0 });
    clearSessions();
    const r = await e.signup({ signupUrl: "https://target.test/register", target: "target.test" });
    assert.strictEqual(r.isError, true);
    const d = r.details as { registered: boolean; reason: string };
    assert.strictEqual(d.registered, false);
    assert.match(d.reason, /captcha required/);
    assert.strictEqual(listSessions().length, 0, "no session stored on rejection");
  });

  it("rejects signup on an HTTP error status", async () => {
    const fetchImpl: FetchImpl = async (input: string | URL) => {
      if (String(input).endsWith("/register")) return textResp(400, "bad request");
      return textResp(200, "ok");
    };
    const e = new Engage({ fetchImpl, now: () => 0 });
    const r = await e.signup({ signupUrl: "https://target.test/register", target: "target.test" });
    assert.strictEqual(r.isError, true);
    assert.strictEqual((r.details as { registered: boolean }).registered, false);
  });

  it("marks a registered-but-unverified account as unconfirmed, not success", async () => {
    // /register accepts (HTTP 200, no app error) but no verification email ever arrives.
    const fetchImpl: FetchImpl = async (input: string | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/domains")) return jsonResp({ "hydra:member": [{ domain: "mail.tm" }] });
      if (url.endsWith("/accounts")) return jsonResp({ id: "a1", address: "x@mail.tm" });
      if (url.endsWith("/token")) return jsonResp({ token: "TOK" });
      if (url.endsWith("/messages") && (init?.method ?? "GET") === "GET") {
        return jsonResp({ "hydra:member": [] });
      }
      if (url.endsWith("/register")) return textResp(200, "welcome");
      return textResp(200, "ok");
    };
    const e = new Engage({ fetchImpl, now: () => 0 });
    const r = await e.signup({
      signupUrl: "https://target.test/register",
      target: "target.test",
      verifyStrategy: "inbox",
      verifyTimeoutMs: 1500,
    });
    assert.strictEqual(r.isError, undefined);
    const d = r.details as { registered: boolean; verified: boolean; accountConfirmed: boolean };
    assert.strictEqual(d.registered, true);
    assert.strictEqual(d.verified, false);
    assert.strictEqual(d.accountConfirmed, false, "unverified => existence unconfirmed");
  });

  it("confirms account creation via login when loginUrl accepts the credentials", async () => {
    const fetchImpl: FetchImpl = async (input: string | URL) => {
      const url = String(input);
      if (url.endsWith("/register")) return textResp(200, "welcome");
      if (url.endsWith("/login")) return withCookieResp("sid=abc", "");
      return textResp(200, "ok");
    };
    const e = new Engage({ fetchImpl, now: () => 0 });
    const r = await e.signup({
      signupUrl: "https://target.test/register",
      target: "target.test",
      verifyStrategy: "none",
      loginUrl: "https://target.test/login",
      loginFields: { email: "<EMAIL>", password: "<PASS>" },
    });
    assert.strictEqual(r.isError, undefined);
    const d = r.details as {
      registered: boolean;
      verified: boolean;
      loginConfirmed: boolean;
      accountConfirmed: boolean;
    };
    assert.strictEqual(d.registered, true);
    assert.strictEqual(d.verified, false);
    assert.strictEqual(d.loginConfirmed, true, "login succeeded => account exists");
    assert.strictEqual(d.accountConfirmed, true);
  });

  it("marks account unconfirmed when login rejects the new credentials", async () => {
    const fetchImpl: FetchImpl = async (input: string | URL) => {
      const url = String(input);
      if (url.endsWith("/register")) return textResp(200, "welcome");
      if (url.endsWith("/login")) {
        return textResp(
          200,
          JSON.stringify({
            ResponseStatus: { Ack: "Failure", Errors: [{ Message: "invalid credentials" }] },
          }),
        );
      }
      return textResp(200, "ok");
    };
    const e = new Engage({ fetchImpl, now: () => 0 });
    const r = await e.signup({
      signupUrl: "https://target.test/register",
      target: "target.test",
      verifyStrategy: "none",
      loginUrl: "https://target.test/login",
    });
    const d = r.details as {
      registered: boolean;
      loginConfirmed: boolean;
      accountConfirmed: boolean;
    };
    assert.strictEqual(d.registered, true);
    assert.strictEqual(d.loginConfirmed, false, "login failed => no proof of account");
    assert.strictEqual(d.accountConfirmed, false);
  });

  it("standalone login action captures a session on success", async () => {
    const fetchImpl: FetchImpl = async (input: string | URL) => {
      if (String(input).endsWith("/login")) return withCookieResp("sid=abc", "");
      return textResp(200, "ok");
    };
    const e = new Engage({ fetchImpl, now: () => 0 });
    const r = await e.login({ loginUrl: "https://target.test/login", target: "target.test" });
    assert.strictEqual(r.isError, undefined);
    const d = r.details as { loggedIn: boolean; mode: string };
    assert.strictEqual(d.loggedIn, true);
    assert.strictEqual(d.mode, "cookie");
  });
});
