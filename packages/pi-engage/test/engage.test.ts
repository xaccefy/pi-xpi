import assert from "node:assert";
import { afterEach, beforeEach, describe, it } from "node:test";
import { MockExtensionAPI } from "../../../test-utils.ts";
import { buildToolArgs, Engage, headersToFlags, parseToolOutput } from "../src/engage.ts";
import registerEngage from "../src/index.ts";
import type { AuthSession } from "../src/store.ts";
import { clearSessions } from "../src/store.ts";

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
  return async (tool: string, args: string[]) => {
    if (tool === "nuclei" && args.includes("-version")) {
      return { code: 1, stdout: "", stderr: "nuclei: command not found" };
    }
    if (tool === "nuclei") {
      const issue = JSON.stringify({
        template: "xss",
        severity: "high",
        host: "https://shop.example.com",
        "matched-at": "https://shop.example.com/a",
      });
      return { code: 0, stdout: `${issue}\n`, stderr: "" };
    }
    return { code: 0, stdout: "ok", stderr: "" };
  };
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
});

describe("Engage class (pdtm bridge)", () => {
  afterEach(() => clearSessions());

  it("run injects auth into nuclei and captures findings", async () => {
    const e = new Engage({ execImpl: fakeExec(), fetchImpl: fakeFetch() });
    e.addSession(cookieSession());
    const r = await e.run({ tool: "nuclei", url: "https://shop.example.com", sessionId: "s1" });
    assert.strictEqual(r.isError, undefined);
    const d = r.details as { command: string; exitCode: number; findings: { type: string }[] };
    assert.match(d.command, /-H "Cookie: session=abc123"/);
    assert.match(d.command, /-u https:\/\/shop.example.com/);
    assert.strictEqual(d.findings.length, 1);
    assert.strictEqual(d.findings[0].type, "xss");
  });

  it("run uses a positional URL for curl", async () => {
    const e = new Engage({ execImpl: fakeExec(), fetchImpl: fakeFetch() });
    e.addSession(cookieSession());
    const r = await e.run({ tool: "curl", url: "https://shop.example.com/a", sessionId: "s1" });
    const d = r.details as { command: string };
    assert.match(d.command, /curl/);
    assert.match(d.command, /-H "Cookie: session=abc123"/);
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

  it("scan falls back to a passive header check when nuclei is absent", async () => {
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
    assert.deepStrictEqual(buildToolArgs("nuclei", "https://t", ["-H", "A: B"], ["-silent"]), [
      "-H",
      "A: B",
      "-u",
      "https://t",
      "-silent",
    ]);
  });

  it("parseToolOutput extracts nuclei issues", () => {
    const out = parseToolOutput(
      "nuclei",
      `${JSON.stringify({ template: "xss", severity: "high", "matched-at": "https://t/a" })}\nnot-json\n`,
    );
    assert.strictEqual(out.length, 1);
    assert.strictEqual(out[0].type, "xss");
    assert.strictEqual(out[0].severity, "high");
  });
});
