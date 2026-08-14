import assert from "node:assert";
import { describe, it } from "node:test";
import { isPublicIpAddress as sharedIsPublicIpAddress } from "@xaccefy/pi-shared";
import { POC_CANARY_PLACEHOLDER, type PoCEvidence, parsePoCEvidence } from "../src/evidence.ts";
import {
  controlTargetAuthorizationError,
  evaluateExpect,
  isPublicIpAddress as harnessIsPublicIpAddress,
  replayDifferential,
  replayVerify,
} from "../src/harness-verify.ts";

/** Minimal valid evidence whose verify.url the caller overrides. */
function evidence(overrides: Partial<PoCEvidence["verify"]> = {}): PoCEvidence {
  return {
    nonce: "n",
    claim: "read /etc/passwd of target",
    verify: {
      method: "GET",
      url: "https://example.com/read?file=/etc/passwd",
      expect: { status: [200], body_contains: ["root:"] },
      ...overrides,
    },
    observations: ["root: present"],
  };
}

describe("harness-verify: evaluateExpect", () => {
  it("passes when status and body predicates all match", async () => {
    const failures = await evaluateExpect(
      { status: [200, 201], body_contains: ["root:"], body_regex: ["root:\\S+"] },
      200,
      "root:x:0:0:root:/root:/bin/bash",
    );
    assert.deepStrictEqual(failures, []);
  });

  it("fails per-predicate with a distinct message for each miss", async () => {
    const failures = await evaluateExpect(
      { status: [200], body_contains: ["root:", "nobody:"], body_regex: ["admin:"] },
      403,
      "root:x:0:0",
    );
    assert.strictEqual(failures.length, 3);
    assert.ok(failures.some((f) => f.includes("status 403 not in [200]")));
    assert.ok(failures.some((f) => f.includes("body_contains missing: nobody:")));
    assert.ok(failures.some((f) => f.includes("body_regex failed: admin:")));
  });

  it("rejects an empty expect before the harness can treat it as proof", () => {
    const parsed = parsePoCEvidence(evidence({ expect: {} }));
    assert.strictEqual(parsed.ok, false);
    if (!parsed.ok) assert.match(parsed.error, /at least one non-empty/i);
  });

  it("rejects status-only evidence as too weak for confirmation", () => {
    const parsed = parsePoCEvidence(evidence({ expect: { status: [200] } }));
    assert.strictEqual(parsed.ok, false);
    if (!parsed.ok)
      assert.match(parsed.error, /status-only differences are not vulnerability proof/i);
  });

  it("rejects trivial body predicates that match broad response classes", () => {
    for (const expect of [
      { body_contains: ["a"] },
      { body_regex: [".*"] },
      { body_regex: ["\\d+"] },
    ]) {
      const parsed = parsePoCEvidence(evidence({ expect }));
      assert.strictEqual(parsed.ok, false);
      if (!parsed.ok) assert.match(parsed.error, /discriminating body predicate/i);
    }
  });

  it("rejects caller-controlled authority and framing headers", () => {
    const unsafeHeaders: Array<Record<string, string>> = [
      { Host: "target.test" },
      { "Content-Length": "1" },
    ];
    for (const headers of unsafeHeaders) {
      const parsed = parsePoCEvidence(evidence({ headers }));
      assert.strictEqual(parsed.ok, false);
      if (!parsed.ok) assert.match(parsed.error, /authority, framing, proxy, and hop-by-hop/i);
    }
  });

  it("requires exactly one fixed canary placeholder", () => {
    const missing = parsePoCEvidence(
      evidence({
        canary: { mode: "reflection", placeholder: POC_CANARY_PLACEHOLDER },
      }),
    );
    assert.strictEqual(missing.ok, false);
    if (!missing.ok) assert.match(missing.error, /exactly one/);

    const valid = parsePoCEvidence(
      evidence({
        url: `https://example.com/reflect?q=${POC_CANARY_PLACEHOLDER}`,
        canary: { mode: "reflection", placeholder: POC_CANARY_PLACEHOLDER },
      }),
    );
    assert.strictEqual(valid.ok, true);
  });

  it("times out pathological PoC-authored regular expressions", async () => {
    const failures = await evaluateExpect(
      { body_regex: ["(a+)+$"] },
      200,
      `${"a".repeat(200_000)}!`,
    );
    assert.ok(failures.some((failure) => /evaluation (failed|exceeded)/i.test(failure)));
  });
});

describe("harness-verify: replayVerify policy", () => {
  it("uses the exact shared IP classifier rather than a hand-synced copy", () => {
    assert.strictEqual(harnessIsPublicIpAddress, sharedIsPublicIpAddress);
  });

  it("refuses private IP literals without operator authorization", async () => {
    const result = await replayVerify(evidence({ url: "http://127.0.0.1/read" }));
    assert.strictEqual(result.attempted, false);
    assert.match(result.note, /private\/internal host/);
  });

  it("uses the shared classifier to reject 6to4 and Teredo literals", async () => {
    for (const host of ["[2002:c0a8:0101::1]", "[2001:0000:4136:e378:8000:63bf:3fff:fdd2]"]) {
      const result = await replayVerify(evidence({ url: `http://${host}/proof` }));
      assert.strictEqual(result.attempted, false, host);
      assert.match(result.note, /private\/internal/);
    }
  });

  it("skips localhost and .localhost hostnames", async () => {
    for (const url of ["http://localhost/read", "http://app.localhost/read"]) {
      const result = await replayVerify(evidence({ url }));
      assert.strictEqual(result.attempted, false, url);
    }
  });

  it("fails closed on unresolvable public hostnames", async () => {
    // .invalid is guaranteed NXDOMAIN (RFC 2606) — deterministic, offline.
    const result = await replayVerify(evidence({ url: "http://does-not-exist.invalid/read" }));
    assert.strictEqual(result.attempted, true);
    assert.strictEqual(result.pass, false);
    assert.match(result.note, /errored/);
  });

  it("skips non-http protocols instead of fetching them", async () => {
    const result = await replayVerify(evidence({ url: "file:///etc/passwd" }));
    assert.strictEqual(result.attempted, false);
  });

  it("checks every redirect hop and refuses a public-to-loopback redirect", async () => {
    const requested: string[] = [];
    const fetchImpl = async (input: string | URL) => {
      requested.push(String(input));
      return new Response("", {
        status: 302,
        headers: { location: "http://127.0.0.1/private" },
      });
    };
    const result = await replayVerify(evidence({ url: "http://93.184.216.34/start" }), {
      fetchImpl,
    });
    assert.strictEqual(result.pass, false);
    assert.strictEqual(requested.length, 1, "loopback redirect must not be fetched");
    assert.match(result.note, /private\/internal host|redirect left the bound host/);
  });

  it("refuses redirects that leave the target-bound hostname", async () => {
    const requested: string[] = [];
    const fetchImpl = async (input: string | URL) => {
      requested.push(String(input));
      return new Response("", {
        status: 302,
        headers: { location: "https://unrelated.example/proof" },
      });
    };
    const result = await replayVerify(evidence(), { fetchImpl });
    assert.strictEqual(result.pass, false);
    assert.deepStrictEqual(requested, ["https://example.com/read?file=/etc/passwd"]);
    assert.match(result.note, /redirect left the bound host/);
  });

  it("treats a truncated response as inconclusive even if its prefix matches", async () => {
    const result = await replayVerify(evidence(), {
      fetchImpl: async () => new Response(`root:${"x".repeat(2 * 1024 * 1024)}`),
    });
    assert.strictEqual(result.pass, false);
    assert.strictEqual(result.target?.matched, undefined);
    assert.match(result.note, /capture limit.*inconclusive/i);
  });
});

describe("harness-verify: machine differential", () => {
  it("applies the target request and predicates to both target and control", async () => {
    const requested: string[] = [];
    const fetchImpl = async (input: string | URL) => {
      const url = new URL(String(input));
      requested.push(url.toString());
      return url.hostname === "target.test"
        ? new Response("root:x:0:0", { status: 200 })
        : new Response("not vulnerable", { status: 404 });
    };
    const result = await replayDifferential(
      evidence({ url: "http://target.test/read?file=/etc/passwd" }),
      "target.test",
      "control.test",
      { allowPrivate: true, fetchImpl },
    );
    assert.strictEqual(result.pass, true);
    assert.strictEqual(result.differential, "target_only");
    assert.strictEqual(result.target?.matched, true);
    assert.strictEqual(result.control?.matched, false);
    assert.deepStrictEqual(requested, [
      "http://target.test/read?file=/etc/passwd",
      "http://control.test/read?file=/etc/passwd",
    ]);
  });

  it("treats a control transport failure as inconclusive, never target-only", async () => {
    const fetchImpl = async (input: string | URL) => {
      const url = new URL(String(input));
      if (url.hostname === "control.test") throw new Error("control unavailable");
      return new Response("root:x:0:0", { status: 200 });
    };
    const result = await replayDifferential(
      evidence({ url: "http://target.test/read?file=/etc/passwd" }),
      "target.test",
      "control.test",
      { allowPrivate: true, fetchImpl },
    );
    assert.strictEqual(result.pass, false);
    assert.strictEqual(result.differential, undefined);
    assert.match(result.note, /inconclusive/);
  });

  it("injects an unpredictable canary after PoC output and requires target-only reflection", async () => {
    let observedToken = "";
    const fetchImpl = async (input: string | URL) => {
      const url = new URL(String(input));
      const token = url.searchParams.get("marker") ?? "";
      assert.match(token, /^poc_canary_[a-f0-9]{48}$/);
      observedToken = token;
      return url.hostname === "target.test"
        ? new Response(`root:${token}`, { status: 200 })
        : new Response("not vulnerable", { status: 404 });
    };
    const result = await replayDifferential(
      evidence({
        url: `http://target.test/read?marker=${POC_CANARY_PLACEHOLDER}`,
        canary: { mode: "reflection", placeholder: POC_CANARY_PLACEHOLDER },
      }),
      "target.test",
      "control.test",
      { allowPrivate: true, fetchImpl },
    );
    assert.strictEqual(result.pass, true);
    assert.strictEqual(result.canary?.pass, true);
    assert.strictEqual(result.canary?.targetObserved, true);
    assert.strictEqual(result.canary?.controlObserved, false);
    assert.strictEqual(result.proofStrength, "canary_differential");
    assert.ok(observedToken);
    assert.ok(!JSON.stringify(result).includes(observedToken), "raw canary is not persisted");
  });

  it("rejects a verify URL that is not bound to the case target", async () => {
    const result = await replayDifferential(
      evidence({ url: "https://unrelated.test/proof" }),
      "target.test",
      "control.test",
    );
    assert.strictEqual(result.attempted, false);
    assert.strictEqual(result.pass, false);
    assert.match(result.note, /target binding failed/i);
  });

  it("requires the control identity to be operator-approved", () => {
    assert.strictEqual(
      controlTargetAuthorizationError("https://control.test", "control.test,baseline.test"),
      undefined,
    );
    assert.match(
      controlTargetAuthorizationError("invented.test", "control.test,baseline.test") ?? "",
      /not present in the operator-approved/i,
    );
    assert.match(
      controlTargetAuthorizationError("control.test", "") ?? "",
      /no operator-approved/i,
    );
  });
});
