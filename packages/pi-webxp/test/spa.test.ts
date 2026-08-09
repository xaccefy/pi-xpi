import { describe, expect, it } from "bun:test";
import { isPublicHttpHost, looksLikeSpaShell, preferRenderedText } from "../src/websearch.ts";

describe("looksLikeSpaShell", () => {
  it("skips non-html and already browser-rendered content", () => {
    expect(
      looksLikeSpaShell({ contentType: "text/markdown", retrievalMethod: "request" }, "x"),
    ).toBe(false);
    expect(
      looksLikeSpaShell(
        { contentType: "text/html", retrievalMethod: "browser-html" },
        "Loading...",
      ),
    ).toBe(false);
  });

  it("flags thin HTML shells and JS-required markers", () => {
    expect(looksLikeSpaShell({ contentType: "text/html; charset=utf-8" }, "Loading...")).toBe(true);
    expect(
      looksLikeSpaShell(
        { contentType: "text/html" },
        "Please enable JavaScript to continue using this application.",
      ),
    ).toBe(true);
    const medium =
      "About us - we ship secure software for teams worldwide. Contact support@example.com for help with onboarding, billing, and enterprise plans today.";
    expect(medium.length).toBeGreaterThan(120);
    expect(looksLikeSpaShell({ contentType: "text/html" }, medium)).toBe(false);
  });
});

describe("isPublicHttpHost", () => {
  it("blocks loopback / private / localhost", () => {
    expect(isPublicHttpHost(new URL("http://localhost/x"))).toBe(false);
    expect(isPublicHttpHost(new URL("http://127.0.0.1/x"))).toBe(false);
    expect(isPublicHttpHost(new URL("http://10.0.0.2/x"))).toBe(false);
    expect(isPublicHttpHost(new URL("http://192.168.1.1/x"))).toBe(false);
    expect(isPublicHttpHost(new URL("http://172.16.0.1/x"))).toBe(false);
    expect(isPublicHttpHost(new URL("http://[::1]/x"))).toBe(false);
  });

  it("blocks IPv4-mapped IPv6 loopback", () => {
    expect(isPublicHttpHost(new URL("http://[::ffff:127.0.0.1]/x"))).toBe(false);
    expect(isPublicHttpHost(new URL("http://[::ffff:10.0.0.1]/x"))).toBe(false);
    expect(isPublicHttpHost(new URL("http://[::ffff:192.168.1.1]/x"))).toBe(false);
  });

  it("allows public hosts", () => {
    expect(isPublicHttpHost(new URL("https://example.com/a"))).toBe(true);
    expect(isPublicHttpHost(new URL("https://docs.github.com/en"))).toBe(true);
  });
});

describe("preferRenderedText", () => {
  it("requires meaningfully richer rendered text", () => {
    expect(preferRenderedText("Loading...", "Loading...")).toBe(false);
    expect(preferRenderedText("Loading...", "Load")).toBe(false);
    expect(
      preferRenderedText(
        "Loading...",
        "Rendered Heading\n\nReal SPA content injected by JavaScript at runtime with enough body text.",
      ),
    ).toBe(true);
  });
});
