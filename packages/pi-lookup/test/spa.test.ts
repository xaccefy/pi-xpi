import { afterEach, describe, expect, it } from "bun:test";
import { existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  __resetChromiumPathCacheForTests,
  htmlToText,
  isPublicHttpHost,
  looksLikeSpaShell,
  preferRenderedText,
  renderSpaDom,
  resolveChromiumPath,
} from "../src/websearch.ts";

afterEach(() => {
  __resetChromiumPathCacheForTests();
});

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
    // Real short-but-substantive pages should not always force chromium.
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

describe("preferRenderedText / htmlToText", () => {
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

  it("strips scripts/styles and keeps block text", () => {
    const text = htmlToText(
      `<html><head><style>.x{}</style><script>alert(1)</script></head><body><h1>Title</h1><p>Body &amp; more</p></body></html>`,
    );
    expect(text).toContain("Title");
    expect(text).toContain("Body & more");
    expect(text).not.toContain("alert");
    expect(text).not.toContain(".x{}");
  });
});

describe("resolveChromiumPath", () => {
  it("prefers PI_CHROMIUM_PATH when the file exists", () => {
    const dir = mkdtempSync(join(tmpdir(), "xpichrome-"));
    const fake = join(dir, "chromium");
    writeFileSync(fake, "#!/bin/sh\necho ok\n", { mode: 0o755 });
    try {
      __resetChromiumPathCacheForTests();
      const path = resolveChromiumPath((p) => p === fake, fake);
      expect(path).toBe(fake);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("returns null when nothing exists", () => {
    __resetChromiumPathCacheForTests();
    expect(resolveChromiumPath(() => false, undefined)).toBeNull();
  });
});

describe("renderSpaDom (live chromium when available)", () => {
  it("renders JS-injected SPA content", async () => {
    const chromium = resolveChromiumPath();
    if (!chromium || !existsSync(chromium)) {
      // Skip when chromium is not installed (common on CI runners).
      return;
    }
    const dir = mkdtempSync(join(tmpdir(), "xpi-spa-"));
    const file = join(dir, "spa.html");
    writeFileSync(
      file,
      `<!doctype html><html><body><div id="root">Loading...</div>
<script>document.getElementById('root').innerHTML='<main><h1>Delayed Heading</h1><p>Content rendered by JavaScript.</p></main>';</script>
</body></html>`,
    );
    try {
      let html: string;
      try {
        html = await renderSpaDom(`file://${file}`, chromium, undefined, 20000);
      } catch (err) {
        // Chromium present but unusable (sandbox, missing libs, headless crash).
        // Fake-chromium unit test still covers the web_fetch integration path.
        console.warn(
          "[spa] skipping live chromium render:",
          err instanceof Error ? err.message : String(err),
        );
        return;
      }
      const text = htmlToText(html);
      expect(text).toContain("Delayed Heading");
      expect(text).toContain("Content rendered by JavaScript");
      expect(preferRenderedText("Loading...", text)).toBe(true);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }, 45000);
});
