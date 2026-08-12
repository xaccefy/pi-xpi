import { describe, expect, it } from "bun:test";
import { isPublicHttpHost } from "../src/network-safety.ts";

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
