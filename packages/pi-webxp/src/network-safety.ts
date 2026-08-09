import { lookup as dnsLookup } from "node:dns";
import { lookup as dnsLookupAsync } from "node:dns/promises";
import { isIP } from "node:net";
import { Agent } from "undici";

export function normalizeHostname(hostname: string): string {
  let host = hostname.toLowerCase();
  if (host.startsWith("[") && host.endsWith("]")) host = host.slice(1, -1);
  return host;
}

function ipv4ToLong(ip: string): number | undefined {
  const parts = ip.split(".").map((p) => Number(p));
  if (parts.length !== 4 || parts.some((p) => !Number.isInteger(p) || p < 0 || p > 255)) return;
  return (((parts[0] << 24) >>> 0) + (parts[1] << 16) + (parts[2] << 8) + parts[3]) >>> 0;
}

function inRange(value: number, base: string, bits: number): boolean {
  const baseLong = ipv4ToLong(base);
  if (baseLong === undefined) return false;
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return (value & mask) === (baseLong & mask);
}

function mappedIpv4(ip: string): string | undefined {
  const host = normalizeHostname(ip);
  const dotted = host.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/i);
  if (dotted) return dotted[1];
  const hex = host.match(/^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/i);
  if (!hex) return;
  const g1 = parseInt(hex[1], 16);
  const g2 = parseInt(hex[2], 16);
  return `${(g1 >> 8) & 0xff}.${g1 & 0xff}.${(g2 >> 8) & 0xff}.${g2 & 0xff}`;
}

export function isPublicIpAddress(address: string): boolean {
  const mapped = mappedIpv4(address);
  const ip = mapped ?? normalizeHostname(address);
  const family = isIP(ip);
  if (family === 4) {
    const n = ipv4ToLong(ip);
    if (n === undefined) return false;
    return ![
      ["0.0.0.0", 8],
      ["10.0.0.0", 8],
      ["100.64.0.0", 10],
      ["127.0.0.0", 8],
      ["169.254.0.0", 16],
      ["172.16.0.0", 12],
      ["192.0.0.0", 24],
      ["192.0.2.0", 24],
      ["192.168.0.0", 16],
      ["198.18.0.0", 15],
      ["198.51.100.0", 24],
      ["203.0.113.0", 24],
      ["224.0.0.0", 4],
      ["240.0.0.0", 4],
    ].some(([base, bits]) => inRange(n, base as string, bits as number));
  }
  if (family === 6) {
    if (ip === "::" || ip === "::1") return false;
    if (/^f[cd][0-9a-f]{0,2}:/i.test(ip)) return false;
    if (/^fe[89ab][0-9a-f]?:/i.test(ip)) return false;
    if (/^ff/i.test(ip)) return false;
    if (/^2001:db8:/i.test(ip)) return false;
    return /^2|^3/i.test(ip);
  }
  return false;
}

export function isPublicHttpHost(parsed: URL): boolean {
  const host = normalizeHostname(parsed.hostname);
  if (host === "localhost" || host.endsWith(".localhost")) return false;
  const family = isIP(host) || (mappedIpv4(host) ? 4 : 0);
  return family === 0 ? true : isPublicIpAddress(host);
}

export function assertPublicHttpUrl(parsed: URL, allowPrivateHosts = false): void {
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new Error(`Protocol "${parsed.protocol}" not allowed. Use http:// or https://.`);
  }
  if (!allowPrivateHosts && !isPublicHttpHost(parsed)) {
    throw new Error(
      `Blocked: ${parsed.hostname} is a private/internal host. Set allowPrivateHosts=true to test internal targets.`,
    );
  }
}

function guardedLookup(hostname: string, options: any, callback: any): void {
  dnsLookup(hostname, { ...options, all: true }, (err, addresses) => {
    if (err) return callback(err);
    const list = Array.isArray(addresses) ? addresses : [addresses];
    const blocked = list.find((entry) => !isPublicIpAddress(entry.address));
    if (blocked) {
      return callback(
        new Error(`Blocked: ${hostname} resolved to private/internal address ${blocked.address}`),
      );
    }
    const picked =
      list.find((entry) => !options?.family || entry.family === options.family) ?? list[0];
    return callback(null, picked.address, picked.family);
  });
}

/**
 * Pre-flight DNS guard. Bun's fetch ignores undici's `dispatcher` (verified:
 * 0 lookup calls), so the guardedLookup agent only protects Node runtimes.
 * This check makes the DNS rebinding block effective under Bun too: a
 * hostname that resolves to a private address is rejected before the fetch.
 * On resolution ERRORS we proceed — the fetch itself will fail with its own
 * connection error, so there is no SSRF window (our resolver is the same one
 * the fetch uses).
 *
 * Residual (accepted): under Bun there is a TOCTOU window between this
 * pre-flight and the actual connect (the connect-time guardedLookup is
 * ignored there). A low-TTL rebinding attacker can pass the pre-flight and
 * then serve a private address to the connection. Node closes the window via
 * guardedLookup; Bun does not. Closing it on Bun would require a custom
 * socket layer.
 */
export async function assertPublicDns(hostname: string, allowPrivateHosts = false): Promise<void> {
  if (allowPrivateHosts) return;
  const host = normalizeHostname(hostname);
  if (isIP(host)) return; // literal — already gated by assertPublicHttpUrl
  let addresses: { address: string; family: number }[] | undefined;
  try {
    addresses = await dnsLookupAsync(host, { all: true });
  } catch {
    return; // unresolvable → the fetch fails on its own
  }
  const blocked = addresses.find((entry) => !isPublicIpAddress(entry.address));
  if (blocked) {
    throw new Error(
      `Blocked: ${host} resolved to private/internal address ${blocked.address}. Set allowPrivateHosts=true to test internal targets.`,
    );
  }
}

export function createSafeDispatcher(options: {
  allowPrivateHosts?: boolean;
  verifyTls?: boolean;
}): Agent {
  const connect: Record<string, unknown> = { rejectUnauthorized: options.verifyTls !== false };
  if (!options.allowPrivateHosts) connect.lookup = guardedLookup;
  return new Agent({ connect } as never);
}
