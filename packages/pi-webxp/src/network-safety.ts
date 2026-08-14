import { lookup as dnsLookup } from "node:dns";
import { lookup as dnsLookupAsync } from "node:dns/promises";
import { isIP } from "node:net";
import { isPublicIpAddress } from "@xaccefy/pi-shared";
import { Agent } from "undici";

export { isPublicIpAddress } from "@xaccefy/pi-shared";

export function normalizeHostname(hostname: string): string {
  let host = hostname.toLowerCase();
  if (host.startsWith("[") && host.endsWith("]")) host = host.slice(1, -1);
  return host;
}

export function isPublicHttpHost(parsed: URL): boolean {
  const host = normalizeHostname(parsed.hostname);
  if (host === "localhost" || host.endsWith(".localhost")) return false;
  const family = isIP(host);
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
 * This check rejects a hostname that resolves to a private address before the
 * fetch under Bun too.
 * On resolution ERRORS we proceed — the fetch itself will fail with its own
 * connection error.
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

/**
 * Bun-only TOCTOU close for plain-HTTP requests: Bun's fetch ignores the
 * guardedLookup dispatcher, so the connect-time DNS check never runs there
 * (assertPublicDns pre-flight is the only guard). For http:// HOSTNAMES,
 * re-resolve here and rewrite the URL to the validated IP — the connection
 * then goes to the address this check approved, so a rebinding answer
 * cannot reach a later connect. The caller must carry the original host as
 * the Host header.
 *
 * - Throws (fail closed) when any answer is private — the rebinding attempt.
 * - Returns null when the host no longer resolves (fetch fails on its own).
 * - Returns null for https:// and IP literals: rewriting an https URL host
 *   breaks TLS SNI/cert verification on Bun (documented residual), and IP
 *   literals are already gated by assertPublicHttpUrl.
 */
export async function pinPublicHostForPlainHttp(
  url: URL,
  resolveFn: (host: string) => Promise<{ address: string }[]> = (host) =>
    dnsLookupAsync(host, { all: true }),
): Promise<URL | null> {
  if (url.protocol !== "http:") return null;
  const host = normalizeHostname(url.hostname);
  if (isIP(host)) return null;
  let addresses: { address: string }[];
  try {
    addresses = await resolveFn(host);
  } catch {
    return null;
  }
  const blocked = addresses.find((entry) => !isPublicIpAddress(entry.address));
  if (blocked) {
    throw new Error(`Blocked: ${host} resolved to private/internal address ${blocked.address}`);
  }
  const picked = addresses.find((entry) => isIP(entry.address) === 4) ?? addresses[0];
  if (!picked) return null;
  const pinned = new URL(url.toString());
  pinned.hostname = isIP(picked.address) === 6 ? `[${picked.address}]` : picked.address;
  return pinned;
}
