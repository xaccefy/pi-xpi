import { isIP } from "node:net";

function ipv4ToLong(ip: string): number | undefined {
  const parts = ip.split(".").map((part) => Number(part));
  if (
    parts.length !== 4 ||
    parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)
  ) {
    return;
  }
  return (((parts[0] << 24) >>> 0) + (parts[1] << 16) + (parts[2] << 8) + parts[3]) >>> 0;
}

function ipv4InRange(value: number, base: string, bits: number): boolean {
  const baseLong = ipv4ToLong(base);
  if (baseLong === undefined) return false;
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return (value & mask) === (baseLong & mask);
}

const NON_PUBLIC_IPV4_RANGES: readonly (readonly [string, number])[] = [
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
];

function expandIpv6(address: string): number[] | undefined {
  let value = address.toLowerCase().replace(/^\[|\]$/g, "");
  const zone = value.indexOf("%");
  if (zone !== -1) value = value.slice(0, zone);
  if (isIP(value) !== 6) return;

  const dottedTail = value.match(/(?:^|:)(\d+\.\d+\.\d+\.\d+)$/)?.[1];
  if (dottedTail) {
    const ipv4 = ipv4ToLong(dottedTail);
    if (ipv4 === undefined) return;
    value =
      value.slice(0, -dottedTail.length) +
      `${(ipv4 >>> 16).toString(16)}:${(ipv4 & 0xffff).toString(16)}`;
  }

  const halves = value.split("::");
  if (halves.length > 2) return;
  const left = halves[0] ? halves[0].split(":") : [];
  const right = halves[1] ? halves[1].split(":") : [];
  const missing = 8 - left.length - right.length;
  if ((halves.length === 1 && missing !== 0) || (halves.length === 2 && missing < 1)) return;
  const raw = halves.length === 2 ? [...left, ...Array(missing).fill("0"), ...right] : left;
  if (raw.length !== 8 || raw.some((word) => !/^[0-9a-f]{1,4}$/.test(word))) return;
  return raw.map((word) => Number.parseInt(word, 16));
}

function embeddedMappedIpv4(words: number[]): string | undefined {
  if (!words.slice(0, 5).every((word) => word === 0) || words[5] !== 0xffff) return;
  return `${words[6] >>> 8}.${words[6] & 0xff}.${words[7] >>> 8}.${words[7] & 0xff}`;
}

/**
 * Conservative SSRF boundary classifier shared by every XPI HTTP path.
 * Transition/tunnel ranges are rejected instead of trusting an embedded IPv4
 * address that a later resolver or network stack may interpret differently.
 */
export function isPublicIpAddress(address: string): boolean {
  const normalized = address
    .toLowerCase()
    .replace(/^\[|\]$/g, "")
    .split("%", 1)[0];
  const family = isIP(normalized);
  if (family === 4) {
    const value = ipv4ToLong(normalized);
    return (
      value !== undefined &&
      !NON_PUBLIC_IPV4_RANGES.some(([base, bits]) => ipv4InRange(value, base, bits))
    );
  }
  if (family !== 6) return false;

  const words = expandIpv6(normalized);
  if (!words) return false;
  const mapped = embeddedMappedIpv4(words);
  if (mapped) return isPublicIpAddress(mapped);

  const first = words[0];
  if (
    words.every((word) => word === 0) ||
    (words.slice(0, 7).every((word) => word === 0) && words[7] === 1)
  ) {
    return false;
  }
  if ((first & 0xfe00) === 0xfc00) return false; // fc00::/7 unique-local
  if ((first & 0xffc0) === 0xfe80) return false; // fe80::/10 link-local
  if ((first & 0xffc0) === 0xfec0) return false; // fec0::/10 deprecated site-local
  if ((first & 0xff00) === 0xff00) return false; // ff00::/8 multicast
  if (first === 0x2001 && words[1] === 0x0db8) return false; // documentation
  if (first === 0x2001 && words[1] === 0x0000) return false; // Teredo 2001:0000::/32
  if (first === 0x2002) return false; // 6to4 2002::/16

  // Globally routable unicast currently lives in 2000::/3. Fail closed on
  // unknown/special families instead of guessing that every IPv6 is public.
  return (first & 0xe000) === 0x2000;
}
