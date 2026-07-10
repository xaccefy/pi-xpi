/**
 * pi-engage credential — turn a stored session into ready-to-use request config.
 *
 * Supports the three autonomous-pentest auth modes discussed for XPI:
 *   - cookie                  : replay the user-supplied `Cookie` header
 *   - oauth-client-credentials: agent is its own service identity; fetch + cache a
 *                               bearer token, self-refresh before expiry (no human at runtime)
 *   - mtls                    : present a client certificate during the TLS handshake
 *                               (the handshake IS the auth — no token exchange at all)
 */

import type { AuthSession } from "./store.ts";
import { saveSession } from "./store.ts";
import type { FetchImpl } from "./types.ts";

export interface ResolvedAuth {
  /** Headers to attach to web_fetch / agent HTTP calls. */
  headers: Record<string, string>;
  /** Equivalent CLI flags for `curl` (useful for bash tooling / Burp-through-MCP). */
  curlFlags: string[];
  /** A copy-paste curl command demonstrating the auth. */
  curlExample: string;
}

export function isTokenExpired(session: AuthSession): boolean {
  if (!session.accessToken || typeof session.expiresAt !== "number") return true;
  return Date.now() >= session.expiresAt;
}

export async function fetchClientCredentialsToken(
  session: AuthSession,
  signal?: AbortSignal,
  fetchImpl?: FetchImpl,
): Promise<{ token: string; expiresAt: number }> {
  if (!session.tokenUrl || !session.clientId || !session.clientSecret) {
    throw new Error("oauth-client-credentials requires tokenUrl, clientId, and clientSecret");
  }
  const doFetch = fetchImpl ?? fetch;
  const body = new URLSearchParams({
    grant_type: "client_credentials",
    client_id: session.clientId,
    client_secret: session.clientSecret,
  });
  if (session.scope) body.set("scope", session.scope);

  const res = await doFetch(session.tokenUrl, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body,
    signal,
  });
  if (!res.ok) {
    throw new Error(`Token endpoint returned HTTP ${res.status}`);
  }
  const data = (await res.json()) as { access_token?: string; expires_in?: number };
  if (!data.access_token) {
    throw new Error("Token endpoint response missing access_token");
  }
  const ttl = typeof data.expires_in === "number" ? data.expires_in : 3600;
  // Refresh 30s early to avoid races at the boundary.
  return { token: data.access_token, expiresAt: Date.now() + ttl * 1000 - 30000 };
}

/** Build request config from an already-fresh session (token must be current). */
export function buildResolvedAuth(session: AuthSession): ResolvedAuth {
  const host = session.target ?? "TARGET";

  if (session.mode === "cookie") {
    const cookie = session.cookie ?? "";
    return {
      headers: cookie ? { Cookie: cookie } : {},
      curlFlags: cookie ? ["--cookie", cookie] : [],
      curlExample: cookie ? `curl --cookie '${cookie}' https://${host}/` : `curl https://${host}/`,
    };
  }

  if (session.mode === "oauth-client-credentials") {
    const token = session.accessToken ?? "";
    return {
      headers: token ? { Authorization: `Bearer ${token}` } : {},
      curlFlags: token ? ["-H", `Authorization: Bearer ${token}`] : [],
      curlExample: token
        ? `curl -H 'Authorization: Bearer ${token}' https://${host}/`
        : `curl https://${host}/`,
    };
  }

  // mtls — the client cert presented in the TLS handshake is the identity.
  const flags: string[] = [];
  if (session.certPath) flags.push("--cert", session.certPath);
  if (session.keyPath) flags.push("--key", session.keyPath);
  if (session.caPath) flags.push("--cacert", session.caPath);

  const example = [
    "curl",
    ...(session.certPath ? [`--cert ${session.certPath}`] : []),
    ...(session.keyPath ? [`--key ${session.keyPath}`] : []),
    ...(session.caPath ? [`--cacert ${session.caPath}`] : []),
    `https://${host}/`,
  ].join(" ");

  return { headers: {}, curlFlags: flags, curlExample: example };
}

/**
 * Resolve a session into request config, transparently refreshing an expired
 * OAuth client-credentials token (self-refresh = no human at runtime). The
 * refreshed token is persisted so subsequent calls are cheap.
 */
export async function resolveSessionRequest(
  session: AuthSession,
  fetchImpl?: FetchImpl,
  signal?: AbortSignal,
): Promise<ResolvedAuth> {
  if (session.mode === "oauth-client-credentials" && isTokenExpired(session)) {
    const { token, expiresAt } = await fetchClientCredentialsToken(session, signal, fetchImpl);
    const refreshed: AuthSession = { ...session, accessToken: token, expiresAt };
    saveSession(refreshed);
    return buildResolvedAuth(refreshed);
  }
  return buildResolvedAuth(session);
}
