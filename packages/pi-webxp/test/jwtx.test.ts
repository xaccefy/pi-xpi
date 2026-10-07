import assert from "node:assert";
import { createHmac, sign as cryptoSign, generateKeyPairSync } from "node:crypto";
import { beforeEach, describe, it } from "node:test";
import { MockExtensionAPI } from "../../../test-utils.ts";
import piWebxp from "../src/index.ts";
import { jwtAttack } from "../src/jwtx.ts";

const b64urlEncode = (input: Buffer | string): string =>
  Buffer.from(input).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const b64urlDecode = (part: string): string => {
  const pad = part.length % 4 === 0 ? "" : "=".repeat(4 - (part.length % 4));
  return Buffer.from(part.replace(/-/g, "+").replace(/_/g, "/") + pad, "base64").toString("utf8");
};

/** Build a real RS256-signed JWT for key-confusion testing. */
function makeRs256Token(
  payload: Record<string, unknown>,
  _publicKeyPem: string,
  privateKeyPem: string,
): string {
  const header = { alg: "RS256", typ: "JWT" };
  const signingInput = `${b64urlEncode(JSON.stringify(header))}.${b64urlEncode(JSON.stringify(payload))}`;
  const sig = cryptoSign("sha256", Buffer.from(signingInput), privateKeyPem);
  return `${signingInput}.${b64urlEncode(sig)}`;
}

describe("pi-webxp: jwt", () => {
  let api: MockExtensionAPI;

  beforeEach(() => {
    api = new MockExtensionAPI();
    piWebxp(api as any);
  });

  function tool() {
    const t = api.tools.find((x) => x.name === "jwt");
    assert.ok(t, "jwt registered");
    return t!;
  }

  it("registers the jwt tool", () => {
    tool();
  });

  it("decode reports structure, expiry state, and weakness notes", () => {
    const exp = Math.floor(Date.now() / 1000) + 3600;
    const token =
      `${b64urlEncode(JSON.stringify({ alg: "HS256", typ: "JWT" }))}.` +
      `${b64urlEncode(JSON.stringify({ sub: "1", role: "user", exp }))}.sig`;

    const result = jwtAttack({ action: "decode", token }) as Extract<
      ReturnType<typeof jwtAttack>,
      { decoded: unknown }
    >;
    const d = result.decoded;
    assert.equal(d.header.alg, "HS256");
    assert.equal((d.payload as Record<string, unknown>).role, "user");
    assert.ok(result.notes.some((n) => n.includes("valid")));
    assert.ok(result.notes.some((n) => n.includes("key_confusion applies") === false));
    assert.ok(result.notes.some((n) => n.startsWith("declared alg: HS256")));

    // kid + jku surface notes
    const token2 =
      `${b64urlEncode(JSON.stringify({ alg: "RS256", kid: "../../etc/key", jku: "https://evil/x" }))}.` +
      `${b64urlEncode(JSON.stringify({ sub: "1" }))}.s`;
    const r2 = jwtAttack({ action: "decode", token: token2 }) as Extract<
      ReturnType<typeof jwtAttack>,
      { decoded: unknown }
    >;
    assert.ok(r2.notes.some((n) => n.includes("kid")));
    assert.ok(r2.notes.some((n) => n.includes("jku")));
  });

  it("alg_none forges an unsigned token with overridden claims", () => {
    const original =
      `${b64urlEncode(JSON.stringify({ alg: "HS256", typ: "JWT" }))}.` +
      `${b64urlEncode(JSON.stringify({ sub: "1", role: "user" }))}.realSig`;

    const forged = jwtAttack({
      action: "alg_none",
      token: original,
      claims: { role: "admin" },
    }) as Extract<ReturnType<typeof jwtAttack>, { token: string }>;

    assert.equal(forged.header.alg, "none");
    assert.equal(forged.payload.role, "admin");
    assert.ok(
      forged.token.endsWith("."),
      "alg:none token must end with an empty signature segment",
    );
    const parts = forged.token.split(".");
    assert.equal(parts.length, 3);
    assert.equal(parts[2], "");
    // Payload must round-trip to the escalated claims.
    assert.deepEqual(JSON.parse(b64urlDecode(parts[1])), { sub: "1", role: "admin" });
  });

  it("key_confusion signs RS256 claims as HS256 using the public key PEM as secret", () => {
    const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
    const publicKeyPem = publicKey.export({ type: "spki", format: "pem" }).toString();
    const privateKeyPem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();

    const payload = { sub: "1", role: "user" };
    const rsToken = makeRs256Token(payload, publicKeyPem, privateKeyPem);

    const forged = jwtAttack({
      action: "key_confusion",
      token: rsToken,
      key: publicKeyPem,
      claims: { role: "admin" },
    }) as Extract<ReturnType<typeof jwtAttack>, { token: string }>;

    assert.equal(forged.header.alg, "HS256");
    assert.equal(forged.payload.role, "admin");

    // Independent verification of the signature semantics.
    const [h, p, s] = forged.token.split(".");
    const expected = createHmac("sha256", publicKeyPem)
      .update(`${h}.${p}`)
      .digest("base64")
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
    assert.equal(s, expected, "signature must be HMAC(publicKeyPem, signingInput)");
  });

  it("key_confusion rejects already-HMAC tokens and invalid PEMs", () => {
    const hsToken = `${b64urlEncode(JSON.stringify({ alg: "HS256" }))}.${b64urlEncode(JSON.stringify({ a: 1 }))}.sig`;
    assert.throws(
      () => jwtAttack({ action: "key_confusion", token: hsToken, key: "x" }),
      /already HMAC/,
    );

    const rsLike = `${b64urlEncode(JSON.stringify({ alg: "RS256" }))}.${b64urlEncode(JSON.stringify({ a: 1 }))}.sig`;
    assert.throws(
      () => jwtAttack({ action: "key_confusion", token: rsLike, key: "not a pem" }),
      /public key|Invalid key/,
    );
  });

  it("sign builds fully custom tokens including kid injection payloads", () => {
    const forged = jwtAttack({
      action: "sign",
      key: "s3cret",
      alg: "HS512",
      claims: { sub: "1", role: "admin", exp: 9999999999 },
      headerParams: { kid: "union'--" },
    }) as Extract<ReturnType<typeof jwtAttack>, { token: string }>;

    assert.equal(forged.header.alg, "HS512");
    assert.equal(forged.header.kid, "union'--");

    const [h, p, s] = forged.token.split(".");
    const expected = createHmac("sha512", "s3cret")
      .update(`${h}.${p}`)
      .digest("base64")
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
    assert.equal(s, expected);
    assert.deepEqual(JSON.parse(b64urlDecode(p)).role, "admin");
  });

  it("rejects malformed tokens and missing inputs", () => {
    assert.throws(() => jwtAttack({ action: "decode", token: "not-a-jwt" }), /compact form/);
    assert.throws(() => jwtAttack({ action: "decode", token: "a.b.c" }), /base64url JSON/);
    assert.throws(() => jwtAttack({ action: "sign", claims: {} }), /sign requires key/);
    assert.throws(() => jwtAttack({ action: "alg_none" }), /requires the original token/);
  });
});
