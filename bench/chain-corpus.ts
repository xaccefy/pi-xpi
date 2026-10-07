/**
 * Chain-suggestion benchmark corpus — XBOW 104 style.
 *
 * Each entry is a pair (or single) that ChainSuggest MUST surface on the
 * same asset, and MUST NOT surface when negation or cross-asset rules apply.
 * The runner creates synthetic cases and drives the real suggestChains engine.
 */

export type ChainExpectation = {
  id: string;
  pattern: string;
  a: { title: string; bugClass?: string; tags?: string[] };
  b?: { title: string; bugClass?: string; tags?: string[] };
  targetA: string;
  targetB: string;
  // Single-case escalations have no b; pair chains have b.
  shouldSuggest: boolean;
  negated?: boolean;
};

export const CHAIN_CORPUS: ChainExpectation[] = [
  // ── Original 8 (pre-expansion baseline) ─────────────────────────────
  {
    id: "cred-endpoint",
    pattern: "credential_endpoint",
    a: {
      title: "Leaked API key in JS bundle",
      bugClass: "credential leak",
      tags: ["information_disclosure"],
    },
    b: { title: "Admin API /api/admin/users", bugClass: "auth endpoint", tags: ["idor"] },
    targetA: "app.target.test",
    targetB: "app.target.test",
    shouldSuggest: true,
  },
  {
    id: "idor-leak",
    pattern: "idor_data_leak",
    a: { title: "IDOR BOLA on /api/orders/1001", bugClass: "idor", tags: ["idor"] },
    b: {
      title: "Mass user export /api/users",
      bugClass: "user data exposure",
      tags: ["information_disclosure"],
    },
    targetA: "app.target.test",
    targetB: "app.target.test",
    shouldSuggest: true,
  },
  {
    id: "xss-csrf",
    pattern: "xss_csrf",
    a: { title: "Stored XSS in comment field", bugClass: "xss", tags: ["xss"] },
    b: {
      title: "POST /api/transfer state change",
      bugClass: "state change payment",
      tags: ["business_logic"],
    },
    targetA: "app.target.test",
    targetB: "app.target.test",
    shouldSuggest: true,
  },
  {
    id: "ssti-rce",
    pattern: "ssti_rce",
    a: { title: "SSTI in Jinja greeting", bugClass: "ssti template injection", tags: ["ssti"] },
    targetA: "app.target.test",
    targetB: "app.target.test",
    shouldSuggest: true,
  },

  // ── XBOW expansion — new chaining-heavy pairs ───────────────────────
  // XBEN-028/029: LFI + file upload → RCE (Poison Inclusion)
  {
    id: "lfi-upload-rce",
    pattern: "lfi_rce_chain",
    a: {
      title: "LFI via /view?file=../../etc/passwd",
      bugClass: "lfi path traversal",
      tags: ["lfi", "path_traversal"],
    },
    b: {
      title: "Arbitrary file upload at /upload",
      bugClass: "arbitrary file upload",
      tags: ["arbitrary_file_upload"],
    },
    targetA: "shop.target.test",
    targetB: "shop.target.test",
    shouldSuggest: true,
  },
  // XBEN-020/024/033: SSRF → internal pivot (SSRF to internal command)
  {
    id: "ssrf-internal",
    pattern: "ssrf_internal_pivot",
    a: { title: "SSRF in webhook URL param", bugClass: "ssrf server side request", tags: ["ssrf"] },
    b: {
      title: "Internal admin RCE /admin/exec",
      bugClass: "command injection rce",
      tags: ["command_injection"],
    },
    targetA: "app.target.test",
    targetB: "app.target.test",
    shouldSuggest: true,
  },
  // XBEN-091/005: JWT → privilege escalation
  {
    id: "jwt-privesc",
    pattern: "jwt_privilege_escalation",
    a: { title: "JWT alg none accepted", bugClass: "jwt token tamper", tags: ["jwt"] },
    b: {
      title: "Privilege escalation via /admin/users",
      bugClass: "business logic privilege escalation",
      tags: ["privilege_escalation", "business_logic"],
    },
    targetA: "app.target.test",
    targetB: "app.target.test",
    shouldSuggest: true,
  },
  // XBEN-007/038: GraphQL → SQLi
  {
    id: "graphql-sqli",
    pattern: "graphql_chain",
    a: { title: "GraphQL endpoint at /graphql", bugClass: "graphql", tags: ["graphql"] },
    b: { title: "SQL injection in user lookup", bugClass: "sqli sql injection", tags: ["sqli"] },
    targetA: "api.target.test",
    targetB: "api.target.test",
    shouldSuggest: true,
  },
  // XBEN-007 variant: GraphQL → IDOR
  {
    id: "graphql-idor",
    pattern: "graphql_chain",
    a: { title: "GraphQL endpoint at /graphql", bugClass: "graphql", tags: ["graphql"] },
    b: { title: "IDOR in GraphQL user query", bugClass: "idor broken access", tags: ["idor"] },
    targetA: "api.target.test",
    targetB: "api.target.test",
    shouldSuggest: true,
  },
  // XBEN-036/057: Deserialization → RCE (single)
  {
    id: "deser-rce",
    pattern: "deserialization_rce",
    a: {
      title: "Insecure deserialization in pickle cookie",
      bugClass: "insecure deserialization",
      tags: ["insecure_deserialization"],
    },
    targetA: "app.target.test",
    targetB: "app.target.test",
    shouldSuggest: true,
  },
  // XBEN-032/096: XXE → file read (single)
  {
    id: "xxe-leak",
    pattern: "xxe_file_read",
    a: { title: "XXE in SVG upload", bugClass: "xxe xml external entity", tags: ["xxe"] },
    targetA: "app.target.test",
    targetB: "app.target.test",
    shouldSuggest: true,
  },
  // XBEN-028/029: sqli → credential dump (also sqli → upload)
  {
    id: "sqli-cred-dump",
    pattern: "sqli_credential_dump",
    a: {
      title: "SQLi in login via username",
      bugClass: "sqli blind sqli",
      tags: ["sqli", "blind_sqli"],
    },
    b: {
      title: "Credential dump table users",
      bugClass: "credential leak exposure",
      tags: ["information_disclosure"],
    },
    targetA: "shop.target.test",
    targetB: "shop.target.test",
    shouldSuggest: true,
  },
  // XBEN-029 variant: SQLi + file upload
  {
    id: "sqli-upload",
    pattern: "sqli_credential_dump",
    a: { title: "Blind SQLi in search", bugClass: "sqli blind sqli", tags: ["blind_sqli"] },
    b: {
      title: "Arbitrary file upload at /upload avatar",
      bugClass: "arbitrary file upload",
      tags: ["arbitrary_file_upload"],
    },
    targetA: "shop.target.test",
    targetB: "shop.target.test",
    shouldSuggest: true,
  },
  // Business logic + auth (XBEN-052/054/055)
  {
    id: "bizlogic-priv",
    pattern: "business_logic_privilege",
    a: {
      title: "Business logic flaw price tampering",
      bugClass: "business logic privilege escalation",
      tags: ["business_logic"],
    },
    b: { title: "Admin endpoint /admin/config", bugClass: "auth endpoint admin", tags: ["idor"] },
    targetA: "app.target.test",
    targetB: "app.target.test",
    shouldSuggest: true,
  },
  // Upload → RCE (XBEN-041/067)
  {
    id: "upload-rce",
    pattern: "upload_rce",
    a: {
      title: "Arbitrary file upload at /profile/pic",
      bugClass: "arbitrary file upload",
      tags: ["arbitrary_file_upload"],
    },
    b: {
      title: "Remote code execution via uploaded shell",
      bugClass: "command injection rce",
      tags: ["command_injection"],
    },
    targetA: "app.target.test",
    targetB: "app.target.test",
    shouldSuggest: true,
  },
  // Crypto → auth bypass (XBEN-060/101)
  {
    id: "crypto-bypass",
    pattern: "crypto_auth_bypass",
    a: {
      title: "Weak crypto JWT brute force",
      bugClass: "crypto brute force",
      tags: ["crypto", "brute_force"],
    },
    b: {
      title: "Login auth endpoint /login",
      bugClass: "auth endpoint login",
      tags: ["default_credentials"],
    },
    targetA: "app.target.test",
    targetB: "app.target.test",
    shouldSuggest: true,
  },

  // ── Negatives: should NOT suggest ───────────────────────────────────
  {
    id: "neg-cross-asset",
    pattern: "credential_endpoint",
    a: {
      title: "Leaked API key in JS bundle",
      bugClass: "credential leak",
      tags: ["information_disclosure"],
    },
    b: { title: "Admin API /api/admin/users", bugClass: "auth endpoint", tags: ["idor"] },
    targetA: "app.target.test",
    targetB: "other.io", // different eTLD+1 → no chain
    shouldSuggest: false,
  },
  {
    id: "neg-negated",
    pattern: "xss_csrf",
    a: {
      title: "Stored XSS in comment field not vulnerable — ruled out after re-test",
      bugClass: "xss",
      tags: ["xss"],
    },
    b: {
      title: "POST /api/transfer state change",
      bugClass: "state change payment",
      tags: ["business_logic"],
    },
    targetA: "app.target.test",
    targetB: "app.target.test",
    shouldSuggest: false,
    negated: true,
  },

  // ── Near-miss negatives (holdout-independent) ───────────────────────
  // Right neighborhood, wrong relation: both cases share a topic family but
  // no PAIR_RULE classifier combination fires between these two ids.
  {
    id: "nm-cred-cred",
    pattern: "credential_endpoint",
    a: { title: "Session token exposure in analytics dump", bugClass: "credential leak" },
    b: { title: "Password reset token leaked in debug logs", bugClass: "credential exposure" },
    targetA: "app.target.test",
    targetB: "app.target.test",
    shouldSuggest: false,
  },
  {
    id: "nm-idor-idor",
    pattern: "idor_data_leak",
    a: { title: "Broken object reference lets tenant read neighbor invoices", bugClass: "idor" },
    b: { title: "Second broken access issue on invoice PDFs", bugClass: "idor" },
    targetA: "app.target.test",
    targetB: "app.target.test",
    shouldSuggest: false,
  },
  {
    id: "nm-xss-read-only",
    pattern: "xss_csrf",
    a: { title: "Reflected XSS in search results page", bugClass: "xss" },
    b: { title: "Static marketing landing content page", bugClass: "informational" },
    targetA: "app.target.test",
    targetB: "app.target.test",
    shouldSuggest: false,
  },
  {
    id: "nm-lfi-lfi",
    pattern: "lfi_rce_chain",
    a: { title: "LFI reads ../../etc/passwd via viewer", bugClass: "lfi path traversal" },
    b: { title: "Path traversal in report name downloads", bugClass: "lfi path traversal" },
    targetA: "shop.target.test",
    targetB: "shop.target.test",
    shouldSuggest: false,
  },
  {
    id: "nm-upload-upload",
    pattern: "upload_rce",
    a: {
      title: "Arbitrary file upload on avatar picture field",
      bugClass: "arbitrary file upload",
    },
    b: { title: "Unrestricted upload bypass on media gallery", bugClass: "arbitrary file upload" },
    targetA: "app.target.test",
    targetB: "app.target.test",
    shouldSuggest: false,
  },
  {
    id: "nm-jwt-jwt",
    pattern: "jwt_privilege_escalation",
    a: { title: "JWT alg none accepted by gateway", bugClass: "jwt token tamper" },
    b: { title: "kid injection during JWT signing", bugClass: "jwt key confusion" },
    targetA: "app.target.test",
    targetB: "app.target.test",
    shouldSuggest: false,
  },
  {
    id: "nm-ssrf-ssrf",
    pattern: "ssrf_internal_pivot",
    a: { title: "SSRF via webhook URL parameter", bugClass: "ssrf server side request" },
    b: { title: "Blind SSRF through PDF renderer", bugClass: "ssrf server side request" },
    targetA: "app.target.test",
    targetB: "app.target.test",
    shouldSuggest: false,
  },
  {
    id: "nm-crypto-crypto",
    pattern: "crypto_auth_bypass",
    a: { title: "Weak cipher suite enables brute force offline", bugClass: "crypto brute force" },
    b: { title: "Cryptographic nonce reuse in ticket generation", bugClass: "crypto nonce reuse" },
    targetA: "app.target.test",
    targetB: "app.target.test",
    shouldSuggest: false,
  },
  {
    id: "nm-bizlogic-nonauth",
    pattern: "business_logic_privilege",
    a: {
      title: "Business logic flaw allows negative quantity purchase",
      bugClass: "business logic",
    },
    b: { title: "Coupon stacking drains promotional budget", bugClass: "business logic" },
    targetA: "app.target.test",
    targetB: "app.target.test",
    shouldSuggest: false,
  },
  {
    id: "nm-gql-gql",
    pattern: "graphql_chain",
    a: { title: "GraphQL introspection enabled on endpoint", bugClass: "graphql" },
    b: { title: "GraphQL query depth exhaustion", bugClass: "graphql denial of service" },
    targetA: "api.target.test",
    targetB: "api.target.test",
    shouldSuggest: false,
  },
  {
    id: "nm-redirect-redirect",
    pattern: "redirect_oauth",
    a: { title: "Open redirect in next URL parameter", bugClass: "open redirect" },
    b: { title: "Redirect loop after login attempts", bugClass: "open redirect availability" },
    targetA: "sso.target.test",
    targetB: "sso.target.test",
    shouldSuggest: false,
  },
  {
    id: "nm-oauth-oauth",
    pattern: "redirect_oauth",
    a: { title: "OAuth state mismatch on authorize handler", bugClass: "oauth" },
    b: { title: "SAML audience confusion in assertions", bugClass: "oauth saml" },
    targetA: "sso.target.test",
    targetB: "sso.target.test",
    shouldSuggest: false,
  },
  {
    id: "nm-race-race",
    pattern: "race_condition_business",
    a: { title: "Race condition during coupon redemption", bugClass: "race condition" },
    b: { title: "TOCTOU window in feature flag reload", bugClass: "race condition toctou" },
    targetA: "app.target.test",
    targetB: "app.target.test",
    shouldSuggest: false,
  },
  {
    // myshop.io vs shop.io: substring overlap is NOT an asset relation.
    id: "nm-subdomain-trap",
    pattern: "credential_endpoint",
    a: { title: "Leaked API key in JS bundle", bugClass: "credential leak" },
    b: { title: "Admin console user listing", bugClass: "admin endpoint" },
    targetA: "myshop.io",
    targetB: "shop.io",
    shouldSuggest: false,
  },
  {
    id: "nm-negated-sqli",
    pattern: "sqli_credential_dump",
    a: {
      title: "Blind SQL injection false positive — dismissed after manual verification",
      bugClass: "sqli",
    },
    b: { title: "Credential exposure on staff directory page", bugClass: "credential exposure" },
    targetA: "shop.target.test",
    targetB: "shop.target.test",
    shouldSuggest: false,
    negated: true,
  },
];
