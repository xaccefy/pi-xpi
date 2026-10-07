/**
 * Chain-suggestion HOLD-OUT — natural-language paraphrases, non-gating.
 *
 * The dev corpus (chain-corpus.ts) was authored alongside the classifier
 * regexes, so its cGain measures fit, not generalization. These entries are
 * phrased the way a real auditor writes findings — some stay inside current
 * vocabulary ("SQL injection", "path traversal"), some deliberately use
 * synonyms the classifiers do not know yet ("concatenated queries",
 * "DOCTYPE fetch"). The reported recall is an HONEST generalization probe:
 * misses are information for the next classifier expansion, not CI failures.
 *
 * Run: bun bench/chain-holdout.ts
 */

export type HoldoutEntry = {
  id: string;
  pattern: string;
  difficulty: "in-vocabulary" | "paraphrase";
  a: { title: string; bugClass?: string; tags?: string[] };
  b?: { title: string; bugClass?: string; tags?: string[] };
};

export const CHAIN_HOLDOUT: HoldoutEntry[] = [
  {
    id: "h-auth-sqli-dump",
    pattern: "sqli_credential_dump",
    difficulty: "in-vocabulary",
    a: { title: "SQL injection on /item?id merges attacker rows", bugClass: "sql injection" },
    b: {
      title: "Password hashes retrievable from backup archive",
      bugClass: "credential exposure",
    },
  },
  {
    id: "h-lfi-upload",
    pattern: "lfi_rce_chain",
    difficulty: "in-vocabulary",
    a: { title: "Path traversal in template loader reaches system files", bugClass: "lfi" },
    b: { title: "Attachment upload accepts executable extensions", bugClass: "file upload" },
  },
  {
    id: "h-ssrf-cmd",
    pattern: "ssrf_internal_pivot",
    difficulty: "in-vocabulary",
    a: { title: "Server side request forging in preview generator", bugClass: "ssrf" },
    b: { title: "Diagnostics page passes hostnames to a shell", bugClass: "os command" },
  },
  {
    id: "h-jwt-role",
    pattern: "jwt_privilege_escalation",
    difficulty: "in-vocabulary",
    a: { title: "JSON web token signature check skips algorithm header", bugClass: "jwt" },
    b: {
      title: "Authorization bypass by flipping the role flag in profile edits",
      bugClass: "authorization bypass",
    },
  },
  {
    id: "h-xxe-paraphrase",
    pattern: "xxe_file_read",
    difficulty: "paraphrase",
    a: {
      title: "Malicious DOCTYPE makes the XML parser fetch file:///etc/shadow",
      bugClass: "xml entity",
    },
  },
  {
    id: "h-deser-paraphrase",
    pattern: "deserialization_rce",
    difficulty: "paraphrase",
    a: {
      title: "Crafted session cookie object instantiation escapes into gadget execution",
      bugClass: "object injection",
    },
  },
];
