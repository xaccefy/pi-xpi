# PoC Confirmation — Main-Agent Commit Design

> Status: implemented. This supersedes marker- and exit-code-based confirmation and the former confirmer-worker design.

## 1. Authority invariant

Only the main/coordinator agent may run validation gates or decide whether a PoC is confirmed.

- The main agent writes/runs the PoC and calls `PromoteFinding` to create a pending evidence bundle.
- A worker or subagent may gather artifacts or challenge evidence, but it cannot call `PromoteFinding`, report `pending_confirmation`, or commit `confirmed`.
- No confirmation worker is dispatched. `agents/confirmer.md` is intentionally absent.
- The main agent must inspect the exact PoC and preserved evidence, attempt to disprove the claim, and call `ConfirmFinding` itself; that main-only call captures the fresh target/control replay.
- `CaseUpdate(status: "confirmed")` remains invalid.

The machine gate establishes a reproducible evidence floor. The main agent owns the semantic judgment: whether the observed differential actually proves the stated vulnerability and impact.

## 2. Trust chain

```text
main-agent PoC
  → complete zero-exit execution with complete output capture
  → nonce-bound, schema-valid evidence.json with a body predicate
  → two deterministic target runs and one same-byte-script control run
  → operator-approved distinct control target
  → harness-owned DNS-pinned replay of one request against target and control
  → optional harness-generated reflection canary observed on target only
  → conclusive target match + conclusive control non-match (`target_only`)
  → pending_confirmation bundle
  → main agent reviews and tries to disprove
  → ConfirmFinding performs a fresh harness-owned target/control replay
  → ledger revalidates the bundle and commits or refuses the verdict
```

`exitCode === 0` is required only to show that the run completed normally. It never proves a vulnerability by itself. Stdout and the PoC-authored observations are retained as audit material, not treated as the deciding oracle.

## 3. Evidence contract

The runner provides:

- `PI_POC_EVIDENCE_DIR`: a harness-created directory for `evidence.json`.
- `PI_POC_NONCE`: a fresh per-run value that the evidence must echo.
- `PI_POC_TARGET` and `PI_POC_MODE`: the target and execution mode.

Minimal evidence shape:

```jsonc
{
  "nonce": "must equal PI_POC_NONCE",
  "claim": "the concrete effect being asserted",
  "verify": {
    "method": "GET",
    "url": "https://target.example/path",
    "headers": {},
    "body": "",
    "expect": {
      "status": [200],
      "body_contains": ["target-specific proof"]
    },
    "canary": {
      "mode": "reflection",
      "placeholder": "{{PI_POC_CANARY}}"
    }
  },
  "observations": ["corroboration only"]
}
```

The contract is bounded and strict. A discriminating `body_contains` or `body_regex` assertion is mandatory; status-only and structurally trivial predicates such as one-character contains, `.*`, or `\\d+` are rejected. Authority/framing/hop-by-hop request headers are forbidden. The file must be a regular non-symlink file, is size-limited, read once, hashed from the validated bytes, and copied into the durable evidence store before the run can count.

For reflection-capable findings, `verify.canary` strengthens causality. The fixed placeholder must occur exactly once in the URL, body, or a header value. Only after the PoC process exits, the harness generates an unpredictable token, substitutes it into its own replay, and requires the token to appear in the target response but not the control response. The raw token is never persisted—only its SHA-256 and the target/control observations are stored. This produces `proofStrength: "canary_differential"`; evidence without a canary is honestly labeled `predicate_differential`.

## 4. Phase 1 — main-agent evidence production

`PromoteFinding` does not promote the case. It:

1. Checks the case prerequisites and requires an earlier artifact-backed observation.
2. Defaults `control_path` to `poc_path`; if an override is supplied, both paths must contain identical bytes.
3. Requires `control_target` to be distinct and present in the operator-owned `PI_POC_CONTROL_TARGETS` allowlist.
4. Runs the PoC twice against the target and once against the control.
5. Requires every run to complete, capture all output, exit zero, and produce valid nonce-bound evidence.
6. Requires the two target evidence specifications to be deterministic.
7. Replays the target evidence request with the harness HTTP client against both origins. DNS is pinned at connect time, redirects remain on the bound hostname, and unsafe addresses are rejected unless explicitly authorized.
8. Requires both responses to be conclusive and the result to be `target_only`.
9. If the request declares a reflection canary, also requires target-only reflection of the harness-generated token.
10. Records a one-hour `pending_confirmation` bundle and returns control to the main agent.

A control transport failure is inconclusive, not a passing negative control. Blind/OOB claims fail closed because the current runner cannot prove that a callback came from the target rather than the PoC.

## 5. Phase 2 — main-agent-only decision

The main agent must personally:

1. Read the PoC bytes identified by the stored SHA-256.
2. Read the preserved target/control evidence and harness observations.
3. Check for trivial predicates, unconditional success, hard-coded proof, local mocks, and severity inflation.
4. Perform a concrete disconfirmation attempt.
5. Call `ConfirmFinding` with `CONFIRMED` or `NOT_CONFIRMED`.

On `CONFIRMED`, the tool re-sends the immutable request against the target and approved control with the harness HTTP client. Both responses must again be conclusive and `target_only`; the transcript is timestamped and stored with the verdict. A caller-supplied `re_executed` boolean is not accepted.

`CONFIRMED` requires `re_execution_note`, `differential: "target_only"`, reviewed evidence, reasoning, and the main agent's `disconfirmation_attempt`. It also requires `canary_assessment: "verified"` when the evidence requested a canary, or `canary_assessment: "not_applicable"` plus a concrete reason when that oracle does not fit the exploit class. Before committing, the ledger rechecks the pending bundle, its age, both machine differentials, the canary transcript when requested, the current case target, the PoC hash, and evidence provenance. The persisted verdict is stamped `reviewer: "main_agent"` and with the derived proof strength.

`NOT_CONFIRMED` records the reasoning, keeps the case investigating, and consumes the pending bundle. Any retry requires a fresh `PromoteFinding` run.

## 6. Enforcement boundaries

The design uses several independent controls:

- Worker agent definitions omit `PromoteFinding` and `ConfirmFinding`.
- Workflow text forbids delegating validation or confirmation.
- The extension captures `PI_SUBAGENT_CHILD` when it initializes and omits `PromoteFinding` and `ConfirmFinding` when that snapshot says worker. Its role check is monotonic (`started as worker` OR `currently marked worker`), so unsetting the variable in a child shell cannot upgrade the already-running extension.
- The ledger captures the same module-start role and independently checks the authority snapshot supplied by the extension before committing.
- Validation-stage worker output is no longer accepted; the main agent runs PromoteFinding and owns the pending bundle.
- The ledger is the only component that can transition the case to `confirmed`, and it records main-agent provenance.

The `confirmer_verdict_json` database column and a few internal `confirmerVerdict` identifiers are retained for backward compatibility with existing casefiles. They do not represent a confirmer worker.

## 7. Honest limits

- The fresh phase-2 network transcript is harness-owned, but the main agent's semantic review and disconfirmation are not cryptographically bound to an orchestration identity. The monotonic role snapshot closes the environment-unset gap inside a running extension; it does not stop a same-UID shell user from starting a new clean process or editing SQLite directly.
- The main agent still defines the semantic strength of the predicate and the severity judgment.
- A useful control must be supplied and approved by the operator; the harness can enforce identity and differential behavior, not prove that the control is an ideal patched twin.
- Reflection canaries are implemented, but source-separated OOB verification and general file/account/state canary oracles are not, so claims needing those channels remain investigating.

The next authority hardening step is an unforgeable, orchestration-issued main-agent capability (or OS-isolated broker) bound to the final verdict and ledger write.

## 8. Migration

Existing stored verdicts remain readable. New verdicts add `reviewer: "main_agent"`. Existing marker-era records are historical evidence only; all new promotions use the two-phase gate above.
