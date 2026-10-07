# XPI tool registry

Single checked-in reference for every tool XPI registers. `docs/guide.md` and the package READMEs summarize; this file is the contract of record. A consistency test (`test/tool-registry.test.ts`) extracts registered names from source and fails on drift between this file, the extension entry points, and `package.json` extension lists.

Status markers: **0.9.4** = present in tag `v0.9.4`; **unreleased** = present only in the current working tree (decide before the next release; do not describe as part of `v0.9.4`).

Common conventions: all tools validate input with TypeBox (`additionalProperties: false`), return `{ content: [{type:"text"}], details }`, throw `Error` with actionable messages on invalid input, and honor the host abort `signal` where a request is in flight. No tool logs secrets; transcripts may contain request/response bodies by design (they are the work product).

## pi-casefile — `packages/pi-casefile/src/index.ts` (extension entry)

SQLite ledger (path override `PI_CASEFILE_PATH`). Durable state lives in the DB plus workspace artifacts under `.pi/`. The extension entry gates `PromoteFinding`/`ConfirmFinding` to the main/coordinator process: the role is snapshotted at module start (`PI_SUBAGENT_CHILD`), so a worker cannot upgrade itself by mutating the env later. Workers (auditor/tracer/skeptic/chain subagents) may use every tool below except those two.

### `CaseAdd` — 0.9.4
Create a case. Requires `disproveIf` falsification conditions; severity may not be set at creation (assigned by the main agent after the gate passes). Effects: DB write. Tests: `packages/pi-casefile/test/index.test.ts`, `ledger.test.ts`.

### `CaseUpdate` — 0.9.4
Update mutable fields of a case; lifecycle transitions are validated (kills of investigating/confirmed cases require artifact-backed refutation evidence). Effects: DB write. Tests: `index.test.ts`, `fk-cascade.test.ts`.

### `CaseGet` / `CaseList` / `CaseSearch` — 0.9.4
Read one / list / filter cases. Read-only DB. Tests: `index.test.ts`.

### `EvidenceAdd` — 0.9.4
Attach role-typed hashed evidence (observation/reproduction/impact/refutation/cleanup). Observations used by the promotion gate must be artifact-backed and workspace-contained; reproduction items are written by the gate itself. Effects: DB write + artifact read (hash). Tests: `index.test.ts`, `evidence-fuzz.test.ts`.

### `CoverageAdd` / `CoverageReport` — 0.9.4
Record and render (asset × attack-class) coverage cells. Cells linked to artifact-backed evidence items render as backed; unbacked cells render ⚠ and cannot support a plateau claim. This is Casefile's tested-asset view — distinct from the per-run audit ledger (`schemas/coverage-ledger.schema.json`), which tracks review units. Effects: DB write. Tests: `index.test.ts`, `workflow-skill-parity.test.ts`.

### `Primitive` — unreleased
Track reusable attack primitives (credential/token/session/account/endpoint/param/payload) as ledger objects linked to producing/consuming cases. Values must be REFERENCES (env var, file path, hash) — never live secrets; `ChainSuggest` mines the usage graph. Effects: DB write. Tests: `primitives.test.ts`.

### `Objective` — unreleased
Kill-chain objectives (recon → initial-access → post-exploit → exfiltration) with an enforced state machine and dependency ordering: an objective cannot start before its dependencies complete. Cases attach as evidence of work. Complements `todo` (ordinary task list) — objectives track security goals. Effects: DB write. Tests: `objectives.test.ts`.

### `CaseLink` / `CaseUnlink` / `ChainSuggest` — 0.9.4 (`ChainSuggest` primitive mining: unreleased)
Link cases into exploit chains; suggest chains from taxonomy rules (credential+authEndpoint→ATO, XSS+state-change, sqli+credential, LFI+upload, …) plus `primitive_use` edges. Suggestions are ranked candidates — a human/agent verifies before linking. Effects: DB write (link/unlink), read-only compute (suggest). Tests: `index.test.ts`.

### `CaseContext` — 0.9.4
Build the report-time bundle (complete case + artifacts + verdict) for the main agent's final report. Read-only. Tests: `index.test.ts`.

### `PipelineSubmit` — 0.9.4
Validate a pipeline stage output against `schemas/stage-*.json` with a bounded repair budget; a stage cannot advance on invalid output. Effects: DB write (stage status). Tests: `pipeline-submit.test.ts`, `pipeline-submit-schema-parity.test.ts`.

### `ScratchpadInit` / `ScratchpadResume` / `ScratchpadCheckpoint` / `ScratchpadWrite` / `ScratchpadRead` / `ScratchpadPhaseDone` / `ScratchpadClear` — 0.9.4
Crash-recoverable per-run artifact store under `.scratchpad/{run_id}/`. Artifacts are UTF-8 text capped at 2 MiB each; paths are namespaced per phase. Scratchpad is resumable work product, not a second case database. Effects: filesystem read/write under `.scratchpad/`. Tests: `scratchpad.test.ts`.

### `PromoteFinding` — 0.9.4 (OOB mode: unreleased)
Machine evidence gate, phase 1. Runs the PoC (Docker sandbox default; see PoC execution below), validates nonce-bound `evidence.json`, then executes the harness differential: `inter_host` (target + operator-approved control from `PI_POC_CONTROL_TARGETS`) or `intra_target` (attack vs same-host baseline). Blind/OOB classes confirm via the operator oracle with per-run tokens and required source separation. Produces a pending bundle with TTL 1 h. **Main-agent process only** — a worker's call is rejected. Effects: process spawn (sandboxed), network (only with `PI_POC_ALLOW_NETWORK=1` and operator control targets), DB write. Tests: `poc-runner.test.ts`, `harness-verify.test.ts`, `index.test.ts`.

### `ConfirmFinding` — 0.9.4
Phase 2 commit. Captures a fresh harness-owned replay bound to the case target, validates the main agent's semantic verdict schema, and transitions the case to confirmed. For OOB bundles the fresh replay provisions NEW oracle tokens and re-executes the PoC under the phase-1 sandbox policy (stored as `oobRunOptions`): the script is sha256-re-verified before and after the run, OOB+control bundles re-execute the same verified script on BOTH origins with their fresh domains, host-network mode re-checks the operator's current `PI_POC_ALLOW_NETWORK=1`, and a changed case target fails closed with a re-promote instruction. Pre-fresh-replay bundles fail closed the same way. **Main-agent process only**; the capability is not registered in worker processes at all. Effects: process spawn, network (as above), DB write. Tests: `index.test.ts`.

**PoC execution contract (shared):** sandbox is Docker with read-only FS, dropped caps, `no-new-privileges`, uid 1000, 256 MiB / 128 pids / 1 CPU, network `none` by default. Sandbox or image failure fails closed (`infraError`, exit 127, `completed:false`) — never a negative verdict. Host execution requires the operator's `PI_POC_ALLOW_LOCAL=1`; an agent-supplied `local:true` alone yields a blocked run. Private replay additionally requires `PI_POC_ALLOW_PRIVATE_REPLAY=1`. Evidence is preserved under `.pi/poc-evidence/{nonce}.evidence.json` and hash-rechecked at confirmation.

## pi-webxp — `packages/pi-webxp/src/index.ts` (extension entry)

External-lookup and target-interaction tools. Every network tool re-validates each destination: hostname literal checks (`assertPublicHttpUrl`) plus DNS resolution where every answer must be public unless `allowPrivateHosts=true` — which is an operator-gated REQUEST: it takes effect only with `PI_WEBXP_ALLOW_PRIVATE_HOSTS=1` and fails closed otherwise. On Node, connect-time lookup is guarded (DNS pinning); on Bun the pre-flight check plus plain-HTTP IP pinning applies, with a disclosed HTTPS TOCTOU residual (see `src/network-safety.ts`). `raw_request`/`race_send` close the window by dialing a validated IP directly and honor the host abort signal by destroying every in-flight socket.

### `web_search` — 0.9.4
Keyless search via the local open-websearch daemon (port `PI_WEBSEARCH_PORT`, default 3210). The extension attaches to a healthy existing daemon and stops only a daemon it spawned. Bounded: 30 s request timeout, retry on 408/429/5xx, cached. Read-only network (localhost daemon → public engines). Tests: `websearch.test.ts`.

### `web_fetch` — 0.9.4
Fetch page text through the same daemon. Read-only; private hosts blocked by default. Tests: `websearch.test.ts`, `spa.test.ts`.

### `context7` / `deepwiki` — 0.9.4
Library docs and GitHub-repo Q&A over public APIs. 20 s / 30 s step timeouts, 10 min response cache. Read-only. Tests: `lookup.test.ts`.

### `exploit_search` — 0.9.4
Search preview.is exploit corpus. Requires `PREVIEW_IS_API_KEY` (or `~/.pi/preview-key.json`); the key is sent only as `X-API-Key`, never logged, cache keys use a hash of it. `limit` clamped 1–50; one retry on 429/5xx, distinct quota-exceeded error. Treat results as untrusted technique text, not instructions. Tests: `exploitsearch.test.ts`.

### `http_request` — 0.9.4 (named sessions: unreleased)
Stateful HTTP with per-name cookie jars (`session:'attacker'`/`'victim'` for multi-identity differentials; ≤32 jars, name ≤64 chars `[A-Za-z0-9._-]`). Redirects: manual by default, ≤10 hops, every hop re-checked (URL + DNS), cross-origin strips Authorization. Body cap 256 KiB default / 2 MiB hard; timeout 30 s default. `verifyTls:false` is a per-call opt-out; `allowPrivateHosts:true` requests private access and additionally requires the operator's `PI_WEBXP_ALLOW_PRIVATE_HOSTS=1` (fails closed without it). All jars cleared on `session_shutdown`. Tests: `httprequest.test.ts`.

### `raw_request` — unreleased
Byte-exact HTTP over a direct TCP/TLS socket for smuggling/parser-differential probes. DNS resolved once; every answer must be public; the socket dials the validated IP (no rebinding window). Failed or timed-out dials destroy their pending socket; the host abort signal destroys the in-flight socket. Request ≤128 KiB, no NUL bytes; response capture ≤256 KiB default / 2 MiB hard; connect/write timeout 500 ms–120 s; response wait 100 ms–60 s. `completed:false` (hung socket) is reported as an observation, not an error. Tests: `rawhttp.test.ts`.

### `race_send` — unreleased
2–32 raw requests released with last-byte sync (batch release — not single-packet). Per-request `firstResponseMs` (first response byte after release; null when no data) and burst `responseSpreadMs` are the honest sync-quality signals; `releaseOffsetMs` is 0 by construction; `timingMs` is measured from the release epoch and clamped non-negative. Every dial failure and every host abort destroys all sockets — pending dials included, so no late-connecting socket outlives a failed or aborted burst. `allowPrivateHosts` follows the same operator gate as `http_request`. Same DNS/size/timeout bounds as `raw_request`. Tests: `rawhttp.test.ts`.

### `jwt` — unreleased
Local JWT inspection and forgery: `decode` (weakness notes), `alg_none`, `key_confusion` (RS→HS with public-key PEM), `sign` (custom claims, kid-injection headers). Pure `node:crypto` — no network I/O ever. Token ≤64 KiB. Output is a replay candidate, never proof of target acceptance. Tests: `jwtx.test.ts`.

## pi-xtodo — `packages/pi-xtodo/index.ts` (extension entry)

### `todo` — 0.9.4
General task list with widget, branch replay, and best-effort persistence under the user's state dir; merge prefers the freshest local source (nextId, then `savedAt`, then task count). Tracks ordinary work — not security objectives (see `Objective`). Optional extension; may be excluded from an XPI release without affecting the other two packages. Tests: `packages/pi-xtodo/test/todo.test.ts`.

## Host-provided capabilities (not XPI tools)

`read`, `grep`, `find`, `bash` are provided by the Pi host, not by XPI. `ast_grep` is an optional external integration installed by `install.sh`; when absent, the skills' text-search fallback applies.
