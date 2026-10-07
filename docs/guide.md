# XPI Guide

Full reference: tools, configuration, pipeline, and development. The root [README](../README.md) is the short overview.

## Hosts: Pi Agent and OMP

XPI runs on **Pi Agent** (`@earendil-works/pi-coding-agent`) and its fork **OMP** (`@oh-my-pi/pi-coding-agent`, binary `omp`). The same extension code, tools, ledger, and XP-mode workflow are used on both:

- **Extensions** — both hosts read the `pi` field in `package.json` (OMP also accepts an `omp` field; `plugin.json` is the Agent Plugins manifest OMP uses for skills).
- **Skills** — `skills/cyberwf`, `skills/web-pentest`, `skills/casefile` load on both hosts (OMP via the Agent Plugins provider).
- **Subagent dispatch** — `/xp lite` needs no dispatch dependency. `/xp` and `/xp swarm` use pi-subagents on Pi (`./install.sh --pi` installs it by default; `--no-subagents` skips it) or OMP's native `task` tool. The swarm workflow and the `cyberwf` skill describe both conventions; the extension injects the host-appropriate workflow automatically.
- **Swarm agents** — `/xp` / `/xp swarm` delegates only to auditor, tracer, skeptic, and chain. Recon, validation/PoC writing, patching, reporting, and ConfirmFinding stay with the main agent.

## Configuration

### Environment variables

| Variable | Package | Purpose |
|----------|---------|---------|
| `PREVIEW_IS_API_KEY` | webxp | Required for `exploit_search` ([preview.is](https://preview.is)) |
| `PI_XP_MODE` | casefile | `on` / `swarm` / `lite` / `off` — force casefile cyber-workflow injection (`on` is the default enabled mode: swarm; `lite` disables subagent dispatch) |
| `PI_CASEFILE_PATH` | casefile | Override SQLite ledger path |
| `PI_WEBSEARCH_PORT` | webxp | open-websearch daemon port (default `3210`). If a healthy daemon already answers on the port, XPI attaches to it and leaves it running at shutdown; only a daemon this process spawned is stopped |
| `PI_OOB_ORACLE_URL` | casefile | Operator-run OOB oracle base URL (`https://oracle.example`) — must be **https**, or `http` only on an exact loopback endpoint (`localhost`, `127.x.x.x`, `::1`); URLs with userinfo are rejected and redirects are refused (the interactions query carries the run token). Provision via `POST /provision {token} → {domain}`, poll via `GET /interactions?token=`. Errors report the origin only — run tokens never appear in logs |
| `PI_WEBXP_ALLOW_PRIVATE_HOSTS` | webxp | Operator gate for private/internal target access in `http_request` / `raw_request` / `race_send`. `allowPrivateHosts=true` in a tool call only takes effect when this is `1`; without it the call fails closed. Internal-lab operators set it for the session — agents cannot self-authorize |
| `PI_OOB_ORACLE_TOKEN` | casefile | Optional bearer token for the oracle API. Recommended: without it, run tokens stored in the ledger are pollable by anyone who can reach the oracle endpoint |
| `PI_OOB_SOURCE_SEPARATED` | casefile | Set `1` only when the network topology prevents the PoC sandbox from reaching the oracle directly (three-box model). Required for OOB promotion |
| `PI_OOB_SELF_IPS` | casefile | Comma-separated sandbox/host egress IPs — interactions from these are rejected as self-caused and never counted as target hits |
| `PI_OOB_POLL_MS` / `PI_OOB_INTERVAL_MS` / `PI_OOB_SETTLE_MS` | casefile | OOB polling tuning: total window (default 30s), poll interval (2s), and how long to keep watching after the first interaction (5s) so delayed control-token hits cannot be missed |

```bash
export PREVIEW_IS_API_KEY="rk_yourkeyhere"
```

## Tools

| Tool | Use for |
|------|---------|
| `exploit_search` | Attack techniques, primitives, bypasses (`PREVIEW_IS_API_KEY`) |
| `web_search` | CVEs, advisories, documentation |
| `web_fetch` | Page content from an HTTP(S) URL |
| `context7` | Current library docs |
| `deepwiki` | Q&A on a public GitHub repo |
| `http_request` | Stateful raw HTTP with a persistent cookie jar. `session:'attacker'` / `session:'victim'` hold multiple authenticated identities at once — replay a victim object URL under the attacker session to prove IDOR/access-control bugs without losing either login |
| `raw_request` | Byte-exact HTTP over a direct TCP/TLS socket — nothing normalized or re-framed. Request-smuggling probes (CL.TE/TE.CL desync), parser differentials, malformed framing; a hung socket (`completed:false`) is the classic desync timing signal |
| `race_send` | 2–32 raw requests released with last-byte sync (batch release — not single-packet; check the reported response-side spread `responseSpreadMs`) — coupon over-redemption, balance overdraft, invite/limit bypass. Pair with the race-conditions methodology: burst vs serial baseline, reproduce ≥2× |
| `jwt` | Decode JWTs and forge attack variants locally: structural decode with weakness notes, `alg:none`, RS→HS key confusion (public-key PEM as HMAC secret), custom HS* signing with attacker claims and kid-injection headers. Output is a candidate to REPLAY — proof is the target accepting it |
| `CaseAdd` / `CaseUpdate` / `PromoteFinding` / `ConfirmFinding` | Ledger + two-phase PoC gate. PromoteFinding picks a differential `mode`: **`inter_host`** (default) runs the PoC twice on target + once on an operator-approved control host for body-carried proof (file read, injection, info leak, reflection); **`intra_target`** proves access-control / business-logic classes (IDOR, auth bypass, privilege escalation, logic) with a same-host `baseline` request declared in the evidence (`verify.mode:"intra_target"`) — the harness sends attack + baseline to the target and requires the proof on the attack only, no control host. Both validate nonce-bound response-body evidence, then a DNS-pinned replay requiring a conclusive `target_only` differential. Reflection requests can add a post-PoC harness-generated canary that must appear only on target. Zero exit is run integrity, never proof. ConfirmFinding is main-agent-only, captures a fresh second replay, and binds it to the semantic verdict; worker/subagent gate calls are rejected. Private replay is operator-gated; blind/OOB claims fail closed without source separation |
| `EvidenceAdd` | Role-typed, hashed evidence items (observation/reproduction/impact/refutation/cleanup); refutation justifies kills; reproduction auto-recorded by the PoC gate |
| `CaseGet` / `CaseList` / `CaseSearch` | Browse cases |
| `CaseLink` / `CaseUnlink` | Exploit chains |
| `ChainSuggest` | Auto-detect exploitable chain combinations across cases (credential+endpoint→ATO, XSS+state-change→CSRF, SSTI→RCE, race+payment, primitive_use, …), ranked — verify before linking |
| `Primitive` | Attack primitives as first-class ledger objects: credentials, sessions, tokens, accounts, endpoints, params, payloads linked to producing/consuming cases. Store REFERENCES (env var, file, hash), never live secrets. ChainSuggest mines the usage graph for escalation paths |
| `Objective` | Kill-chain objectives (recon → initial-access → post-exploit → exfiltration) with an enforced state machine and dependencies — an objective cannot start until its dependencies completed. Cases attach as evidence of work; this answers "am I winning?" while cases answer "is this bug real?" |
| `CoverageAdd` / `CoverageReport` | Machine-checkable test coverage: record (asset × attack-class) cells with wide/local scope, linked to artifact-backed evidence items (`evidence_item_id`); unbacked cells render as ⚠ unbacked, and the plateau claim must match the matrix |
| `CaseContext` | Case context bundle (complete record + artifacts) for the main agent's final report |
| `PipelineSubmit` | Stage-output validation gate: schema check + pre-filter + repair budget — stage can't advance on invalid output |
| `ScratchpadInit` / `Resume` / `Checkpoint` | Crash-recoverable artifact store for pipeline runs |
| `ScratchpadWrite` / `Read` / `PhaseDone` / `Clear` | Write, read, and resume pipeline artifacts |
| `/casefile` | Case dashboard |
| `/xp` | Toggle casefile **XP mode** (bare `/xp` toggles the bounded swarm pipeline; `lite` = single-agent workflow; **default OFF**) |
| `todo` / `/todos` | Multi-step task lists |
| `ast_grep` | Structural (AST) code search via [ast-grep](https://ast-grep.github.io) — `run` (pattern match) + `scan` (rule check) modes; enumerate sinks and walk call chains by code shape, not text. Installed by `install.sh` (needs the `ast-grep` binary on PATH). Text search stays on pi's built-in `grep`/`find`. |

## Quick start

```
/xp                                         # toggle bounded swarm XP mode on/off
/xp lite                                    # explicit single-agent security workflow
/xp swarm                                   # bounded multi-agent pipeline for broad audits
```

CaseAdd requires `disproveIf` (falsification conditions) on every new case; a kill of a case that ever reached investigating/confirmed requires artifact-backed refutation evidence. Confirmation is two-phase: **PromoteFinding** runs the same PoC twice against the case target and once against a distinct control pre-approved in `PI_POC_CONTROL_TARGETS`; `control_path` defaults to `poc_path` and is sha256-checked if supplied. Every run must exit zero, complete with fully captured output, and write nonce-bound `evidence.json` with `body_contains` or `body_regex` (status-only is rejected). Those are integrity checks, not proof. The harness binds `verify.url`, pins DNS into each connection, locks redirects to the bound host, derives the control URL, sends the same request to both origins, and requires two conclusive responses with `target_only`. This is the default **`inter_host`** mode. For access-control and business-logic classes (IDOR/BOLA, auth bypass, privilege escalation, mass assignment, logic/price tampering) — where the discriminating variable is the attacker's identity or a request parameter, not the host, so a different host lacks the victim's object/state — promote with **`mode: "intra_target"`**: the evidence declares `verify.mode: "intra_target"` and a legitimate same-host `baseline` request, and the harness requires the attack response to satisfy the predicate while the baseline (same host, no attack) does not. No control target is used. Reflection-capable evidence may place exactly one `{{PI_POC_CANARY}}` in the request and declare `verify.canary`; after the PoC exits, the harness substitutes a fresh secret and requires target-only reflection without persisting the raw token. Private replay requires `PI_POC_ALLOW_PRIVATE_REPLAY=1`, and any networked PoC requires `PI_POC_ALLOW_NETWORK=1`. Blind/OOB classes confirm through the operator-run oracle (`PI_OOB_ORACLE_URL`): the harness provisions per-run callback tokens, injects `PI_POC_CALLBACK_DOMAIN` into the runs, and polls the oracle itself — target-token interactions with zero control-token interactions are required, self-source interactions (`PI_OOB_SELF_IPS`) are rejected, and promotion additionally requires attested source separation (`PI_OOB_SOURCE_SEPARATED=1`). Without an oracle, OOB fails closed. After the machine gate, the **main agent itself** reads the exact evidence/script, attempts disconfirmation, and calls **ConfirmFinding**; that main-only call captures and stores a fresh second target/control replay before committing — for OOB bundles the fresh replay provisions NEW oracle tokens and re-executes the PoC (sha256-re-verified before and after; OOB+control bundles re-run the same verified script on both origins with their fresh domains; host-network mode re-checks the operator's current `PI_POC_ALLOW_NETWORK=1`; a changed case target fails closed), so the differential is a fresh observation rather than a re-read of phase-1 interactions (bundles that predate fresh-replay support fail closed with a re-promote instruction). A worker's role is snapshotted at extension initialization, so unsetting `PI_SUBAGENT_CHILD` cannot upgrade the running extension; this is a process-role guard, not protection against a same-UID process or direct SQLite mutation. Promotion also requires an artifact-backed, workspace-contained `observation` evidence item.

Pi injects skill descriptions (`web-pentest`, `cyberwf`) into every session; the agent reads the full skill file when the task matches. Use `/xp` for the default bounded multi-agent pipeline, or `/xp lite` for CTFs, focused reviews, and one-target work where dispatch is unnecessary.

## Skeptic + scratchpad — how findings stay honest

The pipeline has two mechanisms that keep findings honest:

- **Skeptic stage** — before a high-confidence finding reaches validation, a dedicated skeptic subagent independently re-reads the source (or re-probes the live endpoint) and tries to *disprove* it. If the skeptic finds a concrete reason the finding is false (a missed defense, an unreachable entry point, self-only impact), the finding is killed on the spot — no tie-breaker.
- **Design & runtime check** — before CONFIRMED, every finding must survive a search for the design decision: docs/README, git history, changelog, and whether the runtime/framework version already mitigates the path. Documented intent → kill `intended_behavior`; runtime already blocks it → kill `framework_protection`; neither → the search notes become the non-intentionality evidence the report needs.
- **Scratchpad** — a crash-recoverable artifact store. Each pipeline phase writes its intermediate output (recon maps, trace outputs, verification logs) to `.scratchpad/{run_id}/` instead of stuffing everything into casefile text fields. If a run crashes mid-pipeline, resume picks up from the last checkpoint without re-running completed phases.

See `skills/cyberwf/SKILL.md` for the full stage machine and API.

## Code search (ast-grep)

XPI uses [ast-grep](https://ast-grep.github.io) (`pi-ast-grep`) for **structural** code search — it parses source to a syntax tree and matches by code shape, so a query like "every `eval($X)` call" or "SQL built from string concatenation" hits real call sites, not comments and strings. This is the layer a security audit actually needs: precise sink enumeration and call-chain walking, with far fewer false positives and misses than text grep.

`install.sh` installs the `pi-ast-grep` extension plus the `ast-grep` binary it wraps (`npm i -g @ast-grep/cli`, or `cargo install ast-grep`). No env var or override mode — it registers a distinct `ast_grep` tool with `run` (ad-hoc pattern) and `scan` (rule-based) modes across TypeScript, JavaScript, Python, Rust, Go, and more. It is read-only (no rewrite).

Structural search does **not** replace lexical search. Text patterns (error strings, config, saved HTTP responses, minified bundles, non-code files) still go through pi's built-in `grep`/`find`. Rule of thumb for the auditor/tracer/skeptic agents: **`ast_grep` for code shape, `grep`/`find` for raw text.** Neither uses `bash` — never shell out to `rg`/`grep`/`ast-grep` for code search.

## Run records (source audits and structured runs)

Beyond the live-assessment pipeline, XPI keeps machine-checkable run records for source-first audits (`skills/repo-audit`) and any structured run:

| Record | Schema | Validator |
|---|---|---|
| Run manifest — revision, dirty state, mode (`source_audit` / `authorized_live`), profile, scope, authorization, budget, execution policy | `schemas/audit-run.schema.json` | `node scripts/validate-records.js <manifest.json>` |
| Coverage ledger — per-run review units with stable IDs, statuses, reviewed paths, and evidence-backed checks | `schemas/coverage-ledger.schema.json` | same validator, `--type ledger` |
| Finding record — final `confirmed` / `needs_validation` / `rejected` disposition with verification provenance | `schemas/finding-record.schema.json` | same validator, `--type finding` |

Rules the validator enforces: `authorized_live` requires an authorization record; `source_audit` cannot use target network; a unit closed as `covered` needs reviewed paths **and** evidence-backed checks ("agent found nothing" is not coverage); `confirmed` needs independent-verifier and record-check provenance. The full tool contract reference is [docs/tool-registry.md](tool-registry.md); a consistency test (`test/tool-registry.test.ts`) fails when it drifts from the registered tools.

Two fresh-context roles support this flow: **coverage-critic** (proposes missing/reopened units after a hunt wave; writes nothing) and **finding-verifier** (independently checks the smallest decisive fact per surviving candidate; cannot confirm).

## Structure

```
pi-xpi/
├── agents/                  # auditor, tracer, skeptic, chain, coverage-critic, finding-verifier
├── packages/
│   ├── pi-casefile          # ledger, poc-runner, workflow, scratchpad
│   ├── pi-shared
│   ├── pi-webxp
│   └── pi-xtodo
├── schemas/                 # stage-* pipeline schemas + audit-run, coverage-ledger, finding-record
├── scripts/                 # bump-version, check-pack, validate-records
├── skills/                  # web-pentest, cyberwf, repo-audit, casefile (auto-loaded)
├── install.sh
└── package.json
```

## Develop & release

```bash
bun install
bun test --isolate
bun run typecheck
```

**Release (CI):** GitHub Actions → **Release** workflow → choose `patch` / `minor` / `major`.
Requires repo secret `NPM_TOKEN`. The job runs tests, bumps all workspace versions, publishes every package + umbrella, tags `vX.Y.Z`, and pushes.
