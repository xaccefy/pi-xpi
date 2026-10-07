# Chalk — Offensive-Security Agent Platform on DeepSeek Harness

> Brand: the DSH-native plugin platform is named **Chalk**. "XPI" below refers to the
> legacy Pi-extension repo (`@xaccefy/pi-xpi`) this port is derived from; the preset is
> `chalk`, the board is the shared chalkboard, and the tools are `chalk_*`.

> Status: Phase 0 done — the `chalk` preset is mounted and mount-validated
> (`~/.dsh/.agent-presets/chalk/agent.cordis.yml`); Phase 1 prototype (shared board +
> model auth config) is running in-session under the `chalk-2` plugin. This document is
> the broad implementation spec for running Chalk (the security orchestration formerly
> known as XPI) natively on DeepSeek Harness (DSH), replacing the Pi/OMP host entirely.

## 1. Vision

- **No Pi.** All XPI capabilities become DSH-native: an agent preset (prompt/orchestration
  shell), host-plugin packages (casefile ledger, scratchpad, PoC verification gates), and
  skill files (methodology + role prompts). No fork of DSH — presets, profile patches,
  and plugins.
- **Budget discipline.** Tool-call budget is the core problem. The split is structural,
  **not vendor-specific**: the HEAD runs the stronger model (GLM was only an example),
  and every SUBAGENT runs a faster/cheaper model (e.g. DeepSeek V4 Flash). No model runs
  the agent loop "thinking in circles" — DSH's goal rounds, background subagents, workflow
  fan-out, and no-poll design replace ad-hoc loop behavior.
- **Plugin auth config.** The model split (head = stronger, subagent = faster) and every
  API key are the plugin's **auth config**: provider + model + key references come from
  the plugin's settings/credentials, never hardcoded (see §7).
- **Remote.** Operators do NOT expose the Web GUI (it intentionally binds 127.0.0.1).
  The remote channel is **dsh-remote** (github.com/flymysql/dsh-remote): each operator's
  DSH connects OUT via SSH/SFTP to the central server, picks the remote workspace, and
  works in a real local mirror (`$DSH_HOME/remote-workspaces/<host>-<user>-<port>/`).
  All operators and their agents share the same server-side workspace + board through
  conflict-aware `rw_sync`/`rw_push`.
- **Shared scratchboard.** A cross-session, cross-agent discovery store: whatever an
  agent finds (a bug, a primitive, an exploit chain) is written to the board as a
  **host-plane service**, and OTHER agents read it — board tools + a per-session digest
  injection + ChainSuggest across all agents' cases.
- **setup.sh** provisions the whole deployment from a clean Ubuntu VPS: DSH install,
  profile configuration, model route from the plugin auth config, the `chalk` preset, the
  host plugin package, reverse proxy + TLS, systemd service, and the Web GUI.

## 2. Planes (DSH composition rules that constrain the design)

| Plane | What lives there | XPI mapping |
|---|---|---|
| HOST composition (`~/.dsh/profiles/<name>/cordis.patch.yml` + profile bundles) | registries (`tools`, `subagents`, `systemPrompt`), persistence, sandbox/approval, model route, anything cross-session | casefile ledger service, scratchpad service, PipelineSubmit/evidence/PoC gate tools, role-gate logic, web dashboard slots |
| Profile bundle **dsh-remote** | remote-IO substrate: SSH registry, mirrored remote workspaces, 21 `rw_*` tools, port forwarding, sidebar client half | the remote connection layer (connect-out, not expose-in); the shared board lives INSIDE the mirrored workspace so every operator syncs the same state |
| AGENT PRESET (`~/.dsh/.agent-presets/<id>/agent.cordis.yml`) | one session's persona, prompt sections, skill rows, delegation tools | `chalk` preset: coordinator persona + cyber workflow instructions (`workflow.ts` text), `web-pentest`/`cyberwf`/role skills, existing `tool-subagent`/`tool-workflow`/`tool-jobs` rows |
| Dynamic Cordis Plugin (session-scoped, runtime-only) | prototypes, probes. **No fs/sqlite/network** (builtins limited to ctx/harness/console/base64/Text*) | Phase-1 prototype: `pipeline_submit` gate + storageDomain casefile-lite (reaches host services via `ctx.get`) |

Rules that bite:
- A preset row publishing a service MUST sit behind an `isolate` realm, and shared
  services must NOT be per-session → the ledger/scratchboard live on the host plane.
- A dynamic plugin cannot `import`, `fetch`, read files, or hash — all trust-critical
  code (sha256 evidence binding, DNS-pinned harness replay, Docker PoC sandbox) goes into
  a real npm package composed into the profile: `@xaccefy/dsh-chalk`.
- Never edit the shipped `standard` preset; always `agentPresets.copy('standard', 'chalk')`
  and edit the copy. Validate with `agentPresets.standingKeyFor('chalk')`.

## 3. Model route (plugin auth config)

Current state (this machine): `settings.yaml` has
`llm-pi-ai.providers.opencode-go` (env `OPENCODE_GO_API_KEY`) and
`agent-default-model: { provider: opencode-go, model: deepseek-v4-flash }`.

The split is **config, not code**:

- **Head (stronger):** `agent-default-model` — the coordinator's model. GLM is only an
  example; whatever the deployment routes here must be the *stronger* of the two.
- **Subagents (faster):** DeepSeek V4 Flash by default — every `subagent`/`workflow`
  child call carries an explicit per-call `provider`/`model` override so the head loop is
  never burned on cheap-fan-out work.
- The plugin reads both from its **auth config** (settings namespace + credentials, §7);
  the coordinator gets the resolved ids through `chalk_config` and injects them into every
  dispatch.
- Budget levers: goal `max_goal_rounds`, workflow concurrency caps, ralph `maxRounds`,
  compaction thresholds, token-meter visibility.

## 4. Component map (XPI → DSH)

| XPI piece | DSH target | Change |
|---|---|---|
| `workflow.ts` injection + `cyberwf` skill | `chalk` preset `persona` + `agent-instructions` section; skill rows | text re-host; once-per-session by composition |
| `agents/{auditor,tracer,skeptic,chain}.md` | skill files (loaded by coordinator) or inline subagent prompts; children share the tool catalog (no per-role whitelist) | frontmatter `tools:` → prompt instructions |
| pi-subagents `runs.all` / OMP `task` | native `subagent` (background, parallel), `workflow` tool (phases, schema), `send_message`/`interrupt_agent`/`list_agents` | dispatch shapes → DSH calls |
| `pipeline-submit.ts` (SPECS, pre-filter, dedup, repair budget) | host tool `pipeline_submit` (port the pure-JS validator verbatim) | io: file state → `storageDomain`/`fs` service |
| `scratchpad.ts` | host tools `Scratchpad*` over `ctx.get('fs')`, same `.scratchpad/{run_id}/` layout | root via `sandboxPolicy.workspaceRoot` |
| casefile ledger (SQLite) + `Case*`/`EvidenceAdd`/coverage/`ChainSuggest`/`Objective` | host package `@xaccefy/dsh-chalk` (node:sqlite or storageDomain), shared (host-plane) | per-engagement keying; heavy reads on worker threads |
| main-agent-only gates (`PI_SUBAGENT_CHILD`) | runtime role check in tool handlers via `agents` service (`roots()`/`isOwnedBy`) | stronger identity, verify caller hook at build |
| `poc-runner.ts` + `harness-verify.ts` + `oob-oracle.ts` | host package (undici + node:dns for DNS-pinned replay; `subprocess`/`sandboxPolicy` for PoC exec) | evidence contract / differential logic ports verbatim |
| `pi-webxp` tools | DSH native `web_search`/`web_fetch`; `exploit_search` thin tool over `web` fetch; `http_request`/`raw_request`/`race_send`/`jwt` → host package | SSRF guards port |
| remote host access (Pi's bash-over-SSH patterns) | **dsh-remote bundle**: 21 `rw_*` tools over mirrored workspaces (read/write/edit/exec/search/sync/tunnels) | connect-out instead of expose-in; `rw_exec` replaces raw SSH shell patterns |
| `/xp`, `/casefile` dashboard, `/todos` | `commands` rows in preset; Client-half plugin for a casefile Slot; DSH `tool-todo`/goals | TUI → Slot/theme |
| `bench/` + XBOW runner | keep as repo tests; runner spawns a DSH session at the target instead of `pi -p` | wiring only |

## 5. Build phases

- **Phase 0 — preset**: `agentPresets.copy('standard','chalk')` — ✅ mounted + validated
  (`~/.dsh/.agent-presets/chalk/agent.cordis.yml`, legacy `xpi` id removed); persona/instructions/skills
  `standingKeyFor` mount validation. ← in progress
- **Phase 1 — prototype**: dynamic plugin in the dev session proving `pipeline_submit`
  (+ storageDomain casefile-lite + root-only gate). Proves tool/identity wiring before
  any deployment edit.
- **Phase 2 — host package**: `@xaccefy/dsh-chalk` (ledger, scratchpad, PoC gates, replay),
  composed via `~/.dsh/profiles/web/cordis.patch.yml`.
- **Phase 3 — skills/agents/bench**: port skills + role prompts; run the soundness suite
  and an XBOW smoke under DSH.
- **Phase 4 — server**: `setup.sh` for a clean Ubuntu VPS: SSH user/key + remote
  workspace layout on the server; operator side: `dsh plugin add dsh-remote` + default
  machine in `cordis.patch.yml`, profile config with the model route from the plugin auth
  config (stronger head, fast subagents), the `chalk` preset, and the host plugin package.
  One script toggles the whole deployment.

## 6. Hard constraints (from DSH composition rules)

- Shared scratchboard = host-plane service; never per-session.
- Shipped presets are read-only sources; user presets live under
  `~/.dsh/.agent-presets/<id>/` and are validated by `standingKeyFor`.
- Trust machinery needs real npm packages (dynamic plugins cannot).
- Sandbox/approval stay host-plane; a preset is exactly as privileged as the rows it names.

## 7. Plugin auth config, remote operation, shared board

### 7.1 Auth config (model split + keys)

The plugin's configuration namespace (registered by the host package in Phase 2; the
dynamic probe resolves what it can read-only today):

```yaml
chalk:
  models:                       # resolved 2026-08-26 from the opencode-go provider list
    head:     { provider: opencode-go, model: deepseek-v4-pro }   # coordinator loop (strong)
    subagent: { provider: opencode-go, model: deepseek-v4-flash } # audit/trace/skeptic/chain (fast)
  keys:
    previewIs: credential://chalk/preview-is     # exploit_search (preview.is)
    webSearch: credential://chalk/web-search     # optional search provider key
  board:
    location: <remote-workspace>/.dsh-chalk/board.json   # shared via dsh-remote mirrors
    digestMax: 12                              # entries injected at session start
  remote:      # dsh-remote default machine (also lives in its own cordis.patch.yml)
    host: <server-ip>
    username: <user>
    privateKeyPath: ~/.ssh/id_ed25519
    workspace: <remote-workspace>
```

- The coordinator reads `chalk_config` (resolved head/subagent ids + key status) before
  dispatching and stamps every `subagent`/`workflow` child call with the subagent model.
- Keys live in `credentials`/`settings`; the plugin never hardcodes secrets.
- Network/SSH credentials are dsh-remote's own config (key/password/passphrase/agent/
  keyboard-interactive/proxy/TOFU host-key) — that IS the remote auth config.
- **Applying the head model today**: the `agent-default-model` namespace in
  `~/.dsh/settings.yaml` was set to `opencode-go/deepseek-v4-pro` (strong) and takes
  effect on the next harness start; subagent calls keep `deepseek-v4-flash` per-call.
  Caveat: the settings *service* rejects plugin-realm objects (strict plain-object
  checks), so the write path for this namespace lives in the Phase-2 host package, not a
  dynamic plugin.

### 7.2 Remote operation (via dsh-remote)

- The harness Web UI stays bound to 127.0.0.1 on every operator's machine. **Remote
  access = connect-out**: `dsh plugin add dsh-remote` (profile bundle), configure the
  server machine (host/port/user + key or password, passphrase, agent,
  keyboard-interactive, proxy/jump, TOFU host-key), pick the remote workspace, and the
  plugin mirrors it into a real local workspace (`$DSH_HOME/remote-workspaces/...`).
- The 21 `rw_*` tools are the remote substrate: `rw_list_dir`, `rw_read_file`,
  `rw_write_file`, `rw_edit` (mtime optimistic lock), `rw_exec`, `rw_search`,
  `rw_forward` (SSH tunnels), `rw_sync`/`rw_push` (conflict-aware mirror sync).
- `setup.sh` provisions the server side (SSH user/key, workspace layout) and the
  operator side (`dsh plugin add dsh-remote` + default machine in `cordis.patch.yml`).
- All operators' DSH instances share ONE remote workspace; the shared board + ledger
  files live inside it, so every mirror carries the same server-side state, and
  conflicts from concurrent agent writes are surfaced (never silently overwritten).

### 7.3 Shared scratchboard (cross-agent discoveries)

- **The board's home is the remote workspace** (works with the dsh-remote mirror model):
  `<remote-workspace>/.dsh-chalk/board.json` (+ casefile ledger next to it) — every
  operator's local mirror syncs it via `rw_sync`/`rw_push`. On a single-process
  deployment the same files are served by a **host-plane casefile service** backed by
  `storageDomain` (schema-validated).
- **Board tools** (`chalk_board_add` / `chalk_board_list`) abstract it; kinds mirror XPI
  (`case|evidence|primitive|chain|note|objective`).
- **Digest injection**: at each session start the plugin injects the current board digest
  (recent entries + open cases), so every agent starts with what the others found — the
  DSH version of XPI's per-prompt active-case context.
- **Cross-agent chaining**: `ChainSuggest` runs over the whole shared graph (not one
  agent's cases), so an IDOR found by agent A and a leaked token logged by agent B become
  a suggested ATO chain for agent C.
- **Read API**: board/ledger read endpoints exported through `apiProxy` Remote methods so
  the Web dashboard and external clients can query them.
- Prototype note: the Phase-1 dynamic plugin demos the board with an `fs`-backed JSON
  file (`~/.dsh/chalk-board/board.json`, visible to every session on the process); the
  dsh-remote deployment moves it into the mirrored workspace; the authoritative ledger
  uses `storageDomain`.