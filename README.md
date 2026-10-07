<div align="center">

# XPI

**Security tooling for the Pi agent** — casefile tracking, web search, exploit-technique intelligence, code search, and todos.

[![npm version](https://img.shields.io/npm/v/@xaccefy/pi-xpi?style=flat-square&label=npm&color=cb3837)](https://www.npmjs.com/package/@xaccefy/pi-xpi)
[![npm downloads](https://img.shields.io/npm/dm/@xaccefy/pi-xpi?style=flat-square&label=downloads&color=4c9aff)](https://www.npmjs.com/package/@xaccefy/pi-xpi)
[![License: MIT](https://img.shields.io/github/license/xaccefy/pi-xpi?style=flat-square&color=blueviolet)](LICENSE)

</div>

## What it is

XPI turns the Pi agent into a security researcher: a case ledger with enforced gates, real exploit-technique grounding, web lookup, fast code search, and a pipeline that keeps findings honest.

- **Casefile** — hypothesis → investigating → confirmed → reported, with gates at every step
- **Attack transport** — byte-exact `raw_request` (smuggling/desync probes), last-byte-sync `race_send` (batch-release race exploitation; judge sync by the reported spread), multi-identity sessions, local JWT attack forging
- **Machine-owned PoC gates** — zero exit is necessary but never proof: direct-response findings require nonce-bound body evidence plus a DNS-pinned, conclusive `target_only` replay against an operator-approved control; reflection-capable requests can add a harness-generated target-only canary; blind/OOB classes confirm through an operator-run oracle with per-run tokens and source-separation attestation; only the main agent may make the semantic decision and commit phase 2
- **Exploit chains** — `ChainSuggest` surfaces combinations the model missed; `Primitive` tracks credentials/tokens/sessions as reusable ammunition; `Objective` keeps the kill chain moving
- **Coverage matrix** — machine-checkable "we tested everything" claims
- **Code search** — structural AST search (ast-grep) for sinks and call chains, plus built-in grep/find for text

## Install

Works on **Pi Agent** and its fork **OMP** (`@oh-my-pi/pi-coding-agent`). One manifest serves both: OMP reads the same `pi` extension field, the Agent Plugins `plugin.json` for skills, and the `task` tool spawns the specialist agents.

```bash
./install.sh            # auto-detects pi or omp in PATH
./install.sh --pi       # force Pi  (installs pi-subagents + optional ast-grep structural search)
./install.sh --pi --no-subagents  # minimal Pi install; use /xp lite because swarm dispatch is unavailable
./install.sh --omp      # force OMP (copies agents/*.md to ~/.omp/agent/agents)
```

Or install the npm package per host:

```bash
pi install npm:@xaccefy/pi-xpi     # Pi
omp install npm:@xaccefy/pi-xpi    # OMP
```

Set `PREVIEW_IS_API_KEY` for `exploit_search` (see [docs/guide.md](docs/guide.md)).

## Quick start

```
/xp        # toggle bounded swarm XP mode on/off
/xp lite   # explicit single-agent security workflow
/xp swarm  # bounded multi-agent pipeline
```

Use `/xp` for the default bounded swarm workflow, or `/xp lite` for CTFs, focused reviews, and one-target work where dispatch is unnecessary. On Pi, swarm dispatches only `auditor`, `tracer`, `skeptic`, and `chain` via pi-subagents; on OMP it uses the native `task` tool with the same four agent names. Validation, patching, reporting, and `ConfirmFinding` stay with the main agent.

Full tool reference, configuration, and pipeline docs: **[docs/guide.md](docs/guide.md)**.

## Packages

| Package | npm |
|---------|-----|
| Umbrella | [`@xaccefy/pi-xpi`](https://www.npmjs.com/package/@xaccefy/pi-xpi) |
| Case ledger | [`@xaccefy/pi-casefile`](https://www.npmjs.com/package/@xaccefy/pi-casefile) |
| Web lookup + exploit search | [`@xaccefy/pi-webxp`](https://www.npmjs.com/package/@xaccefy/pi-webxp) |
| Todos | [`@xaccefy/pi-xtodo`](https://www.npmjs.com/package/@xaccefy/pi-xtodo) |

## Develop

```bash
bun install
bun test --isolate
bun run typecheck
```
