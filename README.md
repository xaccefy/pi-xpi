<div align="center">

# XPI

**Security tooling for the Pi agent** — casefile tracking, web search, exploit-technique intelligence, code search, and todos.

[![npm version](https://img.shields.io/npm/v/@xaccefy/pi-xpi?style=flat-square&label=npm&color=cb3837)](https://www.npmjs.com/package/@xaccefy/pi-xpi)
[![npm downloads](https://img.shields.io/npm/dm/@xaccefy/pi-xpi?style=flat-square&label=downloads&color=4c9aff)](https://www.npmjs.com/package/@xaccefy/pi-xpi)
[![License: MIT](https://img.shields.io/github/license/x4cc3/pi-xpi?style=flat-square&color=blueviolet)](LICENSE)

</div>

## What it is

XPI turns the Pi agent into a security researcher: a case ledger with enforced gates, real exploit-technique grounding, web lookup, fast code search, and a pipeline that keeps findings honest.

- **Casefile** — hypothesis → investigating → confirmed → reported, with gates at every step
- **Honest PoC gates** — exit 0 + verification marker + mandatory control-target run with liveness marker on every promotion (no fake confirms)
- **Exploit chains** — `ChainSuggest` surfaces combinations the model missed
- **Coverage matrix** — machine-checkable "we tested everything" claims
- **Code search** — fff-powered grep/find, frecency-ranked

## Install

Works on **Pi Agent** and its fork **OMP** (`@oh-my-pi/pi-coding-agent`). One manifest serves both: OMP reads the same `pi` extension field, the Agent Plugins `plugin.json` for skills, and the `task` tool spawns the specialist agents.

```bash
./install.sh            # auto-detects pi or omp in PATH
./install.sh --pi       # force Pi  (adds pi-subagents + optional fff search)
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
/xp on     # enable the cyber workflow (subagent pipeline)
/xp lite   # single-agent variant
```

On Pi, `/xp on` dispatches specialist subagents via pi-subagents; on OMP it uses the native `task` tool with the same agent names (auditor, tracer, skeptic, exploit, chain, reporter, confirmer — installed by `install.sh --omp`).

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
