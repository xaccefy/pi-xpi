<div align="center">

# XPI

**Security tooling for the Pi agent**: casefile tracking, web search, exploit-technique lookup, code search, and todos.

[![npm version](https://img.shields.io/npm/v/@xaccefy/pi-xpi?style=flat-square&label=npm&color=cb3837)](https://www.npmjs.com/package/@xaccefy/pi-xpi)
[![npm downloads](https://img.shields.io/npm/dm/@xaccefy/pi-xpi?style=flat-square&label=downloads&color=4c9aff)](https://www.npmjs.com/package/@xaccefy/pi-xpi)
[![License: MIT](https://img.shields.io/github/license/xaccefy/pi-xpi?style=flat-square&color=blueviolet)](LICENSE)

</div>

## What it does

XPI adds a security workflow to the Pi agent: a SQLite case ledger, staged hunting with specialist agents (auditor, tracer, skeptic, chain), and a PoC gate that checks claims against real target/control behavior instead of trusting the model's say-so.

- Casefile: hypothesis → investigating → confirmed → reported, with gates at each step
- Attack transport: byte-exact `raw_request`, last-byte-sync `race_send`, multi-identity sessions, local JWT forging
- PoC gate: nonce-bound evidence, DNS-pinned target/control replay (or a same-host baseline for access-control bugs); OOB findings need an operator-run oracle; only the main agent can confirm
- Chains and primitives for multi-step findings, objectives for the kill chain
- Coverage matrix, plus AST search (ast-grep) and plain grep for code

## Install

Works on Pi Agent and its fork OMP. One manifest serves both.

```bash
./install.sh            # auto-detects pi or omp in PATH
./install.sh --pi       # force Pi  (installs pi-subagents + optional ast-grep)
./install.sh --pi --no-subagents  # minimal Pi install; use /xp lite
./install.sh --omp      # force OMP (copies agents/*.md to ~/.omp/agent/agents)
```

Or from npm:

```bash
pi install npm:@xaccefy/pi-xpi     # Pi
omp install npm:@xaccefy/pi-xpi    # OMP
```

`exploit_search` needs `PREVIEW_IS_API_KEY` (see [docs/guide.md](docs/guide.md)).

## Quick start

```
/xp        # toggle bounded swarm mode on/off
/xp lite   # single-agent workflow
/xp swarm  # bounded multi-agent pipeline
```

Swarm dispatches only `auditor`, `tracer`, `skeptic`, and `chain`. Validation, patching, reporting, and `ConfirmFinding` stay with the main agent.

Full tool reference and configuration: [docs/guide.md](docs/guide.md).

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
