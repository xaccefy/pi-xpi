---
name: engage
description: Authenticated web-pentest sessions for Pi — hold a user-supplied target identity (cookie / OAuth client-credentials / mTLS) and run curl / nuclei / httpx / ffuf with the auth injected. Use when the agent must operate against an authenticated web target inside a sanctioned engagement.
---

# engage

`engage` is a Pi Agent tool (`@xaccefy/pi-engage`) for **bounded autonomous web pentesting**: it
authenticates to an *authorized* target using an identity a human supplies, then runs web-pentest
actions with that auth applied. No intercepting proxy — resolved auth is handed straight to `curl`
and the pdtm tools, which capture their own output.

## Bounded autonomy (required)
- The agent **never invents, borrows, or self-authorizes** credentials. A human supplies the target
  + identity as a "session".
- Link a session to a casefile case with `caseId` so findings stay scoped to one engagement.

## Sessions — the human-supplied identity
Stored under `~/.pi/xpi-engage` (override with `PI_ENGAGE_DIR`). Auth modes:
- `cookie` — replay a browser `Cookie` header.
- `oauth-client-credentials` — agent is its own service identity; self-refreshing bearer token, zero
  human at runtime (**most autonomous**).
- `mtls` — client-certificate identity presented in the TLS handshake.

## Actions
Session management: `add | get | list | token | delete | clear`
- `token` resolves auth. For client-credentials it fetches a token and returns `headers`,
  `curlFlags`, and a ready `curl` example.

Pentest (auth injected): `run | send | spider | scan`
- `run tool=<cli>` — run a pentest CLI (`curl | nuclei | httpx | ffuf | subfinder | whatweb …`)
  with auth injected.
- `send` — single authenticated HTTP request; also returns a ready `curl` command.
- `spider` — crawl in-scope links with the session applied.
- `scan` — run nuclei if installed, else a passive security-header check.

## Typical flow
1. `engage action=add mode=oauth-client-credentials tokenUrl=… clientId=… clientSecret=… scope=… caseId=<case>` — create the sanctioned session.
2. `engage action=token id=<id>` — resolve auth (headers + curlFlags + curl example).
3. `engage action=run tool=nuclei args=["-u",<target>]` (or `tool=httpx` / `tool=ffuf`) — pentest with auth.
4. Log observations to `casefile`.

## Companion
The `/ops` prompt enforces the sanctioned-session rule. `casefile` is the findings ledger.
