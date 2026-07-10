# pi-engage

Authenticated-session manager + **pdtm-tool bridge** for [Pi Agent](https://github.com/earendil-works/pi) — part of **XPI**.

`pi-engage` gives the XPI offensive toolchain a sanctioned place to hold the
credentials a **user supplies** for an authorized engagement (the `engage`
prompt forbids inventing or borrowing them). It resolves a session into request
headers / mTLS flags and hands them straight to `curl`, `nuclei`, `httpx`,
`ffuf`, `subfinder`, `whatweb`, … — **no MITM proxy required**. The pdtm tools
already capture their own output, so a Burp/Caido intercepting proxy is optional
observability, not a prerequisite.

## Auth modes

| Mode | What it stores | Autonomy | Notes |
|------|----------------|----------|-------|
| `cookie` | raw `Cookie` header | Low — user re-pastes on expiry | Simplest; the agent impersonates the logged-in user |
| `oauth-client-credentials` | `tokenUrl`, `client_id`, `client_secret`, `scope` | **High — no human at runtime** | Agent is its own service identity; token is fetched + auto-refreshed |
| `mtls` | client cert/key + CA path | **Highest — no token exchange** | TLS handshake *is* the auth |

## Tools

### `engage`

| Action | Args | Purpose |
|--------|------|---------|
| `add` | `label`, `mode`, mode-specific fields, optional `target`/`caseId`/`id` | Save a session |
| `get` | `id` | Show one session (secrets masked) |
| `list` | — | List all sessions |
| `token` | `id` | Resolve a session into `headers`, `curlFlags`, `curlExample` (fetches/refreshes token for oauth) |
| `delete` | `id` | Remove a session |
| `clear` | — | Remove all sessions |
| `run` | `tool`, `url`, optional `sessionId`/`args` | Run a pentest CLI with auth injected (`curl`/`nuclei`/`httpx`/`ffuf`/…) |
| `send` | `url`, optional `sessionId`/`method`/`body`/`headers` | Single authenticated request (returns a `curl` command) |
| `spider` | `url`, optional `sessionId`/`inScope`/`depth` | Crawl in-scope links with the session applied |
| `scan` | `url`, optional `sessionId` | Run `nuclei` if installed, else a passive security-header check |

### `/engage`

Show stored sessions (interactive).

## Examples

```text
# Cookie (user pastes from browser devtools)
engage action=add label=shop target=shop.example.com mode=cookie cookie="session=abc123; csrf=xyz"

# OAuth client-credentials — agent's own identity, zero human at runtime
engage action=add label=shop-api target=api.shop.example.com mode=oauth-client-credentials \
     tokenUrl=https://auth.shop.example.com/oauth/token \
     clientId=pentest-agent-01 clientSecret=*** scope="pentest:read pentest:test"

# mTLS — certificate presented in the TLS handshake
engage action=add label=shop-mtls target=api.shop.example.com mode=mtls \
     certPath=~/certs/agent.pem keyPath=~/certs/agent.key caPath=~/certs/ca.pem

# Run a real scanner authenticated — auth is injected automatically
engage action=run tool=nuclei url=https://shop.example.com sessionId=shop-api args="-silent -json"

# Single authenticated request; result includes a ready curl command
engage action=send url=https://shop.example.com/account sessionId=shop

# Authenticated discovery
engage action=spider url=https://shop.example.com/ sessionId=shop inScope=["shop.example.com"]

# Scan: nuclei if present, else passive header check
engage action=scan url=https://shop.example.com/ sessionId=shop
```

`run` builds e.g. `nuclei -H "Authorization: Bearer <token>" -u https://shop.example.com -silent -json`
and parses nuclei JSONL issues into findings. `curl` gets a positional URL;
everything else gets `-u`.

## Autonomy note

The agent never self-authorizes: a human supplies the authorized target + the
sanctioned session (cookie / client-credentials / mTLS). Once stored, the agent
can drive the full loop — resolve auth, run tools, crawl, scan — with no human
re-login (oauth/mtls especially). Link a session to a casefile case with `caseId`.

## Storage

Sessions persist as JSON under `~/.pi/xpi-engage` (override with `PI_ENGAGE_DIR`) —
outside the repo and git-ignored, so secrets never enter version control.
