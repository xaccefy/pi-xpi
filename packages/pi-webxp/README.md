# pi-webxp

Web search, page fetch, library docs, repo QWeb search, page fetch, library docs, repo Q&A, and exploit technique search for Pi Agent. Merges the former `pi-lookup` and `pi-exploitsearch` into one "find information" extension.A, exploit technique search, and raw HTTP requests for Pi Agent. Merges the former `pi-lookup` and `pi-exploitsearch` into one "web interaction" extension.

## Install

```bash
pi install npm:@xaccefy/pi-webxp
```

Or via the XPI umbrella package: `pi install npm:@xaccefy/pi-xpi`

## Tools

### `web_search`
Search engines through the local `open-websearch` daemon (no API key).

- `query` (required)
- `limit` (optional, default 10)
- `engines` (optional, e.g. `duckduckgo`, `brave`, `bing`)

### `web_fetch`
Fetch a URL as clean text/markdown (GitHub READMEs use a dedicated path).

- `url` (required, http/https)

**JS pages:** if the static extract is a bare HTML shell, `web_fetch` re-renders with system Chromium (`--headless --dump-dom`) when present.

| Variable | Purpose |
|----------|---------|
| `PI_CHROMIUM_PATH` | Absolute path to chromium/chrome binary |
| `PI_WEBSEARCH_PORT` | Daemon port (default `3210`) |

### `context7`
Up-to-date library docs + examples.

- `libraryName` (required, e.g. `react`)
- `topic` (optional, e.g. `hooks`)
- `maxTokens` (optional, default 10000)

### `deepwiki`
Natural-language Q&A over a public GitHub repo.

- `repo` (required, `owner/name`)
- `question` (required)

### `exploit_search`
Search [preview.is](https://preview.is) for real exploit tricks and bypasses — each hit links to a write-up.

- `query` (required)
- `limit` (optional, default 5, 1–50)
- `minScore` (optional, default 0.1, 0–1 relevance floor)

**Rule:** always cite the source URL; don't invent exploit steps from memory.

```bash
export PREVIEW_IS_API_KEY="rk_your_api_key_here"
```

### `http_request`
Stateful HTTP request with a persistent cookie jar, full method/header/body control, and manual redirect observability — for authenticated web-app pentesting and API probing.

- `url` (required, http/https)
- `method` (optional, default GET; enum: GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS)
- `headers` (optional, custom request headers)
- `body` (optional, raw request body for POST/PUT/PATCH)
- `json` (optional, JSON body — stringified automatically with Content-Type set)
- `contentType` (optional, shorthand Content-Type)
- `redirect` (optional, default "manual" — return 3xx as-is; "follow" auto-follows up to Bun's limit)
- `timeoutMs` (optional, default 30000)
- `verifyTls` (optional, default true; set false for self-signed certs)
- `allowPrivateHosts` (optional, default false — SSRF-safe)

**Cookie jar:** `Set-Cookie` headers are stored per-host and automatically injected into subsequent requests to the same host — enabling login → probe workflows without manual cookie threading.

**SSRF guard:** private/internal hosts (127.0.0.1, 10.x, 192.168.x, fc00::/7, link-local) are blocked by default. Set `allowPrivateHosts: true` for internal red-team targets. DNS rebinding is unmitigated — see the `web-pentest` skill §8.

**Lifecycle:** cookie jar is cleared on `session_shutdown`.

## Lifecycle

- **session_start**: tries to start the `open-websearch` daemon (non-blocking).
- **session_shutdown**: stops the daemon this extension started.

## Development

```bash
bun test packages/pi-webxp
bun run typecheck
```
