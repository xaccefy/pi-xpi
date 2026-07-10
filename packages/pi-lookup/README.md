# pi-lookup

Web search, page fetch, library docs (Context7), and GitHub repo Q&A (DeepWiki) for Pi Agent. **No API keys** for search/fetch/docs (DeepWiki is public-repo only).

## Install

```bash
pi install npm:@xaccefy/pi-lookup
```

## Tools

### `web_search`
Queries engines via the local `open-websearch` daemon (no API key).

- `query` (required)
- `limit` (optional, default 10)
- `engines` (optional, e.g. `duckduckgo`, `brave`, `bing`)

### `web_fetch`
Fetches a URL as clean text/markdown (GitHub READMEs use a dedicated path).

- `url` (required, http/https)

**SPA / JS-rendered pages:** if the daemon only returns a thin HTML shell, `web_fetch` re-renders with system Chromium (`--headless --dump-dom`) when available and swaps in the richer text.

| Variable | Purpose |
|----------|---------|
| `PI_CHROMIUM_PATH` | Absolute path to chromium/chrome binary |
| `PI_WEBSEARCH_PORT` | Daemon port (default `3210`) |

Fallback binaries checked: `/usr/bin/chromium`, `/usr/sbin/chromium`, Chrome stable paths, etc. If Chromium is missing, static extraction is returned as-is.

### `context7`
Up-to-date library docs + examples.

- `libraryName` (required, e.g. `react`)
- `topic` (optional, e.g. `hooks`)
- `maxTokens` (optional, default 10000)

### `deepwiki`
Natural-language Q&A over a public GitHub repo.

- `repo` (required, `owner/name`)
- `question` (required)

## Lifecycle

- **session_start**: best-effort warm-up of the `open-websearch` daemon (non-blocking).
- **session_shutdown**: stops the daemon process started by this extension.

## Development

```bash
bun test packages/pi-lookup
bun run typecheck
```
