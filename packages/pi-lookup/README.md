# pi-lookup

`pi-lookup` is a suite of web search, page retrieval, library documentation, and repository Q&A tools designed to feed high-fidelity external information into the agent context. **No API keys or external authentication configurations are required to use this package.**

## Features

- **Daemon-Based Search & Fetch**: Integrates with the local `open-websearch` daemon to perform search engine queries and retrieve stripped, clean markdown content from target URLs.
- **Context7 Integration**: Resolves npm library names and retrieves current documentation fragments up to a specified token threshold.
- **DeepWiki Q&A**: Queries public GitHub repositories using a JSON-RPC MCP tunnel, returning synthesized answers with file-path citations.

## Installation

```bash
pi install npm:pi-lookup
```

## Tools Specification

### `web_search`
Queries search engines via the local `open-websearch` daemon.
- **Parameters**:
  - `query` (string, required): The search string.
  - `limit` (number, optional, default: 10): Max results.
  - `engines` (array of strings, optional): Target engines (e.g. `duckduckgo`, `brave`, `bing`).

### `web_fetch`
Downloads web page contents and parses them to clean markdown.
- **Parameters**:
  - `url` (string, required): The destination HTTP/HTTPS URL.

### `context7`
Fetches API documentation and code examples for a given framework.
- **Parameters**:
  - `libraryName` (string, required): Library name (e.g., `react`, `next.js`, `zod`).
  - `topic` (string, optional): Specific API category/hook to search for.
  - `maxTokens` (number, optional, default: 10000): Token limit.

### `deepwiki`
Asks repository-level questions of public GitHub codebases.
- **Parameters**:
  - `repo` (string, required): Repo target in `"owner/name"` format.
  - `question` (string, required): Natural language question.

## Lifecycle Management

- **Startup**: Upon session initialization, the extension verifies if the `open-websearch` daemon is active on the port configured via `PI_WEBSEARCH_PORT` (default `3210`). If inactive, it spawns the daemon process automatically.
- **Shutdown**: Automatically terminates the daemon process when the agent session shut downs.
