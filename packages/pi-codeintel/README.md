# pi-codeintel

AST-based TypeScript/JavaScript indexer for Pi Agent: symbols, imports, call graph, architecture summary. Tools include `promptSnippet` / `promptGuidelines` so the model knows when to use them (e.g. “analyze the codebase” → `CodebaseGetArchitecture`).

## Install

```bash
pi install npm:@xaccefy/pi-codeintel
```

## Tools

| Tool | Use |
|------|-----|
| `CodebaseIndex` | Build/refresh SQLite index (`.pi/codebase.db`) |
| `CodebaseFindSymbol` | Search symbols by name/kind |
| `CodebaseGetDefinition` | Declaration + source snippet |
| `CodebaseFindReferences` | Callers/references |
| `CodebaseGetCallGraph` | Inbound/outbound call tree (`depth` default 3) |
| `CodebaseTraceCallPath` | Paths leading to a target (optional `sourceSymbol`) |
| `CodebaseGetArchitecture` | Layout, hotspots, top imports |

Most query tools **auto-index** on first use (throttled). Call `CodebaseIndex` explicitly for a full/forced refresh.

## Development

```bash
bun test packages/pi-codeintel
bun run typecheck
```
