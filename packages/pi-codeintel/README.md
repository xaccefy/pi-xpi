# pi-codeintel

`pi-codeintel` is an AST-based TypeScript and JavaScript codebase indexer and query suite. It constructs a structural database of codebase symbols, imports, and call graphs to enable rapid code analysis, navigation, and taint-path tracing.

## Features

- **AST-Based Indexing**: Uses the TypeScript Compiler API to extract structured symbols (Classes, Functions, Methods, Interfaces) and call edges.
- **Zero-Configuration SQLite Backend**: Stores AST mappings in a local SQLite file (`.pi/codebase.db`), enabling fast querying without startup overhead.
- **Call Graph Traversal**: Computes inbound/outbound call trees and execution pathways.
- **Lazy Loading**: Imports the compiler API only when performing index operations, keeping extension load times near zero.

## Installation

```bash
pi install npm:pi-codeintel
```

## Tool Reference

### `CodebaseIndex`
Scans the workspace directory and builds/updates the SQLite index.
- **Parameters**:
  - `workspace` (string, optional): Absolute path of workspace.
  - `force` (boolean, optional): Force re-indexing of all files.

### `CodebaseFindSymbol`
Queries the database for symbols matching a text query.
- **Parameters**:
  - `query` (string, required): Case-insensitive match on symbol name.
  - `kind` (string, optional): Filter by symbol type (e.g. `Class`, `Function`, `Method`).

### `CodebaseGetDefinition`
Retrieves declaration details and direct source code lines for a given symbol.
- **Parameters**:
  - `symbolName` (string, required): Name of the symbol to look up.

### `CodebaseFindReferences`
Locates all occurrences calling or importing the target symbol.
- **Parameters**:
  - `symbolName` (string, required): Name of the symbol to trace.

### `CodebaseGetCallGraph`
Computes inbound or outbound call trees up to a specified depth.
- **Parameters**:
  - `symbolName` (string, required): Root symbol name.
  - `direction` (string, required): `"inbound"` or `"outbound"`.
  - `depth` (number, optional, default: 3): Max recursion depth.

### `CodebaseTraceCallPath`
Traces exact execution routes between a source symbol and a target symbol.
- **Parameters**:
  - `targetSymbol` (string, required): Sink/destination function.
  - `sourceSymbol` (string, optional): Filter pathways starting from this source.

### `CodebaseGetArchitecture`
Generates a structural summary of the repository, highlighting top-level directories, external dependencies, and hotspot functions (symbols with high inbound call counts).
