# XPI

Security tools for Pi Agent: casefile tracking, web search, library docs, exploit technique search.

## Install

You can automate the installation of XPI along with its required 3rd party extension dependencies (`pi-codex-goal` and `pi-mcp-adapter`) by running the setup script:

```bash
./install.sh
```

Or install them manually:

```bash
# Install XPI
pi install npm:@xaccefy/pi-xpi
```

### ExploitSearch API key

ExploitSearch queries the [preview.is](https://preview.is) security corpus and
requires an API key. Get one at https://preview.is, then export it:

```bash
export PREVIEW_IS_API_KEY="rk_yourkeyhere"
```

Add this to your shell profile (`~/.bashrc` / `~/.zshrc`) so Pi Agent picks it
up on every session. Without the key, ExploitSearch returns a clear error
message guiding you to set it.

## Tools

| Tool | Use for |
|------|---------|
| ExploitSearch | Attack techniques, primitives, bypasses (preview.is, requires `PREVIEW_IS_API_KEY`) |
| web_search | CVEs, advisories, documentation |
| web_fetch | Page content retrieval |
| context7 | Current library docs (e.g. `libraryName: "react", topic: "hooks"`) |
| deepwiki | Ask about a GitHub repo (e.g. `repo: "facebook/react", question: "How does the reconciler work?"`) |
| CaseAdd | New finding in the ledger |
| CaseUpdate | Update case fields and status |
| PromoteFinding | Run on-disk PoC, confirm on exit 0 |
| CaseGet / CaseList / CaseSearch | Read and browse cases |
| CaseLink / CaseUnlink | Chain findings |
| CaseReport | Generate markdown report |
| /casefile | Interactive case dashboard |
| todo | Manage task lists for tracking multi-step progress |
| /todos | TUI command to display active/completed tasks |
| CodebaseIndex | Scan and build/update a persistent AST-based SQLite codebase index |
| CodebaseFindSymbol | Search for symbols in the index matching a pattern or kind |
| CodebaseGetDefinition | Find the declaration details and source code of a symbol |
| CodebaseFindReferences | Search for all code locations calling or referencing a symbol |
| CodebaseGetCallGraph | Trace inbound or outbound call pathways for a symbol |
| CodebaseTraceCallPath | Scan call graph pathways leading to a target function or symbol |
| CodebaseGetArchitecture | Summarize directory layout, key imports, and hotspot functions |

## Quick start

```
/pentest api.example.com
/bugbounty https://hackerone.com/example
/ctf web-challenge-01
/hunt scan for insecure input parsing
/patch fix the vulnerability in test_file
/harness scan, verify, and patch buffer overflows
```

## Structure

```
pi-xpi/
├── prompts/                 # /pentest, /bugbounty, /ctf, /hunt, /patch, /harness
├── agents/                  # auditor, exploit-dev, patch-writer, harness definitions
├── packages/
│   ├── @xaccefy/pi-casefile         # SQLite case tracker
│   ├── @xaccefy/pi-exploitsearch    # ExploitSearch tool
│   ├── @xaccefy/pi-lookup           # web_search, web_fetch, context7, deepwiki
│   ├── @xaccefy/pi-codeintel        # Codebase indexer & graph queries
│   └── @xaccefy/pi-xtodo            # Todo tracking
└── package.json
```
