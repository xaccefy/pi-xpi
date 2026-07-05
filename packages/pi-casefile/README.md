# pi-casefile

`pi-casefile` is a local-first case ledger and validation harness designed to track offensive security investigations, bug bounty findings, and CTF progress. It features a SQLite storage engine and an isolated PoC execution runner.

## Features

- **State Management**: Enforces strict lifecycle transitions across states (`hypothesis`, `investigating`, `confirmed`, `blocked`, `killed`, `reported`).
- **PoC Runner**: Validates vulnerability reachability in an isolated Docker sandbox with `--network none` or locally on the host.
- **SQL Backend**: Syncs case information to SQLite via Node's `node:sqlite` or Bun's `bun:sqlite` compat layers.
- **Reporting**: Automatically compiles markdown vulnerability reports for confirmed or reported findings.

## Installation

```bash
pi install npm:pi-casefile
```

## Environment Variables

- `CASEFILE_PATH`: Set explicit absolute path to the SQLite database file.
- `CASEFILE_SCOPE`: Scope database storage. Options: `project` (default, stores in `.pi/casefile.db` or `.casefile/casefile.db` relative to workspace root) or `global` (stores in `~/.pi/casefile/casefile.db` or `~/.casefile/casefile.db`).

## Core Workflow & State Transitions

The ledger acts as a state gate to ensure finding validity:
1. **Hypothesis**: Initial lead tracking (`CaseAdd`).
2. **Investigation**: Move to `investigating` when code paths or reachability trace are identified (`CaseUpdate`).
3. **Confirmation**: Validate with a working PoC script (`PromoteFinding`). Requires the PoC script to exit with code `0`.
4. **Chaining**: Link low-impact primitives to build high-impact chains (`CaseLink`).
5. **Reporting**: Compile markdown report (`CaseReport`) and transition finding to `reported` (`CaseUpdate`).

## Tools Reference

| Tool | Action | Requirements |
|---|---|---|
| `CaseAdd` | Create a new hypothesis or investigation case | Title, target (scope) |
| `CaseUpdate` | Modify case details (remediation, impact, status) | ID, field updates |
| `PromoteFinding` | Run on-disk PoC script to transition status to `confirmed` | ID, `poc_path`, `local` flag |
| `CaseGet` | Retrieve full JSON details of a case | ID |
| `CaseList` | Query and filter cases by status/confidence/tags | Filter flags, limit, offset |
| `CaseSearch` | Perform full-text search across specific case fields | Query string, optional field |
| `CaseLink` | Create a bidirectional link between two cases | Source ID, Target ID |
| `CaseUnlink` | Remove link between two cases | Source ID, Target ID |
| `CaseReport` | Write markdown report to disk | ID (must be `confirmed` or `reported`) |

## Development and Testing

Run tests via Bun:
```bash
bun test
```
