# Package lineage: embedded vs standalone

Recorded 2026-10-07 as the owner's source-of-truth decision for the packages
that exist both inside this workspace and as standalone repositories.

## Canonical lineage

The packages in this workspace are the canonical source for the XPI extension
surface going forward:

| Package | Since | Notes |
|---|---|---|
| `@xaccefy/pi-xpi` | 0.9.4 | Umbrella / extension entry |
| `@xaccefy/pi-casefile` (embedded) | 0.9.4 | Two-phase evidence gate, `PI_POC_*` operator gates, `inter_host` control mode, OOB oracle, attack transport |
| `@xaccefy/pi-webxp` (embedded) | 0.9.4 | Target-interaction tools behind the network-safety layer |
| `@xaccefy/pi-shared` | 0.9.4 | Shared utilities |
| `@xaccefy/pi-xtodo` | 0.9.4 | Optional task-list extension |

## Diverged research-only lineage

Two standalone repositories were extracted from XPI in the past and have since
evolved separately. They are **frozen as a research-only lineage**:

| Repository | Standalone revision | npm | Contract differences |
|---|---|---|---|
| `xaccefy/pi-casefile` | `3441453` (package 0.11.1) | `@xaccefy/pi-casefile@0.11.1` | Removed all `PI_POC_*` operator gates (isolation degrades to best-effort Docker); collapsed confirmation to the single `intra_target` same-host-baseline mode; no OOB oracle, Primitive/Objective, or scratchpad pipeline tools |
| `xaccefy/pi-webxp` | `278270d` (package 0.11.0) | `@xaccefy/pi-webxp@0.11.0` | Research tools only (`web_search`, `web_fetch`, `context7`, `deepwiki`); no `http_request`, `raw_request`, `race_send`, `jwt`, or attack transport |

These are **different safety contracts**, not older copies of the embedded
packages. Neither direction of silent syncing is permitted. Drift is tracked
per release in the workspace version table.

## npm dist-tag consequence

On the npm registry, `latest` for `@xaccefy/pi-casefile` (0.11.1) and
`@xaccefy/pi-webxp` (0.11.0) currently points at the standalone lineage.
Publishing the embedded packages (0.10.0-rc1) under the same names would be a
version regression against a *different contract*. Until a version strategy is
chosen — rename the embedded packages, or advance them past the standalone
lineage — embedded `pi-casefile`/`pi-webxp` releases are held back from npm.
The umbrella, `pi-shared`, and `pi-xtodo` have no such collision and publish
normally.
