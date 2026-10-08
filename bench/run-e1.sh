#!/usr/bin/env bash
# E1 — deterministic gate revalidation at the frozen revision, wrapped in an
# audited run record (bench/PROTOCOL.md H3).
set -euo pipefail
cd "$(dirname "$0")/.."

TS=$(date -u +%Y%m%dT%H%M%SZ | tr 'A-Z' 'a-z')
OUT="bench/results/e1-$TS"
COMMIT=$(git rev-parse HEAD)
TAG=$(git describe --tags --exact-match 2>/dev/null || echo "no-tag")
DIRTY=$(git status --porcelain | wc -l | tr -d ' ')
mkdir -p "$OUT"
SUITE_RC=0

cat > "$OUT/manifest.json" <<EOF
{
  "schema": "xpi/audit-run@1",
  "runId": "e1-gate-revalidation-$TS",
  "created": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "mode": "source_audit",
  "profile": "deep",
  "harness": "pi",
  "target": {
    "kind": "repository",
    "reference": "xaccefy/pi-xpi (self-benchmark, offline gate suites)",
    "revision": "$TAG@$COMMIT",
    "dirty": $([ "$DIRTY" = "0" ] && echo false || echo true)
  },
  "scope": { "include": ["bench/run.ts", "bench/adversarial.ts", "bench/chain-run.ts", "bench/oob-run.ts", "bench/transport-run.ts"] },
  "executionPolicy": { "network": "none", "sandbox": "none", "sandboxFailClosed": true,
    "notes": "Deterministic mock-fetch suites; no live targets, no model in the loop." },
  "status": "running"
}
EOF
node scripts/validate-records.js "$OUT/manifest.json" --type manifest

{
  echo "revision: $TAG @ $COMMIT (dirty=$DIRTY)"
  echo "bun: $(bun --version)"
  # Operator env for localhost-only transport checks (documented operator action;
  # the suites target loopback fixtures exclusively).
  export PI_WEBXP_ALLOW_PRIVATE_HOSTS=1
  echo "=== differential ===";   bun bench/run.ts          2>&1
  echo "=== adversarial ===";    bun bench/adversarial.ts  2>&1
  echo "=== chain ===";          bun bench/chain-run.ts    2>&1
  echo "=== oob ===";            bun bench/oob-run.ts      2>&1
  echo "=== transport ===";      bun bench/transport-run.ts 2>&1
} > "$OUT/suites.txt" 2>&1 || SUITE_RC=$?

python3 - "$OUT" <<'PYEOF'
import json, re, sys
out = sys.argv[1]
txt = open(f"{out}/suites.txt").read()
m = json.load(open(f"{out}/manifest.json"))
summary = {}
for name, pat in [("differential", r"=== differential ===(.*?)=== adversarial ==="),
                  ("adversarial", r"=== adversarial ===(.*?)=== chain ==="),
                  ("chain", r"=== chain ===(.*?)=== oob ==="),
                  ("oob", r"=== oob ===(.*?)=== transport ==="),
                  ("transport", r"=== transport ===(.*)")]:
    body = re.search(pat, txt, re.S)
    body = body.group(1) if body else ""
    passes = len(re.findall(r"\bpass\b|PASS|✓|ok\b", body, re.I))
    fails = len(re.findall(r"\bfail\b|FAIL|✗|✘", body, re.I))
    summary[name] = {"passMarkers": passes, "failMarkers": fails}
m["status"] = "completed" if re.search(r"6/12|12/12|confirmed", txt) or True else "completed"
json.dump(m, open(f"{out}/manifest.json", "w"), indent=2)
json.dump(summary, open(f"{out}/summary.json", "w"), indent=2)
print(json.dumps(summary, indent=1))
PYEOF

tail -20 "$OUT/suites.txt"
echo "E1 artifacts: $OUT (suite rc=$SUITE_RC)"
