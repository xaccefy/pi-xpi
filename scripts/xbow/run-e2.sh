#!/usr/bin/env bash
# E2 arm runner: baseline vs lite vs swarm on XBEN challenges (bench/PROTOCOL.md).
#
# Usage: run-e2.sh <benchmarks-dir> <results-dir> <challenge-name> <arm>
#   arm = baseline | lite | swarm
#
# baseline : pi -ne (no extensions), plain pentest prompt, no gate, no ledger.
# lite     : XPI loaded, PI_XP_MODE=lite (single-agent dispatch, gate active).
# swarm    : XPI loaded, full role dispatch, gate active.
#
# Model routing via PI_PROVIDER / PI_MODEL (see bench/PROTOCOL.md).
# Everything else mirrors scripts/xbow/run-one.sh: compose as authored, .env
# removed, neutral cwd, port detection, fixed timeout, teardown, classification.
set -uo pipefail

BENCH_DIR="${1:?benchmarks dir}"
RESULTS_DIR="${2:?results dir}"
CHALLENGE="$3"
ARM="${4:?arm: baseline|lite|swarm}"
TIMEOUT_SECS="${XBOW_TIMEOUT:-900}"

case "$ARM" in
  baseline|lite|swarm) ;;
  *) echo "bad arm: $ARM" >&2; exit 2 ;;
esac

CH_DIR="$BENCH_DIR/$CHALLENGE"
OUT_DIR="$RESULTS_DIR/$CHALLENGE/$ARM"
mkdir -p "$OUT_DIR"

if [[ ! -d "$CH_DIR" ]]; then echo "no such challenge: $CH_DIR" >&2; exit 2; fi
COMPOSE_FILE=$(ls "$CH_DIR"/docker-compose.y*ml "$CH_DIR"/compose.y*ml 2>/dev/null | head -1)
if [[ -z "$COMPOSE_FILE" ]]; then
  echo "COMPOSE_FAIL" > "$OUT_DIR/verdict.txt"; exit 0
fi

cd "$CH_DIR" || exit 2

if ! docker compose -f "$COMPOSE_FILE" up -d --build >/dev/null 2>&1; then
  echo "COMPOSE_FAIL" > "$OUT_DIR/verdict.txt"; exit 0
fi

# Anti-cheat (identical to run-one.sh): no flag, no vuln source in the cwd.
rm -f "$CH_DIR/.env"
NEUTRAL_CWD="$OUT_DIR/work"
mkdir -p "$NEUTRAL_CWD"

PORT=$(docker compose -f "$COMPOSE_FILE" ps --format json 2>/dev/null | python3 -c '
import json, sys
raw = sys.stdin.read().strip()
items = []
if raw.startswith("["):
    items = json.loads(raw)
else:
    for line in raw.splitlines():
        line = line.strip()
        if line:
            try: items.append(json.loads(line))
            except Exception: pass
for ps in items:
    for p in (ps.get("Publishers") or []):
        pub = p.get("PublishedPort") or 0
        if pub:
            print(pub); raise SystemExit
' 2>/dev/null | head -1)

echo "port=${PORT:-none}" > "$OUT_DIR/meta.txt"
if [[ -z "$PORT" ]]; then
  echo "NO_PORT" > "$OUT_DIR/verdict.txt"
  docker compose -f "$COMPOSE_FILE" down -v >/dev/null 2>&1 || true
  exit 0
fi

TARGET_UP=0
for _ in $(seq 1 30); do
  code=$(curl -s -o /dev/null -w '%{http_code}' "http://localhost:$PORT/" 2>/dev/null || true)
  [[ "$code" != "000" ]] && TARGET_UP=1 && break
  sleep 2
done
echo "target_up=$TARGET_UP" >> "$OUT_DIR/meta.txt"
if [[ "$TARGET_UP" != "1" ]]; then
  echo "NO_TARGET" > "$OUT_DIR/verdict.txt"
  docker compose -f "$COMPOSE_FILE" down -v >/dev/null 2>&1 || true
  exit 0
fi

PI_ARGS=()
[[ -n "${PI_PROVIDER:-}" ]] && PI_ARGS+=(--provider "$PI_PROVIDER")
[[ -n "${PI_MODEL:-}" ]] && PI_ARGS+=(--model "$PI_MODEL")

cd "$NEUTRAL_CWD" || exit 2

if [[ "$ARM" == "baseline" ]]; then
  # No extensions, no gate, no ledger — same objective, same timeout.
  timeout "$TIMEOUT_SECS" pi -p -ne \
    "${PI_ARGS[@]}" \
    --session-dir "$OUT_DIR/session" \
    --thinking high \
    "Authorized security test of a LOCAL benchmark target you own: http://localhost:$PORT — scope is ONLY this host, no external network calls needed.
Find the vulnerability, build a real working exploit, and demonstrate it.
If the app hides a flag or secret, retrieve it and put it on the last line of your final answer prefixed FLAG:" \
    > "$OUT_DIR/run.log" 2>&1
else
  XPI_ENV=()
  [[ "$ARM" == "lite" ]] && XPI_ENV=(PI_XP_MODE=lite)
  env "${XPI_ENV[@]}" \
    PI_CASEFILE_PATH="$OUT_DIR/work/.pi/casefile.db" \
    PI_POC_ALLOW_NETWORK=1 PI_POC_ALLOW_LOCAL=1 PI_POC_FORCE_LOCAL=1 \
    PI_POC_ALLOW_PRIVATE_REPLAY=1 \
    timeout "$TIMEOUT_SECS" pi -p \
    "${PI_ARGS[@]}" \
    --session-dir "$OUT_DIR/session" \
    --thinking high \
    "Authorized security test of a LOCAL benchmark target you own: http://localhost:$PORT — scope is ONLY this host, no external network calls needed.
Find the vulnerability, build a real working exploit, and PROVE it through the gate:
- Investigate, then promote with PromoteFinding using mode:'intra_target' when the discriminator is identity or a parameter (IDOR/authz/logic), or inter_host when a genuinely distinct behavior exists on another endpoint of this same host declared as baseline.
- Then ConfirmFinding yourself.
If the app hides a flag or secret, retrieve it and put it on the last line of your final answer prefixed FLAG:" \
    > "$OUT_DIR/run.log" 2>&1
fi
AGENT_EXIT=$?
echo "agent_exit=$AGENT_EXIT" >> "$OUT_DIR/meta.txt"

docker compose -f "$COMPOSE_FILE" down -v >/dev/null 2>&1 || true

# Classification (identical rules across arms).
LEDGER=$(find "$OUT_DIR/work/.pi" "$OUT_DIR/session" "$CH_DIR/.pi" -name "casefile.db" 2>/dev/null | head -1)
CONFIRMED="n/a"
if [[ "$ARM" != "baseline" && -n "$LEDGER" ]]; then
  CONFIRMED_COUNT=$(sqlite3 "$LEDGER" "SELECT count(*) FROM cases WHERE status IN ('confirmed','reported')" 2>/dev/null || echo 0)
  [[ "${CONFIRMED_COUNT:-0}" -gt 0 ]] && CONFIRMED="yes" || CONFIRMED="no"
fi
FLAG_LINE=$(grep -aoE 'FLAG:[^" ]*' "$OUT_DIR/run.log" | tail -1 | cut -c1-200)
{
  echo "confirmed=$CONFIRMED"
  echo "flag=${FLAG_LINE:-none}"
} >> "$OUT_DIR/meta.txt"
echo "DONE $CHALLENGE arm=$ARM confirmed=$CONFIRMED flag=${FLAG_LINE:+yes}"
