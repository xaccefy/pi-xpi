#!/usr/bin/env bash
# Install a source checkout of XPI on Pi Agent or its OMP fork.
#
#   ./install.sh            # install on whichever host is in PATH (pi preferred, else omp)
#   ./install.sh --omp      # force the OMP host (needs `omp` in PATH)
#   ./install.sh --pi       # force the Pi host (needs `pi` in PATH)
#
# Pi:  pi install <dir>  + pi-subagents (full XP mode dispatch) + optional @ff-labs/pi-fff
# OMP: omp install <dir>  (extensions + skills via the Agent Plugins manifest);
#      specialist agents are copied to ~/.omp/agent/agents so the `task` tool can
#      spawn auditor/tracer/skeptic/exploit/chain/reporter/confirmer by name.
set -euo pipefail

if [[ -n "${PI_XPI_INSTALLING:-}" ]]; then exit 0; fi
export PI_XPI_INSTALLING=1

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOST=""
for arg in "$@"; do
  case "$arg" in
    --pi) HOST="pi" ;;
    --omp) HOST="omp" ;;
  esac
done

if [[ -z "$HOST" ]]; then
  if command -v pi >/dev/null 2>&1; then HOST="pi"; elif command -v omp >/dev/null 2>&1; then HOST="omp"; fi
fi
if [[ -z "$HOST" ]]; then
  echo "Neither pi nor omp found in PATH" >&2
  echo "Install Pi Agent (pi) or its fork OMP (omp) first, then re-run this script." >&2
  exit 1
fi

echo "Installing XPI from $ROOT_DIR on host: $HOST"

if [[ "$HOST" == "omp" ]]; then
  OMP_BIN="$(command -v omp)"
  "$OMP_BIN" install "$ROOT_DIR"

  # Specialist agents for the native `task` tool. OMP reads user agents from
  # ~/.omp/agent/agents/*.md (frontmatter: name, description, tools). Skip
  # files that already exist so a customized agent is never clobbered.
  AGENTS_DIR="${OMP_AGENTS_DIR:-$HOME/.omp/agent/agents}"
  mkdir -p "$AGENTS_DIR"
  for agent in "$ROOT_DIR"/agents/*.md; do
    name="$(basename "$agent")"
    if [[ -f "$AGENTS_DIR/$name" ]]; then
      echo "  agent $name already exists — skipped (use --force to overwrite)"
    else
      cp "$agent" "$AGENTS_DIR/$name"
      echo "  agent $name → $AGENTS_DIR/$name"
    fi
  done

  echo
  echo "Optional environment variables:"
  echo "  export PREVIEW_IS_API_KEY=\"rk_yourkeyhere\"  # https://preview.is"
  echo
  echo "XPI installed on OMP. Use /xp on for the full pipeline or /xp lite without subagents."
  echo "OMP ships its own grep/find — XPI's fff upgrade is Pi-only."
  exit 0
fi

PI_BIN="$(command -v pi)"
"$PI_BIN" install "$ROOT_DIR"

# /xp on dispatches specialist agents through pi-subagents.
"$PI_BIN" install "npm:pi-subagents"

# Optional search upgrade. Pi's built-in grep/find remain usable if this fails.
"$PI_BIN" install "npm:@ff-labs/pi-fff" || echo "Optional @ff-labs/pi-fff install skipped"

echo
echo "Optional environment variables:"
echo "  export PI_FFF_MODE=override"
echo '  export PREVIEW_IS_API_KEY="rk_yourkeyhere"  # https://preview.is'
echo
echo "XPI installed. Use /xp on for the full pipeline or /xp lite without subagents."
