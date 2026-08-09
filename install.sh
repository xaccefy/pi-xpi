#!/usr/bin/env bash
# Install a source checkout of XPI and the companion used by full XP mode.
set -euo pipefail

if [[ -n "${PI_XPI_INSTALLING:-}" ]]; then exit 0; fi
export PI_XPI_INSTALLING=1

PI_BIN="$(command -v pi || true)"
if [[ -z "$PI_BIN" ]]; then
  echo "pi not found in PATH" >&2
  exit 1
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
echo "Installing XPI from $ROOT_DIR"
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
