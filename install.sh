#!/bin/bash
# Install dependencies for XPI
# Guard against recursive install (pi postinstall → npm postinstall → pi install → ...)
if [ -n "$PI_XPI_INSTALLING" ]; then exit 0; fi
export PI_XPI_INSTALLING=1

PI_BIN="$(command -v pi 2>/dev/null)"
if [ -z "$PI_BIN" ]; then
  echo "pi not found in PATH — skipping 3rd party dep install"
  exit 0
fi

echo "Installing 3rd party extension dependencies..."
$PI_BIN install github:fitchmultz/pi-codex-goal
$PI_BIN install npm:pi-mcp-adapter
$PI_BIN install npm:@tintinweb/pi-subagents

# Setup custom subagents & prompts
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
mkdir -p ~/.pi/agent/agents
cp -f "$SCRIPT_DIR"/agents/*.md ~/.pi/agent/agents/ 2>/dev/null || true
mkdir -p ~/.pi/agent/prompts
cp -f "$SCRIPT_DIR"/prompts/*.md ~/.pi/agent/prompts/ 2>/dev/null || true

# ExploitSearch API key notice
echo ""
echo "ExploitSearch requires a preview.is API key."
echo "Get one at https://preview.is and add to your shell profile:"
echo '  export PREVIEW_IS_API_KEY="rk_yourkeyhere"'
echo ""

echo "XPI dependencies successfully set up!"
