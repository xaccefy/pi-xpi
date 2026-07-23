#!/bin/bash
# Install XPI dependencies
# Guard against recursive install (pi postinstall → npm postinstall → pi install → ...)
if [ -n "$PI_XPI_INSTALLING" ]; then exit 0; fi
export PI_XPI_INSTALLING=1

PI_BIN="$(command -v pi 2>/dev/null)"
if [ -n "$PI_BIN" ] && ! "$PI_BIN" --help 2>&1 | grep -q "Extensions"; then
  PI_BIN=""
fi

if [ -z "$PI_BIN" ]; then
  echo "pi not found in PATH — skipping extension install"
  exit 0
fi

echo "Installing XPI extension dependencies..."

# Install required pi extensions
for pkg in pi-codex-goal pi-mcp-adapter pi-subagents codebase-memory-mcp; do
  $PI_BIN install "npm:$pkg" 2>/dev/null || echo "  $pkg install skipped"
done

# Copy agent definitions so pi-subagents discovers them
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
mkdir -p ~/.pi/agent/agents
cp -f "$SCRIPT_DIR"/agents/*.md ~/.pi/agent/agents/ 2>/dev/null || true

echo ""
echo "ExploitSearch requires a preview.is API key."
echo "Get one at https://preview.is and add to your shell profile:"
echo '  export PREVIEW_IS_API_KEY="rk_yourkeyhere"'
echo ""
echo "XPI dependencies set up."
