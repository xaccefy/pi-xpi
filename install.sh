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
for pkg in pi-codex-goal pi-mcp-adapter pi-subagents @ff-labs/pi-fff; do
  $PI_BIN install "npm:$pkg" 2>/dev/null || echo "  $pkg install skipped"
done


# Agent definitions (agents/*.md) are discovered directly from this package
# via the pi.subagents.agents entry in package.json — pi-subagents loads them
# fresh from the installed package every session, so updates propagate without
# any copy step. No files are copied to ~/.pi/agent/agents anymore; stale
# copies from older installs must be deleted (they shadow package agents).

echo ""
echo "Two environment variables to add to your shell profile"
echo "(~/.bashrc, ~/.zshrc, ...) — an install script cannot export them for you:"
echo ""
echo "  # fff in override mode: transparently upgrades pi's built-in"
echo "  # grep/find/multi_grep with frecency-ranked, typo-tolerant search"
echo '  export PI_FFF_MODE=override'
echo ""
echo "  # exploit_search API key (get one at https://preview.is)"
echo '  export PREVIEW_IS_API_KEY="rk_yourkeyhere"'
echo ""
echo "XPI dependencies set up."
