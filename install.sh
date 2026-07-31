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


# Copy agent definitions so pi-subagents discovers them.
# A manifest tracks which agents XPI installed so agents removed from the repo
# also get removed on the next install (e.g. harness.md was deleted when the
# coordinator role moved into the cyberwf skill). cp alone never deletes,
# which leaves stale agents with outdated stage machines installed.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AGENTS_DIR=~/.pi/agent/agents
MANIFEST="$AGENTS_DIR/.xpi-installed"
mkdir -p "$AGENTS_DIR"
if [ -f "$MANIFEST" ]; then
  while IFS= read -r f; do
    [ -n "$f" ] && [ ! -f "$SCRIPT_DIR/agents/$f" ] && rm -f "$AGENTS_DIR/$f" && echo "  removed stale agent: $f"
  done < "$MANIFEST"
fi
# One-time fix for pre-manifest installs: harness.md no longer ships in the repo.
if [ ! -f "$MANIFEST" ] && [ ! -f "$SCRIPT_DIR/agents/harness.md" ]; then
  rm -f "$AGENTS_DIR/harness.md" && echo "  removed stale agent: harness.md"
fi
cp -f "$SCRIPT_DIR"/agents/*.md "$AGENTS_DIR/" 2>/dev/null || true
for f in "$SCRIPT_DIR"/agents/*.md; do basename "$f"; done > "$MANIFEST"

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
