#!/bin/bash
# Install dependencies for XPI
# Guard against recursive install (pi postinstall → npm postinstall → pi install → ...)
if [ -n "$PI_XPI_INSTALLING" ]; then exit 0; fi
export PI_XPI_INSTALLING=1

PI_BIN="$(command -v pi 2>/dev/null)"
if [ -n "$PI_BIN" ] && ! "$PI_BIN" --help 2>&1 | grep -q "Extensions"; then
  PI_BIN=""
fi

if [ -z "$PI_BIN" ]; then
  echo "pi not found in PATH — skipping 3rd party dep install"
  exit 0
fi

echo "Installing 3rd party extension dependencies..."

# Helper function to register packages in settings.json if pi install fails
register_package_in_settings() {
  local pkg="$1"
  node -e '
    const fs = require("fs");
    const path = require("path");
    const os = require("os");
    const settingsPath = path.join(os.homedir(), ".pi", "agent", "settings.json");
    if (fs.existsSync(settingsPath)) {
      try {
        const data = JSON.parse(fs.readFileSync(settingsPath, "utf8"));
        data.packages = data.packages || [];
        const pkgName = process.argv[1];
        if (!data.packages.includes(pkgName)) {
          data.packages.push(pkgName);
          fs.writeFileSync(settingsPath, JSON.stringify(data, null, 2) + "\n");
          console.log(`  Registered ${pkgName} in settings.json`);
        }
      } catch (err) {
        console.error("  Failed to update settings.json:", err.message);
      }
    }
  ' "$pkg"
}

# Install pi-codex-goal via npm
if ! $PI_BIN install npm:pi-codex-goal 2>/dev/null; then
  echo "  pi install failed for pi-codex-goal, falling back to npm"
  npm install --no-save pi-codex-goal 2>/dev/null || echo "  (fallback skipped)"
  register_package_in_settings "npm:pi-codex-goal"
fi

# npm-scoped packages — try pi, then npm
for pkg in pi-mcp-adapter @tintinweb/pi-subagents; do
  if ! $PI_BIN install "npm:${pkg}" 2>/dev/null; then
    echo "  pi install failed for ${pkg}, falling back to npm"
    npm install --no-save "${pkg}" 2>/dev/null || echo "  (fallback skipped for ${pkg})"
    register_package_in_settings "npm:${pkg}"
  fi
done

# codebase-memory-mcp — default code indexer (158 languages, MCP server).
# Static binary; ships tree-sitter grammars + Hybrid LSP type resolution.
# Polyglot replacement for the removed in-process codeintel (TS/JS-only) package.
if ! $PI_BIN install "npm:codebase-memory-mcp" 2>/dev/null; then
  echo "  pi install failed for codebase-memory-mcp, falling back to npm"
  npm install --no-save codebase-memory-mcp 2>/dev/null || echo "  (fallback skipped for codebase-memory-mcp)"
  register_package_in_settings "npm:codebase-memory-mcp"
fi

# Setup custom subagents & prompts
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
mkdir -p ~/.pi/agent/agents
cp -f "$SCRIPT_DIR"/agents/*.md ~/.pi/agent/agents/ 2>/dev/null || true

# ExploitSearch API key notice
echo ""
echo "ExploitSearch requires a preview.is API key."
echo "Get one at https://preview.is and add to your shell profile:"
echo '  export PREVIEW_IS_API_KEY="rk_yourkeyhere"'
echo ""

echo "XPI dependencies successfully set up!"
