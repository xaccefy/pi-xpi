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

# GitHub-hosted extension — pi treats bare org/repo as remote spec
if ! $PI_BIN install fitchmultz/pi-codex-goal 2>/dev/null; then
  echo "  pi install failed for fitchmultz/pi-codex-goal, falling back to npm"
  npm install --no-save github:fitchmultz/pi-codex-goal 2>/dev/null || echo "  (fallback skipped)"
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
