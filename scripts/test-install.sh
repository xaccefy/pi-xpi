#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEST_DIR="$(mktemp -d)"
cleanup() {
  rm -rf -- "$TEST_DIR"
}
trap cleanup EXIT

mkdir -p "$TEST_DIR/bin" "$TEST_DIR/agents"
printf '#!/usr/bin/env bash\nexit 0\n' > "$TEST_DIR/bin/omp"
chmod +x "$TEST_DIR/bin/omp"
printf 'stale confirmer\n' > "$TEST_DIR/agents/confirmer.md"

run_installer() {
  PATH="$TEST_DIR/bin:$PATH" \
    OMP_AGENTS_DIR="$TEST_DIR/agents" \
    "$ROOT_DIR/install.sh" --omp "$@" >/dev/null
}

run_installer
test ! -e "$TEST_DIR/agents/confirmer.md"
for source in "$ROOT_DIR"/agents/*.md; do
  name="$(basename "$source")"
  cmp "$source" "$TEST_DIR/agents/$name"
done

# Existing customized agents must survive a normal reinstall.
first_agent="$(basename "$(find "$ROOT_DIR/agents" -maxdepth 1 -name '*.md' -print -quit)")"
printf 'customized\n' > "$TEST_DIR/agents/$first_agent"
run_installer
test "$(cat "$TEST_DIR/agents/$first_agent")" = "customized"

# --force is the explicit overwrite path.
run_installer --force
cmp "$ROOT_DIR/agents/$first_agent" "$TEST_DIR/agents/$first_agent"
