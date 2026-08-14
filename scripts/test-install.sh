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
PI_LOG="$TEST_DIR/pi.log"
printf '#!/usr/bin/env bash\nprintf "%%s\\n" "$*" >> "${PI_LOG:?}"\nexit 0\n' > "$TEST_DIR/bin/pi"
chmod +x "$TEST_DIR/bin/pi"
git -C "$ROOT_DIR" show c1c88d9c94560f4e69a198146bc7b23d91ea0ffa:agents/confirmer.md > "$TEST_DIR/agents/confirmer.md"
git -C "$ROOT_DIR" show c1c88d9c94560f4e69a198146bc7b23d91ea0ffa:agents/exploit.md > "$TEST_DIR/agents/exploit.md"
git -C "$ROOT_DIR" show 12daa82521d2047d6b6489853c6de8b650438745:agents/reporter.md > "$TEST_DIR/agents/reporter.md"

run_installer() {
  PATH="$TEST_DIR/bin:$PATH" \
    OMP_AGENTS_DIR="$TEST_DIR/agents" \
    "$ROOT_DIR/install.sh" --omp "$@" >/dev/null
}

run_installer
for retired in confirmer.md exploit.md reporter.md; do
  test ! -e "$TEST_DIR/agents/$retired"
done
for source in "$ROOT_DIR"/agents/*.md; do
  name="$(basename "$source")"
  cmp "$source" "$TEST_DIR/agents/$name"
done

# Existing customized agents must survive a normal reinstall.
first_agent="$(basename "$(find "$ROOT_DIR/agents" -maxdepth 1 -name '*.md' -print -quit)")"
printf 'customized\n' > "$TEST_DIR/agents/$first_agent"
run_installer
test "$(cat "$TEST_DIR/agents/$first_agent")" = "customized"

# Same-named retired agents that users customized must not be deleted.
printf 'customized retired agent\n' > "$TEST_DIR/agents/exploit.md"
run_installer
test "$(cat "$TEST_DIR/agents/exploit.md")" = "customized retired agent"

# --force is the explicit overwrite path.
run_installer --force
cmp "$ROOT_DIR/agents/$first_agent" "$TEST_DIR/agents/$first_agent"

run_pi_installer() {
  : > "$PI_LOG"
  PATH="$TEST_DIR/bin:$PATH" \
    PI_LOG="$PI_LOG" \
    "$ROOT_DIR/install.sh" --pi "$@" >/dev/null
}

run_pi_installer
grep -q "install $ROOT_DIR" "$PI_LOG"
grep -q "install npm:@ff-labs/pi-fff" "$PI_LOG"
grep -q "install npm:pi-subagents" "$PI_LOG"

run_pi_installer --subagents
grep -q "install npm:pi-subagents" "$PI_LOG"

run_pi_installer --full
grep -q "install npm:pi-subagents" "$PI_LOG"

run_pi_installer --no-subagents
! grep -q "install npm:pi-subagents" "$PI_LOG"
