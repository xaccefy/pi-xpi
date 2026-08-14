#!/usr/bin/env bash
# Install a source checkout of XPI on Pi Agent or its OMP fork.
#
#   ./install.sh            # install on whichever host is in PATH (pi preferred, else omp)
#   ./install.sh --omp      # force the OMP host (needs `omp` in PATH)
#   ./install.sh --pi       # force the Pi host (needs `pi` in PATH)
#   ./install.sh --pi --no-subagents  # skip pi-subagents; use /xp lite on Pi
#
# Pi:  pi install <dir> + pi-subagents + optional @ff-labs/pi-fff
# OMP: omp install <dir>  (extensions + skills via the Agent Plugins manifest);
#      specialist agents are copied to ~/.omp/agent/agents so the `task` tool can
#      spawn auditor/tracer/skeptic/chain by name for /xp or /xp swarm.
set -euo pipefail

if [[ -n "${PI_XPI_INSTALLING:-}" ]]; then exit 0; fi
export PI_XPI_INSTALLING=1

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOST=""
FORCE=""
INSTALL_SUBAGENTS=1
for arg in "$@"; do
  case "$arg" in
    --pi) HOST="pi" ;;
    --omp) HOST="omp" ;;
    --force) FORCE=1 ;;
    --subagents | --full) INSTALL_SUBAGENTS=1 ;;
    --no-subagents | --lite) INSTALL_SUBAGENTS="" ;;
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
  # Exact retired-agent allowlist: upgrades remove only unchanged files XPI
  # previously installed and has deliberately dropped. Same-named customized
  # user agents are preserved.
  file_sha256() {
    if command -v sha256sum >/dev/null 2>&1; then
      sha256sum "$1" | awk '{print $1}'
    else
      shasum -a 256 "$1" | awk '{print $1}'
    fi
  }
  is_retired_agent_template() {
    case "$1:$2" in
      confirmer.md:e113a8f9403b03c56e8a0fff5766505b273c629274c137540052bc9355b91f23) return 0 ;;
      exploit.md:23ca94e7dab70b72aa8d8d4899b21376ab683eccda4140aeaf14693890ea0e8b) return 0 ;;
      exploit.md:28a1796a27b61ede41555c3629bd1008e35216e99f5911e5af93713d79f55180) return 0 ;;
      exploit.md:2db51078f36c2edc62629bfeec63d5199522e5caff244b5326b235d8660ef32c) return 0 ;;
      exploit.md:2f0d0e90ebb4545469699e66bd7eaa20b02343e73ad053b20017e2eaaa3bb73d) return 0 ;;
      exploit.md:44b42658247fdf39bb788beb6c5106905b8e95e60dd3b6d0d7b8a14cd9cddf46) return 0 ;;
      exploit.md:68bfd9706b654bc559d2b907d282f8963a5ff3e29caad8adf4787ffc3cc0e793) return 0 ;;
      exploit.md:6def7a7e6f0e98bba659d6d8d5042418fc0deb5d44c766d35279402f5c4997bf) return 0 ;;
      exploit.md:779fe37c1b6e6d09747ff9138b9f8ec436e1a87762cda496747dfbe869ecfecf) return 0 ;;
      exploit.md:876deb68f2e42ecab952caadbc058e50ff315df8faa8ab4622a23df0c51e5257) return 0 ;;
      exploit.md:a9e3987afa90bdd22acf52c527abe9c01243eb021b44bf01627fcd700d017659) return 0 ;;
      exploit.md:c596e2f9a5494353d35e4c7d222299051eadb8e00f76f16b1af33f274435ba3c) return 0 ;;
      exploit.md:cf3bf268c08e0f8eb4b3398b65b7dd6ec7f6a8a9dafd3c1e3ebaadfc1e81321a) return 0 ;;
      exploit.md:f153ab16e969a7d5c75a26054f91ea82fd6e83d353612dcaa9e773af39f777d1) return 0 ;;
      reporter.md:72e34ac8102dfcfc554048e23fb3a6940d4d4b9bb5959a47e5a366bffe224b9b) return 0 ;;
      reporter.md:7d120a3eb57dac649abfa0107b0dfac790de61a1bbeb9a37e86bd3b6889b386d) return 0 ;;
      reporter.md:e8da938ffd6084c41b505a4310b82a34fd9ca125fb94651143c061cfc350cd37) return 0 ;;
      *) return 1 ;;
    esac
  }
  for retired in confirmer.md exploit.md reporter.md; do
    if [[ -f "$AGENTS_DIR/$retired" ]]; then
      actual="$(file_sha256 "$AGENTS_DIR/$retired")"
      if is_retired_agent_template "$retired" "$actual"; then
        rm -f -- "$AGENTS_DIR/$retired"
        echo "  retired agent $retired removed"
      else
        echo "  retired agent $retired customized — preserved"
      fi
    fi
  done
  for agent in "$ROOT_DIR"/agents/*.md; do
    name="$(basename "$agent")"
    if [[ -f "$AGENTS_DIR/$name" && -z "$FORCE" ]]; then
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
  echo "XPI installed on OMP. Use /xp for the bounded swarm pipeline, or /xp lite for single-agent mode."
  echo "OMP ships its own grep/find — XPI's fff upgrade is Pi-only."
  exit 0
fi

PI_BIN="$(command -v pi)"
"$PI_BIN" install "$ROOT_DIR"

if [[ -n "$INSTALL_SUBAGENTS" ]]; then
  # /xp and /xp swarm dispatch specialist agents through pi-subagents.
  "$PI_BIN" install "npm:pi-subagents"
else
  echo "Skipping pi-subagents install (--no-subagents requested)"
fi

# Optional search upgrade. Pi's built-in grep/find remain usable if this fails.
"$PI_BIN" install "npm:@ff-labs/pi-fff" || echo "Optional @ff-labs/pi-fff install skipped"

echo
echo "Optional environment variables:"
echo "  export PI_FFF_MODE=override"
echo '  export PREVIEW_IS_API_KEY="rk_yourkeyhere"  # https://preview.is'
echo
echo "XPI installed. Use /xp for the bounded swarm pipeline, or /xp lite for single-agent mode."
