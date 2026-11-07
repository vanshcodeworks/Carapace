#!/usr/bin/env bash
# Full verification loop for Carapace. Run inside the Linux dev environment
# (see docs/agent/ENV.md). CI runs the same commands without
# CARA_STRICT_ENV_TESTS.
set -euo pipefail
cd "$(dirname "$0")/.."

# Keep build artifacts off the Windows-mounted source tree (dev env only);
# harmless on native Linux.
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$HOME/.cache/carapace-target}"
export CARA_STRICT_ENV_TESTS="${CARA_STRICT_ENV_TESTS:-1}"

# rustup installs live in ~/.cargo unless already on PATH.
if ! command -v cargo >/dev/null 2>&1 && [ -f "$HOME/.cargo/env" ]; then
  # shellcheck disable=SC1091
  . "$HOME/.cargo/env"
fi

# Cgroup delegation requires running inside the user slice. Normal Linux
# logins are; WSL's wsl.exe commands land in a root-owned /non-systemd
# cgroup outside it, so bridge the whole run through the user manager
# (one systemd-run, ~15ms — see docs/agent/ENV.md and doctor's remedy).
if ! grep -q "user.slice/user-$(id -u).slice" /proc/self/cgroup 2>/dev/null \
   && command -v systemd-run >/dev/null 2>&1 \
   && systemd-run --user true >/dev/null 2>&1; then
  echo "==> outside user slice; re-running under systemd-run --user --scope"
  exec systemd-run --user --scope --quiet "$0" "$@"
fi

echo "==> docs check"
python3 scripts/check-docs.py

echo "==> shell syntax"
bash -n scripts/check.sh
bash -n scripts/install.sh
bash -n demo/demo.sh

echo "==> cargo fmt --check"
cargo fmt --all -- --check

echo "==> cargo clippy"
cargo clippy --all-targets --all-features -- -D warnings

echo "==> cargo test"
cargo test --workspace

# P2 integration: real runtimes, not just the unit suite. Skips cleanly
# when the environment cannot isolate (e.g. hosted CI).
if command -v python3 >/dev/null 2>&1; then
  echo "==> runtime matrix"
  CARA="$CARGO_TARGET_DIR/debug/cara" python3 scripts/runtime-matrix.py
fi

echo "==> all green"
