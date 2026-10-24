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

echo "==> cargo fmt --check"
cargo fmt --all -- --check

echo "==> cargo clippy"
cargo clippy --all-targets --all-features -- -D warnings

echo "==> cargo test"
cargo test --workspace

echo "==> all green"
