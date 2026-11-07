#!/usr/bin/env bash
# Build and install the Carapace binaries, then run the doctor gate.
#
# Usage:
#   bash scripts/install.sh [--debug] [--prefix DIR]
#
# The default profile is release. The default prefix is ~/.local, so the
# binaries land in ~/.local/bin. The script never edits the host, never uses
# sudo, and never disables the doctor gate.
set -euo pipefail

PREFIX="${PREFIX:-$HOME/.local}"
PROFILE="release"

usage() {
    cat <<'EOF'
Usage: bash scripts/install.sh [options]

Options:
  --debug          Build the debug profile instead of release.
  --prefix DIR     Install under DIR (default: ~/.local).
  -h, --help       Show this help.

Environment:
  PREFIX           Same as --prefix.
  CARGO_TARGET_DIR Cargo target directory, if you already set one.
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --debug)
            PROFILE="debug"
            shift
            ;;
        --prefix)
            if [ "$#" -lt 2 ]; then
                echo "install: --prefix needs a directory" >&2
                exit 2
            fi
            PREFIX="$2"
            shift 2
            ;;
        --prefix=*)
            PREFIX="${1#*=}"
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "install: unknown option: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [ "$(uname -s)" != "Linux" ]; then
    echo "install: Carapace runs on Linux or WSL2, not on $(uname -s)." >&2
    exit 2
fi

if ! command -v cargo >/dev/null 2>&1; then
    if [ -f "$HOME/.cargo/env" ]; then
        # shellcheck disable=SC1091
        . "$HOME/.cargo/env"
    fi
fi
if ! command -v cargo >/dev/null 2>&1; then
    echo "install: cargo was not found." >&2
    echo "Install Rust 1.85 or newer from https://rustup.rs and run this script again." >&2
    exit 2
fi

if [ "$PROFILE" = "release" ]; then
    echo "==> building release binaries"
    cargo build --release -p carapace-cli -p carapace-mcp
else
    echo "==> building debug binaries"
    cargo build -p carapace-cli -p carapace-mcp
fi

TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"
BIN_DIR="$TARGET_DIR/$PROFILE"

for bin in cara cara-mcp; do
    if [ ! -x "$BIN_DIR/$bin" ]; then
        echo "install: expected binary not found: $BIN_DIR/$bin" >&2
        exit 2
    fi
done

install -d "$PREFIX/bin"
install -m 0755 "$BIN_DIR/cara" "$PREFIX/bin/cara"
install -m 0755 "$BIN_DIR/cara-mcp" "$PREFIX/bin/cara-mcp"

echo "==> installed"
echo "    $PREFIX/bin/cara"
echo "    $PREFIX/bin/cara-mcp"
"$PREFIX/bin/cara" --version

run_doctor() {
    # WSL commands launched by wsl.exe sit outside the systemd user slice.
    # Bridge into it the same way scripts/check.sh does.
    if grep -q "user.slice/user-$(id -u).slice" /proc/self/cgroup 2>/dev/null; then
        "$PREFIX/bin/cara" doctor
    elif command -v systemd-run >/dev/null 2>&1 \
        && systemd-run --user true >/dev/null 2>&1; then
        systemd-run --user --scope --quiet "$PREFIX/bin/cara" doctor
    else
        "$PREFIX/bin/cara" doctor
    fi
}

echo "==> cara doctor"
if ! run_doctor; then
    echo
    echo "install: the binaries are installed, but this host is not ready." >&2
    echo "Carapace will refuse to run code until every required check passes." >&2
    echo "Read docs/troubleshooting.md and apply the remedy printed above." >&2
    exit 4
fi

case ":$PATH:" in
    *":$PREFIX/bin:"*) ;;
    *)
        echo
        echo "Add $PREFIX/bin to PATH, for example:"
        echo "  export PATH=\"$PREFIX/bin:\$PATH\""
        ;;
esac

cat <<EOF

==> MCP client configuration

Use this absolute path in your MCP client:

  $PREFIX/bin/cara-mcp

Claude Desktop or Cursor JSON:

{
  "mcpServers": {
    "carapace": {
      "command": "$PREFIX/bin/cara-mcp",
      "args": []
    }
  }
}

Next: read AGENT_SETUP.md, or run:

  $PREFIX/bin/cara run -- /bin/sh -c 'echo hello from the sandbox'

EOF
