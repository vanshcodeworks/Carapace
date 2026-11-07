#!/usr/bin/env bash
# Carapace tmux session - one terminal, all workflows
# Usage: ./scripts/tmux-carapace.sh [attach|new|kill]

SESSION="carapace"
ROOT="/mnt/p/Carapace"

new_session() {
    # Kill existing session if any
    tmux kill-session -t "$SESSION" 2>/dev/null || true

    # Create session with first window "dev"
    tmux new-session -d -s "$SESSION" -c "$ROOT" -n "dev"

    # Split dev window: editor (left 70%), tests (right 30%)
    tmux split-window -h -p 30 -c "$ROOT" -t "$SESSION:dev"
    tmux select-pane -t "$SESSION:dev.0"

    # Window 2: Git/Commands
    tmux new-window -t "$SESSION" -n "git" -c "$ROOT"

    # Window 3: Logs/Output
    tmux new-window -t "$SESSION" -n "logs" -c "$ROOT"

    # Window 4: Docs/Research
    tmux new-window -t "$SESSION" -n "docs" -c "$ROOT/docs"

    # Set up pane 2 (tests) with useful aliases
    tmux send-keys -t "$SESSION:dev.1" "export CARGO_TARGET_DIR=\$HOME/.cache/carapace-target" Enter
    tmux send-keys -t "$SESSION:dev.1" "alias ct='cargo test --workspace'" Enter
    tmux send-keys -t "$SESSION:dev.1" "alias cc='cargo check --workspace'" Enter
    tmux send-keys -t "$SESSION:dev.1" "alias cf='cargo fmt --all -- --check'" Enter
    tmux send-keys -t "$SESSION:dev.1" "alias cl='cargo clippy --all-targets --all-features -- -D warnings'" Enter
    tmux send-keys -t "$SESSION:dev.1" "alias check='bash scripts/check.sh'" Enter

    # Set up git window
    tmux send-keys -t "$SESSION:git" "git status" Enter

    echo "Session '$SESSION' created. Attach with: tmux attach -t $SESSION"
}

case "${1:-attach}" in
    new)
        new_session
        ;;
    kill)
        tmux kill-session -t "$SESSION" 2>/dev/null || true
        echo "Session killed"
        ;;
    attach|*)
        if tmux has-session -t "$SESSION" 2>/dev/null; then
            tmux attach-session -t "$SESSION"
        else
            new_session
            tmux attach-session -t "$SESSION"
        fi
        ;;
esac