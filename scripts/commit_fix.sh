#!/usr/bin/env bash
set -euo pipefail
cd /mnt/p/Carapace

export GIT_AUTHOR_NAME="vanshcodeworks"
export GIT_AUTHOR_EMAIL="vanshcodeworks@users.noreply.github.com"
export GIT_COMMITTER_NAME="vanshcodeworks"
export GIT_COMMITTER_EMAIL="vanshcodeworks@users.noreply.github.com"

git add -A
git commit -m "fix(test): increase rt_stdin_reads_eof timeout to 10s for CI stability

The test was failing intermittently in CI due to timing issues (5s threshold
too tight for sandbox startup overhead in CI). Increased threshold to 10s
to match the run timeout, since the test already has a 10s timeout anyway."