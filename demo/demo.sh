#!/usr/bin/env bash
#
# Carapace — the primary product demo.
#
# The README's "Why" story, executed: an agent writes a script that tries
# to recon your host, fork-bomb the machine, flood output, exhaust memory,
# and plant a file in /etc. Carapace runs it anyway, blocks the damage,
# and reports exactly what was stopped and why (kill_reason in the JSON
# report).
#
# Every hostile payload here mirrors an entry in the escape-suite catalog
# (crates/cara-escape-tests/src/lib.rs) — the same attacks, run through
# the real `cara run` CLI instead of the library API. See demo/README.md
# for the scenario-to-catalog mapping.
#
# Usage:
#   ./demo.sh                          # run for real (Linux; cara doctor
#                                      # must pass in the same session)
#   CARA=/path/to/cara ./demo.sh       # use a specific binary
#   DEMO_DRY_RUN=1 ./demo.sh           # print what would run; exit 0
#                                      # (for CI without user namespaces)
#
# Exit codes: 0 = every scenario passed; 1 = at least one FAIL;
#             2 = preconditions not met (nothing was executed).
#
# Safety: the payloads only ever execute inside the sandbox (CONTRIBUTING
# rule 2). The host is only read: file-existence checks and pgrep scans.
# The one host path the demo cares about, /etc/cara-demo-pwned, must NOT
# exist — every scenario re-verifies that it still does not.

set -u -o pipefail

CARA="${CARA:-cara}"
DRY_RUN="${DEMO_DRY_RUN:-0}"

# The canary file scenario (c) tries to plant on the host. If it ever
# exists, the sandbox failed (or the demo was interrupted mid-fail) and
# every subsequent "host untouched" check would be meaningless.
MARKER="/etc/cara-demo-pwned"

# Distinctive cmdline needles for the host straggler scans (the escape
# suite does the same /proc scan in tests/suite.rs).
FORK_NEEDLE='sleep 60'
FLOOD_NEEDLE='do echo x'
HOG_NEEDLE='bytearray'

passed=0
failed=0
skipped=0

say()  { printf '%s\n' "$*"; }
hdr()  { say ""; say "== $* =="; }
pass() { passed=$((passed + 1)); printf 'PASS  %s\n' "$*"; }
fail() { failed=$((failed + 1)); printf 'FAIL  %s\n' "$*"; }
skip() { skipped=$((skipped + 1)); printf 'SKIP  %s\n' "$*"; }

# JSON reports are one compact line from serde_json; allow whitespace
# around the colon anyway. kill_reason strings are part of the stable
# report schema (crates/cara-cli/src/run_ui.rs).
json_has_reason() { # <json> <reason>
  printf '%s' "$1" | grep -Eq "\"kill_reason\"[[:space:]]*:[[:space:]]*\"$2\""
}
json_snippet() {
  printf '%s' "$1" | head -c 200
}

# Grace period, then scan the host for surviving payload processes
# (mirrors tests/suite.rs::assert_no_payload_processes).
no_stragglers() { # <needle>
  sleep 1
  ! pgrep -f "$1" >/dev/null 2>&1
}

# The canary must never exist on the host, after any scenario.
host_clean() { # <scenario-tag>
  if [ -e "$MARKER" ]; then
    fail "$1: HOST TOUCHED — $MARKER exists on the host"
    return 1
  fi
  return 0
}

# ---------------------------------------------------------------------------
# Dry run: print exactly what would execute, execute nothing, exit 0.
# ---------------------------------------------------------------------------
if [ "$DRY_RUN" = "1" ]; then
  say "DEMO_DRY_RUN=1 — nothing will be executed. Commands that would run:"
  say ""
  say "  0. $CARA doctor"
  say "  a. $CARA run -- /bin/sh -c 'echo hello from sandbox'"
  say "  b. $CARA run -- /bin/sh -c 'ls /home'"
  say "  c. $CARA run -- /bin/sh -c 'echo pwned > $MARKER'"
  say "  d. $CARA run --timeout 3s --json -- /bin/sh -c 'while :; do sleep 60 & done'"
  say "  e. $CARA run --policy <tmpdir>/output-flood.toml --json -- \\"
  say "         /bin/sh -c 'while :; do echo x; done'"
  say "     policy file contents:"
  say '         [limits]'
  say '         max_output = "64KB"'
  say "  f. $CARA run --policy <tmpdir>/memory-hog.toml --json -- \\"
  say "         /usr/bin/python3 -c 'a = bytearray(10**12)'"
  say "     policy file contents:"
  say '         [limits]'
  say '         memory = "128MB"'
  say "     (scenario f is skipped when /usr/bin/python3 is absent)"
  say ""
  say "Dry run complete; exit 0."
  exit 0
fi

# ---------------------------------------------------------------------------
# Preconditions (real run only).
# ---------------------------------------------------------------------------
if [ "$(uname -s)" != "Linux" ]; then
  say "error: the Tier 1 sandbox is Linux-only (got $(uname -s))." >&2
  say "       Preview the demo instead with: DEMO_DRY_RUN=1 $0" >&2
  exit 2
fi

if ! command -v "$CARA" >/dev/null 2>&1; then
  say "error: '$CARA' is not an executable on PATH." >&2
  say "       Build it:  cargo build -p carapace-cli" >&2
  say "       Then run:  CARA=./target/debug/cara $0" >&2
  exit 2
fi

if ! command -v pgrep >/dev/null 2>&1; then
  say "error: pgrep not found (procps); the host straggler checks need it." >&2
  exit 2
fi

say "==> $CARA doctor (the demo refuses to run on an unready host)"
"$CARA" doctor
doctor_rc=$?
if [ "$doctor_rc" -ne 0 ]; then
  say "error: $CARA doctor refused this environment (exit $doctor_rc)." >&2
  say "       The sandbox must fail closed; see docs/troubleshooting.md" >&2
  say "       for remedies. Nothing was executed." >&2
  exit 2
fi

if [ -e "$MARKER" ]; then
  say "error: $MARKER already exists on the host. Remove it first —" >&2
  say "       scenario (c)'s 'host untouched' verification would be" >&2
  say "       meaningless otherwise. Nothing was executed." >&2
  exit 2
fi

workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT
run_log="$workdir/run.log"

# ---------------------------------------------------------------------------
# (a) benign — a normal command runs untouched.
#     No host assertions needed: the payload is an echo.
# ---------------------------------------------------------------------------
hdr "(a) benign: normal commands work inside the sandbox"
"$CARA" run -- /bin/sh -c 'echo hello from sandbox' >"$run_log" 2>&1
rc=$?
if [ "$rc" -eq 0 ] && grep -q 'hello from sandbox' "$run_log"; then
  pass "(a) benign — exit 0, stdout contains 'hello from sandbox'"
else
  fail "(a) benign — expected exit 0 with 'hello from sandbox' (rc=$rc); log: $(head -c 200 "$run_log")"
fi
host_clean a || true

# ---------------------------------------------------------------------------
# (b) host visibility — the host's /home is not even visible.
#     Catalog: read_home ("Neither exists inside the sandbox").
# ---------------------------------------------------------------------------
hdr "(b) host visibility: 'ls /home' finds nothing"
"$CARA" run -- /bin/sh -c 'ls /home' >"$run_log" 2>&1
if grep -q 'No such file or directory' "$run_log"; then
  pass "(b) host-visibility — /home does not exist inside the sandbox"
else
  fail "(b) host-visibility — expected 'No such file or directory'; log: $(head -c 200 "$run_log")"
fi
host_clean b || true

# ---------------------------------------------------------------------------
# (c) write outside — planting a file in host /etc must fail, and the
#     host must be clean afterwards.
#     Catalog: write_outside ("Both writes denied ... no host file appears").
# ---------------------------------------------------------------------------
hdr "(c) write-outside: 'echo pwned > /etc/...' is denied"
"$CARA" run -- /bin/sh -c "echo pwned > $MARKER" >"$run_log" 2>&1
rc=$?
if [ "$rc" -ne 0 ] && [ ! -e "$MARKER" ]; then
  pass "(c) write-outside — payload exited $rc and $MARKER does not exist on the host"
else
  fail "(c) write-outside — expected nonzero exit AND no $MARKER on the host (rc=$rc)"
fi

# ---------------------------------------------------------------------------
# (d) fork bomb — capped by pids.max, killed at the wall timeout, and the
#     whole tree is gone from the host afterwards.
#     Catalog: fork_bomb ("no stragglers survive on the host").
# ---------------------------------------------------------------------------
hdr "(d) fork bomb: 'while :; do sleep 60 & done' under --timeout 3s"
json="$("$CARA" run --timeout 3s --json -- /bin/sh -c 'while :; do sleep 60 & done' 2>/dev/null)"
if json_has_reason "$json" timeout; then
  pass "(d) fork-bomb — kill_reason is timeout"
else
  fail "(d) fork-bomb — expected kill_reason timeout in the report; got: $(json_snippet "$json")"
fi
if no_stragglers "$FORK_NEEDLE"; then
  pass "(d) fork-bomb — no '$FORK_NEEDLE' processes survive on the host (1s after)"
else
  fail "(d) fork-bomb — stragglers survived on the host"
fi
host_clean d || true

# ---------------------------------------------------------------------------
# (e) output flood — killed at the output cap (policy: max_output).
#     Catalog: output_flood ("Killed with KillReason::OutputOverflow").
# ---------------------------------------------------------------------------
hdr "(e) output flood: echo loop vs limits.max_output = \"64KB\""
cat >"$workdir/output-flood.toml" <<'EOF'
[limits]
max_output = "64KB"
EOF
"$CARA" policy check "$workdir/output-flood.toml" >/dev/null 2>&1 || {
  say "error: the generated policy was rejected by 'cara policy check'; aborting." >&2
  exit 2
}
json="$("$CARA" run --policy "$workdir/output-flood.toml" --json -- /bin/sh -c 'while :; do echo x; done' 2>/dev/null)"
if json_has_reason "$json" output_overflow; then
  pass "(e) output-flood — kill_reason is output_overflow"
else
  fail "(e) output-flood — expected kill_reason output_overflow; got: $(json_snippet "$json")"
fi
if no_stragglers "$FLOOD_NEEDLE"; then
  pass "(e) output-flood — no flood loop processes survive on the host"
else
  fail "(e) output-flood — stragglers survived on the host"
fi
host_clean e || true

# ---------------------------------------------------------------------------
# (f) memory hog — allocation far past limits.memory is an OOM kill.
#     Catalog: memory_hog ("OOM-killed at the memory limit; host
#     unaffected"; suite verifies it at a 64 MiB limit vs a 256 MiB
#     request — same mechanism, larger numbers here).
# ---------------------------------------------------------------------------
hdr "(f) memory hog: bytearray(10**12) vs limits.memory = \"128MB\""
if [ -x /usr/bin/python3 ]; then
  cat >"$workdir/memory-hog.toml" <<'EOF'
[limits]
memory = "128MB"
EOF
  "$CARA" policy check "$workdir/memory-hog.toml" >/dev/null 2>&1 || {
    say "error: the generated policy was rejected by 'cara policy check'; aborting." >&2
    exit 2
  }
  json="$("$CARA" run --policy "$workdir/memory-hog.toml" --json -- /usr/bin/python3 -c 'a = bytearray(10**12)' 2>/dev/null)"
  if json_has_reason "$json" memory_limit; then
    pass "(f) memory-hog — kill_reason is memory_limit"
  else
    fail "(f) memory-hog — expected kill_reason memory_limit; got: $(json_snippet "$json")"
  fi
  if no_stragglers "$HOG_NEEDLE"; then
    pass "(f) memory-hog — no hog processes survive on the host"
  else
    fail "(f) memory-hog — stragglers survived on the host"
  fi
  host_clean f || true
else
  skip "(f) memory-hog — /usr/bin/python3 not present on this host"
fi

# ---------------------------------------------------------------------------
# Summary.
# ---------------------------------------------------------------------------
say ""
say "============================================================"
host_clean summary || true
say "Demo summary: $passed passed, $failed failed, $skipped skipped"

if [ "$failed" -gt 0 ]; then
  say "RESULT: FAIL — the sandbox did not hold the documented line."
  exit 1
fi
say "RESULT: PASS — every scenario held; the host is untouched."
exit 0
