# Carapace — Final Report (agent build, cycles 1–10)

Date: 2026-10-25 · Branch: `agent/work` · 26 commits · 178 tests, 0 failures
Reference environment: WSL2, kernel 6.18.54.1, Ubuntu 24.04.5, i7-class
x86_64 laptop (docs/agent/ENV.md).

## What exists today (all measured, all claim→test mapped in CLAIMS.md)

**The product works end to end.** `cara run -- /usr/bin/python3 script.py`
executes untrusted code inside a rootless sandbox with defense in depth:

1. **Doctor gate** (`cara doctor`): 10 measured capability checks; fails
   closed (exit 4) when the host cannot isolate. Handles the WSL2
   /non-systemd cgroup case with the documented systemd-run bridge (~13 ms).
2. **Two-stage child** (ADR-0003): plain fork → cgroup attach while parked
   → unshare(7 namespaces) → id maps → stage-2 = PID-namespace init.
3. **Rootfs**: size-capped tmpfs staged over a parent-created mkdtemp dir,
   read-only /usr bind, only-safe /dev nodes, sandbox-owned /etc (marker),
   capped /work scratch, fresh /proc, `pivot_root` + old-root detach,
   post-pivot self-verification. Zero host-side artifacts.
4. **Hardening chain** (fail-closed order): fd sanitization (payload sees
   exactly 0,1,2) → rlimits (fsize/nofile/core) → capability drop (CapEff=0)
   → no_new_privs → Landlock (ABI-aware, deny-by-default) → seccomp-bpf
   allowlist (~140 syscalls; clone without NEW* flags only; wrong arch =
   KILL; verified by a BPF mini-interpreter unit test).
5. **cgroup v2 limits** (rootless): memory.max + swap=0, pids.max, cpu.max;
   kernel OOM → `KillReason::MemoryLimit`; resource report (cpu/peak-mem/
   peak-pids).
6. **Supervision**: pidfd + poll, wall timeout, per-stream byte caps with a
   self-pipe (overflow kills in milliseconds), PR_SET_PDEATHSIG so a
   SIGKILLed supervisor orphans nothing, tree kill = pidns-init SIGKILL →
   stage-1 → cgroup.kill.
7. **Tiers**: Tier 1 native (above); Tier 2 Wasm (wasmtime 50: fuel →
   CpuLimit, epoch → Timeout, store limiter → MemoryLimit, capped WASI
   pipes, one /work preopen, parity-tested); Tier 3 microVM designed
   (ADR-0006, libkrun first; KVM-free logic + fail-closed stub; boot path
   needs KVM — dev host has none).
8. **Policy engine**: strict TOML (deny unknown fields, capped/checked
   unit parsing — hardened by fuzzing), presets strict/dev/network-light,
   `cara policy check|explain`, extra ro/rw binds, network none/full
   (allowlist fails closed per ADR-0004).
9. **Interfaces**: CLI (`doctor/run/policy/mcp/bench`), Rust library
   (Backend trait, 3 implementations), MCP server (`run_code`,
   `explain_result`, hostile-input validated), stable JSON report schema
   and exit codes.
10. **Escape suite**: 20-payload hostile catalog (generated README table),
    17 red-team probes, 178 tests total — every public claim maps to a
    named test.

## Measured performance (quote only with machine context)

`cara bench` (n=100, reference env): /bin/true median 6.7–7.0 ms p95
8.5–9.3 ms; /bin/sh 6.4–6.6 ms; python3 22–25 ms (interpreter startup
dominates). Full cold path: 7 namespaces + rootfs + pivot + cgroup attach
+ Landlock + seccomp + exec.

## Bugs the process itself caught (and fixed, each with a regression test)

1. **seccomp BPF jump bug** (C4): a mislaid fall-through allowed EVERY
   syscall — caught by the hardening tests; permanently guarded by a BPF
   mini-interpreter test proving filter semantics structurally.
2. **Policy duration/size wrap** (C8 fuzz): `8888888888888m` = 16,900
   years; huge values could silently wrap in release. Fixed with
   checked_mul + 90-day/1 TiB caps + fuzz-input regression tests.
3. **Orphaned sandbox leak** (C11 red-team 2): SIGKILLing the supervisor
   left the sandbox running forever. Fixed with PR_SET_PDEATHSIG + a
   getppid race check; RT16 reproduces the attack and proves the fix.
4. Landlock verified load-bearing (blocks /etc writes on writable tmpfs);
   PEP 538 LC_CTYPE injection identified as interpreter behavior, not a
   leak; dash's exported PWD documented.

## Honest limitations (also in threat-model §7)

- Tier 1 does NOT protect against Linux kernel exploits (shared kernel) —
  that is Tier 3's job (designed; needs KVM).
- Wasm tier TODOs: fuel→cpu_time estimate, scratch byte cap, shared Engine
  for external kill().
- Network allowlist mode: designed (ADR-0004), runs fail closed.
- microVM boot path: designed (ADR-0006), needs KVM + libkrun integration.
- Publishing (crates.io, tags) is a human action (docs/release.md runbook).
- TODO(verify) items live in SECURITY.md (contact email), ADR-0006
  (nested-virt on this host, libkrun teardown semantics), docs/release.md
  (musl build untested).

## Verification status

- `scripts/check.sh` (fmt + clippy -D warnings + full test suite,
  self-bridging the cgroup context): **all green** at commit 02044f0.
- Fuzz: policy_parse 50k / spec_limits 940k / report_json 199k runs, clean
  post-fix; corpus committed.
- Demo: `demo/demo.sh` 9/9 PASS (bridged) — benign, host-visibility,
  write-outside, fork-bomb, output-flood, memory-hog; host untouched after
  every scenario.
- Not verified on this host: microVM boot (no KVM), musl static builds,
  non-x86_64 architectures (seccomp kills non-x86_64 by design).

## Recommended next steps for a human

1. Review the security claims chain: docs/agent/CLAIMS.md → named tests.
2. Set the SECURITY.md contact address (TODO(verify)).
3. Decide publish-vs-path-only for carapace-sys/native (docs/release.md).
4. Try the musl build; run `cargo audit`/`cargo deny` (commands in runbook).
5. If KVM is available anywhere: implement the ADR-0006 boot path.
6. Phase-3 backlog unchanged: Python/JS bindings, HTTP daemon, more
   runtimes, snapshot/restore, GPU policies.
