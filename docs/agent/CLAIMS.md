# CLAIMS — every public claim mapped to its test or measurement

Rules: a claim without a test/measurement reference is a bug in this file.
Measured numbers must state the machine (reference env: WSL2 kernel
6.18.54.1, Ubuntu 24.04, i.e. docs/agent/ENV.md). TODO(test) = claimed but
test lands at listed milestone.

| Claim | Basis | Status |
|---|---|---|
| Dev environment supports rootless Tier 1: userns, cgroup v2 (cpu/io/memory/pids delegated), Landlock ABI 7, seccomp-bpf | Empirical probes in docs/agent/ENV.md + `cara doctor` run | ✅ verified cycle 1 (doctor output) |
| `cara doctor` reports each capability by measuring it at runtime and exits 4 when Tier 1 is impossible (fail closed) | cara-native doctor tests; cara-cli tests/doctor_cli.rs | ✅ C0 |
| Landlock ABI on dev machine is exactly v7 | carapace-sys landlock strict test (`strict_env_has_landlock`) | ✅ C0 |
| seccomp-bpf available on dev machine | carapace-sys seccomp strict test | ✅ C0 |
| Kernel config: CONFIG_SECURITY_LANDLOCK=y, CONFIG_SECCOMP_FILTER=y, CONFIG_LSM includes landlock (dev machine) | /proc/config.gz read in ENV.md (manual, cycle 1) | ✅ manual; TODO(test): doctor reads /proc/config.gz where available |
| Isolation claims (fs, network, caps, limits) | escape suite | ⏳ C1–C6 (see docs/threat-model.md §8) |
| Performance claims (cold/warm start) | benches/ | ⏳ C8 (will state machine specs) |
| "What Carapace stops" README table | generated from cara-escape-tests | ⏳ C6 |

## Retractions / corrections
(none yet)
