# Security Policy

Carapace is a sandbox that runs hostile code. Reports about ways it might
fail to do that are the reports we care most about. Thank you for taking
the time.

## Reporting a vulnerability

**Please do not open a public GitHub issue for security reports.**

Report privately via:

- Email: **TODO(verify)** — security contact address not yet provisioned
  (pre-release). Until it is announced here, use a GitHub private
  vulnerability report on the repository
  (https://github.com/vanshgoyal000/Carapace/security/advisories/new).

Include: affected commit or release, kernel and distro (`uname -a`),
environment (bare metal / WSL2 / container — `cara doctor --json` output
helps), a minimal reproduction, and your assessment of impact. A proof of
concept that runs through Carapace itself (never on the host) is ideal.

If the report involves a third-party component (kernel, interpreter,
Wasmtime, Firecracker), we will still coordinate, but consider whether the
upstream project is the primary recipient.

## Supported versions

Pre-release: **only the `main` branch is supported.** We do not maintain
release branches or backports yet; fixes land on `main` and users are
expected to build from a recent commit. The kernel baseline is Linux ≥ 5.10
(developed/tested on 6.18); kernel-specific behavior is only supported on
kernels that pass `cara doctor`.

## Disclosure timeline

- We aim to acknowledge reports within **2 business days**.
- We aim to publish a fix and a coordinated advisory within **90 days** of
  the report — the standard disclosure deadline. If a fix needs more time
  (e.g. a kernel-version-dependent issue), we will agree on a schedule with
  you and keep you informed.
- Credit: we will credit you in the advisory by default; tell us if you
  prefer anonymity.

## Scope

**In scope** — defects in Carapace itself:

- The policy parser / validator: any way to make a malformed or hostile
  policy produce *more* permission than it declares (the contract is
  fail-closed; docs/policy.md).
- The supervisor and child setup: any escape from the documented sandbox
  properties — filesystem outside granted paths, network in `mode = "none"`,
  resource limits bypassed (memory/pids/cpu/output/disk/timeout), fd leaks
  into the payload, environment leakage, processes surviving teardown,
  supervisor death or exhaustion, privilege transitions inside the
  sandbox.
- The (upcoming) MCP server: input validation bypasses, size-cap bypasses.
- The doctor gate: an environment that `doctor` declares ready but that
  cannot actually isolate (or vice versa: a false refusal is a bug too,
  just not a security one).

**Out of scope:**

- **Linux kernel 0-days/1-days.** Tier 1 namespaces share the host kernel;
  a kernel exploit escapes any namespace sandbox. This is a documented,
  deliberate boundary (docs/threat-model.md §3), addressed by Tiers 2/3,
  not by patching Carapace.
- Side channels (Spectre-class, Rowhammer), hardware/DMA attacks — out of
  scope for v1 (threat model §3).
- The host already being compromised by other means.
- Misconfiguration by the trusted user who writes the policy (granting
  read-write on your `~` is granting read-write on your `~`);
  `cara policy explain` exists to make policies legible.
- Vulnerabilities in third-party runtimes themselves (report those
  upstream; we will help coordinate).

## Safe harbor

We consider security research on Carapace, conducted in good faith, to be
authorized and will not pursue legal action against it, provided you:

- only run hostile test payloads **inside the sandbox or against systems
  you own or have permission to test** — never against someone else's
  Carapace deployment;
- avoid service degradation, data destruction, and privacy violations
  while investigating;
- give us a reasonable window to fix before public disclosure (see the
  90-day goal above);
- do not demand payment or extort users as part of the research.

If you are unsure whether an action falls inside this policy, ask first
via the reporting channel.

## What "fixed" means here

Every accepted security fix must come with a regression test named in
docs/agent/CLAIMS.md — the same claim → test discipline the rest of the
project follows. A fix without a test does not close the report.
