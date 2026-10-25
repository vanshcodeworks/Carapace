# ADR-0006: MicroVM tier (C10) — libkrun first, Firecracker second

Date: 2026-10-25 · Status: accepted as DESIGN; boot path unimplemented (tier fails closed) · Milestone: C10

## Context

Tier 1 (namespaces) shares the host kernel with the payload. Threat-model §3
names the consequence honestly: a Linux kernel 0-day/1-day exploited *from
inside* the sandbox escapes — seccomp/Landlock shrink the surface but are
mitigation, not a boundary. Tier 3 adds the boundary: **one disposable
kernel per run**. A payload that kernel-panics or kernel-exploits its way
out compromises only a VM that is destroyed at the end of the run. This is
the strongest tier Carapace offers, bounded by VMM correctness and hardware
virtualization.

Honest constraint, measured (docs/agent/ENV.md): **the reference dev
environment has no `/dev/kvm`** (WSL2 without nested virtualization).
Therefore C10 is delivered as: this design + the KVM-free logic crate
(`carapace-vm`: limits→VM-config mapping, KVM gate) whose tests run
everywhere, plus KVM-gated boot tests that skip cleanly when `/dev/kvm` is
absent. Until the boot path lands, the backend fails closed on *every*
host — `EnvironmentNotReady` without KVM, `Setup` with KVM. No code path
runs a payload without isolation (threat-model §6). The documented remedy
for the dev env is WSL2 `nestedVirtualization=true`
(`%UserProfile%\.wslconfig`, then `wsl --shutdown`);
TODO(verify): whether this host/BIOS supports it.

## Evaluation

Facts below were checked against primary sources on 2026-10-25. Versions
move; re-check before implementation.

### Firecracker (AWS) — v1.17.0, released 2026-09-10

[Releases](https://github.com/firecracker-microvm/firecracker/releases) ·
[Getting started](https://github.com/firecracker-microvm/firecracker/blob/main/docs/getting-started.md) ·
[API schema](https://github.com/firecracker-microvm/firecracker/blob/main/src/firecracker/swagger/firecracker.yaml) ·
[Project page](https://firecracker-microvm.github.io/)

- **API surface**: external binary, one process per microVM, controlled via
  an HTTP/1.1 REST API over a Unix domain socket (`firecracker --api-sock`)
  or a static `--config-file` JSON. Sequence: `PUT /boot-source`
  (`kernel_image_path`, `boot_args`), `PUT /drives/rootfs`
  (`path_on_host`, ext4 image), `PUT /machine-config` (`vcpu_count`,
  `mem_size_mib`), `PUT /actions {"action_type":"InstanceStart"}`. Requests
  are handled asynchronously (the guide inserts sleeps between steps). Not
  an in-process library.
- **Kernel/rootfs images**: user-provided uncompressed ELF kernel
  (`vmlinux`, CI-built); v1.17.0 added auto-detected `bzImage` boot on
  x86_64. Rootfs is an ext4 disk image (`mkfs.ext4 -d`). Both artifacts are
  ours to pin, build and ship per guest kernel/runtime.
- **KVM**: required — "uses the Linux Kernel-based Virtual Machine (KVM)";
  64-bit Intel/AMD/Arm with hardware virtualization.
- **Boot time / memory overhead** (official claims): "< 125 ms" boot,
  "<5 MiB overhead per VM", up to 150 microVMs/s/host.
- **Config caps**: API schema caps `vcpu_count` at 32 (min 1);
  `mem_size_mib` has no schema maximum.
- **License**: Apache-2.0 (crosvm-derived sections BSD-3-Clause).
- **Maintenance**: AWS-backed, steady cadence (v1.16.1 2026-07-02,
  v1.16.2/v1.17.0 2026-09-10); official guest-kernel support list
  (5.10/6.1/6.18); security program + `jailer` companion process for a
  second host-side isolation ring.

### libkrun (Red Hat / containers) — v1.19.7, released 2026-10-22

[Releases](https://github.com/containers/libkrun/releases) ·
[README](https://github.com/containers/libkrun) ·
[1.x C header](https://github.com/containers/libkrun/blob/v1.19.7/include/libkrun.h) ·
[libkrunfw](https://github.com/containers/libkrunfw)

- **API surface**: an in-process dynamic library (C ABI defined in
  `include/libkrun.h`, plus a Rust API). 1.x shape:
  `krun_create_ctx()` → `krun_set_vm_config(ctx, uint8_t num_vcpus,
  uint32_t ram_mib)` → `krun_set_root(ctx, path)` (host **directory**
  served via virtiofs) → `krun_set_exec(ctx, exec_path, argv, envp)` /
  `krun_set_env` → `krun_add_virtio_console_default(ctx, input_fd,
  output_fd, err_fd)` (or `krun_set_console_output(path)`) →
  `krun_start_enter(ctx)` (blocks the calling thread). vsock available
  (`krun_add_vsock*`). No VMM process, no HTTP client.
- **Kernel/rootfs images**: none to manage — the guest kernel ships
  *inside* `libkrunfw` (a shared library that bundles the kernel so the
  dynamic linker does the mapping; libkrun injects the mappings into the
  guest). Rootfs is a host directory (virtiofs), not a disk image.
- **KVM**: required on Linux (HVF on macOS; Windows WHP "upcoming"; SEV/TDX
  variants exist). Note: libkrun's **TSI** is a *networking* approach
  (guest socket syscalls hooked over virtio-vsock to share host
  connectivity without a virtual NIC) — it is **not** a no-KVM software
  virtualization mode.
- **Boot time / memory overhead**: no official number comparable to
  Firecracker's published figures. TODO(verify): measure on a KVM host.
- **License**: libkrun Apache-2.0; libkrunfw LGPL-2.1 (library code) which
  carries the GPL-2.0 Linux kernel; the project's position is that the
  bundle is a "storage format", programs linking it are not required to be
  GPL, but binary distributions must include the kernel source. Legal
  review TODO(verify) before shipping binaries.
- **Maintenance**: active (slp/Red Hat; 1.19.3→1.19.7 between 2026-06 and
  2026-10: vsock fixes, init fixes incl. UID/GID parsing and an embedded
  DHCP client). Known wart: a virtio-console "TX data loss race on
  shutdown" was fixed in 1.19.1 and **reverted** in 1.19.2 — output
  truncation at teardown is a live upstream state to verify against
  whatever we pin. Announced: **2.0 will not be backwards compatible with
  the 1.x API/ABI** (new builder-style `krun_vmm_builder_*` API, disk-image
  devices raw/qcow2/vmdk).
- **Ecosystem**: used by RamaLama, krunkit, and Podman's libkrun provider
  ([Red Hat, 2025-07](https://developers.redhat.com/articles/2025/07/02/supercharging-ai-isolation-microvms-ramalama-libkrun)).

### cloud-hypervisor (rust-vmm) — v54.0, released 2026-10-14

[Releases](https://github.com/cloud-hypervisor/cloud-hypervisor/releases) ·
[API docs](https://github.com/cloud-hypervisor/cloud-hypervisor/blob/main/docs/api.md) ·
[Repo](https://github.com/cloud-hypervisor/cloud-hypervisor)

- **API surface**: external binary controlled via REST over a local UNIX
  socket (helper tool `ch-remote`; D-Bus events; `--serial socket=<path>`
  / `--console socket=<path>`). The README documents CLI/API use only —
  no stable in-process embedding story (rust-vmm *component* crates are
  importable, but the integrated VMM is not published as a library API;
  TODO(verify) crates.io packaging if this ever matters).
- **Kernel/rootfs images**: user-provided kernel image + root disk,
  direct-kernel boot — same artifact-management class as Firecracker.
- **KVM**: KVM or Microsoft Hyper-V (MSHV).
- **Boot time / memory overhead**: no official figures comparable to
  Firecracker's. TODO(verify).
- **License**: Apache-2.0 AND BSD-3-Clause (repo `LICENSES/`).
- **Maintenance**: active rust-vmm community project (v52 2026-05-14,
  v53 2026-07-12, v54 2026-10-14; live-migration n-2 guarantee). Its
  differentiators — CPU/memory/device hotplug, live migration, Windows
  guests, SEV-SNP — are all out of Carapace's scope.

## Decision

**Target libkrun first; keep Firecracker as the designed second backend
behind the same `Backend` trait; do not use cloud-hypervisor for v1.**

libkrun wins on facts that map onto Carapace's architecture:

1. **In-process library** preserves Carapace's "no daemon, no Docker,
   single binary" property. Firecracker/cloud-hypervisor both mean one
   external VMM process per run plus an HTTP-over-UDS client we must write
   and trust (more host-side attack surface, more code to fail closed).
2. **Payload-as-init is libkrun's native model**: `krun_set_exec(exec,
   argv, envp)` is literally our `SandboxSpec.program/args/env`
   (allowlist-built). With Firecracker we would have to build a guest
   rootfs containing a custom init to reach the same shape.
3. **No kernel artifact pipeline**: the kernel is bundled in libkrunfw;
   Firecracker requires pinning and shipping `vmlinux` (or bzImage) per
   guest kernel version, plus an ext4 rootfs image per runtime.
4. **Rootfs is a host directory** (virtiofs) — the same skeleton-from-host
   files approach Tier 1 already uses; no image builds.
5. **stdio wiring is fds** (`krun_add_virtio_console_default`) — plugs
   directly into the byte-capped capture-pipe model every other tier uses.

Firecracker's compensating strength — the most battle-tested security
record among microVMs, plus the `jailer` — is exactly why it stays the
designed second backend rather than being rejected: if the microVM tier
matters in production, a second VMM behind the same trait is the natural
red-team cross-check.

## Design

`carapace-vm` implements `carapace_core::Backend` (ADR-0001's synchronous
shape) as follows:

- **spawn → boot a VM with the payload as the guest's only userland
  program.** libkrun's guest init (`include/libkrun_init.h`) launches
  `spec.program` (absolute path resolved inside the guest rootfs) with
  `spec.args` and `spec.env` (allowlist by construction). When the payload
  exits, the VM ends. Exact PID-1/teardown semantics of `krun_start_enter`
  on Linux x86_64: TODO(verify) (the shutdown eventfd is documented for
  macOS/aarch64 in the 1.19.7 header).
- **`policy.limits` → VM config via `VmPlan::from_limits`** (pure logic,
  unit-tested everywhere):
  - `memory_bytes → memory_mib` rounded **up** to MiB, clamped to
    [64 MiB, 16 GiB] — a guest needs enough RAM for the kernel plus the
    payload (the floor), and Carapace refuses to silently allocate more
    than 16 GiB because a policy said so (the ceiling). The plan is
    tier-agnostic; VMM-specific caps are applied at boot-config time
    (e.g. Firecracker's schema caps `vcpu_count` at 32; libkrun 1.x takes
    `uint8_t` vcpus / `uint32_t` ram_mib — both fit our clamps).
  - `cpu_percent → vcpus = ceil(percent/100)` clamped to [1, 64]. A VM's
    CPU budget is expressed in *cores*, not fuel or quota: `cpu.max`-style
    throttling inside the guest is out of v1 scope (documented parity
    deviation, below).
  - A **0** memory or CPU budget is an `Err`, not a silent clamp to the
    floor — granting a VM to a policy that asked for none would violate
    the fail-closed rule (threat-model §6: ambiguous values are errors).
- **`network = none` (default) = no network device at all**: no virtio-net
  attached (Firecracker: no `PUT /network-interfaces`; libkrun: no net
  device), and in libkrun TSI socket-hijacking stays **off** — TSI would
  give guest sockets reach into the host, which is precisely what `none`
  forbids. No vsock in v1 either: every host↔guest channel is attack
  surface; only the console fds and the virtiofs exports cross it.
- **Filesystem = the scratch via virtio only.** Root: read-only runtime
  skeleton directory (same shape as Tier 1's), served with virtiofs.
  Scratch: a second virtiofs export mounted at `/work` by the guest init,
  sized `limits.scratch_bytes`. Honest gap, same as the Wasm tier:
  virtiofs has no byte quota — enforcement is TODO(vm-tier) (candidates:
  host-side accounting, or a guest-init loop device).
- **Output via the guest serial/console, captured with the same caps.**
  The VM console fds are wired into the supervisor's capped capture pipes;
  `limits.max_output_bytes` applies per stream exactly as in Tiers 1–2,
  and overflow kills the VM.
- **Kill = VM shutdown.** `SandboxHandle::kill(reason)` shuts the VM down
  from the host side (forced teardown path: TODO(verify) for Linux x86_64
  — guest-initiated exit is the happy path, a host-side hard stop must
  exist for a wedged guest). The VM is destroyed on every exit path.
- **KillReason parity — same meanings, different detection mechanisms**:
  `Timeout` (supervisor wall clock exceeded → VM killed) and
  `OutputOverflow` (console byte cap → VM killed) keep their exact
  cross-tier meanings. `Internal` = VMM/boot/teardown failures.
  `MemoryLimit`: guest RAM is a fixed allocation; OOM detection inside the
  guest has no cgroup `memory.events` to read — mechanism TODO(verify).
  `CpuLimit`: **never produced by this tier in v1** (the CPU budget maps
  to vCPU count, not a metered quota) — the same kind of documented
  proxy-deviation as the Wasm tier's fuel.
- **Environment gate**: `kvm_available()` (exists AND openable — the
  common failure on multi-user hosts is a `/dev/kvm` permission error,
  which a metadata check misses). False → `BackendError::EnvironmentNotReady`
  (doctor-gate semantics). KVM present but boot path unimplemented →
  `BackendError::Setup` — fail closed either way until the FFI layer
  lands.

### Test strategy

- **Always-run pure-logic tests** (no KVM): the `VmPlan` mapping — round
  up, floor/ceiling clamps, percent→vCPU ladder, 0-budget errors — plus
  error-classification of the gate. These run on the reference dev env
  (no `/dev/kvm`) in every `check.sh` pass.
- **KVM-gated tests skip cleanly**: any test that needs the hypervisor
  starts with `if !kvm_available() { return; }` (a documented clean skip,
  not a failure) — the same convention as the strict env tests, but
  KVM-absence is the *normal* dev case so no env var gates it.
- **Gate test on both hosts**: without KVM, `spawn` must return
  `EnvironmentNotReady`; with KVM, `spawn` must return `Setup` ("not
  implemented") — each asserted on the branch the host actually takes.
- **Boot-path integration tests** (real libkrun boot, escape-suite
  additions for the VM boundary: guest kernel exploit surface is upstream's
  to patch, but *our* claims — no network, scratch-only fs, capped output,
  VM dies with payload — get VM-tier escape tests): TODO(vm-tier), behind
  the KVM gate.

## Consequences

- C10 ships an honest, documented, compiling tier: green tests everywhere,
  fail-closed on every host, zero payload execution.
- The single-binary property survives: libkrun is loaded as a library, not
  spawned. Deployment story (distro packages vs vendored build of
  libkrun/libkrunfw): TODO(verify).
- libkrun 1.x is pinned; the FFI layer lives in one small module so the
  announced 2.0 ABI break is a contained port, not a rewrite.
- The libkrunfw kernel-embedding licensing (LGPL-2.1 carrier, GPL-2.0
  kernel, source-accompaniment requirement for binary distribution) needs
  a legal pass before any binary ships.
- Output truncation on VM shutdown is a known upstream libkrun state
  (fix reverted in 1.19.2) — verify against the pinned version; our capped
  readers must still report what they got.
- TODO(verify) list carried by this ADR: dev-env nested virtualization
  support; libkrun boot/teardown semantics on Linux x86_64; guest OOM →
  `MemoryLimit` detection; scratch byte-cap enforcement; boot-time and
  memory-overhead measurements for libkrun (publish measured numbers with
  machine specs per ADR-0005's honesty rules — never vendor claims).

### Re-trigger conditions (any one)

- A no-KVM or Windows (WHP) backend lands in libkrun, making the tier
  usable in the dev environment without nested virtualization.
- Firecracker ships an in-process embedding story, or our needs grow a
  production deployment where its track record + `jailer` outweigh the
  process/HTTP cost — build the Firecracker backend behind this trait.
- Payload workloads demand >32 vCPUs or >16 GiB, forcing a per-VMM
  limits review (Firecracker's schema caps `vcpu_count` at 32).
- libkrun maintenance stalls (no release in ~6 months) or the 2.0 ABI
  break ships without a workable migration path — re-evaluate
  Firecracker/cloud-hypervisor.
- A libkrun CVE class touching the host↔guest boundary (virtio, vsock,
  console) appears — reassess whether Firecracker's isolation model is
  required for the tier's claims.
