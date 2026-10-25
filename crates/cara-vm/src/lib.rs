//! `carapace-vm`: Tier 3 backend (microVM — libkrun first, Firecracker
//! second; chosen by ADR-0006).
//!
//! # Isolation model
//!
//! This is the strongest tier (threat-model §3): every run gets its own
//! **disposable Linux kernel** under hardware virtualization (KVM on Linux).
//! A payload that exploits the kernel compromises only that VM — the host
//! kernel is never shared, unlike Tier 1. The payload boots as the guest's
//! only userland program (payload-as-init, `krun_set_exec` in libkrun
//! terms) and sees: no network device, no vsock, a read-only rootfs
//! skeleton served via virtiofs, one writable scratch export at `/work`,
//! and console output wired to the supervisor's byte-capped capture pipes.
//! When the payload exits — or is killed — the whole VM is destroyed.
//!
//! # Status (C10: design milestone, fails closed)
//!
//! This module is the **pure-logic, KVM-free part**: the limits→VM-config
//! mapping ([`VmPlan`]) and the environment gate ([`kvm_available`]).
//! The boot path (libkrun FFI) is not implemented yet, so
//! [`VmBackend::spawn`] refuses to run anything on *every* host:
//!
//! - no `/dev/kvm` → [`BackendError::EnvironmentNotReady`] (doctor-gate
//!   semantics; the reference dev env is in this state, docs/agent/ENV.md);
//! - `/dev/kvm` present → [`BackendError::Setup`] — an honest "not
//!   implemented" rather than a degraded run. Fail closed either way
//!   (threat-model §6); see docs/decisions/ADR-0006-microvm-tier.md.

pub const MILESTONE: &str = "C10";

use carapace_core::spec::{Limits, SandboxSpec};
use carapace_core::{Backend, BackendError, SandboxHandle};

/// One kibibyte, for byte→MiB arithmetic.
const BYTES_PER_MIB: u64 = 1024 * 1024;

/// Exact gate message when `/dev/kvm` is unusable (asserted by tests;
/// quoted in ADR-0006).
const ERR_NO_KVM: &str = "KVM unavailable on this host — the microVM tier requires /dev/kvm (see docs/decisions/ADR-0006.md)";

/// Exact not-implemented message while the boot path is unbuilt
/// (asserted by tests; quoted in ADR-0006).
const ERR_BOOT_PATH: &str = "microVM boot path not implemented yet — see ADR-0006; the tier fails closed rather than run without isolation";

/// Floor for guest memory, in MiB. Below this the guest kernel plus the
/// payload cannot be expected to boot; a smaller policy budget is inflated
/// to this floor (and rejected only when it asks for *zero* memory).
pub const MIN_MEMORY_MIB: u64 = 64;

/// Ceiling for guest memory, in MiB (16 GiB). Carapace refuses to
/// silently allocate more because a policy said so.
pub const MAX_MEMORY_MIB: u64 = 16 * 1024;

/// Ceiling for guest vCPUs. Tier-agnostic; a backend applies any
/// VMM-specific cap on top at boot-config time (e.g. Firecracker's API
/// schema caps `vcpu_count` at 32; libkrun 1.x takes `uint8_t`).
pub const MAX_VCPUS: u32 = 64;

/// The VM shape implied by a policy's [`Limits`]: how many vCPUs and how
/// much guest RAM the microVM gets. Pure data — no VMM is touched, this
/// type exists so the mapping is unit-testable on hosts without KVM.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VmPlan {
    vcpus: u32,
    memory_mib: u64,
}

impl VmPlan {
    /// Maps [`Limits`] onto a VM shape (ADR-0006 "Design"):
    ///
    /// - `memory_bytes` → `memory_mib`, rounded **up** to whole MiB, then
    ///   clamped to [`MIN_MEMORY_MIB`]..=[`MAX_MEMORY_MIB`];
    /// - `cpu_percent` → `vcpus = ceil(percent / 100)`, clamped to
    ///   1..=[`MAX_VCPUS`] (100 % = one core).
    ///
    /// A budget of **0** memory or **0** % CPU is an error, not a silent
    /// clamp: a policy that asks for no resources must not be granted a
    /// VM anyway (fail closed, threat-model §6).
    pub fn from_limits(limits: &Limits) -> Result<VmPlan, String> {
        if limits.memory_bytes == 0 {
            return Err("memory_bytes=0 cannot map to a microVM; fix the policy".to_string());
        }
        if limits.cpu_percent == 0 {
            return Err("cpu_percent=0 cannot map to a microVM; fix the policy".to_string());
        }
        let memory_mib = limits
            .memory_bytes
            .div_ceil(BYTES_PER_MIB)
            .clamp(MIN_MEMORY_MIB, MAX_MEMORY_MIB);
        let vcpus = limits.cpu_percent.div_ceil(100).clamp(1, MAX_VCPUS);
        Ok(VmPlan { vcpus, memory_mib })
    }

    /// Guest vCPU count (1..=[`MAX_VCPUS`]).
    pub fn vcpus(&self) -> u32 {
        self.vcpus
    }

    /// Guest RAM in MiB ([`MIN_MEMORY_MIB`]..=[`MAX_MEMORY_MIB`]).
    pub fn memory_mib(&self) -> u64 {
        self.memory_mib
    }
}

/// `true` when this host can drive a KVM-based microVM: `/dev/kvm` exists
/// AND can actually be opened. The open (not a metadata check) matters —
/// the common failure on multi-user hosts is a permission error on the
/// device node (kvm group membership), which `stat` would miss.
///
/// On non-Linux hosts this is simply `false` (there is no `/dev/kvm` to
/// open). The file handle is dropped immediately; merely opening `/dev/kvm`
/// does not create a VM (that requires an ioctl).
pub fn kvm_available() -> bool {
    std::fs::File::open("/dev/kvm").is_ok()
}

/// The microVM tier backend (libkrun first — ADR-0006).
///
/// Until the boot path lands, [`Backend::spawn`] **fails closed on every
/// host**: [`BackendError::EnvironmentNotReady`] without `/dev/kvm`,
/// [`BackendError::Setup`] with it. There is no code path from this tier
/// to "ran anyway".
#[derive(Debug, Clone, Default)]
pub struct VmBackend;

impl VmBackend {
    pub fn new() -> Self {
        Self
    }
}

impl Backend for VmBackend {
    fn spawn(&self, spec: &SandboxSpec) -> Result<Box<dyn SandboxHandle>, BackendError> {
        // Environment gate first (doctor semantics, threat-model §6):
        // a host without usable KVM can never run this tier.
        if !kvm_available() {
            return Err(BackendError::EnvironmentNotReady(ERR_NO_KVM.to_string()));
        }
        // Policy validation: the limits must map to a sane VM shape before
        // anything boots. (The plan itself is consumed by the boot path,
        // which does not exist yet.)
        let _plan = VmPlan::from_limits(&spec.limits).map_err(BackendError::Setup)?;
        // Boot path intentionally missing (C10 is the design milestone):
        // fail closed rather than run the payload without isolation.
        Err(BackendError::Setup(ERR_BOOT_PATH.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits(memory_bytes: u64, cpu_percent: u32) -> Limits {
        let mut l = Limits::default();
        l.memory_bytes = memory_bytes;
        l.cpu_percent = cpu_percent;
        l
    }

    fn plan(memory_bytes: u64, cpu_percent: u32) -> VmPlan {
        VmPlan::from_limits(&limits(memory_bytes, cpu_percent)).unwrap()
    }

    const MIB: u64 = 1024 * 1024;

    // --- VmPlan::from_limits: the mapping (runs everywhere, no KVM) ---

    #[test]
    fn default_limits_map_to_one_vcpu_and_default_ram() {
        // Limits::default(): 256 MiB, 100 %.
        let p = plan(256 * MIB, 100);
        assert_eq!(p, VmPlan { vcpus: 1, memory_mib: 256 });
    }

    #[test]
    fn memory_rounds_up_to_whole_mib() {
        assert_eq!(plan(64 * MIB + 1, 100).memory_mib(), 65);
        assert_eq!(plan(64 * MIB, 100).memory_mib(), 64);
        assert_eq!(plan(1, 100).memory_mib(), 64); // floor applies after round-up
    }

    #[test]
    fn memory_floor_is_64_mib() {
        assert_eq!(plan(2 * MIB, 100).memory_mib(), 64);
    }

    #[test]
    fn memory_ceiling_is_16_gib() {
        assert_eq!(plan(32 * 1024 * MIB, 100).memory_mib(), 16 * 1024);
        assert_eq!(plan(u64::MAX, 100).memory_mib(), 16 * 1024);
    }

    #[test]
    fn cpu_percent_ceil_divides_to_vcpus() {
        assert_eq!(plan(256 * MIB, 1).vcpus(), 1);
        assert_eq!(plan(256 * MIB, 100).vcpus(), 1);
        assert_eq!(plan(256 * MIB, 101).vcpus(), 2);
        assert_eq!(plan(256 * MIB, 200).vcpus(), 2);
        assert_eq!(plan(256 * MIB, 201).vcpus(), 3);
        assert_eq!(plan(256 * MIB, 400).vcpus(), 4);
        assert_eq!(plan(256 * MIB, 6400).vcpus(), 64);
    }

    #[test]
    fn vcpu_ceiling_is_64() {
        assert_eq!(plan(256 * MIB, 6401).vcpus(), 64);
        assert_eq!(plan(256 * MIB, u32::MAX).vcpus(), 64);
    }

    #[test]
    fn zero_budgets_are_errors_not_silent_clamps() {
        let e = VmPlan::from_limits(&limits(0, 100)).unwrap_err();
        assert!(e.contains("memory"), "got: {e}");
        let e = VmPlan::from_limits(&limits(256 * MIB, 0)).unwrap_err();
        assert!(e.contains("cpu"), "got: {e}");
    }

    // --- The gate (branch taken depends on the host; both skip cleanly) ---

    #[test]
    fn spawn_without_kvm_fails_with_environment_not_ready() {
        if kvm_available() {
            return; // clean skip: this host has KVM, the other test covers it
        }
        let err = VmBackend::new()
            .spawn(&spec_with(256 * MIB, 100))
            .unwrap_err();
        assert!(
            matches!(err, BackendError::EnvironmentNotReady(_)),
            "expected EnvironmentNotReady, got: {err:?}"
        );
        assert!(err.to_string().contains("/dev/kvm"), "got: {err}");
        assert!(err.to_string().contains("ADR-0006"), "got: {err}");
    }

    #[test]
    fn spawn_with_kvm_fails_closed_until_boot_path_lands() {
        if !kvm_available() {
            return; // clean skip: KVM-capable hosts only (docs/agent/ENV.md: dev env has none)
        }
        let err = VmBackend::new()
            .spawn(&spec_with(256 * MIB, 100))
            .unwrap_err();
        assert!(
            matches!(err, BackendError::Setup(_)),
            "expected Setup, got: {err:?}"
        );
        assert!(err.to_string().contains("not implemented"), "got: {err}");
        assert!(err.to_string().contains("fail"), "got: {err}");
    }

    fn spec_with(memory_bytes: u64, cpu_percent: u32) -> SandboxSpec {
        let mut spec = SandboxSpec::new("/bin/true");
        spec.limits = limits(memory_bytes, cpu_percent);
        spec
    }
}
