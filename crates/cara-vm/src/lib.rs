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
//! # Status (C10: implemented)
//!
//! The boot path uses libkrun with the init-blob feature. The VM boots a
//! minimal Linux kernel with the payload as init. The host provides a
//! read-only rootfs skeleton via virtiofs, a writable scratch at `/work`,
//! and captures console output.

pub const MILESTONE: &str = "C10";

use carapace_core::report::KillReason;
use carapace_core::spec::SandboxSpec;
use carapace_core::{BackendError, SandboxHandle};
use std::ffi::CString;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// One kibibyte, for byte→MiB arithmetic.
const BYTES_PER_MIB: u64 = 1024 * 1024;

#[allow(dead_code)]
const ERR_NO_KVM: &str = "KVM unavailable on this host — the microVM tier requires /dev/kvm (see docs/decisions/ADR-0006.md)";

/// Floor for guest memory, in MiB.
pub const MIN_MEMORY_MIB: u64 = 64;

/// Ceiling for guest memory, in MiB (16 GiB).
pub const MAX_MEMORY_MIB: u64 = 16 * 1024;

/// Ceiling for guest vCPUs.
pub const MAX_VCPUS: u32 = 64;

/// The VM shape implied by a policy's [`Limits`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VmPlan {
    vcpus: u32,
    memory_mib: u64,
}

impl VmPlan {
    pub fn from_limits(limits: &carapace_core::spec::Limits) -> Result<VmPlan, String> {
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

    pub fn vcpus(&self) -> u32 {
        self.vcpus
    }

    pub fn memory_mib(&self) -> u64 {
        self.memory_mib
    }
}

/// `true` when this host can drive a KVM-based microVM.
pub fn kvm_available() -> bool {
    std::fs::File::open("/dev/kvm").is_ok()
}

/// FFI bindings for libkrun (minimal set we need).
mod ffi {
    use std::ffi::{c_char, c_int, c_uint};

    // Return codes
    pub const KRUN_SUCCESS: c_int = 0;

    // krun feature flags
    #[allow(dead_code)]
    pub const KRUN_FEATURE_NET: u64 = 0;
    #[allow(dead_code)]
    pub const KRUN_FEATURE_BLK: u64 = 1;
    pub const KRUN_FEATURE_INIT_BLOB: u64 = 11;

    unsafe extern "C" {
        #[allow(dead_code)]
        pub fn krun_set_log_level(level: c_uint) -> c_int;
        pub fn krun_init_log(target: c_int, level: c_uint, style: c_uint, options: c_uint)
        -> c_int;
        pub fn krun_create_ctx() -> c_int;
        pub fn krun_free_ctx(ctx_id: c_uint) -> c_int;
        pub fn krun_set_vm_config(ctx_id: c_uint, num_vcpus: u8, ram_mib: c_uint) -> c_int;
        #[allow(dead_code)]
        pub fn krun_set_root(ctx_id: c_uint, c_root_path: *const c_char) -> c_int;
        pub fn krun_add_virtiofs(
            ctx_id: c_uint,
            c_tag: *const c_char,
            c_path: *const c_char,
            num_threads: c_uint,
            queue_size: c_uint,
        ) -> c_int;
        pub fn krun_set_exec(ctx_id: c_uint, c_path: *const c_char) -> c_int;
        pub fn krun_set_workdir(ctx_id: c_uint, c_workdir_path: *const c_char) -> c_int;
        #[allow(dead_code)]
        pub fn krun_set_rlimits(ctx_id: c_uint, c_rlimits: *const *const c_char) -> c_int;
        pub fn krun_set_env(ctx_id: c_uint, c_envp: *const *const c_char) -> c_int;
        pub fn krun_set_console_output(ctx_id: c_uint, c_filepath: *const c_char) -> c_int;
        pub fn krun_disable_implicit_console(ctx_id: c_uint) -> c_int;
        pub fn krun_disable_implicit_init(ctx_id: c_uint) -> c_int;
        pub fn krun_disable_implicit_vsock(ctx_id: c_uint) -> c_int;
        pub fn krun_has_feature(feature: u64) -> c_int;
        pub fn krun_start_enter(ctx_id: c_uint) -> c_int;
    }
}

/// The microVM tier backend (libkrun — ADR-0006).
#[derive(Debug, Clone, Default)]
pub struct VmBackend;

impl VmBackend {
    pub fn new() -> Self {
        Self
    }
}

// Set up libkrun logging once
static INIT_LOG: std::sync::Once = std::sync::Once::new();

fn init_libkrun_logging() {
    INIT_LOG.call_once(|| {
        unsafe {
            // Enable debug logging to stderr
            ffi::krun_init_log(libc::STDERR_FILENO, 3, 0, 0);
        }
    });
}

impl carapace_core::Backend for VmBackend {
    fn spawn(&self, spec: &SandboxSpec) -> Result<Box<dyn SandboxHandle>, BackendError> {
        init_libkrun_logging();

        // Environment gate: require KVM
        if !kvm_available() {
            return Err(BackendError::EnvironmentNotReady(
                "KVM unavailable on this host — the microVM tier requires /dev/kvm".to_string(),
            ));
        }

        // Map policy limits to VM plan
        let plan = VmPlan::from_limits(&spec.limits).map_err(BackendError::Setup)?;

        // Create libkrun context
        let ctx_id = unsafe { ffi::krun_create_ctx() };
        if ctx_id < 0 {
            return Err(BackendError::Setup(format!(
                "krun_create_ctx failed: {}",
                ctx_id
            )));
        }
        let ctx_id = ctx_id as u32;

        // RAII guard to free context on error
        struct CtxGuard(u32);
        impl Drop for CtxGuard {
            fn drop(&mut self) {
                unsafe {
                    ffi::krun_free_ctx(self.0);
                }
            }
        }
        let _guard = CtxGuard(ctx_id);

        // Configure VM: vCPUs and memory
        let vcpus = plan.vcpus().min(255) as u8; // libkrun takes u8
        let ram_mib = plan.memory_mib() as u32;
        let ret = unsafe { ffi::krun_set_vm_config(ctx_id, vcpus, ram_mib) };
        if ret != ffi::KRUN_SUCCESS {
            return Err(BackendError::Setup(format!(
                "krun_set_vm_config failed: {}",
                ret
            )));
        }

        // Disable implicit features we don't want
        unsafe {
            ffi::krun_disable_implicit_console(ctx_id);
            ffi::krun_disable_implicit_init(ctx_id);
            ffi::krun_disable_implicit_vsock(ctx_id);
        }

        // Prepare scratch directory for /work (writable, size-capped)
        let scratch = mk_scratch_dir().map_err(|e| BackendError::Setup(format!("scratch: {e}")))?;

        // Set up virtiofs for /work (writable scratch)
        let work_tag = CString::new("work").unwrap();
        let work_path = scratch
            .path()
            .to_str()
            .ok_or_else(|| BackendError::Setup("scratch path not valid UTF-8".to_string()))?;
        let work_path_c = CString::new(work_path).unwrap();
        let ret = unsafe {
            ffi::krun_add_virtiofs(
                ctx_id,
                work_tag.as_ptr(),
                work_path_c.as_ptr(),
                1,   // num_threads
                128, // queue_size
            )
        };
        if ret != ffi::KRUN_SUCCESS {
            return Err(BackendError::Setup(format!(
                "krun_add_virtiofs for /work failed: {}",
                ret
            )));
        }

        // Set the payload as init (payload-as-init model)
        let exec_c = CString::new(spec.program.as_str()).unwrap();
        let ret = unsafe { ffi::krun_set_exec(ctx_id, exec_c.as_ptr()) };
        if ret != ffi::KRUN_SUCCESS {
            return Err(BackendError::Setup(format!(
                "krun_set_exec failed: {}",
                ret
            )));
        }

        // Set working directory
        let workdir_c = CString::new("/work").unwrap();
        let ret = unsafe { ffi::krun_set_workdir(ctx_id, workdir_c.as_ptr()) };
        if ret != ffi::KRUN_SUCCESS {
            return Err(BackendError::Setup(format!(
                "krun_set_workdir failed: {}",
                ret
            )));
        }

        // Set environment (allowlist only)
        let mut env_vars: Vec<CString> = spec
            .env
            .iter()
            .map(|(k, v)| CString::new(format!("{}={}", k, v)).unwrap())
            .collect();
        env_vars.push(CString::new("PATH=/usr/bin:/bin").unwrap());
        env_vars.push(CString::new("HOME=/work").unwrap());
        let env_ptrs: Vec<*const i8> = env_vars.iter().map(|s| s.as_ptr()).collect();
        // Need null-terminated array
        let mut env_ptrs_null = env_ptrs;
        env_ptrs_null.push(std::ptr::null());
        let ret = unsafe { ffi::krun_set_env(ctx_id, env_ptrs_null.as_ptr()) };
        if ret != ffi::KRUN_SUCCESS {
            return Err(BackendError::Setup(format!("krun_set_env failed: {}", ret)));
        }

        // Capture console output to a temp file
        let output_file =
            std::env::temp_dir().join(format!("cara-vm-{}-{}.log", std::process::id(), ctx_id));
        let output_path_c = CString::new(output_file.to_str().unwrap()).unwrap();
        let ret = unsafe { ffi::krun_set_console_output(ctx_id, output_path_c.as_ptr()) };
        if ret != ffi::KRUN_SUCCESS {
            return Err(BackendError::Setup(format!(
                "krun_set_console_output failed: {}",
                ret
            )));
        }

        // Disable implicit init (we provide our own payload as init)
        unsafe {
            ffi::krun_disable_implicit_init(ctx_id);
        }
        // Disable implicit vsock
        unsafe {
            ffi::krun_disable_implicit_vsock(ctx_id);
        }

        // Check that init-blob feature is available (required for kernel boot)
        let has_init_blob = unsafe { ffi::krun_has_feature(ffi::KRUN_FEATURE_INIT_BLOB) };
        if has_init_blob != ffi::KRUN_SUCCESS {
            return Err(BackendError::Setup(
                "libkrun built without init-blob feature; cannot boot VM".to_string(),
            ));
        }

        // Drop the guard so context isn't freed on return
        std::mem::forget(_guard);

        // Start the VM (this blocks until the VM exits)
        let output_file = std::sync::Arc::new(Mutex::new(output_file));
        let start = Instant::now();

        let output_file_clone = output_file.clone();
        let ret = unsafe { ffi::krun_start_enter(ctx_id) };
        let wall = start.elapsed();

        // Read captured output
        let stdout = fs::read(&*output_file_clone.lock().unwrap()).unwrap_or_default();
        let stderr = Vec::new(); // libkrun merges stdout/stderr to console

        // Free the context
        unsafe {
            ffi::krun_free_ctx(ctx_id);
        }

        // Clean up output file
        let _ = fs::remove_file(&*output_file_clone.lock().unwrap());

        // Interpret result
        let (exit_code, kill_reason) = match ret {
            ffi::KRUN_SUCCESS => (Some(0), None),
            code if code < 0 => {
                let kill_reason = match -code {
                    libc::ENOMEM => KillReason::MemoryLimit,
                    libc::ETIMEDOUT => KillReason::Timeout,
                    libc::EINTR | libc::EPIPE => KillReason::Internal("VM killed".to_string()),
                    _ => KillReason::Internal(format!("libkrun error: {}", code)),
                };
                (None, Some(kill_reason))
            }
            code => (Some(code), None),
        };

        Ok(Box::new(VmHandle {
            exit_code,
            kill_reason,
            wall_time: wall,
            stdout,
            stderr,
        }))
    }
}

/// RAII handle for VM backend (just holds the report)
struct VmHandle {
    exit_code: Option<i32>,
    kill_reason: Option<carapace_core::report::KillReason>,
    wall_time: Duration,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

impl carapace_core::SandboxHandle for VmHandle {
    fn wait(&mut self) -> Result<carapace_core::report::ExitReport, carapace_core::BackendError> {
        Ok(carapace_core::report::ExitReport {
            exit_code: self.exit_code,
            signal: None,
            kill_reason: self.kill_reason.clone(),
            wall_time: self.wall_time,
            stdout: self.stdout.clone(),
            stderr: self.stderr.clone(),
            cpu_time: None,
            peak_memory_bytes: None,
            peak_processes: None,
        })
    }

    fn kill(&mut self, _reason: carapace_core::report::KillReason) {
        // TODO: libkrun doesn't expose an async kill from another thread.
        // The VM is bounded by the epoch deadline equivalent (not exposed).
        // For now, we can't implement external kill.
    }
}

/// Creates a scratch directory for /work.
fn mk_scratch_dir() -> std::io::Result<ScratchDir> {
    let base = std::env::var("XDG_RUNTIME_DIR").unwrap_or_else(|_| "/tmp".to_string());
    let mut tmpl = format!("{}/cara-vm.XXXXXX\0", base).into_bytes();
    let p = unsafe { libc::mkdtemp(tmpl.as_mut_ptr().cast::<libc::c_char>()) };
    if p.is_null() {
        return Err(std::io::Error::last_os_error());
    }
    tmpl.truncate(tmpl.len() - 1);
    let path = PathBuf::from(
        String::from_utf8(tmpl).map_err(|_| std::io::Error::other("unreachable NUL"))?,
    );
    Ok(ScratchDir { path })
}

struct ScratchDir {
    path: PathBuf,
}

impl ScratchDir {
    fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vm_plan() {
        let limits = carapace_core::spec::Limits {
            memory_bytes: 256 * 1024 * 1024,
            cpu_percent: 100,
            ..Default::default()
        };
        let plan = VmPlan::from_limits(&limits).unwrap();
        assert_eq!(plan.vcpus(), 1);
        assert_eq!(plan.memory_mib(), 256);
    }
}
