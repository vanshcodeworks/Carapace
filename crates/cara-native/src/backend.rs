//! The Tier 1 backend: environment gate + supervisor wiring.

use carapace_core::report::KillReason;
use carapace_core::spec::SandboxSpec;
use carapace_core::{Backend, BackendError, DoctorReport, ExitReport, SandboxHandle};
use std::sync::OnceLock;

/// Constructs the native backend after checking the environment (doctor
/// gate). Cloning the backend is cheap; the gate runs once per process.
#[derive(Debug, Clone)]
pub struct NativeBackend {
    gate: OnceLock<DoctorReport>,
}

impl NativeBackend {
    pub fn new() -> Self {
        Self::default()
    }

    /// Runs (or returns the cached) environment check. `ready()` is the
    /// fail-closed gate from the threat model §6.
    pub fn environment(&self) -> &DoctorReport {
        self.gate.get_or_init(crate::doctor::run_checks)
    }
}

impl Default for NativeBackend {
    fn default() -> Self {
        Self {
            gate: OnceLock::new(),
        }
    }
}

impl Backend for NativeBackend {
    fn spawn(&self, spec: &SandboxSpec) -> Result<Box<dyn SandboxHandle>, BackendError> {
        let report = self.environment();
        if !report.ready() {
            let failed: Vec<String> = report
                .failed_required()
                .iter()
                .map(|c| format!("{} ({})", c.id, c.detail))
                .collect();
            return Err(BackendError::EnvironmentNotReady(failed.join("; ")));
        }
        // Subreaper is process-wide: set it before the first spawn and keep
        // it set (defense in depth for tree cleanup — ADR-0002).
        static SUBREAPER: OnceLock<()> = OnceLock::new();
        SUBREAPER.get_or_init(|| {
            carapace_sys::fork::set_child_subreaper()
                .expect("PR_SET_CHILD_SUBREAPER must succeed on the supported baseline (5.10+)")
        });

        let inner = crate::supervisor::spawn(spec)?;
        Ok(Box::new(NativeHandle { inner }))
    }
}

struct NativeHandle {
    inner: crate::supervisor::NativeSandbox,
}

impl SandboxHandle for NativeHandle {
    fn wait(&mut self) -> Result<ExitReport, BackendError> {
        self.inner.wait()
    }

    fn kill(&mut self, reason: KillReason) {
        self.inner.kill(reason);
    }
}
